"""Read target bytes and validate a finite private admission freeze.

Static decoders consume tiny raw instruction fragments; the captured ELF is
never executed, evaluated, copied, or patched. No Rust source is involved.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / 'artifacts/node/94/hl-node'
SUPPORT = ROOT / 'research/work-items/RE-006-j9-first-front-rust-94/verify_native.py'
LLVM = '/workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-mc'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def operand(text):
    text = re.sub(r'<[^>]*>', '', text).split('#')[0]
    return re.sub(r'\s+', ' ', text.replace('0x', '')).strip()


def main(out):
    require(not out.exists(), 'fresh output required')
    out.mkdir(parents=True)
    (out / 'raw').mkdir()
    require(sha(SUPPORT.read_bytes()) == '99adb98cb0558d57f8fcc5adc28156c9c2f6ea69d233f35a230786745efb2f8d', 'predecessor ELF reader pin')
    spec = importlib.util.spec_from_file_location('prior_static_elf_reader', SUPPORT)
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    data = BINARY.read_bytes()
    require(len(data) == 91774280 and sha(data) == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f', 'target identity')
    image = support.Image(data)
    sections = support.sections(data)
    _, frames = support.eh_frame_records(data, sections)
    intake = json.loads((HERE / 'OUTER-NATIVE-INTAKE.json').read_text())
    verified = []
    for expected in intake['functions']:
        lo, hi = int(expected['start'], 16), int(expected['end'], 16)
        hits = [item for item in frames if item['start'] <= lo < item['end']]
        require(len(hits) == 1 and hits[0]['start'] == lo and hits[0]['end'] == hi, 'unique exact FDE')
        actual = hits[0]
        require(sha(image.read(lo, hi - lo)) == expected['sha256'], 'complete native body')
        for name in ['fde', 'cie']:
            require(hex(actual[name]) == expected[name] and image.record(actual[name]) == expected[name + '_hex'], name + ' byte binding')
        require((None if actual['lsda'] is None else hex(actual['lsda'])) == expected['lsda'], 'LSDA identity')
        verified.append(dict(start=hex(lo), end=hex(hi), bytes=hi - lo, body_sha256=expected['sha256']))
    for edge in intake['calls']:
        at, target = int(edge['site'], 16), int(edge['target'], 16)
        raw = image.read(at, 5)
        require(raw.hex() == edge['bytes'] and raw[0] == 0xE8 and at + 5 + struct.unpack('<i', raw[1:])[0] == target, 'direct E8 edge')
    rela = next(section for section in sections if section['name'] == '.rela.dyn')
    relocations = [struct.unpack_from('<QQq', data, at) for at in range(rela['offset'], rela['offset'] + rela['size'], 24)]
    for at, slot, target in [(0x4DBD5D1, 0x57768A0, 0x4497A90), (0x4450242, 0x576DFD8, 0x54C06B0), (0x44503AF, 0x5774F50, 0x4486D10)]:
        raw = image.read(at, 6)
        require(raw[:2] == b'\xff\x15' and at + 6 + struct.unpack('<i', raw[2:])[0] == slot, 'RIP call slot')
        require([row for row in relocations if row[0] == slot] == [(slot, 8, target)], 'unique relative relocation')
    functions = json.loads((HERE / 'primary-rows.json').read_text())
    cfg = []
    for start, rows in functions.items():
        expected = next(f for f in intake['functions'] if f['start'] == start)
        cursor = int(start, 16)
        boundaries = {int(row['va'], 16) for row in rows}
        flow = []
        for row in rows:
            at, raw = int(row['va'], 16), bytes.fromhex(row['bytes'])
            require(at == cursor and image.read(at, len(raw)) == raw, 'complete primary partition')
            cursor += len(raw)
            mnemonic = row['gnu'].split()[0]
            if mnemonic.startswith('j'):
                target = int(row['gnu'].split()[1], 16)
                require(target in boundaries, 'all primary jump targets are body boundaries')
                flow.append(dict(site=row['va'], mnemonic=mnemonic, target=hex(target)))
        require(cursor == int(expected['end'], 16) and len(rows) == expected['instructions'], 'complete primary denominator')
        cfg.append(dict(start=start, complete_instructions=len(rows), branches=flow,
                        calls=[row['va'] for row in rows if row['gnu'].split()[0] == 'call']))
    allocator_hits = [f for f in frames if f['start'] <= 0x54C06B0 < f['end']]
    require(len(allocator_hits) == 1 and allocator_hits[0]['start'] == 0x54C06B0, 'allocator entry exact FDE')
    allocator = allocator_hits[0]
    opaque_allocator = dict(start=hex(allocator['start']), end=hex(allocator['end']),
                            body_sha256=sha(image.read(allocator['start'], allocator['end'] - allocator['start'])),
                            fde=hex(allocator['fde']), fde_hex=image.record(allocator['fde']),
                            limit='Identity/opaque boundary only; no allocator ownership/freshness or complete allocator semantics recovered.')
    freeze = json.loads((HERE / 'PRE-SOURCE-BOUNDARIES.json').read_text())
    admitted = 0
    for case in freeze['cases']:
        values = [int(value, 16) for value in case['a21']]
        require(sha(struct.pack('<21Q', *values)) == case['a21_le_sha256'], 'literal input byte hash')
        # Independent formulation: count the maximal adjacent monotone prefix.
        ascending = values[0] <= values[1]
        run = 2
        for index in range(2, 21):
            good = values[index - 1] <= values[index] if ascending else values[index - 1] > values[index]
            if not good:
                break
            run += 1
        require(run == case['natural_run'] and (run < 11) == case['first_short_run_delegate'], 'frozen run/admission arithmetic')
        admitted += run < 11
        require(case['a21_unchanged_at_delegate'] == (case['a21'] if run < 11 else None), 'endpoint source preservation projection')
    require((len(freeze['cases']), admitted) == (76, 56), 'exact finite corpus denominator')
    streams = []
    controls = json.loads((HERE / 'PRE-SOURCE-NATIVE-CONTROLS.json').read_text())['controls']
    with tempfile.TemporaryDirectory(prefix='n21-admission-raw-static-') as directory:
        fragment = Path(directory) / 'instruction.raw'
        for control in controls:
            at = int(control['va'], 16)
            before, after = bytes.fromhex(control['before']), bytes.fromhex(control['after'])
            require(before == image.read(at, len(before)) and len(before) == len(after), 'exact control bytes/width')
            observations = []
            for label, raw in [('native', before), ('overlay', after)]:
                fragment.write_bytes(raw)
                gnu = subprocess.run(['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-Mintel', '--insn-width=16', f'--adjust-vma={at}', str(fragment)], capture_output=True)
                llvm = subprocess.run([LLVM, '--disassemble', '--triple=x86_64', '--output-asm-variant=1', '--print-imm-hex'],
                                      input=(' '.join(f'0x{x:02x}' for x in raw) + '\n').encode(), capture_output=True)
                require(gnu.returncode == llvm.returncode == 0 and not gnu.stderr and not llvm.stderr, 'static fragment decoder exit/stderr')
                for tool, process in [('gnu', gnu), ('llvm', llvm)]:
                    for channel in ['stdout', 'stderr']:
                        (out / 'raw' / (control['name'] + '.' + label + '.' + tool + '.' + channel)).write_bytes(getattr(process, channel))
                parsed = [support.LINE.match(line) for line in gnu.stdout.decode().splitlines()]
                parsed = [match for match in parsed if match]
                require(len(parsed) == 1 and int(parsed[0][1], 16) == at and bytes.fromhex(parsed[0][2]) == raw, 'one complete GNU instruction')
                llvm_lines = [line.strip() for line in llvm.stdout.decode().splitlines() if line.strip() and line.strip() != '.text']
                require(len(llvm_lines) == 1, 'one complete LLVM instruction')
                if label == 'native':
                    require(operand(parsed[0][3]) == operand(control['expected_gnu_operand']), 'original operand anchor')
                observations.append(dict(kind=label, gnu=parsed[0][3], llvm=llvm_lines[0],
                                         gnu_stdout_sha256=sha(gnu.stdout), llvm_stdout_sha256=sha(llvm.stdout),
                                         gnu_stderr_sha256=sha(gnu.stderr), llvm_stderr_sha256=sha(llvm.stderr)))
            require(observations[0]['gnu'] != observations[1]['gnu'] and observations[0]['llvm'] != observations[1]['llvm'], 'operative decoder distinction')
            streams.append(dict(name=control['name'], observations=observations, status='executed static decoding only; not node execution'))
    result = dict(target_sha256=sha(data), six_body_fde_bindings=verified, complete_primary_cfg=cfg,
                  opaque_allocator_boundary=opaque_allocator, cases=76, admitted=56, excluded=20,
                  native_controls=streams, static_instruction_fragment_variants=32, decoder_processes=64,
                  captured_execution=False, instruction_evaluation=False, rust_compilation=False,
                  frozen_files={name: sha((HERE / name).read_bytes()) for name in ['OUTER-NATIVE-INTAKE.json', 'PRE-SOURCE-BOUNDARIES.json', 'PRE-SOURCE-NATIVE-CONTROLS.json']},
                  limits='Finite arithmetic and static decoder distinctions. GNU raw branch targets use adjusted VAs; llvm-mc decodes raw relative operands without ELF relocation/context. No runtime pointer, allocator, target array-output or whole-sort validation.')
    (out / 'native-results.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print('PASS: six exact FDE/body bindings; selected call relocations;76 arithmetic cases;16 native operand controls/64 tiny-fragment decoder processes; no target execution/Rust')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    main(args.out.resolve())
