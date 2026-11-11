#!/usr/bin/env python3
"""Replay the #115 cgroup V1 integer-parser and Unicode-trim evidence.

Only parse/disassemble authenticated bytes. Never load or emulate target code.
The ELF reader, FDE decoder and GNU partition checker are existing MIT tools.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from cpu_quota_115_static import (
    Image, SHA256, TARGET, exception_sites, instruction, native_bytes, no_writers, require,
)
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

PACKET = Path(__file__).resolve().parent
BODIES = {
    'v1_integer': (0x5ba9f00, 0x5baa07d, 'c0f17701f7be39d9a7396ed88fd7955c5397b926b9213a266aa7227a39bece9a'),
    'read_boundary': (0x5baa080, 0x5baa18b, 'e4a19e585bae35f073aa313575421bb1c718fe93cabd461335e47175a47287da'),
    'unicode_trim': (0x5baa6f0, 0x5baa987, '406988321fd9354e1e60432f9b9888ecb21e0b649aa16e19e19d560110cc0221'),
}
PINS = {
    'empty_and_lone_sign': (0x5ba9f42, '4885d274184883fa01753a0fb6304531ff83fe2b740a83fe2d7405'),
    'optional_plus_and_length': (0x5ba9f8a, '31c94080fe2b0f94c14889ce48f7de4889d74829cf4801c14883ff11734e'),
    'fast_digit_check': (0x5ba9fd0, '0fb6140183c2d083fa097770'),
    'multiply_overflow': (0x5baa012, '4c89e048f7e70f8044ffffff'),
    'digit_and_add_overflow': (0x5baa021, '420fb6140183c2d04901d40f92c083fa090f872affffff49ffc084c074cb'),
    'quota_caller': (0x5ba9197, 'e8640d0000'),
    'period_caller': (0x5ba91be, 'e83d0d0000'),
    'v1_dispatch_arguments': (0x5ba9185, '488d1524a08afab9100000004c89ef4c89f6e8640d000041b7014883f8010f858b0100004989d4488d15735cd9fab9110000004c89ef4c89f6e83d0d00004883f8010f85160400004885d274ab'),
}
TABLE_VA = 0x479266
TABLE_SHA = '2479482c1d14bb27cb07be6eb893aaf994aa096f8318804b68a8d18b0a23ff3f'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def analyze(data, identity=True):
    if identity:
        require(len(data) == 105896032 and sha(data) == SHA256, 'target identity')
    image = Image(data)
    for name, (va, expected) in PINS.items():
        require(image.read(va, len(bytes.fromhex(expected))).hex() == expected, 'instruction pin: ' + name)
    table = image.read(TABLE_VA, 256)
    no_writers(image, TABLE_VA, 256)
    require(sha(table) == TABLE_SHA, 'whitespace table')
    literals = {0x4531b0: b'cpu.cfs_quota_us', 0x93ee26: b'cpu.cfs_period_us'}
    for va, raw in literals.items():
        no_writers(image, va, len(raw))
        require(image.read(va, len(raw)) == raw, 'V1 filename')
    table_binding = image.binding(0x64dfc30)
    require(table_binding is not None and table_binding['kind'] == 8
            and table_binding['symbol_index'] == 0
            and table_binding['addend'] == TABLE_VA, 'whitespace relocation')
    bodies, decoded, calls, branches, references = [], {}, [], [], []
    for name, (start, end, expected_sha) in BODIES.items():
        frames = [f for f in image.fdes if f['start'] < end and start < f['end']]
        require(len(frames) == 1 and (frames[0]['start'], frames[0]['end']) == (start, end), 'FDE extent: ' + name)
        raw = image.read(start, end - start)
        no_writers(image, start, end-start)
        require(sha(raw) == expected_sha, 'body digest: ' + name)
        insns = image.decode(start, end)
        decoded[name] = insns
        frame = frames[0]
        row = dict(name=name, start=hex(start), end_exclusive=hex(end), file_offset=hex(image.offset(start, end-start)),
                   bytes=end-start, sha256=sha(raw), instructions=len(insns), frame=frame)
        for key in ('fde', 'cie'):
            va = frame[key]
            size = 4 + struct.unpack('<I', image.read(va, 4))[0]
            row[key + '_hex'] = image.read(va, size).hex()
        row['exception_sites'] = exception_sites(image, frame, {i.address for i in insns})
        bodies.append(row)
        for ins in insns:
            if ins.mnemonic == 'call':
                call = dict(owner=name, **instruction(ins))
                op = ins.operands[0]
                if op.type == X86_OP_IMM:
                    call['target'] = hex(op.imm)
                elif op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    slot = ins.address + ins.size + op.mem.disp
                    call['binding'] = image.binding(slot)
                calls.append(call)
            if ins.mnemonic.startswith('j'):
                branches.append(dict(owner=name, **instruction(ins)))
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    references.append(dict(owner=name, site=hex(ins.address),
                                           referent=hex(ins.address + ins.size + op.mem.disp)))
    whitespace = list(range(9, 14)) + [32, 0x1680, 0x3000]
    whitespace += [i for i, bits in enumerate(table) if bits & 1]
    whitespace += [0x2000 + i for i, bits in enumerate(table) if bits & 2]
    report = dict(target_sha256=SHA256, bodies=bodies, calls=calls, branches=branches,
                  rip_references=references, instruction_pins={name: [hex(va), raw] for name, (va, raw) in PINS.items()},
                  filenames={hex(va): raw.decode() for va, raw in literals.items()},
                  whitespace_table=dict(va=hex(TABLE_VA), file_offset=hex(image.offset(TABLE_VA, 256)),
                                        sha256=sha(table), hex=table.hex(), relocation=table_binding),
                  trim_codepoints=[f'U+{cp:04X}' for cp in sorted(whitespace)],
                  instruction_count=sum(len(v) for v in decoded.values()),
                  analyzed_bytes=sum(end-start for start, end, _ in BODIES.values()),
                  captured_binary_executed=False, instruction_emulation=False,
                  runtime_outputs_measured=False, completed_gates=0)
    return report, image, decoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--check', action='store_true', help='compare with committed records')
    args = parser.parse_args()
    require(not args.out.exists(), 'use a fresh output directory')
    data = TARGET.read_bytes()
    report, image, decoded = analyze(data)
    args.out.mkdir(parents=True)
    commands = []
    for name, (start, end, _) in BODIES.items():
        command = ['objdump', '-d', '-M', 'intel', '--insn-width=16',
                   '--start-address=' + hex(start), '--stop-address=' + hex(end), str(TARGET)]
        result = subprocess.run(command, check=True, capture_output=True)
        require(not result.stderr, 'objdump stderr')
        stdout = result.stdout.replace(str(TARGET).encode(), b'<authenticated-node115>').replace(b'\r\n', b'\n')
        expected = [(i.address, bytes(i.bytes)) for i in decoded[name]]
        require(native_bytes(stdout.decode(), start, end) == expected, 'GNU/Capstone partition: ' + name)
        (args.out / (name + '.objdump')).write_bytes(stdout)
        commands.append([part.replace(str(TARGET), 'artifacts/node/115/hl-node') for part in command])
    frame_command = ['readelf', '--debug-dump=frames', str(TARGET)]
    frames = subprocess.run(frame_command, check=True, capture_output=True, text=True).stdout
    wanted = {(start, end) for start, end, _ in BODIES.values()}
    matched = []
    native_extents = set()
    for line in frames.splitlines():
        match = re.search(r'\bFDE\b.*\bpc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
        if match and (int(match[1], 16), int(match[2], 16)) in wanted:
            native_extents.add((int(match[1], 16), int(match[2], 16)))
            matched.append(line)
    require(native_extents == wanted and len(matched) == len(wanted), 'GNU readelf FDE disagreement')
    (args.out / 'frames.txt').write_text('\n'.join(matched) + '\n', encoding='utf-8', newline='\n')
    controls = []
    sites = [('sign', 0x5ba9f8f), ('digit', 0x5ba9fd9), ('length', 0x5ba9fa5),
             ('multiply_overflow', 0x5baa018), ('add_overflow', 0x5baa03d),
             ('quota_call', 0x5ba9198), ('filename', 0x4531b0),
             ('low_whitespace', TABLE_VA + 0x85), ('high_whitespace', TABLE_VA + 0x0b),
             ('table_relocation', None), ('parser_fde_range', None), ('target_identity', None)]
    for name, va in sites:
        if name == 'table_relocation':
            offset = int(report['whitespace_table']['relocation']['file_offset'], 16) + 16
        elif name == 'parser_fde_range':
            offset = image.offset(report['bodies'][0]['frame']['fde'] + 12, 1)
        else:
            offset = 0 if va is None else image.offset(va, 1)
        mutated = bytearray(data)
        mutated[offset] ^= 1
        try:
            analyze(mutated, identity=name == 'target_identity')
        except ValueError as error:
            controls.append(dict(name=name, file_offset=hex(offset), rejected=True, reason=str(error),
                                 whole_image_digest_checked=name == 'target_identity'))
        else:
            raise ValueError('undetected corruption: ' + name)
        del mutated
    if args.check:
        require(report == json.loads((PACKET / 'records.json').read_text(encoding='utf-8')), 'retained record drift')
        for name, (start, end, _) in BODIES.items():
            filename = name + '.objdump'
            expected = [(i.address, bytes(i.bytes)) for i in decoded[name]]
            require(native_bytes((PACKET / filename).read_text(encoding='utf-8'), start, end) == expected,
                    'retained GNU instruction drift: ' + name)
    (args.out / 'records.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    (args.out / 'controls.json').write_text(json.dumps(controls, indent=2) + '\n', encoding='utf-8', newline='\n')
    versions = {}
    for tool in ('objdump', 'readelf'):
        versions[tool] = subprocess.run([tool, '--version'], check=True, capture_output=True, text=True).stdout.splitlines()[0]
    import capstone
    versions.update(python=sys.version.split()[0], capstone=capstone.__version__)
    summary = dict(analyzed_bytes=report['analyzed_bytes'], instructions=report['instruction_count'],
                   complete_fde_ranges=len(BODIES), native_partitions_agree=True,
                   whitespace_codepoints=len(report['trim_codepoints']), corruptions_rejected=len(controls),
                   commands=commands + [['readelf', '--debug-dump=frames', 'artifacts/node/115/hl-node']],
                   versions=versions, captured_binary_executed=False, instruction_emulation=False)
    source_paths = ['tools/cpu_quota_115_static.py', 'tools/elf_index.py', 'tools/fde_extents.py',
                    'research/work-items/RE-002-node115-cgroup-v1-integer/collect.py']
    summary['source_sha256'] = {path: sha((ROOT / path).read_bytes()) for path in source_paths}
    (args.out / 'qualification.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
