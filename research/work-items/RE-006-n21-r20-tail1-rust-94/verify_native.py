"""Authenticate the r20 route and replay retained finite static evidence.

No captured target, instruction evaluator or dynamic import provider is run.
The GNU/LLVM full exports and tiny-fragment raw channels are original retained
outputs; this verifier checks their bytes/partitions/properties, not new decoding.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import importlib.util
import json
import struct
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def read(name):
    return json.loads((HERE / name).read_text())


def unbundle(entry):
    require(type(entry['bytes']) is int and 0 <= entry['bytes'] <= 2 * 1024 * 1024, 'member bound')
    raw = base64.b64decode(entry['zlib_base64'], validate=True)
    require(base64.b64encode(raw).decode() == entry['zlib_base64'], 'canonical base64')
    decoder = zlib.decompressobj()
    payload = decoder.decompress(raw, entry['bytes'] + 1)
    require(len(payload) == entry['bytes'] and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, 'compressed boundary')
    require(sha(payload) == entry['sha256'], 'member hash')
    return payload


def verify(binary):
    support = ROOT / 'research/work-items/RE-006-j9-first-front-rust-94/verify_native.py'
    require(sha(support.read_bytes()) == '99adb98cb0558d57f8fcc5adc28156c9c2f6ea69d233f35a230786745efb2f8d', 'reviewed ELF reader')
    spec = importlib.util.spec_from_file_location('prior_elf_reader', support)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data = binary.read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity')
    image = module.Image(data)
    sections = {row['name']: row for row in module.sections(data)}
    _, frames = module.eh_frame_records(data, list(sections.values()))
    expected = read('NATIVE-INTAKE.json')
    export_pins = []
    for function in expected['functions']:
        lo, hi = int(function['start'], 16), int(function['end'], 16)
        matches = [row for row in frames if row['start'] <= lo < row['end']]
        require(len(matches) == 1 and matches[0]['start'] == lo and matches[0]['end'] == hi, 'unique exact FDE')
        found = matches[0]
        require(sha(image.read(lo, hi - lo)) == function['sha256'], 'complete body hash')
        require(image.record(found['fde']) == function['fde_hex'] and image.record(found['cie']) == function['cie_hex'], 'FDE/CIE bytes')
        require((None if found['lsda'] is None else hex(found['lsda'])) == function['lsda'], 'LSDA identity')
        directory = 'RE-006-fixed-n21-delegate-rust-94/seed' if lo == 0x4918D30 else 'RE-006-n21-outer-admission-rust-94'
        partitions = []
        for tool in ['gnu', 'llvm']:
            path = ROOT / 'research/work-items' / directory / f'{lo:x}.{tool}.txt'
            raw = path.read_bytes()
            rows, cursor = [], lo
            for line in raw.decode().splitlines():
                match = module.LINE.match(line)
                if match:
                    at, code = int(match[1], 16), bytes.fromhex(match[2])
                    require(at == cursor and image.read(at, len(code)) == code, 'full export partition')
                    rows.append((at, code));cursor += len(code)
            require(cursor == hi and len(rows) == function['instructions'], 'complete export denominator')
            partitions.append(rows)
            export_pins.append(dict(path=str(path.relative_to(ROOT)), bytes=len(raw), sha256=sha(raw)))
        require(partitions[0] == partitions[1], 'GNU/LLVM partition equality')
    rela = sections['.rela.dyn']
    relocations = [struct.unpack_from('<QQq', data, at) for at in range(rela['offset'], rela['offset'] + rela['size'], 24)]
    for row in expected['relocation_bindings']:
        slot, info, addend = int(row['slot'], 16), int(row['info'], 16), int(row['addend'], 16)
        require([item for item in relocations if item[0] == slot] == [(slot, info, addend)], 'unique exact relocation')
    for at in [0x4DBDA2F, 0x4DBD87E]:
        raw = image.read(at, 6)
        require(raw[:2] == b'\xff\x15' and at + 6 + struct.unpack('<i', raw[2:])[0] == 0x576DFE0, 'selected dynamic copy edge')
    version = read('VERSION-BINDING.json')
    for field in ['dynsym', 'gnu_version']:
        raw = bytes.fromhex(version[field + '_hex']);at = version[field + '_file_offset']
        require(data[at:at + len(raw)] == raw, 'symbol/version exact bytes')
    for binding in version['bindings']:
        for field in ['verneed', 'vernaux']:
            raw = bytes.fromhex(binding[field + '_hex']);at = binding[field + '_file_offset']
            require(data[at:at + len(raw)] == raw, 'GNU version binding bytes')
    require(version['symbol'] == 'memcpy' and version['bindings'][0]['library'] == 'libc.so.6' and version['bindings'][0]['version'] == 'GLIBC_2.14', 'explicit dynamic boundary')
    controls = read('PRE-SOURCE-NATIVE-CONTROLS.json')['controls']
    result = read('STATIC-CONTROL-RESULTS.json')
    require(len(controls) == len(result['controls']) == 12 and result['actual_decoder_processes'] == 48, 'static control denominator')
    require(result['control_erratum_sha256'] == sha((HERE / 'CONTROL-ERRATUM.json').read_bytes()), 'unsafe-control erratum linked')
    archive = read('RAW-COMPARISONS.json')['members']
    for control, observations in zip(controls, result['controls']):
        require(control['name'] == observations['name'], 'control order/name')
        at = int(control['va'], 16);before, after = bytes.fromhex(control['before']), bytes.fromhex(control['after'])
        require(image.read(at, len(before)) == before and len(after) == len(before) and before != after, 'control anchor/width')
        require(not observations['counted_as_array_output_control'], 'no native executed-array control')
        for observed in observations['observations']:
            for tool in ['gnu', 'llvm']:
                for channel in ['stdout', 'stderr']:
                    name = '.'.join([control['name'], observed['kind'], tool, channel])
                    raw = unbundle(archive['native/static-control-run/' + name])
                    require(sha(raw) == observed[tool + '_' + channel + '_sha256'], 'actual fragment raw channel binding')
                    if channel == 'stderr':
                        require(not raw, 'decoder stderr')
        a, b = observations['observations']
        require(a['gnu'] != b['gnu'] and a['llvm'] != b['llvm'], 'operative finite operand distinctions')
    freeze = read('PRE-SOURCE-FREEZE.json')
    require(sha((HERE / 'PRE-SOURCE-FREEZE.json').read_bytes()) == '6e83dde660d28198ce140eae49b615cdae66c0ccec5e8be3fb9536d1eaabe65c', 'unchanged pre-source arrays')
    for row in freeze['cases']:
        source = row['source21'];ascending = source[1] >= source[0]
        run = next((i for i in range(2, 21) if not (source[i] >= source[i-1] if ascending else source[i] < source[i-1])), 21)
        require(run == 20 and row['source21_final'] == sorted(source), 'independent natural domain/math output')
        normalized = (source[:20] if ascending else source[:20][::-1]) + source[20:]
        rank = sum(value <= source[20] for value in normalized[:20])
        require(normalized == row['post_normalization21'] and rank == row['upper_bound_index'], 'normalization/unsigned rank')
        require(row['loop_store_count'] == min(20, 21 - rank) and row['copy_calls'][1]['bytes'] == (8 if rank == 0 else 0), 'exhaustion/copy boundary')
    return dict(target_sha256=TARGET, complete_fde_bodies=4, primary_bytes=4340, instructions=1112,
                reused_full_export_pins=export_pins, frozen_cases=48, static_controls=12,
                original_fragment_processes=48, retained_fragment_channels=96,
                captured_execution=False, instruction_evaluation=False,
                limits='Replay authenticates target bytes and retained decoder/math evidence. It does not execute node, dynamically resolve memcpy, establish provider frame/identity or assert original ABI/runtime equality.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), 'fresh output required')
    result = verify(args.binary)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print('PASS4completeFDEs/1112instructions/48frozenarrays/12retainedstaticcontrols; dynamicmemcpy remains premise; no captured execution')
