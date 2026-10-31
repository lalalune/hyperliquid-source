#!/usr/bin/env python3
"""Read-only #94/#115 comparison of two named struct-variant decoders."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

PACKET = ROOT / 'research/work-items/RE-014-settled-request-fields'
TARGETS = {
    '94': (91774280, '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'),
    '115': (105896032, 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'),
}
# name, start, end, diagnostic slot, string VA, slot-LEA instruction
VARIANTS = {
    '94': [('SettledOutcome', 0x2051140, 0x20519b4, 0x569abf0, 0x3d1e6f, 0x2051210),
           ('SettledQuestion', 0x2076950, 0x20771c4, 0x569ac00, 0x3d1eac, 0x2076a20)],
    '115': [('SettledOutcome', 0x1fb7530, 0x1fb81dd, 0x642b238, 0x5e5755, 0x1fb75fe),
            ('SettledQuestion', 0x1fc5470, 0x1fc611d, 0x642b308, 0x5e5a72, 0x1fc553e)],
}
# MOVABS pairs compare [key+0:key+8] and [key+3:key+11].
KEY_PAIRS = [(0x1fb7925, 0x1fb7936), (0x1fb7ae0, 0x1fb7af1),
             (0x1fc585f, 0x1fc5870), (0x1fc5a20, 0x1fc5a31)]
# Additional scalar key comparisons are exported but not modeled as a parser.
FLAG_CONTROLS = {
    0x1fb76ef: '41b502', 0x1fb79bc: '4180fd02',
    0x1fb7c87: '4180e501', 0x1fb7c9c: '44886d10',
    0x1fc562f: '41b502', 0x1fc58fc: '4180fd02',
    0x1fc5bc7: '4180e501', 0x1fc5bdc: '44886d10',
    0x1fb77fa: '4883ff0b', 0x1fb7830: '4883ff0b',
    0x1fc573a: '4883ff0b', 0x1fc5768: '4883ff0b',
    0x1fb7948: 'b001',
    0x1fb79a6: '0fb684248100000083f802746d83f8010f85b40000004180fd020f857d0600000fb68424a0000000c68424a0000000163c160f843a060000488d8c24a10000000f10010f10490f488d4c24510f11490f0f11018844245084c00f85ac060000440fb66c2451',
    0x1fc58e6: '0fb684248100000083f802746d83f8010f85b40000004180fd020f857d0600000fb68424a0000000c68424a0000000163c160f843a060000488d8c24a10000000f10010f10490f488d4c24510f11490f0f11018844245084c00f85ac060000440fb66c2451',
}


def read(data, va, count):
    mapped = [s['offset'] + va - s['address'] for s in sections(data)
              if s['type'] != 8 and s['address'] <= va
              and va + count <= s['address'] + s['size']]
    if len(mapped) != 1:
        raise ValueError('expected unique file-backed mapping')
    off = mapped[0]
    return off, bytes(data[off:off + count])


def overlapping_key_match(key, low, high):
    """Conditional 11-byte equality obligation, not a whole decoder execution."""
    if len(key) != 11:
        return False
    return (int.from_bytes(key[:8], 'little') ^ low) | (int.from_bytes(key[3:], 'little') ^ high) == 0


def analyze(data94, data115):
    records = {}
    for release, data in [('94', data94), ('115', data115)]:
        _, frames, _ = fde_extents(data)
        sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
        rels = {a: (i, v) for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']])}
        count = 1 if release == '94' else 2
        rows = []
        for name, start, end, slot, string_va, site in VARIANTS[release]:
            matches = [f for f in frames if (f['start'], f['end']) == (start, end)]
            if len(matches) != 1:
                raise ValueError('variant FDE changed')
            diagnostic = f'struct variant NodeInfoRequest::{name} with {count} element' + ('s' if count != 1 else '')
            if rels.get(slot) != (8, string_va) or read(data, slot + 8, 8)[1] != struct.pack('<Q', len(diagnostic)):
                raise ValueError('diagnostic fat-string relocation or length changed')
            if read(data, string_va, len(diagnostic))[1] != diagnostic.encode():
                raise ValueError('variant diagnostic changed')
            raw = read(data, site, 7)[1]
            if raw[:3] != b'\x48\x8d\x35' or site + 7 + struct.unpack_from('<i', raw, 3)[0] != slot:
                raise ValueError('diagnostic slot xref changed')
            off, body = read(data, start, end - start)
            frame = matches[0]
            frame_raw = {}
            for key in ['fde', 'cie']:
                va = frame[key]
                n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
                frame_raw[key] = {'va': hex(va), 'bytes_hex': read(data, va, n)[1].hex()}
            rows.append({'name': name, 'start': hex(start), 'end': hex(end), 'bytes': len(body),
                         'file_offset': hex(off), 'body_sha256': hashlib.sha256(body).hexdigest(),
                         'diagnostic': diagnostic, 'diagnostic_va': hex(string_va), 'slot': hex(slot),
                         'diagnostic_lea_site': hex(site), 'diagnostic_lea_hex': raw.hex(),
                         'frame_records': frame_raw})
        records[release] = {'target_sha256': TARGETS[release][1], 'variants': rows}
    pairs = []
    for first, second in KEY_PAIRS:
        raw1, raw2 = read(data115, first, 10)[1], read(data115, second, 10)[1]
        if raw1[:2] != b'\x48\xb9' or raw2[:2] != b'\x48\xba':
            raise ValueError('key comparison MOVABS changed')
        low, high = struct.unpack_from('<Q', raw1, 2)[0], struct.unpack_from('<Q', raw2, 2)[0]
        left, right = low.to_bytes(8, 'little'), high.to_bytes(8, 'little')
        if left[3:] != right[:5] or left + right[5:] != b'only_use_db':
            raise ValueError('additional key spelling or overlap changed')
        pairs.append({'first': hex(first), 'second': hex(second), 'low': hex(low), 'high': hex(high),
                      'first_hex': raw1.hex(), 'second_hex': raw2.hex(), 'decoded_key': 'only_use_db'})
    for va, value in FLAG_CONTROLS.items():
        if read(data115, va, len(bytes.fromhex(value)))[1] != bytes.fromhex(value):
            raise ValueError('field selector or flag control changed')
    return {'releases': records, 'additional_key_pairs_115': pairs,
            'flag_controls_115': {hex(a): v for a, v in FLAG_CONTROLS.items()},
            'local_missing_flag': {'initial_raw_byte': 2, 'normal_output': 'raw byte AND 1 at output + 0x10'},
            'captured_binaries_executed': False,
            'limits': 'Two named struct-variant decoders per release. Cardinality diagnostics and selected #115 key/flag obligations, not a recovered request API, complete parser/codec, router reachability, JSON acceptance oracle or runtime equivalence. No gates.'}


def generate(paths, output):
    data = {release: paths[release].read_bytes() for release in TARGETS}
    for release, raw in data.items():
        size, digest = TARGETS[release]
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'expected pinned node{release}')
    result = analyze(data['94'], data['115'])
    output.mkdir(parents=True, exist_ok=True)
    all_frames = []
    with tempfile.TemporaryDirectory() as directory:
        for release in TARGETS:
            snapshot = Path(directory) / f'node{release}.elf'
            snapshot.write_bytes(data[release])
            frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
            for name, start, end, _slot, _string, site in VARIANTS[release]:
                chosen = [line for line in frames.splitlines() if f'pc={start:016x}..{end:016x}' in line]
                if len(chosen) != 1:
                    raise ValueError('native variant FDE confirmation failed')
                all_frames.append(f'{release} {name} {chosen[0]}')
                asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                              f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
                ins = decode_export(asm, start, end, read(data[release], start, end - start)[1])
                controls = {site}
                if release == '115':
                    controls |= {v for v in FLAG_CONTROLS if start <= v < end}
                    controls |= {v for pair in KEY_PAIRS for v in pair if start <= v < end}
                if not controls <= set(ins):
                    raise ValueError('selected obligations must start actual decoded instructions')
                (output / f'{release}-{name}.objdump.txt').write_text(asm.replace(str(snapshot), f'<authenticated-node{release}>'))
    (output / 'frames.txt').write_text('\n'.join(all_frames) + '\n')
    (output / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node94', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--node115', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT / 'work/request-variant-drift')
    args = parser.parse_args()
    result = generate({'94': args.node94, '115': args.node115}, args.output)
    print(json.dumps({'releases': list(result['releases']), 'executed': False}))
