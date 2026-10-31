#!/usr/bin/env python3
"""Authenticate two releases and export five action-structure metadata changes."""
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

PACKET = ROOT / 'research/work-items/RE-014-action-field-drift'
SPEC_SHA = 'c19746f2ad71a2ea6d67caa0a69eef6f98781a007c95789fc1ddfbebf794ab23'
EXPECTED_FIELDS = {'CancelAction': ['cancels', 'f'], 'CancelByCloidAction': ['cancels', 'f'],
                   'BatchModifyAction': ['modifies', 'a'], 'TwapOrderAction': ['twap', 'details'],
                   'ReserveRequestWeightAction': ['weight', 'destination']}


def specification():
    raw = (PACKET / 'spec.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != SPEC_SHA:
        raise ValueError('retained coordinate spec changed')
    return json.loads(raw)


def read(data, secs, va, size):
    offsets = [s['offset'] + va - s['address'] for s in secs
               if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    if len(offsets) != 1:
        raise ValueError('expected unique file-backed mapping')
    off = offsets[0]
    return off, bytes(data[off:off + size])


def analyze(inputs):
    spec = specification()
    result = {'releases': {}, 'captured_binaries_executed': False}
    for release, item in spec.items():
        data = inputs[release]
        secs = sections(data)
        _, frames, _ = fde_extents(data)
        frame_map = {(f['start'], f['end']): f for f in frames}
        sec = next(s for s in secs if s['name'] == '.rela.dyn')
        rels = {a: (i, v) for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']])}
        rd = lambda va, n: read(data, secs, va, n)[1]
        rows = {}
        for name, variant in item['variants'].items():
            count = 1 if release == '94' else 2
            diagnostic = f'struct {name} with {count} element' + ('' if count == 1 else 's')
            va, slot = int(variant['diagnostic_va'], 16), int(variant['slot'], 16)
            if diagnostic != variant['text'] or rd(va, len(diagnostic)) != diagnostic.encode():
                raise ValueError('action diagnostic changed')
            if rels.get(slot) != (8, va) or rd(slot + 8, 8) != struct.pack('<Q', len(diagnostic)):
                raise ValueError('action diagnostic relocation/length changed')
            owners = []
            for owner in variant['owners']:
                start, end = int(owner['start'], 16), int(owner['end'], 16)
                if (start, end) not in frame_map:
                    raise ValueError('action owner FDE changed')
                site = int(owner['diagnostic_lea'], 16)
                raw = rd(site, 7)
                if raw.hex() != owner['diagnostic_lea_hex'] or site + 7 + struct.unpack_from('<i', raw, 3)[0] != slot:
                    raise ValueError('action diagnostic LEA changed')
                for c in owner['field_consumers']:
                    if c['keys'] != EXPECTED_FIELDS[name]:
                        raise ValueError('unexpected field-name association')
                    for key in ['lea', 'count_site', 'call_site']:
                        expected = bytes.fromhex(c[{'lea': 'lea_hex', 'count_site': 'count_hex', 'call_site': 'call_hex'}[key]])
                        if rd(int(c[key], 16), len(expected)) != expected:
                            raise ValueError('action field/count/call instruction changed')
                    at, table = int(c['lea'], 16), int(c['table'], 16)
                    if at + 7 + struct.unpack_from('<i', rd(at, 7), 3)[0] != table:
                        raise ValueError('action field table target changed')
                    call = int(c['call_site'], 16)
                    if call + 5 + struct.unpack_from('<i', rd(call, 5), 1)[0] != int(c['call_target'], 16):
                        raise ValueError('action field consumer target changed')
                    for entry in c['entries']:
                        a, string_va, length = int(entry['slot'], 16), int(entry['string_va'], 16), entry['length']
                        if rels.get(a) != (8, string_va) or rd(a + 8, 8) != struct.pack('<Q', length):
                            raise ValueError('action field relocation/length changed')
                        if rd(string_va, length) != entry['text'].encode():
                            raise ValueError('action field name changed')
                off, body = read(data, secs, start, end - start)
                f = frame_map[(start, end)]
                raw_frames = {}
                for kind in ['fde', 'cie']:
                    a = f[kind]
                    n = struct.unpack('<I', rd(a, 4))[0] + 4
                    raw_frames[kind] = {'va': hex(a), 'bytes_hex': rd(a, n).hex()}
                owners.append({**owner, 'file_offset': hex(off), 'bytes': len(body),
                               'sha256': hashlib.sha256(body).hexdigest(), 'frame_records': raw_frames})
            if len(owners) != 2:
                raise ValueError('expected two observed diagnostic owners per action')
            rows[name] = {'diagnostic': diagnostic, 'diagnostic_va': hex(va), 'slot': hex(slot),
                          'diagnostic_element_count': count, 'owners': owners}
        result['releases'][release] = {'target_sha256': item['sha256'], 'target_bytes': item['bytes'], 'variants': rows}
    result['limits'] = 'Named struct diagnostics and selected #115 two-entry field-list consumers. No complete value codec, old unknown-field policy, field defaults/requiredness, tuple/wire order, Rust ABI, signing/dispatch/HTTP reachability, helper/unwind closure or runtime equivalence. No gates.'
    return result


def generate(paths, output):
    spec = specification()
    data = {r: paths[r].read_bytes() for r in spec}
    for release, item in spec.items():
        raw = data[release]
        if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise ValueError(f'expected pinned node{release}')
    result = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    frames_out = []
    with tempfile.TemporaryDirectory() as directory:
        for release, item in result['releases'].items():
            snapshot = Path(directory) / f'node{release}.elf'
            snapshot.write_bytes(data[release])
            frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
            secs = sections(data[release])
            for name, variant in item['variants'].items():
                for owner in variant['owners']:
                    start, end = int(owner['start'], 16), int(owner['end'], 16)
                    chosen = [line for line in frames.splitlines() if f'pc={start:016x}..{end:016x}' in line]
                    if len(chosen) != 1:
                        raise ValueError('native action FDE confirmation failed')
                    frames_out.append(f'{release} {name} {chosen[0]}')
                    asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                                  f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
                    ins = decode_export(asm, start, end, read(data[release], secs, start, end - start)[1])
                    required = {int(owner['diagnostic_lea'], 16)}
                    for c in owner['field_consumers']:
                        required |= {int(c[k], 16) for k in ['lea', 'count_site', 'call_site']}
                    if not required <= set(ins):
                        raise ValueError('selected action sites must be actual decoded instruction starts')
                    owner['decoded_instructions'] = len(ins)
                    (output / f'{release}-{name}-{start:x}.objdump.txt').write_bytes(asm.replace(str(snapshot), f'<authenticated-node{release}>').encode('utf-8'))
    (output / 'frames.txt').write_bytes(('\n'.join(frames_out) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes((json.dumps(result, indent=2) + '\n').encode('utf-8'))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node94', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--node115', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT / 'work/action-field-drift')
    args = parser.parse_args()
    result = generate({'94': args.node94, '115': args.node115}, args.output)
    owners = [o for r in result['releases'].values() for v in r['variants'].values() for o in v['owners']]
    print(json.dumps({'functions': len(owners), 'bytes': sum(o['bytes'] for o in owners),
                      'instructions': sum(o['decoded_instructions'] for o in owners), 'executed': False}))
