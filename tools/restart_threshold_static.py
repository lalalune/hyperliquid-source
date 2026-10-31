#!/usr/bin/env python3
"""Bind node94 restart-threshold global template and unsigned return floor."""
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

TARGET = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-restart-threshold-94'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES = [(0x13ca000, 0x13ca0d5), (0x144b900, 0x144bfcb)]
# Selected decoded obligations, not a generic decompiler or full parser model.
CONTROLS = {
    0x13ca007: '488b1d1a493a048b435085c0756d',
    0x13ca015: '4883c31848891c24488d056c0001004889442408',
    0x13ca029: '488d355f46e1fe488d7c24104889e2ff1502403a04',
    0x13ca03e: '488b5c2418488b742420488d1531cb29044889dfe8a9180800',
    0x13ca057: '488b7424104885f674114889df31d24889c3ff15a13f3a044889d8',
    0x13ca072: '4883f8014883d0004883c4285b415ec3',
    0x13ca0aa: 'ff1508483a04e960ffffff',
    0x144b90e: '4889f24889fe',
    0x144bcdb: '488d7c2428e8cb2505004889c14889d0f6c1010f8432010000',
    0x144bd9d: '488b7424684885f6740d488b7c247031d2ff155c223204488b034889dfff1031c0',
    0x144be0f: 'e8ace2f5ff80bc2480000000097547488b842488000000',
    0x144be26: '4d85f674144c89ff4c89f631d24889c3ff15d42132044889d8',
}
RELATIVE = {0x576e928: 0x577b288, 0x576e040: 0x1344760,
            0x576e010: 0x54c8cb0, 0x576e8b8: 0x4ee3b20,
            0x5666b80: 0x1ef2de, 0x5666a68: 0x1f87cf}
TEMPLATE = b'\xc0\x29/hyperliquid_data/n_restarts_to_page.json\0'


def read(data, va, size):
    matches = [s['offset'] + va - s['address'] for s in sections(data)
               if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected unique file-backed mapping')
    off = matches[0]
    return off, bytes(data[off:off + size])


def return_floor(value):
    """Conditional CMP RAX,1; ADC RAX,0, for a raw returned u64."""
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError('expected unsigned 64-bit return word')
    return value + int(value < 1)


def analyze(data):
    _, frames, _ = fde_extents(data)
    for start, end in RANGES:
        if sum((f['start'], f['end']) == (start, end) for f in frames) != 1:
            raise ValueError('restart FDE changed')
    for va, value in CONTROLS.items():
        raw = bytes.fromhex(value)
        if read(data, va, len(raw))[1] != raw:
            raise ValueError(f'restart instruction changed at {va:#x}')
    if read(data, 0x1de68f, len(TEMPLATE))[1] != TEMPLATE:
        raise ValueError('restart template changed')
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    rels = {a: (i, v) for a, i, v in struct.iter_unpack('<QQq',
            data[sec['offset']:sec['offset'] + sec['size']])}
    if any(rels.get(a) != (8, v) for a, v in RELATIVE.items()):
        raise ValueError('restart relocation changed')
    frame_records = []
    for start, end in RANGES:
        f = next(f for f in frames if (f['start'], f['end']) == (start, end))
        raw = {}
        for key in ['fde', 'cie']:
            va = f[key]
            length = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            raw[key] = {'va': hex(va), 'bytes_hex': read(data, va, length)[1].hex()}
        frame_records.append(raw)
    locations = []
    for slot, path, line, column in [
        (0x5666b80, '/home/ubuntu/hl/code_Mainnet/base/src/u.rs', 549, 5),
        (0x5666a68, '/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sync/once.rs', 219, 20),
    ]:
        if read(data, RELATIVE[slot], len(path))[1] != path.encode() or read(data, slot + 8, 16)[1] != struct.pack('<QII', len(path), line, column):
            raise ValueError('restart Location changed')
        locations.append({'slot': hex(slot), 'path': path, 'line': line, 'column': column})
    ranges = []
    for start, end in RANGES:
        off, body = read(data, start, end - start)
        ranges.append({'start': hex(start), 'end': hex(end), 'bytes': len(body),
                       'file_offset': hex(off), 'sha256': hashlib.sha256(body).hexdigest()})
    return {'target_sha256': SHA, 'ranges': ranges,
            'frame_records': frame_records,
            'template': {'va': '0x1de68f', 'bytes_hex': TEMPLATE.hex(),
                         'argument_storage': 'relocated global + 0x18', 'argument_formatter': '0x13da090'},
            'wrapper_input': 'no incoming argument register read before overwrite',
            'global': {'slot': '0x576e928', 'addend': '0x577b288', 'state_offset': '0x50'},
            'reader_call': {'site': '0x13ca052', 'target': '0x144b900',
                            'result': 'raw RAX; no Result tag check in wrapper'},
            'return_rule': 'n + (n < 1), unsigned 64-bit; exactly max(1,n)',
            'reader_error_route': {'callback_site': '0x144bdba', 'zero_if_callback_returns': '0x144bdbc'},
            'locations': locations,
            'relative_bindings': {hex(a): hex(v) for a, v in RELATIVE.items()},
            'instruction_controls': {hex(a): v for a, v in CONTROLS.items()},
            'captured_binary_executed': False,
            'limits': 'No file read or captured execution. Concrete global/root type, rendered path, parser/IO/callback closure, all callers, reachability and runtime equivalence unresolved. Reader source Location is materialized by wrapper; entry overwrites RDX, so not claimed consumed. No gate.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('expected pinned node94')
    result = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node94.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        chosen = []
        for start, end in RANGES:
            lines = [line for line in frames.splitlines() if f'pc={start:016x}..{end:016x}' in line]
            if len(lines) != 1:
                raise ValueError('native FDE confirmation failed')
            chosen += lines
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                          f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
            ins = decode_export(asm, start, end, read(data, start, end - start)[1])
            if not {v for v in CONTROLS if start <= v < end} <= set(ins):
                raise ValueError('controls must be actual decoded instruction starts')
            (output / f'{start:x}.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
        (output / 'frames.txt').write_text('\n'.join(chosen) + '\n')
    (output / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/restart-threshold-94')
    args = parser.parse_args()
    print(json.dumps({'ranges': generate(args.binary, args.output)['ranges'], 'executed': False}))
