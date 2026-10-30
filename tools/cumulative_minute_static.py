#!/usr/bin/env python3
"""RE-001 node94 cumulative-minute conversion sites; no target execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import prove_division, decode_export

TARGET = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-cumulative-minute-94'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES = [(0x26ff460, 0x27000a2), (0x2700390, 0x2701d93),
          (0x4925220, 0x4925f0c), (0x4925f10, 0x4926dac),
          (0x4ce8b40, 0x4ce9662), (0x4ce9670, 0x4cea192),
          (0x4cea760, 0x4cec25c), (0x4cec260, 0x4cedcc9)]


def read(data, va, size):
    matches = [s['offset'] + va - s['address'] for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected one file-backed mapping')
    off = matches[0]
    return off, bytes(data[off:off + size])


def ripple(raw, va, prefix):
    if not raw.startswith(prefix):
        raise ValueError('RIP instruction changed')
    return va + len(prefix) + 4 + struct.unpack_from('<i', raw, len(prefix))[0]


def arithmetic_constants(raw):
    # Admission below pins each complete selected instruction window. These
    # immediates then supply the proof, rather than separately invented values.
    constants = []
    for value in (0x91a2b3c5, 0x88888889, 0x08888889):
        needle = struct.pack('<I', value)
        if raw.count(needle) != 1:
            raise ValueError('reciprocal immediate changed')
        constants.append(struct.unpack_from('<I', raw, raw.index(needle))[0])
    return constants


def analyze(data, spec=None):
    spec = json.loads((PACKET / 'selected-windows.json').read_text()) if spec is None else spec
    _, frames, _ = fde_extents(data)
    if not set(RANGES) <= {(f['start'], f['end']) for f in frames}:
        raise ValueError('actual FDE changed')
    if [(int(r['start'], 16), int(r['end'], 16)) for r in spec] != RANGES:
        raise ValueError('selected range records changed')
    message = b'assertion failed: cumin <= 1440'
    path = b'/home/ubuntu/hl/code_Mainnet/base/src/cumin.rs'
    if read(data, 0x21adef, 31)[1] != message or read(data, 0x1e3851, 46)[1] != path:
        raise ValueError('diagnostic/path changed')
    if read(data, 0x566cb58, 16)[1] != struct.pack('<QII', 46, 21, 13):
        raise ValueError('source Location changed')
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    rels = {a: (i, v) for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']])}
    if rels.get(0x566cb50) != (8, 0x1e3851) or rels.get(0x576e108) != (8, 0x157b7f0):
        raise ValueError('Location/helper binding changed')
    blocks, ranges, constants = [], [], []
    for row, (start, end) in zip(spec, RANGES):
        off, body = read(data, start, end - start)
        ranges.append({'start_va': hex(start), 'end_va': hex(end), 'file_offset': hex(off),
                       'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
        panic = int(row['panic'], 16)
        raw = bytes.fromhex(row['panic_hex'])
        if read(data, panic, len(raw))[1] != raw:
            raise ValueError('panic block changed')
        if (ripple(raw, panic, b'\x48\x8d\x3d') != 0x21adef
                or ripple(raw[7:], panic + 7, b'\x48\x8d\x15') != 0x566cb50
                or raw[14:19] != b'\xbe\x1f\0\0\0'
                or ripple(raw[19:], panic + 19, b'\xff\x15') != 0x576e108):
            raise ValueError('assertion arguments/call changed')
        for block in row['blocks']:
            va = int(block['start'], 16)
            raw = bytes.fromhex(block['body_hex'])
            if read(data, va, len(raw))[1] != raw:
                raise ValueError('selected conversion changed')
            if not start <= va < va + len(raw) <= end or raw[-6:-4] != b'\x0f\x83':
                raise ValueError('window extent or unsigned assertion edge changed')
            target = va + len(raw) + struct.unpack('<i', raw[-4:])[0]
            if target != panic:
                raise ValueError('assertion branch not bound to panic block')
            constants.append(arithmetic_constants(raw))
            blocks.append({'start_va': hex(va), 'end_va': hex(va + len(raw)),
                           'body_hex': raw.hex(), 'assertion_block_va': hex(panic),
                           'assembly': block['assembly']})
    if len(blocks) != 14 or any(c != constants[0] for c in constants):
        raise ValueError('selected conversion denominator/constants changed')
    c0, c1, c2 = constants[0]
    proofs = [prove_division(c0, 43, 3600, (1 << 32) - 1),
              prove_division(c1, 37, 60, (1 << 32) - 1),
              prove_division(c2, 33, 60, ((1 << 32) - 1) // 60)]
    return {'target_sha256': SHA256, 'ranges': ranges, 'conversions': blocks,
            'source_location': {'slot': '0x566cb50', 'path': path.decode(), 'line': 21, 'column': 13},
            'diagnostic': {'va': '0x21adef', 'bytes': 31, 'literal': message.decode()},
            'assertion_call': {'slot': '0x576e108', 'relative_addend': '0x157b7f0'},
            'division_proofs': proofs,
            'result': '60*floor(n/3600) + floor(n/60) - 60*floor(floor(n/60)/60) = floor(n/60), for every u32 n',
            'guard_order': ['unsigned result > 65535', 'unsigned result >= 1441'],
            'local_raw_u32_domains': {'both_guards_pass': [0, 86459],
                                      'cumin_assertion': [86460, 3932159],
                                      'earlier_narrowing_failure': [3932160, (1 << 32) - 1]},
            'captured_binary_executed': False,
            'limits': 'Eight selected FDEs / fourteen conversions tied to one Location. Not a complete function or caller census, concrete time type, reachable-state proof, helper closure or runtime equivalence.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('expected pinned node94')
    report = analyze(data)
    spec = json.loads((PACKET / 'selected-windows.json').read_text())
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node94.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        selected = [line for line in frames.splitlines() if any(f'pc={a:016x}..{b:016x}' in line for a, b in RANGES)]
        if len(selected) != len(RANGES):
            raise ValueError('native FDE validation failed')
        (output / 'frames.txt').write_text('\n'.join(selected) + '\n')
        for row, (start, end) in zip(spec, RANGES):
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                          f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
            ins = decode_export(asm, start, end, read(data, start, end - start)[1])
            # Validate every retained conversion instruction from native decoding,
            # not a decode begun at a raw byte-pattern candidate.
            lines = {}
            for match in re.finditer(r'^\s*([0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)+\s*(.*)', asm, re.M):
                lines[int(match[1], 16)] = ' '.join(match[2].split()).split(' <')[0]
            for block in row['blocks']:
                va = int(block['start'], 16)
                stop = va + len(bytes.fromhex(block['body_hex']))
                actual = [lines[a] for a in ins if va <= a < stop]
                if actual != block['assembly']:
                    raise ValueError('native conversion instruction sequence changed')
            if int(row['panic'], 16) not in ins:
                raise ValueError('panic block is not a decoded instruction start')
            (output / f'{start:x}.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/cumulative-minute-94')
    args = parser.parse_args()
    print(json.dumps({'ranges': len(generate(args.binary, args.output)['ranges']), 'executed': False}))
