#!/usr/bin/env python3
"""RE-001: node94 post-delegate forward end check, not ASCII pre-trimming."""
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
PACKET = ROOT / 'research/work-items/RE-001-json-trailing-admission-94'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES = [(0x15ba010, 0x15ba1c8), (0x1611910, 0x1615281)]
CONTROLS = {
    0x15ba01a: "4889fb488974241848895424200f57c00f114424284889742438488954244048c704240000000048c74424080100000048c744241000000000c6442448804889e6e8306d0000",
    0x15ba060: "49be01000000000000804c39330f84a3000000",
    0x15ba0bd: "488b442420488b4c24284839c1734a488b54241848f7d848ffc148be0026000001000000",
    0x15ba0f0: "0fb67c0aff4883ff20773f480fa3fe733948894c2428488d3c0848ffc748ffc14883ff0175da",
    0x15ba12c: "4889d84881c4d80000005b415ec3",
    0x15ba13a: "48c78424c0000000160000004889e7488db424c0000000e83aedffff488943084c8933",
    0x1613dfd: "488d7c24704889ee4c89f2e80362faff488b442470488d4b014839c80f8573020000",
}
DIRECT = {0x15ba05b: 0x15c0d90, 0x15ba151: 0x15b8e90,
          0x15ba18d: 0x15bcf70, 0x15ba19a: 0x15bdc60,
          0x15ba1c3: 0x5660110, 0x1613e08: 0x15ba010}


def read(data, va, size):
    found = [s['offset'] + va - s['address'] for s in sections(data) if s['type'] != 8
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('expected one file-backed mapping')
    off = found[0]
    return off, bytes(data[off:off + size])


def conditional_tail(suffix, mask=0x100002600, maximum=32):
    """Abstract post-delegate suffix check; no JSON parsing or captured execution."""
    consumed = 0
    for byte in suffix:
        if byte > maximum or not (mask & (1 << byte)):
            return {'consumed': consumed, 'local_error_code': 0x16}
        consumed += 1
    return {'consumed': consumed, 'local_error_code': None}


def analyze(data):
    _, frames, _ = fde_extents(data)
    if not set(RANGES) <= {(f['start'], f['end']) for f in frames}:
        raise ValueError('selected FDE changed')
    for va, value in CONTROLS.items():
        raw = bytes.fromhex(value)
        if read(data, va, len(raw))[1] != raw:
            raise ValueError(f'end-check instruction changed at {va:#x}')
    for va, expected in DIRECT.items():
        raw = read(data, va, 5)[1]
        if raw[0] != 0xe8 or va + 5 + struct.unpack_from('<i', raw, 1)[0] != expected:
            raise ValueError('direct helper/caller edge changed')
    mask = struct.unpack('<Q', read(data, 0x15ba0d9, 8)[1])[0]
    maximum = read(data, 0x15ba0f8, 1)[1][0]
    if mask != 0x100002600 or maximum != 32:
        raise ValueError('end-check mask/bound changed')
    rows = []
    for start, end in RANGES:
        off, body = read(data, start, end - start)
        rows.append({'start_va': hex(start), 'end_va': hex(end), 'file_offset': hex(off),
                     'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
    return {'target_sha256': SHA256, 'ranges': rows,
            'input_and_cursor_state': {'original_pointer_offset': '0x18', 'original_length_offset': '0x20',
                                       'cursor_offset': '0x28', 'initial_cursor': 0},
            'initial_delegate': {'site': '0x15ba05b', 'target': '0x15c0d90', 'state_rsi': 'rsp'},
            'result_skip_sentinel': '0x8000000000000001',
            'tail_check': {'mask': hex(mask), 'unsigned_maximum': maximum,
                           'accepted_bytes': [b for b in range(256) if b <= maximum and mask & (1 << b)],
                           'load_site': '0x15ba0f0', 'cursor_store_site': '0x15ba101',
                           'non_whitespace_branch': '0x15ba13a', 'local_error_code': '0x16',
                           'error_helper': '0x15b8e90', 'out_error_pointer_offset': '0x8'},
            'reference_correction': {'lead': 'base/http_client.rs parse_json_rpc_response',
                                     'observed_order': 'initial delegate first, then forward cursor end check',
                                     'not_established': 'backwards ASCII-whitespace pre-trim before delegate',
                                     'form_feed_0x0c': 'excluded by observed mask, included by stamped Rust u8::is_ascii_whitespace'},
            'selected_caller': {'site': '0x1613e08', 'output_rdi': 'rsp+0x70',
                                'input_rsi': 'rbp', 'length_rdx': 'r14'},
            'direct_targets': {hex(a): hex(v) for a, v in DIRECT.items()},
            'instruction_controls': {hex(a): v for a, v in CONTROLS.items()},
            'captured_binary_executed': False,
            'limits': 'One 440-byte wrapper and one selected caller edge. The full enclosing 14705-byte caller is decoded for boundaries, not recovered. Initial parser semantics, concrete response/result types, error enum name, cleanup helpers, all callers and whole-parser acceptance/equivalence are unproved. Tail model assumes a non-sentinel initial result and valid cursor <= length.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('expected pinned node94')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node94.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        chosen = [line for line in frames.splitlines() if any(f'pc={a:016x}..{b:016x}' in line for a, b in RANGES)]
        if len(chosen) != 2:
            raise ValueError('native FDE validation failed')
        (output / 'frames.txt').write_text('\n'.join(chosen) + '\n')
        for start, end in RANGES:
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                          f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
            ins = decode_export(asm, start, end, read(data, start, end - start)[1])
            required = set(CONTROLS) | set(DIRECT)
            if not {a for a in required if start <= a < end} <= set(ins):
                raise ValueError('selected control/call must be a decoded instruction start')
            (output / f'{start:x}.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/json-trailing-admission-94')
    args = parser.parse_args()
    print(json.dumps({'ranges': len(generate(args.binary, args.output)['ranges']), 'executed': False}))
