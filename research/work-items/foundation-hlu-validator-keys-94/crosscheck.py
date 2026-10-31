#!/usr/bin/env python3
"""Check LLVM's complete retained disassembly against authenticated ELF bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import foundation_hlu_keys as hlu
from elf_index import sections

PACKET = Path(__file__).resolve().parent
LOADER_STARTS = [va for va in hlu.INSTRUCTIONS if hlu.LOADER[0] <= va < hlu.LOADER[1]]
COLLECTOR_STARTS = [va for va in hlu.INSTRUCTIONS if hlu.COLLECTOR[0] <= va < hlu.COLLECTOR[1]]
# Each window is decoded from its FDE start; consumers only validate the slot loads.
RANGES = [
    ('loader', *hlu.LOADER, LOADER_STARTS + [0x13d2777]),
    ('collector', *hlu.COLLECTOR, COLLECTOR_STARTS),
    ('shim', *hlu.SHIM, [0x13da09e]),
    ('consumer-a', 0x13cd040, 0x13cd257, [0x13cd07d]),
    ('consumer-b', 0x14b14c0, 0x14b1612, [0x14b1501]),
]


def instructions(output, start, end, expected_bytes):
    rows = []
    for line in output.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)', line)
        if match:
            rows.append((int(match[1], 16), bytes.fromhex(match[2])))
    position = start
    for address, raw in rows:
        hlu.require(address == position, 'Disassembly is not contiguous from FDE start')
        position += len(raw)
    hlu.require(position == end, 'Disassembly does not end at FDE end')
    hlu.require(b''.join(raw for _, raw in rows) == expected_bytes, 'Disassembly bytes differ from target')
    return dict(rows)


def check(objdump=None):
    hlu.inspect(hlu.TARGET)
    data = hlu.TARGET.read_bytes()
    text = next(s for s in sections(data) if s['name'] == '.text')
    result = dict(target_sha256=hlu.SHA256, windows=[], complete_cfg=False)
    for name, start, end, required in RANGES:
        if objdump:
            output = subprocess.check_output([objdump, '-d', f'--start-address={start:#x}',
                                              f'--stop-address={end:#x}', 'artifacts/node/94/hl-node'],
                                             cwd=ROOT, text=True)
        else:
            output = (PACKET / f'{name}.objdump.txt').read_text()
        offset = text['offset'] + start - text['address']
        body = data[offset:offset + end - start]
        rows = instructions(output, start, end, body)
        hlu.require(all(va in rows for va in required), 'Required address is not an instruction boundary')
        hlu.require(all(rows[va].hex() == hlu.INSTRUCTIONS[va] for va in required if va in hlu.INSTRUCTIONS),
                    'Locked instruction differs from disassembly')
        result['windows'].append(dict(name=name, start_va=hex(start), end_va_exclusive=hex(end),
                                      byte_count=len(body), instruction_count=len(rows),
                                      sha256=hashlib.sha256(body).hexdigest(),
                                      validated_instruction_starts=list(map(hex, required))))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--objdump', help='Rerun this LLVM executable instead of checking retained raw output')
    args = parser.parse_args()
    print(json.dumps(check(args.objdump), indent=2))
