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
import foundation_hour as hour
from elf_index import sections

PACKET = Path(__file__).resolve().parent
RANGES = [('hour', hour.START, hour.END), ('caller', 0x14027b0, 0x1403c29)]


def instructions(output, start, end, expected_bytes):
    rows = []
    for line in output.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)(.*)$', line)
        if match:
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            # GNU objdump wraps instructions longer than 7 bytes: the bytes
            # past the seventh continue on an addressed row whose mnemonic
            # field is empty. Merge such a row into the previous instruction
            # instead of counting it as a separate instruction.
            if rows and not match[3].strip() and address == rows[-1][0]+len(rows[-1][1]):
                rows[-1] = (rows[-1][0], rows[-1][1]+raw)
            else:
                rows.append((address, raw))
    position = start
    for address, raw in rows:
        hour.require(address == position, 'Disassembly is not contiguous from FDE start')
        position += len(raw)
    hour.require(position == end, 'Disassembly does not end at FDE end')
    hour.require(b''.join(raw for _, raw in rows) == expected_bytes, 'Disassembly bytes differ from target')
    return dict(rows)


def check(objdump=None):
    hour.inspect(hour.TARGET)
    data = hour.TARGET.read_bytes()
    text = next(s for s in sections(data) if s['name'] == '.text')
    result = dict(target_sha256=hour.SHA256, windows=[], complete_cfg=False)
    for name, start, end in RANGES:
        if objdump:
            output = subprocess.check_output([objdump, '-d', f'--start-address={start:#x}',
                                              f'--stop-address={end:#x}', 'artifacts/node/94/hl-node'],
                                             cwd=ROOT, text=True)
        else:
            output = (PACKET / f'{name}.objdump.txt').read_text()
        offset = text['offset'] + start - text['address']
        body = data[offset:offset+end-start]
        rows = instructions(output, start, end, body)
        required = ([hour.START, 0x1450a13, 0x1450a38, 0x1450a32, 0x1450a4b]
                    if name == 'hour' else [0x140380f, 0x1403814, 0x140381a])
        hour.require(all(va in rows for va in required), 'Required address is not an instruction boundary')
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
