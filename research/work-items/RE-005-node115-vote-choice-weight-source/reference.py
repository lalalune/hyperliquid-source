#!/usr/bin/env python3
"""Independent synthetic struct packing model; no target execution."""
import hashlib
import json
import struct
from pathlib import Path
import sys

weights = [0, 127, 128, 255, 256, 65535, 65536, (1 << 32) - 1, 1 << 32, (1 << 64) - 1]
lines = ['# mode choice weight wire_hex']
for mode in range(256):
    for choice in (0, 1, 255):
        for weight in weights:
            wire = bytes([(((mode ^ 1) << 4) | 0x82) & 255])
            if mode != 0:
                wire += bytes([0xa6]) + b'choice'
            name = (b'yes', b'no', b'abstain')[min(choice, 2)]
            wire += bytes([0xa0 | len(name)]) + name
            if mode == 1:
                wire += bytes([0xa6]) + b'weight'
            if weight < 128:
                wire += bytes([weight])
            else:
                marker, code = ((0xcc, '>B') if weight < 256 else
                                (0xcd, '>H') if weight < 65536 else
                                (0xce, '>I') if weight < (1 << 32) else (0xcf, '>Q'))
                wire += bytes([marker]) + struct.pack(code, weight)
            lines.append(f'{mode} {choice} {weight} {wire.hex()}')
contents = '\n'.join(lines) + '\n'
root = Path(__file__).resolve().parents[3]
fixture = root / 'src/node115-vote-choice-weight/tests/reference-vectors.txt'
if '--write' in sys.argv:
    fixture.write_text(contents)
else:
    assert fixture.read_text() == contents
print(json.dumps({'cases': len(lines)-1, 'fixture_sha256': hashlib.sha256(contents.encode()).hexdigest(),
                  'reference': 'Python struct packing model; no captured execution'}, indent=2))
