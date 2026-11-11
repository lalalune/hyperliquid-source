#!/usr/bin/env python3
"""Generate synthetic selection fixtures from the prior independent Python model.

This imports only static project source; no captured code is executed. The
fixture includes arbitrary row orders because the API receives ordered rows.
"""
import hashlib
import json
import random
import struct
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from evm_fee_history115 import model_reward_selection

rng = random.Random(1153922)
percentile_bits = [0, 0x8000000000000000, 0xbff0000000000000,
                   0x4034000000000000, 0x4049000000000000,
                   0x4059000000000000, 0x7ff0000000000000,
                   0xfff0000000000000, 0x7ff8000000000000]
lines = ['# total percentile_bits weight:payload,... expected_or_overflow']
for index in range(1200):
    total = [0, 1, 10, (1 << 53) + 1, (1 << 64) - 1, rng.getrandbits(64)][index % 6]
    bits = percentile_bits[index % len(percentile_bits)]
    pct = struct.unpack('<d', struct.pack('<Q', bits))[0]
    rows = [(rng.choice([0, 1, 2, (1 << 64) - 1, rng.getrandbits(64)]), rng.getrandbits(128)) for _ in range(index % 5)]
    try:
        value = str(model_reward_selection([pct], rows, total)[0])
    except OverflowError:
        value = 'overflow'
    entries = ','.join(f'{w}:{p}' for w,p in rows) or '-'
    lines.append(f'{total} {bits:016x} {entries} {value}')
text = '\n'.join(lines) + '\n'
fixture = ROOT / 'src/node115-fee-history-reward/tests/selection-fixtures.txt'
if '--write' in sys.argv:
    fixture.write_text(text)
else:
    assert fixture.read_text() == text, 'fixture mismatch'
print(json.dumps({'cases':1200,'sha256':hashlib.sha256(text.encode()).hexdigest(),
                  'reference':'existing Python post-sort selection model; not target execution'}, indent=2))
