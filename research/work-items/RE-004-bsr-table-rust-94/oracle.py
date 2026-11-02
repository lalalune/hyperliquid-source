"""Independent interval-selection oracle for a real 128-word native table."""
from pathlib import Path
import gzip
import hashlib
import json
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
MASK = 2**64 - 1
INPUT = struct.Struct('<QQQQIQ')

def require(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def interval(value):
    # Independent partition into [2^k, 2^(k+1)) intervals, no BSR or CLZ.
    matches = [k for k in range(128) if 2**k <= value < 2**(k + 1)]
    require(len(matches) == int(value != 0), 'power interval partition')
    return None if not matches else matches[0]

def expected(low, high, seed, step, override_index, override_value):
    index = interval(low + high * 2**64)
    if index is None:
        return 0
    return override_value if index == override_index else (seed + step * index) % 2**64

def corpus():
    values = {0, 1, 2**128 - 1}
    for bit in range(128):
        for delta in (-1, 0, 1):
            value = 2**bit + delta
            if 0 <= value < 2**128:
                values.add(value)
        if bit >= 64:
            values.add(2**bit + MASK)
    cases = set()
    for value in sorted(values):
        selected = interval(value)
        selected = 0 if selected is None else selected
        for seed, step in [(0, 1), (MASK, 0), (MASK - 3, 2**63 + 1), (0, 0)]:
            for index in {0, 127, selected, (selected + 1) % 128}:
                cases.add((value & MASK, value >> 64, seed, step, index, 0x9876543210fedcba))
    for index in range(4096):
        raw = hashlib.sha512(f'node94-bsr-table:{index}'.encode()).digest()
        low, high, seed, step, override_value = struct.unpack('<QQQQQ', raw[:40])
        cases.add((low, high, seed, step | 1, raw[40] % 128, override_value))
    return sorted(cases)

def fixtures():
    rows = corpus()
    inputs = b''.join(INPUT.pack(*row) for row in rows)
    outputs = b''.join(struct.pack('<Q', expected(*row)) for row in rows)
    indices = {interval(row[0] + row[1]*2**64) for row in rows}
    require(indices == set(range(128)) | {None}, 'all 128 intervals and zero')
    record = {'cases': len(rows), 'input_bytes_per_case': INPUT.size,
              'inputs_sha256': sha(inputs), 'expected_sha256': sha(outputs),
              'zero_cases': sum(a == b == 0 for a, b, *_ in rows),
              'domain': 'two u64 field snapshots and an arbitrary 128-qword table',
              'method': 'unique power interval plus closed-form affine table entry with one override',
              'native_table': 'materialized 128 u64 words before library call',
              'selected_indices': list(range(128))}
    return inputs, outputs, record

if __name__ == '__main__':
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze is supported')
    require(not (ROOT / 'src/node94-bsr-table').exists(), 'freeze must precede Rust')
    inputs, outputs, record = fixtures()
    record['oracle_sha256_at_freeze'] = sha(Path(__file__).read_bytes())
    record['rust_source_existed_at_freeze'] = False
    for name, raw in [('inputs', inputs), ('expected', outputs)]:
        with (PACKET / (name + '.bin.gz')).open('xb') as f:
            f.write(gzip.compress(raw, mtime=0))
    with (PACKET / 'frozen.json').open('x') as f:
        json.dump(record, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps(record, indent=2))
