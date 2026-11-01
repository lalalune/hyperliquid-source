"""Freeze independent textual bit counts before Rust construction."""
from pathlib import Path
import gzip
import hashlib
import json
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
MASK = (1 << 64) - 1

def require(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def corpus():
    words = set(range(1 << 16))
    words.update(MASK ^ n for n in range(1 << 16))
    for byte in range(256):
        for position in range(8):
            words.add(byte << (8 * position))
            words.add(MASK ^ (byte << (8 * position)))
    for count in range(65):
        words.add((1 << count) - 1)
        words.add(MASK ^ ((1 << count) - 1))
    for index in range(2048):
        words.add(int.from_bytes(hashlib.sha256(f'node94-popcount:{index}'.encode()).digest()[:8], 'little'))
    return sorted(words)

def fixtures():
    words = corpus()
    # Literal digit tally: no subtract-mask-fold recipe or machine evaluation.
    answers = [(format(n, '064b').count('1'), format(n % (1 << 32), '032b').count('1')) for n in words]
    inputs = b''.join(struct.pack('<Q', n) for n in words)
    expected = b''.join(struct.pack('<II', *pair) for pair in answers)
    record = {'cases': len(words), 'popcount_values': sorted({a for a, _ in answers}),
              'field_count_values': sorted({b for _, b in answers}),
              'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected),
              'method': 'count one digits in fixed-width textual binary representation; u32 caller uses residue modulo2^32',
              'domain': 'all u64 words and all u32 field values; finite corpus is not exhaustive'}
    require(record['popcount_values'] == list(range(65)), 'missing population count')
    require(record['field_count_values'] == list(range(33)), 'missing field count')
    return inputs, expected, record

if __name__ == '__main__':
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze is supported')
    require(not (ROOT / 'src/node94-popcount/lib.rs').exists(), 'freeze must precede Rust')
    inputs, expected, record = fixtures()
    record['oracle_sha256_at_freeze'] = sha(Path(__file__).read_bytes())
    record['rust_source_existed_at_freeze'] = False
    for name, raw in [('inputs', inputs), ('expected', expected)]:
        with (PACKET / (name + '.bin.gz')).open('xb') as f:
            f.write(gzip.compress(raw, mtime=0))
    with (PACKET / 'frozen.json').open('x') as f:
        json.dump(record, f, indent=2, sort_keys=True); f.write('\n')
    print(json.dumps({k:v for k,v in record.items() if not k.endswith('_values')}, indent=2))
