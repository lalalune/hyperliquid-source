"""Frozen equivalence-class oracle; no Rust or decoded-instruction evaluation."""
from pathlib import Path
import gzip
import hashlib
import json
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

def require(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

# Disjoint classes: each ASCII letter pair, and singleton nonletters.
classes = [{a, b} for a, b in zip(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ', b'abcdefghijklmnopqrstuvwxyz')]
covered = set().union(*classes)
classes += [{value} for value in range(256) if value not in covered]
CLASS = {value: index for index, group in enumerate(classes) for value in group}
require(len(CLASS) == 256 and sum(map(len, classes)) == 256, 'byte partition')

def expected(length, left, right):
    return int(length == 3 and all(CLASS[a] == CLASS[b] for a, b in zip(left, right)))

def corpus():
    cases = set()
    # All 65,536 ordered byte pairs at each position, with the other two
    # positions equal under the independently listed classes.
    for position in range(3):
        for a in range(256):
            for b in range(256):
                left, right = bytearray(b'Az!'), bytearray(b'aZ!')
                left[position], right[position] = a, b
                cases.add((3, bytes(left), bytes(right)))
    lengths = [0, 1, 2, 3, 4, 255, 256, 259, 2**32 + 3, 2**63, 2**64 - 1]
    for length in lengths:
        for left, right in [(b'ABC', b'abc'), (b'ABC', b'abd'), (b'\0\0\0', b'\0\0\0'),
                            (b'@[{', b'`[{'), (b'XYZ', b'xyz'), (b'\xff\x80\0', b'\xff\x80\0')]:
            cases.add((length, left, right))
    for index in range(4096):
        raw = hashlib.sha256(f'node94-ascii-three:{index}'.encode()).digest()
        cases.add((3, raw[:3], raw[3:6]))
        cases.add((3, raw[:3], raw[:3]))
    return sorted(cases)

def fixtures():
    rows = corpus()
    inputs = b''.join(struct.pack('<Q', n) + a + b for n, a, b in rows)
    outputs = bytes(expected(*row) for row in rows)
    record = {'cases': len(rows), 'input_bytes_per_case': 14, 'equal_cases': sum(outputs),
              'inputs_sha256': sha(inputs), 'expected_sha256': sha(outputs),
              'domain': 'u64 length gate and two three-byte stable snapshots',
              'method': 'membership in 26 literal ASCII-letter pairs and 204 singleton classes',
              'exhaustive_pairs_per_position': 65536, 'positions': 3}
    return inputs, outputs, record

if __name__ == '__main__':
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze is supported')
    require(not (ROOT / 'src/node94-ascii-three').exists(), 'freeze must precede Rust')
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
