"""Freeze an independently enumerated 900-word decimal language before Rust."""
from pathlib import Path
import gzip
import hashlib
import json
import random
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def corpus():
    rows = set()
    def add(length, available, raw):
        rows.add((length, available, int.from_bytes(raw, 'little')))
    # All 65,536 values for each pair of positions; the remaining byte is
    # a fixed valid digit. This is not an exhaustive three-byte enumeration.
    for first, second, fixed in [(0, 1, 2), (0, 2, 1), (1, 2, 0)]:
        for a in range(256):
            for b in range(256):
                raw = bytearray(b'573\xa5')
                raw[first], raw[second] = a, b
                add(3, 4, raw)
    for value in range(1000):
        raw = f'{value:03d}'.encode() + b'\x00'
        for available in range(5):
            add(3, available, raw)
    for bit in range(64):
        for length in [1 << bit, (1 << bit) | 3, ((1 << bit) - 1) & ((1 << 64)-1)]:
            for available in range(5):
                for raw in [b'123\x00', b'000\xff', b'\x0034\x7f']:
                    add(length, available, raw)
    for length in [0, 1, 2, 3, 4, 5, 255, 256, (1 << 64)-1]:
        for available in range(5):
            for b in range(256):
                add(length, available, b'123' + bytes([b]))
    rng = random.Random(0x1683670)
    for _ in range(12000):
        add(rng.choice([3, rng.getrandbits(64)]), rng.randrange(5), rng.getrandbits(32).to_bytes(4, 'little'))
    return sorted(rows)


def fixtures():
    # A finite language dictionary gives expected values without reproducing
    # the source's range tests, subtraction or weighted-sum implementation.
    language = {str(n).encode('ascii'): n for n in range(100, 1000)}
    inputs, expected = bytearray(), bytearray()
    counts = {'cases': 0, 'length_rejections': 0, 'safe_refusals': 0,
              'invalid_triples': 0, 'valid_triples': 0}
    accepted = set()
    for length, available, packed in corpus():
        inputs.extend(struct.pack('<3Q', length, available, packed))
        if length != 3:
            status, value = 0, 0
            counts['length_rejections'] += 1
        elif available < 3:
            status, value = 1, 0
            counts['safe_refusals'] += 1
        else:
            status = 0
            word = packed.to_bytes(4, 'little')[:3]
            value = language.get(word, 0)
            counts['valid_triples' if value else 'invalid_triples'] += 1
            if value:
                accepted.add(word)
        counts['cases'] += 1
        expected.extend(struct.pack('<2Q', status, value))
    require(accepted == set(language), 'all 900 valid words')
    return bytes(inputs), bytes(expected), {
        **counts, 'distinct_valid_words': len(accepted),
        'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected),
        'oracle_sha256_at_freeze': sha(Path(__file__).read_bytes()),
        'static_sha256_at_freeze': sha((PACKET / 'static.json').read_bytes()),
        'captured_code_executed': False,
    }


if __name__ == '__main__':
    require(not (ROOT / 'src/node94-three-digit-parser').exists(), 'freeze before Rust exists')
    inputs, expected, record = fixtures()
    for name, raw in [('inputs', inputs), ('expected', expected)]:
        with (PACKET / (name + '.bin.gz')).open('xb') as f:
            f.write(gzip.compress(raw, mtime=0))
    record['source_directory_existed_at_freeze'] = False
    with (PACKET / 'frozen.json').open('x') as f:
        f.write(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps(record, indent=2))
