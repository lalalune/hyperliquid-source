"""Freeze byte-exchange values independently of native atomics or target code."""
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


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def corpus():
    modulus = 1 << 64
    addresses = [0, 1, 15, 16, modulus-17, modulus-16, modulus-15, modulus-1]
    rows = {(tag, addresses[(tag+old) % len(addresses)], old)
            for tag in range(256) for old in range(256)}
    for bit in range(8, 64):
        for tag in [0, 1, 2, 3, 127, 128, 255]:
            for old in [0, 1, 2, 127, 128, 255]:
                rows.add(((1 << bit) | tag, addresses[(bit+old) % len(addresses)], old))
                rows.add(((modulus-(1 << bit)) | tag, addresses[(bit+old+1) % len(addresses)], old))
    rng = random.Random(0x4f7fb20)
    for _ in range(6000):
        rows.add((rng.getrandbits(64), rng.getrandbits(64), rng.randrange(256)))
    return sorted(rows)


def fixtures():
    inputs, expected = bytearray(), bytearray()
    counts = {'cases': 0, 'high_tag_bits': 0, 'high_old_bit': 0,
              'wrapped_field_address': 0, 'stored_zero': 0, 'stored_one': 0,
              'stored_two': 0}
    pairs = set()
    for tag, object_address, old in corpus():
        digit = tag % 256
        # The two singleton classes and their complement define an abstract
        # exchange; no load/store simulation or target instruction stepping.
        stored = int(digit != 0) + int(digit == 2)
        address = (object_address + 16) % (1 << 64)
        inputs.extend(struct.pack('<3Q', tag, object_address, old))
        expected.extend(struct.pack('<4Q', old, 0, address, stored))
        counts['cases'] += 1
        counts['high_tag_bits'] += tag > 255
        counts['high_old_bit'] += old >= 128
        counts['wrapped_field_address'] += object_address + 16 >= 1 << 64
        counts[['stored_zero', 'stored_one', 'stored_two'][stored]] += 1
        pairs.add((digit, old))
    require(len(pairs) == 65536, 'complete byte/old-byte product')
    return bytes(inputs), bytes(expected), {
        **counts, 'byte_pairs': len(pairs),
        'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected),
        'oracle_sha256_at_freeze': sha(Path(__file__).read_bytes()),
        'static_sha256_at_freeze': sha((PACKET / 'static.json').read_bytes()),
        'captured_code_executed': False,
        'concurrency_claim': 'Fixtures are isolated exchange observations; they do not enumerate schedules.',
    }


if __name__ == '__main__':
    require(not (ROOT / 'src/node94-tag-exchange').exists(), 'freeze before source')
    inputs, expected, record = fixtures()
    for name, raw in [('inputs', inputs), ('expected', expected)]:
        with (PACKET / (name + '.bin.gz')).open('xb') as f:
            f.write(gzip.compress(raw, mtime=0))
    record['source_directory_existed_at_freeze'] = False
    with (PACKET / 'frozen.json').open('x') as f:
        f.write(json.dumps(record, indent=2, sort_keys=True)+'\n')
    print(json.dumps(record, indent=2))
