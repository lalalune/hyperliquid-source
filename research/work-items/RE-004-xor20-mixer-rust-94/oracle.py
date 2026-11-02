"""Independent 32-bit product-column oracle, frozen before new Rust."""
from pathlib import Path
import gzip
import hashlib
import json
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BASE = 1 << 32
MASK = (1 << 64) - 1

def require(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def folded_columns(a, b):
    a1, a0 = divmod(a, BASE)
    b1, b0 = divmod(b, BASE)
    carry0, word0 = divmod(a0 * b0, BASE)
    carry1, word1 = divmod(a0 * b1 + a1 * b0 + carry0, BASE)
    high = a1 * b1 + carry1
    require(0 <= high <= MASK, 'upper product bound')
    return (word0 + BASE * word1) ^ high

def expected(prefix, data, seed0, seed1):
    require(len(data) == 20, 'input width')
    # Unbounded base-256 digit decoding, retaining all overlapping byte reads.
    word = lambda offset: sum(data[offset + i] * 256**i for i in range(8))
    left = folded_columns(word(8) ^ seed1, word(12) ^ seed0)
    right = folded_columns(word(0) ^ prefix, word(4) ^ seed0)
    return folded_columns(left ^ right ^ 20, seed0)

def corpus():
    words = [0, 1, 2, 1 << 32, 1 << 63, MASK, 0xdeadbeefcafef00d, 0x123456789abcdef0]
    buffers = [bytes(20), bytes([255]) * 20, bytes(range(20)), bytes(reversed(range(20))),
               bytes([0x55, 0xaa]) * 10, bytes([0xaa, 0x55]) * 10]
    cases = set()
    for data in buffers:
        for prefix in (0, MASK, 1 << 63, 0x0706050403020100):
            for seed0 in words:
                for seed1 in words:
                    cases.add((prefix, data, seed0, seed1))
    for offset in range(20):
        for value in range(256):
            data = bytearray(range(20));data[offset] = value
            cases.add((0xfedcba9876543210, bytes(data), 0xdeadbeefcafef00d, 0x123456789abcdef0))
    for bit in range(64):
        for delta in (-1, 0, 1):
            edge = (1 << bit) + delta
            if 0 <= edge <= MASK:
                cases.add((edge, bytes(range(20)), MASK, edge))
                cases.add((MASK, bytes(range(20)), edge, MASK))
    for index in range(4096):
        raw = hashlib.sha512(f'node94-xor20:{index}'.encode()).digest()
        prefix, seed0, seed1 = struct.unpack('<QQQ', raw[:24])
        cases.add((prefix, raw[24:44], seed0, seed1))
    return sorted(cases)

def fixtures():
    cases = corpus()
    require(expected(0x0706050403020100, bytes(range(20)), 0xdeadbeefcafef00d,
                     0x123456789abcdef0) == 0x9c4e42a7cec11b69, 'retained static sample')
    inputs = b''.join(struct.pack('<Q', a) + b + struct.pack('<QQ', c, d) for a,b,c,d in cases)
    expected_bytes = b''.join(struct.pack('<Q', expected(*case)) for case in cases)
    record = {'cases':len(cases), 'input_bytes_per_case':44, 'zero_seed0_cases':sum(c == 0 for a,b,c,d in cases),
              'inputs_sha256':sha(inputs),'expected_sha256':sha(expected_bytes),
              'method':'base256 byte decoding and explicit base2^32 multiplication columns with carry',
              'domain':'u64 prefix, 20 bytes, two u64 runtime seed snapshots'}
    return inputs, expected_bytes, record

if __name__ == '__main__':
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze is supported')
    require(not (ROOT / 'src/node94-xor20-mixer/lib.rs').exists(), 'freeze must precede Rust')
    inputs, expected_bytes, record = fixtures()
    record['oracle_sha256_at_freeze'] = sha(Path(__file__).read_bytes())
    record['rust_source_existed_at_freeze'] = False
    for name, raw in [('inputs', inputs), ('expected', expected_bytes)]:
        with (PACKET / (name + '.bin.gz')).open('xb') as f:f.write(gzip.compress(raw, mtime=0))
    with (PACKET / 'frozen.json').open('x') as f:
        json.dump(record, f, indent=2, sort_keys=True);f.write('\n')
    print(json.dumps(record, indent=2))
