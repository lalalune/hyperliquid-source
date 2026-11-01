"""Independent algebraic block-fold and signed-tail expectations, frozen before Rust."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
MASK = (1 << 32) - 1
FACTOR = 0xc6a4a793
INPUT = struct.Struct('<QHHI256s512s')
OUTPUT = struct.Struct('<IBB')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def mathematical_hash(data):
    """Fold polynomial word sums in Z/(2**32), with a separate signed tail sum."""
    n = len(data)
    value = ((n * FACTOR) & MASK) ^ 397
    words = [sum(data[start + j] * (256 ** j) for j in range(4))
             for start in range(0, n - n % 4, 4)]
    for word in words:
        product = ((value + word) * FACTOR) % (1 << 32)
        value = product ^ (product // (1 << 16))
    if n % 4:
        tail = data[n - n % 4:]
        signed_sum = sum(((byte ^ 128) - 128) * (256 ** j)
                         for j, byte in enumerate(tail))
        product = ((value + signed_sum) * FACTOR) % (1 << 32)
        value = product ^ (product // (1 << 24))
    return value


def expected(case):
    index, divisor, length, table_length, raw, table = case
    value = mathematical_hash(raw[:length])
    if divisor == 0:
        return value, 1, 0
    position = (index % (1 << 32)) + value % divisor
    return (value, 0, table[position]) if position < table_length else (value, 2, 0)


def corpus():
    rng = random.Random(0x538c8205422e70)
    table = bytes(rng.randrange(256) for _ in range(512))
    rows = []
    def add(data, divisor=257, index=0, table_length=512):
        require(len(data) <= 256 and 0 <= table_length <= 512, 'fixture framing')
        rows.append((index, divisor, len(data), table_length, data.ljust(256, b'\0'), table))
    # Every two-byte tail, with independently varying ignored index high bits.
    for pair in range(65536):
        add(bytes((pair & 255, pair >> 8)), index=((pair * 0x9e3779b9 & MASK) << 32) | (pair % 251))
    for length in range(257):
        samples = [bytes(length), bytes([255]) * length,
                   bytes(i % 256 for i in range(length)),
                   bytes(rng.randrange(256) for _ in range(length))]
        for sample in samples:
            for divisor in (1, 2, 3, 255, 256, 257, 65535):
                add(sample, divisor)
    for prefix in (b'', bytes.fromhex('0123456789abcdef')):
        for position in range(3):
            for byte in range(256):
                tail = bytearray([0x7f, 0x80, 0xff]); tail[position] = byte
                add(prefix + tail, 257, (1 << 63) + position)
    for _ in range(4096):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(257)))
        divisor = rng.choice((0, 1, 257, rng.randrange(65536)))
        index = rng.choice((0, 1, 255, 511, 1 << 32, (1 << 64)-1, rng.randrange(1 << 64)))
        add(raw, divisor, index, rng.choice((0, 1, 256, 511, 512)))
    for raw in (b'', b'\x80', b'\xff\x80', b'\x80\xff\x7f', bytes(range(8))):
        for divisor in (0, 1, 255, 256, 257, 32768, 65535):
            h = mathematical_hash(raw)
            for index in (0, 1, 256, 511, 512, 1 << 32, (1 << 64)-1):
                pos = (index % (1 << 32)) + (h % divisor if divisor else 0)
                for length in {0, 512, min(pos, 512), min(pos + 1, 512)}:
                    add(raw, divisor, index, length)
    return rows


def fixtures():
    rows = corpus()
    results = [expected(row) for row in rows]
    inputs = b''.join(INPUT.pack(*row) for row in rows)
    outputs = b''.join(OUTPUT.pack(*row) for row in results)
    meta = {'cases': len(rows), 'input_record_bytes': INPUT.size,
            'output_record_bytes': OUTPUT.size,
            'inputs_sha256': sha(inputs), 'expected_sha256': sha(outputs),
            'outcomes': dict(sorted(Counter(str(row[1]) for row in results).items())),
            'tail_lengths': dict(sorted(Counter(str(row[2] % 4) for row in rows).items())),
            'all_two_byte_tails': len({row[4][:2] for row in rows[:65536]})}
    return inputs, outputs, meta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', action='store_true'); args = parser.parse_args()
    inputs, outputs, meta = fixtures()
    meta['oracle_sha256_at_freeze'] = sha(Path(__file__).read_bytes())
    if args.freeze:
        require(not (ROOT / 'src/node94-modulo-index/lib.rs').exists(), 'freeze before Rust')
        for name, raw in [('inputs', inputs), ('expected', outputs)]:
            with (PACKET / (name + '.bin.gz')).open('xb') as f:
                f.write(gzip.compress(raw, mtime=0))
        with (PACKET / 'frozen.json').open('x') as f:
            json.dump(meta, f, indent=2, sort_keys=True); f.write('\n')
    else:
        require(json.loads((PACKET / 'frozen.json').read_text()) == meta, 'oracle freeze drift')
        for name, raw in [('inputs', inputs), ('expected', outputs)]:
            require(gzip.decompress((PACKET / (name + '.bin.gz')).read_bytes()) == raw, 'fixture drift')
    print(json.dumps(meta, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
