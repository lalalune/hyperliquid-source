"""Frozen whole-prefix integer differences and immutable byte overlays for aliases."""
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
INPUT = struct.Struct('<QQQH256s')
OUTPUT = struct.Struct('<BQ256s')
MOD = 1 << 64


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def expected(case):
    destination, left, right, length, initial = case
    if any(start + width > length for start, width in [(left, 32), (right, 32), (destination, 33)]):
        return 1, 0, initial
    # A lower-limb update cannot affect any later minuend limb. Its value A is
    # therefore the entry integer. Effective subtrahend words may incorporate
    # already determined lower-limb writes, each defined by a prefix difference.
    a = int.from_bytes(initial[left:left + 32], 'little')
    effective_b, writes = 0, []
    def at(address):
        for start, value in reversed(writes):
            if start <= address < start + len(value):
                return value[address - start]
        return initial[address]
    def read(start, width):
        return bytes(at(start + i) for i in range(width))
    for limb in range(4):
        effective_b += int.from_bytes(read(right + 8 * limb, 8), 'little') * (MOD ** limb)
        prefix = (a - effective_b) % (MOD ** (limb + 1))
        word = prefix // (MOD ** limb)
        writes.append((left + 8 * limb, word.to_bytes(8, 'little')))
    borrow = int(a < effective_b)
    # Functional overlays preserve the separately snapshotted 16/8/8 reads.
    writes.append((destination, read(left, 16)))
    writes.append((destination + 16, read(left + 16, 8)))
    last = read(left + 24, 8)
    writes.append((destination + 24, last))
    writes.append((destination + 32, bytes([borrow])))
    return 0, int.from_bytes(last, 'little'), bytes(at(i) for i in range(256))


def corpus():
    rng = random.Random(0x32d8310)
    rows = []
    def add(destination, left, right, data=None, length=256):
        if data is None:
            data = bytes(rng.randrange(256) for _ in range(256))
        require(len(data) == 256 and 0 <= length <= 256, 'framing')
        rows.append((destination, left, right, length, bytes(data)))
    # Every source/subtrahend displacement and every output/minuend displacement
    # including the final borrow-byte-only overlap; use joint layouts, not just
    # one isolated pair at a time. Four nontrivial entry patterns each.
    patterns = [bytes(256), bytes([255]) * 256, bytes(range(256)),
                bytes((29 * i + 17) % 256 for i in range(256))]
    for rhs_delta in range(-31, 32):
        for dst_delta in range(-32, 32):
            for initial in patterns:
                add(96 + dst_delta, 96, 96 + rhs_delta, initial)
    # Unaligned address lanes and single-bit perturbations across the operands.
    for alignment in range(8):
        for bit in range(256):
            image = bytearray([255] * 256)
            image[32 + alignment + bit // 8] ^= 1 << (bit % 8)
            add(160 + alignment, 32 + alignment, 80 + alignment, image)
    values = [0, 1, MOD-1, 1 << 63, 1 << 32, (1 << 256)-1]
    for a in values:
        for b in values:
            for destination in [0, 32, 33, 47, 48, 56, 63, 64, 65, 80, 160, 223]:
                image = bytearray(256)
                image[32:64] = a.to_bytes(32, 'little')
                image[96:128] = b.to_bytes(32, 'little')
                add(destination, 32, 96, image)
    for _ in range(4096):
        add(rng.randrange(224), rng.randrange(225), rng.randrange(225))
    # Exact endpoints and absent ranges; untouched suffix bytes are observed.
    for length in [0, 7, 15, 16, 31, 32, 33, 63, 64, 95, 96, 127, 128, 223, 224, 225, 255, 256]:
        for destination, left, right in [(0, 0, 0), (0, 32, 64), (32, 0, 64), (223, 224, 224), (224, 224, 224)]:
            add(destination, left, right, length=length)
    for large in [MOD-1, MOD-31, MOD-32, 1 << 63, 257]:
        add(large, 0, 0); add(0, large, 0); add(0, 0, large)
    return rows


def fixtures():
    rows = corpus(); results = [expected(row) for row in rows]
    inputs = b''.join(INPUT.pack(*row) for row in rows)
    outputs = b''.join(OUTPUT.pack(*row) for row in results)
    valid = [row for row, result in zip(rows, results) if result[0] == 0]
    overlap = lambda a, aw, b, bw: a < b + bw and b < a + aw
    meta = {'cases': len(rows), 'outcomes': dict(Counter(str(x[0]) for x in results)),
            'input_record_bytes': INPUT.size, 'output_record_bytes': OUTPUT.size,
            'inputs_sha256': sha(inputs), 'expected_sha256': sha(outputs),
            'valid_left_right_overlap': sum(overlap(r[1],32,r[2],32) for r in valid),
            'valid_output_left_overlap': sum(overlap(r[0],33,r[1],32) for r in valid),
            'valid_all_three_same': sum(r[0]==r[1]==r[2] for r in valid)}
    return inputs, outputs, meta


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze',action='store_true'); args=parser.parse_args()
    inputs,outputs,meta=fixtures();meta['oracle_sha256_at_freeze']=sha(Path(__file__).read_bytes())
    if args.freeze:
        require(not (ROOT/'src/node94-wide-subtract/image.rs').exists(), 'freeze before new image implementation')
        for name,raw in [('inputs',inputs),('expected',outputs)]:
            with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
        with (PACKET/'frozen.json').open('x') as f:json.dump(meta,f,indent=2,sort_keys=True);f.write('\n')
    else:
        require(json.loads((PACKET/'frozen.json').read_text())==meta,'oracle freeze drift')
        for name,raw in [('inputs',inputs),('expected',outputs)]:
            require(gzip.decompress((PACKET/(name+'.bin.gz')).read_bytes())==raw,'fixture drift')
    print(json.dumps(meta,indent=2,sort_keys=True))


if __name__=='__main__':main()
