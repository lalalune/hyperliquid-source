"""Pre-Rust image oracle: unbounded affine arithmetic and literal field selection."""
import gzip
import struct
from verify_static import ROOT, PACKET, TARGET, encoded, require, sha

MOD = 1 << 64
MASK = MOD - 1
SIZE = 1024
HEADER = struct.Struct('<QQH')
OUTPUT = struct.Struct('<BQQ')


def expected(row):
    base, obj, length, image = row
    if length and base + length > MOD:
        return (1, 0, 0)
    def at(field, width):
        offset = (obj + field) % MOD - base
        return offset if 0 <= offset and offset + width <= length else None
    def word(offset):
        return sum(image[offset + k] * 256**k for k in range(8))
    gate = at(0x240, 1)
    if gate is None:
        return (2, 0, 0)
    if image[gate] == 1:
        limit, value = at(0x310, 8), at(0x308, 8)
        if limit is None or value is None:
            return (3, 0, 0)
        return (0, word(value), word(limit))
    gate = at(0xd8, 1)
    if gate is None:
        return (4, 0, 0)
    span, value, limit = at(0xa8, 8), at(0xa0, 8), at(0x300, 8)
    if span is None or value is None or limit is None:
        return (5, 0, 0)
    # One unbounded affine expression; the Rust implementation uses staged
    # wrapping subtraction and addition after its own checked image reads.
    cursor = word(value) + word(span) - word(limit) - 8 * int(image[gate] == 0)
    return (0, cursor % MOD, word(limit))


def corpus():
    rows = set()
    def add(primary=0, secondary=0, value=MASK-3, span=13, limit=17,
            stored=0x123456789abcdef0, stored_limit=0xfedcba9876543210,
            base=4096, obj=16, length=SIZE, seed=19):
        image = bytearray((seed + 37*j) % 256 for j in range(SIZE))
        def put(field, data):
            at = obj + field
            if 0 <= at and at + len(data) <= SIZE:
                image[at:at+len(data)] = data
        for field, v in [(0xa0, value), (0xa8, span), (0x300, limit), (0x308, stored), (0x310, stored_limit)]:
            put(field, v.to_bytes(8, 'little'))
        put(0x240, bytes([primary])); put(0xd8, bytes([secondary]))
        rows.add((base, (base+obj) % MOD, length, bytes(image)))
    for primary in range(256):
        for secondary in range(256):
            add(primary, secondary)
    edges = [0, 1, 7, 8, 9, 15, 16, 2**31-1, 2**31, 2**32-1, 2**32, 2**32+1, 2**63-1, 2**63, MASK-7, MASK]
    for value in edges:
        for span in edges:
            for limit in edges:
                add(0, 0, value, span, limit)
                add(2, 255, value, span, limit)
        for limit in edges:
            add(1, 0, stored=value, stored_limit=limit)
    for bit in range(64):
        for primary in [0, 1, 2, 255]:
            add(primary, 0, value=1 << bit, span=MASK, limit=1, stored=1 << bit, stored_limit=MASK ^ (1 << bit))
    for base in [0, 4096, MOD-SIZE]:
        for obj in [-0x318, -0x310, -0x308, -0x300, -0x240, -0xd8, -0xa8, -0xa0, -1, 0, 1, 16, SIZE-0x318, SIZE-0x318+1, SIZE]:
            for primary in [0, 1, 2, 128, 255]:
                for secondary in [0, 1, 128, 255]:
                    add(primary, secondary, base=base, obj=obj)
    for obj in [-0x240, -0xa0, 0, 1, 16]:
        boundaries = {0, 1, SIZE}
        for field, width in [(0x240,1), (0xd8,1), (0xa0,8), (0xa8,8), (0x300,8), (0x308,8), (0x310,8)]:
            boundaries.update(x for x in [obj+field, obj+field+width-1, obj+field+width] if 0 <= x <= SIZE)
        for length in sorted(boundaries):
            for primary in [0, 1, 2, 255]:
                for secondary in [0, 255]:
                    add(primary, secondary, base=0, obj=obj, length=length)
    for base in [MOD-SIZE+1, MASK-7, MASK]:
        add(base=base)
    for index in range(1024):
        digest = bytes.fromhex(sha(f'pointer-arithmetic-pair94:{index}'.encode()))
        values = [int.from_bytes(digest[k:k+8], 'little') for k in range(0, 32, 8)]
        add(digest[0], digest[1], value=values[0], span=values[1], limit=values[2],
            stored=values[3], stored_limit=values[0], obj=digest[2],
            length=SIZE if index % 2 else int.from_bytes(digest[3:5], 'little') % (SIZE+1), seed=digest[5])
    return sorted(rows)


def fixtures():
    rows = corpus()
    answers = [expected(row) for row in rows]
    inputs = b''.join(HEADER.pack(*r[:3]) + r[3] for r in rows)
    outputs = b''.join(OUTPUT.pack(*r) for r in answers)
    counts = {str(tag): sum(r[0] == tag for r in answers) for tag in range(6)}
    require(all(counts.values()), 'all safe outcomes represented')
    return inputs, outputs, {'target_sha256': TARGET, 'cases': len(rows), 'input_record_bytes': HEADER.size+SIZE,
        'output_record_bytes': OUTPUT.size, 'image_bytes': SIZE, 'outcome_counts': counts,
        'exhaustive_flag_pairs': 65536, 'inputs_sha256': sha(inputs), 'expected_sha256': sha(outputs),
        'oracle': 'unbounded affine integer expression reduced modulo 2^64; literal stored field selection',
        'refusals': 'new image/primary/stored/secondary/computed span refusals, not original fault results'}


def main():
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze supported')
    require(not (ROOT/'src/node94-pointer-arithmetic-pair').exists(), 'freeze before Rust')
    inputs, outputs, record = fixtures()
    record.update(oracle_sha256_at_freeze=sha((PACKET/'oracle.py').read_bytes()),
                  static_sha256_at_freeze=sha((PACKET/'static.json').read_bytes()), rust_source_existed_at_freeze=False)
    for name, raw in [('inputs', inputs), ('expected', outputs)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as file:
            file.write(gzip.compress(raw, mtime=0))
    with (PACKET/'frozen.json').open('xb') as file:
        file.write(encoded(record))
    print(encoded(record).decode(), end='')


if __name__ == '__main__':
    main()
