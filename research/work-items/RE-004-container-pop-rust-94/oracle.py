"""Pre-Rust immutable byte-overlay oracle for the pop/retreat transition."""
import gzip
import struct
from verify_static import PACKET, ROOT, TARGET, encoded, require, sha

MOD = 2 ** 64
MASK = MOD - 1
SIZE = 256
HEADER = struct.Struct('<QQH')
OUTPUT = struct.Struct('<BQ')


def expected(row):
    image_base, obj, length, initial = row
    def answer(code, value=0, image=initial):
        return OUTPUT.pack(code, value) + image
    if length and image_base + length > MOD:
        return answer(1)
    def span(address, width):
        offset = address - image_base
        return offset if 0 <= offset and offset + width <= length else None
    def address(offset):
        return (obj + offset) % MOD
    def number(position, width=8):
        return sum(initial[position + j] * 256 ** j for j in range(width))
    current_at = span(address(8), 8)
    if current_at is None:
        return answer(2)
    compared_at = span(address(16), 8)
    if compared_at is None:
        return answer(3)
    current, compared = number(current_at), number(compared_at)
    writes = []
    if current != compared:
        count_at = span(address(40), 8)
        if count_at is None:
            return answer(6)
        result = (current - 32) % MOD
        writes = [(count_at, 8, (number(count_at) - 16) % MOD), (current_at, 8, result)]
    else:
        top_at = span(address(32), 8)
        if top_at is None:
            return answer(4)
        next_top = (number(top_at) - 8) % MOD
        popped_at = span(next_top, 8)
        if popped_at is None:
            return answer(5)
        count_at, pair_at = span(address(40), 8), span(address(16), 16)
        if count_at is None or pair_at is None:
            return answer(6)
        # Evaluate the popped qword through a closed per-byte overlay of the
        # preceding top write; no imperative memory store or CPU interpreter.
        def after_top(j):
            return (next_top // 256 ** (j - top_at)) % 256 if top_at <= j < top_at + 8 else initial[j]
        value = sum(after_top(popped_at + j) * 256 ** j for j in range(8))
        count = sum(after_top(count_at + j) * 256 ** j for j in range(8))
        result = (value + 480) % MOD
        writes = [(top_at, 8, next_top), (count_at, 8, (count - 16) % MOD),
                  (current_at, 8, result), (pair_at, 16, value + ((value + 512) % MOD) * MOD)]
    # Independent final-byte relation: last covering write wins. The actual
    # object's four output intervals are disjoint on every admitted image.
    def final_byte(j):
        for at, width, value in reversed(writes):
            if at <= j < at + width:
                return (value // 256 ** (j - at)) % 256
        return initial[j]
    return answer(0, result, bytes(final_byte(j) for j in range(SIZE)))


def corpus():
    rows = set()
    def make(pop=True, current=19, popped=7, count=15, image_base=4096, object_offset=32,
             popped_offset=128, length=SIZE, seed=23, top_override=None, compared_override=None):
        image = bytearray((seed + 37 * j) % 256 for j in range(SIZE))
        address = lambda offset: (image_base + offset) % MOD
        def put(offset, value):
            if 0 <= offset and offset + 8 <= SIZE:
                image[offset:offset + 8] = (value % MOD).to_bytes(8, 'little')
        put(popped_offset, popped)
        put(object_offset + 8, current)
        compared = current if pop else current ^ (1 << 63)
        put(object_offset + 16, compared if compared_override is None else compared_override)
        put(object_offset + 32, address(popped_offset + 8) if top_override is None else top_override)
        put(object_offset + 40, count)
        rows.add((image_base, address(object_offset), length, bytes(image)))

    values = [0, 1, 15, 16, 31, 32, 33, 479, 480, 511, 512, 513,
              2 ** 32 - 1, 2 ** 32, 2 ** 63, MASK - 512, MASK - 480, MASK - 31, MASK]
    for current in values:
        for image_base in [0, 4096, MOD - SIZE]:
            for object_offset in [-8, -1, 0, 32, 33, 208]:
                make(False, current, count=current, image_base=image_base, object_offset=object_offset,
                     top_override=MASK)
        for popped in values:
            make(True, current, popped=popped, count=current)
    for object_offset in range(32, 40):
        for displacement in range(-7, 8):
            make(popped_offset=object_offset + 32 + displacement, object_offset=object_offset,
                 popped=0x8877665544332211, count=0xfedcba9876543210)
    for target in [8, 16, 24, 40]:
        for displacement in range(-7, 8):
            for count in [0, 16, MASK]:
                make(popped_offset=32 + target + displacement, count=count,
                     popped=0x8070605040302010)
    for image_base in [0, MOD - SIZE]:
        for popped_offset in [0, 1, 7, 128, 248]:
            make(image_base=image_base, popped_offset=popped_offset, popped=MASK)
    for bit in range(64):
        make(popped=1 << bit, count=1 << bit)
        make(False, current=1 << bit, count=MASK, compared_override=0)
    for length in [0, 7, 8, 15, 16, 23, 24, 31, 32, 39, 40, 47, 48, 63, 64, 71, 72, 79, 80, 127, 128, 135, 136, 255, 256]:
        for pop in [False, True]:
            for object_offset in [0, 32, 208]:
                make(pop, length=length, object_offset=object_offset)
    for raw_top in [0, 1, 7, 8, 2 ** 32, 2 ** 63, MASK]:
        make(top_override=raw_top)
        make(False, top_override=raw_top)
    for object_offset in [-112, -16, -8, 209, 248, 255, 256, 2 ** 32, MASK]:
        make(object_offset=object_offset)
    for image_base in [MOD - SIZE + 1, MASK - 7, MASK]:
        make(image_base=image_base)
    for index in range(256):
        raw = bytes.fromhex(sha(f'container-pop94:{index}'.encode()))
        make(bool(raw[0] & 1), current=int.from_bytes(raw[1:9], 'little'),
             popped=int.from_bytes(raw[9:17], 'little'), count=int.from_bytes(raw[17:25], 'little'),
             object_offset=raw[25] % 209, popped_offset=raw[26] % 249, seed=raw[27])
    return sorted(rows)


def fixtures():
    rows = corpus(); outputs = [expected(row) for row in rows]
    inputs = b''.join(HEADER.pack(*row[:3]) + row[3] for row in rows); raw = b''.join(outputs)
    counts = {str(code): sum(row[0] == code for row in outputs) for code in range(7)}
    require(all(counts.values()), 'missing safe admission outcome')
    pop, retreat, aliased = 0, 0, set()
    for row, output in zip(rows, outputs):
        if output[0]:
            continue
        image_base, obj, _, image = row
        at = lambda k: (obj + k) % MOD - image_base
        number = lambda j: int.from_bytes(image[j:j + 8], 'little')
        if number(at(8)) == number(at(16)):
            pop += 1; popped_at = (number(at(32)) - 8) % MOD - image_base
            if abs(popped_at - at(32)) < 8:
                aliased.add(popped_at - at(32))
        else:
            retreat += 1
    require(aliased == set(range(-7, 8)), 'missing top/popped partial overlap')
    return inputs, raw, {'target_sha256': TARGET, 'cases': len(rows), 'image_bytes': SIZE,
        'input_record_bytes': HEADER.size + SIZE, 'output_record_bytes': OUTPUT.size + SIZE,
        'outcome_counts': counts, 'admitted_pop': pop, 'admitted_retreat': retreat,
        'top_popped_overlap_displacements': sorted(aliased), 'inputs_sha256': sha(inputs), 'expected_sha256': sha(raw),
        'oracle': 'immutable per-byte top-write overlay followed by scalar modular arithmetic and final-byte overlays',
        'refusals': 'new atomic safe admission, not native fault results', 'return': 'full numeric RAX, equal to the new object+8 word'}


def main():
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze supported')
    require(not (ROOT / 'src/node94-container-pop').exists(), 'freeze must precede Rust')
    inputs, outputs, record = fixtures()
    record['oracle_sha256_at_freeze'] = sha((PACKET / 'oracle.py').read_bytes())
    record['static_sha256_at_freeze'] = sha((PACKET / 'static.json').read_bytes())
    record['rust_source_existed_at_freeze'] = False
    for name, raw in [('inputs', inputs), ('expected', outputs)]:
        with (PACKET / (name + '.bin.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0))
    with (PACKET / 'frozen.json').open('xb') as stream:
        stream.write(encoded(record))
    print(encoded(record).decode(), end='')


if __name__ == '__main__':
    main()
