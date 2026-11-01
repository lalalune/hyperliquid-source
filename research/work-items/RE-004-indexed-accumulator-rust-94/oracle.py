"""Pre-Rust integer/immutable-byte-overlay oracle for the indexed accumulator."""
import gzip
import struct

from verify_static import PACKET, ROOT, TARGET, encoded, require, sha

MOD = 2 ** 64
MASK = MOD - 1
SIZE = 512
HEADER = struct.Struct('<QQQQH')  # image base, index-pointer slot, addend address, base slot, length
OUTPUT = struct.Struct('<BQ')


def expected(row):
    image_base, selector_slot, addend_address, base_slot, length, initial = row
    def answer(tag, value=0, data=initial):
        return OUTPUT.pack(tag, value) + data
    if length and image_base + length > MOD:
        return answer(1)
    def offset(address, width):
        position = address - image_base
        return position if 0 <= position and position + width <= length else None
    def number(position, width):
        return sum(initial[position + j] * 256 ** j for j in range(width))
    pointer_position = offset(selector_slot, 8)
    if pointer_position is None:
        return answer(2)
    pointer = number(pointer_position, 8)
    addend_position = offset(addend_address, 8)
    if addend_position is None:
        return answer(3)
    addend = number(addend_position, 8)
    if pointer == 0:
        index = 13
    else:
        index_position = offset((pointer + 32) % MOD, 4)
        if index_position is None:
            return answer(4)
        unsigned = number(index_position, 4)
        index = unsigned if unsigned < 2 ** 31 else unsigned - 2 ** 32
    base_position = offset(base_slot, 8)
    if base_position is None:
        return answer(5)
    entry = (number(base_position, 8) + 8 * index) % MOD
    counter = offset((entry + 176) % MOD, 8)
    if counter is None:
        return answer(6)
    total = offset((entry + 64) % MOD, 8)
    if total is None:
        return answer(7)
    require(counter + 8 <= total or total + 8 <= counter, 'distinct native update words')
    incremented = (number(counter, 8) + 1) % MOD
    accumulated = (number(total, 8) + addend) % MOD
    # Independent final-byte overlay, computed entirely from the entry image.
    final = bytes((incremented // 256 ** (j - counter)) % 256 if counter <= j < counter + 8
                  else (accumulated // 256 ** (j - total)) % 256 if total <= j < total + 8
                  else initial[j] for j in range(SIZE))
    return answer(0, entry, final)


def corpus():
    rows = set()
    def make(index=0, present=True, image_base=4096, entry_offset=224,
             selector_offset=8, addend_offset=24, base_offset=40, object_offset=64,
             length=SIZE, count=MASK, total=MASK - 3, addend=7, seed=17):
        image = bytearray((seed + 29 * j) % 256 for j in range(SIZE))
        address = lambda offset: (image_base + offset) % MOD
        def put(offset, value, width):
            if 0 <= offset and offset + width <= SIZE:
                image[offset:offset + width] = (value % (256 ** width)).to_bytes(width, 'little')
        put(entry_offset + 176, count, 8)
        put(entry_offset + 64, total, 8)
        put(addend_offset, addend, 8)
        # Pointer and index setup may deliberately overlap update words. The
        # expectations always read the resulting complete immutable image.
        put(selector_offset, address(object_offset) if present else 0, 8)
        put(object_offset + 32, index, 4)
        put(base_offset, address(entry_offset) - 8 * (index if present else 13), 8)
        rows.add((image_base, address(selector_offset), address(addend_offset),
                  address(base_offset), length, bytes(image)))

    indices = [-2 ** 31, -2 ** 31 + 1, -65536, -129, -1, 0, 1, 12, 13, 127, 65536, 2 ** 31 - 1]
    addends = [0, 1, 2 ** 32 - 1, 2 ** 32, 2 ** 63, MASK]
    for index in indices:
        for present in [False, True]:
            for image_base in [0, 4096, MOD - SIZE]:
                for entry_offset in [-64, -1, 0, 224, 328]:
                    for addend in addends:
                        make(index, present, image_base, entry_offset, addend=addend)
    # All 15 partial/exact alias displacements of an eight-byte addend read
    # with either updated word; every byte lane carries nontrivial data.
    for entry_offset in [112, 224]:
        for target in [64, 176]:
            for delta in range(-7, 8):
                for index in [-1, 0, 13, 2 ** 31 - 1]:
                    make(index, entry_offset=entry_offset,
                         addend_offset=entry_offset + target + delta,
                         count=0x8877665544332211, total=0xfedcba9876543210,
                         addend=0x1020304050607080)
    # State/updated-word aliases: selector pointers, index fields and loaded
    # base slots can change after their snapshotted uses.
    for entry_offset in [112, 224]:
        for target in [64, 176]:
            for delta in range(-7, 8):
                make(-1, entry_offset=entry_offset, selector_offset=entry_offset + target + delta)
                make(13, entry_offset=entry_offset, base_offset=entry_offset + target + delta)
            for delta in range(-3, 8):
                make(-1, entry_offset=entry_offset, object_offset=entry_offset + target + delta - 32)
    # Load operands may alias each other as well, including null pointer slots.
    for selector_offset in [0, 8, 24, 40, 96]:
        for addend_offset in [0, 8, 24, 40, 96]:
            for base_offset in [0, 8, 24, 40, 96]:
                make(selector_offset=selector_offset, addend_offset=addend_offset, base_offset=base_offset)
    for length in [0, 7, 8, 15, 16, 31, 32, 47, 48, 95, 96, 99, 100, 287, 288, 295, 296, 399, 400, 407, 408, 511, 512]:
        for present in [False, True]:
            make(present=present, length=length)
            make(present=present, entry_offset=-65, length=length)
    for image_base in [MOD - SIZE + 1, MASK - 7, MASK]:
        make(image_base=image_base)
    for index in [-2 ** 31, -1, 0, 1, 2 ** 31 - 1]:
        for lane in range(8):
            for bit in [0, 7]:
                value = 1 << (8 * lane + bit)
                make(index, count=MASK - value, total=value, addend=MASK)
    # Field address +32 may wrap while the actual four accessed bytes are in
    # the image. The pointer's numeric base itself need not be dereferenced.
    make(-1, image_base=0, object_offset=-32)
    for source_index in range(256):
        raw = bytes.fromhex(sha(f'indexed-accumulator94:{source_index}'.encode()))
        index = int.from_bytes(raw[:4], 'little', signed=True)
        make(index, count=int.from_bytes(raw[4:12], 'little'), total=int.from_bytes(raw[12:20], 'little'),
             addend=int.from_bytes(raw[20:28], 'little'), entry_offset=raw[28] + 32, seed=raw[29])
    return sorted(rows)


def fixtures():
    rows = corpus()
    inputs = b''.join(HEADER.pack(*row[:5]) + row[5] for row in rows)
    expected_rows = [expected(row) for row in rows]
    outputs = b''.join(expected_rows)
    counts = {str(code): sum(row[0] == code for row in expected_rows) for code in range(8)}
    require(all(counts.values()), 'missing admission branch')
    return inputs, outputs, {'target_sha256': TARGET, 'cases': len(rows), 'image_bytes': SIZE,
        'input_record_bytes': HEADER.size + SIZE, 'output_record_bytes': OUTPUT.size + SIZE,
        'outcome_counts': counts, 'inputs_sha256': sha(inputs), 'expected_sha256': sha(outputs),
        'oracle': 'unbounded signed index arithmetic and two disjoint immutable byte overlays',
        'address_arithmetic': 'all effective address additions reduced modulo 2^64 before mapped-span checks',
        'refusal': 'new atomic safe admission; not original error results',
        'return': 'full numeric RAX entry address, not the signed index'}


def main():
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze is supported')
    require(not (ROOT / 'src/node94-indexed-accumulator').exists(), 'freeze must precede Rust')
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
