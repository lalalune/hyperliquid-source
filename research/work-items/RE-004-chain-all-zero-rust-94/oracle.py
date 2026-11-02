"""Freeze immutable graph-reachability expectations before Rust exists."""
import gzip
import itertools
import struct
from verify_static import PACKET, ROOT, TARGET, encoded, require, sha

MOD = 2 ** 64
MASK = MOD - 1
SIZE = 512
HEADER = struct.Struct('<QQH')  # image base, entry RDI/root-pointer slot, admitted length
OUTPUT = struct.Struct('<BQ')


def expected(row):
    image_base, root_slot, length, image = row
    def result(tag, value=0):
        return OUTPUT.pack(tag, value) + image
    if length and image_base + length > MOD:
        return result(1)
    def read(address, width):
        position = address - image_base
        if position < 0 or position + width > length:
            return None
        return sum(image[position + j] * 256 ** j for j in range(width))
    obj = read(root_slot, 8)
    if obj is None:
        return result(2)
    flag = read((obj + 112) % MOD, 1)
    if flag is None:
        return result(3)
    if flag:
        return result(0, 0)
    node = read((obj + 72) % MOD, 8)
    if node is None:
        return result(4)
    # A visited-address set is independent of the Rust image-derived visit
    # bound. Revisiting a stable zero node proves a nonterminating cycle.
    seen = set()
    while node:
        if node in seen:
            return result(7)
        field = read((node + 16) % MOD, 8)
        if field is None:
            return result(5)
        if field:
            return result(0, 0)
        following = read(node, 8)
        if following is None:
            return result(6)
        seen.add(node); node = following
    return result(0, 1)


def corpus():
    rows = set()
    def make(links=(), fields=(), head=-1, flag=0, image_base=4096, root_offset=8,
             object_offset=32, node_start=160, stride=24, length=SIZE, seed=19,
             raw_head=None, raw_links=None):
        image = bytearray((seed + 17 * j) % 256 for j in range(SIZE))
        address = lambda offset: (image_base + offset) % MOD
        def put(offset, value, width):
            if 0 <= offset and offset + width <= SIZE:
                image[offset:offset + width] = (value % (256 ** width)).to_bytes(width, 'little')
        for index, (link, field) in enumerate(zip(links, fields)):
            target = 0 if link < 0 else address(node_start + stride * link)
            if raw_links is not None:
                target = raw_links[index]
            put(node_start + stride * index, target, 8)
            put(node_start + stride * index + 16, field, 8)
        put(root_offset, address(object_offset), 8)
        value = 0 if head < 0 else address(node_start + stride * head)
        put(object_offset + 72, value if raw_head is None else raw_head, 8)
        put(object_offset + 112, flag, 1)
        rows.add((image_base, address(root_offset), length, bytes(image)))

    # Exhaust all functional successor maps and zero/nonzero assignments on
    # three named nodes, with each head and a null head (64*8*4 descriptors).
    for links in itertools.product(range(-1, 3), repeat=3):
        for mask in range(8):
            fields = [0 if mask & (1 << j) == 0 else 1 << (j * 21) for j in range(3)]
            for head in range(-1, 3):
                make(links, fields, head)
    for count in range(1, 13):
        links = list(range(1, count)) + [-1]
        for image_base in [0, 4096, MOD - SIZE]:
            for phase in [0, 1, 7]:
                make(links, [0] * count, 0, image_base=image_base, node_start=160 + phase)
                for position in range(count):
                    fields = [0] * count; fields[position] = MASK
                    make(links, fields, 0, image_base=image_base, node_start=160 + phase)
        # Tail into every cycle position, including a self-loop at the tail.
        for cycle_entry in range(count):
            make(links[:-1] + [cycle_entry], [0] * count, 0)
    for bit in range(64):
        make([0], [1 << bit], 0, raw_links=[MASK])
    for flag in range(256):
        # Flag at offset zero is readable, but object+72 is outside the image.
        make(flag=flag, object_offset=-112, root_offset=16, image_base=4096)
    for field in [0, 1, 2 ** 32, 2 ** 63, MASK]:
        # Field is readable at zero; the node's own link address is not mapped.
        make([-1], [field], 0, node_start=-16, image_base=4096)
        make([-1], [field], 0, node_start=-16, image_base=0)
    for object_offset in [-112, -72, -1, 0, 32, 400, 401, 440]:
        for flag in [0, 1, 128, 255]:
            make([-1], [0], 0, flag, object_offset=object_offset)
    for length in [0, 7, 8, 15, 16, 103, 104, 111, 112, 143, 144, 145, 159, 160, 167, 168, 175, 176, 183, 184, 511, 512]:
        for flag in [0, 1]:
            make([-1], [0], 0, flag, length=length)
            make([-1], [MASK], 0, flag, length=length)
    for image_base in [MOD - SIZE + 1, MASK - 15, MASK]:
        make(image_base=image_base)
    for root_offset in [-1, 0, 505, 511, 512, 2 ** 32, MASK]:
        make(root_offset=root_offset)
    # Real byte-image aliases and packed/unaligned node placements: outcomes
    # are derived from the final immutable image, not the intended graph labels.
    for node_start in [0, 7, 8, 16, 32, 72, 88, 96, 104, 112, 128, 145, 160]:
        for stride in [1, 7, 8, 15, 16, 23, 24]:
            make([1, 2, -1], [0, 0, 0], 0, node_start=node_start, stride=stride)
    for index in range(256):
        raw = bytes.fromhex(sha(f'chain-all-zero94:{index}'.encode()))
        count = 1 + raw[0] % 12
        links = [(raw[1 + j] % (count + 1)) - 1 for j in range(count)]
        fields = [0 if raw[13 + j] & 3 else 1 << (raw[13 + j] % 64) for j in range(count)]
        make(links, fields, raw[25] % count, seed=raw[26], node_start=160 + raw[27] % 8)
    return sorted(rows)


def fixtures():
    rows = corpus(); outputs = [expected(row) for row in rows]
    inputs = b''.join(HEADER.pack(*row[:3]) + row[3] for row in rows)
    raw = b''.join(outputs)
    counts = {str(code): sum(row[0] == code for row in outputs) for code in range(8)}
    require(all(counts.values()), 'missing admission/cycle outcome')
    returns = {str(value): sum(row[:9] == OUTPUT.pack(0, value) for row in outputs) for value in [0, 1]}
    return inputs, raw, {'target_sha256': TARGET, 'cases': len(rows), 'image_bytes': SIZE,
        'input_record_bytes': HEADER.size + SIZE, 'output_record_bytes': OUTPUT.size + SIZE,
        'outcome_counts': counts, 'success_values': returns, 'inputs_sha256': sha(inputs),
        'expected_sha256': sha(raw), 'oracle': 'immutable graph reachability with a visited-address set',
        'exhaustive_graphs': {'nodes': 3, 'successor_maps': 64, 'zero_nonzero_assignments': 8, 'heads_including_null': 4},
        'refusals': 'new safe bounds and proved-cycle outcomes, not native error returns',
        'return_projection': 'bool encoded as the original full-RAX integer 0 or 1'}


def main():
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze supported')
    require(not (ROOT / 'src/node94-chain-all-zero').exists(), 'freeze must precede Rust')
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
