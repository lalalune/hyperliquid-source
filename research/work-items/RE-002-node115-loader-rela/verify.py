"""Verify the node #115 loader's RELA partition without section headers."""
from collections import Counter
from hashlib import sha256
from pathlib import Path
import struct

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def partition(rows, count):
    if not 0 <= count <= len(rows):
        raise ValueError("RELACOUNT out of range")
    if any(info != 8 for _, info, _ in rows[:count]):
        raise ValueError("non-relative row in prefix")
    if any(info & 0xffffffff == 8 for _, info, _ in rows[count:]):
        raise ValueError("relative row outside prefix")
    return Counter(info & 0xffffffff for _, info, _ in rows[count:])


def main():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    if sha256(data).hexdigest() != DIGEST:
        raise ValueError("wrong target")
    print("node #115 sha256", DIGEST)
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 54)
    headers = [struct.unpack_from("<II6Q", data, phoff + i * entsize)
               for i in range(count)]
    dynamic, = [h for h in headers if h[0] == 2]
    _, _, offset, _, _, size, _, _ = dynamic
    tags = {}
    for tag, value in struct.iter_unpack("<QQ", data[offset:offset + size]):
        if not tag:
            break
        if tag != 1:
            if tag in tags:
                raise ValueError("duplicate singleton tag")
            tags[tag] = value
    else:
        raise ValueError("missing DT_NULL")

    def mapped(va, length):
        start, = [off + va - addr for kind, _, off, addr, _, filesz, _, _ in headers
                  if kind == 1 and addr <= va <= addr + filesz - length]
        return data[start:start + length]

    rela_size = tags[8]
    plt_size = tags[2]
    assert tags[9] == 24 and tags[20] == 7
    assert tags[7] + rela_size <= tags[23]
    assert not {35, 36, 37} & tags.keys()
    rows = list(struct.iter_unpack("<QQq", mapped(tags[7], rela_size)))
    plt = Counter(info & 0xffffffff for _, info, _ in
                  struct.iter_unpack("<QQq", mapped(tags[23], plt_size)))
    relative_count = tags[0x6ffffff9]
    suffix = partition(rows, relative_count)
    assert (len(rows), relative_count, suffix, plt) == (
        60723, 59534, {1: 924, 6: 263, 18: 2}, {7: 278})
    print(f"PT_DYNAMIC file offset {offset:#x}; DT_RELR tags absent")
    print(f"DT_RELA VA {tags[7]:#x}, rows {len(rows)}, relative prefix {relative_count}")
    print("DT_RELA suffix type counts", sorted(suffix.items()))
    print(f"DT_JMPREL VA {tags[23]:#x}, type counts {sorted(plt.items())}")
    for wrong_count in (relative_count - 1, relative_count + 1):
        try:
            partition(rows, wrong_count)
        except ValueError as error:
            print(f"wrong RELACOUNT {wrong_count} rejected: {error}")
        else:
            raise RuntimeError("wrong RELACOUNT accepted")


if __name__ == "__main__":
    main()
