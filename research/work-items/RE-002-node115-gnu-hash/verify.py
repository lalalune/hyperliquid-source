"""Qualify the GNU hash layout used for the pinned node's dynamic export."""
from hashlib import sha256
from pathlib import Path
import struct

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def gnu_hash(name):
    h = 5381
    for byte in name:
        h = (33 * h + byte) & 0xffffffff
    return h


data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != SHA:
    raise ValueError("wrong node digest")
phoff = struct.unpack_from("<Q", data, 32)[0]
stride, count = struct.unpack_from("<HH", data, 54)
headers = [struct.unpack_from("<II6Q", data, phoff + n * stride) for n in range(count)]
(_, _, off, _, _, size, _, _), = (h for h in headers if h[0] == 2)
tags = {}
for tag, value in struct.iter_unpack("<QQ", data[off:off + size]):
    if tag == 0:
        break
    tags[tag] = value


def read(va, size):
    offset, = (off + va - start for kind, _, off, start, _, length, _, _ in headers
               if kind == 1 and start <= va <= start + length - size)
    return data[offset:offset + size]


hash_va = tags[0x6ffffef5]
buckets, first, words, shift, bloom, bucket, chain = struct.unpack(
    "<IIIIQII", read(hash_va, 32))
assert (buckets, first, words, shift, bucket) == (1, 509, 1, 26, 509)
assert tags[5] == hash_va + 32 and tags[11] == 24
name_offset, _, _, shndx, _, _ = struct.unpack(
    "<IBBHQQ", read(tags[6] + 24 * bucket, 24))
assert shndx != 0 and name_offset < tags[10]
strings = read(tags[5], tags[10])
name = strings[name_offset:strings.index(b"\0", name_offset)]
hash_value = gnu_hash(name)
mask = (1 << (hash_value % 64)) | (1 << ((hash_value >> shift) % 64))
assert name == b"_ZNKSt5ctypeIcE8do_widenEc"
assert bloom == mask and chain == hash_value | 1
changed = name[:-1] + b"e"
assert gnu_hash(name[:-1] + b"d") & ~1 == chain & ~1
assert gnu_hash(changed) & ~1 != chain & ~1
print("node #115 sha256", SHA)
print(f"DT_GNU_HASH {hash_va:#x}, bucket 0 -> symbol {bucket}, shift {shift}")
print(name.decode(), f"hash={hash_value:#x} chain={chain:#x} bloom={bloom:#018x}")
print("one-byte altered name rejected by chain hash")
print("second altered name matches masked hash but differs in bytes")
