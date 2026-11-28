"""Reproduce two direct initializer calls into the registered zlib window."""
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import sections

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == SHA
layout = {s["name"]: s for s in sections(data)}


def read(section, va, size):
    row = layout[section]
    rel = va - row["address"]
    assert 0 <= rel <= row["size"] - size
    offset = row["offset"] + rel
    return data[offset:offset + size]


def destination(va, instruction):
    assert instruction[0] == 0xe8 and len(instruction) == 5
    return va + 5 + struct.unpack_from("<i", instruction, 1)[0]


print("node #115 sha256", SHA)
for mode, label, size, call in [
    (0x5db13b2, 0x5db13c1, 0x5db13cb, 0x5db13d3),
    (0x616c60a, 0x616c619, 0x616c623, 0x616c62b),
]:
    assert read(".text", mode, 5) == bytes.fromhex("bef2ffffff")
    assert read(".text", size, 5) == bytes.fromhex("b970000000")
    arg = read(".text", label, 7)
    assert arg[:3] == bytes.fromhex("488d15")
    literal = label + 7 + struct.unpack_from("<i", arg, 3)[0]
    assert literal == 0x433f30 and read(".rodata", literal, 6) == b"1.3.1\0"
    raw = read(".text", call, 5)
    assert destination(call, raw) == 0x6305810
    assert read(".text", call + 5, 4) == bytes.fromhex("85c00f85")
    assert destination(call, raw[:1] + bytes([raw[1] ^ 1]) + raw[2:]) != 0x6305810
    print(f"{call:#x} {raw.hex()} -> inflateInit2_ VA 0x6305810: window -14, version 1.3.1, size 112")
print("two altered displacement controls fail destination check")

for zero, call, branch, success in [
    (0x5db128f, 0x5db12ba, 0x84, 0x5db1a00),
    (0x616c4f7, 0x616c528, 0x85, 0x616c535),
]:
    assert read(".text", zero, 4) == bytes.fromhex("31d231f6")
    raw = read(".text", call, 5)
    assert destination(call, raw) == 0x630d080
    tail = read(".text", call + 5, 8)
    assert tail[:4] == bytes((0x85, 0xc0, 0x0f, branch))
    zero_target = call + 13 + struct.unpack_from("<i", tail, 4)[0] if branch == 0x84 else call + 13
    assert success == zero_target
    print(f"{call:#x} {raw.hex()} -> BZ2_bzDecompressInit VA 0x630d080: both scalar arguments 0, zero return -> {success:#x}")
