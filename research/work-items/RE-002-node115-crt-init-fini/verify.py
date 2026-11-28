"""Verify DT_INIT/DT_FINI and the optional profiling hook statically."""
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import sections

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != SHA:
    raise ValueError("wrong node digest")
layout = {s["name"]: s for s in sections(data)}


def raw(name):
    section = layout[name]
    off = section["offset"]
    return data[off:off + section["size"]]


tags = {}
for key, val in struct.iter_unpack("<QQ", raw(".dynamic")):
    if not key:
        break
    tags[key] = val
init, fini = raw(".init"), raw(".fini")
assert tags[12] == layout[".init"]["address"] == 0x63f0a00
assert tags[13] == layout[".fini"]["address"] == 0x63f0a1c
assert init.hex() == "f30f1efa4883ec08488b0551ea0e004885c07402ffd04883c408c3"
assert fini.hex() == "f30f1efa4883ec084883c408c3"
slot = tags[12] + 15 + struct.unpack_from("<i", init, 11)[0]
_, info, addend = tuple(
    row for row in struct.iter_unpack("<QQq", raw(".rela.dyn")) if row[0] == slot
)[0]
assert (slot, info, addend) == (0x64df460, (2 << 32) | 6, 0)
offset, flags, _, index, _, _ = struct.unpack_from("<IBBHQQ", raw(".dynsym"), 24 * (info >> 32))
strings = raw(".dynstr")
name = strings[offset:strings.index(b"\0", offset)]
assert name == b"__gmon_start__" and index == 0 and flags >> 4 == 2


def branch_target(body):
    if body[18] != 0x74:
        raise ValueError("conditional branch changed")
    return 20 + struct.unpack_from("<b", body, 19)[0]


assert branch_target(init) == 22
assert branch_target(init[:19] + bytes([0]) + init[20:]) != 22
print("node #115 sha256", SHA)
print(f"DT_INIT {tags[12]:#x}, DT_FINI {tags[13]:#x}")
print(f"DT_INIT GOT slot {slot:#x}: GLOB_DAT for undefined weak {name.decode()}")
print("null slot skips indirect call; zero displacement mutation fails that check")
print("DT_FINI has no call")
