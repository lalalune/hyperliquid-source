"""Reproduce the Snappy size probe and selected allocator handoff."""
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
for probe, load, stack_delta, allocate, decode in [
    (0x5db14d2, 0x5db1990, -0xb0, 0x5db19a7, 0x5db19bd),
    (0x616c412, 0x616ca40, -0xd0, 0x616ca56, 0x616ca74),
]:
    assert destination(probe, read(".text", probe, 5)) == 0x620b5a0
    init = read(".text", probe - 21, 11)
    assert init[:3] == bytes.fromhex("48c785")
    assert struct.unpack_from("<ii", init, 3) == (stack_delta, 0)
    args = read(".text", probe - 10, 10)
    assert args[:3] == bytes.fromhex("4889c2")
    test_branch = read(".text", probe + 5, 8)
    assert test_branch[:4] == bytes.fromhex("84c00f85")
    assert probe + 13 + struct.unpack_from("<i", test_branch, 4)[0] == load
    insn = read(".text", load, 7)
    assert insn[:3] == bytes.fromhex("488bb5")
    assert struct.unpack_from("<i", insn, 3)[0] == stack_delta
    invoke = read(".text", allocate, 6)
    assert invoke == bytes.fromhex("ff9098000000")
    handoff = {0x5db19bd: 0x5db19ad, 0x616ca74: 0x616ca6a}[decode]
    assert read(".text", handoff, 3).hex() == "4889c2"
    assert destination(decode, read(".text", decode, 5)) == 0x620db60
    assert read(".text", decode + 5, 2) == bytes.fromhex("84c0")
    assert probe + 13 + (struct.unpack_from("<i", test_branch, 4)[0] ^ 1) != load
    print(f"{probe:#x} size probe -> {load:#x} (stack {stack_delta:#x}) -> {allocate:#x} slot 0x98 -> {decode:#x} raw decode")
print("two changed branch displacements fail to reach size loads")
