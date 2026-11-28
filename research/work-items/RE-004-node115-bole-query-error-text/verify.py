"""Verify the selected borrow/lend error paths against node #115."""
from hashlib import sha256
from pathlib import Path
import re
from struct import iter_unpack

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
for bounds in ((0x3D4EB60, 0x3D4EBB4), (0x46DE430, 0x46DE67A)):
    assert any((entry["start"], entry["end"]) == bounds for entry in entries)

by_name = {section["name"]: section for section in sections}


def read(va, size):
    for name in (".text", ".rodata", ".rela.dyn"):
        section = by_name[name]
        delta = va - section["address"]
        if 0 <= delta <= section["size"] - size:
            start = section["offset"] + delta
            return data[start:start + size]
    raise AssertionError(hex(va))


row_pattern = re.compile(r"^\s*([a-f0-9]+):\t([a-f0-9 ]+)\s+\t")
rows = {}
for line in Path(__file__).with_name("windows.txt").read_text().splitlines():
    match = row_pattern.match(line)
    if match:
        rows[int(match[1], 16)] = bytes.fromhex(match[2])

targets = {
    0x38E61BA: 0x64E9570, 0x38E6968: 0x64E9570,
    0x3D4EB72: 0x46DE430, 0x3D4EB8B: 0x3D57B80,
    0x46DE447: 0x7D7B94, 0x46DE499: 0x64E28A0, 0x46DE4C5: 0x46DE5A7,
    0x46EF717: 0x7D8C1C, 0x46F1049: 0x41C68E0, 0x46F105C: 0x43BE19,
    0x41C68F3: 0x7C6728, 0x41C6901: 0x64EA670, 0x41C8AB3: 0x7C639C,
    0x41C8ACE: 0x7C6736,
}
slots = {0x64E9570: 0x3D4EB60, 0x64E28A0: 0x46EF710, 0x64EA670: 0x41C8AB0}
tables = ((0x7D7B94, 0xF1, 0x46DE457), (0x7D8C1C, 0xF1, 0x46F1039),
          (0x7C639C, 0, 0x41C8AC3))
literals = {0x43BE19: b"\x13Borrow/Lend error: \xc0\x00",
            0x7C6728: b"Internal error", 0x7C6736: b"Invalid token"}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, target in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-4:], "little", signed=True) == target
    reloc = by_name[".rela.dyn"]
    actual = [(offset, kind, addend) for offset, kind, addend in iter_unpack(
        "<QQq", reader(reloc["address"], reloc["size"])) if offset in slots]
    assert sorted(actual) == sorted((slot, 8, target) for slot, target in slots.items())
    for base, index, target in tables:
        delta = int.from_bytes(reader(base + 4 * index, 4), "little", signed=True)
        assert base + delta == target
    for address, literal in literals.items():
        assert reader(address, len(literal)) == literal, hex(address)


check(read)
controls = (0x38E61A5, 0x38E695A, 0x46DE49F, 0x7C639C, 0x7C6728, 0x7C6736)
for bad in controls:
    def corrupt(va, size):
        raw = bytearray(read(va, size))
        if va <= bad < va + size:
            raw[bad - va] ^= 1
        return raw

    try:
        check(corrupt)
    except AssertionError:
        continue
    raise AssertionError(f"mutation at {bad:#x} was accepted")

print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(slots)} relocations")
print(f"{len(tables)} table entries, {len(literals)} literals, {len(controls)} corruption controls passed")
