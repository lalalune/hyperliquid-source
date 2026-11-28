"""Check node #115 fixed20 sequence serializer."""
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
owners = (0x2270910, 0x2EABB50)
assert all(any(entry["start"] == owner for entry in entries) for owner in owners)

by_name = {section["name"]: section for section in sections}


def read(va, size):
    for name in (".text", ".rodata"):
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
    0x227094C: (0x2270C72, 4), 0x22709B0: (0x25E7940, 4),
    0x2270A1A: (0x64E4D08, 4), 0x2270A42: (0x64E4D08, 4),
    0x2270A26: (0x25E8750, 4), 0x2270A7D: (0x25E8750, 4),
    0x2270C79: (0x5E90A1, 4), 0x2EABB89: (0x455D40, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
    assert reader(0x5E90A1, 14) == b"expected tuple"
    assert reader(0x455D40, 16) == b"0123456789abcdef"


reloc = by_name[".rela.dyn"]
data_slice = data[reloc["offset"]:reloc["offset"] + reloc["size"]]
expected = {0x64E4D08: (8, 0x2EABB50)}
actual = [(slot, (kind, target)) for slot, kind, target in iter_unpack("<QQq", data_slice)
          if slot in expected]
assert sorted(actual) == sorted(expected.items())

check(read)
controls = (0x227093A, 0x2270988, 0x2270A66, 0x2270A8F, 0x2EABB66, 0x455D4A)
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



print(f"{len(rows)} instructions, {len(targets)} relative targets, one ELF relocation")
print(f"{len(controls)} corruption controls passed")
