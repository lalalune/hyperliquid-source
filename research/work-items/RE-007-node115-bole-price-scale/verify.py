"""Check node #115 BOLE refresh scale binding."""
from hashlib import sha256
from itertools import product
from pathlib import Path
import re
from struct import iter_unpack

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x369A480, 0x369F730, 0x5C43C60)
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
    0x369AA3B: 0x369F730, 0x369AAAB: 0x369F730, 0x369AC84: 0x369F730,
    0x369F7E3: 0x5C43C60, 0x369F900: 0x64E6468,
    0x369F827: 0x4553C4, 0x369F833: 0x4553CC,
    0x369F90D: 0x369F91F,
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, target in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-1:] if site == 0x369F90D else ins[-4:], "little", signed=True) == target
    assert reader(0x4553C4, 12) == bytes(12)


reloc = by_name[".rela.dyn"]
reloc_data = data[reloc["offset"]:reloc["offset"] + reloc["size"]]
assert [row for row in iter_unpack("<QQq", reloc_data) if row[0] == 0x64E6468] == [
    (0x64E6468, 8, 0x421E9D0)
]

check(read)
controls = (0x369F73D, 0x369F796, 0x369F8EB, 0x369F8FD, 0x369F90B, 0x4553CC)
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


def scale_digits(base_digits, reference_digits):
    return None if base_digits < reference_digits else base_digits - reference_digits


count = 0
for base, reference in product(range(256), repeat=2):
    expected = bytes([base - reference])[0] if base >= reference else None
    assert scale_digits(base, reference) == expected
    count += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, one ELF relocation")
print(f"{len(controls)} corruption controls and {count} synthetic scale-byte pairs checked")
