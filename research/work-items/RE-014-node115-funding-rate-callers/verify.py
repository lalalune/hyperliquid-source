"""Check the selected node #115 funding-rate caller paths."""
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
owners = (0x54A9C70, 0x54B66B0, 0x44D8590)
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
    0x54AA05C: 0x64E7898, 0x54B6A9C: 0x64E7898,
    0x54AA031: 0x4DCF640, 0x54B6A71: 0x4DCF640,
    0x54AA0D5: 0x54AA020, 0x54B6B15: 0x54B6A60,
    0x54AA124: 0x54AA007, 0x54B6B64: 0x54B6A47,
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, target in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-4:], "little", signed=True) == target
reloc = by_name[".rela.dyn"]
reloc_data = data[reloc["offset"]:reloc["offset"] + reloc["size"]]
assert [row for row in iter_unpack("<QQq", reloc_data) if row[0] == 0x64E7898] == [
    (0x64E7898, 8, 0x44D8590)
]

check(read)
controls = (0x54AA045, 0x54AA06B, 0x54AA077, 0x54AA0D6, 0x54B6AB4, 0x54B6B51)
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


def collect(tag, rate, asset, found):
    if tag == 1:
        return (asset, rate), None
    pending = asset if asset < 10000 and not found else None
    return (asset, 0.0), pending


rows_checked = 0
for tag, rate, asset, found in product((0, 1, 2), (-0.25, 0.25), (0, 9999, 10000), (False, True)):
    pending = asset if (tag != 1 and asset <= 0x270F and not found) else None
    value = rate if tag == 1 else 0.0
    assert collect(tag, rate, asset, found) == ((asset, value), pending)
    rows_checked += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, one ELF relocation")
print(f"{len(controls)} corruption controls and {rows_checked} synthetic routing tuples checked")
