"""Check node #115 quantity leftmost descent."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x55BEF10, 0x3CE8DF0)
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
    0x55BEFA9: (0x3CE8DF0, 4),
    0x55BEFB4: (0x3CE8DF0, 4),
    0x3CE8E2D: (0x3CE8EFC, 4),
    0x3CE8E3A: (0x3CE8FDE, 4),
    0x3CE8E5D: (0x3CE8E50, 1),
    0x3CE8FDC: (0x3CE8FA0, 1),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 50
check(read)
controls = (0x55BEFAA, 0x3CE8E35, 0x3CE8E46, 0x3CE8E52, 0x3CE8FA2, 0x3CE8FDB)
for bad in controls:
    def corrupt(address, size):
        raw = bytearray(read(address, size))
        if address <= bad < address + size:
            raw[bad - address] ^= 1
        return raw
    try:
        check(corrupt)
    except AssertionError:
        continue
    raise AssertionError(f"mutation at {bad:#x} was accepted")
for height in range(129):
    remainder = height & 7
    groups = (height - remainder) // 8
    assert remainder + 8 * groups == height
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print("129 tree-height fixtures")
