"""Check the selected node #115 book level cache check."""
from hashlib import sha256
from itertools import product
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x518E690, 0x5911890, 0x5911B30, 0x58E1400)
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
    0x5911929: 0x518E690, 0x5911BC9: 0x518E690, 0x58E1A59: 0x518E690,
    0x518E6D0: 0x518EC00, 0x518E6E5: 0x518EBEE,
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, target in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-4:], "little", signed=True) == target
check(read)
controls = (0x518E6B0, 0x518E6BE, 0x518E6C7, 0x518E6CF, 0x518E6D9, 0x518E6E6)
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


def entry_path(level_tag, index, count, row_tag, ring_length):
    if level_tag != 1:
        return False, "ring" if ring_length else "return"
    if index >= count or row_tag == 2:
        return True, "ring" if ring_length else "return"
    return False, "cached-row"


seen = set()
for tag, index, count, row, length in product(range(3), range(4), range(4), range(4), range(2)):
    keep = tag == 1 and index < count and row != 2
    clear = tag == 1 and not keep
    destination = "cached-row" if keep else ("ring" if length else "return")
    assert entry_path(tag, index, count, row, length) == (clear, destination)
    seen.add((clear, destination))
assert len(seen) == 5
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print("384 synthetic cache input tuples checked")
