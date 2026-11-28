"""Check node #115 quantity-tree right-edge growth."""
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
owners = (0x4CAFF20,)
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
    0x4CB019A: (0x4CB01B0, 1),
    0x4CB01A8: (0x4CB0190, 1),
    0x4CB01AA: (0x4CB020C, 1),
    0x4CB01BD: (0x64DF480, 4),
    0x4CB0211: (0x64DF480, 4),
    0x4CB023D: (0x4CB0288, 1),
    0x4CB0245: (0x64DF480, 4),
    0x4CB0286: (0x4CB0240, 1),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 55
check(read)
controls = (0x4CB0192, 0x4CB01A7, 0x4CB01B9, 0x4CB020D, 0x4CB02C8, 0x4CB02D5)
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


def growth(parent_counts):
    height = 1
    for count in parent_counts:
        if count < 11:
            return False, height, count + 1
        height += 1
    return True, height, 1


cases = 0
for depth in range(8):
    for counts in product((0, 1, 10, 11), repeat=depth):
        root, height, edge = growth(counts)
        full_prefix = 0
        for count in counts:
            if count != 11:
                break
            full_prefix += 1
        assert root == (full_prefix == depth)
        assert height == full_prefix + 1
        assert edge == (1 if root else counts[full_prefix] + 1)
        cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} right-edge occupancy fixtures")
