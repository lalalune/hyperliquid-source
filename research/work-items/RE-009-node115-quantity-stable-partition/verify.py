"""Check node #115 stable quantity partition."""
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
owners = (0x4290A90,)
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
    0x4290B97: (0x4290D70, 4),
    0x4290BA0: (0x4290F57, 4),
    0x4290C02: (0x4290BD0, 1),
    0x4290C30: (0x4290BC0, 1),
    0x4290C57: (0x64DF508, 4),
    0x4290CEC: (0x4290CB0, 1),
    0x4290CF2: (0x4290D12, 1),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 90
check(read)
controls = (0x4290BA0, 0x4290BD7, 0x4290BE2, 0x4290BF9, 0x4290CE7, 0x4290CF1)
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


def partition(rows, pivot_index):
    scratch = [None] * len(rows)
    low, high = 0, len(rows) - 1
    pivot = rows[pivot_index][0]
    for i, row in enumerate(rows):
        if i != pivot_index and row[0] < pivot:
            scratch[low] = row
            low += 1
        else:
            scratch[high] = row
            high -= 1
    return low, scratch[:low] + scratch[low:][::-1]


cases = 0
for count in range(1, 7):
    for keys in product((0, 1, 2**63, 2**64 - 1), repeat=count):
        sample = [(key, idx, idx * 7 + 1) for idx, key in enumerate(keys)]
        for pivot in range(count):
            left = [row for row in sample if row[0] < keys[pivot]]
            right = [row for row in sample if row[0] >= keys[pivot]]
            assert partition(sample, pivot) == (len(left), left + right)
            cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} synthetic partition fixtures")
