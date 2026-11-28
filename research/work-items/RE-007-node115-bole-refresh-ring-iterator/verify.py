"""Check node #115 BOLE refresh flat iterator."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x4506810, 0x369A480)
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
    0x369A678: (0x4506810, 4),
    0x4506829: (0x4506848, 1),
    0x4506842: (0x4506A37, 4),
    0x369A680: (0x369B0C7, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
check(read)
controls = (0x4506817, 0x4506834, 0x4506844, 0x450684C, 0x4506855, 0x369A68B)
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


def step(spans):
    start, end, other_start, other_end = spans
    if start == end:
        start, end, other_start, other_end = other_start, other_end, start, end
        if start == end:
            return (0, 8), (start, end, other_start, other_end)
    return (start, start + 8), (start + 184, end, other_start, other_end)


cases = 0
for first in range(13):
    for second in range(13):
        state = (0x10000, 0x10000 + 184 * first, 0x8000, 0x8000 + 184 * second)
        expected = [0x10000 + 184 * index for index in range(first)]
        expected += [0x8000 + 184 * index for index in range(second)]
        for address in expected:
            pair, state = step(state)
            assert pair == (address, address + 8)
        for _ in range(3):
            pair, state = step(state)
            assert pair == (0, 8)
        cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} synthetic span-length pairs checked")
