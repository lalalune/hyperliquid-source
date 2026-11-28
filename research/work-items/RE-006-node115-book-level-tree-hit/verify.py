"""Check the selected node #115 book level tree-hit path."""
from bisect import bisect_left
from hashlib import sha256
from itertools import combinations
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x4DC42F0, 0x4DC52B0, 0x5911890, 0x5911B30)
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

targets = {0x5911901: 0x4DC42F0, 0x5911BA1: 0x4DC52B0}
twin_delta = 0xFC0

def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, target in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-4:], "little", signed=True) == target
    for address, ins in rows.items():
        if 0x4DC4571 <= address <= 0x4DC4654:
            assert reader(address + twin_delta, len(ins)) == ins

check(read)
controls = (0x4DC4589, 0x4DC45A9, 0x4DC45BC, 0x4DC4637, 0x4DC55FF, 0x5911902)
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


def scan(keys, key):
    index = 0
    for current in keys:
        index += 1
        if key <= current:
            return index - 1, key == current
    return index, False


count = 0
for size in range(12):
    for keys in combinations(range(-5, 6), size):
        for key in range(-6, 7):
            index = bisect_left(keys, key)
            assert scan(keys, key) == (index, index < len(keys) and keys[index] == key)
            count += 1
print(f"{len(rows)} instructions, {len(targets)} caller targets, {len(controls)} corruption controls")
print(f"{count} synthetic signed node-scan cases checked")
