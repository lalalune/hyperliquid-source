"""Check node #115 quantity ordering run scan."""
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
owners = (0x36E5360, 0x3E73880)
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
    0x36E5401: (0x3E73880, 4),
    0x3E73A4D: (0x3E73A89, 1),
    0x3E73A79: (0x3E73ADA, 1),
    0x3E73AB9: (0x3E73ADA, 1),
    0x3E73AFC: (0x3E73B60, 1),
    0x3E73B57: (0x3E73B20, 1),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 60
check(read)
controls = (0x3E73A4D, 0x3E73A79, 0x3E73AB9, 0x3E73B2C, 0x3E73B54)
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


def scan(rows):
    falling = rows[1][0] < rows[0][0]
    length = 2
    while length < len(rows) and (rows[length][0] < rows[length - 1][0]) == falling:
        length += 1
    return list(reversed(rows[:length])) if falling else rows[:length]


cases = 0
for size in range(2, 8):
    for keys in product((0, 1, 2**63, 2**64 - 1), repeat=size):
        sample = [(key, idx, idx * 3 + 5) for idx, key in enumerate(keys)]
        pairs = list(zip(keys, keys[1:]))
        falling = keys[1] < keys[0]
        first_break = next((pos for pos, (a, b) in enumerate(pairs, 1)
                            if (a > b) != falling), size)
        assert scan(sample) == sorted(sample[:first_break], key=lambda row: row[0])
        cases += 1

print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} synthetic key and payload fixtures")
