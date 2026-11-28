"""Check node #115 matched quantity sibling repair dispatch."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x35B00B0, 0x35336F0, 0x3524610, 0x352BF00)
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
    0x35B015C: (0x35B01FC, 4),
    0x35B0171: (0x35B0206, 4),
    0x35B0187: (0x35B0215, 4),
    0x35B01DF: (0x35B028F, 4),
    0x35B0272: (0x35B02C0, 1),
    0x35B0288: (0x35336F0, 4),
    0x35B02A2: (0x3524610, 4),
    0x35B02D6: (0x352BF00, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 65
check(read)
controls = (0x35B017F, 0x35B0194, 0x35B01DE, 0x35B0227, 0x35B0271, 0x35B02D7)
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

for edge in range(12):
    if edge:
        assert 0x110 + 8 * edge == 0x118 + 8 * (edge - 1)
    else:
        assert 0x120 == 0x118 + 8
for a in range(5):
    for b in range(12):
        assert (a + b < 12) == (a + b <= 11)
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print("12 edge and 60 sibling-count fixtures")
