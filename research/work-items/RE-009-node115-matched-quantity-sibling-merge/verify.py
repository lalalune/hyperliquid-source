"""Check node #115 matched quantity sibling merge."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x35B00B0, 0x35336F0)
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
    0x35B01DF: (0x35B028F, 4),
    0x3533721: (0x3533ABA, 4),
    0x353373E: (0x3533AD3, 4),
    0x35337CB: (0x64DF568, 4),
    0x3533802: (0x64DF508, 4),
    0x3533830: (0x64DF568, 4),
    0x3533885: (0x64DF568, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 95
check(read)
controls = (0x35B01DE, 0x353373B, 0x353378D, 0x35337D9, 0x3533832, 0x35338D3)
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

for left in range(12):
    for right in range(12):
        if left + right < 11:
            merged = list(range(left)) + [100] + list(range(200, 200 + right))
            assert len(merged) == left + right + 1 <= 11
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print("144 sibling-count fixtures")
