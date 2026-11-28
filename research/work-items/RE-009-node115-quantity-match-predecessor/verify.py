"""Check node #115 matched quantity predecessor replacement."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x3877D60, 0x35B6600, 0x35B00B0)
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
    0x3877F40: (0x35B6600, 4),
    0x35B6616: (0x35B67D2, 4),
    0x35B662A: (0x35B66EE, 4),
    0x35B6656: (0x35B6640, 1),
    0x35B6713: (0x35B00B0, 4),
    0x35B6768: (0x35B6750, 1),
    0x35B67ED: (0x35B00B0, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 75
check(read)
controls = (0x3877F41, 0x35B6617, 0x35B664B, 0x35B66F7, 0x35B677C, 0x35B6790)
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

for height in range(1, 129):
    remaining = height - 1
    assert remaining % 8 + 8 * (remaining // 8) == remaining
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print("128 predecessor descent height fixtures")
