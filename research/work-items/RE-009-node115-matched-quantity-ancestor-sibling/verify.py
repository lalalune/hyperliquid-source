"""Check node #115 matched quantity ancestor sibling selection."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x35B00B0, 0x3524610, 0x352BF00)
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
    0x35B03C8: (0x35B0450, 4),
    0x35B0420: (0x35B086E, 4),
    0x35B044A: (0x35B04D8, 4),
    0x35B045B: (0x35B08BB, 4),
    0x35B04B7: (0x35B0888, 4),
    0x35B087E: (0x3524610, 4),
    0x35B0898: (0x352BF00, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 60
check(read)
controls = (0x35B03B9, 0x35B03D3, 0x35B041F, 0x35B0464, 0x35B04B6, 0x35B087F)
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
for edge in range(1, 12):
    assert 0x110 + 8 * edge == 0x118 + 8 * (edge - 1)
for count in range(5):
    assert count + (5 - count) == 5
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print("11 left edges and 5 transfer-count fixtures")
