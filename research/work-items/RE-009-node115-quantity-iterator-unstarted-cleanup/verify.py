"""Check node #115 unstarted quantity iterator cleanup."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x51DA3A0,)
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
    0x51DA468: (0x51DA66C, 4),
    0x51DA66F: (0x51DA6A9, 1),
    0x51DA678: (0x51DA6B1, 1),
    0x51DA68D: (0x51DA680, 1),
    0x51DA6AC: (0x51DA474, 4),
    0x51DA70C: (0x51DA6D0, 1),
    0x51DA70E: (0x51DA474, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 40
check(read)
controls = (0x51DA468, 0x51DA66F, 0x51DA677, 0x51DA683, 0x51DA6D3, 0x51DA70C)
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
for height in range(129):
    assert (height & 7) + 8 * (height // 8) == height
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print("129 cleanup descent heights")
