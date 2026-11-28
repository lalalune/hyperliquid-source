"""Check the selected node #115 book level address paths."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x4DA5F90, 0x4DA7010, 0x5911890, 0x5911B30)
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

targets = {0x591190B: 0x4DA5F90, 0x5911BAB: 0x4DA7010}
twin_delta = 0x1080

def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, target in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-4:], "little", signed=True) == target
    for address, ins in rows.items():
        if 0x4DA5F90 <= address <= 0x4DA60CE:
            assert reader(address + twin_delta, len(ins)) == ins

check(read)
controls = (0x4DA5FA4, 0x4DA5FB7, 0x4DA60B8, 0x4DA7143, 0x591190C)
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


cases = 0
for capacity in range(1, 17):
    for head in range(capacity):
        slots = [0x1000 + 136 * slot + 8 for slot in range(capacity)]
        ordered = slots[head:] + slots[:head]
        for logical, expected in enumerate(ordered):
            physical = head + logical
            if physical >= capacity:
                physical -= capacity
            assert 0x1000 + (physical << 7) + 8 * physical + 8 == expected
            cases += 1

print(f"{len(rows)} instructions, {len(targets)} caller targets, {len(controls)} corruption controls")
print(f"{cases} synthetic ring coordinates checked")
