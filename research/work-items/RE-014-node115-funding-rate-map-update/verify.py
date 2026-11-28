"""Check node #115 funding map replacement."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x4DCF640, 0x54A9C70, 0x54B66B0)
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
    0x54AA031: 0x4DCF640, 0x54B6A71: 0x4DCF640,
    0x4DCF7C6: 0x57F8260, 0x4DCF8DB: 0x4DCF9A6,
    0x4DCF9B9: 0x4DCFA19,
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, target in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[1:], "little", signed=True) == target
check(read)
controls = (0x4DCF877, 0x4DCF8C8, 0x4DCF8D3, 0x4DCF9A9, 0x4DCF9B3, 0x4DCF9B5)
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
for capacity in range(1, 16):
    for head in range(capacity):
        physical_slots = [16 * slot + 8 for slot in range(capacity)]
        rotated_slots = physical_slots[head:] + physical_slots[:head]
        for logical, expected in enumerate(rotated_slots):
            physical = head + logical
            if physical >= capacity:
                physical -= capacity
            assert (physical << 4) + 8 == expected
            cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} synthetic flat-ring value addresses checked")
