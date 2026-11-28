"""Check node #115 matched quantity conversion handoff."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x3CE8DF0, 0x3DAC770, 0x390CF80)
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
    0x3CE9059: (0x3CE9097, 1),
    0x3CE90BA: (0x3DAC770, 4),
    0x3CE9146: (0x390CF80, 4),
    0x3CE9154: (0x3CE9140, 1),
    0x3DAC7B2: (0x3DAC7CF, 1),
    0x3DAC7BA: (0x64DF480, 4),
    0x3DAC886: (0x390CF80, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 95
check(read)
controls = (0x3CE9048, 0x3CE90BB, 0x3CE9147, 0x3CE9164, 0x3DAC78D, 0x3DAC7D0)
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
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print("Allocation-size interpretation is a static reading, not a target execution test.")
