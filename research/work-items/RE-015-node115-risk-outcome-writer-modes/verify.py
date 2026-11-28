"""Check node #115 risk outcome writer modes."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x2271480, 0x28FFAB0, 0x25E7670, 0x25E7940)
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
    0x22715FB: (0x28FFAB0, 4), 0x28FFAE3: (0x25E7670, 4),
    0x28FFB15: (0x25E7940, 4), 0x28FFB59: (0x25E9C70, 4),
    0x28FFC1C: (0x22E6FC0, 4), 0x28FFC69: (0x2276C90, 4),
}
keys = {0x5FEE41: b"outcome", 0x5FFA08: b"settleFraction", 0x5FEE24: b"details",
        0x5FFA16: b"nameAndDescription", 0x5FF299: b"sideNames"}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
    for address, key in keys.items():
        assert reader(address, len(key)) == key


check(read)
controls = (0x28FFAD2, 0x28FFADF, 0x28FFB11, 0x28FFB28, 0x28FFB4D, 0x5FFA08)
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


print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
