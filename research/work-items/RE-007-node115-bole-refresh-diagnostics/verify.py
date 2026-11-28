"""Check node #115 BOLE refresh diagnostics."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x369A480, 0x3CE2D10)
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
    0x369AA46: (0x369ABDD, 4), 0x369AC00: (0x79D402, 4),
    0x369AC8F: (0x369AE7E, 4), 0x369AEB3: (0x79D409, 4),
    0x369AEBA: (0x369AB3D, 4), 0x369AEFD: (0x369B040, 4),
    0x369B063: (0x79D42F, 4), 0x369B011: (0x3CE2D10, 4),
}
constants = {
    0x79D402: b"mark px",
    0x79D409: b"oracle px",
    0x79D42F: b"missing median",
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
    for address, value in constants.items():
        assert reader(address, len(value)) == value


check(read)
controls = (0x369AA47, 0x369AC10, 0x369AC90, 0x369AEB6, 0x369B072, 0x79D42F)
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


print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(constants)} literal spans")
print(f"{len(controls)} corruption controls passed")
