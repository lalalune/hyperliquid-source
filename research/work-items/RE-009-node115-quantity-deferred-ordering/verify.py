"""Check node #115 quantity ordering of deferred runs."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records
from line_writer_owners_115 import relative_relocations

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x3E73880, 0x4290A90)
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
    0x3E73997: (0x3E739B0, 1),
    0x3E73A2F: (0x3E73B68, 4),
    0x3E73C63: (0x3E73C80, 1),
    0x3E73E9B: (0x3E73980, 4),
    0x3E73EA5: (0x3E73EDC, 1),
    0x3E73ED6: (0x64EA138, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 59
check(read)
assert relative_relocations(data)[0x64EA138] == 0x4290A90

controls = (0x3E73986, 0x3E73B64, 0x3E73C62, 0x3E73E91, 0x3E73EA4, 0x3E73EC1)
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


counts = list(range(2, 4098))
counts.extend((1 << bit) + delta for bit in range(13, 61) for delta in (-1, 0, 1))
for count in counts:
    top = (count | 1).bit_length() - 1
    budget = (2 * (top ^ 63)) ^ 126
    assert budget % 2 == 0 and 2**(budget // 2) <= count < 2**(budget // 2 + 1)
    for ordered in (0, 1):
        word = 2 * count + ordered
        assert (word >> 1, word & 1) == (count, ordered)

for left in range(1, 65):
    for right in range(1, 65):
        assert (((2 * left) >> 1) + ((2 * right) >> 1)) << 1 == 2 * (left + right)
print(f"{len(rows)} instructions, {len(targets)} relative targets, one relocation")
print(f"{len(controls)} corruption controls, {len(counts)} count fixtures, 4096 run pairs")
