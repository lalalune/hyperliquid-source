"""Check node #115 quantity partition pivot selection."""
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
    0x3E73CC7: (0x64EA138, 4),
    0x4290AB3: (0x4290AD3, 1),
    0x4290AC9: (0x43B4E60, 4),
    0x4290B0E: (0x4290B40, 1),
    0x4290B4E: (0x43620E0, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 50
check(read)
assert relative_relocations(data)[0x64EA138] == 0x4290A90

controls = (0x3E73CC9, 0x4290AB2, 0x4290B03, 0x4290B25, 0x4290B7E)
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


def median_row(a, b, c):
    before = a[0] < b[0]
    selected = c if (b[0] < c[0]) != before else b
    return a if (a[0] < c[0]) != before else selected


from itertools import product

cases = 0
for count in range(33, 64):
    q = count >> 3
    offsets = (0, 96 * q, 168 * q)
    assert offsets == tuple(24 * i for i in (0, 4 * q, 7 * q))
    assert 0 < 4 * q < 7 * q < count
    for keys in product((0, 1, 2**63, 2**64 - 1), repeat=3):
        candidates = [(key, offset, offset + 8) for key, offset in zip(keys, offsets)]
        pivot = median_row(*candidates)
        assert pivot[0] == sorted(keys)[1] and pivot in candidates
        cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, one relocation")
print(f"{len(controls)} corruption controls and {cases} unsigned pivot fixtures")
