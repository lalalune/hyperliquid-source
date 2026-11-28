"""Check node #115 quantity ordering scratch storage."""
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
owners = (0x516B610, 0x36E5360)
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
    0x516B73C: (0x516B76A, 1),
    0x516B775: (0x64E5368, 4),
    0x36E539E: (0x36E53AA, 1),
    0x36E5401: (0x3E73880, 4),
    0x36E540D: (0x36E5422, 1),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 50
check(read)
assert relative_relocations(data)[0x64E5368] == 0x36E5360

controls = (0x516B777, 0x36E5388, 0x36E539A, 0x36E53F6, 0x36E5402)
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


def scratch(n):
    capacity = min(n - (n >> 1), 0x51615)
    return max(170, capacity), capacity > 170, n < 65


fixtures = {
    21: (170, False, True),
    64: (170, False, True),
    65: (170, False, False),
    340: (170, False, False),
    341: (171, True, False),
    666665: (333333, True, False),
    666667: (333333, True, False),
}
for count, expected in fixtures.items():
    assert scratch(count) == expected
print(f"{len(rows)} instructions, {len(targets)} relative targets, one relocation")
print(f"{len(controls)} corruption controls and {len(fixtures)} scratch boundary fixtures")
