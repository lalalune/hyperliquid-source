"""Check node #115 paired quantity representation gate."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x55BEF10, 0x3CE8DF0)
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
    0x55BEF92: (0x55BEFB9, 1),
    0x55BEFA9: (0x3CE8DF0, 4),
    0x55BEFB4: (0x3CE8DF0, 4),
    0x3CE8E82: (0x454F190, 4),
    0x3CE8E9D: (0x3CE9167, 4),
    0x3CE9016: (0x3877D60, 4),
    0x3CE9038: (0x3CE9167, 4),
}

assert len(rows) >= 45
def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)


check(read)
controls = (0x55BEF92, 0x55BEFA0, 0x3CE8E0D, 0x3CE8E94, 0x3CE902F, 0x3CE9163)
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
for site, (target, width) in targets.items():
    ins = rows[site]
    assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target

expected = [(2**63, count) for count in range(32)]
actual = [(tag, count) for tag in (0, 2**63 - 1, 2**63, 2**63 + 1)
          for count in range(65) if (tag == 2**63) & (count < 0x20)]
assert actual == expected
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls, 260 tag/count fixtures")
