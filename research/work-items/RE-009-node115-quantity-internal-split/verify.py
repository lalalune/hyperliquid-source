"""Check node #115 quantity internal-node split."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x4C5B580,)
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
    0x4C5B8F9: (0x4C5BD5A, 4),
    0x4C5B945: (0x64DF480, 4),
    0x4C5B9DE: (0x64DF508, 4),
    0x4C5BA55: (0x64DF508, 4),
    0x4C5BC98: (0x64DF480, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 115
check(read)
controls = (0x4C5B942, 0x4C5BA4E, 0x4C5BA74, 0x4C5BA7D, 0x4C5BCC9, 0x4C5BD33)
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


for separator in (4, 5, 6):
    keys = list(range(11))
    children = list(range(12))
    left_edges, right_edges = children[:separator + 1], children[separator + 1:]
    assert len(left_edges) == len(keys[:separator]) + 1
    assert len(right_edges) == len(keys[separator + 1:]) + 1
    assert left_edges + right_edges == children

print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print("3 separator and child-suffix fixtures")
