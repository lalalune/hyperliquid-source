"""Check node #115 quantity-tree final right-edge fill."""
from hashlib import sha256
from itertools import product
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x4CAFF20, 0x4C958A0)
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
    0x4CB03EF: (0x4CB0406, 1),
    0x4CB040D: (0x4CB04A4, 4),
    0x4CB0426: (0x4CB04A4, 1),
    0x4CB048D: (0x4CB0420, 1),
    0x4CB049A: (0x4C958A0, 4),
    0x4CB049F: (0x4CB0420, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 44
check(read)
controls = (0x4CB03F7, 0x4CB043B, 0x4CB0448, 0x4CB048C, 0x4CB0493, 0x4CB049B)
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


def plan(parent_count, last_count):
    return (parent_count - 1, 0x110 + 8 * parent_count,
            0x118 + 8 * parent_count, 5 - last_count if last_count < 5 else 0)


cases = 0
for parent_count, last_count in product(range(1, 12), range(12)):
    edge, left, right, transfer = plan(parent_count, last_count)
    assert (left, right) == (0x118 + 8 * edge, 0x118 + 8 * (edge + 1))
    assert last_count + transfer == max(last_count, 5)
    cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} right-edge descriptor and occupancy fixtures")
