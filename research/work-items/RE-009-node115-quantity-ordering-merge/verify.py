"""Check node #115 quantity ordering merge."""
from hashlib import sha256
from itertools import combinations_with_replacement, product
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x3E73880,)
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
    0x3E73D5A: (0x3E73C13, 4),
    0x3E73D76: (0x3E73C13, 4),
    0x3E73DA3: (0x64DF508, 4),
    0x3E73DB4: (0x3E73E1D, 1),
    0x3E73E16: (0x3E73DC0, 1),
    0x3E73E79: (0x3E73E30, 1),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 60
check(read)
controls = (0x3E73D76, 0x3E73D94, 0x3E73DDA, 0x3E73DEE, 0x3E73E3D, 0x3E73E53)
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


def merge(left, right):
    backwards = len(left) > len(right)
    left = left[::-1] if backwards else left[:]
    right = right[::-1] if backwards else right[:]
    out = []
    i = j = 0
    while i < len(left) and j < len(right):
        take_right = right[j][0] >= left[i][0] if backwards else right[j][0] < left[i][0]
        if take_right:
            out.append(right[j])
            j += 1
        else:
            out.append(left[i])
            i += 1
    out.extend(left[i:])
    out.extend(right[j:])
    return out[::-1] if backwards else out


runs = [run for length in range(1, 6)
        for run in combinations_with_replacement((0, 1, 2**63, 2**64 - 1), length)]
for a, b in product(runs, repeat=2):
    left = [(key, 0, i) for i, key in enumerate(a)]
    right = [(key, 1, i) for i, key in enumerate(b)]
    assert merge(left, right) == sorted(left + right, key=lambda row: row[0])
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{len(runs)**2} synthetic run pairs")
