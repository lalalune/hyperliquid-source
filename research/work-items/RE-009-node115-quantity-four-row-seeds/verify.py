"""Check node #115 quantity four-row sort seeds."""
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
owners = (0x43B4E60,)
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
    0x43B4E92: (0x43B504B, 4),
    0x43B5044: (0x43B508B, 1),
    0x43B5046: (0x43B5131, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 110
check(read)
controls = (0x43B4EA8, 0x43B4EF7, 0x43B4F4F, 0x43B4FBA, 0x43B5028, 0x43B5037)
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


def before(a, b):
    return a[0] < b[0]


def seeds(a, b, c, d):
    if before(b, a):
        a, b = b, a
    if before(d, c):
        c, d = d, c
    lower_from_right = before(c, a)
    upper_from_left = before(d, b)
    low = c if lower_from_right else a
    high = b if upper_from_left else d
    first_middle = a if lower_from_right else c if upper_from_left else b
    second_middle = d if upper_from_left else b if lower_from_right else c
    if before(second_middle, first_middle):
        first_middle, second_middle = second_middle, first_middle
    return low, first_middle, second_middle, high


domain = (0, 1, 2, 2**63, 2**64 - 1)
for keys in product(domain, repeat=4):
    sample = [(key, idx, idx * 9 + 1) for idx, key in enumerate(keys)]
    assert list(seeds(*sample)) == sorted(sample, key=lambda row: row[0])
for count in range(8, 33):
    half = count // 2
    assert half >= 4 and count - half >= 4
    assert 8 * (3 * half) == 24 * half
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{len(domain)**4} seed-order fixtures and 25 half boundaries")
