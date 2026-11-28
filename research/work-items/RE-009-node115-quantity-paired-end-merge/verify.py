"""Check node #115 quantity paired-end merge."""
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
owners = (0x4290A90, 0x43B4E60)
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
    0x4290AC9: (0x43B4E60, 4),
    0x43B5144: (0x43B51F1, 4),
    0x43B5216: (0x43B5270, 1),
    0x43B526E: (0x43B52C7, 1),
    0x43B528C: (0x43B5291, 1),
    0x43B52B9: (0x43B5220, 4),
    0x43B52D8: (0x43B52FD, 1),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 72
check(read)
controls = (0x43B5247, 0x43B526E, 0x43B5287, 0x43B52B9, 0x43B52D7, 0x43B5315)
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


def paired(left, right):
    lo = []
    hi = []
    for _ in range((len(left) + len(right)) // 2):
        source = left if not right or (left and left[0][0] <= right[0][0]) else right
        lo.append(source.pop(0))
        source = right if not left or (right and right[-1][0] >= left[-1][0]) else left
        hi.append(source.pop())
    return lo + left + right + hi[::-1]


cases = 0
domain = (0, 1, 2**63, 2**64 - 1)
for count in range(2, 13):
    mid = count // 2
    for a, b in product(combinations_with_replacement(domain, mid),
                        combinations_with_replacement(domain, count - mid)):
        left = [(key, 0, idx) for idx, key in enumerate(a)]
        right = [(key, 1, idx) for idx, key in enumerate(b)]
        expected = sorted(left + right, key=lambda row: row[0])
        assert paired(left, right) == expected
        cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} paired-end merge fixtures")
