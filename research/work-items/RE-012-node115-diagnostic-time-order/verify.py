"""Check node #115 diagnostic time ordering."""
from hashlib import sha256
from itertools import product
from pathlib import Path
import re
from struct import iter_unpack

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x1507F10, 0x1509B70)
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
    0x1509F76: (0x64E0AF8, 4),
    0x1507FC6: (0x1507FE0, 1), 0x1507FD2: (0x1507FE0, 1),
    0x1507FDB: (0x1507FA0, 1), 0x1507FE2: (0x1507FA0, 1),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
reloc = by_name[".rela.dyn"]
data_slice = data[reloc["offset"]:reloc["offset"] + reloc["size"]]
expected = {0x64E0AF8: (8, 0x1507F10)}
actual = [(slot, (kind, target)) for slot, kind, target in iter_unpack("<QQq", data_slice)
          if slot in expected]
assert sorted(actual) == sorted(expected.items())

check(read)
controls = (0x1507F45, 0x1507FA8, 0x1507FC0, 0x1507FD1, 0x1507FDA, 0x1507FF8)
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



def earlier(left, right):
    if left[0] != right[0]:
        return left[0] < right[0]
    if left[1] != right[1]:
        return left[1] < right[1]
    return left[2] < right[2]


times = tuple(product((-2**31, -1, 0, 1, 2**31 - 1), (0, 1, 2**32 - 1)))
times = tuple((date, second, nano) for date, second in times for nano in (0, 1, 2**32 - 1))
for left, right in product(times, repeat=2):
    assert earlier(left, right) == (left < right)
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{len(times)**2} synthetic ordering tuples checked")
