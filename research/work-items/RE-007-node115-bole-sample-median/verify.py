"""Check node #115 BOLE sample median."""
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
owners = (0x369A480, 0x452AEC0, 0x36EEBA0)
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
    0x369AEF5: (0x452AEC0, 4), 0x369AEFD: (0x369B040, 4),
    0x452AECE: (0x452AF36, 1), 0x452AF4C: (0x452AFAA, 1),
    0x452AFB5: (0x64E91D0, 4), 0x452AFC1: (0x452AF17, 4),
    0x452AFEE: (0x452AF22, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
reloc = by_name[".rela.dyn"]
reloc_data = data[reloc["offset"]:reloc["offset"] + reloc["size"]]
assert [row for row in iter_unpack("<QQq", reloc_data) if row[0] == 0x64E91D0] == [
    (0x64E91D0, 8, 0x36EEBA0)
]

check(read)
controls = (0x452AECE, 0x452AF4B, 0x452AF7A, 0x452AFBF, 0x452AFE4, 0x452AFEA)
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


def median_model(words):
    if not words:
        return 0
    ordered = list(words)
    for index in range(1, len(ordered)):
        value = ordered[index]
        position = index
        while position and ordered[position - 1] > value:
            ordered[position] = ordered[position - 1]
            position -= 1
        ordered[position] = value
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    lo, hi = ordered[middle - 1:middle + 1]
    return (lo & hi) + ((lo ^ hi) >> 1)


count = 0
for length in range(7):
    for sample in product((0, 1, 2, (1 << 63), (1 << 64) - 1), repeat=length):
        ordered = sorted(sample)
        if not ordered:
            expected = 0
        else:
            expected = (ordered[(length - 1) // 2] + ordered[length // 2]) // 2
        assert median_model(sample) == expected
        count += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, one ELF relocation")
print(f"{len(controls)} corruption controls and {count} synthetic sample tuples checked")
