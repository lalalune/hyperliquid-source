"""Check node #115 vacant quantity-tree entry."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x4DD6150, 0x51F21D0, 0x4C5B580)
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
    0x4DD653C: (0x51F21D0, 4),
    0x51F21E9: (0x51F2231, 1),
    0x51F2218: (0x4C5B580, 4),
    0x51F2239: (0x64DF480, 4),
    0x4C5B5BE: (0x4C5B5FB, 1),
    0x4C5B62B: (0x64DF568, 4),
    0x4C5B659: (0x64DF568, 4),
    0x4C5B68A: (0x4C5BF3B, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 100
check(read)
controls = (0x4DD653D, 0x51F2235, 0x51F227C, 0x4C5B5BF, 0x4C5B651, 0x4C5B67E)
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


cases = 0
for count in range(11):
    for index in range(count + 1):
        initial = [(2 * i + 2, (i, 100 - i)) for i in range(count)]
        row = (2 * index + 1, (1000, 2000))
        keys = [key for key, _ in initial]
        values = [value for _, value in initial]
        keys[index + 1:] = keys[index:]
        values[index + 1:] = values[index:]
        if index == count:
            keys.append(row[0])
            values.append(row[1])
        else:
            keys[index], values[index] = row
        assert list(zip(keys, values)) == sorted(initial + [row])
        cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} vacant insertion placements")
