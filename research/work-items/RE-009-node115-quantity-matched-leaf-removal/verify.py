"""Check node #115 matched quantity leaf removal."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x35B6600, 0x35B00B0)
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
    0x35B010C: (0x64DF568, 4),
    0x35B013F: (0x64DF568, 4),
    0x35B015C: (0x35B01FC, 4),
    0x35B0171: (0x35B0206, 4),
    0x35B67ED: (0x35B00B0, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 45
check(read)
controls = (0x35B00E5, 0x35B0107, 0x35B0125, 0x35B013A, 0x35B014F, 0x35B015B)
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

cases = 0
for count in range(1, 12):
    for index in range(count):
        rows_before = [(i, (i + 13, i + 27)) for i in range(count)]
        keys = [item[0] for item in rows_before]
        values = [item[1] for item in rows_before]
        old = (keys[index], values[index])
        keys[index:count - 1] = keys[index + 1:count]
        values[index:count - 1] = values[index + 1:count]
        assert old == rows_before[index]
        assert list(zip(keys[:count - 1], values[:count - 1])) == rows_before[:index] + rows_before[index + 1:]
        cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} leaf removal positions")
