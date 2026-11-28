"""Check node #115 quantity-tree key runs."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x516B610, 0x4CAFF20)
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
    0x516B6E0: (0x4CAFF20, 4),
    0x4CB00F3: (0x4CB0150, 1),
    0x4CB0123: (0x4CB015D, 1),
    0x4CB013E: (0x4CB0110, 1),
    0x4CB0176: (0x4CB0050, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 55
check(read)
controls = (0x516B6E1, 0x4CB006C, 0x4CB0099, 0x4CB00F3, 0x4CB012B, 0x4CB0175)
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


def one_per_run(ordered):
    index = 0
    while index < len(ordered):
        current = ordered[index]
        index += 1
        while index < len(ordered) and ordered[index][0] == current[0]:
            current = ordered[index]
            index += 1
        yield current


from itertools import combinations_with_replacement

cases = 0
for size in range(12):
    for keys in combinations_with_replacement((0, 1, 2**63, 2**64 - 1), size):
        ordered = [(key, (i, 3 * i + 1)) for i, key in enumerate(keys)]
        assert list(one_per_run(ordered)) == list(dict(ordered).items())
        cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} ordered row fixtures")
