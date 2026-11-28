"""Check node #115 quantity row stable insertion sort."""
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
owners = (0x516B610, 0x53EEA20)
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
    0x516B74E: (0x53EEA20, 4), 0x53EEA27: (0x53EEABE, 4),
    0x53EEA74: (0x53EEA60, 1), 0x53EEAA9: (0x53EEA50, 1),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
check(read)
controls = (0x53EEA63, 0x53EEA74, 0x53EEA9D, 0x53EEAA8, 0x516B73B, 0x516B74F)
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


def stable_rows(keys):
    output = list(enumerate(keys))
    for index in range(1, len(output)):
        item = output[index]
        position = index
        while position and output[position - 1][1] > item[1]:
            output[position] = output[position - 1]
            position -= 1
        output[position] = item
    return output


cases = 0
for size in range(8):
    for sample in product((0, 1, 2**63, 2**64 - 1), repeat=size):
        assert stable_rows(sample) == sorted(enumerate(sample), key=lambda row: row[1])
        cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} synthetic row-order fixtures checked")
