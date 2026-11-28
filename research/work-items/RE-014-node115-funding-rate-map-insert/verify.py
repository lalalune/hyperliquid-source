"""Check node #115 funding map vacancy insertion."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x4DCF640, 0x57EE7B0, 0x51EE690)
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
    0x4DCF88C: 0x57EE7B0, 0x4DCF9F1: 0x51EE690,
    0x57EE826: 0x5814D30, 0x57EE85F: 0x5814D30,
    0x51EE6D0: 0x4C5AB90, 0x51EE6A4: 0x51EE6E9,
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, target in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[1:], "little", signed=True) == target
check(read)
controls = (0x57EE7F5, 0x57EE857, 0x57EE88A, 0x57EE894, 0x51EE739, 0x51EE746, 0x4DCFA18)
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
for capacity in range(2, 17):
    for length in range(capacity):
        for index in range(length + 1):
            for head in range(capacity):
                new_head = (head - 1) % capacity if length - index >= index else head
                occupied = [(new_head + item) % capacity for item in range(length + 1)]
                changed = 0 if head == new_head else -1
                assert new_head == (head + changed) % capacity
                slot = new_head + index
                if slot >= capacity:
                    slot -= capacity
                assert slot == occupied[index]
                cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} synthetic flat-ring insertion coordinates checked")
