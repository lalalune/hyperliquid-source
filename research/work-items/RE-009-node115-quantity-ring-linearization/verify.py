"""Check node #115 quantity ring linearization."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x516B610, 0x5B79D40)
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
    0x516B63C: (0x5B79D40, 4), 0x5B79D89: (0x64DF480, 4),
    0x5B79E1E: (0x5B79E00, 1), 0x5B79E5C: (0x5B79E40, 1),
    0x5B79E6D: (0x64DF4A0, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
check(read)
controls = (0x5B79DBE, 0x5B79DE9, 0x5B79E19, 0x5B79E47, 0x5B79E57, 0x5B79E79)
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
for capacity in range(1, 33):
    rows_data = [bytes(range(index, index + 24)) for index in range(capacity)]
    for supplied_head in range(2 * capacity):
        for length in range(capacity + 1):
            head = supplied_head - capacity if supplied_head >= capacity else supplied_head
            tail = min(length, capacity - head)
            actual = rows_data[head:head + tail] + rows_data[:length - tail]
            expected = [rows_data[(supplied_head + index) % capacity] for index in range(length)]
            assert b"".join(actual) == b"".join(expected)
            cases += 1
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{cases} complete synthetic ring layouts checked")
