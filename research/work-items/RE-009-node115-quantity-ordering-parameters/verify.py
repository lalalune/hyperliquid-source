"""Check node #115 quantity ordering parameters."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x3E73880,)
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
    0x3E738A4: (0x3E73EDC, 4),
    0x3E738DB: (0x3E738FA, 1),
    0x3E738F8: (0x3E73921, 1),
    0x3E739C2: (0x3E73A10, 1),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 46
check(read)
controls = (0x3E738BC, 0x3E738C5, 0x3E738CF, 0x3E73907, 0x3E739C1, 0x3E73B87)
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


def parameters(count):
    quotient, remainder = divmod(1 << 62, count)
    if count <= 4096:
        threshold = min(count - (count >> 1), 64)
    else:
        top = (count | 1).bit_length() - 1
        shift = (top >> 1) + (top & 1)
        threshold = ((count >> shift) + (1 << shift)) >> 1
    return quotient + (remainder != 0), threshold


counts = list(range(2, 20000))
counts.extend((1 << power) + delta for power in range(15, 61) for delta in (-1, 0, 1))
for count in counts:
    scale, threshold = parameters(count)
    assert (scale - 1) * count < (1 << 62) <= scale * count
    if count <= 4096:
        expected = min(64, (count + 1) // 2)
    else:
        block = 1
        while 2 * block * block <= count:
            block *= 2
        expected = (count + block * block) // (2 * block)
    assert threshold == expected and 1 <= threshold <= count
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{len(counts)} count fixtures")
