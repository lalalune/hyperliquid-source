"""Check node #115 recursive quantity pivot sampling."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x4290A90, 0x43620E0)
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
    0x4290B0E: (0x4290B40, 1),
    0x4290B4E: (0x43620E0, 4),
    0x4362101: (0x436216B, 1),
    0x436212B: (0x43620E0, 4),
    0x4362145: (0x43620E0, 4),
    0x4362163: (0x43620E0, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target


assert len(rows) >= 70
check(read)
controls = (0x4290B0D, 0x4362106, 0x4362119, 0x436212C, 0x4362158, 0x4362174)
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


def select(bases, span, key):
    step = span >> 3
    if step:
        bases = [select((i, i + 4 * step, i + 7 * step), step, key)
                 for i in bases]
    a, b, c = bases
    ascending = key(a) < key(b)
    second = c if (key(b) < key(c)) != ascending else b
    return a if (key(a) < key(c)) != ascending else second


def sampled(bases, span):
    if span < 8:
        return set(bases)
    step = span // 8
    return set.union(*(sampled((base, base + 4 * step, base + 7 * step), step)
                       for base in bases))


counts = (*range(64, 600), 4095, 4096, 4097, 32767, 32768, 32769)
for count in counts:
    span = count // 8
    bases = (0, 4 * span, 7 * span)
    indices = sampled(bases, span)
    assert min(indices) == 0 and max(indices) < count
    for key in (lambda i: i, lambda i: -i, lambda i: i % 7):
        assert select(bases, span, key) in indices
    assert select(bases, span, lambda i: i) == select(bases, span, lambda i: -i)
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{len(counts)} sampling-span fixtures")
