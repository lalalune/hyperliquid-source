"""Check node #115 decimal coefficient digits."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x5C43040, 0x5C449C0)
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
    0x5C449EF: (0x5C43040, 4), 0x5C43069: (0x5C43129, 4),
    0x5C430E4: (0x5C435AF, 4), 0x5C43115: (0x5C43090, 4),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
check(read)
controls = (0x5C4305D, 0x5C43080, 0x5C43086, 0x5C430DF, 0x5C430ED, 0x5C43115)
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


mask = (1 << 32) - 1


def reverse_digits(value):
    high, middle, low = value >> 64, (value >> 32) & mask, value & mask
    result = []
    while high or middle or low:
        q_high = (high * 0xCCCCCCCD) >> 35
        mid_wide = ((high - 10 * q_high) << 32) | middle
        q_mid = (mid_wide * 0x199999999999999A) >> 64
        low_wide = ((mid_wide - 10 * q_mid) << 32) | low
        q_low = (low_wide * 0x199999999999999A) >> 64
        result.append(48 + low_wide - 10 * q_low)
        high, middle, low = q_high, q_mid, q_low
    return bytes(result)


vectors = set(range(10000))
vectors.update((1 << k) + delta for k in range(1, 97) for delta in (-1, 0, 1)
               if (1 << k) + delta < 1 << 96)
vectors.update(10**k + delta for k in range(29) for delta in (-1, 0, 1))
for value in vectors:
    assert reverse_digits(value) == (str(value).encode()[::-1] if value else b"")
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(controls)} corruption controls")
print(f"{len(vectors)} synthetic coefficients checked")
