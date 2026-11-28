"""Check node #115 BOLE refresh price bounds."""
from hashlib import sha256
from itertools import product
from pathlib import Path
import re
from struct import pack, unpack

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
owners = (0x369A480, 0x452AEC0)
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
    0x369AF11: (0x451210, 4), 0x369AF1D: (0x450170, 4),
    0x369AF52: (0x458DC8, 4), 0x369AFB6: (0x458DC8, 4),
    0x369AF62: (0x369AF67, 1), 0x369AFC6: (0x369AFCB, 1),
}
constants = {
    0x451210: bytes.fromhex("0000304300003045"),
    0x450170: bytes.fromhex("00000000000030430000000000003045"),
    0x458DC8: pack("<d", -1.0),
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, (target, width) in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-width:], "little", signed=True) == target
    for address, value in constants.items():
        assert reader(address, len(value)) == value


check(read)
controls = (0x369AF0A, 0x369AF62, 0x369AFC2, 0x369AFCE, 0x451215, 0x458DCF)
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


def convert(word):
    low, high = word & 0xffffffff, word >> 32
    bias_lo, bias_hi = unpack("<II", constants[0x451210])
    zero_lo, zero_hi = unpack("<dd", constants[0x450170])
    lane_lo = unpack("<d", pack("<II", low, bias_lo))[0] - zero_lo
    lane_hi = unpack("<d", pack("<II", high, bias_hi))[0] - zero_hi
    return lane_hi + lane_lo


def bound(value, lower, upper, convert_word):
    if lower and (convert_word(value) / convert_word(lower)) - 1.0 < 0:
        value = lower
    if upper and (convert_word(value) / convert_word(upper)) - 1.0 > 0:
        value = upper
    return value


words = (0, 1, 2, (1 << 32) - 1, 1 << 32, (1 << 53) - 1, 1 << 53,
         (1 << 53) + 1, 1 << 63, (1 << 64) - 1)
for word in words:
    assert convert(word) == float(word)
for value, lower, upper in product(words[1:], words, words):
    assert bound(value, lower, upper, convert) == bound(value, lower, upper, float)
assert bound(1, 3, 2, convert) == 2
assert bound(1 << 53, (1 << 53) + 1, 0, convert) == 1 << 53
print(f"{len(rows)} instructions, {len(targets)} relative targets, {len(constants)} constants")
print(f"{len(controls)} corruption controls and {len(words[1:]) * len(words)**2} routed cases checked")
