"""Check selected argument extraction for the node #115 BOLE queries."""
from hashlib import sha256
from pathlib import Path
import re

from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, _ = unwind_index(data)
_, entries = eh_frame_records(data, sections)
for bounds in ((0x3897020, 0x38971F5), (0x3897200, 0x389733E)):
    assert any((entry["start"], entry["end"]) == bounds for entry in entries)

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
    0x38E5D74: 0x3897020, 0x38E6524: 0x3897200,
    0x3897124: 0x454F90, 0x3897281: 0x454F90,
}


def check(reader):
    for address, expected in rows.items():
        assert reader(address, len(expected)) == expected, hex(address)
    for site, target in targets.items():
        ins = rows[site]
        assert site + len(ins) + int.from_bytes(ins[-4:], "little", signed=True) == target
    assert reader(0x454F90, 16) == bytes.fromhex("ff" * 14 + "0000")


check(read)
controls = (0x3897049, 0x3897180, 0x3897187, 0x3897227, 0x38972D4, 0x454F9E)
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


def transfer(src, token_offset, address=None):
    out = bytearray([0xA5]) * (40 if address is not None else 16)
    out[0] = 12
    token = src[token_offset:token_offset + 8][::-1]
    if address is not None:
        out[8:24] = src[12:28]
        out[24:28] = src[28:32]
        out[32:40] = token
    else:
        out[8:16] = token
    return out


tokens = (0, 1, 255, 256, (1 << 32) - 1, 1 << 32, 1 << 63, (1 << 64) - 1)
addresses = (bytes(20), bytes(range(20)), bytes(reversed(range(20))), b"\xff" * 20)
for token in tokens:
    padded_word = token.to_bytes(32, "big")
    expected_token = token.to_bytes(8, "little")
    assert transfer(padded_word, 24) == b"\x0c" + b"\xa5" * 7 + expected_token
    for address in addresses:
        got = transfer(bytes(12) + address + padded_word, 56, address)
        assert got == b"\x0c" + b"\xa5" * 7 + address + b"\xa5" * 4 + expected_token

print(f"{len(rows)} instructions, {len(targets)} relative targets, two FDEs and one vector constant")
print(f"{len(controls)} corruption controls and {len(tokens) * (len(addresses) + 1)} standard encodings passed")
