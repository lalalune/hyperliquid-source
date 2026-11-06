"""Verify the replay record identity route in the pinned #115 ELF."""
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
if hashlib.sha256(data).hexdigest() != "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":
    raise ValueError("wrong target")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
def read(addr, size):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= addr and addr + size <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError("invalid address")
    s = hits[0]
    off = s["offset"] + addr - s["address"]
    return data[off:off + size]

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x5a6e1e0] != [(0x5a6e1e0, 0x5a70656)]:
    raise ValueError("wrong replay worker extent")

for site, hex_opcode, target in (
    (0x5a6e328, "e8", 0x5ab6df0),
    (0x5a6e335, "0f85", 0x5a70087),
    (0x5a6e39c, "e8", 0x5a63100),
    (0x5a6e3a6, "0f85", 0x5a6e318),
    (0x5a6e3b1, "ff15", 0x64e4cb8),
    (0x5a6e3b7, "e9", 0x5a6e318),
    (0x5a6e3ea, "0f85", 0x5a700f8),
    (0x5a6e42d, "e8", 0x5a63100),
    (0x5a6e43d, "e8", 0x5a63100),
):
    opcode = bytes.fromhex(hex_opcode)
    raw = read(site, len(opcode) + 4)
    if raw[:-4] != opcode or site + len(raw) + struct.unpack("<i", raw[-4:])[0] != target:
        raise ValueError(f"wrong transfer at {site:#x}")

for address, raw in {
    0x5a6e1f1: "4c89c5",
    0x5a6e2d6: "4889ac2468010000",
    0x5a6e33b: "488bac2470040000488b9424780400004885ed7430",
    0x5a6e360: "48b800000000000000804c8d60014c396528754c488d4530eb5c",
    0x5a6e380: "488954246848c744246000000000",
    0x5a6e3a1: "f048ff4d00",
    0x5a6e3c0: "488d4d28488d85b80000004c39a5b8000000480f44c1488b4030",
    0x5a6e3e2: "483b842468010000",
    0x5a6e3f0: "f048ff45000f8e6d1d0000f048ff020f8e631d0000",
    0x5a6e442: "488d4550",
    0x5a6e44e: "4c396528488d8da0000000480f44c8488b491048ffc148c7c0ffffffff480f44c8",
    0x5a6e46f: "48898c2468010000",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

word = 1 << 64
marker = (word >> 1) + 1
for tag_at_28, tag_at_b8, identity_offset, next_input in (
    (marker, marker, 0x60, 0x60),
    (marker, 0, 0x60, 0x60),
    (0, marker, 0x58, 0xb0),
    (0, 0, 0xe8, 0xb0),
):
    selected_base = 0x30 if tag_at_28 == marker else (0x28 if tag_at_b8 == marker else 0xb8)
    selected_next = 0x50 if tag_at_28 == marker else 0xa0
    if selected_base + 0x30 != identity_offset or selected_next + 0x10 != next_input:
        raise ValueError("wrong record projection")
for value, expected in ((0, 1), (word - 2, word - 1), (word - 1, word - 1)):
    incremented = (value + 1) % word
    if (incremented if incremented else word - 1) != expected:
        raise ValueError("wrong saturated successor")
print("Verified replay identity projections, null-record retry and saturated successor.")
