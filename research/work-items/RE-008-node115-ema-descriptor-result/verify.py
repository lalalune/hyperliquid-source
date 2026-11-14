"""Check selected descriptor/result effects in the pinned node #115 helper."""

from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY = "5c2fb47aef3e43bf495937434d561d8ae0e8e285f83cd4d56a5c912538669254"
data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != TARGET:
    raise ValueError("wrong node artifact")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
if [(f["start"], f["end"]) for f in frames if f["start"] == 0x514EF40] != [
    (0x514EF40, 0x51506D0)
]:
    raise ValueError("unexpected helper FDE")


def read(address, length):
    matches = [
        s for s in secs
        if s["type"] != 8
        and s["address"] <= address
        and address + length <= s["address"] + s["size"]
    ]
    if len(matches) != 1:
        raise ValueError(f"unmapped witness {address:#x}")
    s = matches[0]
    offset = s["offset"] + address - s["address"]
    return data[offset:offset + length]


if sha256(read(0x514EF40, 6032)).hexdigest() != BODY:
    raise ValueError("helper body changed")

# These are complete instructions, not an inferred function transcript.
witnesses = {
    0x514EF54: "488b4618",       # prior descriptor +0x18
    0x514EF60: "48c7461800000000", # clear descriptor +0x18
    0x514EF68: "4885c0",         # branch on prior value
    0x514F2A6: "48b80000000000000080", # sentinel base
    0x514F2B0: "48ffc0",         # sentinel +1
    0x514F2B3: "48894708",       # result +0x08
    0x51504FF: "488b942410010000", # reload descriptor
    0x5150539: "488d742430",     # local tuple for selected call
    0x5150543: "e84804beff",     # call 0x4d30990
    0x5150558: "48894730",       # result +0x30
    0x5150574: "0f115720",       # result +0x20..+0x2f
    0x5150578: "0f114f10",       # result +0x10..+0x1f
    0x515057C: "0f1107",         # result +0x00..+0x0f
    0x5150599: "488b8c2488010000", # descriptor +0x18 pointer
    0x51505A1: "48894110",       # descriptor +0x28
    0x51505A5: "0f1101",         # descriptor +0x18..+0x27
}
for address, expected in witnesses.items():
    raw = bytes.fromhex(expected)
    if read(address, len(raw)) != raw:
        raise ValueError(f"witness mismatch at {address:#x}")

def edge(site, prefix, target):
    raw = read(site, len(prefix) + 4)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f"wrong edge opcode at {site:#x}")
    actual = site + len(raw) + struct.unpack("<i", raw[-4:])[0]
    if actual != target:
        raise ValueError(f"wrong edge target at {site:#x}: {actual:#x}")

edge(0x514EF6B, bytes.fromhex("0f84"), 0x514F2A6)
edge(0x5150543, bytes.fromhex("e8"), 0x4D30990)
edge(0x51505A8, bytes.fromhex("e9"), 0x514F2B7)

def check_control(address, expected):
    altered = bytearray(bytes.fromhex(expected))
    altered[0] ^= 1
    if altered == bytes.fromhex(expected):
        raise RuntimeError("mutation failed")
    if altered == read(address, len(altered)):
        raise RuntimeError(f"corrupted witness accepted at {address:#x}")

for address in (0x514EF60, 0x514F2B3, 0x5150543, 0x5150574, 0x51505A1):
    check_control(address, witnesses[address])

print("Verified node #115, 6032-byte FDE body, 16 instruction witnesses, 3 edges and 5 byte-mutation controls.")
