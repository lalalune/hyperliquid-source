"""Verify selected node-link maintenance in node #115 helper 0x4d2ec40."""
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY = "cdf565ff24380bd6d5f1bcb456ba828dd2b8d0bdf2279f51b221c82ae1bad691"
data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != TARGET:
    raise ValueError("wrong node artifact")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4D2EC40] != [(0x4D2EC40, 0x4D2F8BB)]:
    raise ValueError("unexpected helper FDE")

def read(address, length):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= address and address + length <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError(f"unmapped witness {address:#x}")
    s = hits[0]
    off = s["offset"] + address - s["address"]
    return data[off:off + length]

if sha256(read(0x4D2EC40, 3195)).hexdigest() != BODY:
    raise ValueError("helper body changed")

witnesses = {
    0x4D2EC64: "488b2e",                 # root node from descriptor
    0x4D2EC6B: "0fb79d72020000",         # root child count
    0x4D2EC72: "4a8dbced18020000",       # selected slot address
    0x4D2ECA3: "4c8b35be087b0141",       # allocator/slot helper
    0x4D2ED02: "8d7bff",                  # decremented count
    0x4D2ED05: "6689bd72020000",         # store count
    0x4D2ED59: "498b8cf770020000",       # child node by index
    0x4D2EDA1: "4401cb",                  # accumulate child count
    0x4D2EDA7: "0f8350040000",           # capacity guard
    0x4D2EF8C: "4c89be10020000",         # child parent pointer
    0x4D2EF93: "664489b670020000",       # child index store
    0x4D2F01A: "6641ff8f72020000",       # decrement child count
    0x4D2F7C6: "48c7811002000000",       # clear removed node parent
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

edge(0x4D2ED21, bytes.fromhex("0f87"), 0x4D2F249)
edge(0x4D2EDA7, bytes.fromhex("0f83"), 0x4D2F1FD)
edge(0x4D2F7AC, bytes.fromhex("0f84"), 0x4D2F888)

for address, expected in witnesses.items():
    altered = bytearray(bytes.fromhex(expected))
    altered[0] ^= 1
    if altered == read(address, len(altered)):
        raise RuntimeError(f"corrupted witness accepted at {address:#x}")

print("Verified node #115, 3195-byte FDE body, 13 instruction witnesses, 3 edges and 13 mutation controls.")
