"""Verify selected path reconstruction and output writes in node #115 helper."""
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY = "f872fc8a63299d0e5d3f450cb54d40ceb07e876151aa155c10d6c6bc9ae0277e"
data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != TARGET:
    raise ValueError("wrong node artifact")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4D256E0] != [(0x4D256E0, 0x4D25FD8)]:
    raise ValueError("unexpected helper FDE")

def read(address, length):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= address and address + length <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError(f"unmapped witness {address:#x}")
    s = hits[0]
    off = s["offset"] + address - s["address"]
    return data[off:off + length]

if sha256(read(0x4D256E0, 2296)).hexdigest() != BODY:
    raise ValueError("helper body changed")

witnesses = {
    0x4D256FE: "488b2e",                 # root object
    0x4D25705: "0fb79dda040000",         # root count at +0x4da
    0x4D2570C: "4a8d7ced08",             # selected slot +0x08
    0x4D25737: "4c8b3d2a9e7b0141",       # memmove slot load
    0x4D2573E: "41ffd7",                 # selected slot helper
    0x4D25752: "488b8c05c0000000",        # selected record +0xc0
    0x4D257D1: "8d43ff",                  # count decrement
    0x4D257D4: "668985da040000",         # count store
    0x4D257E4: "0f8790000000",            # capacity branch
    0x4D25849: "4c89a424c0000000",       # descendant descriptor field
    0x4D25906: "e80599f7ff",              # selected recursive call
    0x4D259A8: "488b4c2470488b44",       # output pointer and result scalar
    0x4D259B2: "488901",                 # output +0x00
    0x4D259D5: "0f114108",               # output vector store
    0x4D25A05: "48894168",               # output +0x68
    0x4D25A11: "4c89b980000000",         # output +0x80
    0x4D25BF4: "ffd0",                   # second selected slot helper
    0x4D25C18: "8d14c500000000",         # copy width from slot index
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

edge(0x4D257E4, bytes.fromhex("0f87"), 0x4D2587A)
edge(0x4D257F0, bytes.fromhex("0f84"), 0x4D25884)
edge(0x4D25805, bytes.fromhex("0f84"), 0x4D25893)
edge(0x4D2585D, bytes.fromhex("0f83"), 0x4D2590D)

for address, expected in witnesses.items():
    altered = bytearray(bytes.fromhex(expected))
    altered[0] ^= 1
    if altered == read(address, len(altered)):
        raise RuntimeError(f"corrupted witness accepted at {address:#x}")

print("Verified node #115, 2296-byte FDE body, 18 instruction witnesses, 4 edges and 18 mutation controls.")
