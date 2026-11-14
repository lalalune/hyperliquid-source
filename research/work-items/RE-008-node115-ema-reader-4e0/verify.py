"""Verify the selected node-table reader and output layout in node #115."""
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY = "fbc21b2a3e4c1b659195550a0f0c84de35ef88c5b7e063aa727b812ab1f22167"
data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != TARGET:
    raise ValueError("wrong node artifact")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4D30C80] != [(0x4D30C80, 0x4D31061)]:
    raise ValueError("unexpected reader FDE")

def read(address, length):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= address and address + length <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError(f"unmapped witness {address:#x}")
    s = hits[0]
    off = s["offset"] + address - s["address"]
    return data[off:off + length]

if sha256(read(0x4D30C80, 993)).hexdigest() != BODY:
    raise ValueError("reader body changed")

witnesses = {
    0x4D30C88: "4889fb",                 # preserve output pointer
    0x4D30C9F: "488b8cc8e0040000",      # selected child table +0x4e0
    0x4D30DA4: "4889e7",                 # stack output for helper
    0x4D30DAF: "e82c49ffff",             # call 0x4d256e0
    0x4D30E5F: "48897cc808",             # replace selected entry pointer
    0x4D30E64: "4a8bbc00c0000000",       # preserve +0xc0 field
    0x4D30E8D: "420f10440060",           # load record vector
    0x4D30EDE: "420f11440060",           # restore record vector
    0x4D30F70: "e98c000000",             # join output path
    0x4D31001: "488913",                 # output +0x00
    0x4D31017: "0f114308",               # output +0x08..+0x17
    0x4D3101B: "0f114b18",               # output +0x18..+0x27
    0x4D3101F: "0f115328",               # output +0x28..+0x37
    0x4D31023: "0f115b38",               # output +0x38..+0x47
    0x4D3102C: "0f114348",               # output +0x48..+0x57
    0x4D31035: "0f114358",               # output +0x58..+0x67
    0x4D3103E: "48895368",               # output +0x68
    0x4D31042: "48894370",               # output +0x70
    0x4D31046: "48c7437800000000",       # output +0x78 = 0
    0x4D3104E: "48898b80000000",         # output +0x80
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

edge(0x4D30C99, bytes.fromhex("0f84"), 0x4D30F75)
edge(0x4D30DAF, bytes.fromhex("e8"), 0x4D256E0)
edge(0x4D30F70, bytes.fromhex("e9"), 0x4D31001)

for address, expected in witnesses.items():
    altered = bytearray(bytes.fromhex(expected))
    altered[0] ^= 1
    if altered == read(address, len(altered)):
        raise RuntimeError(f"corrupted witness accepted at {address:#x}")

print("Verified node #115, 993-byte FDE body, 20 instruction witnesses, 3 edges and 20 mutation controls.")
