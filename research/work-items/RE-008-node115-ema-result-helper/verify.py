"""Verify selected result and tree-slot effects in node #115 helper 0x4d30990."""
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY = "a0f4eda395fa738e185a3f08641d0320731a6f318d17f580584b0ccc09af9139"
data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != TARGET:
    raise ValueError("wrong node artifact")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4D30990] != [(0x4D30990, 0x4D30C7A)]:
    raise ValueError("unexpected helper FDE")

def read(address, length):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= address and address + length <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError(f"unmapped witness {address:#x}")
    s = hits[0]
    off = s["offset"] + address - s["address"]
    return data[off:off + length]

if sha256(read(0x4D30990, 746)).hexdigest() != BODY:
    raise ValueError("helper body changed")

witnesses = {
    0x4D30998: "4889fb",       # preserve result pointer
    0x4D309A6: "4885ff",       # empty/nonempty path count
    0x4D30AAE: "488d742468",   # helper input descriptor
    0x4D30AB3: "e888e1ffff",   # call 0x4d2ec40
    0x4D30B2A: "4889bcd018020000", # replace tree slot with result pointer
    0x4D30B69: "420f110400",   # restore first 16-byte entry
    0x4D30C41: "48890b",       # output +0x00
    0x4D30C52: "0f114308",     # output +0x08..+0x17
    0x4D30C56: "0f114b18",     # output +0x18..+0x27
    0x4D30C5A: "0f115328",     # output +0x28..+0x37
    0x4D30C5E: "48894338",     # output +0x38
    0x4D30C62: "48c7434000000000", # output +0x40 = 0
    0x4D30C6A: "48895348",     # output +0x48
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

edge(0x4D309BD, bytes.fromhex("0f84"), 0x4D30A8E)
edge(0x4D30AB3, bytes.fromhex("e8"), 0x4D2EC40)
edge(0x4D30BDD, bytes.fromhex("e8"), 0x4D2EC40)

for address, expected in witnesses.items():
    altered = bytearray(bytes.fromhex(expected))
    altered[0] ^= 1
    if altered == read(address, len(altered)):
        raise RuntimeError(f"corrupted witness accepted at {address:#x}")

print("Verified node #115, 746-byte FDE body, 13 instruction witnesses, 3 edges and 13 mutation controls.")
