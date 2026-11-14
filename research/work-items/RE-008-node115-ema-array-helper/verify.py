"""Verify selected node #115 EMA array-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY = "f46db2929f342c40857a9687b3f7f99d486a30d2d1354629507dd15a13c64343"
data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != TARGET:
    raise ValueError("wrong node artifact")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4D25FE0] != [(0x4D25FE0, 0x4D26BC6)]:
    raise ValueError("unexpected array-helper FDE")

def read(address, length):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= address and address + length <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError(f"unmapped witness {address:#x}")
    s = hits[0]
    off = s["offset"] + address - s["address"]
    return data[off:off + length]

if sha256(read(0x4D25FE0, 3046)).hexdigest() != BODY:
    raise ValueError("array-helper body changed")

witnesses = {
    0x4D26004: "4c8b2e",
    0x4D2600B: "410fb79d46020000",
    0x4D26013: "4b8d04b6",
    0x4D26017: "498dbc8568010000",
    0x4D2601F: "418b8c8578010000",
    0x4D2604D: "49f7d4",
    0x4D26068: "4c89742420",
    0x4D260A5: "448d4bff",
    0x4D260B1: "4d8b7708",
    0x4D2612E: "440fb78146020000",
    0x4D26139: "83fb0c",
    0x4D261A6: "668908",
    0x4D26211: "410f11848668010000",
    0x4D2621E: "41898c8678010000",
    0x4D262C3: "4c8d7501",
    0x4D262E4: "ff15",
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

edge(0x4D260BA, bytes.fromhex("0f87"), 0x4D265DB)
edge(0x4D260CF, bytes.fromhex("0f84"), 0x4D265C2)
edge(0x4D260E4, bytes.fromhex("0f84"), 0x4D264FD)
edge(0x4D2613C, bytes.fromhex("0f83"), 0x4D26597)
edge(0x4D26159, bytes.fromhex("0f87"), 0x4D2657F)
edge(0x4D26182, bytes.fromhex("0f83"), 0x4D26B8D)

for address, expected in witnesses.items():
    altered = bytearray(bytes.fromhex(expected))
    altered[0] ^= 1
    if altered == read(address, len(altered)):
        raise RuntimeError(f"corrupted witness accepted at {address:#x}")

print("Verified node #115, 3046-byte FDE body, 16 instruction witnesses, 6 edges and 16 mutation controls.")
