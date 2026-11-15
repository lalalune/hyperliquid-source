"""Verify selected node #115 EMA deep-branch-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct, sys
sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY = "306bb559ffec4bfcc550911d7a30703e628495aacc4690168f9e906f152e3c8d"
data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != TARGET:
    raise ValueError("wrong node artifact")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4D2E480] != [(0x4D2E480, 0x4D2EC38)]:
    raise ValueError("unexpected FDE")

def read(address, size):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= address and address + size <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError(f"unmapped {address:#x}")
    section = hits[0]
    offset = section["offset"] + address - section["address"]
    return data[offset:offset + size]

if sha256(read(0x4D2E480, 1976)).hexdigest() != BODY:
    raise ValueError("body changed")
witnesses = {
    0x4D2E49E: "488b2e", 0x4D2E4A1: "4c8b7e10", 0x4D2E4A5: "0fb79d3e010000",
    0x4D2E4B0: "488d7c8560", 0x4D2E4B5: "8b4c8570", 0x4D2E4C0: "0f10448560",
    0x4D2E4ED: "4c8b3574107b01", 0x4D2E4F4: "41ffd6", 0x4D2E502: "4a8b44fd08",
    0x4D2E51C: "49c1e503", 0x4D2E523: "41ffd6", 0x4D2E529: "8d43ff",
    0x4D2E52C: "6689853e010000", 0x4D2E538: "6683f804", 0x4D2E542: "488b06",
    0x4D2E552: "0fb7963c010000", 0x4D2E562: "4989f7", 0x4D2E565: "488bb4d038010000",
    0x4D2E5AF: "01c3", 0x4D2E5B1: "83fb0c", 0x4D2E6CF: "488b1e",
    0x4D2E6E1: "0fb7833e010000", 0x4D2E6E8: "6683f804", 0x4D2E700: "488b4c2468",
    0x4D2E705: "48894110", 0x4D2E709: "0f288424b0000000", 0x4D2E719: "48894118",
    0x4D2E71D: "48897120", 0x4D2E72A: "4c897130",
}
for address, expected in witnesses.items():
    raw = bytes.fromhex(expected)
    if read(address, len(raw)) != raw:
        raise ValueError(f"witness mismatch {address:#x}")
raw = read(0x4D2E53C, 6)
if raw[:2] != bytes.fromhex("0f87") or 0x4D2E53C + 6 + struct.unpack("<i", raw[2:])[0] != 0x4D2E5D1:
    raise ValueError("wrong capacity edge")
for address, expected in witnesses.items():
    altered = bytearray(bytes.fromhex(expected)); altered[0] ^= 1
    if altered == read(address, len(altered)):
        raise RuntimeError(f"mutation accepted {address:#x}")
print(f"Verified node #115, 1976-byte FDE body, {len(witnesses)} instruction witnesses, 1 edge and {len(witnesses)} mutation controls.")
