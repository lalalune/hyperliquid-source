"""Verify selected node #115 EMA branch-merge-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct, sys
sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY = "ade8c3a66de58d1d3703ecb4e9349adb255497bb2b9a802e55202d8a8c9be6a4"
data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != TARGET:
    raise ValueError("wrong node artifact")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4D2E270] != [(0x4D2E270, 0x4D2E479)]:
    raise ValueError("unexpected FDE")

def read(address, size):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= address and address + size <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError(f"unmapped {address:#x}")
    section = hits[0]
    offset = section["offset"] + address - section["address"]
    return data[offset:offset + size]

if sha256(read(0x4D2E270, 521)).hexdigest() != BODY:
    raise ValueError("body changed")
witnesses = {
    0x4D2E28A: "4c8b2e", 0x4D2E28D: "4c8b7610", 0x4D2E291: "410fb7ade6000000",
    0x4D2E299: "4b8d04b6", 0x4D2E29D: "498d7c8508", 0x4D2E2A2: "418b4c8518",
    0x4D2E2AB: "410f10448508", 0x4D2E2D1: "ff1591127b01", 0x4D2E2D7: "8d45ff",
    0x4D2E2DA: "66418985e6000000", 0x4D2E2F8: "6683f804", 0x4D2E302: "498b4500",
    0x4D2E309: "0f84ed000000", 0x4D2E314: "410fb795e4000000", 0x4D2E321: "488bb4d0e0000000",
    0x4D2E35B: "737c", 0x4D2E36C: "6683b8e600000000", 0x4D2E374: "0f84e6000000",
    0x4D2E3C0: "83fd0c", 0x4D2E3C3: "7328", 0x4D2E433: "8b442430",
    0x4D2E437: "894310", 0x4D2E43A: "0f28442420", 0x4D2E43F: "0f1103",
    0x4D2E442: "4c896b18", 0x4D2E446: "4c896320", 0x4D2E44A: "4c897328",
}
for address, expected in witnesses.items():
    raw = bytes.fromhex(expected)
    if read(address, len(raw)) != raw:
        raise ValueError(f"witness mismatch {address:#x}")
raw = read(0x4D2E2FC, 6)
if raw[:2] != bytes.fromhex("0f87") or 0x4D2E2FC + 6 + struct.unpack("<i", raw[2:])[0] != 0x4D2E433:
    raise ValueError("wrong capacity edge")
for address, expected in witnesses.items():
    altered = bytearray(bytes.fromhex(expected)); altered[0] ^= 1
    if altered == read(address, len(altered)):
        raise RuntimeError(f"mutation accepted {address:#x}")
print(f"Verified node #115, 521-byte FDE body, {len(witnesses)} instruction witnesses, 1 edge and {len(witnesses)} mutation controls.")
