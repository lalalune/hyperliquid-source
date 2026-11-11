"""Verify wide queue segment append."""
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

for address, raw in {
    0x5818a3b: "4c8b81100b0000490fbae0200f830e0100004c8b81180b00004c3b46100f87fd000000",
    0x5818a90: "488946080f1181000b000048c781100b000000000000",
    0x5818abe: "490fb188080b00007468",
    0x5818ae0: "490fb188080b00007446",
    0x5818b02: "490fb188080b00007424",
    0x5818b0f: "be200b0000",
    0x581a356: "bf200b0000",
    0x581a36d: "4883c320488998000b00000f57c00f1180080b000048c780180b000000000000",
    0x581a38f: "f0490fb19424080b00007455",
    0x581a39e: "488b80000b00004883c020488982000b0000",
    0x581a3d6: "f0480fb196080b00004889c675dc",
    0x581a3f0: "498b8424100b000083f8ff0f94c04084c50f8419ffffff",
    0x581a407: "4c89e0f0490fb1170f850bfffffff0834c24c000498b470849898424180b000048b80000000001000000f049098424100b0000",
    0x581bf40: "498b86100b000083f8ff0f94c04084c50f841affffff",
    0x581bf56: "4c89f0f0480fb10b0f850cfffffff0834c24c000488b4308498986180b000048b80000000001000000f0490986100b0000",
    0x581bea1: "bf200b0000",
    0x581bec3: "0f1180080b000048c780180b000000000000",
    0x581bed8: "490fb18e080b0000",
    0x581befa: "480fb18a080b0000",
    0x581bf27: "480fb18e080b0000",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction window at {address:#x}")
print("Verified allocation, initialization and link attempts in both wide queue writers.")
