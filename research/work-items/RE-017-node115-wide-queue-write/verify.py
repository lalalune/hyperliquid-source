"""Verify wide replay queue publication."""
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
    0x5a6e2a3: "488d83800000004889842498030000",
    0x5a6fe12: "488bbc2498030000488d7424604c8b6c2418e8a7a4daff",
    0x581a2db: "41be01000000f04c0fc177084d89f54983e5e0",
    0x581a450: "496bc658488b4e5048894c02500f1046400f114402400f10060f104e100f1056200f105e300f115c02300f115402200f114c0210",
    0x581a484: "be010000004489f148d3e60f110402f04809b2100b0000",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction window at {address:#x}")
print("Verified wide replay queue row and readiness publication.")
