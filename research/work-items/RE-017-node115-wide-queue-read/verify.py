"""Verify the selected wide queue read."""
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
    0x5a348b6: "e83541deff",
    0x5a348c3: "48f7d848894c24200f800f010000",
    0x5a348d1: "48b801000000000000804839c10f852c010000",
    0x5a348f3: "ff151fbcaa00",
    0x5a34904: "e8e740deff",
    0x5a34911: "48f7d848894c24200f80c1000000",
    0x5818b5f: "488b90100b00000fa3ca735889ca83e21f486bd258",
    0x5818b74: "0f1004100f104c10100f105410200f105c10300f11074c8b4410504c8947500f104410400f1147400f115f300f1157200f114f10",
    0x5818ba8: "48b8010000000000008048ffc04839077c2c48ffc148894e10",
    0x5818bc3: "480fbae221720c48b80100000000000080eb0d48b8010000000000008048ffc8488907",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong window at {address:#x}")
print("Verified wide queue row, signed advance gate and terminal flag decoding.")
