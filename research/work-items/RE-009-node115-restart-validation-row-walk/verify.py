"""Verify restart validation row walking."""
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
    0x59eda5f: "488d4c241089efff156430af00",
    0x1506ea2: "488d04db498d04c64889842470010000",
    0x1506ee3: "4983c6484c3bb424700100000f847f030000",
    0x1506f16: "4c89f6488d542410ff15b49bfd0480bc24a8000000017512",
    0x15071c8: "48ffc348c7c1ffffffff480f44d948899c2440010000",
    0x59eda74: "498b7520498b5528488d8c24e000000089efff156430af00",
    0x1507691: "48898c2470010000",
    0x15077ab: "488b8424700100000f10000f1048100f294c24600f29442450",
    0x15076ba: "4885d2897c24140f840e060000",
    0x15076d0: "488d04d2488d04c64889842468010000",
    0x15076e0: "488b0d1189fd044c8b251289fd04498d742428488d41284080ff034c0f44e1480f44f0",
    0x1507799: "4983c7484c3bbc24680100000f8457030000",
    0x15077cc: "4c89fe488d542450ff15fe92fd04",
    0x15077da: "80bc24a800000001753c488bbc24b0000000488b44244048ffc048c7c1ffffffff480f44c14889442440",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction window at {address:#x}")
rela = next(section for section in secs if section["name"] == ".rela.dyn")
entries = struct.iter_unpack("<QQq", read(rela["address"], rela["size"]))
if [row for row in entries if row[0] in (0x64e0ad0, 0x64e0ad8, 0x64e0af0)] != [(0x64e0ad0, 8, 0x1506e40), (0x64e0ad8, 8, 0x1536a90), (0x64e0af0, 8, 0x1507680)]:
    raise ValueError("wrong restart slot binding")
print("Verified restart row layout, mode selection and traversal boundary.")
