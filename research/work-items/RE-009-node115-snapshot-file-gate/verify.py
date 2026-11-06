"""Verify snapshot file admission and error result."""
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
    0x26a362c: "ff1516d3e303488b5c24104c8b7424184889df4c89f6ff1508d3e30384c0740d",
    0x26a366a: "488d05a434dafd",
    0x26a36b3: "ff152fc0e303488dbc24b0000000e83ae93500e908010000",
    0x26a37d3: "4889c341be01000000488b7424084885f6740d",
    0x26a37f3: "4c89f04889da",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction window at {address:#x}")
if read(0x446b15, 17) != b"\x0emissing file: \xc0\x00":
    raise ValueError("wrong diagnostic descriptor")
rela = next(section for section in secs if section["name"] == ".rela.dyn")
entries = struct.iter_unpack("<QQq", read(rela["address"], rela["size"]))
if [row for row in entries if row[0] == 0x64e0950] != [(0x64e0950, 8, 0x1500d20)]:
    raise ValueError("wrong file predicate binding")
print("Verified snapshot file predicate, diagnostic and error result.")
