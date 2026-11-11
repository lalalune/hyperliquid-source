"""Verify snapshot write error context."""
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
    0x1502563: "4885c07417488d7c2408488d7424604889c2e866010000",
    0x15026e5: "488954240848897c2410488d054aa4ffff48894424184889742420488d0599940e004889442428",
    0x150270c: "488d4424084889442430488b0593cdfd044889442438488d3d91a3f3fe488d742410e81db20000",
    0x1502733: "4889c3488d7c2408e8509e00004889d8",
    0x1502749: "4889c3488d7c2408e83a9e00004889df",
    0x150c598: "488b0789c183e1038d51fe83fa0272054885c9750c",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong window at {address:#x}")
literal = b"\x14write_bytes_to_file \xc0\x02, \xc0\x02: \xc0\x00"
if read(0x43caba, len(literal)) != literal:
    raise ValueError("wrong write error descriptor")
print("Verified snapshot write error context and selected cleanup gate.")
