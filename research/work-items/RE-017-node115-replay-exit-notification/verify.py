"""Verify replay exit notification in the pinned artifact."""
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

for site, target in ((0x5a70097, 0x5a5a300), (0x5a5a31c, 0x581be00)):
    opcode, displacement = struct.unpack("<Bi", read(site, 5))
    if opcode != 0xe8 or site + 5 + displacement != target:
        raise ValueError(f"wrong edge at {site:#x}")

for address, raw in {
    0x5a6fe24: "e8a7a4daff",
    0x5a6fe40: "4889c14883c902f0480fb18a1001000075ee4885c00f85d0000000",
    0x5a6fe63: "488b8200010000488bba0801000048c7820001000000000000",
    0x5a6fe7c: "31c948878a100100004885c00f849d000000ff5008",
    0x581be0b: "b801000000f0480fc147084989c74983e7e0488b0f4c89fa482b91000b00007521",
    0x581be2c: "48b80000000002000000f0480981100b0000",
    0x5a5a308: "4c8b3ff049ff8fc8010000755c",
    0x5a5a330: "4889c14883c902f0490fb18f1001000075ee4885c0752a",
    0x5a5a347: "498b8700010000498bbf0801000049c7870001000000000000",
    0x5a5a360: "31c949878f100100004885c07403ff5008",
    0x5a5a371: "f049ff0f7509",
    0x5a5a380: "488b4308f048ff087512",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong window at {address:#x}")
print("Verified replay exit reference and notification ordering.")
