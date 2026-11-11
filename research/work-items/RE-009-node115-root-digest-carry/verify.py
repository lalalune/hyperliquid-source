"""Verify checkpoint text projection in the pinned #115 ELF."""
import hashlib
from pathlib import Path
import re
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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x160b0e0] != [(0x160b0e0, 0x160b39f)]:
    raise ValueError("carry FDE mismatch")
for addr, raw in {
    0x160b0f7: "48b95555555555555555", 0x160b107: "48b83333333333333333",
    0x160b12b: "48b90f0f0f0f0f0f0f0f", 0x160b138: "48b80101010101010101",
    0x160b146: "48c1e838", 0x160b14a: "448baf90000000",
    0x160b156: "4c39e8", 0x160b17c: "80c904",
    0x160b1af: "48ffc8", 0x160b1c2: "4983c4fe",
    0x160b1c6: "4489a390000000", 0x160b1d0: "48c1e505",
    0x160b246: "c68424c800000040", 0x160b32e: "418d442401",
    0x160b333: "898390000000", 0x160b339: "4c3b642458",
}.items():
    code = bytes.fromhex(raw)
    if read(addr, len(code)) != code:
        raise ValueError(f"carry witness changed at {addr:#x}")

for site, target, prefix in (
    (0x160b552, 0x160b0e0, b"\xe8"),
    (0x160b159, 0x160b344, b"\x0f\x83"),
    (0x160b33e, 0x160b1a0, b"\x0f\x83"),
):
    code = read(site, len(prefix) + 4)
    if code[:-4] != prefix or site + len(code) + struct.unpack("<i", code[-4:])[0] != target:
        raise ValueError("carry edge mismatch")

def bit_total(value):
    value -= (value >> 1) & 0x5555555555555555
    value = (value & 0x3333333333333333) + ((value >> 2) & 0x3333333333333333)
    value = (value + (value >> 4)) & 0x0f0f0f0f0f0f0f0f
    return ((value * 0x0101010101010101) & ((1 << 64) - 1)) >> 56

for low in range(65536):
    for value in (low, low << 48, low | (1 << 63)):
        if bit_total(value) != bin(value).count("1"):
            raise ValueError("popcount arithmetic mismatch")
print("Verified 16 byte witnesses, three edges and 196608 synthetic bit-count cases.")
