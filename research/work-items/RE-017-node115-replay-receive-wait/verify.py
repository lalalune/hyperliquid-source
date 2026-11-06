"""Verify replay receive wait and retry in the pinned #115 ELF."""
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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x5ab6df0] != [(0x5ab6df0, 0x5ab72b5)]:
    raise ValueError("wrong replay receive extent")

for site, prefix, target in (
    (0x5ab6f3e, "0f84", 0x5ab70cb),
    (0x5ab70d7, "ff15", 0x64e0520),
    (0x5ab717f, "e9", 0x5ab7091),
    (0x5ab7137, "e8", 0x5cfdb90),
    (0x5ab7141, "e9", 0x5ab6eb0),
    (0x5ab714d, "e8", 0x5cdf300),
):
    opcode = bytes.fromhex(prefix)
    raw = read(site, len(opcode) + 4)
    if raw[:-4] != opcode or site + len(raw) + struct.unpack("<i", raw[-4:])[0] != target:
        raise ValueError(f"wrong transfer at {site:#x}")

for address, raw in {
    0x5ab6ee0: "64410fb66f4464410fb65745646641c747440180",
    0x5ab6f26: "64450fb66f4464450fb667454489e04180fd01750e4584e4",
    0x5ab6f44: "418d4424ff6441884745",
    0x5ab6fd6: "4180bfb8010000017511498b87c00100004883f8020f82c6000000",
    0x5ab6ff1: "b30341be020000004584ed",
    0x5ab70e3: "b30341be02000000eba4",
    0x5ab7110: "6441886f446445886f454183fe027564",
    0x5ab7120: "64803c25f0fbffff01488b4424207516488b384883c710",
    0x5ab713c: "4c8b742410",
    0x5ab7152: "4885c075d9",
    0x5ab7174: "6441c64744016445886745",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

print("Verified replay budget gate, TLS continuation and post-wait retry.")
