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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4c5f1b0] != [(0x4c5f1b0, 0x4c5fda6)]:
    raise ValueError("history insertion FDE changed")

for address, raw in {
    0x4c5f553: "440fb7bac0010000", 0x4c5f55b: "440fb798c2010000",
    0x4c5f5c0: "bf28020000", 0x4c5f6bb: "498d5701",
    0x4c5f6e0: "498dbc24c8010000", 0x4c5f6ec: "4881c6d0010000",
    0x4c5f6f3: "c1e203", 0x4c5f70a: "498b94cec8010000",
    0x4c5f712: "4c89b260010000", 0x4c5f719: "66898ac0010000",
    0x4c5f728: "76d6", 0x4c5f875: "4b8994fcd0010000",
    0x4c5f87d: "6641898c24c2010000", 0x4c5f8b4: "4c89a660010000",
    0x4c5f8be: "6689bec0010000",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"reparent witness mismatch at {address:#x}")

def copy_slot(code):
    site = 0x4c5f6f6
    if code[:2] != b"\xff\x15" or site + len(code) + struct.unpack("<i", code[2:])[0] != 0x64df508:
        raise ValueError("copy slot mismatch")

code = read(0x4c5f6f6, 6)
copy_slot(code)
changed = bytearray(code)
changed[2] ^= 1
try:
    copy_slot(changed)
except ValueError:
    pass
else:
    raise RuntimeError("corrupted copy slot accepted")
print("Verified 15 reparent witnesses, child-copy slot and displacement corruption.")
