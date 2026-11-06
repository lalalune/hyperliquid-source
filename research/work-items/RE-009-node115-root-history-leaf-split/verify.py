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
    raise ValueError("wrong history FDE")
for address, raw in {
    0x4c5f1d5: "4883fb0b", 0x4c5f1ff: "4883fb05",
    0x4c5f216: "bb04000000", 0x4c5f2cb: "741c",
    0x4c5f2cd: "4883fb06", 0x4c5f2d3: "bb05000000",
    0x4c5f2de: "48c744241000000000", 0x4c5f2f8: "4883c3f9",
    0x4c5f301: "bb06000000", 0x4c5f315: "bfc8010000",
    0x4c5f350: "48f7d5", 0x4c5f353: "4801c5",
    0x4c5f356: "664189aec2010000", 0x4c5f3b9: "488d14ed00000000",
    0x4c5f3d2: "48c1e505", 0x4c5f3e2: "6641899dc2010000",
    0x4c5f40c: "4d0f44e5", 0x4c5f4ce: "6641899c24c2010000",
}.items():
    code = bytes.fromhex(raw)
    if read(address, len(code)) != code:
        raise ValueError(f"split witness changed at {address:#x}")

def route(index):
    if index < 5:
        return 4, False, index
    if index == 5:
        return 5, False, index
    if index == 6:
        return 5, True, 0
    return 6, True, index - 7

old = list(range(0, 22, 2))
for index in range(12):
    pivot, right_side, local = route(index)
    left, right = old[:pivot], old[pivot+1:]
    key = 2 * index - 1
    selected = right if right_side else left
    if local > len(selected):
        raise ValueError("local index outside selected node")
    selected.insert(local, key)
    expected = old.copy()
    expected.insert(index, key)
    if left + [old[pivot]] + right != expected or len(left) not in (5, 6) or len(right) not in (5, 6):
        raise ValueError("split model does not preserve ordered contents")
print("Verified 18 split instructions and all 12 valid insertion positions.")
