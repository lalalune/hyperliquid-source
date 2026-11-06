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

from itertools import combinations_with_replacement

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x57f2d30] != [(0x57f2d30, 0x57f2e12)]:
    raise ValueError("cutoff FDE mismatch")
for address, raw in {
    0x57f2d30: "488b5718", 0x57f2d3c: "4c8b4710",
    0x57f2d45: "480f43c1", 0x57f2d49: "4929c0",
    0x57f2d52: "4829c8", 0x57f2d61: "7369",
    0x57f2d7a: "4b8d1480", 0x57f2d7e: "48c1e203",
    0x57f2db2: "490f42c0", 0x57f2dc7: "4883d000",
    0x57f2df2: "490f42f1", 0x57f2e07: "4883d600",
    0x4de5b99: "4929c7", 0x4de5ba2: "4a8d0cfd00000000",
    0x4de5baa: "488d3489",
}.items():
    code = bytes.fromhex(raw)
    if read(address, len(code)) != code:
        raise ValueError(f"cutoff witness changed at {address:#x}")
site = 0x4de5b8d
call = read(site, 5)
if call[0] != 0xe8 or site + 5 + struct.unpack("<i", call[1:])[0] != 0x57f2d30:
    raise ValueError("removal-to-cutoff edge changed")

def scan_span(rows, key):
    if not rows:
        return 0
    left = 0
    size = len(rows)
    while size > 1:
        half = size // 2
        mid = left + half
        if rows[mid] < key:
            left = mid
        size -= half
    return left + (rows[left] < key)

def cutoff(first, second, key):
    if second and second[0] < key:
        return len(first) + scan_span(second, key)
    return scan_span(first, key)

cases = 0
for length in range(9):
    for rows in combinations_with_replacement((0, 1, 1 << 63, (1 << 64) - 1), length):
        for split in range(length + 1):
            for key in (0, 1, 2, 1 << 63, (1 << 64) - 1):
                if cutoff(rows[:split], rows[split:], key) != sum(row < key for row in rows):
                    raise ValueError("cutoff model disagrees with linear count")
                cases += 1
print(f"Verified 15 cutoff witnesses, direct removal edge and {cases} synthetic wrapped spans.")
