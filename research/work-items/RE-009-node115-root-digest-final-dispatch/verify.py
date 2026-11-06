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

import re
start, end = 0x160bcd0, 0x160bda0
if [(f["start"], f["end"]) for f in frames if f["start"] == start] != [(start, end)]:
    raise ValueError("finalizer extent mismatch")
rows = re.findall(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)", Path(__file__).with_name("body.llvm.txt").read_text(), re.M)
cursor = start
for addr, raw in rows:
    code = bytes.fromhex(raw)
    if cursor != int(addr, 16) or read(cursor, len(code)) != code:
        raise ValueError("finalizer body mismatch")
    cursor += len(code)
if cursor != end:
    raise ValueError("incomplete body")

def edge(site, prefix, target):
    code = read(site, len(prefix) + 4)
    if code[:-4] != prefix or site + len(code) + struct.unpack("<i", code[-4:])[0] != target:
        raise ValueError(f"edge mismatch at {site:#x}")

table = 0x46ab4c
for index, destination in enumerate((0x160bd54, 0x160bd6d, 0x160bd22, 0x160bd22, 0x160bd3b)):
    code = read(table + 4*index, 4)
    if table + struct.unpack("<i", code)[0] != destination:
        raise ValueError("dispatch mismatch")
    corrupt = bytes([code[0] ^ 1]) + code[1:]
    if table + struct.unpack("<i", corrupt)[0] == destination:
        raise RuntimeError("changed dispatch cell accepted")

edge(0x41c539a, b"\xff\x15", 0x64df518)
edge(0x160bce0, b"\xe8", 0x160ab60)
rela = next(s for s in secs if s["name"] == ".rela.dyn")
relocations = list(struct.iter_unpack("<QQq", data[rela["offset"]:rela["offset"] + rela["size"]]))
for site, slot, callee in (
    (0x41c539a, 0x64df518, start),
    (0x160bd33, 0x64e1950, 0x633fac0),
    (0x160bd4c, 0x64e1958, 0x6345bc0),
    (0x160bd65, 0x64e1960, 0x160d200),
    (0x160bd7e, 0x64e1968, 0x633d0c0),
):
    edge(site, b"\xff\x15", slot)
    if [(info, addend) for dst, info, addend in relocations if dst == slot] != [(8, callee)]:
        raise ValueError("relocation mismatch")
print(f"Verified {end-start} bytes, {len(rows)} rows, five table entries and five relative slots.")
