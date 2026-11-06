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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x5a03fa0] != [(0x5a03fa0, 0x5a046ec)]:
    raise ValueError("history wrapper FDE changed")

def edge(site, prefix, expected, code=None):
    if code is None:
        code = read(site, len(prefix) + 4)
    if code[:-4] != prefix or site + len(code) + struct.unpack("<i", code[-4:])[0] != expected:
        raise ValueError(f"unexpected edge at {site:#x}")

if read(0x5a03fbd, 8) != bytes.fromhex("488b53184883fa33"):
    raise ValueError("post-insertion threshold changed")
edge(0x5a03fb8, b"\xe8", 0x4dd45c0)
edge(0x5a03fc5, b"\x0f\x82", 0x5a040aa)
for number in range(43):
    address = 0x5a042ff + number * 0x13
    edge(address, b"\xe8", 0x4e2a530)
    if read(address + 5, 3) != bytes.fromhex("4885c0"):
        raise ValueError("iterator result not tested")
    edge(address + 8, b"\x0f\x84", 0x5a040aa)
if read(0x5a04635, 8) != bytes.fromhex("488b004889442450"):
    raise ValueError("selected key projection changed")
edge(0x5a0464a, b"\xe8", 0x4de5ad0)
edge(0x4e2a533, b"\x0f\x85", 0x514dc20)
if read(0x4e2a55f, 4) != bytes.fromhex("4883c1d8"):
    raise ValueError("flat stride changed")
site = 0x5a04625
bad = bytearray(read(site, 6))
bad[2] ^= 1
try:
    edge(site, b"\x0f\x84", 0x5a040aa, bad)
except ValueError:
    pass
else:
    raise RuntimeError("corrupted early exit accepted")
print("Verified post-insert threshold, 43 advance/exit pairs, selected key, helper dispatch and corruption control.")
