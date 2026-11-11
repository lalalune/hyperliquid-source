"""Verify the replay receive poll route in the pinned #115 ELF."""
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
    raise ValueError("wrong receive extent")

for site, prefix, target in (
    (0x5a6e328, "e8", 0x5ab6df0),
    (0x5ab6f81, "e8", 0x581a100), (0x5ab6fba, "e8", 0x581a100),
    (0x5ab6fa9, "ff15", 0x64e0518),
    (0x5ab6f8e, "0f84", 0x5ab7030), (0x5ab6f97, "0f85", 0x5ab7050),
    (0x5ab6fc7, "0f84", 0x5ab705b), (0x5ab6fd0, "0f85", 0x5ab70b2),
    (0x5ab706a, "0f82", 0x5ab71c4),
    (0x5ab7197, "e8", 0x5cfd5e0),
):
    opcode = bytes.fromhex(prefix)
    raw = read(site, len(opcode) + 4)
    if raw[:-4] != opcode or site + len(raw) + struct.unpack("<i", raw[-4:])[0] != target:
        raise ValueError(f"wrong transfer at {site:#x}")

for address, raw in {
    0x5ab6f86: "488b4424484885c0",
    0x5ab6f94: "83f802",
    0x5ab6f9d: "498dbf00010000488d742438",
    0x5ab6fbf: "488b4424484885c0",
    0x5ab6fcd: "83f802",
    0x5ab7030: "f04983afc001000002",
    0x5ab7050: "4531f6",
    0x5ab705b: "f04983afc001000002",
    0x5ab7075: "488d4424500f10000f2944246041be01000000",
    0x5ab7184: "0f28442460488b5c24300f114308488b7c2418",
    0x5ab719c: "4c89334d85f6740e",
    0x5ab71ad: "f048ff4810",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

for value, expected in (
    (0, "record"), (1, "other"), (2, "repoll"), (3, "other"),
    (1 << 32, "other"), ((1 << 32) + 2, "repoll"),
):
    outcome = "record" if value == 0 else "repoll" if value & 0xffffffff == 2 else "other"
    if outcome != expected:
        raise ValueError("wrong synthetic status classification")

print("Verified replay poll, repoll, and record publication windows.")
