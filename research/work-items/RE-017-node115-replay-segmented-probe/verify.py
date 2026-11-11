"""Verify the replay queue probe in the pinned #115 ELF."""
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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x581a100] != [(0x581a100, 0x581a2cf)]:
    raise ValueError("wrong replay probe extent")

for site in (0x5ab6f81, 0x5ab6fba):
    opcode, displacement = struct.unpack("<Bi", read(site, 5))
    if opcode != 0xe8 or site + 5 + displacement != 0x581a100:
        raise ValueError(f"wrong probe call at {site:#x}")

for address, raw in {
    0x581a109: "488b06488b4e104883e1e0483988000200007421",
    0x581a120: "488b80080200004885c00f847e010000488906f3904839880002000075e2",
    0x581a26b: "488b4e10488b90100200000fa3ca7320",
    0x581a27b: "89ca83e21fc1e2040f1004100f11470848c7070000000048ffc148894e10eb1a",
    0x581a29b: "480fbae221b8010000004883d8ff488907eb07",
    0x581a2ae: "48c70702000000",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

maximum = (1 << 64) - 1
for base in (0, 32, 1 << 63, maximum - 31):
    for slot in range(32):
        index = base + slot
        if index & ~31 != base or (index & 31) * 16 != slot * 16:
            raise ValueError("wrong segment or slot projection")
        for ready in (False, True):
            for flag in (False, True):
                status = ((1 << slot) if ready else 0) | ((1 << 33) if flag else 0)
                if (status & (1 << (index & 31))) != 0:
                    tag, next_index = 0, (index + 1) & maximum
                else:
                    tag, next_index = 2 - ((status >> 33) & 1), index
                expected = (0, (index + 1) & maximum) if ready else (1 if flag else 2, index)
                if (tag, next_index) != expected:
                    raise ValueError("wrong readiness or cursor progression")
print("Verified segment lookup, slot projection and 512 synthetic readiness cases.")
