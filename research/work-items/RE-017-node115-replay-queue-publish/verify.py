"""Verify the selected 16-byte queue publication in the pinned #115 ELF."""
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

extents = {0x581b0c0: 0x581b2a8, 0x5a35480: 0x5a35f48}
if sorted((frame["start"], frame["end"]) for frame in frames if frame["start"] in extents) != sorted(extents.items()):
    raise ValueError("wrong producer or caller extent")

site = 0x5a35b8b
opcode, displacement = struct.unpack("<Bi", read(site, 5))
if opcode != 0xe8 or site + 5 + displacement != 0x581b0c0:
    raise ValueError("wrong producer call")

for address, raw in {
    0x5a35b71: "48c74424400000000048894c2448488dbb80000000488d742440",
    0x581b0cb: "41be01000000f04c0fc17708",
    0x581b0d7: "4d89f54983e5e0488b174c89e8482b82000200007509",
    0x581b0ed: "4183e61fe948010000",
    0x581b114: "4c39aa000200000f8419010000",
    0x581b124: "488b92080200004885d2",
    0x581b23a: "488b3424",
    0x581b23e: "4489f0c1e0040f1006be010000004489f148d3e60f110402f04809b210020000",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

# The reader's selected slot arithmetic and bit test are separate instructions.
if read(0x581a276, 3) != bytes.fromhex("0fa3ca") or read(0x581a27d, 9) != bytes.fromhex("83e21fc1e2040f1004"):
    raise ValueError("reader projection anchor changed")

for block in (0, 1, 1 << 58, (1 << 59) - 1):
    for slot in range(32):
        index = block * 32 + slot
        base = index & ~31
        offset = (index & 31) * 16
        readiness = 1 << (index & 31)
        if (base, offset, readiness) != (block * 32, slot * 16, 1 << slot):
            raise ValueError("producer and reader coordinates disagree")
print("Verified 16-byte publication order and 128 synthetic producer/reader coordinates.")
