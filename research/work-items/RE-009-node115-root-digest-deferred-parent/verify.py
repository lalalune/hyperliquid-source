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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x160ab60] != [(0x160ab60, 0x160b0d9)]:
    raise ValueError("preparer FDE mismatch")

def edge(site, prefix, target, code=None):
    if code is None:
        code = read(site, len(prefix) + 4)
    if code[:-4] != prefix or site + len(code) + struct.unpack("<i", code[-4:])[0] != target:
        raise ValueError(f"edge mismatch at {site:#x}")

for site, prefix, target in (
    (0x160bce0, b"\xe8", 0x160ab60),
    (0x160ab7d, b"\x0f\x84", 0x160aca1),
    (0x160ab99, b"\x0f\x84", 0x160ad04),
    (0x160ad07, b"\x0f\x84", 0x160af38),
    (0x160ae0f, b"\x0f\x84", 0x160b067),
):
    edge(site, prefix, target)
bad = bytearray(read(0x160ae0f, 6))
bad[2] ^= 1
try:
    edge(0x160ae0f, b"\x0f\x84", 0x160b067, bad)
except ValueError:
    pass
else:
    raise RuntimeError("corrupted edge accepted")

for address, raw in {
    0x160ab74: "8bb690000000", 0x160ab8f: "08ca",
    0x160ad0d: "488d6efe", 0x160ad14: "48c1e005",
    0x160ad29: "410f10840694000000", 0x160ad45: "410f10540e74",
    0x160ad7e: "80ca04", 0x160adec: "48c744247000000000",
    0x160adf5: "c644247840", 0x160b074: "48894160",
    0x160b07d: "884168", 0x160b085: "884169",
    0x160b08d: "88416a", 0x160b0d1: "0f1101",
}.items():
    code = bytes.fromhex(raw)
    if read(address, len(code)) != code:
        raise ValueError(f"preparer witness changed at {address:#x}")
print("Verified 14 witnesses, five edges and the deferred-parent branch corruption control.")
