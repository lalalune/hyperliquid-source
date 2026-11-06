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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x160b3a0] != [(0x160b3a0, 0x160bcce)]:
    raise ValueError("wrong update FDE")

def edge(site, prefix, target, code=None):
    if code is None:
        code = read(site, len(prefix) + 4)
    if code[:-4] != prefix or site + len(code) + struct.unpack("<i", code[-4:])[0] != target:
        raise ValueError(f"unexpected edge at {site:#x}")

edge(0x41c5387, b"\xff\x15", 0x64df510)
edge(0x160b3f7, b"\xff\x15", 0x64e1948)
edge(0x160b400, b"\x0f\x84", 0x160bb4c)
edge(0x160b552, b"\xe8", 0x160b0e0)
bad = bytearray(read(0x160b400, 6))
bad[2] ^= 1
try:
    edge(0x160b400, b"\x0f\x84", 0x160bb4c, bad)
except ValueError:
    pass
else:
    raise RuntimeError("corrupted zero-remainder exit accepted")

rela = next(s for s in secs if s["name"] == ".rela.dyn")
entries = list(struct.iter_unpack("<QQq", data[rela["offset"]:rela["offset"] + rela["size"]]))
for slot, target in ((0x64df510, 0x160b3a0), (0x64e1948, 0x1609ab0)):
    if [(info, addend) for dst, info, addend in entries if dst == slot] != [(8, target)]:
        raise ValueError("update relocation mismatch")
for address, raw in {
    0x160b3bc: "0fb64f69", 0x160b3c0: "c1e106",
    0x160b3c3: "0fb64768", 0x160b3c7: "4801c8",
    0x160b3d0: "483d01040000", 0x160b3dc: "41bf00040000",
    0x160b3e2: "4929c7", 0x160b3e8: "4c0f42fb",
    0x160b3fd: "4c29fb", 0x160b406: "41807e6900",
    0x160b40e: "410a466a", 0x160b412: "0c02",
    0x160b55e: "4883f837", 0x160b56b: "48c1e105",
    0x160b58d: "41898690000000", 0x160b5a7: "48ffc0",
}.items():
    code = bytes.fromhex(raw)
    if read(address, len(code)) != code:
        raise ValueError(f"chunk witness mismatch at {address:#x}")

def split(used, incoming):
    taken = min(1024 - used, incoming)
    return taken, incoming - taken

for used, incoming, expected in [(1, 1022, (1022, 0)), (1, 1023, (1023, 0)), (1, 1024, (1023, 1)), (1024, 0, (0, 0)), (1024, 1, (0, 1))]:
    if split(used, incoming) != expected:
        raise ValueError("chunk boundary model mismatch")
print("Verified 16 instruction witnesses, four edges, two relocations and five boundary cases.")
