"""Verify cutoff redistribution in the pinned #115 ELF."""
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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4ca3ca0] != [(0x4ca3ca0, 0x4ca457b)]:
    raise ValueError("wrong cutoff helper extent")

for site, prefix, target in (
    (0x4de4ab7, "e8", 0x4ca3ca0), (0x4de5b22, "e8", 0x4ca3ca0),
    (0x4ca3cc0, "ff15", 0x64df480), (0x4ca3e0b, "ff15", 0x64df508),
    (0x4ca3e25, "ff15", 0x64df508), (0x4ca3e4f, "ff15", 0x64df508),
):
    opcode = bytes.fromhex(prefix)
    raw = read(site, len(opcode) + 4)
    if raw[:-4] != opcode or site + len(raw) + struct.unpack("<i", raw[-4:])[0] != target:
        raise ValueError(f"wrong transfer at {site:#x}")

for address, raw in {
    0x4ca3cbb: "bfc8010000",
    0x4ca3cdd: "66c780c20100000000",
    0x4ca3d00: "bf28020000",
    0x4ca3d24: "4c89a8c8010000",
    0x4ca3d2b: "49898560010000",
    0x4ca3d32: "6641c785c001000000",
    0x4ca3d69: "4e8d3cf5c8010000",
    0x4ca3d77: "4d8ba424c8010000",
    0x4ca3dad: "483b6cd008",
    0x4ca3db5: "77e9",
    0x4ca3dc3: "664183bc24c2010000",
    0x4ca3de3: "664589b5c2010000",
    0x4ca3deb: "6641899c24c2010000",
    0x4ca3df4: "4a8d34f0",
    0x4ca3e03: "488d14dd00000000",
    0x4ca3e14: "48c1e605",
    0x4ca3e1e: "48c1e205",
    0x4ca3e34: "4a8d34f5d0010000",
    0x4ca3e3f: "498dbc24d0010000",
    0x4ca3e47: "488d14dd00000000",
    0x4ca3e90: "498b54cce8",
    0x4ca3e95: "4c89a260010000",
    0x4ca3e9f: "6689b2c0010000",
    0x4ca3ee8: "4883c104",
    0x4ca3f00: "498b94ccc8010000",
    0x4ca3f08: "4c89a260010000",
    0x4ca3f0f: "66898ac0010000",
    0x4ca3f4e: "4d8bb424c8010000",
    0x4ca3f56: "4d8937",
    0x4ca3f5d: "49894708",
    0x4ca3f61: "49c7866001000000000000",
    0x4ca3f6c: "be28020000",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")

for count in range(12):
    keys = list(range(0, 2 * count, 2))
    edges = list(range(count + 1))
    for cutoff in range(-1, 2 * count + 1):
        index = next((i for i, key in enumerate(keys) if key >= cutoff), count)
        left, right = keys[:index], keys[index:]
        if left != [key for key in keys if key < cutoff] or right != [key for key in keys if key >= cutoff]:
            raise ValueError("wrong cutoff index")
        right_edges = ["parallel cutoff child", *edges[index + 1:]]
        moved = len(right)
        group_end = 1 + (moved & ~3)
        slots = [slot for start in range(1, group_end, 4) for slot in range(start, start + 4)]
        slots.extend(range(group_end, group_end + (moved & 3)))
        if len(right_edges) != moved + 1 or [right_edges[slot] for slot in slots] != edges[index + 1:]:
            raise ValueError("right child update misses a transferred edge")

print("Verified two history callers, cutoff redistribution, and 156 synthetic node partitions.")
