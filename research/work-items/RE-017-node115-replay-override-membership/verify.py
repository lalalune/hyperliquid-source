"""Verify replay override membership in the pinned #115 ELF."""
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

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x5a63100] != [(0x5a63100, 0x5a6434f)]:
    raise ValueError("wrong callback extent")

for site, prefix, target in (
    (0x5a6e39c, "e8", 0x5a63100),
    (0x5a6e42d, "e8", 0x5a63100),
    (0x5a6e43d, "e8", 0x5a63100),
    (0x5a631f9, "e8", 0x4f24140),
    (0x5a6325a, "488d0d", 0x93ac50),
    (0x5a632bd, "e8", 0x4f0fce0),
):
    opcode = bytes.fromhex(prefix)
    raw = read(site, len(opcode) + 4)
    if raw[:-4] != opcode or site + len(raw) + struct.unpack("<i", raw[-4:])[0] != target:
        raise ValueError(f"wrong transfer at {site:#x}")

if read(0x93ac50, 24) != b"update_and_get_overrides":
    raise ValueError("wrong operation label")

for address, raw in {
    0x5a63209: "41807e20017539498b55204885d27430418b4621498b4d18488d1492",
    0x5a63230: "4883c6054839f27410803c310175f13944310175ebb001eb0231c0",
    0x5a6324b: "88842418010000",
    0x5a63266: "48c744244818000000",
    0x5a63287: "488d8424180100004889842418020000",
    0x5a632b3: "488d94241002000031c9",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"wrong instruction bytes at {address:#x}")


def member(flag, key, rows):
    if flag != 1:
        return False
    return any(rows[i] == 1 and struct.unpack_from("<I", rows, i + 1)[0] == key
               for i in range(0, len(rows), 5))


hit = struct.pack("<BI", 1, 0xffffffff)
wrong_tag = struct.pack("<BI", 2, 0xffffffff)
wrong_key = struct.pack("<BI", 1, 0x00ffffff)
for flags, rows, expected in (
    (1, b"", False), (0, hit, False), (2, hit, False),
    (1, wrong_tag, False), (1, wrong_key, False), (1, wrong_tag + wrong_key + hit, True),
):
    if member(flags, 0xffffffff, rows) != expected:
        raise ValueError("wrong synthetic membership result")
print("Verified packed override membership and boolean handoff.")
