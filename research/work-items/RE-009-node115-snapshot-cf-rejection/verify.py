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

def relative(site, prefix, target):
    raw = read(site, len(prefix) + 4)
    if raw[:-4] != prefix or site + len(raw) + struct.unpack("<i", raw[-4:])[0] != target:
        raise ValueError(f"edge mismatch at {site:#x}")

def check_cell(table, index, target, encoded):
    if table + struct.unpack("<i", encoded)[0] != target:
        raise ValueError(f"cell mismatch at {table + index*4:#x}")

for table, index, target in [(0x57834c, 0xcf, 0x1b4500d), (0x77ad80, 0x0f, 0x341ffc9)]:
    encoded = read(table + index * 4, 4)
    check_cell(table, index, target, encoded)
    altered = bytes([encoded[0] ^ 1]) + encoded[1:]
    try:
        check_cell(table, index, target, altered)
    except ValueError:
        pass
    else:
        raise RuntimeError("corruption accepted")

relative(0x1b4501e, b"\xff\x15", 0x64e4220)
relative(0x341ffd5, b"\x0f\x82", 0x34200c4)
relative(0x341fff7, b"\xe8", 0x3bc91d0)
rela = next(s for s in secs if s["name"] == ".rela.dyn")
entries = struct.iter_unpack("<QQq", data[rela["offset"]:rela["offset"] + rela["size"]])
if [(info, addend) for dst, info, addend in entries if dst == 0x64e4220] != [(8, 0x341ff00)]:
    raise ValueError("scalar reader relocation mismatch")

for address, raw in {
    0x1b4500d: "89c7", 0x341ff05: "418d8040ffffff",
    0x341ffd1: "4883fa08", 0x341ffdb: "4883c2f8",
    0x341ffe2: "4883c108", 0x341ffe6: "480fc8",
    0x341ffe9: "48894e10", 0x341ffed: "48895618",
    0x34200c4: "4801d1", 0x34200c7: "48894e10",
    0x34200cb: "48c7461800000000", 0x34200d3: "c60701",
}.items():
    expected = bytes.fromhex(raw)
    if read(address, len(expected)) != expected:
        raise ValueError(f"scalar witness mismatch at {address:#x}")
print("Verified two CF dispatch cells, three edges, one relocation, twelve instructions and two corrupted cells.")

relative(0x3bc9224, b"\x48\x8d\x35", 0x44f07a)
relative(0x3bc9230, b"\xe8", 0x3046740)
if read(0x44f07a, 30) != b"\x0einvalid type: \xc0\x0b, expected \xc0\x00":
    raise ValueError("invalid-type format changed")
entries = struct.iter_unpack("<QQq", data[rela["offset"]:rela["offset"] + rela["size"]])
if [(info, addend) for dst, info, addend in entries if dst == 0x64622f0] != [(8, 0x7930c4)]:
    raise ValueError("truncated diagnostic relocation changed")
if read(0x7930c4, 27) != b"failed to fill whole buffer":
    raise ValueError("truncated diagnostic changed")
for begin, end in [(0x341ff00, 0x34201bb), (0x3bc91d0, 0x3bc923e)]:
    if [(f["start"], f["end"]) for f in frames if f["start"] == begin] != [(begin, end)]:
        raise ValueError("scalar FDE mismatch")
print("Verified invalid-type and truncation diagnostics and both scalar FDEs.")
