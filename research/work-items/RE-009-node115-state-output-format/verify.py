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
start, end = 0x27743e0, 0x277458a
if [(f["start"], f["end"]) for f in frames if f["start"] == start] != [(start, end)]:
    raise ValueError("wrong FDE")

def read(addr, size):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= addr and addr + size <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError("invalid address")
    s = hits[0]
    off = s["offset"] + addr - s["address"]
    return data[off:off + size]

here = Path(__file__).resolve().parent
rows = re.findall(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)", (here / "body.llvm.txt").read_text(), re.M)
cursor = start
for addr, hex_code in rows:
    code = bytes.fromhex(hex_code)
    if cursor != int(addr, 16) or read(cursor, len(code)) != code:
        raise ValueError(f"body mismatch at {cursor:#x}")
    cursor += len(code)
if cursor != end:
    raise ValueError("body truncated")

def target(site, size, code):
    return site + size + struct.unpack("<i", code[-4:])[0]

fields = [
    (0x2774434, 0x2774440, 0x2774445, b"hardfork_version", 0x2590810),
    (0x2774462, 0x277446e, 0x2774473, b"initial_height", 0x2590810),
    (0x2774490, 0x277449c, 0x27744a1, b"height", 0x2590810),
    (0x27744b6, 0x27744c2, 0x27744ca, b"scheduled_freeze_height", 0x259b800),
    (0x27744df, 0x27744eb, 0x27744f0, b"consensus_time", 0x25a1b50),
    (0x2774505, 0x2774511, 0x2774519, b"wall_clock_time", 0x25a1b50),
]
for lea, length, call, name, callee in fields:
    opcode = read(lea, 7)
    dest = target(lea, 7, opcode)
    if opcode[:3] != b"\x48\x8d\x35" or read(dest, len(name)) != name:
        raise ValueError("field key mismatch")
    if read(length, 5) != b"\xba" + struct.pack("<I", len(name)):
        raise ValueError("field key length mismatch")
    code = read(call, 5)
    if code[0] != 0xe8 or target(call, 5, code) != callee:
        raise ValueError("field writer mismatch")
    changed = bytearray(code)
    changed[1] ^= 1
    if target(call, 5, changed) == callee:
        raise RuntimeError("displacement control failed")
print(f"Verified {end-start} bytes, {len(rows)} rows, six ordered field keys and six changed call targets.")

if [(f["start"], f["end"]) for f in frames if f["start"] == 0x26a55a0] != [(0x26a55a0, 0x26a5884)]:
    raise ValueError("wrong caller FDE")
call = read(0x26a5768, 5)
if call[0] != 0xe8 or target(0x26a5768, 5, call) != start:
    raise ValueError("wrong caller edge")
if read(0x2774419, 4) != bytes.fromhex("c604017b"):
    raise ValueError("opening delimiter changed")
print("Verified caller FDE, direct call, and opening delimiter.")

for site, destination in ((0x2c7d8af, 0x26a55a0), (0x26a5694, 0x159fca0), (0x26a56e2, 0x2774150)):
    code = read(site, 5)
    if code[0] != 0xe8 or target(site, 5, code) != destination:
        raise ValueError(f"selected format edge mismatch at {site:#x}")
for address, expected in {
    0x4659e5: b"rmp", 0x60eb5d: b"rmp", 0x459f60: b"json",
    0x2c7d78d: bytes.fromhex("48b9616263695f737461"),
    0x2c7d79e: bytes.fromhex("4881f274650000"),
    0x2c7d7b8: bytes.fromhex("480f44ca"),
    0x26a569b: bytes.fromhex("7471"),
    0x26a56fd: bytes.fromhex("0f85fe000000"),
}.items():
    if read(address, len(expected)) != expected:
        raise ValueError(f"format witness mismatch at {address:#x}")
rela = next(s for s in secs if s["name"] == ".rela.dyn")
for site, slot, callee in [(0x26a5791, 0x64e0028, 0x15020f0), (0x26a57ab, 0x64e09e8, 0x15024a0)]:
    code = read(site, 6)
    if code[:2] != b"\xff\x15" or target(site, 6, code) != slot:
        raise ValueError("output slot mismatch")
    records = struct.iter_unpack("<QQq", data[rela["offset"]:rela["offset"] + rela["size"]])
    if [(info, addend) for dst, info, addend in records if dst == slot] != [(8, callee)]:
        raise ValueError("output relocation mismatch")
print("Verified format selection, output slots and three additional call edges.")
