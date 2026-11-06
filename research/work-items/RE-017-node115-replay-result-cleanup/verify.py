"""Check the #115 reducer handoff from static ELF evidence."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

HERE = Path(__file__).resolve().parent
expected = json.loads((HERE / "local-verification.json").read_text())
data = Path("artifacts/node/115/hl-node").read_bytes()
if hashlib.sha256(data).hexdigest() != expected["target_sha256"]:
    raise ValueError("target digest mismatch")
table = sections(data)
text = next(section for section in table if section["name"] == ".text")
start, end, site = (int(expected[key], 16) for key in ("start", "end", "caller_site"))

def read(va, size):
    if not text["address"] <= va or va + size > text["address"] + text["size"]:
        raise ValueError("outside .text")
    offset = va - text["address"] + text["offset"]
    return data[offset:offset + size]

_, frames = eh_frame_records(data, table)
if [(f["start"], f["end"]) for f in frames if f["start"] == start] != [(start, end)]:
    raise ValueError("FDE mismatch")
body = read(start, end - start)
if hashlib.sha256(body).hexdigest() != expected["body_sha256"]:
    raise ValueError("body digest mismatch")
row_pattern = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)", re.M)
for filename in ("reduction-final-helper.llvm.txt", "caller-window.llvm.txt"):
    rows = row_pattern.findall((HERE / filename).read_text())
    cursor = start if filename.startswith("reduction") else int(rows[0][0], 16)
    for address, encoded in rows:
        code = bytes.fromhex(encoded)
        if cursor != int(address, 16) or read(cursor, len(code)) != code:
            raise ValueError(f"byte mismatch at {cursor:#x}")
        cursor += len(code)
    if filename.startswith("reduction") and (cursor != end or len(rows) != expected["instruction_rows"]):
        raise ValueError("incomplete function evidence")

def check_edge(code):
    if code[0] != 0xe8 or site + 5 + struct.unpack_from("<i", code, 1)[0] != start:
        raise ValueError("replay cleanup call target mismatch")

original = read(site, 5)
check_edge(original)
mutated = bytearray(original)
mutated[1] ^= 1
try:
    check_edge(mutated)
except ValueError:
    print("Changed displacement rejected.")
else:
    raise RuntimeError("Displacement control failed.")
print(f"Verified {len(body)} bytes, {expected['instruction_rows']} function rows and replay cleanup call {site:#x}.")

pins = json.loads((HERE / "worker-pins.json").read_text())
for address, raw in pins.items():
    code = bytes.fromhex(raw)
    if read(int(address, 16), len(code)) != code:
        raise ValueError(f"worker witness mismatch at {address}")
print(f"Verified {len(pins)} worker instruction witnesses.")

context_start, context_end = 0x5b4f1c0, 0x5b4f23e
if [(f["start"], f["end"]) for f in frames if f["start"] == context_start] != [(context_start, context_end)]:
    raise ValueError("contextual cleanup FDE mismatch")
cursor = context_start
for address, encoded in row_pattern.findall((HERE / "context-cleanup.llvm.txt").read_text()):
    code = bytes.fromhex(encoded)
    if int(address, 16) != cursor or read(cursor, len(code)) != code:
        raise ValueError(f"contextual cleanup byte mismatch at {cursor:#x}")
    cursor += len(code)
if cursor != context_end:
    raise ValueError("incomplete contextual cleanup")
for address in (0x5b4db23, 0x5b4f203):
    code = read(address, 5)
    if code[0] != 0xe8 or address + 5 + struct.unpack_from("<i", code, 1)[0] != 0x5b232a0:
        raise ValueError("nested destructor mismatch")
print("Verified contextual cleanup and shared nested destructor.")
