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
        raise ValueError("snapshot writer call target mismatch")

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
print(f"Verified {len(body)} bytes, {expected['instruction_rows']} function rows and snapshot writer call {site:#x}.")

# Keep the claimed stores, width and early-exit decisions pinned independently.
for address, encoded in {
    0x25ea938: "c60401cf",        # marker
    0x25ea947: "4c894f10",        # one-byte length publication
    0x25ea951: "4883fa07",        # eight-byte space threshold
    0x25ea964: "727c",            # wrapped-length exit
    0x25ea9a7: "7439",            # payload growth rejection
    0x25ea9cc: "480fce",          # full-width endian conversion
    0x25ea9d3: "4a893408",        # payload store
    0x25ea9d7: "4883471008",      # eight-byte length publication
    0x25eaa2c: "4531f6",          # zero result before marker
}.items():
    code = bytes.fromhex(encoded)
    if read(address, len(code)) != code:
        raise ValueError(f"snapshot writer decision changed at {address:#x}")

def selected_bytes(word):
    swapped = int.from_bytes(word.to_bytes(8, "little"), "big")
    return b"\xcf" + swapped.to_bytes(8, "little")

for word, wire in {
    0x100000000: "cf0000000100000000",
    0x0102030405060708: "cf0102030405060708",
    0xffffffffffffffff: "cfffffffffffffffff",
}.items():
    if selected_bytes(word) != bytes.fromhex(wire):
        raise ValueError("wide-value model control failed")
print("Pinned nine writer instructions and checked three synthetic wide values.")
