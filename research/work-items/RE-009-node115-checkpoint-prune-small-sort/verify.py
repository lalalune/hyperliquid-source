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
    if code[0] != 0xe9 or site + 5 + struct.unpack_from("<i", code, 1)[0] != start:
        raise ValueError("checkpoint prune tail jump target mismatch")

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
print(f"Verified {len(body)} bytes, {expected['instruction_rows']} function rows and checkpoint prune tail jump {site:#x}.")

from itertools import product

for address, raw in {
    0x14c6436: "4883fe02", 0x14c6443: "4883fe20",
    0x14c67d0: "b901000000", 0x14c67d5: "4883fa08",
    0x14c69fa: "4c39ca", 0x14c69fd: "73e7",
    0x14c6a10: "4d890c38", 0x14c6a14: "4883ff08",
    0x14c6a23: "4c39ca", 0x14c6a26: "72e8",
}.items():
    code = bytes.fromhex(raw)
    if read(address, len(code)) != code:
        raise ValueError(f"insertion witness mismatch at {address:#x}")

def modeled_insertion(source):
    words = list(source)
    for index in range(1, len(words)):
        value = words[index]
        hole = index
        while hole and value < words[hole - 1]:
            words[hole] = words[hole - 1]
            hole -= 1
        words[hole] = value
    return words

cases = 0
for length in range(2, 9):
    for words in product((0, 1 << 63, (1 << 64) - 1), repeat=length):
        if modeled_insertion(words) != sorted(words):
            raise ValueError("unsigned insertion model disagrees with reference")
        cases += 1
print(f"Checked ten decision witnesses and {cases} synthetic insertion cases.")
