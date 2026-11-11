"""Verify the bounded #115 formatter candidate without executing captured code."""
import argparse
from hashlib import sha256
from pathlib import Path
import re
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--llvm-objdump", required=True)
args = parser.parse_args()
sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

artifact = Path("artifacts/node/115/hl-node")
start, end = 0x14c2530, 0x14c2658
digest = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
data = artifact.read_bytes()
if sha256(data).hexdigest() != digest:
    raise ValueError("wrong #115 artifact")
table = sections(data)
_, frames = eh_frame_records(data, table)
if [(f["start"], f["end"]) for f in frames if f["start"] == start] != [(start, end)]:
    raise ValueError("wrong or ambiguous FDE extent")

def read(va, size):
    offsets = [
        s["offset"] + va - s["address"]
        for s in table
        if s["type"] != 8 and s["address"] <= va and va + size <= s["address"] + s["size"]
    ]
    if len(offsets) != 1:
        raise ValueError("ambiguous VA")
    return data[offsets[0]:offsets[0] + size]

raw = subprocess.check_output(
    [args.llvm_objdump, "-d", f"--start-address={start:#x}", f"--stop-address={end:#x}", str(artifact)],
    text=True,
)
pattern = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$", re.M)
rows = {int(addr, 16): (bytes.fromhex(code), asm) for addr, code, asm in pattern.findall(raw)}

def verify_window(window):
    cursor = start
    for address, (code, _) in rows.items():
        if address != cursor or window[cursor-start:cursor-start+len(code)] != code:
            raise ValueError(f"byte mismatch at {address:#x}")
        cursor += len(code)
    if cursor != end:
        raise ValueError("incomplete disassembly")

window = read(start, end-start)
verify_window(window)
mutated = bytearray(window)
mutated[0x14c25a0-start+1] ^= 1
try:
    verify_window(mutated)
except ValueError as exc:
    print(f"changed call displacement rejected: {exc}")
else:
    raise RuntimeError("corruption control failed")

calls = {address: asm for address, (_, asm) in rows.items() if asm.startswith("call")}
if set(calls) != {0x14c2562, 0x14c2591, 0x14c25a0, 0x14c25c8, 0x14c2611, 0x14c2634, 0x14c264e}:
    raise ValueError("call inventory changed")
for address in (0x14c25a0, 0x14c2611):
    code = rows[address][0]
    if address + len(code) + int.from_bytes(code[1:], "little", signed=True) != 0x15ea8f0:
        raise ValueError("payload delegate changed")
for address, literal in {
    0x464a67: b"InvalidParityValue", 0x46e7c4: b"(", 0x46e7c5: b"(\n",
    0x46e7c2: b",\n", 0x46e84d: b")",
}.items():
    if read(address, len(literal)) != literal:
        raise ValueError(f"literal mismatch at {address:#x}")
print(f"{len(window)} bytes, {len(rows)} instruction rows, {len(calls)} calls, 5 literal slices")
print(f"body sha256 {sha256(window).hexdigest()}")
