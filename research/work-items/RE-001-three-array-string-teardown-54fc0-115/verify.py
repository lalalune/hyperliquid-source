#!/usr/bin/env python3
"""Verify the RE-001 three-array string teardown 0x5d54fc0 packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt regenerates byte-for-byte from a fresh objdump run.
 4. Every excerpt instruction's bytes match the raw binary at
    the file offset (virtual address minus 0x1000).
 5. The routine and caller FDE ranges are present in readelf output.
 6. The census is reproduced: exactly 2 direct calls and 0 tail
    jumps with the exact site list from callers.tsv.
 7. No stored qword / relocation for the routine address, and
    relocations.txt is empty.
 8. records.json holds semantic records only (no per-instruction
    mnemonic list).
 9. Model spot checks (order, short-string skip, capacity + 1,
    null-begin skip, empty buffer free).
"""
import importlib.util
import json
import re
import struct
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parents[2]
BIN = ROOT / "work/hl-node-115.bin"
MAIN_START, MAIN_END = 0x5D54FC0, 0x5D55105


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


# 1. Target digest.
artifacts = json.loads((ROOT / "provenance/artifacts.json").read_text())
want = next(f["sha256"] for f in artifacts["files"]
            if f["path"] == "artifacts/node/115/hl-node")
if sha256(BIN.read_bytes()).hexdigest() != want:
    fail("binary digest mismatch")

# 2. Manifest.
for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
    digest, name = line.split("  ", 1)
    if sha256((HERE / name).read_bytes()).hexdigest() != digest:
        fail(f"manifest mismatch for {name}")

# 3. Excerpt regeneration (header normalized to the bare binary name,
# matching export_excerpts.py, so the check is not machine-specific).
fresh = subprocess.run(
    ["objdump", "-d", f"--start-address={hex(MAIN_START)}",
     f"--stop-address={hex(MAIN_END)}", str(BIN)],
    capture_output=True, text=True, check=True).stdout
fresh = fresh.replace(str(BIN), BIN.name)
if fresh != (HERE / "main.txt").read_text():
    fail("main.txt does not regenerate byte-for-byte")

# 4. Instruction bytes vs raw binary.
data = BIN.read_bytes()
checked = 0
for line in (HERE / "main.txt").read_text().splitlines():
    m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t|$)", line)
    if not m:
        continue
    va = int(m.group(1), 16)
    raw = bytes(int(b, 16) for b in m.group(2).split())
    if data[va - 0x1000:va - 0x1000 + len(raw)] != raw:
        fail(f"byte mismatch at {hex(va)} in main.txt")
    checked += 1
if checked < 30:
    fail(f"too few instructions checked in main.txt: {checked}")
print(f"instruction bytes checked in main.txt: {checked}")

# 5. FDE ranges.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True, check=True).stdout
if "pc=0000000005d54fc0..0000000005d55105" not in frames:
    fail("routine FDE not found")
if "pc=0000000005d7d5a8..0000000005d7d740" not in frames:
    fail("caller FDE not found")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)["main"]
if (counts["direct_calls"], counts["tail_jumps"]) != (2, 0):
    fail(f"census counts changed: {counts}")
sites = set()
for line in (HERE / "callers.tsv").read_text().splitlines()[1:]:
    site, kind, _, _ = line.split("\t")
    sites.add((int(site, 16), kind))
fresh_sites = {(int(va, 16), kind) for va, kind in counts["sites"]}
if sites != fresh_sites:
    fail("callers.tsv site list changed")

# 7. No stored qword / relocation for the routine address.
if struct.pack("<Q", MAIN_START) in data:
    fail("stored qword found for the routine address")
relocs = subprocess.run(
    ["readelf", "--relocs", str(BIN)],
    capture_output=True, text=True, check=True).stdout
if "5d54fc0" in relocs:
    fail("relocation found for the routine address")
if (HERE / "relocations.txt").read_text() != "":
    fail("relocations.txt is not empty")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
blob = json.dumps(records)
if "mnemonic" in blob or "instructions" in blob:
    fail("records.json carries instruction-level detail")
for key in ("target", "routines", "census", "consumers", "algorithm"):
    if key not in records:
        fail(f"records.json missing key {key}")

# 9. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "teardown_model", ROOT / "tools/three_array_string_teardown_54fc0_115.py")
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)
empty = {n: (False, [], 0) for n in ("A", "B", "C")}
assert model.teardown(empty) == []
holder = dict(empty)
holder["A"] = (True, [(False, 0), (True, 15)], 64)
holder["C"] = (True, [(True, 0)], 32)
assert model.teardown(holder) == [
    ("elem", "A", 1, 16), ("buffer", "A", 64),
    ("elem", "C", 0, 1), ("buffer", "C", 32),
]

print("ALL CHECKS PASSED")
