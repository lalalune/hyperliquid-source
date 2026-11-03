#!/usr/bin/env python3
"""Verify the RE-001 pair insertion sort 0x5d497e0 evidence packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt regenerates byte-for-byte from a fresh objdump run.
 4. Every excerpt instruction's bytes match the raw binary at
    the file offset (virtual address minus 0x1000).
 5. Routine FDE range present in readelf output.
 6. Census reproduction: exactly 6 direct calls, 0 tail jumps,
    with the exact site list from callers.tsv.
 7. No stored qword / relocation for 0x5d497e0.
 8. records.json holds semantic records only.
 9. Model spot checks (sort behavior end to end).
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
START, END = 0x5D497E0, 0x5D498B5


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
    ["objdump", "-d", f"--start-address={hex(START)}",
     f"--stop-address={hex(END)}", str(BIN)],
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
        fail(f"byte mismatch at {hex(va)}")
    checked += 1
if checked < 40:
    fail(f"too few instructions checked: {checked}")
print(f"instruction bytes checked: {checked}")

# 5. FDE range.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True).stdout
if "pc=0000000005d497e0..0000000005d498b5" not in frames:
    fail("routine FDE not found")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)
if (counts["direct_calls"], counts["tail_jumps"]) != (6, 0):
    fail(f"census counts changed: {counts}")
sites = set()
for line in (HERE / "callers.tsv").read_text().splitlines()[1:]:
    site, kind, _, _ = line.split("\t")
    sites.add((int(site, 16), kind))
fresh_sites = {(int(va, 16), kind) for va, kind in counts["sites"]}
if len(sites) != 6 or sites != fresh_sites:
    fail("callers.tsv site list changed")

# 7. No stored pointers / relocations.
if struct.pack("<Q", START) in data:
    fail("stored qword for 0x5d497e0 found")
relocs = subprocess.run(
    ["readelf", "-rW", str(BIN)], capture_output=True, text=True).stdout
if "5d497e0" in relocs:
    fail("relocation names 0x5d497e0")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
if "mnemonics" in records or "instructions" in records:
    fail("records.json carries a per-instruction list")
for key in ("task", "target", "routine", "object_layout",
            "algorithm", "consumers", "internal_transfers",
            "census", "unknowns"):
    if key not in records:
        fail(f"records.json missing {key}")

# 9. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "pair_insertion_sort_497e0_115",
    ROOT / "tools/pair_insertion_sort_497e0_115.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cases = [
    ([], []),
    ([(7, 70)], [(7, 70)]),
    ([(5, 50), (2, 20)], [(2, 20), (5, 50)]),
    ([(5, 50), (5, 20)], [(5, 20), (5, 50)]),
    ([(3, 1), (2, 2), (1, 3)], [(1, 3), (2, 2), (3, 1)]),
    ([(2**64 - 1, 0), (0, 2**64 - 1), (2**63, 2**63)],
     [(0, 2**64 - 1), (2**63, 2**63), (2**64 - 1, 0)]),
]
for given, want_sorted in cases:
    got = mod.insertion_sort(list(given))
    if got != want_sorted:
        fail(f"spot sort wrong: {given} -> {got}")
print("ALL CHECKS PASSED")
