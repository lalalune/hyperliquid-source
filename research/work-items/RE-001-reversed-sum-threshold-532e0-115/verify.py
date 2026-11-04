#!/usr/bin/env python3
"""Verify the RE-001 flag-gated range reverse and sum threshold
0x5d532e0 packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt regenerates byte-for-byte from a fresh objdump run.
 4. Every excerpt instruction's bytes match the raw binary at
    the file offset (virtual address minus 0x1000).
 5. The routine and caller FDE ranges are present in readelf output.
 6. The census is reproduced: exactly 1 direct call and 0 tail
    jumps with the exact site list from callers.tsv.
 7. No stored qword / relocation for the routine address.
 8. records.json holds semantic records only (no per-instruction
    mnemonic list).
 9. The global pair slots sit in a BSS tail of their LOAD segment
    (file-backed bytes end before them, memsz covers them).
10. Model spot checks (reverse, flag clearing, sum, threshold,
    null-pair path, consumer branch).
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
MAIN_START, MAIN_END = 0x5D532E0, 0x5D5346F
GLOBAL_BEGIN, GLOBAL_END = 0x6500780, 0x6500788


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
if "pc=0000000005d532e0..0000000005d5346f" not in frames:
    fail("routine FDE not found")
if "pc=0000000005d60fa0..0000000005d623e0" not in frames:
    fail("caller FDE not found")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)["main"]
if (counts["direct_calls"], counts["tail_jumps"]) != (1, 0):
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
if "5d532e0" in relocs:
    fail("relocation found for the routine address")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
blob = json.dumps(records)
if "mnemonic" in blob or "instructions" in blob:
    fail("records.json carries instruction-level detail")
for key in ("target", "routines", "census", "consumers", "algorithm"):
    if key not in records:
        fail(f"records.json missing {key}")

# 9. Global pair slots in a BSS tail.
loads = subprocess.run(
    ["readelf", "-l", "-W", str(BIN)],
    capture_output=True, text=True, check=True).stdout
bss_ok = False
for line in loads.splitlines():
    parts = line.split()
    if len(parts) >= 6 and parts[0] == "LOAD":
        vaddr = int(parts[2], 16)
        filesz = int(parts[4], 16)
        memsz = int(parts[5], 16)
        if vaddr <= GLOBAL_BEGIN < vaddr + memsz \
                and GLOBAL_BEGIN >= vaddr + filesz \
                and vaddr <= GLOBAL_END < vaddr + memsz \
                and GLOBAL_END >= vaddr + filesz:
            bss_ok = True
if not bss_ok:
    fail("global pair slots are not in a BSS tail")

# 10. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "reversed_sum_threshold_532e0_115",
    ROOT / "tools/reversed_sum_threshold_532e0_115.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
H = mod.Holder


def el(first, second):
    return (first, second)


elems, flag, result = mod.check(H([el(1, 0x8000), el(2, 7)], flag=1))
assert elems == [el(2, 7), el(1, 0x8000)] and flag == 0 and result, \
    "flag-set reverse + threshold"
elems, flag, result = mod.check(H([el(1, 100)], flag=0))
assert elems == [el(1, 100)] and flag == 0 and not result, \
    "small sum under threshold"
_, flag, result = mod.check(H(None, flag=1), global_pair=[])
assert flag == 1 and not result, "null pair ignores flag, empty global"
assert mod.evaluate_range([el(0, 0x7FFF)]) is False
assert mod.evaluate_range([el(0, 0x8000)]) is True
assert mod.evaluate_range([el(0, 1)] * 19) is False
assert mod.consumer_branch(True) == "allocate"
assert mod.consumer_branch(False) == "walk"
print("ALL CHECKS PASSED")
