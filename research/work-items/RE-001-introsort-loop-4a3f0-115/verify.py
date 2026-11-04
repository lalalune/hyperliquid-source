#!/usr/bin/env python3
"""Verify the RE-001 pair introsort loop 0x5d4a3f0 evidence packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt and helper.txt regenerate byte-for-byte from fresh
    objdump runs.
 4. Every excerpt instruction's bytes match the raw binary at
    the file offset (virtual address minus 0x1000).
 5. Both routine FDE ranges present in readelf output.
 6. Both censuses reproduced: main exactly 4 direct calls, 0 tail
    jumps, with the exact site list from callers.tsv; helper
    exactly 2 direct calls, 0 tail jumps, with the exact site list
    from helper_callers.tsv.
 7. No stored qword / relocation for either routine address.
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
MAIN_START, MAIN_END = 0x5D4A3F0, 0x5D4A698
HELPER_START, HELPER_END = 0x5D49530, 0x5D496CD


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
for start, end, fname in ((MAIN_START, MAIN_END, "main.txt"),
                          (HELPER_START, HELPER_END, "helper.txt")):
    fresh = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    fresh = fresh.replace(str(BIN), BIN.name)
    if fresh != (HERE / fname).read_text():
        fail(f"{fname} does not regenerate byte-for-byte")

# 4. Instruction bytes vs raw binary.
data = BIN.read_bytes()
for fname, minimum in (("main.txt", 100), ("helper.txt", 50)):
    checked = 0
    for line in (HERE / fname).read_text().splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t|$)", line)
        if not m:
            continue
        va = int(m.group(1), 16)
        raw = bytes(int(b, 16) for b in m.group(2).split())
        if data[va - 0x1000:va - 0x1000 + len(raw)] != raw:
            fail(f"byte mismatch at {hex(va)} in {fname}")
        checked += 1
    if checked < minimum:
        fail(f"too few instructions checked in {fname}: {checked}")
    print(f"instruction bytes checked in {fname}: {checked}")

# 5. FDE ranges.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True).stdout
if "pc=0000000005d4a3f0..0000000005d4a698" not in frames:
    fail("main FDE not found")
if "pc=0000000005d49530..0000000005d496cd" not in frames:
    fail("helper FDE not found")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)
expected = {
    "main": (4, 0, "callers.tsv"),
    "helper": (2, 0, "helper_callers.tsv"),
}
for name, (want_calls, want_jumps, fname) in expected.items():
    got = counts[name]
    if (got["direct_calls"], got["tail_jumps"]) != (want_calls, want_jumps):
        fail(f"census counts changed for {name}: {got}")
    sites = set()
    for line in (HERE / fname).read_text().splitlines()[1:]:
        site, kind, _, _ = line.split("\t")
        sites.add((int(site, 16), kind))
    fresh_sites = {(int(va, 16), kind) for va, kind in got["sites"]}
    if len(sites) != want_calls or sites != fresh_sites:
        fail(f"{fname} site list changed")

# 7. No stored pointers / relocations.
for addr in (MAIN_START, HELPER_START):
    if struct.pack("<Q", addr) in data:
        fail(f"stored qword for {hex(addr)} found")
relocs = subprocess.run(
    ["readelf", "-rW", str(BIN)], capture_output=True, text=True).stdout
if "5d4a3f0" in relocs or "5d49530" in relocs:
    fail("relocation names a routine address")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
if "mnemonics" in records or "instructions" in records:
    fail("records.json carries a per-instruction list")
for key in ("task", "target", "routine", "helper", "object_layout",
            "algorithm", "consumers", "internal_transfers",
            "census", "unknowns"):
    if key not in records:
        fail(f"records.json missing {key}")

# 9. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "introsort_loop_4a3f0_115",
    ROOT / "tools/introsort_loop_4a3f0_115.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
if mod.introsort_loop([(9, 1), (8, 2)] + [(5, 5)] * 20, 0) != \
        sorted([(9, 1), (8, 2)] + [(5, 5)] * 20):
    fail("depth-zero model sort mismatch")


def insertion_sort(pairs):
    out = list(pairs)
    for i in range(1, len(out)):
        cur = out[i]
        j = i - 1
        while j >= 0 and out[j] > cur:
            out[j + 1] = out[j]
            j -= 1
        out[j + 1] = cur
    return out


sample = [(30, 3), (10, 1), (20, 2), (40, 4), (5, 5), (25, 0),
          (15, 9), (35, 8), (45, 7), (1, 1), (50, 0), (12, 12),
          (22, 22), (33, 33), (44, 44), (2, 2), (3, 3), (4, 4),
          (6, 6), (7, 7)]
looped = mod.introsort_loop(sample, 20)
if sorted(looped) != sorted(sample):
    fail("loop output permutation mismatch")
if insertion_sort(looped) != sorted(sample):
    fail("loop output not completed by insertion sort")
arr = [(9, 9)] * 25
arr[1] = (3, 30)
arr[12] = (1, 10)
arr[24] = (2, 20)
mod.median_to_first(arr, 0, 25)
if arr[0] != (2, 20):
    fail("median spot check mismatch")
heap = sorted([(i, 100 - i) for i in range(20)], reverse=True)
mod.adjust_heap(heap, 0, 5, 20, heap[11])
if heap[0] != (19, 81) or heap[5] != (8, 92):
    fail("adjust-heap spot check mismatch")
for i in range(1, 20):
    if heap[(i - 1) // 2] < heap[i]:
        fail("adjust-heap spot check heap violation")

print("ALL CHECKS PASSED")
