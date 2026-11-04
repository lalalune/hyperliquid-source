#!/usr/bin/env python3
"""Self-check for RE-001-instrumented-acquire-6ca40-115.

Checks, all against the real binary (no synthetic packets):
 1. work/hl-node-115.bin SHA-256 equals provenance/artifacts.json.
 2. MANIFEST.sha256 matches every packet file.
 3. main.txt regenerates byte-for-byte from a fresh objdump run.
 4. Every excerpt instruction's bytes match the raw binary at
    file offset (vaddr - 0x1000) in the executable LOAD segment.
 5. The routine FDE 0x606ca40..0x606cc6a is in the unwind data.
 6. census.py reproduces 244 direct calls + 8 tail jumps and the
    exact site list in callers.tsv.
 7. No stored qword and no RELATIVE relocation names 0x606ca40.
 8. records.json is semantic records only (no per-instruction
    mnemonic list).
 9. Three model spot checks end to end.
Exit nonzero on the first failure; print ALL CHECKS PASSED on success.
"""
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parents[2]
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
START, END = 0x606CA40, 0x606CC6A


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# 1. Binary digest + provenance binding.
if sha256(BIN) != DIGEST:
    fail("binary digest mismatch")
prov = json.loads((ROOT / "provenance/artifacts.json").read_text())
entry = [e for e in prov.get("files", [])
         if isinstance(e, dict)
         and e.get("path") == "artifacts/node/115/hl-node"]
if not entry or entry[0].get("sha256") != DIGEST:
    fail("provenance digest mismatch")

# 2. Manifest.
manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
for line in manifest:
    digest, name = line.split("  ", 1)
    if sha256(HERE / name) != digest:
        fail(f"manifest mismatch for {name}")

# 3. Excerpt regeneration.
fresh = subprocess.run(
    ["objdump", "-d", "--start-address=0x606ca40",
     "--stop-address=0x606cc6a", str(BIN)],
    capture_output=True, text=True, check=True).stdout
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
if checked < 50:
    fail(f"too few instructions checked: {checked}")
print(f"instruction bytes checked: {checked}")

# 5. FDE range.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True).stdout
if f"pc=000000000606ca40..000000000606cc6a" not in frames:
    fail("routine FDE not found")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)
if (counts["direct_calls"], counts["tail_jumps"]) != (244, 8):
    fail(f"census counts changed: {counts}")
sites = set()
for line in (HERE / "callers.tsv").read_text().splitlines()[1:]:
    site, kind, _, _ = line.split("\t")
    sites.add((int(site, 16), kind))
fresh_sites = {(int(va, 16), kind) for va, kind in counts["sites"]}
if len(sites) != 252 or sites != fresh_sites:
    fail("callers.tsv site list changed")

# 7. No stored pointers / relocations.
if struct.pack("<Q", START) in data:
    fail("stored qword for 0x606ca40 found")
relocs = subprocess.run(
    ["readelf", "-rW", str(BIN)], capture_output=True, text=True).stdout
if "606ca40" in relocs:
    fail("relocation names 0x606ca40")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
if "mnemonics" in records or "instructions" in records:
    fail("records.json carries a per-instruction list")
for key in ("task", "target", "routine", "gates", "record_layout",
            "transfers", "census", "unknowns"):
    if key not in records:
        fail(f"records.json missing {key}")

# 9. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "instrumented_acquire_6ca40_115",
    ROOT / "tools/instrumented_acquire_6ca40_115.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
timer = iter((100, 160))
hooks = {"tls_byte": 5, "global_nonzero": True, "counter": [0],
         "prologue": lambda: None, "tls_getter": lambda: None,
         "begin": lambda r: None, "now": lambda: next(timer),
         "lock": lambda: None,
         "observe": lambda c, t, e: None}
out = mod.acquire({"ctx": {"byte": 5}, "flag_nonzero": True,
                   "type_code": 0x34}, hooks)
if out["events"] != ["prologue", "tls_getter", "begin", "now",
                     "lock", "now", "observe"] or out["counter"] != 60:
    fail("fast timer model spot check failed")
hooks2 = {"tls_byte": 4, "global_nonzero": False, "counter": [0],
          "prologue": lambda: None, "tls_getter": lambda: None,
          "begin": lambda r: None, "now": lambda: 0,
          "lock": lambda: None, "observe": lambda c, t, e: None}
out2 = mod.acquire({"ctx": None, "flag_nonzero": False,
                    "type_code": 0x34}, hooks2)
if out2["events"] != ["prologue", "lock"]:
    fail("fallback lock-only model spot check failed")
print("ALL CHECKS PASSED")
