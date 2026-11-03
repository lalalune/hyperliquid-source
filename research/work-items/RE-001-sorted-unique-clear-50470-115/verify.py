#!/usr/bin/env python3
"""Self-check for RE-001-sorted-unique-clear-50470-115.

Checks, all against the real binary (no synthetic packets):
 1. work/hl-node-115.bin SHA-256 equals provenance/artifacts.json.
 2. MANIFEST.sha256 matches every packet file.
 3. main.txt regenerates byte-for-byte from a fresh objdump run.
 4. Every excerpt instruction's bytes match the raw binary at
    file offset (vaddr - 0x1000) in the executable LOAD segment.
 5. The routine FDE 0x5d50470..0x5d506a8 is in the unwind data.
 6. census.py reproduces 9 direct calls + 0 tail jumps and the
    exact site list in callers.tsv.
 7. No stored qword and no RELATIVE relocation names 0x5d50470.
 8. records.json is semantic records only (no per-instruction
    mnemonic list).
 9. Model spot checks end to end.
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
START, END = 0x5D50470, 0x5D506A8


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
    ["objdump", "-d", f"--start-address={hex(START)}",
     f"--stop-address={hex(END)}", str(BIN)],
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
if checked < 40:
    fail(f"too few instructions checked: {checked}")
print(f"instruction bytes checked: {checked}")

# 5. FDE range.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True).stdout
if "pc=0000000005d50470..0000000005d506a8" not in frames:
    fail("routine FDE not found")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)
if (counts["direct_calls"], counts["tail_jumps"]) != (9, 0):
    fail(f"census counts changed: {counts}")
sites = set()
for line in (HERE / "callers.tsv").read_text().splitlines()[1:]:
    site, kind, _, _ = line.split("\t")
    sites.add((int(site, 16), kind))
fresh_sites = {(int(va, 16), kind) for va, kind in counts["sites"]}
if len(sites) != 9 or sites != fresh_sites:
    fail("callers.tsv site list changed")

# 7. No stored pointers / relocations.
if struct.pack("<Q", START) in data:
    fail("stored qword for 0x5d50470 found")
relocs = subprocess.run(
    ["readelf", "-rW", str(BIN)], capture_output=True, text=True).stdout
if "5d50470" in relocs:
    fail("relocation names 0x5d50470")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
if "mnemonics" in records or "instructions" in records:
    fail("records.json carries a per-instruction list")
for key in ("task", "target", "routine", "object_layout",
            "element_layout", "gates", "sort_phase", "unique_phase",
            "destroy_phase", "reset_phase", "virtual_phase",
            "free_phase", "internal_transfers", "census", "unknowns"):
    if key not in records:
        fail(f"records.json missing {key}")

# 9. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "sorted_unique_clear_50470_115",
    ROOT / "tools/sorted_unique_clear_50470_115.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
tracker = {"disposed": [], "head_calls": [], "chain_calls": [],
           "chain_deleted": []}
obj = {"flag": True,
       "pairs": [(5, 50), (2, 20), (5, 50), (1, 10)],
       "capacity_bytes": 64, "buffer_present": True,
       "head": "h", "head_args": (10, 20),
       "chain": [{"func": "c1", "args": (30, 40)},
                 {"func": "c2", "args": (50, 60)}]}
out = mod.clear_container(obj, tracker)
if tracker["disposed"] != [(1, 10), (2, 20), (5, 50)]:
    fail(f"spot dispose order wrong: {tracker['disposed']}")
if out["freed_bytes"] != 64 or not out["tail"]:
    fail(f"spot free/tail wrong: {out}")
if tracker["head_calls"] != [("h", 10, 20)]:
    fail("spot head call wrong")
if tracker["chain_calls"] != [("c1", 30, 40), ("c2", 50, 60)]:
    fail("spot chain calls wrong")
if tracker["chain_deleted"] != [32, 32]:
    fail("spot chain delete sizes wrong")
if obj["pairs"] != [] or obj["head"] is not None or obj["chain"] != []:
    fail("spot post-state wrong")
tracker2 = {"disposed": [], "head_calls": [], "chain_calls": [],
            "chain_deleted": []}
obj2 = {"flag": False,
        "pairs": [(9, 90)], "capacity_bytes": 16,
        "buffer_present": True, "head": "h", "head_args": (1, 2),
        "chain": [{"func": "c1", "args": (3, 4)}]}
out2 = mod.clear_container(obj2, tracker2)
if tracker2["disposed"] or tracker2["head_calls"]:
    fail("flag-clear path must dispose and call nothing")
if out2["freed_bytes"] != 16 or obj2["head"] != "h":
    fail("flag-clear path post-state wrong")
print("ALL CHECKS PASSED")
