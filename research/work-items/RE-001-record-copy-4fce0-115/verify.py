#!/usr/bin/env python3
"""Self-check for RE-001-record-copy-4fce0-115.

Checks, all against the real binary (no synthetic packets):
 1. work/hl-node-115.bin SHA-256 equals provenance/artifacts.json.
 2. MANIFEST.sha256 matches every packet file.
 3. main.txt and helper.txt regenerate byte-for-byte from fresh
    objdump runs.
 4. Every excerpt instruction's bytes match the raw binary at
    file offset (vaddr - 0x1000) in the executable LOAD segment.
 5. The routine FDE 0x5d4fce0..0x5d4fd97 and the helper FDE
    0x61cf610..0x61cf64f are in the unwind data.
 6. census.py reproduces 112 direct calls + 0 tail jumps and the
    exact site list in callers.tsv.
 7. No stored qword and no RELATIVE relocation names 0x5d4fce0.
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
START, END = 0x5D4FCE0, 0x5D4FD97
HSTART, HEND = 0x61CF610, 0x61CF64F


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
for start, end, name in ((hex(START), hex(END), "main.txt"),
                         (hex(HSTART), hex(HEND), "helper.txt")):
    fresh = subprocess.run(
        ["objdump", "-d", f"--start-address={start}",
         f"--stop-address={end}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    if fresh != (HERE / name).read_text():
        fail(f"{name} does not regenerate byte-for-byte")

# 4. Instruction bytes vs raw binary.
data = BIN.read_bytes()
checked = 0
for name in ("main.txt", "helper.txt"):
    for line in (HERE / name).read_text().splitlines():
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

# 5. FDE ranges.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True).stdout
if "pc=0000000005d4fce0..0000000005d4fd97" not in frames:
    fail("routine FDE not found")
if "pc=00000000061cf610..00000000061cf64f" not in frames:
    fail("helper FDE not found")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)
if (counts["direct_calls"], counts["tail_jumps"]) != (112, 0):
    fail(f"census counts changed: {counts}")
sites = set()
for line in (HERE / "callers.tsv").read_text().splitlines()[1:]:
    site, kind, _, _ = line.split("\t")
    sites.add((int(site, 16), kind))
fresh_sites = {(int(va, 16), kind) for va, kind in counts["sites"]}
if len(sites) != 112 or sites != fresh_sites:
    fail("callers.tsv site list changed")

# 7. No stored pointers / relocations.
if struct.pack("<Q", START) in data:
    fail("stored qword for 0x5d4fce0 found")
relocs = subprocess.run(
    ["readelf", "-rW", str(BIN)], capture_output=True, text=True).stdout
if "5d4fce0" in relocs:
    fail("relocation names 0x5d4fce0")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
if "mnemonics" in records or "instructions" in records:
    fail("records.json carries a per-instruction list")
for key in ("task", "target", "routine", "clone_callee", "gates",
            "record_layout", "order", "transfers", "census", "unknowns"):
    if key not in records:
        fail(f"records.json missing {key}")

# 9. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "record_copy_4fce0_115",
    ROOT / "tools/record_copy_4fce0_115.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
tracker = {"strings": {}, "freed": set()}
src_id = "alloc0"
tracker["strings"][src_id] = "hello"
src = {"field32": 5, "field16": 6, "pad": "P", "text": src_id}
dest = {"field32": 0, "field16": 0, "pad": "P", "text": None}
out = mod.copy_record(dest, src, tracker)
if (dest["field32"], dest["field16"],
        tracker["strings"][dest["text"]]) != (5, 6, "hello"):
    fail("copy model spot check failed")
if out["freed"] != [] or dest["text"] == src_id:
    fail("clone freshness / dead-delete spot check failed")
tracker2 = {"strings": {"alloc0": "old"}, "freed": set()}
dest2 = {"field32": 0, "field16": 0, "pad": "P", "text": "alloc0"}
out2 = mod.copy_record(
    dest2, {"field32": 0, "field16": 0, "pad": "P", "text": None},
    tracker2)
if out2 != {"dropped_old": "alloc0", "freed": []}:
    fail("dropped-old spot check failed")
print("ALL CHECKS PASSED")
