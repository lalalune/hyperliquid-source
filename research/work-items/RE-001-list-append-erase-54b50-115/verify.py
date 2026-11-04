#!/usr/bin/env python3
"""Verify the RE-001 list append 0x5d54b50 / erase 0x5d54ba0 packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt and erase.txt regenerate byte-for-byte from fresh
    objdump runs.
 4. Every excerpt line's bytes match the raw binary at the file
    offset (virtual address minus 0x1000).
 5. Every FDE line in frames.txt is present in readelf output.
 6. Both censuses are reproduced: append exactly 6 direct calls and
    0 tail jumps; erase exactly 8 direct calls and 0 tail jumps,
    with exact site lists matching the committed TSVs.
 7. No stored qword / relocation for either routine address, and
    relocations.txt is empty.
 8. records.json holds semantic records only (no per-line detail
    list).
 9. Model spot checks (append order and return, erase frees and
    slot zeroing, null-slot no-op).
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
MAIN_START, MAIN_END = 0x5D54B50, 0x5D54B9B
ERASE_START, ERASE_END = 0x5D54BA0, 0x5D54C01


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def fresh_excerpt(start, end):
    text = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    return text.replace(str(BIN), BIN.name)


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
if fresh_excerpt(MAIN_START, MAIN_END) != (HERE / "main.txt").read_text():
    fail("main.txt does not regenerate byte-for-byte")
if fresh_excerpt(ERASE_START, ERASE_END) != (HERE / "erase.txt").read_text():
    fail("erase.txt does not regenerate byte-for-byte")

# 4. Line bytes vs raw binary.
data = BIN.read_bytes()
for name, minimum in (("main.txt", 20), ("erase.txt", 32)):
    checked = 0
    for line in (HERE / name).read_text().splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t|$)", line)
        if not m:
            continue
        va = int(m.group(1), 16)
        raw = bytes(int(b, 16) for b in m.group(2).split())
        if data[va - 0x1000:va - 0x1000 + len(raw)] != raw:
            fail(f"byte mismatch at {hex(va)} in {name}")
        checked += 1
    if checked < minimum:
        fail(f"too few lines checked in {name}: {checked}")
    print(f"lines checked in {name}: {checked}")

# 5. FDE ranges.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True, check=True).stdout
for line in (HERE / "frames.txt").read_text().splitlines():
    if line not in frames:
        fail(f"FDE not found: {line}")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)
app = counts["append"]
if (app["direct_calls"], app["tail_jumps"]) != (6, 0):
    fail(f"append census counts changed: {app}")
era = counts["erase"]
if (era["direct_calls"], era["tail_jumps"]) != (8, 0):
    fail(f"erase census counts changed: {era}")
for tsv, key in (("callers.tsv", "append"),
                 ("erase_callers.tsv", "erase")):
    sites = set()
    for line in (HERE / tsv).read_text().splitlines()[1:]:
        site, kind, _, _ = line.split("\t")
        sites.add((int(site, 16), kind))
    fresh_sites = {(int(va, 16), kind)
                   for va, kind in counts[key]["sites"]}
    if sites != fresh_sites:
        fail(f"{tsv} site list changed")

# 7. No stored qword / relocation for either routine address.
for addr in (MAIN_START, ERASE_START):
    if struct.pack("<Q", addr) in data:
        fail(f"stored qword found for {hex(addr)}")
relocs = subprocess.run(
    ["readelf", "--relocs", str(BIN)],
    capture_output=True, text=True, check=True).stdout
for needle in ("5d54b50", "5d54ba0"):
    if needle in relocs:
        fail(f"relocation found for {needle}")
if (HERE / "relocations.txt").read_text() != "":
    fail("relocations.txt is not empty")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
blob = json.dumps(records)
if "mnemonic" in blob or "instructions" in blob:
    fail("records.json carries line-level detail")
for key in ("target", "routines", "census", "consumers", "algorithm"):
    if key not in records:
        fail(f"records.json missing key {key}")

# 9. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "append_erase_model", ROOT / "tools/list_append_erase_54b50_115.py")
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)
holder = model.Holder("first")
n1 = model.append(holder)
holder.source_value = "second"
n2 = model.append(holder)
assert holder.values() == ["first", "second"]
assert holder.sentinel.prev is n2
slot = model.Slot()
model.install_handle(slot, n2)
assert model.erase(holder, slot) == [("node", 0x18), ("cell", 8)]
assert holder.values() == ["first"] and holder.size == 1
assert slot.cell is None and n2.freed
empty = model.Slot()
assert model.erase(holder, empty) == []
assert holder.size == 1
holder.check_links()

print("ALL CHECKS PASSED")
