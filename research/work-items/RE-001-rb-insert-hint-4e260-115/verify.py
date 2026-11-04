#!/usr/bin/env python3
"""Verify the RE-001 RB insert-position 0x5d4e260 / 0x5d49910 packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt and helper.txt regenerate byte-for-byte from fresh
    objdump runs.
 4. Every excerpt instruction's bytes match the raw binary at
    the file offset (virtual address minus 0x1000).
 5. Both routine FDE ranges are present in readelf output.
 6. The census is reproduced: hinted exactly 4 direct calls and
    0 tail jumps with the exact site list from callers.tsv;
    unhinted exactly 0 direct calls and 1 tail jump (from the
    hinted routine) with the exact site list from
    helper_callers.tsv.
 7. No stored qword / relocation for either routine address.
 8. records.json holds semantic records only.
 9. Model spot checks (hinted and unhinted search end to end).
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
MAIN_START, MAIN_END = 0x5D4E260, 0x5D4E3EA
HELPER_START, HELPER_END = 0x5D49910, 0x5D499A2


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
for start, end, name in ((MAIN_START, MAIN_END, "main.txt"),
                         (HELPER_START, HELPER_END, "helper.txt")):
    fresh = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    fresh = fresh.replace(str(BIN), BIN.name)
    if fresh != (HERE / name).read_text():
        fail(f"{name} does not regenerate byte-for-byte")

# 4. Instruction bytes vs raw binary.
data = BIN.read_bytes()
for name, minimum in (("main.txt", 100), ("helper.txt", 40)):
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
        fail(f"too few instructions checked in {name}: {checked}")
    print(f"instruction bytes checked in {name}: {checked}")

# 5. FDE ranges.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True).stdout
if "pc=0000000005d4e260..0000000005d4e3ea" not in frames:
    fail("hinted FDE not found")
if "pc=0000000005d49910..0000000005d499a2" not in frames:
    fail("unhinted FDE not found")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)
if (counts["hinted"]["direct_calls"],
        counts["hinted"]["tail_jumps"]) != (4, 0):
    fail(f"hinted census counts changed: {counts['hinted']}")
if (counts["unhinted"]["direct_calls"],
        counts["unhinted"]["tail_jumps"]) != (0, 1):
    fail(f"unhinted census counts changed: {counts['unhinted']}")
for key, tsv in (("hinted", "callers.tsv"),
                 ("unhinted", "helper_callers.tsv")):
    sites = set()
    for line in (HERE / tsv).read_text().splitlines()[1:]:
        site, kind, _, _ = line.split("\t")
        sites.add((int(site, 16), kind))
    fresh_sites = {(int(va, 16), kind)
                   for va, kind in counts[key]["sites"]}
    if sites != fresh_sites:
        fail(f"{tsv} site list changed")

# 7. No stored pointers / relocations.
for addr in (MAIN_START, HELPER_START):
    if struct.pack("<Q", addr) in data:
        fail(f"stored qword for {hex(addr)} found")
relocs = subprocess.run(
    ["readelf", "-rW", str(BIN)], capture_output=True, text=True).stdout
if "5d4e260" in relocs or "5d49910" in relocs:
    fail("relocation names a routine address")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
if "mnemonics" in records or "instructions" in records:
    fail("records.json carries a per-instruction list")
for key in ("task", "target", "routines", "object_layout",
            "algorithm", "consumers", "internal_transfers",
            "census", "unknowns"):
    if key not in records:
        fail(f"records.json missing {key}")

# 9. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "rb_insert_hint_4e260_115",
    ROOT / "tools/rb_insert_hint_4e260_115.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def build(spec_tree):
    tree = mod.Tree()

    def make(node_spec):
        if node_spec is None:
            return None
        key, left, right = node_spec
        node = mod.Node(key)
        if left is not None:
            node.left = make(left)
            node.left.parent = node
        if right is not None:
            node.right = make(right)
            node.right.parent = node
        return node

    tree.root = make(spec_tree)

    def count(node):
        return 0 if node is None else 1 + count(node.left) + count(node.right)

    tree.count = count(tree.root)
    return tree


tree = build((20, (10, (5, None, None), (15, None, None)),
              (30, (25, None, None), None)))


def find(tree, key):
    node = tree.root
    while node is not None:
        if key == node.key:
            return node
        node = node.left if key < node.key else node.right
    return None


first, second = mod.get_insert_unique_pos(tree, 20)
assert first is find(tree, 20) and second is None
first, second = mod.get_insert_unique_pos(tree, 12)
assert first is None and second is find(tree, 15)
first, second = mod.get_insert_hint_unique_pos(tree, find(tree, 10), 12)
assert first is second is find(tree, 15)
first, second = mod.get_insert_hint_unique_pos(tree, tree.header, 99)
assert first is None and second is find(tree, 30)
first, second = mod.get_insert_hint_unique_pos(tree, find(tree, 30), 12)
assert first is None and second is find(tree, 15)

print("ALL CHECKS PASSED")
