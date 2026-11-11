#!/usr/bin/env python3
"""Verify the RE-001 footer magic packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt, cold.txt and decode.txt regenerate byte-for-byte from
    fresh objdump runs (header normalized to the bare binary name).
 4. Every excerpt line's bytes match the raw binary at the file
    offset (virtual address minus 0x1000).
 5. The two 16-byte constant blocks in the binary match the values,
    slot addresses and SHA-256 digests in records.json.
 6. Every FDE line in frames.txt is present in readelf output.
 7. The censuses are reproduced exactly: 16 constant references with
    the committed site lists, Build 3 direct calls / 0 tail jumps,
    DecodeFrom 1 direct call / 0 tail jumps, and the stored-occurrence
    lists (each value's raw occurrences are exactly its slot plus,
    where present, the bytes of its movabs immediate).
 8. No relocation names any constant slot or pinned routine address,
    and relocations.txt is empty.
 9. records.json holds semantic records only and carries the
    required keys.
10. Model spot checks (build substitution, padding, versioned
    layout, decode-gate acceptance matrix).
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
EXCERPTS = (("main.txt", 0x6168620, 0x61686E4, 20),
            ("cold.txt", 0x61686E4, 0x6168780, 15),
            ("decode.txt", 0x6168780, 0x6169F65, 1000))
SLOTS = (0x97A0A0, 0x97A0A8, 0x97BDF0, 0x97BDF8)
ROUTINES = (0x6168620, 0x6168780)


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
data = BIN.read_bytes()
if sha256(data).hexdigest() != want:
    fail("binary digest mismatch")

# 2. Manifest.
for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
    digest, name = line.split("  ", 1)
    if sha256((HERE / name).read_bytes()).hexdigest() != digest:
        fail(f"manifest mismatch for {name}")

# 3. Excerpt regeneration.
for name, start, end, _ in EXCERPTS:
    if fresh_excerpt(start, end) != (HERE / name).read_text():
        fail(f"{name} does not regenerate byte-for-byte")

# 4. Line bytes vs raw binary.
for name, _, _, minimum in EXCERPTS:
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

# 5. Constant blocks.
records = json.loads((HERE / "records.json").read_text())
by_slot = {}
for entry in records["constants"]:
    if entry["slot_va"] is not None:
        by_slot[int(entry["slot_va"], 16)] = entry
for base in (0x97A0A0, 0x97BDF0):
    block = data[base:base + 16]
    digest = sha256(block).hexdigest()
    for i in (0, 8):
        entry = by_slot[base + i]
        if struct.unpack_from("<Q", block, i)[0] != int(entry["value"], 16):
            fail(f"constant value mismatch at {hex(base + i)}")
        if entry["pair_block_sha256"] != digest:
            fail(f"constant block digest mismatch at {hex(base + i)}")
        if int(entry["file_offset"], 16) != base + i:
            fail(f"constant file offset mismatch at {hex(base + i)}")

# 6. FDE lines.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True, check=True).stdout
for line in (HERE / "frames.txt").read_text().splitlines():
    if line not in frames:
        fail(f"FDE not found: {line}")

# 7. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)
if counts["refs"]["total"] != 16:
    fail(f"reference census total changed: {counts['refs']['total']}")
if (counts["build"]["direct_calls"], counts["build"]["tail_jumps"]) != (3, 0):
    fail(f"build census changed: {counts['build']}")
if (counts["decode"]["direct_calls"],
        counts["decode"]["tail_jumps"]) != (1, 0):
    fail(f"decode census changed: {counts['decode']}")


def tsv_sites(fname, ncols, key):
    rows = set()
    for line in (HERE / fname).read_text().splitlines()[1:]:
        parts = line.split("\t")
        rows.add(tuple(parts[:key]))
    return rows


ref_rows = {(p[0], p[1], p[2]) for p in
            (line.split("\t") for line in
             (HERE / "refs.tsv").read_text().splitlines()[1:])}
fresh_refs = {(va, kind, name)
              for va, kind, name in counts["refs"]["sites"]}
if ref_rows != fresh_refs:
    fail("refs.tsv site list changed")
for tsv, key in (("callers.tsv", "build"),
                 ("decode_callers.tsv", "decode")):
    rows = {(line.split("\t")[0], line.split("\t")[1])
            for line in (HERE / tsv).read_text().splitlines()[1:]}
    fresh = {(va, kind) for va, kind in counts[key]["sites"]}
    if rows != fresh:
        fail(f"{tsv} site list changed")
stored_rows = {(line.split("\t")[0], line.split("\t")[1])
               for line in (HERE / "stored.tsv").read_text().splitlines()[1:]}
fresh_stored = {(name, off) for name, offs in counts["stored"].items()
                for off in offs}
if stored_rows != fresh_stored:
    fail("stored.tsv occurrence list changed")

# 8. No relocations for the slots or routines.
relocs = subprocess.run(
    ["readelf", "--relocs", str(BIN)],
    capture_output=True, text=True, check=True).stdout
for addr in SLOTS + ROUTINES:
    if format(addr, "x") in relocs:
        fail(f"relocation found for {hex(addr)}")
if (HERE / "relocations.txt").read_text() != "":
    fail("relocations.txt is not empty")

# 9. Semantic records only.
blob = json.dumps(records)
if "mnemonic" in blob or "instructions" in blob:
    fail("records.json carries line-level detail")
for key in ("target", "constants", "routines", "footer_layout",
            "decode_gate", "census", "consumers", "algorithm"):
    if key not in records:
        fail(f"records.json missing key {key}")

# 10. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "footer_magic_model", ROOT / "tools/footer_magic_115.py")
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)
f = model.build_footer(0, 0, model.BLOCK_CURRENT, (0x1000, 0x200),
                       (0x3000, 0x40))
assert len(f) == 48
assert int.from_bytes(f[40:48], "little") == model.BLOCK_LEGACY
f = model.build_footer(0, 0, model.PAIR2_CURRENT, (0, 0), (0, 0))
assert int.from_bytes(f[40:48], "little") == model.PAIR2_WRITTEN
f = model.build_footer(3, 2, model.BLOCK_CURRENT, (0x10, 0x20),
                       (0x30, 0x40))
assert len(f) == 53 and f[0] == 2
assert int.from_bytes(f[41:45], "little") == 3
assert int.from_bytes(f[45:53], "little") == model.BLOCK_CURRENT
assert model.decode_gate(model.BLOCK_LEGACY, 0) == (
    True, model.BLOCK_CURRENT, 5, "decode48")
assert model.decode_gate(model.BLOCK_LEGACY, model.PAIR2_CURRENT)[0] is False
assert model.decode_gate(model.PAIR2_WRITTEN, model.PAIR2_CURRENT) == (
    True, model.PAIR2_CURRENT, 0, "decode48")
assert model.decode_gate(model.BLOCK_CURRENT, model.BLOCK_CURRENT) == (
    True, model.BLOCK_CURRENT, None, "decode_current")
assert model.decode_gate(0xDEADBEEFCAFEF00D, model.BLOCK_CURRENT) == (
    False, None, None, "error")

print("ALL CHECKS PASSED")
