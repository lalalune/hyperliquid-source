#!/usr/bin/env python3
"""Verify the RE-001 Ip variant JSON writer 0x5a2ff40 packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt regenerates byte-for-byte from a fresh objdump run.
 4. Every excerpt instruction's bytes match the raw binary at
    the file offset (virtual address minus 0x1000).
 5. The routine and caller FDE ranges are present in readelf output.
 6. The census is reproduced: exactly 5 direct calls and 1 tail
    jump with the exact site list from callers.tsv.
 7. No stored qword / relocation for the routine address.
 8. records.json holds semantic records only.
 9. The key bytes in records.json match the binary byte-for-byte.
10. Model spot checks (framing, growth gates, failure path).
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
MAIN_START, MAIN_END = 0x5A2FF40, 0x5A300AD


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
for rng in ("pc=0000000005a2ff40..0000000005a300ad",
            "pc=00000000050457f0..0000000005045cec",
            "pc=0000000005072e50..000000000507302d",
            "pc=0000000005080db0..0000000005080f30",
            "pc=00000000050df590..00000000050dfa15",
            "pc=00000000050e9340..00000000050e96f3"):
    if rng not in frames:
        fail(f"FDE not found: {rng}")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)["main"]
if (counts["direct_calls"], counts["tail_jumps"]) != (5, 1):
    fail(f"census counts changed: {counts}")
sites = set()
for line in (HERE / "callers.tsv").read_text().splitlines()[1:]:
    site, kind, _, _ = line.split("\t")
    sites.add((int(site, 16), kind))
fresh_sites = {(int(va, 16), kind) for va, kind in counts["sites"]}
if sites != fresh_sites:
    fail("callers.tsv site list changed")

# 7. No stored pointers / relocations.
if struct.pack("<Q", MAIN_START) in data:
    fail("stored qword for 0x5a2ff40 found")
relocs = subprocess.run(
    ["readelf", "-rW", str(BIN)], capture_output=True, text=True).stdout
if "5a2ff40" in relocs:
    fail("relocation names the routine address")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
if "mnemonics" in records or "instructions" in records:
    fail("records.json carries a per-instruction list")
for key in ("task", "target", "routines", "object_layout",
            "algorithm", "consumers", "internal_transfers",
            "census", "unknowns"):
    if key not in records:
        fail(f"records.json missing {key}")

# 9. Key bytes byte-for-byte from the binary's read-only segment
# (the first LOAD segment is identity-mapped, so the virtual
# address is the file offset).
if data[0x93A200:0x93A202] != b"Ip":
    fail("key bytes at 0x93a200 are not 'Ip'")

# 10. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "ip_variant_json_2ff40_115",
    ROOT / "tools/ip_variant_json_2ff40_115.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def writer(payload, status=0):
    def write(value, ctx):
        if payload:
            ctx[0].append_bytes(payload)
        return status

    return write


buf = mod.Buffer(capacity=64)
assert mod.write_ip_variant(None, [buf], writer(b'"10.0.0.1"')) == 0
assert buf.bytes() == b'{"Ip":"10.0.0.1"}'
assert buf.grow_calls == []

buf = mod.Buffer(capacity=0)
assert mod.write_ip_variant(None, [buf], writer(b"")) == 0
assert buf.bytes() == b'{"Ip":}'
assert buf.grow_calls == [(1, 1, 1)] * 5

buf = mod.Buffer(capacity=64)
assert mod.write_ip_variant(None, [buf], writer(b'"10.', 7)) == 7
assert buf.bytes() == b'{"Ip":"10.'

buf = mod.Buffer(capacity=14)
assert mod.write_ip_variant(None, [buf], writer(b"12345678")) == 0
assert buf.bytes() == b'{"Ip":12345678}'
assert buf.grow_calls == [(1, 1, 1)]

print("ALL CHECKS PASSED")
