#!/usr/bin/env python3
"""Verify the RE-001 buffer growth routine 0x5963a10 packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt regenerates byte-for-byte from a fresh objdump run.
 4. Every excerpt instruction's bytes match the raw binary at
    the file offset (virtual address minus 0x1000).
 5. The routine, allocator-callee and failure-entry FDE ranges
    are present in readelf output.
 6. The census is reproduced: exactly 15,566 direct calls and 0
    tail jumps with the exact site list from callers.tsv.
 7. No stored qword / relocation for the routine address.
 8. records.json holds semantic records only.
 9. The routine's FDE carries no LSDA (augmentation length 0,
    CIE augmentation "zR" with no personality), and the failure
    slot 0x64df498 resolves to 0x141e264 in the relocations.
10. Model spot checks (capacity table, wrapping, failure order).
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
MAIN_START, MAIN_END = 0x5963A10, 0x5963A9E


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
for rng in ("pc=0000000005963a10..0000000005963a9e",
            "pc=0000000005963650..0000000005963739",
            "pc=000000000141e264..000000000141e279"):
    if rng not in frames:
        fail(f"FDE not found: {rng}")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)["main"]
if (counts["direct_calls"], counts["tail_jumps"]) != (15566, 0):
    fail(f"census counts changed: {counts}")
sites = set()
for line in (HERE / "callers.tsv").read_text().splitlines()[1:]:
    site, kind, _, _ = line.split("\t")
    sites.add((int(site, 16), kind))
fresh_sites = {(int(va, 16), kind) for va, kind in counts["sites"]}
if sites != fresh_sites:
    fail("callers.tsv site list changed")

# 7. No stored pointers / relocations naming the routine.
if struct.pack("<Q", MAIN_START) in data:
    fail("stored qword for 0x5963a10 found")
relocs = subprocess.run(
    ["readelf", "-rW", str(BIN)], capture_output=True, text=True).stdout
for line in relocs.splitlines():
    if line.rstrip().endswith("5963a10"):
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

# 9. No LSDA on the routine's FDE, and the failure slot resolves
# as pinned. The .eh_frame CIE 0 has augmentation "zR" (no 'L',
# no personality); an FDE under it carries one augmentation-length
# byte after the initial location and range, and 0 means no LSDA.
e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
secs = [struct.unpack_from("<IIQQQQ", data, e_shoff + i * e_shentsize)
        for i in range(e_shnum)]
str_off = secs[e_shstrndx][4]


def sec_name(sec):
    end = data.index(b"\x00", str_off + sec[0])
    return data[str_off + sec[0]:end].decode()


eh = next(s for s in secs if sec_name(s) == ".eh_frame")
eh_off, eh_va, eh_size = eh[4], eh[3], eh[5]
aug_end = data.index(b"\x00", eh_off + 9)
if data[eh_off + 9:aug_end] != b"zR":
    fail("CIE 0 augmentation is not 'zR'")
aug_len = None
off = eh_off
while off < eh_off + eh_size:
    ln = struct.unpack_from("<I", data, off)[0]
    if ln == 0:
        break
    if struct.unpack_from("<I", data, off + 4)[0] != 0:
        field_va = eh_va + (off - eh_off) + 8
        init = field_va + struct.unpack_from("<i", data, off + 8)[0]
        if init == MAIN_START:
            aug_len = data[off + 16]
            break
    off += 4 + ln
if aug_len != 0:
    fail(f"routine FDE augmentation length is {aug_len}, not 0")
slot_lines = [ln for ln in relocs.splitlines()
              if ln.startswith("00000000064df498")]
if len(slot_lines) != 1 or not slot_lines[0].rstrip().endswith("141e264"):
    fail("failure slot 0x64df498 does not resolve to 0x141e264")

# 10. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "buffer_grow_963a10_115",
    ROOT / "tools/buffer_grow_963a10_115.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

assert mod.min_capacity(1) == 8
assert mod.min_capacity(0x400) == 4
assert mod.min_capacity(0x401) == 1
assert mod.new_capacity(0, 0, 1, 1) == 8
assert mod.new_capacity(16, 16, 1, 1) == 32
assert mod.new_capacity(4, 4, 100, 1) == 104
assert mod.new_capacity(1 << 63, 5, 1, 1) == 8
for bad in ((0, 0, 1, 0), (0, (1 << 64) - 1, 1, 1)):
    try:
        mod.new_capacity(*bad)
    except mod.GrowthFailure:
        pass
    else:
        raise AssertionError(f"no failure for {bad}")

buf = mod.Buffer(capacity=3, data_ptr=0x1000, length=3)
assert mod.grow(buf, 3, 1, 1, 1, lambda c, p, n, f: (0, 0x9000, 0)) == 8
assert (buf.capacity, buf.data_ptr, buf.length) == (8, 0x9000, 3)
buf = mod.Buffer(capacity=3, data_ptr=0x1000, length=3)
try:
    mod.grow(buf, 3, 1, 1, 1, lambda c, p, n, f: (1, 0xAA, 0xBB))
except mod.AllocFailure as exc:
    assert (exc.word1, exc.word2) == (0xAA, 0xBB)
else:
    raise AssertionError("allocator error did not raise")
assert (buf.capacity, buf.data_ptr) == (3, 0x1000)

print("ALL CHECKS PASSED")
