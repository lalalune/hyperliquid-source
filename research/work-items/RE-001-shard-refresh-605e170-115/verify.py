#!/usr/bin/env python3
"""Verify the RE-001 shard refresh routine 0x605e170 packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt regenerates byte-for-byte from a fresh objdump run.
 4. Every excerpt instruction's bytes match the raw binary at
    the file offset (virtual address minus 0x1000).
 5. frames.txt equals the readelf frames-interp FDE lines for
    the routine and its two callees.
 6. The census is reproduced: exactly 2 direct calls and 0 tail
    jumps with the exact site list from callers.tsv, and no
    qword hit or RELATIVE slot for the routine address.
 7. The routine's FDE carries no LSDA (CIE augmentation "zR",
    FDE augmentation data length 0) and the FDE pc range is the
    window.
 8. records.json holds semantic records only (digest and window
    agree with this checker).
 9. Model spot checks (Park-Miller orbit and fixed points, mask
    wrap at 32, TLS bit width, fallback selection).
10. The model test file passes under plain python3.
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
MAIN_START, MAIN_END = 0x605E170, 0x605E20D
FDE_OFFSET = 0x3677D0
EH_FRAME_OFF = 0xCA6ED8


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


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

# 3. Excerpt regeneration (header normalized to the bare binary
# name, matching export_excerpts.py).
fresh = subprocess.run(
    ["objdump", "-d", f"--start-address={hex(MAIN_START)}",
     f"--stop-address={hex(MAIN_END)}", str(BIN)],
    capture_output=True, text=True, check=True).stdout
fresh = fresh.replace(str(BIN), BIN.name)
if fresh != (HERE / "main.txt").read_text():
    fail("main.txt does not regenerate byte-for-byte")

# 4. Instruction bytes vs raw binary.
checked = 0
for line in (HERE / "main.txt").read_text().splitlines():
    m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t|$)", line)
    if not m:
        continue
    va = int(m.group(1), 16)
    want_bytes = bytes.fromhex(m.group(2).replace(" ", ""))
    got = data[va - 0x1000:va - 0x1000 + len(want_bytes)]
    if got != want_bytes:
        fail(f"instruction bytes mismatch at {va:#x}")
    checked += 1
if checked < 40:
    fail(f"too few instructions checked: {checked}")

# 5. frames.txt vs fresh readelf.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True, check=True).stdout
want_frames = []
for line in frames.splitlines():
    m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
    if m and "FDE cie=" in line and int(m.group(1), 16) in (
            0x605E170, 0x60D5CD0, 0x61C4080):
        want_frames.append(line)
if "\n".join(want_frames) + "\n" != (HERE / "frames.txt").read_text():
    fail("frames.txt does not match readelf output")

# 6. Census reproduction.
spec = importlib.util.spec_from_file_location(
    "census", HERE / "census.py")
census = importlib.util.module_from_spec(spec)
spec.loader.exec_module(census)
ranges = census.fde_ranges()
sites = census.confirmed(census.scan(census.TARGET), ranges)
tsv = (HERE / "callers.tsv").read_text().splitlines()[1:]
want_sites = []
for row in tsv:
    site, kind, lo, hi = row.split("\t")
    want_sites.append((int(site, 16), kind,
                       (int(lo, 16), int(hi, 16))))
if sites != want_sites:
    fail(f"census mismatch: {sites} vs {want_sites}")
hits, slots = census.qword_and_slots(census.TARGET)
if hits or slots:
    fail("unexpected qword hit or RELATIVE slot for the routine")

# 7. FDE / LSDA parse.
p = EH_FRAME_OFF + FDE_OFFSET
length, cie_ptr = struct.unpack_from("<II", data, p)
if length != 0x2C:
    fail(f"FDE length {length:#x} != 0x2c")
cie_off = (FDE_OFFSET + 4) - cie_ptr
cie_len = struct.unpack_from("<I", data, EH_FRAME_OFF + cie_off)[0]
cie = data[EH_FRAME_OFF + cie_off:EH_FRAME_OFF + cie_off + cie_len]
z = cie.index(b"z")
aug = cie[z:cie.index(b"\x00", z)]
if aug != b"zR":
    fail(f"CIE augmentation {aug!r} != b'zR'")
field_va = EH_FRAME_OFF + FDE_OFFSET + 8  # sdata4 pcrel ('R' = 0x1b)
pc_begin = field_va + struct.unpack_from("<i", data, p + 8)[0]
pc_range = struct.unpack_from("<I", data, p + 12)[0]
if (pc_begin, pc_begin + pc_range) != (MAIN_START, MAIN_END):
    fail(f"FDE pc range {pc_begin:#x}..{pc_begin + pc_range:#x}")
if data[p + 16] != 0:
    fail("FDE augmentation data is not empty (unexpected LSDA)")

# 8. records.json consistency.
records = json.loads((HERE / "records.json").read_text())
if records["target"]["sha256"] != want:
    fail("records digest mismatch")
if records["routines"] != [{"end": "0x605e20d", "name": "main",
                             "start": "0x605e170"}]:
    fail("records window mismatch")
if records["census"]["main"]["direct_calls"] != ["0x5f11931",
                                                  "0x5f11cf7"]:
    fail("records census mismatch")

# 9. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "model", ROOT / "tools/shard_refresh_605e170_115.py")
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)
if model.park_miller_step(1) != 16807:
    fail("model: Park-Miller first step")
if model.park_miller_step(16807) != 282475249:
    fail("model: Park-Miller second step")
if model.park_miller_step(0x7FFFFFFF) != 0x7FFFFFFF:
    fail("model: modulus fixed point")
if model.park_miller_step(0) != 0:
    fail("model: zero fixed point")
if model.index_mask(32) != 0 or model.index_mask(33) != 1:
    fail("model: mask wrap")
entry, tls, seed = model.refresh(0x20000000, 32, 200, 1)
if (entry, tls, seed) != (0x20000000, 1 << 32, 1):
    fail("model: shift-32 split widths")
entry, tls, seed = model.refresh(0x20000000, 8, -1, 1)
if (entry, tls, seed) != (0x20000000 + (16807 & 0xFF) * 64,
                          (16807 & 0xFF) + (1 << 8), 16807):
    fail("model: fallback selection")

# 10. Model test file.
out = subprocess.run(
    [sys.executable, "-m", "unittest", "discover", "-s",
     str(ROOT / "tests"), "-p", "test_shard_refresh_605e170_115.py"],
    capture_output=True, text=True, cwd=ROOT)
if out.returncode != 0 or "OK" not in out.stderr:
    fail("model tests failed:\n" + out.stderr[-2000:])

print("ALL CHECKS PASSED")
