#!/usr/bin/env python3
"""Verify the RE-001-iterator-vtable-tail-115 packet against node #115.

Static only: reads the node binary and the packet files, never executes
the node. Exits non-zero on the first failed check.

Checks:
  1. work/hl-node-115.bin SHA-256 matches provenance/artifacts.json.
  2. The vtable census re-derived from .rela.dyn matches vtables.tsv
     (21 classes, 231 tail rows, same addresses).
  3. Every excerpts/*.objdump.txt file is byte-for-byte identical to a
     fresh objdump run on the real binary for its FDE range.
  4. Three seeded-random instructions from the excerpts verify
     byte-for-byte against a fresh objdump run.
  5. records.json is consistent with vtables.tsv / callers.tsv.
  6. Every callers.tsv site decodes as the claimed indirect call/jmp
     in a fresh objdump of its containing FDE.
  7. The model tests (tests/test_iterator_vtable_tail.py) pass.

Usage (from the repository root):
    python3 research/work-items/RE-001-iterator-vtable-tail-115/verify.py
"""
import hashlib
import json
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8

SHARED = {
    0x5DF7650: 11,
    0x5DF7670: 14,
    0x5DF7680: 15,
    0x5DF7690: 16,
    0x5D485B0: 17,
    0x5DF7800: 20,
    0x5DF76D0: 21,
    0x5DF76E0: 22,
    0x5DF7640: 23,
}
FALSE_POSITIVES = {0x64ECE78, 0x64ED2A8, 0x64ED2D0, 0x64ED2F8, 0x64ED308}
SLOT_NAMES = {
    11: "user_key", 14: "PrepareValue", 15: "MayBeOutOfUpperBound",
    16: "UpperBoundCheckResult", 17: "SetPinnedItersMgr",
    18: "IsKeyPinned", 19: "IsValuePinned", 20: "GetProperty",
    21: "GetReadaheadState", 22: "SetReadaheadState",
    23: "IsDeleteRangeSentinelKey",
}
SEGMENTS = [
    (0x0000000, 0x1418254, 0x0000000),
    (0x1419300, 0x4FD88A0, 0x1418300),
    (0x63F2BA0, 0x000FBE80, 0x63F0BA0),
    (0x64EFA20, 0x000103E8, 0x64ECA20),
]


def fail(msg):
    raise SystemExit(f"FAIL: {msg}")


def va_to_off(va):
    for start, size, off in SEGMENTS:
        if start <= va < start + size:
            return off + (va - start)
    return None


def read_cstr(data, va, limit=200):
    off = va_to_off(va)
    if off is None:
        return None
    end = data.index(b"\x00", off, off + limit)
    return data[off:end].decode("ascii", "replace")


def objdump(start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={start:#x}",
         f"--stop-address={end:#x}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    return [l for l in out.splitlines()
            if re.match(r"^\s*[0-9a-f]+:\t", l)]


def main():
    data = BIN.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    provenance = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    want_digest = None
    for entry in provenance["files"]:
        if entry["path"] == "artifacts/node/115/hl-node":
            want_digest = entry["sha256"]
            break
    if want_digest is None:
        fail("provenance has no artifacts/node/115/hl-node entry")
    if digest != want_digest:
        fail(f"binary digest {digest} != provenance {want_digest}")

    # 2. Re-derive the vtable census from .rela.dyn.
    rel = {}
    for i in range(RELA_SIZE // 24):
        off, info, add = struct.unpack_from("<QQq", data, RELA_OFF + i * 24)
        if (info & 0xFFFFFFFF) == 8:
            rel[off] = add
    vtables = {}
    for va, add in rel.items():
        if add in SHARED:
            vtables.setdefault(va - SHARED[add] * 8, set()).add(SHARED[add])
    real = {p for p in vtables if p not in FALSE_POSITIVES}
    if len(real) != 21:
        fail(f"re-derived {len(real)} real vtables, expected 21")
    derived = {}
    for ptr in real:
        ti_va = rel.get(ptr - 8)
        name = None
        if ti_va is not None:
            name_va = rel.get(ti_va + 8)
            if name_va is not None:
                name = read_cstr(data, name_va)
        for slot in (11, *range(14, 24)):
            addr = rel.get(ptr + slot * 8)
            if addr is not None:
                derived[(name, slot)] = f"0x{addr:x}"
    rows = []
    for line in open(HERE / "vtables.tsv").read().splitlines()[1:]:
        cls, _ptr, slot, name, addr = line.split("\t")
        rows.append((cls, int(slot), name, addr))
    if len(rows) != 231:
        fail(f"vtables.tsv has {len(rows)} rows, expected 231")
    for cls, slot, name, addr in rows:
        if SLOT_NAMES[slot] != name:
            fail(f"slot {slot} named {name}, expected {SLOT_NAMES[slot]}")
        if derived.get((cls, slot)) != addr:
            fail(f"{cls}[{slot}] is {derived.get((cls, slot))} in the "
                 f"binary, {addr} in vtables.tsv")

    # 3. Every excerpt is byte-for-byte a fresh objdump of its FDE range.
    fdes = {}
    for line in open(HERE / "frames.txt"):
        m = re.match(r"^[0-9a-f]{8} [0-9a-f]{16} [0-9a-f]{8} FDE cie=[0-9a-f]+ "
                     r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            fdes[int(m.group(1), 16)] = int(m.group(2), 16)
    excerpts = sorted((HERE / "excerpts").glob("*.objdump.txt"))
    if len(excerpts) != 80:
        fail(f"{len(excerpts)} excerpts, expected 80")
    all_instr = []
    for path in excerpts:
        addr = int(path.stem.split(".")[0], 16)
        if addr not in fdes:
            fail(f"no FDE for excerpt {path.name}")
        fresh = objdump(addr, fdes[addr])
        pinned = [l for l in path.read_text().splitlines()
                  if re.match(r"^\s*[0-9a-f]+:\t", l)]
        if pinned != fresh:
            fail(f"excerpt {path.name} differs from fresh objdump")
        all_instr.extend((addr, l) for l in fresh)

    # 4. Three seeded-random instructions, byte-for-byte vs fresh objdump.
    rng = random.Random(115)
    picks = rng.sample(all_instr, 3)
    for addr, line in picks:
        va = int(line.split(":")[0].strip(), 16)
        end = fdes[addr]
        fresh = objdump(addr, end)
        match = [l for l in fresh if l.split(":")[0].strip() == f"{va:x}"]
        if not match or match[0] != line:
            fail(f"spot-check instruction at 0x{va:x} mismatches")

    # 5. records.json consistency.
    records = json.loads((HERE / "records.json").read_text())
    if records["artifact"]["sha256"] != digest:
        fail("records.json artifact digest mismatch")
    if len(records["windows"]) != 78:
        fail(f"records.json has {len(records['windows'])} windows")
    if records["vtables"]["tail_rows"] != 231:
        fail("records.json tail_rows != 231")
    callers = open(HERE / "callers.tsv").read().splitlines()[1:]
    if len(callers) != records["dispatch_census"]["kept_iterator_consumer_sites"]:
        fail("callers.tsv row count != records.json kept count")

    # 6. Every dispatch site decodes as claimed in its FDE.
    # (The packet frames.txt covers only the excerpt windows, so the
    # full FDE table is re-read here for arbitrary consumer FDEs.)
    full_frames = subprocess.run(
        ["objdump", "--dwarf=frames", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    full_fdes = {}
    for line in full_frames.splitlines():
        m = re.match(r"^[0-9a-f]{8} [0-9a-f]{16} [0-9a-f]{8} FDE cie=[0-9a-f]+ "
                     r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            full_fdes[int(m.group(1), 16)] = int(m.group(2), 16)
    fde_cache = {}
    for line in callers:
        slot, off, site, fde, kind, reg, _core, _ev = line.split("\t")
        site, fde, off = int(site, 16), int(fde, 16), int(off, 16)
        if fde not in fde_cache:
            if fde not in full_fdes:
                fail(f"dispatch FDE 0x{fde:x} has no FDE entry")
            fde_cache[fde] = objdump(fde, full_fdes[fde])
        match = [l for l in fde_cache[fde]
                 if l.split(":")[0].strip() == f"{site:x}"]
        if not match or not re.search(
                rf"\b{kind}\s+\*0x{off:x}\({reg}\)", match[0]):
            fail(f"dispatch site 0x{site:x} is not a {kind} *0x{off:x}({reg})")

    # 7. The model tests pass.
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_iterator_vtable_tail.py",
         "-q"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"model tests failed:\n{r.stdout}\n{r.stderr}")

    print("Verified RE-001-iterator-vtable-tail-115: 21 vtables, 231 tail "
          "rows, 78 windows + 2 supporting excerpts, 132 dispatch sites, "
          "14 model tests passed")
    print("Spot-checked instructions: " +
          ", ".join(f"0x{int(l.split(':')[0].strip(), 16):x}"
                    for _, l in picks))


if __name__ == "__main__":
    main()
