#!/usr/bin/env python3
"""Packet checker for RE-001-derived-destructor-55970-115.

Checks, all against the materialized node #115 binary:
  1. binary SHA-256 matches provenance/artifacts.json
  2. MANIFEST.sha256 matches every packet file
  3. excerpts + frames.txt regenerate byte-for-byte via export_excerpts.py
  4. every excerpt instruction line's bytes match the raw binary
     (file offset = virtual address - 0x1000 in the executable LOAD segment)
  5. every frames.txt FDE line is present in fresh readelf output
  6. census: executable-LOAD E8/E9 scan gives exactly the recorded sites
     for all three routines; relocation addends for the three routines
     are exactly the relocations.txt records
  7. records.json is semantic-only (no per-instruction mnemonic list)
  8. model spot checks (import the tools/ model and exercise the behavior)
     plus every test_* function in tests/test_derived_destructor_55970_115.py

Run from the repository root: python3 <packet>/verify.py
Prints ALL CHECKS PASSED or exits non-zero naming the failed check.
"""
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path.cwd()
PACKET = ROOT / "research/work-items/RE-001-derived-destructor-55970-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "complete.txt": (0x5D55970, 0x5D559B9),
    "deleting.txt": (0x5D559C0, 0x5D55A16),
    "base.txt": (0x5FE70B0, 0x5FE7135),
}
EXPECTED_SITES = {
    0x5D55970: [],
    0x5D559C0: [],
    0x5FE70B0: [(0x5D559B4, "jmp"), (0x5D55A03, "call"),
                (0x5D55A84, "jmp"), (0x5D5629B, "call"),
                (0x5E01C58, "call"), (0x5F74E3C, "call"),
                (0x5FB180E, "jmp"), (0x5FB183D, "jmp"),
                (0x5FB18C8, "call"), (0x5FE71E5, "call"),
                (0x5FE734E, "jmp"), (0x5FE737D, "jmp"),
                (0x5FE7408, "call"), (0x5FEEC96, "jmp"),
                (0x5FEECC5, "jmp"), (0x5FEED70, "call"),
                (0x5FF3040, "jmp"), (0x5FF308F, "call"),
                (0x5FFBFFE, "jmp"), (0x5FFC022, "call"),
                (0x5FFC052, "jmp"), (0x5FFC39B, "call"),
                (0x6028A3B, "call"), (0x6028CE5, "jmp"),
                (0x61EDBCE, "jmp"), (0x61EDBFD, "jmp"),
                (0x61EDC88, "call"), (0x61F040E, "jmp"),
                (0x61F043D, "jmp"), (0x61F04C8, "call")],
}
EXPECTED_RELOCS = {
    0x5D55970: [0x64D08A8, 0x64ED3F0],
    0x5D559C0: [0x64D08B0],
    0x5FE70B0: [],
}


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main():
    data = BIN.read_bytes()
    # 1. digest + provenance binding
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    prov = json.loads((ROOT / "provenance/artifacts.json").read_text())
    digests = [f["sha256"] for f in prov["files"]]
    if DIGEST not in digests:
        fail("digest not present in provenance/artifacts.json")
    # 2. manifest
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    seen = {}
    for line in manifest:
        digest, name = line.split("  ")
        seen[name] = digest
    actual = {p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256"}
    if set(seen) != actual:
        fail(f"manifest file set mismatch: {sorted(set(seen) ^ actual)}")
    for name, digest in seen.items():
        if hashlib.sha256((PACKET / name).read_bytes()).hexdigest() != digest:
            fail(f"manifest hash mismatch for {name}")
    # 3. excerpt + frames regeneration byte-for-byte
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(PACKET / "export_excerpts.py"), tmp],
                       check=True, cwd=ROOT, capture_output=True)
        for name in list(EXCERPTS) + ["frames.txt"]:
            if (Path(tmp) / name).read_bytes() != (PACKET / name).read_bytes():
                fail(f"regenerated {name} differs from packet copy")
    # 4. every excerpt instruction line byte-for-byte vs raw binary
    line_re = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\t")
    total = 0
    for name, (start, end) in EXCERPTS.items():
        for line in (PACKET / name).read_text().splitlines():
            m = line_re.match(line)
            if not m:
                continue
            va = int(m.group(1), 16)
            raw = bytes.fromhex(m.group(2).replace(" ", ""))
            if not (start <= va < end):
                fail(f"{name}: line address 0x{va:x} outside range")
            if data[va - 0x1000: va - 0x1000 + len(raw)] != raw:
                fail(f"{name}: bytes mismatch at 0x{va:x}")
            total += 1
    print(f"excerpt instruction lines verified byte-for-byte: {total}")
    # 5. FDE lines present in fresh readelf output
    frames = subprocess.run(["readelf", "--debug-dump=frames", str(BIN)],
                            capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line not in frames:
            fail(f"FDE line missing from readelf output: {line}")
    # 6. census
    found = {t: [] for t in EXPECTED_SITES}
    for off, base, size in EXEC:
        seg = data[off:off + size]
        for i in range(len(seg) - 5):
            op = seg[i]
            if op in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", seg, i + 1)[0]
                tgt = base + i + 5 + rel
                if tgt in found:
                    found[tgt].append((base + i, op))
    for target, sites in EXPECTED_SITES.items():
        confirmed = []
        for va, op in found[target]:
            out = subprocess.run(
                ["objdump", "-d", f"--start-address={va:#x}",
                 f"--stop-address={va + 6:#x}", str(BIN)],
                capture_output=True, text=True).stdout
            for line in out.splitlines():
                if (f"{va:x}:" in line and f"{target:x}" in line
                        and ((op == 0xE8 and "call" in line)
                             or (op == 0xE9 and "jmp" in line))):
                    confirmed.append((va, "call" if op == 0xE8 else "jmp"))
        if confirmed != sites:
            fail(f"census mismatch for 0x{target:x}: {confirmed}")
    relocs = subprocess.run(["readelf", "-r", str(BIN)],
                            capture_output=True, text=True).stdout
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if line not in relocs:
            fail(f"relocation line missing from readelf output: {line}")
    stored = {t: [] for t in EXPECTED_RELOCS}
    for line in relocs.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "R_X86_64_RELATIVE":
            try:
                addend = int(parts[-1], 16)
            except ValueError:
                continue
            if addend in stored:
                stored[addend].append(int(parts[0], 16))
    if stored != EXPECTED_RELOCS:
        fail(f"relocation census mismatch: {stored}")
    # 7. records.json semantic-only
    records = json.loads((PACKET / "records.json").read_text())
    blob = json.dumps(records)
    for banned in ('"instructions"', '"mnemonic"', '"operands"'):
        if banned in blob:
            fail(f"records.json contains banned key {banned}")
    # 8. model spot checks + full test module
    spec = importlib.util.spec_from_file_location(
        "dtor_model", ROOT / "tools/derived_destructor_55970_115.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    r38 = mod.Ref("r38", strong=1)
    r28 = mod.Ref("r28", strong=2)
    obj = mod.deleting_destroy(
        mod.Obj((True, [(True, 20), (False, 0)], 80), ptr28=r28, ptr38=r38))
    assert obj.frees == [("destroy", "r38"), ("elem", 0, 21),
                         ("buffer", 80), ("self", 0x48)], obj.frees
    assert not r28.destroyed and r28.packed == 1
    assert obj.vptr == mod.BASE_VPTR
    tspec = importlib.util.spec_from_file_location(
        "dtor_tests", ROOT / "tests/test_derived_destructor_55970_115.py")
    tmod = importlib.util.module_from_spec(tspec)
    tspec.loader.exec_module(tmod)
    tests = [getattr(tmod, n) for n in dir(tmod) if n.startswith("test_")]
    for fn in tests:
        fn()
    print(f"model tests passed: {len(tests)}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
