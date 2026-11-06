#!/usr/bin/env python3
"""Packet checker for RE-001-three-release-55830-115.

Checks, all against the materialized node #115 binary:
  1. binary SHA-256 matches provenance/artifacts.json
  2. MANIFEST.sha256 matches every packet file
  3. excerpts + frames.txt regenerate byte-for-byte via export_excerpts.py
  4. every excerpt instruction line's bytes match the raw binary
     (file offset = virtual address - 0x1000 in the executable LOAD segment)
  5. every frames.txt FDE line is present in fresh readelf output
  6. census: executable-LOAD E8/E9 scan gives exactly the recorded sites
     for the routine; relocation addends for the routine are exactly
     the relocations.txt records (none)
  7. records.json is semantic-only (no per-instruction list)
  8. model spot checks plus every test_* function in
     tests/test_three_release_55830_115.py

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
PACKET = ROOT / "research/work-items/RE-001-three-release-55830-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "main.txt": (0x5D55830, 0x5D5586A),
    "helper_low.txt": (0x5D350C0, 0x5D35145),
    "helper_high.txt": (0x5D35070, 0x5D350BC),
}
EXPECTED_SITES = {
    0x5D55830: [(0x5D5F3B0, "call"), (0x5D7774A, "call"),
                (0x5D8169E, "call"), (0x5D81FC7, "call"),
                (0x5D84978, "call"), (0x5D84C63, "call"),
                (0x5D880E0, "call"), (0x5FB1CB3, "call")],
}
EXPECTED_RELOCS = {
    0x5D55830: [],
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
    # 6. census + relocations
    for target, expected in EXPECTED_SITES.items():
        cands = []
        for off, base, size in EXEC:
            seg = data[off:off + size]
            for i in range(len(seg) - 5):
                op = seg[i]
                if op in (0xE8, 0xE9):
                    rel = struct.unpack_from("<i", seg, i + 1)[0]
                    if base + i + 5 + rel == target:
                        cands.append((base + i, op))
        confirmed = []
        for va, op in cands:
            out = subprocess.run(
                ["objdump", "-d", f"--start-address={va:#x}",
                 f"--stop-address={va + 6:#x}", str(BIN)],
                capture_output=True, text=True).stdout
            for line in out.splitlines():
                if (f"{va:x}:" in line and f"{target:x}" in line
                        and ((op == 0xE8 and "call" in line)
                             or (op == 0xE9 and "jmp" in line))):
                    confirmed.append((va, "call" if op == 0xE8 else "jmp"))
        if confirmed != expected:
            fail(f"census mismatch for 0x{target:x}: {confirmed}")
    relocs = subprocess.run(["readelf", "-r", str(BIN)],
                            capture_output=True, text=True).stdout
    stored = []
    for line in relocs.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "R_X86_64_RELATIVE":
            try:
                if int(parts[-1], 16) == 0x5D55830:
                    stored.append(int(parts[0], 16))
            except ValueError:
                pass
    if stored != EXPECTED_RELOCS[0x5D55830]:
        fail(f"relocation census mismatch: {stored}")
    # 7. records.json is semantic-only
    records = json.loads((PACKET / "records.json").read_text())
    blob = json.dumps(records)
    for banned in ("mnemonic", "instruction"):
        if banned in blob:
            fail(f"records.json contains banned token: {banned}")
    for key in ("task", "target", "artifact", "artifact_sha256", "routine",
                "helper_low", "helper_high", "phases", "callers",
                "observations", "unknowns"):
        if key not in records:
            fail(f"records.json missing key {key}")
    # 8. model spot checks + every test_* in the tests file
    spec = importlib.util.spec_from_file_location(
        "three_release_model", ROOT / "tools/three_release_55830_115.py")
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    holder = {f: None for f in ("+0x28", "+0x18", "+0x08")}
    assert model.teardown(holder) == []
    ref = model.RefCounted("s", 1, 1)
    holder["+0x18"] = ref
    assert model.teardown(holder) == [("destructor", "s"), ("deleter", "s")]
    assert holder["+0x18"] is ref
    tspec = importlib.util.spec_from_file_location(
        "three_release_tests",
        ROOT / "tests/test_three_release_55830_115.py")
    tmod = importlib.util.module_from_spec(tspec)
    tspec.loader.exec_module(tmod)
    tests = [n for n in dir(tmod) if n.startswith("test_")]
    for name in tests:
        getattr(tmod, name)()
    print(f"model tests passed: {len(tests)}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
