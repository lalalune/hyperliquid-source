#!/usr/bin/env python3
"""Packet checker for RE-001-drain-and-flush-52e60-115.

Checks, all against the materialized node #115 binary:
  1. binary SHA-256 matches provenance/artifacts.json
  2. MANIFEST.sha256 matches every packet file
  3. excerpts + frames.txt regenerate byte-for-byte via export_excerpts.py
  4. every excerpt line's bytes match the raw binary
     (file offset = virtual address - 0x1000 in the executable LOAD segment)
  5. every frames.txt FDE line is present in fresh readelf output
  6. census: executable-LOAD E8/E9 scan gives exactly the recorded sites
     for the routine; relocation addends are exactly the
     relocations.txt records (none here)
  7. records.json is semantic-only (no per-item list)
  8. model spot checks plus every test_* function in
     tests/test_drain_and_flush_52e60_115.py

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
PACKET = ROOT / "research/work-items/RE-001-drain-and-flush-52e60-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "main.txt": (0x5D52E60, 0x5D532CA),
    "caller.txt": (0x5DD6060, 0x5DD6097),
}
EXPECTED_SITES = {
    0x5D52E60: [(0x5dd6092, "jmp")],
}
EXPECTED_RELOCS = {
    0x5D52E60: [],
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
    # 4. every excerpt line byte-for-byte vs raw binary, including
    # objdump continuation lines
    line_re = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\t")
    cont_re = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*$")
    total = 0
    for name, (start, end) in EXCERPTS.items():
        prev_va = prev_len = None
        for line in (PACKET / name).read_text().splitlines():
            m = line_re.match(line)
            if m:
                va = int(m.group(1), 16)
                if prev_va is not None and va != prev_va + prev_len:
                    fail(f"{name}: line at 0x{va:x} does not follow previous")
                raw = bytes.fromhex(m.group(2).replace(" ", ""))
                if not (start <= va < end):
                    fail(f"{name}: line address 0x{va:x} outside range")
                if data[va - 0x1000: va - 0x1000 + len(raw)] != raw:
                    fail(f"{name}: bytes mismatch at 0x{va:x}")
                prev_va, prev_len = va, len(raw)
                total += 1
            else:
                m = cont_re.match(line)
                if not m:
                    continue
                va = int(m.group(1), 16)
                if prev_va is None or va != prev_len + prev_va:
                    fail(f"{name}: continuation line at 0x{va:x} "
                         f"does not follow previous bytes")
                raw = bytes.fromhex(m.group(2).replace(" ", ""))
                if not (start <= va < end):
                    fail(f"{name}: line address 0x{va:x} outside range")
                if data[va - 0x1000: va - 0x1000 + len(raw)] != raw:
                    fail(f"{name}: bytes mismatch at 0x{va:x}")
                prev_va, prev_len = va, len(raw)
                total += 1
    print(f"excerpt lines verified byte-for-byte: {total}")
    # 5. FDE lines present in fresh readelf output
    frames = subprocess.run(["readelf", "--debug-dump=frames", str(BIN)],
                            capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line not in frames:
            fail(f"FDE line missing from readelf output: {line}")
    # 6. census + relocations (fast E8/E9 position scan, objdump-confirmed)
    for target, expected in EXPECTED_SITES.items():
        cands = []
        for off, base, size in EXEC:
            seg = data[off:off + size]
            for op in (0xE8, 0xE9):
                i = seg.find(bytes([op]))
                while i != -1:
                    if i + 5 <= len(seg):
                        rel = struct.unpack_from("<i", seg, i + 1)[0]
                        if base + i + 5 + rel == target:
                            cands.append((base + i, op))
                    i = seg.find(bytes([op]), i + 1)
        confirmed = []
        for va, op in cands:
            out = subprocess.run(
                ["objdump", "-d", f"--start-address={va:#x}",
                 f"--stop-address={va + 6:#x}", str(BIN)],
                capture_output=True, text=True).stdout
            for line in out.splitlines():
                if (f"{va:x}:" in line and f"{target:x}" in line
                        and ("call" in line or "jmp" in line)):
                    confirmed.append((va, "call" if op == 0xE8 else "jmp"))
        if confirmed != expected:
            fail(f"census mismatch for {target:#x}: {confirmed} != {expected}")
        print(f"census for {target:#x}: {len(confirmed)} sites, as recorded")
    relocs = subprocess.run(["readelf", "-r", str(BIN)],
                            capture_output=True, text=True).stdout
    for target, expected in EXPECTED_RELOCS.items():
        hits = []
        for ln in relocs.splitlines():
            f = ln.split()
            if len(f) >= 4 and f[-1] == f"{target:x}":
                try:
                    hits.append((int(f[0], 16), int(f[-1], 16)))
                except ValueError:
                    pass
        if hits != expected:
            fail(f"relocation mismatch for {target:#x}: {hits}")
        print(f"relocations for {target:#x}: {len(hits)}, as recorded")
    # 7. records.json is semantic-only
    records = json.loads((PACKET / "records.json").read_text())
    blob = json.dumps(records)
    for banned in ("mnemonic", "instruction", "opcode"):
        if banned in blob:
            fail(f"records.json contains banned token: {banned}")
    if records["routine"]["address"] != "0x5d52e60":
        fail("records.json routine address mismatch")
    if records["consumers"]["direct_calls"] != 0:
        fail("records.json caller count mismatch")
    if records["consumers"]["tail_jumps"] != 1:
        fail("records.json tail-jump count mismatch")
    # 8. model spot checks + every test_* function
    spec = importlib.util.spec_from_file_location(
        "drain_and_flush_model", ROOT / "tools/drain_and_flush_52e60_115.py")
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    recs = {"r1": {"next": "r2", "key": 12, "str_a": ("a1", None),
                    "str_b": ("b1", None), "f50": 1, "f58": 2, "f60": 3},
            "r2": {"next": None, "key": 22, "str_a": ("a2", None),
                    "str_b": ("b2", None), "f50": 4, "f58": 5, "f60": 6}}
    ops, state = model.flush([["e1"]], [], recs, {2: model.HEAD}, 10,
                             "r1", 2, 5)
    assert state["head"] is None and state["count"] == 0
    assert state["tail_counter"] == 4
    assert [op for op in ops if op[0] == "emit"] == [
        ("emit", 0x5E4B7C0, 3, "a1", "b1", 1, 2),
        ("emit", 0x5E4B7C0, 6, "a2", "b2", 4, 5)]
    spec = importlib.util.spec_from_file_location(
        "drain_and_flush_tests",
        ROOT / "tests/test_drain_and_flush_52e60_115.py")
    tests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests)
    names = [n for n in dir(tests) if n.startswith("test_")]
    for name in names:
        getattr(tests, name)()
    print(f"model tests passed: {len(names)}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
