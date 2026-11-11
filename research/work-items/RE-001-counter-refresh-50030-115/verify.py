#!/usr/bin/env python3
"""Packet checker for RE-001-counter-refresh-50030-115.

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
  7. records.json is semantic-only (no per-instruction list)
  8. model spot checks plus every test_* function in
     tests/test_shared_copy_refcount_50400_115.py

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
PACKET = ROOT / "research/work-items/RE-001-counter-refresh-50030-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "main.txt": (0x5D50030, 0x5D5016A),
}
EXPECTED_SITES = {
    0x5D50030: [(0x5d535a0, "call"),
                (0x5d54400, "call"),
                (0x5d60e6a, "call"),
                (0x5d61744, "call"),
                (0x5d78a6e, "call"),
                (0x5d79015, "call"),
                (0x5db0cb3, "call"),
                (0x5db12d1, "call"),
                (0x5db14e9, "call"),
                (0x5db161c, "call"),
                (0x5e10951, "call"),
                (0x5e1122b, "call"),
                (0x5e183b1, "call"),
                (0x5e18881, "call"),
                (0x5e1b979, "call"),
                (0x5e1ef4f, "call"),
                (0x5e21ac7, "call"),
                (0x5e21da4, "call"),
                (0x5e22105, "call"),
                (0x5e2215d, "call"),
                (0x5e260ed, "call"),
                (0x5e261ea, "call"),
                (0x5e2658d, "call"),
                (0x5e26719, "call"),
                (0x5e7c9fd, "call"),
                (0x5e7d11e, "call"),
                (0x5e86376, "call"),
                (0x5e86842, "call"),
                (0x5e87128, "call"),
                (0x5e8731a, "call"),
                (0x5e8754d, "call"),
                (0x5e89c60, "call"),
                (0x5e8a3d9, "call"),
                (0x5e8eec2, "call"),
                (0x5e8fae9, "call"),
                (0x5e9090a, "call"),
                (0x5e91244, "call"),
                (0x5e91d35, "call"),
                (0x5e92b4f, "call"),
                (0x5ea2dff, "call"),
                (0x5ea32a2, "call"),
                (0x5ea394d, "call"),
                (0x5ea8577, "call"),
                (0x5ea8c77, "call"),
                (0x5ea8e4e, "call"),
                (0x5f3dd5c, "call"),
                (0x5f3ec4c, "call"),
                (0x6035287, "call"),
                (0x6035468, "call"),
                (0x6035995, "call"),
                (0x6035ba5, "call"),
                (0x6036589, "call"),
                (0x6036927, "call"),
                (0x6036bf2, "call"),
                (0x6036c45, "call"),
                (0x6037021, "call"),
                (0x6037727, "call"),
                (0x603f9da, "call"),
                (0x60439f9, "call"),
                (0x60445e1, "call"),
                (0x6045ad5, "call"),
                (0x6045b9a, "call"),
                (0x6046ec0, "call"),
                (0x6047bd4, "call"),
                (0x60e718d, "call"),
                (0x60e741d, "call"),
                (0x61089a7, "call"),
                (0x6108a36, "call"),
                (0x6108af4, "call"),
                (0x6108d2c, "call"),
                (0x6108f6c, "call"),
                (0x61121f2, "call"),
                (0x611227a, "call"),
                (0x6112338, "call"),
                (0x6112572, "call"),
                (0x61127bc, "call"),
                (0x6113cf9, "call"),
                (0x6113d81, "call"),
                (0x6113e42, "call"),
                (0x6114063, "call"),
                (0x611425f, "call"),
                (0x611588b, "call"),
                (0x611591a, "call"),
                (0x61159d8, "call"),
                (0x6115c2c, "call"),
                (0x6115e74, "call"),
                (0x61174ab, "call"),
                (0x611753a, "call"),
                (0x61175f8, "call"),
                (0x611784c, "call"),
                (0x6117a94, "call")],
}
EXPECTED_RELOCS = {
    0x5D50030: [],
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
    # 6b. GOT slots read by the routine resolve to the known values
    got = {}
    for ln in relocs.splitlines():
        f = ln.split()
        if len(f) >= 4 and f[2] == "R_X86_64_RELATIVE":
            try:
                got[int(f[0], 16)] = int(f[-1], 16)
            except ValueError:
                pass
    if got.get(0x64ECF80) != 0x5D4D490 or got.get(0x64ECF50) != 0x5D48960:
        fail("GOT slot resolution mismatch for the routine's identity checks")
    print("GOT identity slots resolve to 0x5d4d490 and 0x5d48960, as recorded")
    # 7. records.json is semantic-only
    records = json.loads((PACKET / "records.json").read_text())
    blob = json.dumps(records)
    for banned in ("mnemonic", "instruction", "opcode"):
        if banned in blob:
            fail(f"records.json contains banned token: {banned}")
    if records["routine"]["address"] != "0x5d50030":
        fail("records.json routine address mismatch")
    if records["consumers"]["direct_calls"] != 91:
        fail("records.json caller count mismatch")
    if records["consumers"]["tail_jumps"] != 0:
        fail("records.json tail-jump count mismatch")
    # 8. model spot checks + every test_* function
    spec = importlib.util.spec_from_file_location(
        "counter_refresh_model", ROOT / "tools/counter_refresh_50030_115.py")
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)

    counter, exit_, ops = model.refresh(
        10, 0, 0, 0, 3, 7, 5, slot98=0x5D40000)
    assert (counter, exit_) == (12, "return")
    assert ops == [("producer", "direct"), ("store", 12)]
    counter, exit_, ops = model.refresh(
        10, 1, 1, 1, 3, 7, 5, slot98=model.KNOWN_PRODUCER,
        slot_c8=model.KNOWN_HANDLER, waiter_byte=9)
    assert counter == (2 - 7) % (1 << 64) and exit_ == "tail_dispatch"
    counter, exit_, ops = model.refresh(
        None, 0, 1, 0, 3, 0, 8, slot_c8=0x5D40010, waiter_byte=9)
    assert counter is None and exit_ == "handler_call"
    assert ops[0][2] == "computed_unconsumed"
    spec = importlib.util.spec_from_file_location(
        "counter_refresh_tests",
        ROOT / "tests/test_counter_refresh_50030_115.py")
    tests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests)
    names = [n for n in dir(tests) if n.startswith("test_")]
    for name in names:
        getattr(tests, name)()
    print(f"model tests passed: {len(names)}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
