#!/usr/bin/env python3
"""Packet checker for RE-001-map-at-lookup-520d0-115.

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
     tests/test_map_at_lookup_520d0_115.py

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
PACKET = ROOT / "research/work-items/RE-001-map-at-lookup-520d0-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "main.txt": (0x5D520D0, 0x5D52331),
}
EXPECTED_SITES = {
    0x5D520D0: [(0x5e63dc8, "call"), (0x5e7a228, "call")],
}
EXPECTED_RELOCS = {
    0x5D520D0: [],
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
            fail(f"relocation mismatch for {target:#x}: {hits} != {expected}")
        print(f"relocations for {target:#x}: {len(hits)}, as recorded")
    # 7. records.json is semantic-only
    records = json.loads((PACKET / "records.json").read_text())
    blob = json.dumps(records)
    for banned in ("mnemonic", "instruction", "opcode"):
        if banned in blob:
            fail(f"records.json contains banned token: {banned}")
    if records["routine"]["address"] != "0x5d520d0":
        fail("records.json routine address mismatch")
    if records["consumers"]["direct_calls"] != 2:
        fail("records.json caller count mismatch")
    if records["consumers"]["tail_jumps"] != 0:
        fail("records.json tail-jump count mismatch")
    # 8. model spot checks + every test_* function
    spec = importlib.util.spec_from_file_location(
        "lookup_model", ROOT / "tools/map_at_lookup_520d0_115.py")
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)

    def never(_tag, _field):
        raise AssertionError("must not be called")

    def never_assign(_out, _temp):
        raise AssertionError("must not be called")

    def never_delete(_pointer):
        raise AssertionError("must not be called")

    head = model.Node(kind=2, field=0x55)
    out, events = model.map_at_lookup(
        0, 0, head,
        lambda tag, field: model.Temp(0, 0x11111111, 0x2222, 0x33333333),
        never_assign, never_delete)
    assert (out.dword, out.word, out.qword) == (0x11111111, 0x2222, 0x33333333)
    assert out.gap is None
    assert events == [("build", 2, 0x55)], events
    try:
        model.map_at_lookup(0, 0, None, never, never_assign, never_delete)
    except model.OutOfRangeError as exc:
        assert str(exc) == "map::at"
    else:
        fail("null head must throw")
    spec = importlib.util.spec_from_file_location(
        "lookup_tests", ROOT / "tests/test_map_at_lookup_520d0_115.py")
    tests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests)
    names = [n for n in dir(tests) if n.startswith("test_")]
    for name in names:
        getattr(tests, name)()
    print(f"model tests passed: {len(names)}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
