#!/usr/bin/env python3
"""Packet checker for RE-001-nested-array-teardown-58f10-115.

Checks, all against the materialized node #115 binary:
  1. binary SHA-256 matches provenance/artifacts.json
  2. MANIFEST.sha256 matches every packet file
  3. excerpts + caller site windows + frames.txt regenerate
     byte-for-byte via export_excerpts.py
  4. every main.txt line's bytes match the raw binary
     (file offset = virtual address - 0x1000 in the executable LOAD segment)
  5. every frames.txt FDE line is present in fresh readelf output, and
     every site window holds its call to the routine
  6. census: executable-LOAD E8/E9 scan gives exactly the recorded sites
     for the routine; no RELATIVE relocation targets the routine;
     no stored qwords
  7. records.json is semantic-only (no per-instruction token list)
  8. model spot checks plus every test_* function in
     tests/test_nested_array_teardown_58f10_115.py

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
PACKET = ROOT / "research/work-items/RE-001-nested-array-teardown-58f10-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "main.txt": (0x5D58F10, 0x5D58FAB),
}
EXPECTED_SITES = {
    0x5D58F10: [(0x5d60e40, "call"), (0x5d60f28, "call"),
                (0x5d616f9, "call"), (0x5d78a28, "call"),
                (0x5d79991, "call"), (0x5e7039a, "call"),
                (0x5e7c9b7, "call"), (0x5e9dd5f, "call"),
                (0x5ecc4e8, "call"), (0x5f1969f, "call")],
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
    # 3. excerpt + site windows + frames regeneration byte-for-byte
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(PACKET / "export_excerpts.py"), tmp],
                       check=True, cwd=ROOT, capture_output=True)
        for name in list(EXCERPTS) + ["caller_sites.txt", "frames.txt"]:
            if (Path(tmp) / name).read_bytes() != (PACKET / name).read_bytes():
                fail(f"regenerated {name} differs from packet copy")
    # 4. every main.txt line byte-for-byte vs raw binary, including
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
    # 5. FDE lines present in fresh readelf output; every site window
    # holds its call to the routine
    frames = subprocess.run(["readelf", "--debug-dump=frames", str(BIN)],
                            capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line not in frames:
            fail(f"FDE line missing from readelf output: {line}")
    site_text = (PACKET / "caller_sites.txt").read_text()
    for va, _kind in EXPECTED_SITES[0x5D58F10]:
        if f"{va:x}:" not in site_text or "5d58f10" not in site_text:
            fail(f"caller_sites.txt missing window for 0x{va:x}")
    # 6. census + relocations + stored qwords
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
        if data.count(struct.pack("<Q", target)) != 0:
            fail("stored qword references found")
    relocs = subprocess.run(["readelf", "-r", str(BIN)],
                            capture_output=True, text=True).stdout
    for ln in relocs.splitlines():
        f = ln.split()
        if len(f) >= 3 and f[2] == "R_X86_64_RELATIVE":
            try:
                if int(f[-1], 16) == 0x5D58F10:
                    fail("RELATIVE relocation targets the routine")
            except ValueError:
                pass
    # 7. records.json is semantic-only
    records_text = (PACKET / "records.json").read_text()
    for banned in ("mnemonic", "instructions"):
        if banned in records_text:
            fail(f"records.json contains banned token: {banned}")
    records = json.loads(records_text)
    if records["artifact_digest"] != DIGEST:
        fail("records.json digest mismatch")
    if records["consumers"]["direct_calls"] != 10:
        fail("records.json consumer count mismatch")
    # 8. model spot checks + test functions
    spec = importlib.util.spec_from_file_location(
        "nested_array_teardown_58f10_115",
        ROOT / "tools/nested_array_teardown_58f10_115.py")
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    ops = model.nested_array_teardown(
        {"elements": [{"string_alloc": True, "capacity": 5}, None],
         "begin_nonnull": True, "buffer_bytes": 16})
    if ops[:2] != [("free_string", 6), ("free_element", 0x20)]:
        fail(f"model spot check failed at array phase: {ops}")
    if ops[-2:] != [("free_buffer", 16), ("free_inner", 0x18)]:
        fail(f"model spot check failed at exit: {ops}")
    if model.nested_array_teardown(None) != []:
        fail("model spot check failed at null inner")
    spec_t = importlib.util.spec_from_file_location(
        "test_nested_array_teardown_58f10_115",
        ROOT / "tests/test_nested_array_teardown_58f10_115.py")
    tests = importlib.util.module_from_spec(spec_t)
    spec_t.loader.exec_module(tests)
    passed = 0
    for name in dir(tests):
        if name.startswith("test_"):
            getattr(tests, name)()
            passed += 1
    print(f"model tests passed: {passed}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
