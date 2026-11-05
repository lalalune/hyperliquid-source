#!/usr/bin/env python3
"""Packet checker for RE-001-chain-dispatch-notifier-1bca30-115.

Checks, all against the materialized node #115 binary:
  1. binary SHA-256 matches provenance/artifacts.json
  2. MANIFEST.sha256 matches every packet file
  3. excerpts + call-site window + frames.txt regenerate
     byte-for-byte via export_excerpts.py
  4. every excerpt line's bytes match the raw binary
     (file offset = virtual address - 0x1000 in the executable LOAD segment)
  5. every frames.txt FDE line is present in fresh readelf output,
     the site window holds the call to the routine, and callers.tsv
     lists the same site
  6. census: executable-LOAD E8/E9 scan gives exactly the recorded
     site for the routine; no RELATIVE relocation targets the
     routine; no stored qwords; exactly one RELATIVE record at
     0x64ecf80 with addend 0x5d4d490 (the expected-slot walker)
  7. records.json is semantic-only (no per-instruction token list)
  8. model spot checks plus every test_* function in
     tests/test_chain_dispatch_notifier_1bca30_115.py

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
PACKET = ROOT / "research/work-items/RE-001-chain-dispatch-notifier-1bca30-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "main.txt": (0x61BCA30, 0x61BCD5A),
    "walker.txt": (0x5D4D490, 0x5D4D552),
    "varint.txt": (0x61BD410, 0x61BD4E9),
    "framer.txt": (0x61B1260, 0x61B13A3),
    "landing.txt": (0x61BC9F6, 0x61BCA28),
    "caller.txt": (0x61BCDE0, 0x61BCEE4),
}
SITE_FILES = {
    0x61BCEBD: "site-61bcebd.txt",
}
EXPECTED_SITES = {
    0x61BCA30: [(0x61bcebd, "call")],
}
EXPECTED_GLOBAL = 0x64ECF80
EXPECTED_WALKER = 0x5D4D490


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
    # 3. excerpt + site window + frames regeneration byte-for-byte
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(PACKET / "export_excerpts.py"), tmp],
                       check=True, cwd=ROOT, capture_output=True)
        for name in (list(EXCERPTS) + list(SITE_FILES.values())
                     + ["frames.txt"]):
            if (Path(tmp) / name).read_bytes() != (PACKET / name).read_bytes():
                fail(f"regenerated {name} differs from packet copy")
    # 4. every excerpt line byte-for-byte vs raw binary,
    # including objdump continuation lines
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
    print(f"excerpt lines verified byte-for-byte: {total}")
    # 5. FDE lines present in fresh readelf output; site window holds
    # its call to the routine; callers.tsv lists the same site
    frames = subprocess.run(["readelf", "--debug-dump=frames", str(BIN)],
                            capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line not in frames:
            fail(f"FDE line missing from readelf output: {line}")
    for target, sites in EXPECTED_SITES.items():
        for va, _kind in sites:
            site_text = (PACKET / SITE_FILES[va]).read_text()
            if f"{va:x}:" not in site_text or f"{target:x}" not in site_text:
                fail(f"{SITE_FILES[va]} missing window for 0x{va:x}")
    tsv = (PACKET / "callers.tsv").read_text()
    for sites in EXPECTED_SITES.values():
        for va, _kind in sites:
            if f"{va:#x}" not in tsv:
                fail(f"callers.tsv missing site 0x{va:x}")
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
    global_hits = []
    for ln in relocs.splitlines():
        f = ln.split()
        if len(f) >= 3 and f[2] == "R_X86_64_RELATIVE":
            try:
                addr = int(f[0], 16)
                addend = int(f[-1], 16)
            except ValueError:
                continue
            if addend in EXPECTED_SITES:
                fail("RELATIVE relocation targets the routine")
            if addr == EXPECTED_GLOBAL:
                global_hits.append(addend)
    if global_hits != [EXPECTED_WALKER]:
        fail(f"expected-slot global relocation mismatch: {global_hits}")
    print("expected-slot global relocation: 0x64ecf80 -> 0x5d4d490, as recorded")
    # 7. records.json is semantic-only
    records_text = (PACKET / "records.json").read_text()
    for banned in ("mnemonic", "instructions"):
        if banned in records_text:
            fail(f"records.json contains banned token: {banned}")
    records = json.loads(records_text)
    if records["routine"]["binary_sha256"] != DIGEST:
        fail("records.json digest mismatch")
    if records["consumers"]["direct_calls"] != 1:
        fail("records.json consumer count mismatch")
    if len(records["consumers"]["sites"]) != 1:
        fail("records.json site list mismatch")
    # 8. model spot checks + test functions
    sys.path.insert(0, str(ROOT))
    from tools.chain_dispatch_notifier_1bca30_115 import (
        EXPECTED_SLOT, build_frame, build_message, uleb128_encode,
        walk_chain, walk_expected)
    if walk_chain([EXPECTED_SLOT] * 5) != 4:
        fail("model spot check failed: homogeneous walk")
    if walk_chain([0x61B1260] + [EXPECTED_SLOT] * 4) != 0:
        fail("model spot check failed: head mismatch walk")
    if walk_expected([EXPECTED_SLOT] * 9) != 8:
        fail("model spot check failed: homogeneous walker")
    if uleb128_encode(0x80) != b"\x80\x01":
        fail("model spot check failed: varint 0x80")
    if uleb128_encode(0xFFFFFFFF) != b"\xff\xff\xff\xff\x0f":
        fail("model spot check failed: varint 0xffffffff")
    if build_message(b"AB") != b"\x02AB\x08\x00\x00\x00\x01\x00\x00\x00":
        fail("model spot check failed: message bytes")
    frame = build_frame(0x1122334455667788, 1, build_message(b"AB"))
    if frame[:9] != (0x1122334455667788).to_bytes(8, "little") + b"\x01":
        fail("model spot check failed: frame head")
    spec_t = importlib.util.spec_from_file_location(
        "test_chain_dispatch_notifier_1bca30_115",
        ROOT / "tests/test_chain_dispatch_notifier_1bca30_115.py")
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
