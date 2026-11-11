#!/usr/bin/env python3
"""Packet checker for RE-001-object-destructor-5b3a0-115.

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
     tests/test_object_destructor_5b3a0_115.py

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
PACKET = ROOT / "research/work-items/RE-001-object-destructor-5b3a0-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "main.txt": (0x5D5B3A0, 0x5D5B4B7),
}
EXPECTED_SITES = {
    0x5D5B3A0: [(0x5d8489f, "call")],
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
    print(f"excerpt lines verified byte-for-byte: {total}")
    # 5. FDE lines present in fresh readelf output; every site window
    # holds its call to the routine; callers.tsv lists the same sites
    frames = subprocess.run(["readelf", "--debug-dump=frames", str(BIN)],
                            capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line not in frames:
            fail(f"FDE line missing from readelf output: {line}")
    site_text = (PACKET / "caller_sites.txt").read_text()
    for target, sites in EXPECTED_SITES.items():
        for va, _kind in sites:
            if f"{va:x}:" not in site_text or f"{target:x}" not in site_text:
                fail(f"caller_sites.txt missing window for 0x{va:x}")
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
    for ln in relocs.splitlines():
        f = ln.split()
        if len(f) >= 3 and f[2] == "R_X86_64_RELATIVE":
            try:
                if int(f[-1], 16) in EXPECTED_SITES:
                    fail("RELATIVE relocation targets the routine")
            except ValueError:
                pass
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
    from tools.object_destructor_5b3a0_115 import Holder, destruct
    empty = destruct(Holder(sub_buf_begin=0x1088), inline_base=0x1000)
    if [t[0] for t in empty] != ["memset", "zero", "zero",
                                 "free_buffer", "call"]:
        fail("model spot check failed: empty holder buffer phase")
    full = destruct(Holder(member_160="m", member_110=True, nodes=["n"],
                           buf_begin=0x5000, buf_count=3, member_d0="d",
                           member_c0="c", member_b0="b",
                           sub_buf_begin=0x9000, sub_buf_count=2),
                    inline_base=0x1000)
    if [t[0] for t in full] != ["release", "call", "free_node", "memset",
                                "zero", "zero", "free_buffer", "release",
                                "release", "release", "call",
                                "free_buffer_tail"]:
        fail("model spot check failed: full holder phase order")
    if full[-1] != ("free_buffer_tail", 0x63F0D80, 0x9000, 16):
        fail("model spot check failed: sub-buffer tail free")
    inline = destruct(Holder(buf_begin=0x1108, buf_count=1,
                             sub_buf_begin=0x1088), inline_base=0x1000)
    if any(t[0] == "free_buffer" for t in inline):
        fail("model spot check failed: inline main buffer freed")
    spec_t = importlib.util.spec_from_file_location(
        "test_object_destructor_5b3a0_115",
        ROOT / "tests/test_object_destructor_5b3a0_115.py")
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
