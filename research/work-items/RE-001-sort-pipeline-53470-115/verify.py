#!/usr/bin/env python3
"""Packet checker for RE-001-sort-pipeline-53470-115.

Checks, all against the materialized node #115 binary:
  1. binary SHA-256 matches provenance/artifacts.json
  2. MANIFEST.sha256 matches every packet file
  3. excerpts + call-site windows + frames.txt regenerate
     byte-for-byte via export_excerpts.py
  4. every excerpt line's bytes match the raw binary
     (file offset = virtual address - 0x1000 in the executable LOAD segment)
  5. every frames.txt FDE line is present in fresh readelf output,
     each site window holds its call to the sort entry, and
     callers.tsv lists every recorded site
  6. census: executable-LOAD E8/E9 scan gives exactly the recorded
     sites for all seven routines, confirmed with objdump; no
     RELATIVE relocation targets any pinned routine; no stored
     qwords; exactly one RELATIVE record at 0x64ecfb0 with addend
     0x5d48410 (the comparator-identity global)
  7. records.json is semantic-only (no per-instruction token list)
     and its consumer counts match the census
  8. model spot checks plus every test_* function in
     tests/test_sort_pipeline_53470_115.py

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
PACKET = ROOT / "research/work-items/RE-001-sort-pipeline-53470-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "main.txt": (0x5D53470, 0x5D53577),
    "introsort.txt": (0x5D4C1C0, 0x5D4C8CF),
    "heap.txt": (0x5D4BCE0, 0x5D4C15A),
    "predicate.txt": (0x5D4A830, 0x5D4A90F),
    "swap.txt": (0x5D496D0, 0x5D49739),
    "insert_pass.txt": (0x5D4BA10, 0x5D4BCD7),
    "insert_step.txt": (0x5D4B3F0, 0x5D4B5C0),
    "site-5d6e48e.txt": (0x5D6E460, 0x5D6E4A0),
    "site-5d6f51c.txt": (0x5D6F4F2, 0x5D6F530),
}
SITE_FILES = {
    0x5D6E48E: "site-5d6e48e.txt",
    0x5D6F51C: "site-5d6f51c.txt",
}
EXPECTED_SITES = {
    0x5D53470: [(0x5D6E48E, "call"), (0x5D6F51C, "call")],
    0x5D4C1C0: [(0x5D4C682, "call"), (0x5D534F2, "call")],
    0x5D4BCE0: [(0x5D4C71D, "call"), (0x5D4C890, "call")],
    0x5D4A830: [(0x5D4C26D, "call"), (0x5D4C28A, "call"),
               (0x5D4C756, "call"), (0x5D4C776, "call"),
               (0x5D4C7AE, "call")],
    0x5D496D0: [(0x5D4C2A7, "call"), (0x5D4C791, "call"),
               (0x5D4C7C9, "call"), (0x5D4C80A, "call")],
    0x5D4BA10: [(0x5D53524, "call"), (0x5D53568, "call")],
    0x5D4B3F0: [(0x5D4BB2C, "call"), (0x5D53541, "call")],
}
EXPECTED_GLOBAL = 0x64ECFB0
EXPECTED_ADDEND = 0x5D48410


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
        for name in (list(EXCERPTS) + ["frames.txt"]):
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
    # 5. FDE lines present in fresh readelf output; site windows hold
    # their calls to the sort entry; callers.tsv lists every site
    frames = subprocess.run(["readelf", "--debug-dump=frames", str(BIN)],
                            capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line not in frames:
            fail(f"FDE line missing from readelf output: {line}")
    for va, name in SITE_FILES.items():
        site_text = (PACKET / name).read_text()
        if f"{va:x}:" not in site_text or "5d53470" not in site_text:
            fail(f"{name} missing window for 0x{va:x}")
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
        if sorted(confirmed) != sorted(expected):
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
                fail("RELATIVE relocation targets a pinned routine")
            if addr == EXPECTED_GLOBAL:
                global_hits.append(addend)
    if global_hits != [EXPECTED_ADDEND]:
        fail(f"comparator-identity global relocation mismatch: {global_hits}")
    print("comparator-identity global relocation: 0x64ecfb0 -> 0x5d48410, as recorded")
    # 7. records.json is semantic-only; consumer counts match census
    records_text = (PACKET / "records.json").read_text()
    for banned in ("mnemonic", "instructions"):
        if banned in records_text:
            fail(f"records.json contains banned token: {banned}")
    records = json.loads(records_text)
    if records["routine"]["binary_sha256"] != DIGEST:
        fail("records.json digest mismatch")
    for target, expected in EXPECTED_SITES.items():
        entry = records["consumers"][f"{target:#x}"]
        if entry["direct_calls"] != len(expected):
            fail(f"records.json consumer count mismatch for {target:#x}")
        if entry["tail_jumps"] != 0 or entry["stored_qwords"] != 0:
            fail(f"records.json consumer census mismatch for {target:#x}")
        if sorted(int(s, 16) for s in entry["sites"]) != sorted(
                va for va, _ in expected):
            fail(f"records.json site list mismatch for {target:#x}")
    # 8. model spot checks + test functions
    sys.path.insert(0, str(ROOT))
    from tools.sort_pipeline_53470_115 import (
        SsoList, depth_limit, less_than, sort_entry, swap_elements)
    if depth_limit(16) != 8 or depth_limit(1000) != 18:
        fail("model spot check failed: depth limit")
    if less_than((1, 0), (2, 0), lambda e: e[0],
                 lambda a, b: (a[1] > b[1]) - (a[1] < b[1])) != 1:
        fail("model spot check failed: predicate less")
    if less_than((1, 1), (1, 0), lambda e: e[0],
                 lambda a, b: (a[1] > b[1]) - (a[1] < b[1])) != 0:
        fail("model spot check failed: predicate tie-break")
    c = SsoList([(3, 0), (1, 1), (2, 2)])
    if not sort_entry(c, False, lambda e: e[0],
                      lambda a, b: (a[1] > b[1]) - (a[1] < b[1])):
        fail("model spot check failed: sort did not run")
    if c.data != [(1, 1), (2, 2), (3, 0)]:
        fail("model spot check failed: small sort order")
    c = SsoList([(3, 0), (1, 1), (2, 2)])
    swap_elements(c, 0, 2)
    if c.data != [(2, 2), (1, 1), (3, 0)]:
        fail("model spot check failed: swap")
    spec_t = importlib.util.spec_from_file_location(
        "test_sort_pipeline_53470_115",
        ROOT / "tests/test_sort_pipeline_53470_115.py")
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
