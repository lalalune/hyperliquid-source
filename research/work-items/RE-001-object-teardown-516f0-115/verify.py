#!/usr/bin/env python3
"""Packet checker for RE-001-object-teardown-516f0-115.

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
     tests/test_object_teardown_516f0_115.py

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
PACKET = ROOT / "research/work-items/RE-001-object-teardown-516f0-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "main.txt": (0x5D516F0, 0x5D519C5),
}
EXPECTED_SITES = {
    0x5D516F0: [(0x5d5f391, "call"), (0x5d5f596, "call"), (0x5d5f7d6, "call"), (0x5d5f9fc, "call"), (0x5d68d23, "call"), (0x5d6976b, "call"), (0x5d69939, "call"), (0x5d6a39f, "call"), (0x5d6a706, "call"), (0x5d6a98b, "call"), (0x5d6ad53, "call"), (0x5d6b20f, "call"), (0x5d6b527, "call"), (0x5d6b778, "call"), (0x5d72eb4, "call"), (0x5d738d6, "call"), (0x5d77653, "call"), (0x5d7772a, "call"), (0x5d77d18, "call"), (0x5d77eef, "call"), (0x5d7f2c6, "call"), (0x5d7f805, "call"), (0x5d816ee, "call"), (0x5d81db0, "call"), (0x5d81fa8, "call"), (0x5da8672, "call"), (0x5ddc16c, "call"), (0x5ddc647, "call"), (0x5de3332, "call"), (0x5de3a92, "call"), (0x5de43c5, "call"), (0x5de5179, "call"), (0x5decaf0, "call"), (0x5deddeb, "call"), (0x5e45ba7, "call"), (0x5e51d6b, "call"), (0x5e51f9b, "call"), (0x5e52942, "call"), (0x5e53549, "call"), (0x5e5df55, "call"), (0x5e5eb1d, "call"), (0x5e68cf3, "call"), (0x5e68d12, "call"), (0x5e68f80, "call"), (0x5e68f9c, "call"), (0x5e68fa8, "call"), (0x5e6963f, "call"), (0x5e69658, "call"), (0x5e69664, "call"), (0x5e69afa, "call"), (0x5e6b663, "call"), (0x5e6ba65, "call"), (0x5e6d9e6, "call"), (0x5e8a857, "call"), (0x5e8bca3, "call"), (0x5e8bfed, "call"), (0x5e8ef2b, "call"), (0x5e8f9e2, "call"), (0x5e91de2, "call"), (0x5e938f7, "call"), (0x5ee9475, "call"), (0x5f10390, "call"), (0x5f14e25, "call"), (0x5f1691f, "call"), (0x5f6eafa, "call"), (0x5f72b59, "call"), (0x5f72d7a, "call"), (0x5f7a4fc, "call"), (0x5f89d8b, "call"), (0x5f89dc2, "call"), (0x5f89dda, "call"), (0x5f89e59, "call"), (0x5f8a40c, "call"), (0x5f8aaa4, "call"), (0x5f8ab7d, "call"), (0x5f8b2ef, "call"), (0x5f8b802, "call"), (0x5f8b84d, "call"), (0x5f957f6, "call"), (0x5f970f7, "call"), (0x5f9da87, "call"), (0x5f9e548, "call"), (0x5f9e730, "call"), (0x5fa0e29, "call"), (0x5fa1679, "call"), (0x5fa3af1, "call"), (0x5fa4550, "call")],
}
EXPECTED_RELOCS = {
    0x5D516F0: [],
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
    if records["routine"]["address"] != "0x5d516f0":
        fail("records.json routine address mismatch")
    if records["consumers"]["direct_calls"] != 87:
        fail("records.json caller count mismatch")
    if records["consumers"]["tail_jumps"] != 0:
        fail("records.json tail-jump count mismatch")
    # 8. model spot checks + every test_* function
    spec = importlib.util.spec_from_file_location(
        "teardown_model", ROOT / "tools/object_teardown_516f0_115.py")
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)

    obj = model.empty_obj()
    assert model.object_teardown(obj) == []
    obj = model.empty_obj()
    obj["str_160"] = model.String(0x1000, 15, True)
    obj["buf_110"] = (0x2000, 0x2040)
    obj["list_a8"] = model.Node(0x3000, "arg", None)
    assert model.object_teardown(obj) == [
        ("delete", 0x1000, 16),
        ("delete", 0x2000, 0x40),
        ("teardown_call", "arg"),
        ("delete", 0x3000, 0x30),
    ]
    spec = importlib.util.spec_from_file_location(
        "teardown_tests", ROOT / "tests/test_object_teardown_516f0_115.py")
    tests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests)
    names = [n for n in dir(tests) if n.startswith("test_")]
    for name in names:
        getattr(tests, name)()
    print(f"model tests passed: {len(names)}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
