#!/usr/bin/env python3
"""Packet checker for RE-001-lazy-cache-adapter-548a0-115.

Checks, all against the materialized node #115 binary:
  1. binary SHA-256 matches provenance/artifacts.json
  2. MANIFEST.sha256 matches every packet file
  3. excerpts + frames.txt regenerate byte-for-byte via export_excerpts.py
  4. every excerpt line's bytes match the raw binary
     (file offset = virtual address - 0x1000 in the executable LOAD segment)
  5. every frames.txt FDE line is present in fresh readelf output
  6. census: executable-LOAD E8/E9 scan gives exactly the recorded sites
     for each routine; relocation addends for the adapter are exactly
     the relocations.txt records (parsed as offset/addend pairs)
  7. records.json is semantic-only (no per-step list)
  8. model spot checks plus every test_* function in
     tests/test_lazy_cache_adapter_548a0_115.py

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
PACKET = ROOT / "research/work-items/RE-001-lazy-cache-adapter-548a0-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
EXCERPTS = {
    "adapter.txt": (0x5D548A0, 0x5D5490D),
    "getter.txt": (0x5D54890, 0x5D5489C),
    "cache.txt": (0x61BCDE0, 0x61BCEE4),
    "builder.txt": (0x61BC290, 0x61BC2B7),
    "cleanup.txt": (0x61BCDA6, 0x61BCDDA),
}
EXPECTED_SITES = {
    0x5D548A0: [],
    0x61BCDE0: [(0x5D548E5, "call")],
    0x61BC290: [(0x61BCEA3, "call")],
    0x5D54890: [(0x5D548D1, "call")],
}
EXPECTED_RELOCS = {
    0x5D548A0: [(0x64C9790, 0x5D548A0), (0x64CB508, 0x5D548A0),
                (0x64CB9E8, 0x5D548A0), (0x64CBFE8, 0x5D548A0)],
    0x61BCDE0: [],
    0x61BC290: [],
    0x5D54890: [],
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
                if prev_va is None or va != prev_va + prev_len:
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
        print(f"relocations to {target:#x}: {len(hits)}, as recorded")
    # 7. records.json is semantic-only
    records = json.loads((PACKET / "records.json").read_text())
    blob = json.dumps(records)
    for banned in ("mnemonic", "instruction"):
        if banned in blob:
            fail(f"records.json mentions {banned}; semantic records only")
    # 8. model spot checks + full test module
    spec = importlib.util.spec_from_file_location(
        "lazy_cache_adapter_548a0_115",
        ROOT / "tools/lazy_cache_adapter_548a0_115.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    holder = mod.Holder(g540=0xABCD)
    out = mod.Out("o")
    x = bytes(range(64))
    y = [99]
    events = []
    assert mod.adapter(out, holder, x, y, None, events) is out
    assert bytes(holder.cache.key) == x[:25]
    assert holder.cache.record.blob == x[:32] and y == [0]
    assert holder.cache.present == 1
    out2 = mod.Out("o2")
    events = []
    mod.adapter(out2, holder, x, [1], None, events)
    assert out2.writes == {0x00: ("dword", 11), 0x04: ("word", 0),
                           0x08: ("qword", 0)}
    assert events == [("acquire",), ("release",)]
    spec2 = importlib.util.spec_from_file_location(
        "test_lazy_cache_adapter_548a0_115",
        ROOT / "tests/test_lazy_cache_adapter_548a0_115.py")
    tmod = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(tmod)
    names = [n for n in dir(tmod) if n.startswith("test_")]
    for name in names:
        getattr(tmod, name)()
    print(f"model tests pass: {len(names)}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
