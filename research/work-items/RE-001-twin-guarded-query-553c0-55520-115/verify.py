#!/usr/bin/env python3
"""Packet checker for RE-001-twin-guarded-query-553c0-55520-115.

Checks, all against the materialized node #115 binary:
  1. binary SHA-256 matches provenance/artifacts.json
  2. MANIFEST.sha256 matches every packet file
  3. excerpts + frames.txt regenerate byte-for-byte via export_excerpts.py
  4. every excerpt instruction line's bytes match the raw binary
     (file offset = virtual address - 0x1000 in the executable LOAD segment)
  5. every frames.txt FDE line is present in fresh readelf output
  6. census: executable-LOAD E8/E9 scan gives exactly the recorded sites;
     no stored qwords in data segments; no relocation mentions either address
  7. records.json is semantic-only (no per-instruction mnemonic list)
  8. model spot checks (import the tools/ model and exercise the behavior)

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
PACKET = ROOT / "research/work-items/RE-001-twin-guarded-query-553c0-55520-115"
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXEC = [(0x1418300, 0x1419300, 0x4FD88A0)]
DATA = [(0x63F0BA0, 0x63F2BA0, 0x0FBE80), (0x64ECA20, 0x64EFA20, 0x0103E8)]
EXCERPTS = {
    "twin_a.txt": (0x5D553C0, 0x5D554E4),
    "twin_b.txt": (0x5D55520, 0x5D55644),
    "cleanup_a.txt": (0x5D5538E, 0x5D553C0),
    "cleanup_b.txt": (0x5D554E4, 0x5D55516),
}
EXPECTED_SITES = {0x5D553C0: [(0x5EA300A, "call")],
                  0x5D55520: [(0x5EA877A, "call")]}
EXPECTED_FDES = ["0000000005d553c0..0000000005d554e4",
                 "0000000005d55520..0000000005d55644",
                 "0000000005d5538e..0000000005d553c0",
                 "0000000005d554e4..0000000005d55516",
                 "0000000005ea2e40..0000000005ea3c83",
                 "0000000005ea85b0..0000000005ea93f1"]


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
                       check=True, cwd=ROOT)
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
    for fde in EXPECTED_FDES:
        if fde not in frames:
            fail(f"FDE {fde} missing from readelf output")
    if (PACKET / "frames.txt").read_text().count("FDE") != len(EXPECTED_FDES):
        fail("frames.txt line count mismatch")
    # 6. census
    found = {t: [] for t in EXPECTED_SITES}
    for off, base, size in EXEC:
        seg = data[off:off + size]
        for i in range(len(seg) - 5):
            op = seg[i]
            if op in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", seg, i + 1)[0]
                tgt = base + i + 5 + rel
                if tgt in found:
                    found[tgt].append((base + i, op))
    for target, sites in EXPECTED_SITES.items():
        confirmed = []
        for va, op in found[target]:
            out = subprocess.run(
                ["objdump", "-d", f"--start-address={va:#x}",
                 f"--stop-address={va + 6:#x}", str(BIN)],
                capture_output=True, text=True).stdout
            for line in out.splitlines():
                if (f"{va:x}:" in line and f"{target:x}" in line
                        and ((op == 0xE8 and "call" in line)
                             or (op == 0xE9 and "jmp" in line))):
                    confirmed.append((va, "call" if op == 0xE8 else "jmp"))
        if confirmed != sites:
            fail(f"census mismatch for 0x{target:x}: {confirmed}")
        q = struct.pack("<Q", target)
        for off, base, size in DATA:
            if q in data[off:off + size]:
                fail(f"stored qword found for 0x{target:x}")
    relocs = subprocess.run(["readelf", "-r", str(BIN)],
                            capture_output=True, text=True).stdout
    for target in EXPECTED_SITES:
        if f"{target:x}" in relocs:
            fail(f"relocation mentions 0x{target:x}")
    if (PACKET / "relocations.txt").read_text() != "":
        fail("relocations.txt is not empty")
    # 7. records.json semantic-only
    records = json.loads((PACKET / "records.json").read_text())
    blob = json.dumps(records)
    for banned in ('"instructions"', '"mnemonic"', '"operands"'):
        if banned in blob:
            fail(f"records.json contains banned key {banned}")
    # 8. model spot checks
    spec = importlib.util.spec_from_file_location(
        "twin_model", ROOT / "tools/twin_guarded_query_553c0_55520_115.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    holder = mod.Holder(flag="flag-obj")
    out = mod.Triple(code=7, tag=3, ptr="stale")
    inner = lambda flag, ks, ca, k16, p16: mod.Triple(code=11, tag=5, ptr="new-ptr")
    result = mod.guarded_query(holder, out, inner, "ks", "ca", "k16", "p16")
    assert result is out and (out.code, out.tag, out.ptr) == (11, 5, "new-ptr"), "move failed"
    assert holder.ops == ["acquire", "inner", "release"], holder.ops
    assert holder.freed == [], holder.freed  # twin's conditional free never fires
    zero = mod.Triple(code=9, tag=9, ptr="p")
    mod.guarded_query(mod.Holder(flag=None), zero, inner, "ks", "ca", "k16", "p16")
    assert (zero.code, zero.tag, zero.ptr) == (0, 0, None), "flag-zero path failed"
    probe_holder = mod.Holder(flag="f")
    probe_out = mod.Triple()
    assert mod.probe_call(probe_holder, probe_out, inner, "ks", "ca", "k16", "p16") == "new-ptr"
    assert probe_holder.freed == ["new-ptr"], probe_holder.freed
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
