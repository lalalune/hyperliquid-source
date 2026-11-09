#!/usr/bin/env python3
"""Verify this packet against the target binary (node #115).

Run from the repo root:
    python3 research/work-items/RE-001-map-serializer-7630-115/verify.py
Checks: artifact digest, manifest, excerpt regeneration, FDE ranges,
raw-binary spot bytes, literals, the caller census, semantic-only
records, and the model tests. Exits non-zero on any failure.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
EXPECTED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))


def va_to_off(va):
    return va - TEXT_VA + TEXT_OFF


def read_bytes(va, n):
    data = BIN.read_bytes()
    off = va_to_off(va)
    return data[off:off + n]


def main() -> int:
    data = BIN.read_bytes()

    # 1. Artifact digest.
    check("artifact digest",
          hashlib.sha256(data).hexdigest() == EXPECTED_SHA256)

    # 2. Manifest: every packet file listed, hashes match.
    manifest = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        manifest[name.strip()] = digest
    files = sorted(p.name for p in HERE.iterdir() if p.is_file())
    check("manifest lists every packet file",
          set(manifest) == set(files) - {"MANIFEST.sha256"} or
          set(manifest) == set(files),
          f"manifest={sorted(manifest)} files={files}")
    ok = True
    for name, digest in manifest.items():
        p = HERE / name
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            ok = False
    check("manifest hashes match", ok)

    # 3. Excerpts byte-identical to fresh objdump.
    for name, (start, stop) in {
        "fn-6097630.objdump.txt": (0x6097630, 0x60984E8),
        "fn-6098510.objdump.txt": (0x6098510, 0x60985AF),
        "fn-60985e0.objdump.txt": (0x60985E0, 0x609865E),
    }.items():
        fresh = subprocess.check_output(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", "artifacts/node/115/hl-node"],
            cwd=ROOT, text=True).replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
        check(f"excerpt {name} regenerates byte-identical",
              fresh == (HERE / name).read_text())

    # 4. FDE ranges from readelf.
    frames = subprocess.check_output(
        ["objdump", "--dwarf=frames", "artifacts/node/115/hl-node"],
        cwd=ROOT, text=True).replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
    for start, stop in [(0x6097630, 0x60984E8), (0x6098510, 0x60985AF),
                        (0x60985E0, 0x609865E), (0x609E510, 0x609F073)]:
        check(f"FDE {start:#x}..{stop:#x}",
              f"pc={start:016x}..{stop:016x}" in frames.replace("000000000", "")
              or f"pc=000000000{start:x}..000000000{stop:x}" in frames)

    # 5. Raw-binary spot bytes for the pinned sites.
    spots = {
        0x6097630: bytes.fromhex("f30f1efa"),          # endbr64
        0x6097690: bytes.fromhex("488344240830"),      # addq $0x30, 0x8(%rsp)
        0x60976AB: bytes.fromhex("488b4028"),          # mov 0x28(%rax), %rax
        0x60976B4: bytes.fromhex("488b5810"),          # mov 0x10(%rax), %rbx
        0x609771E: bytes.fromhex("488b1b"),            # mov (%rbx), %rbx
        0x609772A: bytes.fromhex("8b83d4000000"),      # mov 0xd4(%rbx), %eax
        0x6097730: bytes.fromhex("83e804"),            # sub $0x4, %eax
        0x6097733: bytes.fromhex("83f801"),            # cmp $0x1, %eax
        0x6097736: bytes.fromhex("76e6"),              # jbe (skip {4,5})
        0x6097738: bytes.fromhex("8b83d8000000"),      # mov 0xd8(%rbx), %eax
        0x609773E: bytes.fromhex("f6c420"),            # test $0x20, %ah
        0x6097747: bytes.fromhex("41807f0400"),        # cmpb $0x0, 0x4(%r15)
        0x60976E0: bytes.fromhex("f6c401"),            # test $0x1, %ah
        0x60976E9: bytes.fromhex("8b8bd0000000"),      # mov 0xd0(%rbx), %ecx
        0x60976EF: bytes.fromhex("8d51eb"),            # lea -0x15(%rcx), %edx
        0x60976F2: bytes.fromhex("83fa01"),            # cmp $0x1, %edx
        0x6097853: bytes.fromhex("e848410200"),        # call 0x60bb9a0 (A)
        0x6097D82: bytes.fromhex("e8193c0200"),        # call 0x60bb9a0 (B)
        0x6097FE3: bytes.fromhex("e8b8390200"),        # call 0x60bb9a0 (C)
        0x60979AA: bytes.fromhex("488d3594d83afa"),    # lea 0x445245 ("=")
        0x6097EF8: bytes.fromhex("41837f2802"),        # cmpl $0x2, 0x28(%r15)
        0x6097EFF: bytes.fromhex("f6c480"),            # test $0x80, %ah
        0x6098281: bytes.fromhex("c70000000000"),      # movl $0x0, (%rax)
        0x6097BDF: bytes.fromhex("c684241401000001"),  # movb $0x1, 0x114(%rsp)
        0x6097CA7: bytes.fromhex("c684241401000000"),  # movb $0x0, 0x114(%rsp)
        0x6097C92: bytes.fromhex("83400801"),          # addl $0x1, 0x8(%rax)
        0x6098118: bytes.fromhex("f083400801"),        # lock addl $0x1, 0x8(%rax)
        0x60982A8: bytes.fromhex("ff5010"),            # call *0x10(%rax)
        0x60982B3: bytes.fromhex("ff5018"),            # call *0x18(%rax)
        0x6098566: bytes.fromhex("e8c5f0ffff"),        # call 0x6097630 (pre-step)
        0x609861F: bytes.fromhex("e80cf0ffff"),        # call 0x6097630 (wrapper)
    }
    all_spots = True
    for va, want in spots.items():
        got = read_bytes(va, len(want))
        if got != want:
            all_spots = False
            print(f"  spot mismatch at {va:#x}: got {got.hex()} want {want.hex()}")
    check("raw-binary spot bytes (30 sites)", all_spots)

    # 6. Literals from .rodata.
    check("literal '=' at 0x445245", data[0x445245:0x445246] == b"=")
    check("literal '; ' at 0x4409b0", data[0x4409B0:0x4409B2] == b"; ")

    # 7. Caller census reproduction (E8 rel32 scan).
    def scan_callers(target):
        b = data[TEXT_OFF:]
        hits, idx = [], 0
        while True:
            i = b.find(b"\xe8", idx)
            if i < 0:
                break
            if i + 5 <= len(b):
                rel = struct.unpack_from("<i", b, i + 1)[0]
                site = TEXT_VA + i
                if site + 5 + rel == target:
                    hits.append(site)
            idx = i + 1
        return hits

    check("callers of 0x6097630",
          scan_callers(0x6097630) == [0x6098566, 0x609861F])
    check("callers of 0x6098510",
          scan_callers(0x6098510) ==
          [0x609D5EA, 0x609E80F, 0x60B96CD, 0x60B977F, 0x60D4187])
    check("callers of 0x60985e0", scan_callers(0x60985E0) == [0x609E0A9])

    # 8. Records are semantic-only.
    raw = (HERE / "records.json").read_text()
    check("records.json semantic-only",
          '"mnemonic"' not in raw and '"instructions"' not in raw
          and '"opcodes"' not in raw)
    records = json.loads(raw)
    check("records.json binds the artifact digest",
          records["artifact_sha256"] == EXPECTED_SHA256)

    # 9. Model tests pass.
    res = subprocess.run(
        [sys.executable, "tests/test_map_serializer_7630_115.py"],
        cwd=ROOT, capture_output=True, text=True)
    check("model tests pass", res.returncode == 0, res.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin") + res.stderr)

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
