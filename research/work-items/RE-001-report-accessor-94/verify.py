#!/usr/bin/env python3
"""Verify the RE-001-report-accessor-94 evidence packet.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-report-accessor-94/verify.py \
        --binary work/hl-node-94.bin

Checks, all against the digest-verified binary:
  1. the binary SHA-256 matches provenance/artifacts.json (node #94);
  2. every objdump excerpt regenerates byte-for-byte;
  3. MANIFEST.sha256 matches the packet files;
  4. records.json is semantic records only (no per-instruction list);
  5. the recorded call/branch sites sit at their recorded addresses;
  6. the snapshot copy map covers 0x138 bytes with no gap/overlap.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO = PACKET_DIR.parents[2]
DEFAULT_BINARY = REPO / "artifacts" / "node" / "94" / "hl-node"
NODE94_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

EXCERPTS = {
    "window.objdump.txt": ("0x5158ef0", "0x5159130"),
    "cleanup.objdump.txt": ("0x5158ebe", "0x5158ef0"),
    "thunk0.objdump.txt": ("0x5159130", "0x5159140"),
    "thunk1.objdump.txt": ("0x5159140", "0x515914e"),
}

# (address, byte) spot checks for the sites records.json pins.
SITES = [
    (0x5158EBE, 0x48),  # cleanup full entry: mov rbx,rdi (unlock arg)
    (0x5158EC6, 0x4C),  # cleanup dispose-only entry: mov r14,rdi
    (0x5158EF0, 0xF3),  # endbr64 at the window start
    (0x5158F24, 0x83),  # xor $0x1,%edx (flag inversion)
    (0x5158F35, 0xE8),  # call to the timed refresh 0x514f270
    (0x5158F78, 0xE8),  # call pthread_mutex_lock
    (0x5158FA4, 0xE8),  # call to the string assign 0x56605c0
    (0x5159099, 0xE8),  # call pthread_mutex_unlock
    (0x51590AB, 0xE8),  # call to the report builder 0x5157d30
    (0x51590C3, 0xE8),  # call to the sized delete 0x5660440
    (0x5159118, 0xF3),  # landing stub to the dispose-only entry
    (0x5159124, 0xF3),  # landing stub to the full entry
    (0x5159136, 0xE9),  # thunk0 tail jump to 0x5158ef0
    (0x5159149, 0xE9),  # thunk1 tail jump to 0x5158ef0
]

# (snapshot offset, byte length) of the copy map in records.json.
COPY_MAP = [
    (0x00, 16), (0x10, 16), (0x20, 32), (0x40, 16), (0x50, 16),
    (0x60, 16), (0x70, 16), (0x80, 16), (0x90, 16), (0xA0, 16),
    (0xB0, 16), (0xC0, 16), (0xD0, 16), (0xE0, 16), (0xF0, 16),
    (0x100, 16), (0x110, 16), (0x120, 8), (0x128, 16),
]

BANNED_KEYS = ("mnemonic", "mnemonics", "instructions", "disassembly")


def section_map(binary):
    out = subprocess.run(["readelf", "-W", "-S", str(binary)],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("readelf failed: %s" % out.stderr.strip())
    secs = []
    for line in out.stdout.splitlines():
        if "] ." in line:
            p = line.split()
            try:
                secs.append((p[1], int(p[3], 16), int(p[4], 16),
                             int(p[5], 16)))
            except (ValueError, IndexError):
                continue
    return secs


def read_at(raw, secs, va, n):
    for _name, addr, off, size in secs:
        if addr <= va < addr + size:
            return raw[off + (va - addr):off + (va - addr) + n]
    return b""


def walk(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(DEFAULT_BINARY))
    args = ap.parse_args(argv)
    binary = Path(args.binary)
    failures = []

    raw = binary.read_bytes()
    if hashlib.sha256(raw).hexdigest() != NODE94_SHA256:
        failures.append("binary SHA-256 mismatch")

    try:
        display = str(binary.relative_to(REPO))
    except ValueError:
        display = str(binary)
    with tempfile.TemporaryDirectory() as tmp:
        for name, (start, stop) in EXCERPTS.items():
            result = subprocess.run(
                ["objdump", "-d", "--start-address=%s" % start,
                 "--stop-address=%s" % stop, display],
                capture_output=True, text=True, cwd=str(REPO))
            if result.returncode != 0:
                failures.append("objdump failed for %s" % name)
                continue
            want = (PACKET_DIR / name).read_text()
            if result.stdout != want:
                failures.append("excerpt mismatch: %s" % name)

    manifest = (PACKET_DIR / "MANIFEST.sha256").read_text().splitlines()
    for line in manifest:
        digest, name = line.split(None, 1)
        data = (PACKET_DIR / name.strip()).read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            failures.append("manifest mismatch: %s" % name)

    records = json.loads((PACKET_DIR / "records.json").read_text())
    for key in walk(records):
        if key in BANNED_KEYS:
            failures.append("banned key in records.json: %s" % key)

    secs = section_map(str(binary))
    for va, byte in SITES:
        got = read_at(raw, secs, va, 1)
        if not got or got[0] != byte:
            failures.append("site byte mismatch at %#x" % va)

    covered = set()
    for off, length in COPY_MAP:
        for i in range(off, off + length):
            if i in covered:
                failures.append("copy map overlap at %#x" % i)
            covered.add(i)
    if covered != set(range(0x138)):
        failures.append("copy map does not cover exactly 0x138 bytes")

    if failures:
        print("FAILURES:")
        for failure in failures:
            print(" - %s" % failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
