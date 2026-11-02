#!/usr/bin/env python3
"""Verify the RE-001-blockcache-report-94 evidence packet.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-blockcache-report-94/verify.py \
        --binary work/hl-node-94.bin

Checks, all against the digest-verified binary:
  1. the binary SHA-256 matches provenance/artifacts.json (node #94);
  2. every objdump excerpt regenerates byte-for-byte;
  3. MANIFEST.sha256 matches the packet files;
  4. every literal in records.json sits at its recorded address;
  5. the recorded doubles (divisors, helper scale/threshold) match;
  6. the divide-by-1000000 magic equals integer division on samples;
  7. records.json is semantic records only (no per-instruction list).
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO = PACKET_DIR.parents[2]
DEFAULT_BINARY = REPO / "artifacts" / "node" / "94" / "hl-node"
NODE94_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

EXCERPTS = {
    "window.objdump.txt": ("0x514f770", "0x514fd30"),
    "cleanup.objdump.txt": ("0x514f71a", "0x514f770"),
    "accessor.objdump.txt": ("0x514df50", "0x514df80"),
    "helper.objdump.txt": ("0x5430570", "0x5430780"),
    "caller1.objdump.txt": ("0x514ff10", "0x514ff45"),
    "caller2.objdump.txt": ("0x5157460", "0x5157495"),
}

LITERALS = [
    (0x1F5F31, b"Block cache "), (0x1E3308, b" capacity: "),
    (0x1DE0FD, b" usage: "), (0x1E5B0E, b" table_size: "),
    (0x1EDB43, b" occupancy: "), (0x1FFFC8, b" collections: "),
    (0x1FEED8, b" last_copies: "), (0x1E6DE1, b" last_secs: "),
    (0x1EDB50, b" secs_since: "), (0x1F5E2A, b"\n"),
    (0x7D7F00, b"Block cache entry stats(count,size,portion):"),
    (0x1E0A14, b" "), (0x1EFFFA, b"("), (0x1EA0D2, b","),
    (0x1EB2A8, b"%)"),
]

DOUBLES = [
    (0x20AE60, 1000000.0), (0x20A600, 0.0009765625),
    (0x20AEB8, 1024.0), (0x20A960, 100.0),
]

REQUIRED_RECORD_KEYS = [
    "task_id", "bounded_question", "window", "accessor", "helper",
    "clock_chain", "header_sequence", "entry_loop", "caller_census",
    "snapshot_layout", "constants", "unknowns",
]


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


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(DEFAULT_BINARY))
    args = ap.parse_args(argv)
    binary = Path(args.binary)
    failures = []

    raw = binary.read_bytes()
    if hashlib.sha256(raw).hexdigest() != NODE94_SHA256:
        failures.append("binary SHA-256 mismatch")

    # objdump prints the binary path as given; run it from the repo
    # root with the repo-relative path, as the excerpts were made.
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
        name = name.strip()
        path = PACKET_DIR / name
        if not path.exists():
            failures.append("manifest file missing: %s" % name)
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            failures.append("manifest mismatch: %s" % name)

    secs = section_map(binary)
    for va, text in LITERALS:
        if read_at(raw, secs, va, len(text)) != text:
            failures.append("literal mismatch at %#x" % va)
    for va, value in DOUBLES:
        got = struct.unpack("<d", read_at(raw, secs, va, 8))[0]
        if got != value:
            failures.append("double mismatch at %#x: %r" % (va, got))

    magic = 0x431BDE82D7B634DB
    for x in [0, 1, 999, 1000, 10 ** 12, 2 ** 64 - 1,
              12345678901234567890]:
        if ((x * magic) >> 82) != x // 1000000:
            failures.append("divide-by-1000000 magic mismatch at %d" % x)

    records = json.loads((PACKET_DIR / "records.json").read_text())
    for key in REQUIRED_RECORD_KEYS:
        if key not in records:
            failures.append("records.json missing key: %s" % key)
    blob = json.dumps(records)
    if "mnemonic" in blob.lower() and "instructions" in blob.lower():
        failures.append("records.json carries instruction-level data")

    if failures:
        print("FAILED:")
        for f in failures:
            print(" - %s" % f)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
