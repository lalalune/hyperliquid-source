#!/usr/bin/env python3
"""Verify the RE-001-pending-erase-sweep-94 evidence packet.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-pending-erase-sweep-94/verify.py \
        --binary work/hl-node-94.bin

Checks, all against the digest-verified binary:
  1. the binary SHA-256 matches provenance/artifacts.json (node #94);
  2. every objdump excerpt regenerates byte-for-byte;
  3. MANIFEST.sha256 matches the packet files;
  4. records.json is semantic records only (no per-instruction list);
  5. the recorded sites sit at their recorded addresses
     (first-byte spot checks);
  6. the caller excerpts contain the recorded direct calls.
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
    "window.objdump.txt": ("0x5160560", "0x5160783"),
    "cleanup.objdump.txt": ("0x516054e", "0x516055e"),
    "caller-twin.objdump.txt": ("0x50abad0", "0x50abb45"),
    "caller-site3.objdump.txt": ("0x50ec610", "0x50ec630"),
}

# (address, first byte) spot checks for the sites records.json pins.
# .text file offset = VA - 0x1000 for this binary.
SITES = [
    (0x5160560, 0xF3),  # window start (endbr64)
    (0x516057C, 0xE8),  # mutex A lock call
    (0x51605A6, 0xE8),  # mutex B lock call
    (0x5160649, 0xE8),  # operator delete call
    (0x516067B, 0xE8),  # memmove compaction call
    (0x516076B, 0xE8),  # system_error throw call
    (0x5160777, 0xF3),  # landing stub (endbr64)
    (0x516054E, 0x4C),  # cleanup start (mov r12 to rdi)
    (0x50ABAF2, 0xE8),  # twin wrapper call
    (0x50EC61E, 0xE8),  # third caller call
]

CALLER_LINES = [
    ("caller-twin.objdump.txt", "50abaf2", "5160560"),
    ("caller-site3.objdump.txt", "50ec61e", "5160560"),
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def objdump(binary, start, stop):
    result = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % start,
         "--stop-address=%s" % stop, str(binary)],
        capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("objdump failed: %s" % result.stderr.strip())
    return result.stdout


def check_manifest():
    manifest = PACKET_DIR / "MANIFEST.sha256"
    ok = True
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        name = name.lstrip("*")
        actual = sha256_file(PACKET_DIR / name)
        if actual != digest:
            print("MANIFEST MISMATCH: %s" % name)
            ok = False
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(DEFAULT_BINARY))
    args = ap.parse_args(argv)
    binary = Path(args.binary)
    failures = []

    if sha256_file(binary) != NODE94_SHA256:
        failures.append("binary SHA-256 mismatch")

    with tempfile.TemporaryDirectory() as tmp:
        for name, (start, stop) in EXCERPTS.items():
            fresh = objdump(binary, start, stop)
            stored = (PACKET_DIR / name).read_text()
            if fresh != stored:
                failures.append("excerpt mismatch: %s" % name)

    if not check_manifest():
        failures.append("MANIFEST.sha256 mismatch")

    records = json.loads((PACKET_DIR / "records.json").read_text())
    if "mnemonic" in json.dumps(records):
        failures.append("records.json carries instruction mnemonics")
    if set(records) != {"behavior", "binary", "binary_sha256", "buckets",
                        "caller_census_method", "callers", "hash_node",
                        "outer_layout", "pending_element",
                        "preconditions_observed", "provenance", "shape_note",
                        "slug", "task_id", "unknowns", "window"}:
        failures.append("records.json has unexpected top-level keys")

    data = binary.read_bytes()
    for addr, first in SITES:
        if data[addr - 0x1000] != first:
            failures.append("spot check failed at %#x" % addr)

    for name, site, target in CALLER_LINES:
        text = (PACKET_DIR / name).read_text()
        if site not in text or target not in text:
            failures.append("caller excerpt %s lacks the call" % name)

    if failures:
        print("FAILED:")
        for failure in failures:
            print("  - %s" % failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
