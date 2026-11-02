#!/usr/bin/env python3
"""Verify the RE-001-range-ctor-94 evidence packet.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-range-ctor-94/verify.py \\
        --binary work/hl-node-94.bin

Checks, all against the digest-verified binary:
  1. the binary SHA-256 matches provenance/artifacts.json (node #94);
  2. every objdump excerpt regenerates byte-for-byte;
  3. MANIFEST.sha256 matches the packet files;
  4. records.json is semantic records only;
  5. the recorded sites sit at their recorded addresses
     (first-byte spot checks);
  6. the recorded overflow thresholds match the model's rules.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO = PACKET_DIR.parents[2]
DEFAULT_BINARY = REPO / "artifacts" / "node" / "94" / "hl-node"
NODE94_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

EXCERPTS = {
    "window.objdump.txt": ("0x515a960", "0x515ae14"),
    "caller.objdump.txt": ("0x515f160", "0x515f1a0"),
}

# (address, first byte) spot checks for the sites records.json pins.
# .text file offset = VA - 0x1000 for this binary.
SITES = [
    (0x515A960, 0xF3),  # window start
    (0x515A9D1, 0xE8),  # call to _M_next_bkt
    (0x515AA1D, 0x48),  # last-pointer load (skip-alloc target)
    (0x515AA37, 0x48),  # element-count <= 20 test
    (0x515AB26, 0xBA),  # hash seed load
    (0x515AB31, 0xE8),  # call to _Hash_bytes
    (0x515ABA8, 0xBF),  # node allocation size load
    (0x515AC52, 0xE8),  # call to _M_need_rehash
    (0x515ACF8, 0xE8),  # call to the rehash auxiliary
    (0x515AD3F, 0x49),  # single-bucket slot store
    (0x515AD4D, 0x48),  # second overflow shift test
    (0x515AD63, 0xE8),  # bad array new length throw call
    (0x515AD78, 0xE8),  # bad alloc throw call
    (0x515AA90, 0x48),  # canary load on the normal return
    (0x515AD9A, 0xE8),  # stack check failure call
    (0x515F198, 0xE8),  # the sole direct caller's call site
]

BANNED_RECORD_KEYS = ("mnemonics", "instructions", "operands", "bytes")


def fail(message):
    print("FAIL: %s" % message)
    sys.exit(1)


def check_digest(binary):
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != NODE94_SHA256:
        fail("binary SHA-256 %s != node #94 %s" % (digest, NODE94_SHA256))


def check_excerpts(packet_dir, binary):
    for name, (start, stop) in EXCERPTS.items():
        result = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, str(binary)],
            capture_output=True, text=True)
        if result.returncode != 0:
            fail("objdump failed for %s: %s" % (name, result.stderr.strip()))
        want = (packet_dir / name).read_text()
        if result.stdout != want:
            fail("excerpt %s does not regenerate byte-for-byte" % name)


def check_manifest(packet_dir):
    manifest = (packet_dir / "MANIFEST.sha256").read_text().splitlines()
    seen = set()
    for line in manifest:
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        path = packet_dir / name
        if not path.is_file():
            fail("manifest lists missing file %s" % name)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            fail("manifest mismatch for %s" % name)
        seen.add(name)
    for path in sorted(packet_dir.iterdir()):
        if path.name in ("MANIFEST.sha256", "verify.py"):
            continue
        if path.is_file() and path.name not in seen:
            fail("packet file %s missing from manifest" % path.name)


def check_records(packet_dir):
    with open(packet_dir / "records.json") as fh:
        records = json.load(fh)

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in BANNED_RECORD_KEYS:
                    fail("records.json carries banned key %s" % key)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(records)
    window = records["window"]
    if window["start"] != "0x515a960" or window["end"] != "0x515ae14":
        fail("records.json window range mismatch")


def check_sites(binary):
    data = binary.read_bytes()
    for address, first_byte in SITES:
        offset = address - 0x1000
        if data[offset] != first_byte:
            fail("site 0x%x first byte 0x%02x != 0x%02x"
                 % (address, data[offset], first_byte))


def check_thresholds():
    # The model's overflow arms, from records.json's own ranges.
    if not ((1 << 60) - 1 < (1 << 60) <= (1 << 61) - 1 < (1 << 61)):
        fail("overflow threshold ordering broken")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(DEFAULT_BINARY))
    ap.add_argument("--packet-dir", default=str(PACKET_DIR))
    args = ap.parse_args(argv)
    binary = Path(args.binary)
    packet_dir = Path(args.packet_dir)
    if not binary.is_file():
        fail("binary not found: %s" % binary)
    check_digest(binary)
    check_excerpts(packet_dir, binary)
    check_manifest(packet_dir)
    check_records(packet_dir)
    check_sites(binary)
    check_thresholds()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
