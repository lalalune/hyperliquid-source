#!/usr/bin/env python3
"""Verify the RE-001-rehash-aux-94 evidence packet.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-rehash-aux-94/verify.py \
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
    "window.objdump.txt": ("0x515a820", "0x515a960"),
    "caller.objdump.txt": ("0x515acec", "0x515ad10"),
}

# (address, first byte) spot checks for the sites records.json pins.
# .text file offset = VA - 0x1000 for this binary.
SITES = [
    (0x515A820, 0xF3),  # endbr64 at the window start
    (0x515A834, 0x48),  # new count == 1 comparison
    (0x515A844, 0x48),  # new count >> 60 overflow test
    (0x515A859, 0xE8),  # call to operator new
    (0x515A869, 0xE8),  # call to memset
    (0x515A872, 0x48),  # old head load and head reset
    (0x515A8A9, 0x48),  # cached hash load at node+0x70
    (0x515A8AD, 0x48),  # unsigned divide by the new count
    (0x515A8B4, 0x48),  # new bucket entry load
    (0x515A890, 0x48),  # nonempty bucket insert-after-before-node
    (0x515A8BC, 0x48),  # empty bucket head prepend and sentinel entry
    (0x515A8CA, 0x48),  # last-node fixup test (node next == 0)
    (0x515A8D0, 0x4B),  # last-node fixup store at previous index
    (0x515A8E4, 0x4C),  # old buckets pointer vs table+0x30
    (0x515A8ED, 0xE8),  # call to operator delete[]
    (0x515A8F2, 0x48),  # new count commit to table+0x08
    (0x515A8F6, 0x4C),  # new base commit to table+0x00
    (0x515A920, 0x48),  # new count >> 61 second overflow test
    (0x515A926, 0xE8),  # bad array new length throw call
    (0x515A92B, 0xE8),  # bad alloc throw call
    (0x515A930, 0xF3),  # allocation-failure catch entry
    (0x515A93C, 0x49),  # next-resize restore load from saved pointer
    (0x515A940, 0x48),  # next-resize restore store to table+0x28
    (0x515A944, 0xE8),  # rethrow call
    (0x515A949, 0xF3),  # unwind-resume entry
    (0x515ACF8, 0xE8),  # sole direct caller call site
]


def fail(message):
    print("FAIL: %s" % message)
    sys.exit(1)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(DEFAULT_BINARY))
    args = ap.parse_args(argv)
    binary = Path(args.binary)
    data = binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != NODE94_SHA256:
        fail("binary SHA-256 does not match provenance/artifacts.json")

    for name, (start, stop) in EXCERPTS.items():
        result = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, str(binary)],
            capture_output=True, text=True)
        if result.returncode != 0:
            fail("objdump failed for %s" % name)
        if result.stdout != (PACKET_DIR / name).read_text():
            fail("excerpt %s does not regenerate byte-for-byte" % name)

    manifest = (PACKET_DIR / "MANIFEST.sha256").read_text().splitlines()
    for line in manifest:
        digest, name = line.split("  ", 1)
        path = PACKET_DIR / name
        if not path.exists():
            fail("MANIFEST lists missing file %s" % name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            fail("MANIFEST mismatch for %s" % name)

    records_text = (PACKET_DIR / "records.json").read_text()
    records = json.loads(records_text)
    if "mnemonic" in records_text or "instructions" in records:
        fail("records.json holds per-instruction detail, not "
             "semantic records only")

    for address, first_byte in SITES:
        if data[address - 0x1000] != first_byte:
            fail("site 0x%x first byte mismatch" % address)

    if records["window"]["size_bytes"] != 317:
        fail("window size mismatch")
    if records["arms"]["overflow"]["bad_alloc_range"] != \
            "2**60 <= new_bucket_count < 2**61":
        fail("overflow bad_alloc range mismatch")
    if records["arms"]["overflow"]["bad_array_new_length_range"] != \
            "new_bucket_count >= 2**61":
        fail("overflow bad_array_new_length range mismatch")
    if records["caller"]["site"] != "0x515acf8":
        fail("caller site mismatch")

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
