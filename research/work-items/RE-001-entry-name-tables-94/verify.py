#!/usr/bin/env python3
"""Verify the RE-001-entry-name-tables-94 evidence packet.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-entry-name-tables-94/verify.py \
        --binary work/hl-node-94.bin

Checks, all against the digest-verified binary:
  1. the binary SHA-256 matches provenance/artifacts.json (node #94);
  2. every objdump excerpt regenerates byte-for-byte;
  3. MANIFEST.sha256 matches the packet files;
  4. records.json is semantic records only, and its tables match
     the model's name lists;
  5. the recorded sites sit at their recorded addresses
     (first-byte spot checks);
  6. the recorded name strings are present in the binary at their
     recorded .rodata addresses.
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
    "window.objdump.txt": ("0x51601c0", "0x516054e"),
    "assign.objdump.txt": ("0x515f7a0", "0x515f870"),
    "destructor.objdump.txt": ("0x515f870", "0x515f8c5"),
}

# (address, first byte) spot checks for the sites records.json pins.
# .text file offset = VA - 0x1000 for this binary.
SITES = [
    (0x51601C0, 0xF3),  # window start
    (0x51601D9, 0xE8),  # first table's first assign call
    (0x51602E3, 0xE8),  # first table's __cxa_atexit call
    (0x51603F9, 0xE9),  # second table's __cxa_atexit tail jump
    (0x515F7A0, 0x41),  # assign routine start
    (0x515F7D3, 0xE8),  # strlen call
    (0x515F82C, 0xE8),  # _M_create call
    (0x515F86B, 0xE8),  # logic_error throw call
    (0x515F870, 0xF3),  # destructor start
    (0x515F898, 0xE8),  # operator delete[] call
]

# (.rodata address, name) pairs, in initializer call order: the
# first table's 14 names, then the second table's 14 names.
NAME_SITES = [
    (0x1F37A7, "DataBlock"),
    (0x1F4AA5, "FilterBlock"),
    (0x1FEEF5, "FilterMetaBlock"),
    (0x200049, "DeprecatedFilterBlock"),
    (0x1F1793, "IndexBlock"),
    (0x1DE12B, "OtherBlock"),
    (0x1F5F6F, "WriteBuffer"),
    (0x7D8C28, "CompressionDictionaryBuildingBuffer"),
    (0x1E8F98, "FilterConstruction"),
    (0x1E1E6D, "BlockBasedTableReader"),
    (0x1E7F9C, "FileMetadata"),
    (0x1FB885, "BlobValue"),
    (0x1E8FAB, "BlobCache"),
    (0x1E1E83, "Misc"),
    (0x1EB31B, "data-block"),
    (0x1F295D, "filter-block"),
    (0x1E1E88, "filter-meta-block"),
    (0x1F296A, "deprecated-filter-block"),
    (0x1E483E, "index-block"),
    (0x1F981D, "other-block"),
    (0x1E8FB5, "write-buffer"),
    (0x7DE168, "compression-dictionary-building-buffer"),
    (0x1E6E1A, "filter-construction"),
    (0x1FB88F, "block-based-table-reader"),
    (0x1DE136, "file-metadata"),
    (0x1EC6B0, "blob-value"),
    (0x1F37B1, "blob-cache"),
    (0x1FDC89, "misc"),
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
    if window["start"] != "0x51601c0" or window["end"] != "0x516054e":
        fail("records.json window range mismatch")
    tables = records["tables"]
    if len(tables) != 2 or any(len(t["names"]) != 14 for t in tables):
        fail("records.json tables must hold 14 names each")
    flat = [name for table in tables for name in table["names"]]
    if flat != [name for _, name in NAME_SITES]:
        fail("records.json table names do not match the name sites")


def check_sites(binary):
    data = binary.read_bytes()
    for address, first_byte in SITES:
        offset = address - 0x1000
        if data[offset] != first_byte:
            fail("site 0x%x first byte 0x%02x != 0x%02x"
                 % (address, data[offset], first_byte))
    for address, name in NAME_SITES:
        # .rodata file offset equals its virtual address here.
        actual = data[address:address + len(name)]
        if actual.decode() != name:
            fail("name site 0x%x holds %r != %r" % (address, actual, name))
        if data[address + len(name)] != 0:
            fail("name site 0x%x is not NUL-terminated" % address)


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
    check_records(packet_dir)
    check_sites(binary)
    check_manifest(packet_dir)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
