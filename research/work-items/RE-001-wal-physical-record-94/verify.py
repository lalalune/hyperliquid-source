#!/usr/bin/env python3
"""Verify the RE-001-wal-physical-record-94 evidence packet.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-wal-physical-record-94/verify.py \\
        --binary work/hl-node-94.bin

Checks, all against the digest-verified binary:
  1. the binary SHA-256 matches provenance/artifacts.json (node #94);
  2. every objdump excerpt regenerates byte-for-byte;
  3. MANIFEST.sha256 matches the packet files;
  4. records.json is semantic records only (no per-instruction list);
  5. the recorded sites sit at their recorded addresses
     (first-byte spot checks);
  6. both caller excerpts contain the recorded direct calls.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

DEFAULT_PACKET_DIR = Path(__file__).resolve().parent
REPO = DEFAULT_PACKET_DIR.parents[2]
DEFAULT_BINARY = REPO / "artifacts" / "node" / "94" / "hl-node"
NODE94_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

EXCERPTS = {
    "window.objdump.txt": ("0x5161400", "0x516184d"),
    "refill.objdump.txt": ("0x51612a0", "0x5161400"),
    "caller-site-1.objdump.txt": ("0x51619a0", "0x51619d0"),
    "caller-site-2.objdump.txt": ("0x5161ea8", "0x5161ed8"),
}

# (address, first byte) spot checks for the sites records.json pins.
# .text file offset = VA - 0x1000 for this binary.
SITES = [
    (0x5161400, 0xF3),  # window start (endbr64)
    (0x5161441, 0x44),  # type byte load
    (0x516147B, 0xE8),  # refill helper call
    (0x51616EF, 0x41),  # rol 15 (CRC unmask)
    (0x51612A0, 0xF3),  # refill helper start (endbr64)
    (0x5161367, 0xE8),  # block-source read call
    (0x51619C6, 0xE8),  # direct caller 1 call
    (0x5161EC9, 0xE8),  # direct caller 2 call
]

CALLER_LINES = [
    ("caller-site-1.objdump.txt", "51619c6", "5161400"),
    ("caller-site-2.objdump.txt", "5161ec9", "5161400"),
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


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(DEFAULT_BINARY))
    ap.add_argument("--packet", default=str(DEFAULT_PACKET_DIR))
    args = ap.parse_args(argv)
    binary = Path(args.binary)
    packet_dir = Path(args.packet)
    failures = []

    if sha256_file(binary) != NODE94_SHA256:
        failures.append("binary digest mismatch")

    for name, (start, stop) in EXCERPTS.items():
        actual = objdump(binary, start, stop)
        expected = (packet_dir / name).read_text()
        if actual != expected:
            failures.append("excerpt mismatch: %s" % name)

    manifest = packet_dir / "MANIFEST.sha256"
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        name = name.lstrip("*")
        if sha256_file(packet_dir / name) != digest:
            failures.append("manifest mismatch: %s" % name)

    records_text = (packet_dir / "records.json").read_text()
    records = json.loads(records_text)
    if "mnemonic" in records_text or "instructions" in records:
        failures.append("records.json carries instruction-level detail")
    if records.get("task_id") != "RE-001":
        failures.append("records.json task id is not RE-001")

    raw = binary.read_bytes()
    for address, first_byte in SITES:
        if raw[address - 0x1000] != first_byte:
            failures.append("site byte mismatch at %#x" % address)

    for name, call_site, target in CALLER_LINES:
        text = (packet_dir / name).read_text()
        if call_site not in text or target not in text:
            failures.append("caller excerpt missing call: %s" % name)

    if failures:
        for failure in failures:
            print("FAIL: %s" % failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
