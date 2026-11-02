#!/usr/bin/env python3
"""Verify the RE-001-counted-key-insert-94 evidence packet.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-counted-key-insert-94/verify.py \
        --binary work/hl-node-94.bin

Checks, all against the digest-verified binary:
  1. the binary SHA-256 matches provenance/artifacts.json (node #94);
  2. every objdump excerpt regenerates byte-for-byte;
  3. MANIFEST.sha256 matches the packet files;
  4. records.json is semantic records only (no per-instruction list);
  5. the recorded sites sit at their recorded addresses
     (first-byte spot checks);
  6. the caller excerpt contains the recorded direct call.
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
    "window.objdump.txt": ("0x5160940", "0x5160aca"),
    "cleanup.objdump.txt": ("0x5160914", "0x5160940"),
    "caller-site.objdump.txt": ("0x52251e8", "0x52251f7"),
}

# (address, first byte) spot checks for the sites records.json pins.
# .text file offset = VA - 0x1000 for this binary.
SITES = [
    (0x5160940, 0xF3),  # window start (endbr64)
    (0x516096B, 0xE8),  # mutex lock call
    (0x51609F5, 0xE9),  # mutex unlock tail jump
    (0x5160A49, 0xE8),  # memmove tail-shift call
    (0x5160A86, 0xE8),  # growth helper call
    (0x5160ABE, 0xF3),  # landing stub (endbr64)
    (0x5160914, 0x4C),  # cleanup start (mov r12 to rdi)
    (0x52251F2, 0xE8),  # sole direct caller call
]

CALLER_LINES = [
    ("caller-site.objdump.txt", "52251f2", "5160940"),
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
        failures.append("binary digest mismatch")

    for name, (start, stop) in EXCERPTS.items():
        actual = objdump(binary, start, stop)
        expected = (PACKET_DIR / name).read_text()
        if actual != expected:
            failures.append("excerpt mismatch: %s" % name)

    if not check_manifest():
        failures.append("manifest mismatch")

    records_text = (PACKET_DIR / "records.json").read_text()
    records = json.loads(records_text)
    if "mnemonic" in records_text or "instructions" in records:
        failures.append("records.json carries instruction-level detail")
    if records.get("task_id") != "RE-001":
        failures.append("records.json task id is not RE-001")

    blob = binary.read_bytes()
    for address, first_byte in SITES:
        offset = address - 0x1000
        if blob[offset] != first_byte:
            failures.append("site first byte mismatch: %#x" % address)

    for name, site, target in CALLER_LINES:
        text = (PACKET_DIR / name).read_text()
        if site not in text or target not in text:
            failures.append("caller excerpt missing call: %s" % name)

    with tempfile.TemporaryDirectory() as tmp:
        sys.dont_write_bytecode = True
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "export_excerpts", PACKET_DIR / "export_excerpts.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.main(["--binary", str(binary), "--out", tmp])
        for name in EXCERPTS:
            if (Path(tmp) / name).read_text() != (PACKET_DIR / name).read_text():
                failures.append("export script mismatch: %s" % name)

    if failures:
        print("FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
