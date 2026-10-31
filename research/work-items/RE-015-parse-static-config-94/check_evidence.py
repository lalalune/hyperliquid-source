#!/usr/bin/env python3
"""Reproducible checks for this work-item, no binary execution.

Checks the retained disassembly files in this directory for the
markers cited in README.md. With --binary PATH it also re-dumps the
same windows from a verified release 94 binary and compares the
cited addresses. It never loads or runs the binary.
"""
import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

# (file, marker) pairs that must be present: positive controls.
POSITIVE = [
    ("disassembly/parse_static_config_aws_name_164d630.txt", "164d630:"),
    ("disassembly/parse_static_config_aws_name_164d630.txt", "164d677:"),
    ("disassembly/main_json_parser_164e930.txt", "164eae7:"),
    ("disassembly/main_json_parser_164e930.txt", "20a458"),
    ("disassembly/variant_mapper_164b3d0.txt", "164b820:"),
    ("disassembly/expect_null_164e800.txt", "164e86d:"),
    ("disassembly/expect_null_164e800.txt", "164e8c7:"),
    ("disassembly/string_scanner_4ebfd80.txt", "4ebfdfc:"),
]

# Negative controls: these markers must NOT appear in the cited
# windows, because their absence is part of the claim.
NEGATIVE = [
    # No simple backslash-reject compare in the static_config
    # cluster window for the main parser (see README).
    ("disassembly/main_json_parser_164e930.txt", "cmp    $0x5c"),
]


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=None)
    args = ap.parse_args()
    failures = []
    for rel, marker in POSITIVE:
        text = (HERE / rel).read_text(errors="ignore")
        if marker not in text:
            failures.append(f"missing positive marker {marker!r} in {rel}")
    for rel, marker in NEGATIVE:
        text = (HERE / rel).read_text(errors="ignore")
        if marker in text:
            failures.append(f"unexpected negative marker {marker!r} in {rel}")
    if args.binary:
        got = sha256(args.binary)
        if got != EXPECTED_SHA:
            failures.append(f"binary SHA mismatch: {got} != {EXPECTED_SHA}")
        else:
            print(f"binary SHA OK: {args.binary}")
        # Re-dump the parse window and compare the call site.
        out = subprocess.run(
            ["objdump", "-d", "--start-address=0x164d630",
             "--stop-address=0x164d73e", args.binary],
            capture_output=True, text=True, check=True).stdout
        if "164e930" not in out:
            failures.append("re-dump: call to 0x164e930 not found")
        else:
            print("re-dump: call to 0x164e930 present")
    if failures:
        print("FAIL")
        for f in failures:
            print(f" - {f}")
        return 1
    print("PASS: positive markers present, negative markers absent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
