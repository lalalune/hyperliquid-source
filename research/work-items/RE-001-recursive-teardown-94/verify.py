#!/usr/bin/env python3
"""Verify this packet's semantic records against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-recursive-teardown-94/verify.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. The checks themselves live in
tools/foundation_recursive_teardown.py (committed in the same
change, so the checker behind "ALL CHECKS PASSED" is visible in
the diff): target digest, function carve range and SHA, int3
padding, branch/call targets re-derived from raw encodings, the
caller census from a full .text scan, every excerpt line's bytes
against the binary, the FDE line, and the packet manifest hashes.
This script only wires that checker to this packet directory.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join("tools"))
import foundation_recursive_teardown as checker

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    args = ap.parse_args(argv)
    errors = checker.check_packet(PACKET_DIR, args.binary)
    if errors:
        for err in errors:
            print("FAIL: %s" % err)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
