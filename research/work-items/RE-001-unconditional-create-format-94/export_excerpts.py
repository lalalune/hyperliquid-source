#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-unconditional-create-format-94/export_excerpts.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. The excerpts are whole functions (plus int3 padding to
the next FDE where padding exists), never trimmed windows.
"""

import argparse
import os
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- stop is the next FDE start, so the file
    # holds the whole function plus its int3 padding (if any).
    "window.objdump.txt": ("0x514e9f0", "0x514eb3a"),
    "cleanup.objdump.txt": ("0x514e994", "0x514e9f0"),
    "lookup.objdump.txt": ("0x51e9220", "0x51e95f0"),
    "formatter.objdump.txt": ("0x5407f00", "0x540a460"),
    "moveassign.objdump.txt": ("0x514b4f0", "0x514b5d0"),
    "control.objdump.txt": ("0x4f94a90", "0x4f94b20"),
}


def objdump(binary, args):
    result = subprocess.run(["objdump"] + args + [binary],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("objdump failed: %s" % result.stderr.strip())
    return result.stdout


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    ap.add_argument("--out", default=None,
                    help="write excerpts here instead of the packet dir")
    args = ap.parse_args(argv)
    out_dir = args.out or PACKET_DIR
    os.makedirs(out_dir, exist_ok=True)
    for name, (start, stop) in RANGES.items():
        text = objdump(args.binary, [
            "-d",
            "--start-address=%s" % start,
            "--stop-address=%s" % stop])
        with open(os.path.join(out_dir, name), "w") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
