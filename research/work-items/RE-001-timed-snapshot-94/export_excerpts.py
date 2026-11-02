#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-timed-snapshot-94/export_excerpts.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. The excerpts are whole functions (plus int3 padding to
the next FDE where padding exists), never trimmed windows. The
caller-site excerpt is the exception: it is a sample of the enclosing
function around its call site, not the whole enclosing function.
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
    "window.objdump.txt": ("0x514f270", "0x514f71a"),
    "cleanup.objdump.txt": ("0x514f224", "0x514f270"),
    "ctor.objdump.txt": ("0x514def0", "0x514df30"),
    "timestamp_set.objdump.txt": ("0x514df30", "0x514df40"),
    "counter_inc.objdump.txt": ("0x514df40", "0x514df50"),
    "snapshot_callee.objdump.txt": ("0x514ed50", "0x514f224"),
    # Caller-site sample: the flag setup, the window call at
    # 0x514fda5, and the post-call read of the caller's +0x128 field.
    "caller.objdump.txt": ("0x514fd94", "0x514fdc0"),
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
