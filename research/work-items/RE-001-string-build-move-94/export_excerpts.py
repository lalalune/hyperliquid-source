#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-string-build-move-94/export_excerpts.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. Output files are written next to this script and are
byte-identical to the shipped excerpts when run against the
digest-pinned binary with the same binutils version (GNU binutils
2.42 here). The excerpts are whole functions (plus int3 padding to
the next FDE), never trimmed windows.
"""

import argparse
import os
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- window stop is the next FDE start, so the
    # file holds the whole function (this function has no int3
    # padding); callee stop is the next FDE start too, so the file
    # holds the whole callee plus its 5 int3 padding bytes.
    "window.objdump.txt": ("0x514bdf0", "0x514be75"),
    "callee.objdump.txt": ("0x51cd470", "0x51ce460"),
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
    args = ap.parse_args(argv)
    for name, (start, stop) in RANGES.items():
        text = objdump(args.binary, [
            "-d",
            "--start-address=%s" % start,
            "--stop-address=%s" % stop])
        with open(os.path.join(PACKET_DIR, name), "w") as f:
            f.write(text)
    print("wrote %d excerpts" % len(RANGES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
