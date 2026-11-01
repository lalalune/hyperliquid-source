#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-recursive-teardown-94/export_excerpts.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. Output files are written next to this script and are
byte-identical to the shipped excerpts when run against the
digest-pinned binary with the same binutils version (GNU binutils
2.42 here). The window excerpt holds the whole function plus its
int3 padding to the next FDE; the plt excerpt holds the whole
16-byte delete stub; the callers excerpt holds one 5-byte call
instruction per census site, in census order. Excerpts are never
trimmed windows of a function body.
"""

import argparse
import os
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- window stop is the next FDE start, so the
    # file holds the whole function plus its int3 padding.
    "window.objdump.txt": ("0x514bf60", "0x514bfe0"),
    "plt.objdump.txt": ("0x5660440", "0x5660450"),
}

CALLER_SITES = [
    0x514BF77, 0x5153BC2, 0x515410A, 0x5154183, 0x5154354, 0x51543F0,
    0x5154800, 0x5154A6B, 0x5155C1D, 0x5155EF4, 0x5157D77,
]


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
    callers = "".join(
        objdump(args.binary, [
            "-d",
            "--start-address=%#x" % site,
            "--stop-address=%#x" % (site + 5)])
        for site in CALLER_SITES)
    with open(os.path.join(PACKET_DIR, "callers.objdump.txt"), "w") as f:
        f.write(callers)
    print("wrote 3 excerpts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
