#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-list-teardown-94/export_excerpts.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. Output files are written next to this script and are
byte-identical to the shipped excerpts when run against the
digest-pinned binary with the same binutils version (GNU binutils
2.42 here). The window excerpt is the whole function plus its int3
padding to the next FDE, never a trimmed window; the plt excerpt is
the two PLT stubs concatenated in stub order.
"""

import argparse
import os
import subprocess

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- window stop is the next FDE start, so the
    # file holds the whole function plus its int3 padding.
    "window.objdump.txt": ("0x514bd40", "0x514bdf0"),
}

PLT_RANGES = [
    ("0x5660140", "0x5660150"),
    ("0x5660440", "0x5660450"),
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
    plt_text = "".join(
        objdump(args.binary, [
            "-d",
            "--start-address=%s" % start,
            "--stop-address=%s" % stop])
        for start, stop in PLT_RANGES)
    with open(os.path.join(PACKET_DIR, "plt.objdump.txt"), "w") as f:
        f.write(plt_text)
    print("wrote %d excerpts" % (len(RANGES) + 1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
