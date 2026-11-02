#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-counted-key-hashtable-94/export_excerpts.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. The window, insert, rehash and cleanup excerpts are
whole functions, never trimmed windows, except the caller-site
files, which are call-site samples inside larger routines (census
only).
"""

import argparse
import os
import subprocess

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- stop is the next FDE start for the
    # window, insert, rehash and cleanup, so those files hold
    # whole functions.
    "window.objdump.txt": ("0x5160dd0", "0x5160ebd"),
    "insert.objdump.txt": ("0x5160c10", "0x5160dbf"),
    "rehash.objdump.txt": ("0x5160ad0", "0x5160c0d"),
    "cleanup.objdump.txt": ("0x5160dc0", "0x5160dd0"),
    "caller-site-1.objdump.txt": ("0x521d150", "0x521d15c"),
    "caller-site-2.objdump.txt": ("0x521d9d8", "0x521d9e4"),
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
        with open(os.path.join(out_dir, name), "w") as fh:
            fh.write(text)


if __name__ == "__main__":
    main()
