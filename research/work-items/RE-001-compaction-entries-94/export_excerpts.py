#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-compaction-entries-94/export_excerpts.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. The excerpts are whole functions (plus int3 padding
to the next FDE where padding exists), never trimmed windows.
The window excerpt runs to the next FDE 0x515a800, so it holds
the whole window plus its 15 int3 padding bytes; the cleanup
excerpt runs to the window start 0x51599e0, so it holds the whole
cleanup block plus its int3 padding; the caller excerpt runs to
the next FDE 0x515a820, so it holds the whole wrapper plus its
int3 padding.
"""

import argparse
import os
import subprocess

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- stop is the next FDE start, so the
    # file holds the whole function plus its int3 padding.
    "window.objdump.txt": ("0x51599e0", "0x515a800"),
    "cleanup.objdump.txt": ("0x5159968", "0x51599e0"),
    "collector.objdump.txt": ("0x5151970", "0x5152201"),
    "insert.objdump.txt": ("0x51538a0", "0x5153a6e"),
    "teardown.objdump.txt": ("0x514bee0", "0x514bf51"),
    "dblfmt.objdump.txt": ("0x514c050", "0x514c1b5"),
    "epilogue.objdump.txt": ("0x5155710", "0x5155bed"),
    "caller.objdump.txt": ("0x515a800", "0x515a820"),
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
