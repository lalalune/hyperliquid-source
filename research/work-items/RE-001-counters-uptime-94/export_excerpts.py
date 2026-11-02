#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-counters-uptime-94/export_excerpts.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. The excerpts are whole functions (plus int3 padding
to the next FDE where padding exists), never trimmed windows.
The cleanup excerpt starts at 0x515914e, the first cleanup entry;
the two accessor flag-fixing thunks at 0x5159130 and 0x5159140
belong to the 0x5158ef0 accessor and are deliberately excluded.
The caller excerpt is the whole 0x5159950 wrapper plus its single
int3 padding byte to 0x5159968.
"""

import argparse
import os
import subprocess

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- stop is the next FDE start, so the
    # file holds the whole function plus its int3 padding.
    "window.objdump.txt": ("0x5159180", "0x5159950"),
    "cleanup.objdump.txt": ("0x515914e", "0x5159180"),
    "find.objdump.txt": ("0x5153a70", "0x5153bb6"),
    "insert.objdump.txt": ("0x5153650", "0x515383b"),
    "dblfmt.objdump.txt": ("0x514c050", "0x514c1b5"),
    "strctor.objdump.txt": ("0x514b6d0", "0x514b7b3"),
    "compare.objdump.txt": ("0x514b340", "0x514b38e"),
    "moveassign.objdump.txt": ("0x514b4f0", "0x514b5c8"),
    "caller.objdump.txt": ("0x5159950", "0x5159968"),
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
