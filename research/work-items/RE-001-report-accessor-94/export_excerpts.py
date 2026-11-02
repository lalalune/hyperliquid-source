#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-report-accessor-94/export_excerpts.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. The excerpts are whole functions (plus int3 padding to
the next FDE where padding exists), never trimmed windows. The
cleanup excerpt is the exception-cleanup block immediately before
the window; it has its own FDE (0x5158ebe..0x5158eee) plus two
int3 padding bytes to the window start. Thunk1 has no padding: the
bytes at 0x515914e belong to another function's cleanup and are
deliberately excluded.
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
    "window.objdump.txt": ("0x5158ef0", "0x5159130"),
    "cleanup.objdump.txt": ("0x5158ebe", "0x5158ef0"),
    "thunk0.objdump.txt": ("0x5159130", "0x5159140"),
    "thunk1.objdump.txt": ("0x5159140", "0x515914e"),
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
    print("wrote %d excerpts to %s" % (len(RANGES), out_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
