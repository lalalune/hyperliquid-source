#!/usr/bin/env python3
"""Export the verbatim objdump excerpts for the realloc-insert packet.

Run from the clone root: python3 research/work-items/\
RE-001-realloc-insert-5d90f50-115/export_excerpts.py

Writes excerpts/grow.txt (0x5d90f50..0x5d910d5) and
excerpts/caller.txt (0x5f13e00..0x5f13e93) by invoking objdump
with the fixed relative binary path work/hl-node-115.bin, so
regeneration from the clone root is byte-for-byte reproducible.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOWS = {
    "grow.txt": (0x5D90F50, 0x5D910D5),
    "caller.txt": (0x5F13E00, 0x5F13E93),
}


def main():
    outdir = os.path.join(HERE, "excerpts")
    os.makedirs(outdir, exist_ok=True)
    for name, (start, stop) in WINDOWS.items():
        proc = subprocess.run(
            ["objdump", "-d",
             "--start-address=%#x" % start, "--stop-address=%#x" % stop,
             "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True)
        with open(os.path.join(outdir, name), "w") as f:
            f.write(proc.stdout)
        print("wrote", name)


if __name__ == "__main__":
    sys.exit(main())
