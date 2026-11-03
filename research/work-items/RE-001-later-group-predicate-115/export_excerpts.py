#!/usr/bin/env python3
"""Export the verbatim objdump excerpts for the later-group predicate packet.

Run from the clone root: python3 research/work-items/\\
RE-001-later-group-predicate-115/export_excerpts.py

Writes excerpts/predicate.txt (0x5f6d600..0x5f6d6f4) and
excerpts/selector.txt (0x5f6c2a0..0x5f6c2f3) by invoking objdump
with the fixed relative binary path work/hl-node-115.bin, so
regeneration from the clone root is byte-for-byte reproducible.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOWS = {
    "predicate.txt": (0x5F6D600, 0x5F6D6F4),
    "selector.txt": (0x5F6C2A0, 0x5F6C2F3),
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
