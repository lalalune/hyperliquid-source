#!/usr/bin/env python3
"""Export the verbatim objdump excerpt for the element-rate pass window.

Run from the clone root: python3 research/work-items/\\
RE-001-element-rate-pass-115/export_excerpts.py

Writes excerpts/pass.txt (0x5f6b660..0x5f6b715) by invoking objdump with
the fixed relative binary path work/hl-node-115.bin, so regeneration
from the clone root is byte-for-byte reproducible.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOWS = {
    "pass.txt": (0x5F6B660, 0x5F6B715),
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
