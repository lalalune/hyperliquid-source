#!/usr/bin/env python3
"""Export verbatim objdump excerpts for the need-score predicate windows.

Run from the clone root: python3 research/work-items/\\
RE-001-need-score-predicate-115/export_excerpts.py

Writes excerpts/predicate.txt (0x5dbd6d0..0x5dbd7b6) and
excerpts/helper.txt (0x5f6b720..0x5f6b736) by invoking objdump with the
fixed relative binary path work/hl-node-115.bin, so regeneration from
the clone root is byte-for-byte reproducible.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOWS = {
    "predicate.txt": (0x5DBD6D0, 0x5DBD7B6),
    "helper.txt": (0x5F6B720, 0x5F6B736),
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
