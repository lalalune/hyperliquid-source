#!/usr/bin/env python3
"""Export verbatim objdump excerpts for the double-accumulation windows.

Run from the clone root: python3 research/work-items/\
RE-001-double-accumulation-115/export_excerpts.py

Writes excerpts/main.txt (0x5f6c750..0x5f6cb28), excerpts/helper.txt
(0x5f6b720..0x5f6b736) and excerpts/leaf.txt (0x5f6c740..0x5f6c750) by
invoking objdump with the fixed relative binary path work/hl-node-115.bin,
so regeneration from the clone root is byte-for-byte reproducible.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOWS = {
    "main.txt": (0x5F6C750, 0x5F6CB28),
    "helper.txt": (0x5F6B720, 0x5F6B736),
    "leaf.txt": (0x5F6C740, 0x5F6C750),
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
