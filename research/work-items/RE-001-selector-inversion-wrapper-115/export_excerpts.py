#!/usr/bin/env python3
"""Export the verbatim objdump excerpts for the selector-inversion packet.

Run from the clone root: python3 research/work-items/\\
RE-001-selector-inversion-wrapper-115/export_excerpts.py

Writes excerpts/wrapper.txt (0x5ebd130..0x5ebd1b8) and
excerpts/selector.txt (0x5f6c2a0..0x5f6c2f3) by invoking objdump
with the fixed relative binary path work/hl-node-115.bin, so
regeneration from the clone root is byte-for-byte reproducible.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOWS = {
    "wrapper.txt": (0x5EBD130, 0x5EBD1B8),
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
