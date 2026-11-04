"""Regenerate the verbatim objdump excerpts in this packet.

Run from the repository root:
    python3 research/work-items/RE-014-memtable-iterator-seek-gate-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

WINDOWS = {
    "window-5f08c40.objdump.txt": (0x5F08C40, 0x5F09047),
    "timer-5f05950.objdump.txt": (0x5F05950, 0x5F059AB),
}


def main():
    for name, (start, stop) in WINDOWS.items():
        out = subprocess.run(
            [
                "objdump", "-d",
                "--start-address=%#x" % start,
                "--stop-address=%#x" % stop,
                "work/hl-node-115.bin",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(out)
        print("wrote", name, len(out.splitlines()), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
