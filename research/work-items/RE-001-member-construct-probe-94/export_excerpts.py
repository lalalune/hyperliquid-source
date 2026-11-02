"""Regenerate the verbatim objdump excerpts in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-member-construct-probe-94/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

WINDOWS = {
    "window.txt": (0x5169250, 0x5169377),
    "cleanup.txt": (0x5169220, 0x516924C),
    "zero_init.txt": (0x541CA90, 0x541CAA4),
    "teardown.txt": (0x541CAB0, 0x541CB01),
}


def main():
    for name, (start, stop) in WINDOWS.items():
        out = subprocess.run(
            [
                "objdump", "-d",
                "--start-address=%#x" % start,
                "--stop-address=%#x" % stop,
                "work/hl-node-94.bin",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(out)
        print("wrote", name, len(out.splitlines()), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
