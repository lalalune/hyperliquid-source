"""Regenerate the verbatim objdump excerpts in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-probe-gated-lookup-94/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

WINDOWS = {
    "window.txt": (0x516CA20, 0x516D0D4),
    "driver.txt": (0x516C7E0, 0x516C9D7),
    "transform.txt": (0x51922D0, 0x51923DA),
    "move_helper.txt": (0x5164CE0, 0x5164D49),
    "timer_destructor.txt": (0x5165320, 0x516537B),
    "thunk.txt": (0x516AA20, 0x516AA43),
    "hash.txt": (0x5422E70, 0x5422EF5),
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
