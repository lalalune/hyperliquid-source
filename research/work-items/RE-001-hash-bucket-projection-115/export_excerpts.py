"""Regenerate the verbatim objdump excerpt and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-hash-bucket-projection-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))


def main():
    out = subprocess.run(
        ["objdump", "-d",
         "--start-address=0x5f099b0", "--stop-address=0x5f09a42",
         "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    with open(os.path.join(HERE, "window-5f099b0.objdump.txt"), "w") as fh:
        fh.write(out)
    print("wrote window-5f099b0.objdump.txt", len(out.splitlines()), "lines")
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    block = []
    in_block = False
    for line in frames.splitlines():
        if line.startswith("00358a34 "):
            in_block = True
        elif in_block and line == "":
            break
        if in_block:
            block.append(line)
    with open(os.path.join(HERE, "frames.txt"), "w") as fh:
        fh.write("\n".join(block) + "\n")
    print("wrote frames.txt", len(block), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
