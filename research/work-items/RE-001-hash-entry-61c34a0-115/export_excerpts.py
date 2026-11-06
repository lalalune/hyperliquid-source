"""Regenerate the verbatim objdump excerpt and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-hash-entry-61c34a0-115/export_excerpts.py

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
         "--start-address=0x61c34a0", "--stop-address=0x61c3525",
         "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    with open(os.path.join(HERE, "main.txt"), "w") as fh:
        fh.write(out)
    print("wrote main.txt", len(out.splitlines()), "lines")
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    block = []
    in_block = False
    for line in frames.splitlines():
        if "pc=00000000061c34a0..00000000061c3525" in line:
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
