"""Regenerate the verbatim objdump excerpt and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-two-list-aggregate-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("main-5f13130.objdump.txt", "0x5f13130", "0x5f13231"),
]

# .eh_frame section-relative offset of the window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = ["0035909c "]


def main():
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=" + start, "--stop-address=" + stop,
             "work/hl-node-115.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(out)
        print("wrote", name, len(out.splitlines()), "lines")
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    blocks = []
    for prefix in FRAME_PREFIXES:
        block = []
        in_block = False
        for line in frames.splitlines():
            if line.startswith(prefix):
                in_block = True
            elif in_block and line == "":
                break
            if in_block:
                block.append(line)
        blocks.extend(block)
        blocks.append("")
    with open(os.path.join(HERE, "frames.txt"), "w") as fh:
        fh.write("\n".join(blocks))
    print("wrote frames.txt", len(blocks), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
