"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-shared-table-resize-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("window-5f0b420.objdump.txt", "0x5f0b420", "0x5f0b5d2"),
    ("helper-5f0a1dc.objdump.txt", "0x5f0a1dc", "0x5f0a287"),
    ("dispose-5d35070.objdump.txt", "0x5d35070", "0x5d350bc"),
]


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
    block = []
    in_block = False
    for line in frames.splitlines():
        if line.startswith("0074583c "):
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
