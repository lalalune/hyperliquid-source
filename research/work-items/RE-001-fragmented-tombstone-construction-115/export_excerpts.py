"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-fragmented-tombstone-construction-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("ctor-list-5f31470.objdump.txt", "0x5f31470", "0x5f3159e"),
    ("split-by-snapshot-5f33950.objdump.txt", "0x5f33950", "0x5f33b36"),
    ("probe-5f31250.objdump.txt", "0x5f31250", "0x5f3137e"),
    ("once-init-5f2eb90.objdump.txt", "0x5f2eb90", "0x5f2ecc2"),
    ("newiterator-5f29140.objdump.txt", "0x5f29140", "0x5f294ce"),
    ("block-table-new-60fcee0.objdump.txt", "0x60fcee0", "0x60fcf6a"),
    ("truncated-split-5f269e0.objdump.txt", "0x5f269e0", "0x5f26ed5"),
    ("map-emplace-5f33670.objdump.txt", "0x5f33670", "0x5f338fa"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0035abcc ", "00746e64 ", "00746dbc ", "0035a7ac ",
    "00746d44 ", "00762a1c ", "00746bd0 ", "0035b15c ",
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
