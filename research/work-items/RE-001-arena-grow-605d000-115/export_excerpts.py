"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-arena-grow-605d000-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("main-605d000.objdump.txt", "0x605d000", "0x605d3a1"),
    ("helpers-60d4f70.objdump.txt", "0x60d4f70", "0x60d4ff8"),
    ("create-60d5000.objdump.txt", "0x60d5000", "0x60d5094"),
    ("notify-605e830.objdump.txt", "0x605e830", "0x605e859"),
    ("cleanup-605cfd6.objdump.txt", "0x605cfd6", "0x605cffb"),
]

# .eh_frame section-relative offsets of the eight FDEs, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = ["0075a0ac ", "0036c9ec ", "0036ca00 ", "0036ca28 ",
                  "0036ca3c ", "0036ca58 ", "0036782c ", "0075a0fc "]


def main():
    out_dir = os.path.join(HERE, "excerpts")
    os.makedirs(out_dir, exist_ok=True)
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=" + start, "--stop-address=" + stop,
             "work/hl-node-115.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(out_dir, name), "w") as fh:
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
    with open(os.path.join(out_dir, "frames.txt"), "w") as fh:
        fh.write("\n".join(blocks))
    print("wrote frames.txt", len(blocks), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
