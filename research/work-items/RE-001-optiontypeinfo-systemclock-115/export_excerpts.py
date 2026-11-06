"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-optiontypeinfo-systemclock-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("builder-5fd0180.objdump.txt", "0x5fd0180", "0x5fd02f2"),
    ("manager-5fcc660.objdump.txt", "0x5fcc660", "0x5fcc68d"),
    ("invoker-5fd4c30.objdump.txt", "0x5fd4c30", "0x5fd4cc1"),
    ("host-5fd46c0.objdump.txt", "0x5fd46c0", "0x5fd4c2e"),
    ("accessor-5fe2680.objdump.txt", "0x5fe2680", "0x5fe2756"),
    ("default-init-5fd20d0.objdump.txt", "0x5fd20d0", "0x5fd241d"),
    ("status-move-5fcdf70.objdump.txt", "0x5fcdf70", "0x5fcdfdf"),
    ("copy-5e332c0.objdump.txt", "0x5e332c0", "0x5e3354f"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0074e234 ", "00361cd8 ", "003625b4 ", "0074e888 ",
    "0074fe50 ", "0074e43c ", "003621cc ", "0073c9d0 ",
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
