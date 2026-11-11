"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-fragmented-range-tombstones-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout. The
cache-ctor, Cleanable ctor/dtor and list-release excerpts are
re-shipped byte-identically from open PR #3674 (the same binary, so
regeneration reproduces them); see README for the credit.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("host-5f0a3d0.objdump.txt", "0x5f0a3d0", "0x5f0a909"),
    ("readopts-60b21f0.objdump.txt", "0x60b21f0", "0x60b2262"),
    ("introsort-5f053d0.objdump.txt", "0x5f053d0", "0x5f05678"),
    ("insertion-5f05120.objdump.txt", "0x5f05120", "0x5f051f5"),
    ("adjust-heap-5f04f80.objdump.txt", "0x5f04f80", "0x5f0511d"),
    ("cache-ctor-5f37410.objdump.txt", "0x5f37410", "0x5f37e31"),
    ("cleanable-ctor-61bd0c0.objdump.txt", "0x61bd0c0", "0x61bd0d4"),
    ("cleanable-dtor-61bd0e0.objdump.txt", "0x61bd0e0", "0x61bd131"),
    ("list-release-5f059b0.objdump.txt", "0x5f059b0", "0x5f05b79"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by readelf --debug-dump=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "00745700 ", "0036bc40 ", "00358434 ", "00358394 ", "00358344 ",
    "00746fc8 ", "003763d4 ", "0076b880 ", "00358558 ",
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
