"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-range-tombstone-cache-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("host-5f0a9c0.objdump.txt", "0x5f0a9c0", "0x5f0b04c"),
    ("shard-605e170.objdump.txt", "0x605e170", "0x605e20d"),
    ("picker-60d5cd0.objdump.txt", "0x60d5cd0", "0x60d5cf0"),
    ("seed-61c4080.objdump.txt", "0x61c4080", "0x61c4117"),
    ("ctor-a-5f31380.objdump.txt", "0x5f31380", "0x5f3146f"),
    ("ctor-b-5f315a0.objdump.txt", "0x5f315a0", "0x5f316ce"),
    ("cache-ctor-5f37410.objdump.txt", "0x5f37410", "0x5f37e31"),
    ("cleanable-ctor-61bd0c0.objdump.txt", "0x61bd0c0", "0x61bd0d4"),
    ("cleanable-dtor-61bd0e0.objdump.txt", "0x61bd0e0", "0x61bd131"),
    ("release-5d350c0.objdump.txt", "0x5d350c0", "0x5d35145"),
    ("list-release-5f059b0.objdump.txt", "0x5f059b0", "0x5f05b79"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "00745774 ", "003677d0 ", "0036ca90 ", "0076c098 ",
    "0035ab84 ", "0035ac18 ", "00746fc8 ", "003763d4 ", "0076b880 ",
    "00346bc4 ", "00358558 ",
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
