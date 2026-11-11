"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-zstd-compress-cache-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("factory-61c1c10.objdump.txt", "0x61c1c10", "0x61c1cc8"),
    ("factory-landing-61c1bee.objdump.txt", "0x61c1bee", "0x61c1c03"),
    ("create-cctx-6218920.objdump.txt", "0x6218920", "0x6218996"),
    ("reset-62188a0.objdump.txt", "0x62188a0", "0x621891a"),
    ("free-cdict-62187a0.objdump.txt", "0x62187a0", "0x621889b"),
    ("setparam-6212010.objdump.txt", "0x6212010", "0x6212101"),
    ("apply-6211a10.objdump.txt", "0x6211a10", "0x621200c"),
    ("range-check-62119e0.objdump.txt", "0x62119e0", "0x6211a08"),
    ("bounds-62117e0.objdump.txt", "0x62117e0", "0x62119d9"),
    ("refresh-5f041d0.objdump.txt", "0x5f041d0", "0x5f0441c"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0076bd4c ", "0076bda0 ", "0037bf64 ", "0037bf44 ", "0037bee4 ",
    "0037b5e0 ", "0037b5c4 ", "0037b5ac ", "0037b598 ", "0074527c ",
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
