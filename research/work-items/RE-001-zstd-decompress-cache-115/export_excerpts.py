"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-zstd-decompress-cache-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("claim-61c1e10.objdump.txt", "0x61c1e10", "0x61c1f0f"),
    ("claim-landing-61c1dec.objdump.txt", "0x61c1dec", "0x61c1e0a"),
    ("create-dctx-628c0b0.objdump.txt", "0x628c0b0", "0x628c1d6"),
    ("table-ctor-61c1f30.objdump.txt", "0x61c1f30", "0x61c20b6"),
    ("static-init-61c20d0.objdump.txt", "0x61c20d0", "0x61c2109"),
    ("getter-61c2120.objdump.txt", "0x61c2120", "0x61c21a6"),
    ("teardown-61c1d60.objdump.txt", "0x61c1d60", "0x61c1dec"),
    ("factory-61c1ce0.objdump.txt", "0x61c1ce0", "0x61c1d5a"),
    ("picker-60d5cd0.objdump.txt", "0x60d5cd0", "0x60d5cf0"),
    ("seed-61c4080.objdump.txt", "0x61c4080", "0x61c4117"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0076be64 ", "0076bea4 ", "0037fd78 ", "0076bec4 ", "0076bf04 ",
    "0076bf50 ", "0076be24 ", "0076bdc0 ", "0036ca90 ", "0076c098 ",
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
