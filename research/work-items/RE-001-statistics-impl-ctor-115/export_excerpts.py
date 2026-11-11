"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-statistics-impl-ctor-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
The three HistogramImpl record-init excerpts (shared_init.txt,
bucket_count_init.txt, locked_init.txt) are regenerated here from
the same binary and ranges pinned in open PR #3371
(RE-001-histogram-stats-family-115); they are re-shipped
byte-identical as the builder's per-record init callees.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("ctor-6071a00.objdump.txt", "0x6071a00", "0x6071b60"),
    ("ctor-cleanup-6071952.objdump.txt", "0x6071952", "0x60719f2"),
    ("builder-60716d0.objdump.txt", "0x60716d0", "0x6071952"),
    ("shared_init.txt", "0x606b020", "0x606b07c"),
    ("bucket_count_init.txt", "0x606b080", "0x606b0a2"),
    ("locked_init.txt", "0x606b0c0", "0x606b10a"),
    ("allocator-60d5d50.objdump.txt", "0x60d5d50", "0x60d5db0"),
    ("free-60d5db0.objdump.txt", "0x60d5db0", "0x60d5db9"),
    ("destroyer-606fd30.objdump.txt", "0x606fd30", "0x606fd94"),
    ("noop-dtor-5d89570.objdump.txt", "0x5d89570", "0x5d89575"),
    ("mutex-init-60d50c0.objdump.txt", "0x60d50c0", "0x60d5157"),
    ("mutex-destroy-60d5170.objdump.txt", "0x60d5170", "0x60d5200"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0075bce8 ",  # ctor 0x6071a00..0x6071b60
    "0075bd30 ",  # ctor cleanup 0x6071952..0x60719f2
    "0075bc98 ",  # builder 0x60716d0..0x6071952
    "00368eb8 ",  # shared init 0x606b020..0x606b07c
    "00368ecc ",  # bucket-count init 0x606b080..0x606b0a2
    "0075b284 ",  # locked init 0x606b0c0..0x606b10a
    "0036cac8 ",  # allocator 0x60d5d50..0x60d5db0
    "0036caf4 ",  # free 0x60d5db0..0x60d5db9
    "003697d0 ",  # destroyer 0x606fd30..0x606fd94
    "0034b334 ",  # no-op dtor 0x5d89570..0x5d89575
    "00760714 ",  # mutex init 0x60d50c0..0x60d5157
    "00760760 ",  # mutex destroy 0x60d5170..0x60d5200
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
