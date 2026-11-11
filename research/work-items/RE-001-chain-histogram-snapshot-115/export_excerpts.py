"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-chain-histogram-snapshot-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
The five HistogramImpl excerpts (bucket_count_init, locked_init,
record_thunk, record, tostring_entry) are regenerated here from the
same binary and ranges pinned in open PR #3371
(RE-001-histogram-stats-family-115); they are re-shipped
byte-identical as the host's histogram callees.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("host-605feb0.objdump.txt", "0x605feb0", "0x6060199"),
    ("arena-ctor-605dd90.objdump.txt", "0x605dd90", "0x605dfcd"),
    ("index-builder-605f290.objdump.txt", "0x605f290", "0x605f33a"),
    ("index-insert-605f340.objdump.txt", "0x605f340", "0x605f6d5"),
    ("log-gate-5fcef60.objdump.txt", "0x5fcef60", "0x5fcf043"),
    ("size-normalizer-605cfa0.objdump.txt", "0x605cfa0", "0x605cfd6"),
    ("counter-add-605e830.objdump.txt", "0x605e830", "0x605e859"),
    ("thread-seed-61c4080.objdump.txt", "0x61c4080", "0x61c4117"),
    ("bucket_count_init.txt", "0x606b080", "0x606b0a2"),
    ("locked_init.txt", "0x606b0c0", "0x606b10a"),
    ("record_thunk.txt", "0x606b1c0", "0x606b1cd"),
    ("record.txt", "0x606b130", "0x606b1b3"),
    ("tostring_entry.txt", "0x606bc90", "0x606bcd3"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0075a4a8 ",  # host 0x605feb0..0x6060199
    "0075a208 ",  # arena ctor 0x605dd90..0x605dfcd
    "00367b98 ",  # index builder 0x605f290..0x605f33a
    "00367bb4 ",  # index insert 0x605f340..0x605f6d5
    "00362334 ",  # log gate 0x5fcef60..0x5fcf043
    "00367680 ",  # size normalizer 0x605cfa0..0x605cfd6
    "0036782c ",  # counter add 0x605e830..0x605e859
    "0076c098 ",  # thread seed 0x61c4080..0x61c4117
    "00368ecc ",  # bucket-count init 0x606b080..0x606b0a2
    "0075b284 ",  # locked init 0x606b0c0..0x606b10a
    "00368f34 ",  # record thunk 0x606b1c0..0x606b1cd
    "00368f08 ",  # record 0x606b130..0x606b1b3
    "00368ffc ",  # ToString entry 0x606bc90..0x606bcd3
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
        if not block:
            print("FAIL: no FDE block for prefix %s" % prefix.strip())
            return 1
        blocks.append("\n".join(block))
    with open(os.path.join(HERE, "frames.txt"), "w") as fh:
        fh.write("\n\n".join(blocks) + "\n")
    print("wrote frames.txt", len(blocks), "blocks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
