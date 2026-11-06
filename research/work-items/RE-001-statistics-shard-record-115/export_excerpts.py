"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-statistics-shard-record-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.

Re-shipped excerpts are regenerated here from the same binary and
ranges pinned in their source packets and must come out
byte-identical to the copies committed here:
- thread-seed-61c4080.objdump.txt, record_thunk.txt and record.txt
  come from open PR #3575 (RE-001-chain-histogram-snapshot-115);
  the seed and the record family were originally pinned in open PR
  #3371 (RE-001-histogram-stats-family-115);
- boundaries.tsv comes from open PR #3371;
- ctor-6071a00.objdump.txt and builder-60716d0.objdump.txt come
  from open PR #3572 (RE-001-statistics-impl-ctor-115).
The picker and the three StatisticsImpl record slots are pinned
fresh here; the shard-store layout they read (records base at
this+0x60, bucket exponent at this+0x68, level byte at this+0x20,
delegate at this+0x28) is established by the re-shipped ctor and
builder excerpts.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

# Fresh windows pinned by this packet: (file, start, stop).
EXCERPTS = [
    ("picker-60d5cd0.objdump.txt", "0x60d5cd0", "0x60d5cf0"),
    ("ticker-record-606fba0.objdump.txt", "0x606fba0", "0x606fc59"),
    ("histogram-record-606fef0.objdump.txt", "0x606fef0", "0x606ffce"),
    ("histogram-wrapper-606ffd0.objdump.txt", "0x606ffd0", "0x60700c4"),
]

# Re-shipped windows: regenerated from the same binary and ranges
# as their source packets; verify.py requires byte-equality with
# the committed copies.
RESHIPPED = [
    ("thread-seed-61c4080.objdump.txt", "0x61c4080", "0x61c4117"),
    ("record_thunk.txt", "0x606b1c0", "0x606b1cd"),
    ("record.txt", "0x606b130", "0x606b1b3"),
    ("ctor-6071a00.objdump.txt", "0x6071a00", "0x6071b60"),
    ("builder-60716d0.objdump.txt", "0x60716d0", "0x6071952"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0036ca90 ",  # picker 0x60d5cd0..0x60d5cf0
    "00369758 ",  # ticker record 0x606fba0..0x606fc59
    "00369870 ",  # histogram record 0x606fef0..0x606ffce
    "003698b8 ",  # histogram wrapper 0x606ffd0..0x60700c4
    "0076c098 ",  # thread seed 0x61c4080..0x61c4117 (re-shipped #3575)
    "00368f34 ",  # record thunk 0x606b1c0..0x606b1cd (re-shipped #3575)
    "00368f08 ",  # record impl 0x606b130..0x606b1b3 (re-shipped #3575)
    "0075bce8 ",  # StatisticsImpl ctor 0x6071a00..0x6071b60 (re-shipped #3572)
    "0075bc98 ",  # shard-store builder 0x60716d0..0x6071952 (re-shipped #3572)
]


def main():
    for name, start, stop in EXCERPTS + RESHIPPED:
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
