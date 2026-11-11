"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-bitmap-node-callers-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.

Re-shipped excerpts are regenerated here from the same binary and
ranges pinned in their source packets and must come out
byte-identical to the copies committed here:
- ctor-60f4a00.objdump.txt comes from open PR #4156
  (RE-001-other-picker-seed-consumers-115); the bitmap-node ctor
  was originally pinned in open PR #3613 and #4156.
The nine host windows and the ctor's helpers are pinned fresh here.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

# Fresh windows pinned by this packet: (file, start, stop).
# Ranges are the .eh_frame FDE ranges for each function.
EXCERPTS = [
    ("dtor-60f4900.objdump.txt", "0x60f4900", "0x60f4966"),
    ("mag-helper-60f4840.objdump.txt", "0x60f4840", "0x60f48a0"),
    ("kind-helper-60f48a0.objdump.txt", "0x60f48a0", "0x60f4900"),
    ("split-helper-612ceb0.objdump.txt", "0x612ceb0", "0x612cece"),
    ("trail-u16-helper-612ce30.objdump.txt", "0x612ce30", "0x612ce48"),
    ("factory-60f4d10.objdump.txt", "0x60f4d10", "0x60f5069"),
    ("materialize-60f50c0.objdump.txt", "0x60f50c0", "0x60f55a1"),
    ("slot-release-6106790.objdump.txt", "0x6106790", "0x6106834"),
    ("poll-copy-61841a0.objdump.txt", "0x61841a0", "0x618427d"),
    ("host-60e3ad0.objdump.txt", "0x60e3ad0", "0x60e3d01"),
    ("host-6117ed0.objdump.txt", "0x6117ed0", "0x6119dad"),
    ("host-612a800.objdump.txt", "0x612a800", "0x612a887"),
    ("host-612a8a0.objdump.txt", "0x612a8a0", "0x612a91f"),
    ("host-612a940.objdump.txt", "0x612a940", "0x612a9bf"),
    ("host-612a9e0.objdump.txt", "0x612a9e0", "0x612aa5f"),
    ("host-612aa80.objdump.txt", "0x612aa80", "0x612aaff"),
    ("host-61849e0.objdump.txt", "0x61849e0", "0x6184b7a"),
    ("host-6186e30.objdump.txt", "0x6186e30", "0x618a96f"),
]

# Re-shipped windows: regenerated from the same binary and ranges
# as their source packets; verify.py requires byte-equality with
# the committed copies.
RESHIPPED = [
    ("ctor-60f4a00.objdump.txt", "0x60f4a00", "0x60f4cb5"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "00762504 ",  # dtor 0x60f4900..0x60f4966
    "0036e650 ",  # magnitude helper 0x60f4840..0x60f48a0
    "0036e66c ",  # kind helper 0x60f48a0..0x60f4900
    "00370498 ",  # sign/magnitude split helper 0x612ceb0..0x612cece
    "00370440 ",  # trailing-u16 helper 0x612ce30..0x612ce48
    "007625c0 ",  # factory 0x60f4d10..0x60f5069
    "00762624 ",  # materialize 0x60f50c0..0x60f55a1
    "0076332c ",  # slot release 0x6106790..0x6106834
    "007688f4 ",  # poll-copy 0x61841a0..0x618427d
    "00761660 ",  # table host 0x60e3ad0..0x60e3d01
    "00763edc ",  # slot-replace host 0x6117ed0..0x6119dad
    "007646f4 ",  # reset helper A 0x612a800..0x612a887
    "00764764 ",  # reset helper B 0x612a8a0..0x612a91f
    "007647d4 ",  # reset helper C 0x612a940..0x612a9bf
    "00764844 ",  # reset helper D 0x612a9e0..0x612aa5f
    "007648b4 ",  # reset helper E 0x612aa80..0x612aaff
    "007689ac ",  # oneshot factory host 0x61849e0..0x6184b7a
    "00768dac ",  # oneshot factory host 0x6186e30..0x618a96f
    "0076253c ",  # ctor 0x60f4a00..0x60f4cb5 (re-shipped #4156)
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
