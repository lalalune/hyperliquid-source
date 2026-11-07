"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-other-picker-seed-consumers-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.

Re-shipped excerpts are regenerated here from the same binary and
ranges pinned in their source packets and must come out
byte-identical to the copies committed here:
- picker-60d5cd0.objdump.txt and thread-seed-61c4080.objdump.txt
  come from open PR #3613 (RE-001-statistics-shard-record-115);
  the picker and the seed were originally pinned in open PR #3371
  (RE-001-histogram-stats-family-115) and #3575.
The nine seed-host windows are pinned fresh here; the already-pinned
seed consumers (StatisticsImpl record slots #3613, the tombstone
iterator factory 0x5f0a9c0 in the merged RE-001-range-tombstone-cache-115
packet, the shard refresh 0x605e170 in the merged
RE-001-shard-refresh-605e170-115 packet, the hash-index insert
0x605f340 in the merged RE-001-chain-histogram-snapshot-115 /
RE-001-hashlinklist-insert-115 packets, and the slot claim 0x61c1e10
in the merged RE-001-zstd-decompress-cache-115 packet) are cited in
records.json, not re-shipped.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

# Fresh windows pinned by this packet: (file, start, stop).
EXCERPTS = [
    ("seed-host-5f6b000.objdump.txt", "0x5f6b000", "0x5f6b516"),
    ("seed-host-5f999d0.objdump.txt", "0x5f999d0", "0x5f9a478"),
    ("seed-host-5fca940.objdump.txt", "0x5fca940", "0x5fcabdc"),
    ("seed-host-6063150.objdump.txt", "0x6063150", "0x6063229"),
    ("seed-host-6066b80.objdump.txt", "0x6066b80", "0x6066d61"),
    ("seed-host-6066f20.objdump.txt", "0x6066f20", "0x6067450"),
    ("seed-host-60e5610.objdump.txt", "0x60e5610", "0x60e5a39"),
    ("seed-host-60f4a00.objdump.txt", "0x60f4a00", "0x60f4cb5"),
    ("seed-host-616f960.objdump.txt", "0x616f960", "0x616fb83"),
]

# Re-shipped windows: regenerated from the same binary and ranges
# as their source packets; verify.py requires byte-equality with
# the committed copies.
RESHIPPED = [
    ("picker-60d5cd0.objdump.txt", "0x60d5cd0", "0x60d5cf0"),
    ("thread-seed-61c4080.objdump.txt", "0x61c4080", "0x61c4117"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "00748d10 ",  # oneshot-record builder 0x5f6b000..0x5f6b516
    "0074a920 ",  # oneshot-record lookup 0x5f999d0..0x5f9a478
    "0074d9b8 ",  # perf-gated flag wait 0x5fca940..0x5fcabdc
    "00368248 ",  # SkipListRep slot 0 0x6063150..0x6063229
    "0075a9f4 ",  # randomised descent 0x6066b80..0x6066d61
    "0075aa88 ",  # SkipListRep slot 14 0x6066f20..0x6067450
    "00761810 ",  # ZSTD CCtx consumer 0x60e5610..0x60e5a39
    "0076253c ",  # bitmap-node ctor 0x60f4a00..0x60f4cb5
    "00767ab8 ",  # 0x200-byte ctor 0x616f960..0x616fb83
    "0036ca90 ",  # picker 0x60d5cd0..0x60d5cf0 (re-shipped #3613)
    "0076c098 ",  # thread seed 0x61c4080..0x61c4117 (re-shipped #3613)
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
