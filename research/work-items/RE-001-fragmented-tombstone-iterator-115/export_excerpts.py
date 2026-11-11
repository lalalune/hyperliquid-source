"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-fragmented-tombstone-iterator-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout. The
constructors 0x5f31380/0x5f315a0 and the cache ctor 0x5f37410 are NOT
re-shipped here: they are windows of open PR #3674 (same binary, so
regeneration there reproduces them); this packet cites them by
contract, with the layout cross-checked against the destructor and
the seek/scan windows.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("maxseq-5f32900.objdump.txt", "0x5f32900", "0x5f32a0a"),
    ("seek-covering-5f316d0.objdump.txt", "0x5f316d0", "0x5f31973"),
    ("seekforprev-covering-5f31980.objdump.txt", "0x5f31980", "0x5f31c7d"),
    ("scan-forward-5f31c80.objdump.txt", "0x5f31c80", "0x5f31ead"),
    ("seek-top-first-5f31eb0.objdump.txt", "0x5f31eb0", "0x5f32099"),
    ("seek-5f320a0.objdump.txt", "0x5f320a0", "0x5f320e1"),
    ("scan-backward-5f320f0.objdump.txt", "0x5f320f0", "0x5f3230b"),
    ("seek-top-last-5f32310.objdump.txt", "0x5f32310", "0x5f324ea"),
    ("seekforprev-5f324f0.objdump.txt", "0x5f324f0", "0x5f32531"),
    ("topnext-5f32540.objdump.txt", "0x5f32540", "0x5f32719"),
    ("topprev-5f32720.objdump.txt", "0x5f32720", "0x5f328fa"),
    ("dtor-d1-5f32a10.objdump.txt", "0x5f32a10", "0x5f32b7d"),
    ("dtor-d0-5f32b80.objdump.txt", "0x5f32b80", "0x5f32cfd"),
    ("valid-5f2e8f0.objdump.txt", "0x5f2e8f0", "0x5f2e90e"),
    ("seektofirst-5f2e8d0.objdump.txt", "0x5f2e8d0", "0x5f2e8e9"),
    ("seektolast-5f2ee70.objdump.txt", "0x5f2ee70", "0x5f2ee92"),
    ("next-5f2eea0.objdump.txt", "0x5f2eea0", "0x5f2eee4"),
    ("prev-5f2eef0.objdump.txt", "0x5f2eef0", "0x5f2ef60"),
    ("key-5eba980.objdump.txt", "0x5eba980", "0x5ebaa54"),
    ("value-endkey-5eba910.objdump.txt", "0x5eba910", "0x5eba924"),
    ("nextandgetresult-5df7ce0.objdump.txt", "0x5df7ce0", "0x5df7d24"),
    ("slot11-userkey-5df7650.objdump.txt", "0x5df7650", "0x5df7667"),
    ("status-5f2e7b0.objdump.txt", "0x5f2e7b0", "0x5f2e7cc"),
    ("ret1-a-5df7670.objdump.txt", "0x5df7670", "0x5df767a"),
    ("ret1-b-5df7680.objdump.txt", "0x5df7680", "0x5df768a"),
    ("ret0-a-5df7690.objdump.txt", "0x5df7690", "0x5df7697"),
    ("voidret-5d485b0.objdump.txt", "0x5d485b0", "0x5d485b5"),
    ("ret0-b-5f2e790.objdump.txt", "0x5f2e790", "0x5f2e797"),
    ("ret1-c-5f2e7a0.objdump.txt", "0x5f2e7a0", "0x5f2e7aa"),
    ("status-builder-5df7800.objdump.txt", "0x5df7800", "0x5df7871"),
    ("voidret-b-5df76d0.objdump.txt", "0x5df76d0", "0x5df76d5"),
    ("voidret-c-5df76e0.objdump.txt", "0x5df76e0", "0x5df76e5"),
    ("ret0-c-5df7640.objdump.txt", "0x5df7640", "0x5df7647"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by readelf --debug-dump=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0035afec ", "0035ac64 ", "0035accc ", "0035ad4c ", "0035adb4 ",
    "0035ae18 ", "0035ae38 ", "0035aea0 ", "0035af04 ", "0035af24 ",
    "0035af88 ", "0035b018 ", "0035b044 ", "0035a738 ", "0035a724 ",
    "0035a85c ", "0035a870 ", "0035a884 ", "00355a78 ", "00355a34 ",
    "0034fd34 ", "0034faf8 ", "0035a648 ", "0034fb10 ", "0034fb24 ",
    "0034fb38 ", "00348418 ", "0035a620 ", "0035a634 ", "0034fc40 ",
    "0034fb88 ", "0034fb9c ", "0034fae4 ",
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
