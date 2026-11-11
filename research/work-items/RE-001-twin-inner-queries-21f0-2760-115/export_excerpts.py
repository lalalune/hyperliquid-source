"""Regenerate the verbatim disassembly excerpts for the
RE-001-twin-inner-queries-21f0-2760-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-twin-inner-queries-21f0-2760-115/export_excerpts.py [outdir]

Writes twin_tag5.txt: the whole tag-5 twin 0x61b21f0..0x61b2738;
twin_tag6.txt: the whole tag-6 twin 0x61b2760..0x61b2ca8;
gate.txt: the whole throttle gate 0x61b1930..0x61b19e7;
limit_check.txt: the whole limit check 0x61b1910..0x61b192b;
bitset.txt: the whole flag-bit setter 0x61b18b0..0x61b18c8;
frame_deliver.txt: the whole frame-and-deliver 0x61b1a10..0x61b1ac6;
varint.txt: the whole ULEB128 encoder 0x61bd410..0x61bd4e9
(shared helper, also pinned whole in the open PR #2985 packet);
framer.txt: the whole frame builder 0x61b1260..0x61b13a3
(shared helper, also pinned whole in the open PR #2985 packet);
site-<addr>.txt: verbatim windows around each direct call site of
the two twins; frames.txt: the FDE lines for all eight routines
plus both caller FDEs from readelf. The excerpts are stored
verbatim; verify.py checks that a fresh run reproduces them
byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("twin_tag5.txt", 0x61B21F0, 0x61B2738),
    ("twin_tag6.txt", 0x61B2760, 0x61B2CA8),
    ("gate.txt", 0x61B1930, 0x61B19E7),
    ("limit_check.txt", 0x61B1910, 0x61B192B),
    ("bitset.txt", 0x61B18B0, 0x61B18C8),
    ("frame_deliver.txt", 0x61B1A10, 0x61B1AC6),
    ("varint.txt", 0x61BD410, 0x61BD4E9),
    ("framer.txt", 0x61B1260, 0x61B13A3),
    ("site-5d55451.txt", 0x5D55429, 0x5D55479),
    ("site-5d555b1.txt", 0x5D55589, 0x5D555D9),
]

FDE_RANGES = [
    "00000000061b21f0..00000000061b2738",
    "00000000061b2760..00000000061b2ca8",
    "00000000061b1930..00000000061b19e7",
    "00000000061b1910..00000000061b192b",
    "00000000061b18b0..00000000061b18c8",
    "00000000061b1a10..00000000061b1ac6",
    "00000000061bd410..00000000061bd4e9",
    "00000000061b1260..00000000061b13a3",
    "0000000005d553c0..0000000005d554e4",
    "0000000005d55520..0000000005d55644",
]


def main():
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else PACKET
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (outdir / name).write_text(text)
        print("wrote %s (%d bytes)" % (name, len(text)))
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    lines = [ln for ln in frames.splitlines()
             if any(r in ln for r in FDE_RANGES)]
    if len(lines) != len(FDE_RANGES):
        missing = [r for r in FDE_RANGES
                   if not any(r in ln for ln in lines)]
        raise SystemExit("missing FDE lines for: %s" % missing)
    (outdir / "frames.txt").write_text("\n".join(lines) + "\n")
    print("wrote frames.txt (%d lines)" % len(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
