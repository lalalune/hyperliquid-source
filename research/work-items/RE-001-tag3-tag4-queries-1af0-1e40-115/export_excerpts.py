"""Regenerate the verbatim disassembly excerpts for the
RE-001-tag3-tag4-queries-1af0-1e40-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-tag3-tag4-queries-1af0-1e40-115/export_excerpts.py [outdir]

Writes tag3.txt: the whole tag-3 query 0x61b1af0..0x61b1e18;
tag4.txt: the whole tag-4 query 0x61b1e40..0x61b21ca;
gate.txt: the whole throttle gate 0x61b1930..0x61b19e7;
limit_check.txt: the whole limit check 0x61b1910..0x61b192b;
bitset.txt: the whole flag-bit setter 0x61b18b0..0x61b18c8;
frame_deliver.txt: the whole frame-and-deliver 0x61b1a10..0x61b1ac6;
varint.txt: the whole ULEB128 encoder 0x61bd410..0x61bd4e9
(shared helper, also pinned whole in the open PR #3001 packet);
framer.txt: the whole frame builder 0x61b1260..0x61b13a3
(shared helper, also pinned whole in the open PR #3001 packet);
cleanup_tag3.txt: the shared cleanup fragment 0x61b1ac6..0x61b1aeb
the tag-3 landing pad jumps into (_M_dispose, canary check,
_Unwind_Resume); cleanup_tag4.txt: the cleanup fragment
0x61b1e18..0x61b1e3d the tag-4 landing pad jumps into;
site-<addr>.txt: verbatim windows around each direct call site
of the two queries (window starts aligned to an instruction
boundary at or after site-0x28); frames.txt: the FDE lines for
all eight routines plus the six caller FDEs from readelf. The
excerpts are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("tag3.txt", 0x61B1AF0, 0x61B1E18),
    ("tag4.txt", 0x61B1E40, 0x61B21CA),
    ("gate.txt", 0x61B1930, 0x61B19E7),
    ("limit_check.txt", 0x61B1910, 0x61B192B),
    ("bitset.txt", 0x61B18B0, 0x61B18C8),
    ("frame_deliver.txt", 0x61B1A10, 0x61B1AC6),
    ("varint.txt", 0x61BD410, 0x61BD4E9),
    ("framer.txt", 0x61B1260, 0x61B13A3),
    ("cleanup_tag3.txt", 0x61B1AC6, 0x61B1AEB),
    ("cleanup_tag4.txt", 0x61B1E18, 0x61B1E3D),
    ("site-5e8f565.txt", 0x5E8F53E, 0x5E8F58D),
    ("site-5e8f5a4.txt", 0x5E8F57E, 0x5E8F5CC),
    ("site-5e90e06.txt", 0x5E90DDE, 0x5E90E2E),
    ("site-5e90e42.txt", 0x5E90E1C, 0x5E90E6A),
    ("site-5e922ca.txt", 0x5E922A8, 0x5E922F2),
    ("site-5e92ebe.txt", 0x5E92E97, 0x5E92EE6),
    ("site-5e92efa.txt", 0x5E92ED4, 0x5E92F22),
    ("site-5d61261.txt", 0x5D6123B, 0x5D61289),
    ("site-5e706b9.txt", 0x5E70697, 0x5E706E1),
    ("site-5e7cd24.txt", 0x5E7CCFE, 0x5E7CD4C),
]

FDE_RANGES = [
    "00000000061b1af0..00000000061b1e18",
    "00000000061b1e40..00000000061b21ca",
    "00000000061b1930..00000000061b19e7",
    "00000000061b1910..00000000061b192b",
    "00000000061b18b0..00000000061b18c8",
    "00000000061b1a10..00000000061b1ac6",
    "00000000061bd410..00000000061bd4e9",
    "00000000061b1260..00000000061b13a3",
    "0000000005e8ef90..0000000005e904bd",
    "0000000005e909d0..0000000005e91cd2",
    "0000000005e91ed0..0000000005e9406a",
    "0000000005d60fa0..0000000005d623e0",
    "0000000005e704c0..0000000005e7151e",
    "0000000005e7ca80..0000000005e7d919",
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
