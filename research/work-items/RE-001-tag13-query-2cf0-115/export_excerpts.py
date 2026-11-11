"""Regenerate the verbatim disassembly excerpts for the
RE-001-tag13-query-2cf0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-tag13-query-2cf0-115/export_excerpts.py [outdir]

Writes tag13.txt: the whole tag-13 query 0x61b2cf0..0x61b3596;
mismatch.txt: the whole count-mismatch helper 0x61cf670..0x61cf767;
mismatch_cleanup.txt: the helper's cleanup fragment
0x61cf650..0x61cf666 (its own FDE; frees *(rbx+0x08) via _ZdaPv
when non-null, then _Unwind_Resume);
cleanup_shared.txt: the shared cleanup fragment
0x61b2ca8..0x61b2ce2 (its own FDE; the twin tag-6 routine's
cleanup, also entered by this routine's two landing pads);
gate.txt: the whole throttle gate 0x61b1930..0x61b19e7;
limit_check.txt: the whole limit check 0x61b1910..0x61b192b;
bitset.txt: the whole flag-bit setter 0x61b18b0..0x61b18c8;
frame_deliver.txt: the whole frame-and-deliver 0x61b1a10..0x61b1ac6;
varint.txt: the whole ULEB128 encoder 0x61bd410..0x61bd4e9
(shared helper, also pinned whole in the open PR #3001 packet);
framer.txt: the whole frame builder 0x61b1260..0x61b13a3
(shared helper, also pinned whole in the open PR #3001 packet);
site-<addr>.txt: verbatim windows around each direct call site
of the tag-13 query (window starts aligned to an instruction
boundary at or before site-0x28, so the caller's setup reads
whole); frames.txt: the FDE lines for all ten routines and
fragments plus the three caller FDEs from readelf. The
excerpts are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("tag13.txt", 0x61B2CF0, 0x61B3596),
    ("mismatch.txt", 0x61CF670, 0x61CF767),
    ("mismatch_cleanup.txt", 0x61CF650, 0x61CF666),
    ("cleanup_shared.txt", 0x61B2CA8, 0x61B2CE2),
    ("gate.txt", 0x61B1930, 0x61B19E7),
    ("limit_check.txt", 0x61B1910, 0x61B192B),
    ("bitset.txt", 0x61B18B0, 0x61B18C8),
    ("frame_deliver.txt", 0x61B1A10, 0x61B1AC6),
    ("varint.txt", 0x61BD410, 0x61BD4E9),
    ("framer.txt", 0x61B1260, 0x61B13A3),
    ("site-5d79107.txt", 0x5D790C7, 0x5D79125),
    ("site-61b456a.txt", 0x61B4540, 0x61B45A6),
    ("site-61b4739.txt", 0x61B470B, 0x61B4770),
]

FDE_RANGES = [
    "00000000061b2cf0..00000000061b3596",
    "00000000061cf670..00000000061cf767",
    "00000000061cf650..00000000061cf666",
    "00000000061b2ca8..00000000061b2ce2",
    "00000000061b1930..00000000061b19e7",
    "00000000061b1910..00000000061b192b",
    "00000000061b18b0..00000000061b18c8",
    "00000000061b1a10..00000000061b1ac6",
    "00000000061bd410..00000000061bd4e9",
    "00000000061b1260..00000000061b13a3",
    "0000000005d78b40..0000000005d7a806",
    "00000000061b45da..00000000061b4609",
    "00000000061b47a2..00000000061b483b",
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
