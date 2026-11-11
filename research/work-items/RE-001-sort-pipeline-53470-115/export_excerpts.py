"""Regenerate the verbatim disassembly excerpts for the
RE-001-sort-pipeline-53470-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-sort-pipeline-53470-115/export_excerpts.py [outdir]

Writes main.txt: the whole sort-entry FDE 0x5d53470..0x5d53577;
introsort.txt: the whole introsort loop 0x5d4c1c0..0x5d4c8cf;
heap.txt: the whole heap sift-down 0x5d4bce0..0x5d4c15a;
predicate.txt: the whole less-than predicate 0x5d4a830..0x5d4a90f;
swap.txt: the whole element swap 0x5d496d0..0x5d49739;
insert_pass.txt: the whole insertion-sort pass 0x5d4ba10..0x5d4bcd7;
insert_step.txt: the whole single-element insertion step
0x5d4b3f0..0x5d4b5c0; site-<addr>.txt: verbatim windows around
each direct call site of the sort entry; frames.txt: the FDE lines
for all seven routines plus both caller FDEs from readelf. The
excerpts are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D53470, 0x5D53577),
    ("introsort.txt", 0x5D4C1C0, 0x5D4C8CF),
    ("heap.txt", 0x5D4BCE0, 0x5D4C15A),
    ("predicate.txt", 0x5D4A830, 0x5D4A90F),
    ("swap.txt", 0x5D496D0, 0x5D49739),
    ("insert_pass.txt", 0x5D4BA10, 0x5D4BCD7),
    ("insert_step.txt", 0x5D4B3F0, 0x5D4B5C0),
    ("site-5d6e48e.txt", 0x5D6E460, 0x5D6E4A0),
    ("site-5d6f51c.txt", 0x5D6F4F2, 0x5D6F530),
]

FDE_RANGES = [
    "0000000005d53470..0000000005d53577",
    "0000000005d4c1c0..0000000005d4c8cf",
    "0000000005d4bce0..0000000005d4c15a",
    "0000000005d4a830..0000000005d4a90f",
    "0000000005d496d0..0000000005d49739",
    "0000000005d4ba10..0000000005d4bcd7",
    "0000000005d4b3f0..0000000005d4b5c0",
    "0000000005d6da20..0000000005d6ee3c",
    "0000000005d6ef60..0000000005d6faa0",
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
    (outdir / "frames.txt").write_text("\n".join(lines) + "\n")
    print("wrote frames.txt (%d lines)" % len(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
