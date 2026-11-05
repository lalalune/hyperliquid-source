"""Regenerate the verbatim disassembly excerpts for the
RE-001-composite-teardown-5a350-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-composite-teardown-5a350-115/export_excerpts.py [outdir]

Writes main.txt: the whole FDE window 0x5d5a350..0x5d5a6aa
of the digest-verified node #115 work binary, exactly as objdump
emits it; site-5d84a13.txt, site-5d87d02.txt, site-5d8844a.txt:
the verbatim direct-call excerpts (argument setup plus the call
itself plus the immediate post-call step); frames.txt: the
routine FDE plus the two caller FDEs from readelf. The excerpts
are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D5A350, 0x5D5A6AA),
    ("site-5d84a13.txt", 0x5D849FB, 0x5D84A20),
    ("site-5d87d02.txt", 0x5D87CEA, 0x5D87D10),
    ("site-5d8844a.txt", 0x5D88438, 0x5D88456),
]

FDE_RANGES = [
    "0000000005d5a350..0000000005d5a6aa",
    "0000000005d8479c..0000000005d85475",
    "0000000005d878f0..0000000005d887b0",
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
