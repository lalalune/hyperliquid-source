"""Regenerate the verbatim disassembly excerpts for the
RE-001-chain-dispatch-notifier-1bca30-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-chain-dispatch-notifier-1bca30-115/export_excerpts.py [outdir]

Writes main.txt: the whole FDE window 0x61bca30..0x61bcd5a
of the digest-verified node #115 work binary, exactly as objdump
emits it; walker.txt: the whole expected-slot walker
0x5d4d490..0x5d4d552; varint.txt: the whole ULEB128 encoder
0x61bd410..0x61bd4e9; framer.txt: the whole frame builder
0x61b1260..0x61b13a3; landing.txt: the shared cleanup fragment
0x61bc9f6..0x61bca28; site-<addr>.txt: verbatim windows around
each direct call site (filled in once the census is known);
frames.txt: the routine FDE, the walker/varint/framer/landing
FDEs and the caller FDE from readelf. The excerpts are stored
verbatim; verify.py checks that a fresh run reproduces them
byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x61BCA30, 0x61BCD5A),
    ("walker.txt", 0x5D4D490, 0x5D4D552),
    ("varint.txt", 0x61BD410, 0x61BD4E9),
    ("framer.txt", 0x61B1260, 0x61B13A3),
    ("landing.txt", 0x61BC9F6, 0x61BCA28),
    ("caller.txt", 0x61BCDE0, 0x61BCEE4),
]

# Caller-site window: argument setup plus the call itself.
SITE_WINDOWS = [
    ("site-61bcebd.txt", 0x61BCEA8, 0x61BCEC2),
]

FDE_RANGES = [
    "00000000061bca30..00000000061bcd5a",
    "0000000005d4d490..0000000005d4d552",
    "00000000061bd410..00000000061bd4e9",
    "00000000061b1260..00000000061b13a3",
    "00000000061bc9f6..00000000061bca28",
    "00000000061bcde0..00000000061bcee4",
]


def main():
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else PACKET
    for name, start, stop in WINDOWS + SITE_WINDOWS:
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
