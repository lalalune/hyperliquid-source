"""Regenerate the verbatim disassembly excerpts for the
RE-001-drain-append-527a0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-drain-append-527a0-115/export_excerpts.py [outdir]

Writes main.txt: the whole FDE window 0x5d527a0..0x5d52b60
of the digest-verified node #115 work binary, exactly as objdump
emits it; site-5d5ff37.txt and site-5edc0e7.txt: the verbatim
direct-call excerpts (argument setup plus the call itself plus the
immediate post-call step); guard.txt: the whole 5-byte guard callee
0x60d5390..0x60d5395; frames.txt: the routine FDE, the guard FDE
and the two caller FDEs from readelf. The excerpts are stored
verbatim; verify.py checks that a fresh run reproduces them
byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D527A0, 0x5D52B60),
    ("site-5d5ff37.txt", 0x5D5FF2B, 0x5D5FF43),
    ("site-5edc0e7.txt", 0x5EDC0DF, 0x5EDC0F3),
    ("guard.txt", 0x60D5390, 0x60D5395),
]

FDE_RANGES = [
    "0000000005d527a0..0000000005d52b60",
    "00000000060d5390..00000000060d5395",
    "0000000005d5fec0..0000000005d6008a",
    "0000000005edbac0..0000000005edc3b3",
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
