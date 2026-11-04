"""Regenerate the verbatim disassembly excerpts for the
RE-001-flag-variant-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-flag-variant-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5f6b740..0x5f6b753
of the digest-verified node #115 work binary, exactly as objdump
emits it; site.txt: the sole call site 0x5df5bff in
0x5df0f40..0x5df1e22, from the caller's argument setup through
the call itself, the result comparison, and the virtual-call
disposition. The excerpts are stored verbatim; verify.py checks
that a fresh run reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5F6B740, 0x5F6B753),
    ("site.txt", 0x5DF5BE8, 0x5DF5C26),
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / name).write_text(text)
        print("wrote %s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
