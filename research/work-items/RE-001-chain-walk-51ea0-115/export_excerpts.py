"""Regenerate the verbatim disassembly excerpts for the
RE-001-chain-walk-51ea0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-chain-walk-51ea0-115/export_excerpts.py

Writes main.txt (0x5d51ea0..0x5d51feb), the whole routine body,
and cleanup.txt (0x5d51e6e..0x5d51e93), its landing-pad cleanup
block. The excerpts are stored verbatim; verify.py checks that a
fresh run reproduces them byte-for-byte. Instruction-level detail
lives only in these excerpt texts, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D51EA0, 0x5D51FEB),
    ("cleanup.txt", 0x5D51E6E, 0x5D51E93),
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
