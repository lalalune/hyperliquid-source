"""Regenerate the verbatim disassembly excerpts for the
RE-001-flag-clear-52cf0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-flag-clear-52cf0-115/export_excerpts.py

Writes main.txt (0x5d52cf0..0x5d52d6c), the whole routine body,
acquire.txt (0x60d5390..0x60d5395), the no-op acquire stub, and
broadcast.txt (0x60d57c0..0x60d5855), the tail-jump target whose
first action is pthread_cond_broadcast on its argument. The
excerpts are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte. Instruction-level detail lives
only in these excerpt texts, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D52CF0, 0x5D52D6C),
    ("acquire.txt", 0x60D5390, 0x60D5395),
    ("broadcast.txt", 0x60D57C0, 0x60D5855),
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
