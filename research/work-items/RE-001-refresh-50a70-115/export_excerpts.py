"""Regenerate the verbatim disassembly excerpts for the
RE-001-refresh-50a70-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-refresh-50a70-115/export_excerpts.py

Writes main.txt (0x5d50a70..0x5d50dc5), the whole routine body,
cleanup.txt (0x5d50a06..0x5d50a6c), the separate-FDE cleanup
fragment the routine's landing pads jump to, teardown.txt
(0x5d509c0..0x5d50a06), the record teardown the routine calls
on both temps, and global_target.txt (0x5d486c0..0x5d486ce),
the sized-delete helper the old-pointer disposal compares
against. The excerpts are stored verbatim; verify.py checks
that a fresh run reproduces them byte-for-byte. Instruction-
level detail lives only in these excerpt texts, not in
records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D50A70, 0x5D50DC5),
    ("cleanup.txt", 0x5D50A06, 0x5D50A6C),
    ("teardown.txt", 0x5D509C0, 0x5D50A06),
    ("global_target.txt", 0x5D486C0, 0x5D486CE),
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
