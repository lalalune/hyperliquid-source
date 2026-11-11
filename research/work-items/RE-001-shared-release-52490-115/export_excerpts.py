"""Regenerate the verbatim disassembly excerpts for the
RE-001-shared-release-52490-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-shared-release-52490-115/export_excerpts.py

Writes main.txt (0x5a52490..0x5a52518), the whole release
routine body; cleanup.txt (0x5a4f0e0..0x5a4f10b), the whole
standalone pair-release helper its first cleanup pad calls;
and panic_shim.txt (0x1680cab..0x1680cbf), the whole 20-byte
'panic in a destructor during cleanup' shim. The excerpts are
stored verbatim; verify.py checks that a fresh run reproduces
them byte-for-byte. Instruction-level detail lives only in
these excerpt texts, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5A52490, 0x5A52518),
    ("cleanup.txt", 0x5A4F0E0, 0x5A4F10B),
    ("panic_shim.txt", 0x1680CAB, 0x1680CBF),
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
