"""Regenerate the verbatim disassembly excerpts for the
RE-001-delimited-key-parse-eb60-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-delimited-key-parse-eb60-115/export_excerpts.py

Writes main.txt (0x606eb60..0x606eeac, the routine's FDE range)
and cleanup.txt (0x606eb0c..0x606eb5a, the exception-cleanup
fragment the routine's landing-pad stubs jump to), each the whole
range body. The excerpts are stored verbatim; verify.py checks that
a fresh run reproduces them byte-for-byte. Instruction-level
detail lives only in these excerpt texts, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x606EB60, 0x606EEAC),
    ("cleanup.txt", 0x606EB0C, 0x606EB5A),
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
