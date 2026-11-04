"""Regenerate the verbatim disassembly excerpt for the
RE-001-guarded-convert-52c80-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-guarded-convert-52c80-115/export_excerpts.py

Writes main.txt (0x5d52c80..0x5d52ce8, the whole routine
body), predicate.txt (0x5f03b40..0x5f03b50, the whole
converter callee), and cleanup.txt (0x5d52c70..0x5d52c80,
the exception cleanup block).
The excerpt is stored verbatim; verify.py checks that a fresh run
reproduces it byte-for-byte. Instruction-level detail lives only in
this excerpt text, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D52C80, 0x5D52CE8),
    ("predicate.txt", 0x5F03B40, 0x5F03B50),
    ("cleanup.txt", 0x5D52C70, 0x5D52C80),
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
