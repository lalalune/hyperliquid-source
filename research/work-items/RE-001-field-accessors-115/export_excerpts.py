"""Regenerate the verbatim disassembly excerpts for the
RE-001-field-accessors-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-field-accessors-115/export_excerpts.py

Writes main.txt: the three adjacent leaves 0x5d8d0c0..0x5d8d0e9
(the +0x70 getter, the +0x70 unsigned-max raiser, and the +0x18
qword getter, with the int3 padding between them exactly as
objdump emits it); site-recordfill.txt: the record-fill
routine's taken arm at 0x5f6eb80..0x5f6eb96, calling the +0x70
getter at 0x5f6eb88; site-shared.txt: the shared caller's
field-raise sequence at 0x5f9df8f..0x5f9dfd6, calling the +0x70
raiser at 0x5f9dfa1 first and then open PR #2374's leaves.
Further site excerpts are added below as the census lists
them. The excerpts are stored verbatim; verify.py checks that
a fresh run reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D8D0C0, 0x5D8D0E9),
    ("site-recordfill.txt", 0x5F6EB80, 0x5F6EB96),
    ("site-shared.txt", 0x5F9DF8F, 0x5F9DFD6),
    ("site-getter-96156.txt", 0x5F96152, 0x5F96167),
    ("site-getter-97841.txt", 0x5F9782C, 0x5F97858),
    ("site-getter-9ab06.txt", 0x5F9AB02, 0x5F9AB33),
    ("site-get18-95e21.txt", 0x5D95E1A, 0x5D95E37),
    ("site-get18-3c20.txt", 0x5DE3C18, 0x5DE3C2F),
    ("site-get18-ecdd.txt", 0x5E8ECD5, 0x5E8ECE8),
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
