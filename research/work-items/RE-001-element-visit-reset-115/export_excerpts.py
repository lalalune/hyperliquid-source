"""Regenerate the verbatim disassembly excerpts for the
RE-001-element-visit-reset-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-element-visit-reset-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5f6eac0..0x5f6eb13
of the digest-verified node #115 work binary, exactly as objdump
emits it; site1.txt: the 0x5f76388 call site in
0x5f75b10..0x5f763fe, from the argument setup through the call
and the post-call jump; site2.txt: the 0x5fa1796 call site in
0x5fa0e40..0x5fa1d4a, from the empty-range arm through the
follow-up call and the jump to cleanup. The excerpts are stored
verbatim; verify.py checks that a fresh run reproduces them
byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5F6EAC0, 0x5F6EB13),
    ("site1.txt", 0x5F7636D, 0x5F76392),
    ("site2.txt", 0x5FA1786, 0x5FA17A0),
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
