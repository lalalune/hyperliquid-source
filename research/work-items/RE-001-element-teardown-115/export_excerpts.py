"""Regenerate the verbatim disassembly excerpts for the
RE-001-element-teardown-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-element-teardown-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5d516f0..0x5d519c5
of the digest-verified node #115 work binary, exactly as objdump
emits it; consumer.txt: the visit loop of the 0x5f6eac0
routine (open PR #2383) that calls this routine once per
element, from the loop head through the back edge. The excerpts
are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D516F0, 0x5D519C5),
    ("consumer.txt", 0x5F6EAF0, 0x5F6EB02),
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
