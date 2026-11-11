"""Regenerate the verbatim disassembly excerpts for the
RE-001-pow10-scale-01110-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-pow10-scale-01110-115/export_excerpts.py

Writes main.txt (0x5a01110..0x5a0130b), the whole routine body,
panic_unwrap.txt (0x1680c10..0x1680c29), the whole unwrap panic
shim, panic_encode.txt (0x1680e60..0x1680e72), the whole length
encoding forwarder, panic_unwind.txt (0x1680e80..0x1680eac),
the whole unwind payload builder the shims converge on, and
panic_sub_overflow.txt (0x1681e40..0x1681e59), the whole
subtract-overflow panic shim. The excerpts are stored verbatim;
verify.py checks that a fresh run reproduces them byte-for-byte.
Instruction-level detail lives only in these excerpt texts, not
in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5A01110, 0x5A0130B),
    ("panic_unwrap.txt", 0x1680C10, 0x1680C29),
    ("panic_encode.txt", 0x1680E60, 0x1680E72),
    ("panic_unwind.txt", 0x1680E80, 0x1680EAC),
    ("panic_sub_overflow.txt", 0x1681E40, 0x1681E59),
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
