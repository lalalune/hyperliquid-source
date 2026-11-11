"""Regenerate the verbatim disassembly excerpts for the
RE-001-async-value-transition-2f550-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-async-value-transition-2f550-115/export_excerpts.py

Writes main.txt (0x5a2f550..0x5a2f661), the whole routine body;
helper.txt (0x5a2f760..0x5a2fa70), the whole helper routine the
transition calls for its verdict; release.txt
(0x5a52490..0x5a52518), the whole field-release routine;
guard_completion.txt (0x1681e60..0x1681e7a) and guard_panicking.txt
(0x1681e80..0x1681e9a), the two resume-guard shims; and caller.txt
(0x5a794e8..0x5a794f7), one caller's setup and result test around
its call site. The excerpts are stored verbatim; verify.py checks
that a fresh run reproduces them byte-for-byte. Instruction-level
detail lives only in these excerpt texts, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5A2F550, 0x5A2F661),
    ("helper.txt", 0x5A2F760, 0x5A2FA70),
    ("release.txt", 0x5A52490, 0x5A52518),
    ("guard_completion.txt", 0x1681E60, 0x1681E7A),
    ("guard_panicking.txt", 0x1681E80, 0x1681E9A),
    ("caller.txt", 0x5A794E8, 0x5A794F7),
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
