"""Regenerate the verbatim disassembly excerpts for the
RE-001-async-duration-step-2f760-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-async-duration-step-2f760-115/export_excerpts.py

Writes main.txt (0x5a2f760..0x5a2fa70, the whole routine body),
formatter.txt (0x1689370..0x16893a2, the error-kind Display shim the
panic exit formats through), guards.txt (0x1681e60..0x1681e99, both
resume-guard shims) and builder.txt (0x1680e80..0x1680eac, the panic
payload builder shim). The excerpts are stored verbatim; verify.py
checks that a fresh run reproduces them byte-for-byte.
Instruction-level detail lives only in these excerpt texts, not in
records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5A2F760, 0x5A2FA70),
    ("formatter.txt", 0x1689370, 0x16893A2),
    ("guards.txt", 0x1681E60, 0x1681E99),
    ("builder.txt", 0x1680E80, 0x1680EAC),
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
