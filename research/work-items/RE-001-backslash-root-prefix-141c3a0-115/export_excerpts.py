"""Regenerate main.txt for the RE-001-backslash-root-prefix-141c3a0-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-backslash-root-prefix-141c3a0-115/export_excerpts.py

Writes the whole-function excerpt verbatim from a fresh objdump
run over the digest-verified work binary. verify.py re-checks the
stored file byte-for-byte against the same command.
"""

import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x141C3A0, 0x141C3D3),
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / name).write_text(text)
        print("wrote %s (%#x..%#x)" % (name, start, stop))


if __name__ == "__main__":
    main()
