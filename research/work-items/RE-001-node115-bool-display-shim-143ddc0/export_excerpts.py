"""Regenerate main.txt for the 0x143ddc0 packet, byte-for-byte.

Run from the repository root:
    python3 research/work-items/RE-001-node115-bool-display-shim-143ddc0/export_excerpts.py

It runs the same objdump invocation recorded in the packet README and
overwrites main.txt. verify.py independently re-runs the same command
and fails if the stored file differs, so this script is only a
convenience for regeneration.
"""

import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
START, STOP = 0x143DDC0, 0x143DDF2


def main():
    text = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % START,
         "--stop-address=%#x" % STOP, "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    (PACKET / "main.txt").write_text(text)
    print("wrote main.txt (%d bytes)" % len(text))


if __name__ == "__main__":
    main()
