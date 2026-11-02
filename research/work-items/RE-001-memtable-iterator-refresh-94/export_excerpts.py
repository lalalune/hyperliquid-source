"""Regenerate the verbatim objdump excerpts for RE-001-memtable-iterator-refresh-94.

Run from the repository root:
  python3 research/work-items/RE-001-memtable-iterator-refresh-94/export_excerpts.py

Each excerpt is the full objdump output for one whole function, produced
with the relative binary path so the header line matches verify.py.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-memtable-iterator-refresh-94")

WINDOWS = [
    ("window-5167ba0.txt", 0x5167BA0, 0x5167CE7),
    ("window-5167cf0.txt", 0x5167CF0, 0x5167E37),
    ("window-5167e40.txt", 0x5167E40, 0x5167FC7),
    ("window-5167fd0.txt", 0x5167FD0, 0x5168157),
    ("window-51684d0.txt", 0x51684D0, 0x5168604),
    ("callee-51647b0.txt", 0x51647B0, 0x51647C4),
]


def main():
    sys.dont_write_bytecode = True
    for name, start, end in WINDOWS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % end, "work/hl-node-94.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(PACKET, name), "w") as f:
            f.write(out)
        print("wrote %s (%d bytes)" % (name, len(out)))


if __name__ == "__main__":
    main()
