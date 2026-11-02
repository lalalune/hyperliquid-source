"""Regenerate the verbatim objdump excerpts for RE-001-callback-flush-teardown-94.

Run from the repository root:
  python3 research/work-items/RE-001-callback-flush-teardown-94/export_excerpts.py

Each excerpt is the full objdump output for one whole function, produced
with the relative binary path so the header line matches verify.py.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-callback-flush-teardown-94")
BINARY = os.path.join(ROOT, "work", "hl-node-94.bin")

WINDOWS = [
    ("window-5165b80.txt", 0x5165B80, 0x5165F18),
    ("callee-5164af0.txt", 0x5164AF0, 0x5164BC5),
    ("callee-5164da0.txt", 0x5164DA0, 0x5165048),
    ("callee-5165380.txt", 0x5165380, 0x5165549),
    ("callee-541cab0.txt", 0x541CAB0, 0x541CB01),
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
