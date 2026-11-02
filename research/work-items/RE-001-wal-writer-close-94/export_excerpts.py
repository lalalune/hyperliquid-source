"""Regenerate the verbatim objdump excerpts for RE-001-wal-writer-close-94.

Run from the repository root with the relative binary path, so the
objdump header spells the path exactly as stored in the excerpts.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-wal-writer-close-94")
BINARY = "work/hl-node-94.bin"

WINDOWS = [
    ("window-5163e20.txt", 0x5163E20, 0x51641D0),
    ("callsite-503ccce.txt", 0x503CC85, 0x503CD10),
    ("callsite-50b4ac7.txt", 0x50B4A77, 0x50B4AEA),
]


def main():
    os.chdir(ROOT)
    for name, start, stop in WINDOWS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, BINARY],
            capture_output=True, text=True, check=True).stdout
        with open(os.path.join(PACKET, name), "w") as handle:
            handle.write(out)
        print("wrote", name)


if __name__ == "__main__":
    sys.exit(main())
