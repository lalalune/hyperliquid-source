"""Regenerate the verbatim objdump excerpts for RE-001-wal-handle-release-94.

Run from the repository root with the relative binary path, so the
objdump header spells the path exactly as stored in the excerpts.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-wal-handle-release-94")
BINARY = "work/hl-node-94.bin"

WINDOWS = [
    ("window-51641d0.txt", 0x51641D0, 0x516458D),
    ("helper-5163460.txt", 0x5163460, 0x516350D),
    ("callsite-4fb0e87.txt", 0x4FB0E60, 0x4FB0EB0),
    ("callsite-50eadb0.txt", 0x50EAD80, 0x50EADF0),
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
