"""Regenerate the verbatim objdump excerpts for RE-001-wal-writer-init-94.

Run from the repository root with the relative binary path, so the
objdump header spells the path exactly as stored in the excerpts.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-wal-writer-init-94")
BINARY = "work/hl-node-94.bin"

WINDOWS = [
    ("window-51645d0.txt", 0x51645D0, 0x516466B),
    ("callsite-50bbf5a.txt", 0x50BBF0E, 0x50BBF78),
    ("callsite-50be17b.txt", 0x50BE164, 0x50BE180),
    ("callsite-51f7c20.txt", 0x51F7BE3, 0x51F7C54),
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
