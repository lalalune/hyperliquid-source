"""Regenerate the packet's verbatim disassembly excerpts.

Run from anywhere; the script resolves the repository root from its own
location and invokes objdump with the canonical relative binary path,
so the objdump header embeds exactly ``work/hl-node-115.bin`` (an
absolute or otherwise different path would change the header bytes).
"""

import subprocess
import sys
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY = "work/hl-node-115.bin"
WINDOWS = [
    ("0x5eeb490", "0x5eeb4d0", "function_0x5eeb490.txt"),
    ("0x5eeb4d0", "0x5eeb510", "function_0x5eeb4d0.txt"),
    ("0x5f133e0", "0x5f1341c", "function_0x5f133e0.txt"),
    ("0x5f13420", "0x5f13429", "function_0x5f13420.txt"),
]


def main():
    for start, stop, name in WINDOWS:
        proc = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, BINARY],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            return 1
        out = PACKET_DIR / name
        out.write_text(proc.stdout)
        print("wrote %s (%d bytes)" % (out, len(proc.stdout)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
