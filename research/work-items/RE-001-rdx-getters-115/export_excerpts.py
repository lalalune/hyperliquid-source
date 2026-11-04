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
    ("0x5eeb6c0", "0x5eeb6da", "function_0x5eeb6c0.txt"),
    ("0x5eeb6e0", "0x5eeb6fa", "function_0x5eeb6e0.txt"),
    ("0x5eeb700", "0x5eeb720", "function_0x5eeb700.txt"),
    ("0x5eeb720", "0x5eeb741", "function_0x5eeb720.txt"),
    ("0x5e4b550", "0x5e4b560", "function_0x5e4b550.txt"),
    ("0x5e4b560", "0x5e4b599", "function_0x5e4b560.txt"),
    ("0x5fc9610", "0x5fc961c", "function_0x5fc9610.txt"),
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
