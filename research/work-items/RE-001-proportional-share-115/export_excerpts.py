"""Regenerate the packet's verbatim disassembly excerpt.

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
START = "0x5f6ad70"
STOP = "0x5f6aece"
OUT = PACKET_DIR / "function_0x5f6ad70.txt"


def main():
    proc = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % START,
         "--stop-address=%s" % STOP, BINARY],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return 1
    OUT.write_text(proc.stdout)
    print("wrote %s (%d bytes)" % (OUT, len(proc.stdout)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
