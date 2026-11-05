"""Regenerate the verbatim excerpts for the RE-001-value-
widen-57ae540-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-value-widen-57ae540-115/export_excerpts.py

Writes main.txt (objdump disassembly of the pinned body,
0x57ae540..0x57ae642), table.txt (objdump contents dump of
the 22-entry jump table at 0x931abc..0x931b18 in .rodata)
and frames.txt (the readelf frame-dump FDE lines for the
body and for every caller FDE identified by census.py).
The excerpts are stored verbatim; verify.py checks that a
fresh run reproduces them byte-for-byte.  All objdump
invocations use the repository-relative binary path, so no
excerpt carries an absolute path.
"""

import re
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BODY = (0x57AE540, 0x57AE642)
TABLE = (0x931ABC, 0x931B18)

sys.path.insert(0, str(PACKET))
import census  # noqa: E402

FDE_RE = re.compile(r"FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\.([0-9a-f]+)")


def run(args):
    return subprocess.run(args, capture_output=True, text=True,
                          check=True, cwd=ROOT).stdout


def main():
    text = run(["objdump", "-d",
                "--start-address=%#x" % BODY[0],
                "--stop-address=%#x" % BODY[1],
                "work/hl-node-115.bin"])
    (PACKET / "main.txt").write_text(text)
    print("wrote main.txt (%d bytes)" % len(text))

    text = run(["objdump", "-s",
                "--start-address=%#x" % TABLE[0],
                "--stop-address=%#x" % TABLE[1],
                "work/hl-node-115.bin"])
    (PACKET / "table.txt").write_text(text)
    print("wrote table.txt (%d bytes)" % len(text))

    sites = [int(s, 16) for s in census.collect()["direct_calls"]]
    dump = run(["readelf", "--debug-dump=frames", "-W",
                "work/hl-node-115.bin"])
    kept = []
    for line in dump.splitlines():
        m = FDE_RE.search(line)
        if not m:
            continue
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        if (lo, hi) == BODY or any(lo <= s < hi for s in sites):
            kept.append(line)
    (PACKET / "frames.txt").write_text("\n".join(kept) + "\n")
    print("wrote frames.txt (%d FDE lines)" % len(kept))
    return 0


if __name__ == "__main__":
    sys.exit(main())
