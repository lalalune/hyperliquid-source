"""Regenerate callers.tsv: every direct call site of 0x542f8a0.

Scans the executable segment for e8 rel32 calls landing on the window
and resolves each site's enclosing FDE from readelf's frame dump.
Run from the repository root:
    python3 research/work-items/RE-001-status-format-94/gen_callers.py
"""
import bisect
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BINARY = "work/hl-node-94.bin"
TARGET = 0x542F8A0
# .text section of work/hl-node-94.bin (readelf -SW).
TEXT_V, TEXT_O, TEXT_S = 0x1343C80, 0x1342C80, 0x431C430


def main():
    data = Path(BINARY).read_bytes()
    seg = data[TEXT_O:TEXT_O + TEXT_S]
    sites = []
    for i in range(len(seg) - 5):
        if seg[i] == 0xE8:
            rel = struct.unpack_from("<i", seg, i + 1)[0]
            if TEXT_V + i + 5 + rel == TARGET:
                sites.append(TEXT_V + i)
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", BINARY],
        capture_output=True, text=True, check=True).stdout
    ranges = sorted(
        (int(m.group(1), 16), int(m.group(2), 16))
        for m in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", frames))
    starts = [a for a, _ in ranges]
    rows = []
    for v in sites:
        i = bisect.bisect_right(starts, v) - 1
        enc = (f"{ranges[i][0]:#x}..{ranges[i][1]:#x}"
               if i >= 0 and ranges[i][0] <= v < ranges[i][1] else "?")
        rows.append(f"{v:#x}\t{enc}")
    (HERE / "callers.tsv").write_text(
        "call_site\tenclosing_fde\n" + "\n".join(rows) + "\n")
    print(f"callers.tsv: {len(rows)} direct call sites")
    return 0


if __name__ == "__main__":
    sys.exit(main())
