#!/usr/bin/env python3
"""Regenerate main.txt, erase.txt and frames.txt for the node #115
list append routine 0x5d54b50 and its matching erase routine
0x5d54ba0.

Commands recorded in README.md:
  objdump -d --start-address=0x5d54b50 --stop-address=0x5d54b9b \\
      work/hl-node-115.bin
  objdump -d --start-address=0x5d54ba0 --stop-address=0x5d54c01 \\
      work/hl-node-115.bin
  readelf --debug-dump=frames-interp work/hl-node-115.bin
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-115.bin"
HERE = Path(__file__).parent

MAIN_START, MAIN_END = 0x5D54B50, 0x5D54B9B
ERASE_START, ERASE_END = 0x5D54BA0, 0x5D54C01
# Routine FDEs, plus the distinct caller FDEs from the census.
FDE_STARTS = (0x5D54B50, 0x5D54BA0, 0x5D6B530, 0x5D77770,
              0x5D82240, 0x5DEFE00, 0x5DF2380, 0x5DF6530, 0x5E666A0)


def excerpt(start, end):
    text = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    # Normalize the objdump header to the bare binary name so the
    # committed excerpt carries no machine-specific path; verify.py
    # applies the same normalization before comparing.
    return text.replace(str(BIN), BIN.name)


def main():
    main_text = excerpt(MAIN_START, MAIN_END)
    (HERE / "main.txt").write_text(main_text)
    print(f"wrote main.txt ({len(main_text.splitlines())} lines)")
    erase_text = excerpt(ERASE_START, ERASE_END)
    (HERE / "erase.txt").write_text(erase_text)
    print(f"wrote erase.txt ({len(erase_text.splitlines())} lines)")
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    lines = []
    for line in frames.splitlines():
        m = re.search(r"pc=0*([0-9a-f]+)\.\.0*([0-9a-f]+)", line)
        if m and "FDE cie=" in line and int(m.group(1), 16) in FDE_STARTS:
            lines.append(line)
    (HERE / "frames.txt").write_text("\n".join(lines) + "\n")
    print(f"wrote frames.txt ({len(lines)} lines)")


if __name__ == "__main__":
    main()
