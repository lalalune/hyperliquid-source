#!/usr/bin/env python3
"""Regenerate main.txt and frames.txt for the node #115 string
range-fill routine 0x5d4a6a0.

Commands recorded in README.md:
  objdump -d --start-address=0x5d4a6a0 --stop-address=0x5d4a743 \\
      work/hl-node-115.bin
  readelf --debug-dump=frames-interp work/hl-node-115.bin
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-115.bin"
HERE = Path(__file__).parent

MAIN_START, MAIN_END = 0x5D4A6A0, 0x5D4A743
# Routine FDE plus every distinct caller FDE from the census.
FDE_STARTS = (0x5D4A6A0, 0x5D4ACA0, 0x5D4D050, 0x5D4DE20, 0x5D4E6A0,
              0x5D52E60, 0x5D57770, 0x5D598B0, 0x5D655B0, 0x5D65960,
              0x5D665E0, 0x5D6C7A0, 0x5D6CA80, 0x5D713F0, 0x5D77260,
              0x5D78340, 0x5D7B620, 0x5D7D740, 0x5D7FC80, 0x5D80440,
              0x5D85480)


def excerpt(start, end):
    text = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    # Normalize the objdump header to the bare binary name so the
    # committed excerpt carries no machine-specific home-directory
    # path; verify.py applies the same normalization before comparing.
    return text.replace(str(BIN), BIN.name)


def main():
    main_text = excerpt(MAIN_START, MAIN_END)
    (HERE / "main.txt").write_text(main_text)
    print(f"wrote main.txt ({len(main_text.splitlines())} lines)")
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    lines = []
    for line in frames.splitlines():
        m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m and "FDE cie=" in line and int(m.group(1), 16) in FDE_STARTS:
            lines.append(line)
    (HERE / "frames.txt").write_text("\n".join(lines) + "\n")
    print(f"wrote frames.txt ({len(lines)} lines)")


if __name__ == "__main__":
    main()
