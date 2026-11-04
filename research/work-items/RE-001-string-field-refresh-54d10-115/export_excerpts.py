#!/usr/bin/env python3
"""Regenerate main.txt, accessor.txt and frames.txt for the node #115
string-field refresh routine 0x5d54d10 and its registry accessor
0x5d54c30.

Commands recorded in README.md:
  objdump -d --start-address=0x5d54d10 --stop-address=0x5d54ee3 \\
      work/hl-node-115.bin
  objdump -d --start-address=0x5d54c30 --stop-address=0x5d54d06 \\
      work/hl-node-115.bin
  readelf --debug-dump=frames-interp work/hl-node-115.bin
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-115.bin"
HERE = Path(__file__).parent

MAIN_START, MAIN_END = 0x5D54D10, 0x5D54EE3
ACC_START, ACC_END = 0x5D54C30, 0x5D54D06
# Routine FDE, accessor FDE, plus the distinct caller FDE from the census.
FDE_STARTS = (0x5D54D10, 0x5D54C30, 0x5D85480)


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
    acc_text = excerpt(ACC_START, ACC_END)
    (HERE / "accessor.txt").write_text(acc_text)
    print(f"wrote accessor.txt ({len(acc_text.splitlines())} lines)")
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
