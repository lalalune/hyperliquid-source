#!/usr/bin/env python3
"""Regenerate main.txt, helper.txt and frames.txt for the node #115
pair introsort loop 0x5d4a3f0 and its adjust-heap helper 0x5d49530.

Commands recorded in README.md:
  objdump -d --start-address=0x5d4a3f0 --stop-address=0x5d4a698 \
      work/hl-node-115.bin
  objdump -d --start-address=0x5d49530 --stop-address=0x5d496cd \
      work/hl-node-115.bin
  readelf --debug-dump=frames-interp work/hl-node-115.bin
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-115.bin"
HERE = Path(__file__).parent

MAIN_START, MAIN_END = 0x5D4A3F0, 0x5D4A698
HELPER_START, HELPER_END = 0x5D49530, 0x5D496CD
# Routine FDEs plus every distinct caller FDE from the census.
FDE_STARTS = (0x5D4A3F0, 0x5D49530, 0x5D50470, 0x5D60090, 0x5D78B40)


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
    helper_text = excerpt(HELPER_START, HELPER_END)
    (HERE / "helper.txt").write_text(helper_text)
    print(f"wrote helper.txt ({len(helper_text.splitlines())} lines)")
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
