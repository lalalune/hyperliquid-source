#!/usr/bin/env python3
"""Regenerate main.txt: the whole-function objdump excerpt for 0x606ca40.

Command recorded in README.md:
  objdump -d --start-address=0x606ca40 --stop-address=0x606cc6a \
      work/hl-node-115.bin > research/work-items/\
      RE-001-instrumented-acquire-6ca40-115/main.txt
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-115.bin"
OUT = Path(__file__).parent / "main.txt"
text = subprocess.run(
    ["objdump", "-d", "--start-address=0x606ca40",
     "--stop-address=0x606cc6a", str(BIN)],
    capture_output=True, text=True, check=True).stdout
OUT.write_text(text)
print(f"wrote {OUT} ({len(text.splitlines())} lines)")
