#!/usr/bin/env python3
"""Regenerate main.txt: the whole-function objdump excerpt for 0x5d497e0.

Command recorded in README.md:
  objdump -d --start-address=0x5d497e0 --stop-address=0x5d498b5 \\
      work/hl-node-115.bin > research/work-items/\\
      RE-001-pair-insertion-sort-497e0-115/main.txt
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-115.bin"
HERE = Path(__file__).parent
text = subprocess.run(
    ["objdump", "-d", "--start-address=0x5d497e0",
     "--stop-address=0x5d498b5", str(BIN)],
    capture_output=True, text=True, check=True).stdout
# Normalize the objdump header to the bare binary name so the committed
# excerpt carries no machine-specific home-directory path; verify.py
# applies the same normalization before comparing.
text = text.replace(str(BIN), BIN.name)
(HERE / "main.txt").write_text(text)
print(f"wrote main.txt ({len(text.splitlines())} lines)")
