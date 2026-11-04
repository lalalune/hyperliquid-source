#!/usr/bin/env python3
"""Regenerate main.txt and helper.txt: the whole-function objdump
excerpts for 0x5d4fce0 and its clone callee 0x61cf610.

Commands recorded in README.md:
  objdump -d --start-address=0x5d4fce0 --stop-address=0x5d4fd97 \\
      work/hl-node-115.bin > research/work-items/\\
      RE-001-record-copy-4fce0-115/main.txt
  objdump -d --start-address=0x61cf610 --stop-address=0x61cf64f \\
      work/hl-node-115.bin > research/work-items/\\
      RE-001-record-copy-4fce0-115/helper.txt
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-115.bin"
HERE = Path(__file__).parent
for start, end, name in (
        ("0x5d4fce0", "0x5d4fd97", "main.txt"),
        ("0x61cf610", "0x61cf64f", "helper.txt")):
    text = subprocess.run(
        ["objdump", "-d", f"--start-address={start}",
         f"--stop-address={end}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    (HERE / name).write_text(text)
    print(f"wrote {name} ({len(text.splitlines())} lines)")
