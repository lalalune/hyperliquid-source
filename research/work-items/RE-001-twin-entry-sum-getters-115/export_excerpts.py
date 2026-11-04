#!/usr/bin/env python3
"""Regenerate the verbatim whole-function objdump excerpts for this work item.

Usage: python3 research/work-items/RE-001-twin-entry-sum-getters-115/export_excerpts.py
Run from the repository root. The binary path defaults to work/hl-node-115.bin.
Each excerpt is the unmodified output of one objdump invocation over exactly
one function window; nothing is edited, trimmed, or reordered.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work" / "hl-node-115.bin"
OUT = Path(__file__).resolve().parent

WINDOWS = {
    "getter_a_0x5eec290.objdump": (0x5EEC290, 0x5EEC2F3),
    "getter_b_0x5eec300.objdump": (0x5EEC300, 0x5EEC368),
    "leaf_0x5dd3570.objdump": (0x5DD3570, 0x5DD357D),
}


def main():
    for name, (start, stop) in WINDOWS.items():
        text = subprocess.check_output(
            ["objdump", "-d", f"--start-address={hex(start)}",
             f"--stop-address={hex(stop)}", str(BIN)], text=True)
        (OUT / name).write_text(text)
        print(f"{name}: {hex(start)}..{hex(stop)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
