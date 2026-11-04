#!/usr/bin/env python3
"""Regenerate the verbatim whole-function objdump excerpts for this work item.

Usage: python3 research/work-items/RE-001-chain-walk-getters-115/export_excerpts.py
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
    "head_0x5eee5b0.objdump": (0x5EEE5B0, 0x5EEE5C3),
    "getter70_0x5eee5d0.objdump": (0x5EEE5D0, 0x5EEE654),
    "getter78_0x5eee660.objdump": (0x5EEE660, 0x5EEE6E4),
    "getter98_0x5eee6f0.objdump": (0x5EEE6F0, 0x5EEE784),
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
