#!/usr/bin/env python3
"""Regenerate the verbatim whole-function objdump excerpt for this work item.

Usage: python3 research/work-items/RE-001-group-report-formatter-115/export_excerpts.py
Run from the repository root. The binary path defaults to work/hl-node-115.bin.
The excerpt is the unmodified output of one objdump invocation over exactly
one function window; nothing is edited, trimmed, or reordered.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work" / "hl-node-115.bin"
OUT = Path(__file__).resolve().parent

WINDOWS = {
    "formatter_0x5f6c320.objdump": (0x5F6C320, 0x5F6C4D7),
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
