#!/usr/bin/env python3
"""Regenerate the verbatim whole-function objdump excerpts for this work item.

Usage: python3 research/work-items/RE-001-downward-group-scan-115/export_excerpts.py
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
    "scanner_0x5d52bb0.objdump": (0x5D52BB0, 0x5D52C6F),
    "stub_0x60d5390.objdump": (0x60D5390, 0x60D5395),
    "index_leaf_0x5f6c740.objdump": (0x5F6C740, 0x5F6C750),
    "group_sum_0x5f6c300.objdump": (0x5F6C300, 0x5F6C31B),
    "leaf_0x5da4de0.objdump": (0x5DA4DE0, 0x5DA4E1E),
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
