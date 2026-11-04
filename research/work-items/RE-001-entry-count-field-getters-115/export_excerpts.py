#!/usr/bin/env python3
"""Regenerate the verbatim whole-function objdump excerpts for this work item.

Usage: python3 research/work-items/RE-001-entry-count-field-getters-115/export_excerpts.py
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
    "count_0x5eeb150.objdump": (0x5EEB150, 0x5EEB17A),
    "signed_0x5eeb180.objdump": (0x5EEB180, 0x5EEB194),
    "field_0x5eeb1a0.objdump": (0x5EEB1A0, 0x5EEB1B4),
    "field_0x5eeb1c0.objdump": (0x5EEB1C0, 0x5EEB1D4),
    "guarded_0x5eeb1e0.objdump": (0x5EEB1E0, 0x5EEB213),
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
