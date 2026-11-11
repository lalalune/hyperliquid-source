#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts in this packet.

Runs objdump over work/hl-node-115.bin for the destructor body,
its twin instantiation and the pair glue, writing main.txt,
twin.txt and glue.txt next to this script. The objdump file
header is normalized to the bare binary name so the excerpts
stay byte-stable across machines (no absolute paths).
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work/hl-node-115.bin"

EXCERPTS = {
    "main.txt": (0x57AA810, 0x57AA9CD),
    "twin.txt": (0x5B20680, 0x5B2083D),
    "glue.txt": (0x5B0AD70, 0x5B0ADAC),
}


def render(start, stop):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={start:#x}",
         f"--stop-address={stop:#x}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    return out.replace(str(BIN), BIN.name)


def main():
    for name, (start, stop) in EXCERPTS.items():
        (HERE / name).write_text(render(start, stop))
        print(f"wrote {name}")


if __name__ == "__main__":
    sys.exit(main())
