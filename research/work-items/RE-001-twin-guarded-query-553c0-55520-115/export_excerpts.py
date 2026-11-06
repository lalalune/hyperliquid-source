#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and FDE lines for this packet.

Usage: python3 export_excerpts.py [output-dir]  (default: this directory)

The excerpts are the raw output of objdump over each whole-function range,
with only the binary path in the header normalized to the bare binary name
("work/hl-node-115.bin" -> "hl-node-115.bin"). No instruction line is edited.
Run from the repository root so the relative binary path resolves.
"""
import subprocess
import sys
from pathlib import Path

BIN = "work/hl-node-115.bin"
RANGES = {
    "twin_a.txt": (0x5D553C0, 0x5D554E4),
    "twin_b.txt": (0x5D55520, 0x5D55644),
    "cleanup_a.txt": (0x5D5538E, 0x5D553C0),
    "cleanup_b.txt": (0x5D554E4, 0x5D55516),
}
WANTED_FDES = [
    "0000000005d553c0..0000000005d554e4",
    "0000000005d55520..0000000005d55644",
    "0000000005d5538e..0000000005d553c0",
    "0000000005d554e4..0000000005d55516",
    "0000000005ea2e40..0000000005ea3c83",
    "0000000005ea85b0..0000000005ea93f1",
]


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent
    out.mkdir(parents=True, exist_ok=True)
    for name, (start, end) in RANGES.items():
        text = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={end:#x}", BIN],
            capture_output=True, text=True, check=True).stdout
        (out / name).write_text(text.replace(BIN, "hl-node-115.bin"))
    frames = subprocess.run(["readelf", "--debug-dump=frames", BIN],
                            capture_output=True, text=True, check=True).stdout
    lines = [l for l in frames.splitlines()
             if any(w in l for w in WANTED_FDES)]
    assert len(lines) == len(WANTED_FDES), f"expected {len(WANTED_FDES)} FDE lines, got {len(lines)}"
    (out / "frames.txt").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
