#!/usr/bin/env python3
"""Export the whole-function objdump excerpt for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-ttl-option-maps-115/export_excerpts.py

Writes fn-<addr>.objdump.txt per function. The objdump header carries the
repo-relative binary path (work/hl-node-115.bin), never an absolute path.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = "work/hl-node-115.bin"

FUNCTIONS = {
    # The static initializer inserting the four map entries (pinned).
    "6206ef0": (0x6206EF0, 0x620769F),  # TTL option-map initializer
}


def main() -> None:
    for name, (start, end) in FUNCTIONS.items():
        out = subprocess.run(
            ["objdump", "-d",
             f"--start-address={start:#x}", f"--stop-address={end:#x}",
             BIN],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        (HERE / f"fn-{name}.objdump.txt").write_text(out)
    print(f"wrote {len(FUNCTIONS)} excerpts")


if __name__ == "__main__":
    main()
