#!/usr/bin/env python3
"""Export whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-ctr-rot13-provider-115/export_excerpts.py

Writes fn-<addr>.objdump.txt per function. The objdump header carries the
repo-relative binary path (work/hl-node-115.bin), never an absolute path.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = "work/hl-node-115.bin"

FUNCTIONS = {
    "5ff6a00": (0x5FF6A00, 0x5FF6C70),  # the "1://test" provider factory
    "5ff6880": (0x5FF6880, 0x5FF6978),  # CTREncryptionProvider holder init
    "5ff30b0": (0x5FF30B0, 0x5FF3153),  # CTREncryptionProvider destructor
    "5ff6d60": (0x5FF6D60, 0x5FF70A7),  # the "CTR" provider factory
    "5d350c0": (0x5D350C0, 0x5D35145),  # shared_ptr control-block release
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
