#!/usr/bin/env python3
"""Export whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-registry-factory-dispatch-115/export_excerpts.py

Writes fn-<addr>.objdump.txt per function. The objdump header carries the
repo-relative binary path (work/hl-node-115.bin), never an absolute path.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = "artifacts/node/115/hl-node"

FUNCTIONS = {
    "5ff9c60": (0x5FF9C60, 0x5FF9FD7),  # BlockCipher name lookup
    "5ff9fe0": (0x5FF9FE0, 0x5FFA674),  # BlockCipher registry factory dispatch
    "5ffaeb0": (0x5FFAEB0, 0x5FFB247),  # EncryptionProvider name lookup (twin)
    "5ffb250": (0x5FFB250, 0x5FFB981),  # EncryptionProvider dispatch (twin)
}


def main() -> None:
    for name, (start, end) in FUNCTIONS.items():
        out = subprocess.run(
            ["objdump", "-d",
             f"--start-address={start:#x}", f"--stop-address={end:#x}",
             BIN],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
        (HERE / f"fn-{name}.objdump.txt").write_text(out)
    print(f"wrote {len(FUNCTIONS)} excerpts")


if __name__ == "__main__":
    main()
