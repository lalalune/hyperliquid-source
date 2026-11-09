#!/usr/bin/env python3
"""Regenerate the whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-map-serializer-7630-115/export_excerpts.py
Uses the repo-relative binary path so excerpt headers carry no absolute
home-directory path.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

FUNCS = {
    "fn-6097630.objdump.txt": (0x6097630, 0x60984E8),
    "fn-60985e0.objdump.txt": (0x60985E0, 0x609865E),
}


def main() -> None:
    for name, (start, stop) in FUNCS.items():
        out = subprocess.check_output(
            ["objdump", "-d",
             f"--start-address={start:#x}", f"--stop-address={stop:#x}",
             "artifacts/node/115/hl-node"],
            cwd=ROOT, text=True).replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
        (HERE / name).write_text(out)
        print(f"wrote {name} ({start:#x}..{stop:#x})")


if __name__ == "__main__":
    main()
