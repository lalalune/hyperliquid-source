#!/usr/bin/env python3
"""Regenerate the whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-mockfs-group-115/export_excerpts.py
Uses the repo-relative binary path so excerpt headers carry no absolute
home-directory path. All five are regenerated here and must match fresh
objdump byte-for-byte.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

FUNCS = {
    "fn-6028a60-mock-filesystem-ctor.objdump.txt": (0x6028A60, 0x6028BA4),
    "fn-6029d10-static-initializer.objdump.txt": (0x6029D10, 0x602A25D),
    "fn-5fe58b0-mockfs-creator-invoke.objdump.txt": (0x5FE58B0, 0x5FE590C),
    "fn-6028bb0-mockfs-dtor.objdump.txt": (0x6028BB0, 0x6028CEA),
    "fn-6028d80-mockenv-create.objdump.txt": (0x6028D80, 0x6028E80),
}


def main() -> None:
    for name, (start, stop) in FUNCS.items():
        out = subprocess.check_output(
            ["objdump", "-d",
             f"--start-address={start:#x}", f"--stop-address={stop:#x}",
             "work/hl-node-115.bin"],
            cwd=ROOT, text=True)
        (HERE / name).write_text(out)
        print(f"wrote {name} ({start:#x}..{stop:#x})")


if __name__ == "__main__":
    main()
