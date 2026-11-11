#!/usr/bin/env python3
"""Regenerate the whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-cfoptions-groups-115/export_excerpts.py
Uses the repo-relative binary path so excerpt headers carry no absolute
home-directory path. The host excerpt (0x6086e00) was first exported by
#4263 (RE-001-cfoptions-maps-115, consumer-options-dump-6086e00) and the
helper excerpt (0x6099ce0) by #4237; both are regenerated here and must
match fresh objdump byte-for-byte.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

FUNCS = {
    "fn-6086e00-cfoptions-configurable-ctor.objdump.txt": (0x6086E00, 0x608818D),
    "fn-6099ce0-register-options.objdump.txt": (0x6099CE0, 0x6099E34),
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
