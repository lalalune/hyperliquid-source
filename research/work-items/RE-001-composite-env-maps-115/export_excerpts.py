#!/usr/bin/env python3
"""Regenerate the whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-composite-env-maps-115/export_excerpts.py
Uses the repo-relative binary path so excerpt headers carry no absolute
home-directory path. Both excerpts are first published here: the static
initializer 0x5fe0760 (which inserts the three map entries) and the
unordered_map insert helper 0x5d405b0. The CompositeEnvWrapper ctor
0x5fd7360 itself is NOT re-shipped: merged PR #3950 already pins it
(including the three empty-named registrations into these maps); this
packet resolves #3950's open unknown about the maps' contents.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

FUNCS = {
    "fn-5fe0760-static-initializer.objdump.txt": (0x5FE0760, 0x5FE0FBC),
    "fn-5d405b0-map-insert-helper.objdump.txt": (0x5D405B0, 0x5D40F32),
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
