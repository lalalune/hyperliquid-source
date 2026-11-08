#!/usr/bin/env python3
"""Regenerate the whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-dboptions-groups-115/export_excerpts.py
Uses the repo-relative binary path so excerpt headers carry no absolute
home-directory path. The host excerpt (0x60a47f0) was first exported by
#4237 (RE-001-optiontypeinfo-maps-115, consumer-bothmaps-60a47f0) and the
helper excerpt (0x6099ce0) by #4237 as well; both are regenerated here
and must match fresh objdump byte-for-byte.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

FUNCS = {
    "fn-60a47f0-dboptions-configurable-ctor.objdump.txt": (0x60A47F0, 0x60A636B),
    "fn-6099ce0-register-options.objdump.txt": (0x6099CE0, 0x6099E34),
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
