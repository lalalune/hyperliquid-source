#!/usr/bin/env python3
"""Regenerate the whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-parse-then-apply-wrapper-115/export_excerpts.py
Uses the repo-relative binary path so excerpt headers carry no absolute
home-directory path. The map-parse excerpt is re-shipped byte-identical
from #4349 (RE-001-options-map-host-e510-115); it is regenerated here too
and must match the #4349 bytes.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

FUNCS = {
    "fn-60c1bb0-wrapper.objdump.txt": (0x60C1BB0, 0x60C1CC5),
    "fn-60c1190-map-parse.objdump.txt": (0x60C1190, 0x60C1887),
    "fn-60c18b0-apply-loop.objdump.txt": (0x60C18B0, 0x60C1B7C),
    "fn-60c0e90-overflow-insert.objdump.txt": (0x60C0E90, 0x60C112F),
    "fn-5e317a0-caller-a.objdump.txt": (0x5E317A0, 0x5E3190A),
    "fn-5e34160-caller-b.objdump.txt": (0x5E34160, 0x5E347C1),
    "fn-60c1d50-caller-c.objdump.txt": (0x60C1D50, 0x60C26D5),
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
