#!/usr/bin/env python3
"""Regenerate the whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-options-map-host-e510-115/export_excerpts.py
Uses the repo-relative binary path so excerpt headers carry no absolute
home-directory path. The slot-12 and map-parse excerpts are regenerated
here too; their instruction bodies match the #4328 / #4320 packets
(the #4328 file carried an absolute-path header, normalized here).
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

FUNCS = {
    "fn-609e510-host.objdump.txt": (0x609E510, 0x609F073),
    "fn-6098510-pre-step.objdump.txt": (0x6098510, 0x60985AF),
    "fn-5d35070-release-helper.objdump.txt": (0x5D35070, 0x5D350BC),
    "fn-5d36110-map-dtor.objdump.txt": (0x5D36110, 0x5D361D5),
    "fn-5d2e770-base-predicate.objdump.txt": (0x5D2E770, 0x5D2E832),
    "fn-609de80-slot12.objdump.txt": (0x609DE80, 0x609E29E),
    "fn-60c1190-map-parse.objdump.txt": (0x60C1190, 0x60C1887),
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
