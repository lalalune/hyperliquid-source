#!/usr/bin/env python3
"""Export whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-filter-policy-registrations-115/export_excerpts.py

Writes fn-<addr>.objdump.txt per function. The objdump header carries the
repo-relative binary path (work/hl-node-115.bin), never an absolute path.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = "artifacts/node/115/hl-node"

FUNCTIONS = {
    # The two registrars (pinned).
    "6137810": (0x6137810, 0x6137D58),  # per-factory registrar
    "6137fe0": (0x6137FE0, 0x61389E4),  # builtin FilterPolicy registrar
    # The nine creator invokers (pinned).
    "612de10": (0x612DE10, 0x612DE51),  # ReadOnlyBuiltin creator
    "6134130": (0x6134130, 0x6134238),  # bloomfilter creator
    "61338a0": (0x61338A0, 0x61339A8),  # bloomfilter:false creator
    "6134010": (0x6134010, 0x61340FC),  # ribbonfilter:true creator
    "6133ef0": (0x6133EF0, 0x6133FDC),  # ribbonfilter creator
    "6133dc0": (0x6133DC0, 0x6133EBC),  # ribbonfilter: creator
    "61339e0": (0x61339E0, 0x6133AF8),  # LegacyBloom creator
    "6133b30": (0x6133B30, 0x6133C48),  # FastLocalBloom creator
    "6133c80": (0x6133C80, 0x6133D98),  # Standard128Ribbon creator
    # The manager template, representative first instance (pinned).
    "612d2a0": (0x612D2A0, 0x612D2CD),  # lambda manager (op dispatch)
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
