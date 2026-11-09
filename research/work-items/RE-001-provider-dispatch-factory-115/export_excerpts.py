#!/usr/bin/env python3
"""Export whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-provider-dispatch-factory-115/export_excerpts.py

Writes fn-<addr>.objdump.txt per function. The objdump header carries the
repo-relative binary path (work/hl-node-115.bin), never an absolute path.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = "artifacts/node/115/hl-node"

FUNCTIONS = {
    "5ffabd0": (0x5FFABD0, 0x5FFAE04),  # dispatch factory (slot 21)
    "5ffa710": (0x5FFA710, 0x5FFAAD9),  # registry dispatcher
    "5ffae10": (0x5FFAE10, 0x5FFAEA1),  # "id"-guard wrapper -> dispatcher
    "5ffba10": (0x5FFBA10, 0x5FFBDD9),  # twin dispatcher (byte-identical)
    "5ffbde0": (0x5FFBDE0, 0x5FFBE71),  # twin wrapper -> twin dispatcher
    "5ff9fe0": (0x5FF9FE0, 0x5FFA674),  # registry factory dispatch (cited)
    "60bb890": (0x60BB890, 0x60BB932),  # ConfigOptions default init (cited)
    "5ff0300": (0x5FF0300, 0x5FF03E3),  # string ctor from C string (cited)
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
