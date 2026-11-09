#!/usr/bin/env python3
"""Export whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-rot13-factory-115/export_excerpts.py

Writes fn-<addr>.objdump.txt per function. The objdump header carries the
repo-relative binary path (work/hl-node-115.bin), never an absolute path.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = "artifacts/node/115/hl-node"

FUNCTIONS = {
    "5ff7120": (0x5FF7120, 0x5FF7419),  # the ':'-split factory
    "5ff7c90": (0x5FF7C90, 0x5FF8256),  # static initializer, three maps
    "5d405b0": (0x5D405B0, 0x5D40F32),  # map insert helper
    "61d1540": (0x61D1540, 0x61D178B),  # stoul wrapper (suffix -> N)
    "5ff0130": (0x5FF0130, 0x5FF01B5),  # D2 destructor
    "5ff0250": (0x5FF0250, 0x5FF02DB),  # D0 destructor
    "5fef990": (0x5FEF990, 0x5FEF99C),  # Name() -> "ROT13"
    "5fef9a0": (0x5FEF9A0, 0x5FEF9A9),  # slot 19 -> object+0x20
    "5fef9b0": (0x5FEF9B0, 0x5FEF9E3),  # slot 20 ROT13 transform
    "5fef9f0": (0x5FEF9F0, 0x5FEFA23),  # slot 21 ROT13 transform
    "5ff0300": (0x5FF0300, 0x5FF03E3),  # std::string ctor from literal
    "5e32b10": (0x5E32B10, 0x5E32C65),  # OptionTypeInfo move ctor
    "5e332c0": (0x5E332C0, 0x5E3354F),  # OptionTypeInfo move ctor
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
