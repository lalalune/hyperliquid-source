#!/usr/bin/env python3
"""Export whole-function objdump excerpts for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-encrypted-fs-factory-115/export_excerpts.py

Writes fn-<addr>.objdump.txt per function. The objdump header carries the
repo-relative binary path (work/hl-node-115.bin), never an absolute path.
"""
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = "work/hl-node-115.bin"

FUNCTIONS = {
    "5ff6690": (0x5FF6690, 0x5FF682E),  # EncryptedFileSystemImpl factory
    "5fe7210": (0x5FE7210, 0x5FE72E8),  # FileSystemWrapper ctor
    "5fe7080": (0x5FE7080, 0x5FE70AB),  # FileSystem ctor (group vector init)
    "5fe70b0": (0x5FE70B0, 0x5FE7135),  # Configurable/group-vector dtor
    "5ff3000": (0x5FF3000, 0x5FF3045),  # EncryptedFileSystemImpl complete dtor
    "5ff3050": (0x5FF3050, 0x5FF30A2),  # EncryptedFileSystemImpl deleting dtor
    "5fe7a20": (0x5FE7A20, 0x5FE7CFC),  # registered "EncryptedFileSystem" factory
    "5fef930": (0x5FEF930, 0x5FEF93C),  # Name() -> "EncryptedFileSystem"
    "5fe7ee0": (0x5FE7EE0, 0x5FE808A),  # OptionTypeInfo record ctor (type 22)
    "5feb760": (0x5FEB760, 0x5FEBA2E),  # static init: "target" -> map 0x65051e0
    "5febf50": (0x5FEBF50, 0x5FEC408),  # RegisterBuiltinFileSystems
    "5fe5700": (0x5FE5700, 0x5FE572D),  # std::function manager, encrypted pair
}


def main() -> None:
    for name, (start, end) in FUNCTIONS.items():
        out = subprocess.run(
            ["objdump", "-d",
             f"--start-address={start:#x}", f"--stop-address={end:#x}",
             BIN],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        (HERE / f"fn-{name}.objdump.txt").write_text(out)
    print(f"wrote {len(FUNCTIONS)} excerpts")


if __name__ == "__main__":
    main()
