"""Regenerate the verbatim objdump excerpts in this packet.

Run from the repository root (the objdump header spells the binary path
exactly as given on the command line, so the relative path matters):
    python3 research/work-items/RE-001-wal-reader-dtor-94/export_excerpts.py
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BINARY = "work/hl-node-94.bin"

WINDOWS = {
    "window.txt": (0x5162ED0, 0x51632AF),
    "deleting.txt": (0x51632B0, 0x51632CB),
    "helper.txt": (0x543BE20, 0x543BE43),
    "known-type-dtor.txt": (0x5160EC0, 0x5160EED),
    "caller-replay.txt": (0x520B6C5, 0x520B6E3),
    "caller-wrapper.txt": (0x50DB890, 0x50DB8D2),
}


def main():
    for name, (start, stop) in WINDOWS.items():
        out = subprocess.run(
            ["objdump", "-d",
             f"--start-address={start:#x}", f"--stop-address={stop:#x}",
             BINARY],
            capture_output=True, text=True, check=True,
        ).stdout
        (HERE / name).write_text(out)
        print(f"{name}: {len(out.splitlines())} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
