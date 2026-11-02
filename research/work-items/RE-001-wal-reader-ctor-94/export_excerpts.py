"""Regenerate the verbatim objdump excerpts in this packet.

Run from the repository root (the objdump header spells the binary path
exactly as given on the command line, so the relative path matters):
    python3 research/work-items/RE-001-wal-reader-ctor-94/export_excerpts.py
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BINARY = "work/hl-node-94.bin"

WINDOWS = {
    "window.txt": (0x51632F0, 0x51633DE),
    "cleanup.txt": (0x51632CC, 0x51632EB),
    "caller-replay.txt": (0x520B46B, 0x520B4A3),
    "caller-first.txt": (0x50CA0A0, 0x50CA0F1),
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
