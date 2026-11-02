"""Regenerate the verbatim objdump excerpts for RE-001-wal-replay-driver-94.

Run from the repo root so the objdump header spells the repo-relative
binary path, exactly as the committed excerpts do:

    python3 research/work-items/RE-001-wal-replay-driver-94/export_excerpts.py
"""
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
BIN = "work/hl-node-94.bin"

WINDOWS = {
    "window.txt": (0x520C120, 0x520D31D),
    "caller-site.txt": (0x520D580, 0x520D5C0),
}


def main():
    for name, (lo, hi) in WINDOWS.items():
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={lo:#x}",
             f"--stop-address={hi:#x}", BIN],
            capture_output=True, text=True, check=True).stdout
        (PACKET / name).write_text(out)
        print(f"wrote {name} ({lo:#x}..{hi:#x})")


if __name__ == "__main__":
    sys.exit(main())
