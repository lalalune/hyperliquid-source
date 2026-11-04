"""Regenerate the verbatim objdump excerpts for this work item.

Run from the repository root:
    python3 research/work-items/RE-001-single-list-sums-115/export_excerpts.py

Writes the five whole-function excerpt files next to this script.
"""

import os
import subprocess
import sys

WINDOWS = {
    "window_a_0x5f13060.txt": (0x5F13060, 0x5F1308A),
    "window_b_0x5f13100.txt": (0x5F13100, 0x5F1312A),
    "getter_a_0x5eeb510.txt": (0x5EEB510, 0x5EEB535),
    "getter_b_0x5eeb540.txt": (0x5EEB540, 0x5EEB565),
    "composite_0x5eeb570.txt": (0x5EEB570, 0x5EEB608),
}


def main():
    repo = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "..", ".."))
    here = os.path.dirname(os.path.abspath(__file__))
    for name, (start, stop) in WINDOWS.items():
        # Canonical relative path: objdump prints the path it was
        # given in its header line.
        out = subprocess.run(
            ["objdump", "-d",
             f"--start-address={hex(start)}",
             f"--stop-address={hex(stop)}", "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=repo).stdout
        with open(os.path.join(here, name), "w") as fh:
            fh.write(out)
        print(f"wrote {name} ({start:#x}..{stop:#x})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
