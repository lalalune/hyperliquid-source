#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts for this work item.

Usage (from the repository root):
    python3 research/work-items/RE-001-snapshot-consumer-efda0-115/export_excerpts.py

Every excerpt is the raw output of:
    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin
with no post-processing, so each file is byte-for-byte reproducible from
the bound artifact.  The walker excerpt is re-shipped verbatim from open
PR #3049's packet (same routine, same bytes, same invocation path);
verify.py regenerates it the same way and compares byte-for-byte.
"""

import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

# name -> (start, stop); stop is exclusive, both are instruction boundaries.
EXCERPTS = {
    "main.txt": (0x5EEFDA0, 0x5EF0360),
    "cleanup.txt": (0x5EEFD4A, 0x5EEFD9A),
    "fmt.txt": (0x61D0BA0, 0x61D0D96),
    "elapsed.txt": (0x5EEE580, 0x5EEE5A5),
    "initializer.txt": (0x5F007F0, 0x5F00B7E),
    "initializer_cleanup.txt": (0x5F006AC, 0x5F007EC),
    "string_init.txt": (0x5EFFDD0, 0x5EFFEA0),
    "string_fini.txt": (0x5EFFEA0, 0x5EFFEF5),
    "site-5ef0558.txt": (0x5EF0544, 0x5EF0576),
    "site-5ef7aad.txt": (0x5EF7A95, 0x5EF7AC9),
}


def main():
    for name, (start, stop) in EXCERPTS.items():
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=%#x" % start,
             "--stop-address=%#x" % stop,
             "work/hl-node-115.bin"],
            cwd=str(ROOT), check=True, capture_output=True, text=True,
        ).stdout
        (HERE / name).write_text(out)
        print("wrote %s (%d..%#x, %d lines)"
              % (name, start, stop, out.count("\n")))


if __name__ == "__main__":
    main()
