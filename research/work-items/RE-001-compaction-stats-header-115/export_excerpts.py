#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts for this work item.

Usage (from the repository root):
    python3 research/work-items/RE-001-compaction-stats-header-115/export_excerpts.py

Every excerpt is the raw output of:
    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin
with no post-processing, so each file is byte-for-byte reproducible from
the bound artifact.  The name_getter and initializer excerpts are
re-shipped verbatim from the open PR #3164 (same command, diffed
byte-for-byte against the source packet before committing).
"""

import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

# name -> (start, stop); stop is exclusive, both are instruction boundaries
# (each pair is one FDE from readelf --debug-dump=frames-interp, except
# the two site windows, which are instruction-aligned sub-ranges of the
# big dump caller 0x5ef66e0..0x5ef8049).
EXCERPTS = {
    "main.txt": (0x5EEDDA0, 0x5EEE30C),
    "name_getter.txt": (0x5EEB7F0, 0x5EEB850),
    "string_assign.txt": (0x5EEBD00, 0x5EEBDE3),
    "initializer.txt": (0x5EFBD80, 0x5EFFDBB),
    "site-5ef6707.txt": (0x5EF6707, 0x5EF6752),
    "site-5ef710a.txt": (0x5EF710A, 0x5EF7130),
}


def main():
    for name, (start, stop) in EXCERPTS.items():
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=%#x" % start,
             "--stop-address=%#x" % stop,
             str(BIN)],
            check=True, capture_output=True, text=True).stdout
        (HERE / name).write_text(out)
        print("wrote %s (%#x..%#x, %d lines)"
              % (name, start, stop, out.count("\n")))


if __name__ == "__main__":
    main()
