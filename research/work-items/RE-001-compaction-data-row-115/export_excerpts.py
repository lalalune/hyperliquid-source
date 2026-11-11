#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts for this work item.

Usage (from the repository root):
    python3 research/work-items/RE-001-compaction-data-row-115/export_excerpts.py

Every excerpt is the raw output of:
    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin
with no post-processing, so each file is byte-for-byte reproducible from
the bound artifact.  The label_assign excerpt is re-shipped verbatim
from the open PR #3180 (same command, diffed byte-for-byte against the
source packet before committing).
"""

import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

# name -> (start, stop); stop is exclusive, both are instruction boundaries
# (each pair is one FDE from readelf --debug-dump=frames-interp, except
# the four site windows, which are instruction-aligned sub-ranges of the
# big dump caller 0x5ef66e0..0x5ef8049).
EXCERPTS = {
    "main.txt": (0x5EED6F0, 0x5EEDD9E),
    "accessor.txt": (0x5EEBAC0, 0x5EEBB14),
    "intfmt.txt": (0x61D0940, 0x61D0B91),
    "humansize.txt": (0x61D0BA0, 0x61D0D96),
    "label_assign.txt": (0x5EEBD00, 0x5EEBDE3),
    "priority_name.txt": (0x5FCEBC0, 0x5FCEC41),
    "node_create.txt": (0x5EED0A0, 0x5EED161),
    "outer_insert.txt": (0x5EF1630, 0x5EF1D33),
    "site-5ef6b84.txt": (0x5EF6AFA, 0x5EF6B89),
    "site-5ef6e09.txt": (0x5EF6DE8, 0x5EF6E11),
    "site-5ef70de.txt": (0x5EF7050, 0x5EF70E3),
    "site-5ef72dd.txt": (0x5EF72C2, 0x5EF72E2),
}


def main():
    for name, (start, stop) in EXCERPTS.items():
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=%#x" % start,
             "--stop-address=%#x" % stop,
             "work/hl-node-115.bin"],
            cwd=str(ROOT), check=True, capture_output=True, text=True).stdout
        (HERE / name).write_text(out)
        print("wrote %s (%#x..%#x, %d lines)"
              % (name, start, stop, out.count("\n")))


if __name__ == "__main__":
    main()
