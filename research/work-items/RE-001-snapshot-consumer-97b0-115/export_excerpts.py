#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts for this work item.

Usage (from the repository root):
    python3 research/work-items/RE-001-snapshot-consumer-97b0-115/export_excerpts.py

Every excerpt is the raw output of:
    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin
with no post-processing, so each file is byte-for-byte reproducible from
the bound artifact.  The fmt_pct, map_find_insert, map_insert,
map_node_create, string_compare, string_move_assign and walker excerpts
are re-shipped verbatim from the open PRs #3133 (first six) and #3082
(walker); they were regenerated with this same command and diffed
byte-for-byte against the source packets before committing.
"""

import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

# name -> (start, stop); stop is exclusive, both are instruction boundaries.
EXCERPTS = {
    "main.txt": (0x5EF97B0, 0x5EF9F7F),
    "cleanup.txt": (0x5EF977E, 0x5EF97B0),
    "thunk.txt": (0x5EF9F80, 0x5EF9F97),
    "thunk_cleanup.txt": (0x5EF9F98, 0x5EFA001),
    "fmt_pct.txt": (0x5EEC680, 0x5EEC7E5),
    "map_find_insert.txt": (0x5EF40A0, 0x5EF41E6),
    "map_insert.txt": (0x5EF3C80, 0x5EF3E6B),
    "map_node_create.txt": (0x5EF3ED0, 0x5EF409E),
    "string_compare.txt": (0x5EEB970, 0x5EEB9BE),
    "string_move_assign.txt": (0x5EEBB20, 0x5EEBBF8),
    "string_assign.txt": (0x5EEBD00, 0x5EEBDE3),
    "range_insert.txt": (0x5EF11E0, 0x5EF147E),
    "pair_range_insert.txt": (0x5EF0EA0, 0x5EF11DF),
    "name_join.txt": (0x5FCA2D0, 0x5FCA5CA),
    "name_lookup1.txt": (0x5FC9960, 0x5FC9CD5),
    "name_lookup2.txt": (0x5FC9CE0, 0x5FC9E1A),
    "walker.txt": (0x5D4D490, 0x5D4D552),
    "initializer.txt": (0x5EFBD80, 0x5EFFDBB),
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
