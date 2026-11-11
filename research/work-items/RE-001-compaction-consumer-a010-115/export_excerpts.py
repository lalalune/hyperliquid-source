#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts for this work item.

Usage (from the repository root):
    python3 research/work-items/RE-001-compaction-consumer-a010-115/export_excerpts.py

Every excerpt is the raw output of:
    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin
with no post-processing, so each file is byte-for-byte reproducible from
the bound artifact.  The fmt_pct, map_node_create, map_find_insert,
string_move_assign, name_join, name_lookup1, name_lookup2 and
initializer excerpts are re-shipped verbatim from the open PR #3145
(the first four also appeared in #3133); they were regenerated with
this same command and diffed byte-for-byte against the source packet
before committing.
"""

import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

# name -> (start, stop); stop is exclusive, both are instruction boundaries
# (each pair is one FDE from readelf --debug-dump=frames-interp).
EXCERPTS = {
    "main.txt": (0x5EFA010, 0x5EFAE21),
    "filler.txt": (0x5EF1FA0, 0x5EF2831),
    "outer_insert.txt": (0x5EF1630, 0x5EF1D33),
    "inner_insert.txt": (0x5EF1480, 0x5EF1630),
    "move_assign.txt": (0x5EECDB0, 0x5EECF16),
    "node_create.txt": (0x5EED170, 0x5EED231),
    "tree_free.txt": (0x5EEBCC0, 0x5EEBCF1),
    "tree_erase.txt": (0x5EEC510, 0x5EEC581),
    "fmt_pct.txt": (0x5EEC680, 0x5EEC7E5),
    "map_node_create.txt": (0x5EF3ED0, 0x5EF409E),
    "map_find_insert.txt": (0x5EF40A0, 0x5EF41E6),
    "string_move_assign.txt": (0x5EEBB20, 0x5EEBBF8),
    "name_getter.txt": (0x5EEB7F0, 0x5EEB850),
    "scalar_sum.txt": (0x5F6C300, 0x5F6C31B),
    "scalar_sum2.txt": (0x5DA4DE0, 0x5DA4E1E),
    "final.txt": (0x5EF5D40, 0x5EF621D),
    "tag_index.txt": (0x5FC9E20, 0x5FC9E8A),
    "name_join.txt": (0x5FCA2D0, 0x5FCA5CA),
    "name_lookup1.txt": (0x5FC9960, 0x5FC9CD5),
    "name_lookup2.txt": (0x5FC9CE0, 0x5FC9E1A),
    "name_gate1.txt": (0x5FC9EB0, 0x5FC9EBB),
    "name_gate2.txt": (0x5FC9EC0, 0x5FC9ECB),
    "key_a.txt": (0x5FCA050, 0x5FCA163),
    "key_b.txt": (0x5FCA190, 0x5FCA29C),
    "key_c.txt": (0x5FC9ED0, 0x5FC9F7A),
    "key_d.txt": (0x5FC9F80, 0x5FCA02A),
    "u64str.txt": (0x5D4F970, 0x5D4FCDD),
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
        print("wrote %s (%#x..%#x, %d lines)"
              % (name, start, stop, out.count("\n")))


if __name__ == "__main__":
    main()
