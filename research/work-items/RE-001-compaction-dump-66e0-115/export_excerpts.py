#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts for this work item.

Usage (from the repository root):
    python3 research/work-items/RE-001-compaction-dump-66e0-115/export_excerpts.py

Every excerpt is the raw output of:
    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin
with no post-processing, so each file is byte-for-byte reproducible from
the bound artifact.  The eight re-shipped excerpts (header_formatter,
data_row_formatter, outer_insert, snapshot_consumer, final, str_assign,
priority_name, insert_a0) were copied verbatim from the open PRs #3180,
#3189, #3082 and #3164 and diffed byte-for-byte against a fresh objdump
run of the same range before committing.
"""

import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

# name -> (start, stop); stop is exclusive, both are instruction boundaries
# (each pair is one FDE from readelf --debug-dump=frames-interp).
EXCERPTS = {
    "main.txt": (0x5EF66E0, 0x5EF8049),
    "filler.txt": (0x5EF1FA0, 0x5EF2831),
    "sibling_1d60.txt": (0x5EF1D60, 0x5EF1F39),
    "sibling_6280.txt": (0x5EF6280, 0x5EF65DE),
    "insert_170.txt": (0x5EED170, 0x5EED231),
    "lower_bound_db.txt": (0x5EECDB0, 0x5EECF16),
    "lower_bound_f20.txt": (0x5EECF20, 0x5EED09A),
    "tree_free_cc0.txt": (0x5EEBCC0, 0x5EEBCF1),
    "tree_free_510.txt": (0x5EEC510, 0x5EEC581),
    "tree_free_590.txt": (0x5EEC590, 0x5EEC601),
    "str_b20.txt": (0x5EEBB20, 0x5EEBBF8),
    "getter_3570.txt": (0x5DD3570, 0x5DD357D),
    "sum_s.txt": (0x5F6C300, 0x5F6C31B),
    "sum_vec.txt": (0x5DA4DE0, 0x5DA4E1E),
    "parse_u64.txt": (0x61D1540, 0x61D178B),
    "key_total_stops.txt": (0x5FC9ED0, 0x5FC9F7A),
    "key_total_delays.txt": (0x5FC9F80, 0x5FCA02A),
    # Re-shipped (see the module docstring for the sources).
    "header_formatter.txt": (0x5EEDDA0, 0x5EEE30C),
    "data_row_formatter.txt": (0x5EED6F0, 0x5EEDD9E),
    "outer_insert.txt": (0x5EF1630, 0x5EF1D33),
    "snapshot_consumer.txt": (0x5EEFDA0, 0x5EF0360),
    "final.txt": (0x5EF5D40, 0x5EF621D),
    "str_assign.txt": (0x5EEBD00, 0x5EEBDE3),
    "priority_name.txt": (0x5FCEBC0, 0x5FCEC41),
    "insert_a0.txt": (0x5EED0A0, 0x5EED161),
    "map_find_insert.txt": (0x5EF40A0, 0x5EF41E6),
    "inner_insert.txt": (0x5EF1480, 0x5EF1630),
    "str_assign_lit.txt": (0x5FCD890, 0x5FCD973),
    "tree_copy.txt": (0x5EEBE10, 0x5EEC03C),
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
