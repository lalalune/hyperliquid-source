#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts for this work item.

Usage (from the repository root):
    python3 research/work-items/RE-001-snapshot-consumer-8360-115/export_excerpts.py

Every excerpt is the raw output of:
    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin
with no post-processing, so each file is byte-for-byte reproducible from
the bound artifact.  The elapsed, initializer, initializer_cleanup,
string_init, string_fini and caller_5ef9520 excerpts are re-shipped
verbatim from the open PRs #3082 (elapsed, initializer family) and #3049
(caller); they were regenerated with this same command and diffed
byte-for-byte against the source packets before committing.
"""

import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

# name -> (start, stop); stop is exclusive, both are instruction boundaries.
EXCERPTS = {
    "main.txt": (0x5EF8360, 0x5EF94EE),
    "cleanup.txt": (0x5EF823C, 0x5EF835A),
    "elapsed.txt": (0x5EEE580, 0x5EEE5A5),
    "fmt_pct.txt": (0x5EEC680, 0x5EEC7E5),
    "to_string.txt": (0x5D4F970, 0x5D4FCDD),
    "tree_destroy.txt": (0x5EEC590, 0x5EEC601),
    "map_find_insert.txt": (0x5EF40A0, 0x5EF41E6),
    "map_insert.txt": (0x5EF3C80, 0x5EF3E6B),
    "map_insert_pos.txt": (0x5EF3AC0, 0x5EF3C73),
    "map_node_create.txt": (0x5EF3ED0, 0x5EF409E),
    "string_compare.txt": (0x5EEB970, 0x5EEB9BE),
    "string_move_assign.txt": (0x5EEBB20, 0x5EEBBF8),
    "key_di.txt": (0x5EFFF20, 0x5EFFFBB),
    "key_capacity.txt": (0x5EFFFC0, 0x5F00060),
    "key_secs_for_last.txt": (0x5F00090, 0x5F0018B),
    "key_secs_since_last.txt": (0x5F001C0, 0x5F002B9),
    "role_name.txt": (0x5EFFF00, 0x5EFFF13),
    "key_count.txt": (0x5F002D0, 0x5F0040E),
    "key_bytes.txt": (0x5F00420, 0x5F0055E),
    "key_percent.txt": (0x5F00570, 0x5F006AC),
    "initializer.txt": (0x5F007F0, 0x5F00B7E),
    "initializer_cleanup.txt": (0x5F006AC, 0x5F007EC),
    "string_init.txt": (0x5EFFDD0, 0x5EFFEA0),
    "string_fini.txt": (0x5EFFEA0, 0x5EFFEF5),
    "caller_5ef9520.txt": (0x5EF9520, 0x5EF9760),
    "site-5ef96db.txt": (0x5EF96C9, 0x5EF96F8),
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
