"""Export the verbatim objdump excerpts for the
RE-001-histogram-stats-family-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-histogram-stats-family-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Re-shipped excerpts (bucket_count_init.txt, locked_init.txt,
merge_wrapper.txt, percentile_struct.txt,
percentile_struct_thunk.txt) are copied byte-identical from the
RE-001-stats-produce-115 packet (#3362, branch
fix/stats-produce-115), not regenerated here; verify.py
regenerates every excerpt fresh from the binary and requires
byte-equality, which subsumes the re-ship check.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("boundaries_dtor.txt", 0x606AF70, 0x606AF91),       # vector dtor
    ("bucket_index.txt", 0x606AFA0, 0x606B013),          # lower_bound search
    ("shared_init.txt", 0x606B020, 0x606B07C),           # field + bucket init
    ("empty_check.txt", 0x606B110, 0x606B11F),           # count == 0
    ("empty_thunk.txt", 0x606B120, 0x606B12D),           # slot-0x18 thunk
    ("record.txt", 0x606B130, 0x606B1B3),                # Add(value)
    ("record_thunk.txt", 0x606B1C0, 0x606B1CD),          # slot-0x20 thunk
    ("merge_inner.txt", 0x606B1D0, 0x606B253),           # lock merge
    ("percentile.txt", 0x606B260, 0x606B4FE),            # percentile core
    ("median.txt", 0x606B500, 0x606B511),                # P50
    ("median_thunk.txt", 0x606B520, 0x606B52D),          # slot-0x58 thunk
    ("percentile_thunk.txt", 0x606B530, 0x606B53D),      # slot-0x60 thunk
    ("average.txt", 0x606B540, 0x606B5B9),               # sum / count
    ("average_thunk.txt", 0x606B5C0, 0x606B5CD),         # slot-0x68 thunk
    ("stddev.txt", 0x606B5D0, 0x606B6AE),                # sqrt(var)
    ("stddev_thunk.txt", 0x606B6B0, 0x606B6BD),          # slot-0x70 thunk
    ("renderer_cleanup.txt", 0x606B6BE, 0x606B6E6),       # string-dispose pad
    ("renderer.txt", 0x606B6F0, 0x606BC8D),              # full text render
    ("tostring_entry.txt", 0x606BC90, 0x606BCD3),        # slot-0x30 entry
    ("merge_entry.txt", 0x606BE40, 0x606BED5),           # slot-0x28 entry
    ("name_accessor.txt", 0x606AF40, 0x606AF4C),         # slot-0x38
    ("min_accessor.txt", 0x606AF50, 0x606AF59),          # slot-0x40
    ("max_accessor.txt", 0x606AF60, 0x606AF69),          # slot-0x48
    ("boundaries_init.txt", 0x606BF10, 0x606C134),       # boundary generator
    ("boundaries_static_init.txt", 0x606C140, 0x606C16B),  # .init_array entry
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / name).write_text(text)
        print("wrote %s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
