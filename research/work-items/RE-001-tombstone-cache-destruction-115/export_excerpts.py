"""Export whole-function objdump excerpts for this work item.

Run from the repository root:
    python3 research/work-items/RE-001-tombstone-cache-destruction-115/export_excerpts.py

Each file is the verbatim output of:
    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin

The five helper excerpts (introsort, insertion, adjust-heap,
cleanable-dtor, list-release) are byte-identical re-ships of the
excerpts first published by PR #3803 in
research/work-items/RE-001-fragmented-range-tombstones-115/; they are
listed here so this packet is self-contained and verify.py can check
them, with the original work credited in the README.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"

EXCERPTS = [
    ("dispose-5f061b0.objdump.txt", "0x5f061b0", "0x5f06548"),
    ("unique-ptr-dtor-5f0b080.objdump.txt", "0x5f0b080", "0x5f0b418"),
    ("memtable-dtor-5f10d40.objdump.txt", "0x5f10d40", "0x5f11798"),
    ("freemem-605e8a0.objdump.txt", "0x605e8a0", "0x605e8e7"),
    ("doneallocating-605e860.objdump.txt", "0x605e860", "0x605e89e"),
    ("wbm-freemem-606a890.objdump.txt", "0x606a890", "0x606a8bf"),
    ("dispose-inner-5f0a290.objdump.txt", "0x5f0a290", "0x5f0a319"),
    ("arena-d1-5f10180.objdump.txt", "0x5f10180", "0x5f101b2"),
    ("arena-d0-5f10d00.objdump.txt", "0x5f10d00", "0x5f10d3c"),
    ("rb-erase-30-5f05b80.objdump.txt", "0x5f05b80", "0x5f05d49"),
    ("rb-erase-60-5f06770.objdump.txt", "0x5f06770", "0x5f06bae"),
    ("flushjobinfo-dtor-5ecd650.objdump.txt", "0x5ecd650", "0x5ecd9a5"),
    ("introsort-5f053d0.objdump.txt", "0x5f053d0", "0x5f05678"),
    ("insertion-5f05120.objdump.txt", "0x5f05120", "0x5f051f5"),
    ("adjust-heap-5f04f80.objdump.txt", "0x5f04f80", "0x5f0511d"),
    ("cleanable-dtor-61bd0e0.objdump.txt", "0x61bd0e0", "0x61bd131"),
    ("list-release-5f059b0.objdump.txt", "0x5f059b0", "0x5f05b79"),
]


def main():
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=" + start,
             "--stop-address=" + stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(out)
        print("wrote", name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
