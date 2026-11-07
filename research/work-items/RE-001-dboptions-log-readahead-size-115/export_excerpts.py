"""Export verbatim objdump excerpts for RE-001-dboptions-log-readahead-size-115.

Run from the repository root:
    python3 research/work-items/RE-001-dboptions-log-readahead-size-115/export_excerpts.py

Writes one file per window next to this script, using the relative binary
path work/hl-node-115.bin so the objdump header line matches verify.py.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"

# (filename, start, stop). Whole-function windows, except where noted.
WINDOWS = [
    # The behaviour centre: DBOptions default ctor (0x38a B).
    ("dboptions-ctor-60b2db0.objdump.txt", "0x60b2db0", "0x60b3154"),
    # The three verbatim +0x220 copy paths.
    ("dboptions-copy-ctor-5d38750.objdump.txt", "0x5d38750", "0x5d38da5"),
    ("dboptions-options-ctor-60b3280.objdump.txt", "0x60b3280", "0x60b3b87"),
    ("dboptions-assign-60c3480.objdump.txt", "0x60c3480", "0x60c3af4"),
    # The compaction into ImmutableDBOptions (+0x220 -> +0x1a0) and back.
    ("immutabledboptions-ctor-60a3b60.objdump.txt", "0x60a3b60", "0x60a4363"),
    ("immutabledboptions-copy-5da6bc0.objdump.txt", "0x5da6bc0", "0x5da7600"),
    ("builddboptions-60c2e20.objdump.txt", "0x60c2e20", "0x60c3477"),
    # The name -> offset map (the static initializer that builds the
    # global DBOptions type map) and the Configurable ctor that embeds
    # a DBOptions (+0x2d8) and an ImmutableDBOptions (+0x98).
    ("static-init-60aa2b0.objdump.txt", "0x60aa2b0", "0x60b1d78"),
    ("dboptions-configurable-ctor-60a47f0.objdump.txt", "0x60a47f0",
     "0x60a636b"),
    # ConfigOptions ctor and the outer Persist, re-shipped byte-identical
    # from #4108 (ctor-60bb890.objdump.txt, persist-60d4a00.objdump.txt).
    ("configoptions-ctor-60bb890.objdump.txt", "0x60bb890", "0x60bb932"),
    ("persist-60d4a00.objdump.txt", "0x60d4a00", "0x60d4b7e"),
    # The inner Persist (whole function), the verify re-read and Parse.
    ("persist-inner-60d2820.objdump.txt", "0x60d2820", "0x60d49d3"),
    ("verify-options-60d13a0.objdump.txt", "0x60d13a0", "0x60d24ea"),
    ("parse-60cfb60.objdump.txt", "0x60cfb60", "0x60d1354"),
]


def main():
    for name, start, stop in WINDOWS:
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
