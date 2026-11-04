#!/usr/bin/env python3
"""Export the verbatim objdump excerpts for the pipeline/trim windows.

Run from the clone root: python3 research/work-items/\
RE-001-pipeline-trim-115/export_excerpts.py

Writes excerpts/trim.txt (0x5f6bc20..0x5f6bc61) and
excerpts/pipeline.txt (0x5f884b0..0x5f88544) by invoking objdump with
the fixed relative binary path work/hl-node-115.bin, so regeneration
from the clone root is byte-for-byte reproducible.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOWS = {
    "trim.txt": (0x5F6BC20, 0x5F6BC61),
    "pipeline.txt": (0x5F884B0, 0x5F88544),
}


def main():
    outdir = os.path.join(HERE, "excerpts")
    os.makedirs(outdir, exist_ok=True)
    for name, (start, stop) in WINDOWS.items():
        proc = subprocess.run(
            ["objdump", "-d",
             "--start-address=%#x" % start, "--stop-address=%#x" % stop,
             "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True)
        with open(os.path.join(outdir, name), "w") as f:
            f.write(proc.stdout)
        print("wrote", name)


if __name__ == "__main__":
    sys.exit(main())
