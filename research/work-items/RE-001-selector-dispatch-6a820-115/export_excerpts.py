#!/usr/bin/env python3
"""Export the verbatim objdump excerpts for the selector dispatch packet.

Run from the clone root: python3 research/work-items/\
RE-001-selector-dispatch-6a820-115/export_excerpts.py

Writes excerpts/dispatch.txt (0x5f6a820..0x5f6abac), excerpts/builder.txt
(0x5eaa060..0x5eaa10b), excerpts/find.txt (0x5f69d00..0x5f69d31) and
excerpts/thunk.txt (0x5d48410..0x5d48428) by invoking objdump with the
fixed relative binary path work/hl-node-115.bin, so regeneration from
the clone root is byte-for-byte reproducible.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOWS = {
    "dispatch.txt": (0x5F6A820, 0x5F6ABAC),
    "builder.txt": (0x5EAA060, 0x5EAA10B),
    "find.txt": (0x5F69D00, 0x5F69D31),
    "thunk.txt": (0x5D48410, 0x5D48428),
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
