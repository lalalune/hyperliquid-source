#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpt and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-holder-teardown-511b0-115/export_excerpts.py

The excerpt header is normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("main.txt", "0x5d511b0", "0x5d515ae"),
]
FDE_RANGES = ["0000000005d511b0..0000000005d515ae",
              "0000000005d5d2d0..0000000005d5e1e0",
              "0000000005d5fec0..0000000005d6008a",
              "0000000005d68dc0..0000000005d6980a",
              "0000000005d6ad90..0000000005d6b4d5",
              "0000000005defe00..0000000005df03d6",
              "0000000005df36e0..0000000005df3b74",
              "0000000005df6530..0000000005df6d1d",
              "0000000005e56f60..0000000005e57146",
              "0000000005e57170..0000000005e57283",
              "0000000005e846d0..0000000005e84a0d",
              "0000000005e84a80..0000000005e8503f"]


def normalize(text):
    return text.replace("work/hl-node-115.bin", "hl-node-115.bin")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else HERE
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=" + start,
             "--stop-address=" + stop, "work/hl-node-115.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        with open(os.path.join(outdir, name), "w") as fh:
            fh.write(normalize(out))
        print("wrote", name)
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    lines = [ln for ln in frames.splitlines()
             if any(r in ln for r in FDE_RANGES)]
    with open(os.path.join(outdir, "frames.txt"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("wrote frames.txt", len(lines), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
