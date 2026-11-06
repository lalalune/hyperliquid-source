#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-flag-drain-wait-51ab0-115/export_excerpts.py

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
    ("main.txt", "0x5d51ab0", "0x5d51c15"),
    ("stub.txt", "0x60d5390", "0x60d5395"),
]
FDE_RANGES = ["0000000005d51ab0..0000000005d51c15",
              "00000000060d5390..00000000060d5395",
              "0000000005d82240..0000000005d83d9a",
              "0000000005e8e4a0..0000000005e8ee70"]


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
