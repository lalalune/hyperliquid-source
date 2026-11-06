#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-teardown-558f0-115/export_excerpts.py

The excerpt headers are normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("main.txt", "0x5d558f0", "0x5d55967"),
    ("wrapper.txt", "0x60d5470", "0x60d5500"),
]
FDE_RANGES = ["0000000005d558f0..0000000005d55967",
              "00000000060d5470..00000000060d5500",
              "0000000005d8479c..0000000005d85475",
              "0000000005d878f0..0000000005d887b0",
              "0000000005d487b0..0000000005d487da",
              "0000000005d487e0..0000000005d48817",
              "0000000005d4ced0..0000000005d4cf46",
              "0000000005d4cf50..0000000005d4cfce",
              "0000000005f206a0..0000000005f2089b",
              "0000000005f74680..0000000005f74afe",
              "0000000005f98c8e..0000000005f98dcb",
              "000000000602f170..000000000602f52b",
              "00000000060322f6..00000000060323b1",
              "000000000604a4a0..000000000604a826",
              "00000000061c4c56..00000000061c4d18",
              "00000000061c5700..00000000061c5ac7",
              "00000000061c5aec..00000000061c5b28",
              "00000000061c5b30..00000000061c5fa3"]


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
