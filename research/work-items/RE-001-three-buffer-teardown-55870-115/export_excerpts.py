#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpt and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-three-buffer-teardown-55870-115/export_excerpts.py

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
    ("main.txt", "0x5d55870", "0x5d558e2"),
]
FDE_RANGES = ["0000000005d55870..0000000005d558e2",
              "0000000005d69926..0000000005d699fe",
              "0000000005d72e50..0000000005d72ecf",
              "0000000005d9518e..0000000005d954aa",
              "0000000005da8658..0000000005da886d",
              "0000000005dd9340..0000000005dd9b67",
              "0000000005de7ed0..0000000005de7f04",
              "0000000005deca70..0000000005decc65",
              "0000000005decc70..0000000005dedffa",
              "0000000005e6634e..0000000005e6669c",
              "0000000005e82b24..0000000005e82cb4",
              "0000000005e8a7ae..0000000005e8a882",
              "0000000005f94e1e..0000000005f94e93",
              "0000000005f9521e..0000000005f95276",
              "0000000005f957aa..0000000005f95b7e",
              "0000000005f95b80..0000000005f98c8d",
              "0000000005f98c8e..0000000005f98dcb",
              "0000000005f9fb36..0000000005f9fba4",
              "0000000005fa4ede..0000000005fa4f80",
              "0000000006086e00..000000000608818d",
              "00000000060e8ab0..00000000060eb83d"]


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
