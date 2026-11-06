#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpt and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-shared-copy-refcount-50400-115/export_excerpts.py

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
    ("main.txt", "0x5d50400", "0x5d50462"),
]
FDE_RANGES = [
              "0000000005d50400..0000000005d50462",
              "0000000005d665e0..0000000005d66e22",
              "0000000005d71fe0..0000000005d72e50",
              "0000000005d85480..0000000005d878e2",
              "0000000005e5ad50..0000000005e5b2c5",
              "0000000005e5c270..0000000005e5c9a3",
              "0000000005e5e0a0..0000000005e5ee1b",
              "0000000005e68fd0..0000000005e6b82a",
              "0000000005e6bb10..0000000005e6e054",
              "0000000005ebda50..0000000005ebe48e",
              "0000000005ec0ab0..0000000005ec250d",
              "0000000005ec5d80..0000000005ec8e55",
              "0000000005f75b10..0000000005f763fe",
              "0000000005f95b80..0000000005f98c8d",
              "0000000005f9a580..0000000005f9aca9",
]


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
