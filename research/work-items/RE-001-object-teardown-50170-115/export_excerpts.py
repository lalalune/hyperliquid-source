#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpt and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-object-teardown-50170-115/export_excerpts.py

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
    ("main.txt", "0x5d50170", "0x5d503f5"),
]
FDE_RANGES = [
              "0000000005d50170..0000000005d503f5",
              "0000000005d7fc80..0000000005d8043e",
              "0000000005dfbcd0..0000000005dfbcdd",
              "0000000005e03cc2..0000000005e03da2",
              "0000000005e03db0..0000000005e053e9",
              "0000000005e0ce40..0000000005e0d142",
              "0000000005e0d150..0000000005e0eb39",
              "0000000005e1b5ca..0000000005e1b9be",
              "0000000005e1b9c0..0000000005e20481",
              "0000000005e6634e..0000000005e6669c",
              "0000000005e666a0..0000000005e68ceb",
              "0000000005ec4960..0000000005ec511e",
              "0000000005ec5aa8..0000000005ec5d71",
              "0000000005ec5d80..0000000005ec8e55",
              "0000000005ecd9d2..0000000005ecdbe0",
              "0000000005ed01f0..0000000005ed2238",
              "0000000005ee5d30..0000000005ee6d90",
              "0000000005ee7402..0000000005ee7541",
              "0000000005f68d90..0000000005f68dba",
              "0000000005f68dc0..0000000005f68dea",
              "0000000005f76912..0000000005f769fb",
              "0000000005f76a00..0000000005f7714a",
              "0000000005f897c0..0000000005f8984c",
              "00000000060e8220..00000000060e88a7",
              "00000000060e8ab0..00000000060eb83d",
              "00000000060ed7d0..00000000060ed8e5",
              "00000000061051d0..0000000006105ab3",
              "000000000615ff26..000000000615ff86",
              "000000000618fbf4..000000000618feb9",
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
