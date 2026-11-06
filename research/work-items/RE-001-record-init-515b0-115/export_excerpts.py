#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-record-init-515b0-115/export_excerpts.py

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
    ("main.txt", "0x5d515b0", "0x5d516e6"),
]
FDE_RANGES = ["0000000005d515b0..0000000005d516e6",
              "0000000005d68dc0..0000000005d6980a",
              "0000000005d69a00..0000000005d6a6d9",
              "0000000005d6a740..0000000005d6ad0c",
              "0000000005d6ad90..0000000005d6b4d5",
              "0000000005d6b530..0000000005d6b7d4",
              "0000000005d72ed0..0000000005d73e60",
              "0000000005d77770..0000000005d7833f",
              "0000000005d7f3b0..0000000005d7fb40",
              "0000000005e68fd0..0000000005e6b82a",
              "0000000005e6bb10..0000000005e6e054",
              "0000000005f89ef0..0000000005f8bb08",
              "0000000005f95b80..0000000005f98c8d"]


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
