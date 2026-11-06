#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-three-release-55830-115/export_excerpts.py

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
    ("main.txt", "0x5d55830", "0x5d5586a"),
    ("helper_low.txt", "0x5d350c0", "0x5d35145"),
    ("helper_high.txt", "0x5d35070", "0x5d350bc"),
]
FDE_RANGES = ["0000000005d55830..0000000005d5586a",
              "0000000005d350c0..0000000005d35145",
              "0000000005d35070..0000000005d350bc",
              "0000000005d5ef80..0000000005d5f414",
              "0000000005d7761c..0000000005d77761",
              "0000000005d80440..0000000005d81813",
              "0000000005d81820..0000000005d8205c",
              "0000000005d8479c..0000000005d85475",
              "0000000005d878f0..0000000005d887b0",
              "0000000005fb1c5c..0000000005fb1e45"]


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
