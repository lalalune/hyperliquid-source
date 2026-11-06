#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-chunked-array-teardown-58fb0-115/export_excerpts.py

The excerpt headers are normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.

main.txt holds the whole routine. Caller evidence is kept reviewable:
caller_sites.txt holds a verbatim 32-byte window starting exactly at
each of the 7 call sites, and frames.txt holds the routine FDE plus
the 6 caller FDEs. census.py re-confirms the sites against a fresh
objdump run.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

SITES = [
    0x5D847E1,
    0x5D879BD,
    0x5D881C1,
    0x5F3950B,
    0x5F39D15,
    0x5F3B4CC,
    0x61A8256,
]
FDE_RANGES = [
              "0000000005d58fb0..0000000005d59015",
              "0000000005d8479c..0000000005d85475",
              "0000000005d878f0..0000000005d887b0",
              "0000000005f39506..0000000005f39530",
              "0000000005f39d10..0000000005f39d22",
              "0000000005f3b4c4..0000000005f3b4f1",
              "00000000061a820a..00000000061a8525",
              ]


def normalize(text):
    return text.replace("work/hl-node-115.bin", "hl-node-115.bin")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else HERE
    out = subprocess.run(
        ["objdump", "-d", "--start-address=0x5d58fb0",
         "--stop-address=0x5d59015", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    with open(os.path.join(outdir, "main.txt"), "w") as fh:
        fh.write(normalize(out))
    print("wrote main.txt")
    with open(os.path.join(outdir, "caller_sites.txt"), "w") as fh:
        for site in SITES:
            out = subprocess.run(
                ["objdump", "-d", f"--start-address={site:#x}",
                 f"--stop-address={site + 32:#x}",
                 "work/hl-node-115.bin"],
                cwd=ROOT, capture_output=True, text=True, check=True).stdout
            fh.write(normalize(out))
            fh.write("\n")
    print("wrote caller_sites.txt", len(SITES), "windows")
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
