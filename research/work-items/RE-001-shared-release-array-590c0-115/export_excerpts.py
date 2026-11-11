#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-shared-release-array-590c0-115/export_excerpts.py

The excerpt headers are normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.

main.txt holds the whole routine. Caller evidence is kept reviewable:
caller_sites.txt holds a verbatim 32-byte window starting exactly at
each of the 6 call sites, and frames.txt holds the routine FDE plus
all 6 caller FDEs. census.py re-confirms every site against a fresh
objdump run.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

SITES = [
    0x5D5D068, 0x5D93872, 0x5E46060,
    0x5EDBA2B, 0x5F74CB9, 0x5F7CF9A,
]
FDE_RANGES = [
              "0000000005d590c0..0000000005d591c1",
              "0000000005d5cb10..0000000005d5d18a",
              "0000000005d93704..0000000005d938f4",
              "0000000005e45b64..0000000005e46100",
              "0000000005edb856..0000000005edbab9",
              "0000000005f74bc6..0000000005f74ea0",
              "0000000005f7cf88..0000000005f7cfbc",
              ]


def normalize(text):
    return text.replace("work/hl-node-115.bin", "hl-node-115.bin")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else HERE
    out = subprocess.run(
        ["objdump", "-d", "--start-address=0x5d590c0",
         "--stop-address=0x5d591c1", "work/hl-node-115.bin"],
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
