#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-record-teardown-593f0-115/export_excerpts.py

The excerpt headers are normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.

main.txt holds the whole routine. Caller evidence is kept reviewable:
caller_sites.txt holds a verbatim 32-byte window starting exactly at
each of the 2 call sites, and frames.txt holds the routine FDE plus
both caller FDEs. census.py re-confirms every site against a fresh
objdump run.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

SITES = [
    0x5D8160B, 0x5E515AD,
]
FDE_RANGES = [
              "0000000005d593f0..0000000005d594dd",
              "0000000005d80440..0000000005d81813",
              "0000000005e50fe0..0000000005e51710",
              ]


def normalize(text):
    return text.replace("work/hl-node-115.bin", "hl-node-115.bin")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else HERE
    out = subprocess.run(
        ["objdump", "-d", "--start-address=0x5d593f0",
         "--stop-address=0x5d594dd", "work/hl-node-115.bin"],
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
