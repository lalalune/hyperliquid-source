#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-nested-array-teardown-58f10-115/export_excerpts.py

The excerpt headers are normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.

main.txt holds the whole routine. Caller evidence is kept reviewable:
caller_sites.txt holds a verbatim 32-byte window starting exactly at
each of the 10 call sites, and frames.txt holds the routine FDE plus
the 9 caller FDEs. census.py re-confirms the sites against a fresh
objdump run.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

SITES = [
    0x5D60E40,
    0x5D60F28,
    0x5D616F9,
    0x5D78A28,
    0x5D79991,
    0x5E7039A,
    0x5E7C9B7,
    0x5E9DD5F,
    0x5ECC4E8,
    0x5F1969F,
]
FDE_RANGES = [
              "0000000005d58f10..0000000005d58fab",
              "0000000005d60df2..0000000005d60f99",
              "0000000005d60fa0..0000000005d623e0",
              "0000000005d789ce..0000000005d78b40",
              "0000000005d78b40..0000000005d7a806",
              "0000000005e702fc..0000000005e704b9",
              "0000000005e7c960..0000000005e7ca7e",
              "0000000005e9dd44..0000000005e9de2b",
              "0000000005ecc45e..0000000005ecc625",
              "0000000005f19680..0000000005f19739",
              ]


def normalize(text):
    return text.replace("work/hl-node-115.bin", "hl-node-115.bin")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else HERE
    out = subprocess.run(
        ["objdump", "-d", "--start-address=0x5d58f10",
         "--stop-address=0x5d58fab", "work/hl-node-115.bin"],
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
