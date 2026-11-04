#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-object-teardown-56f50-115/export_excerpts.py

The excerpt headers are normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.

main.txt holds the whole routine. Caller evidence is kept reviewable:
instead of whole-function excerpts for all 26 caller FDEs (one of which
was too large for GitHub to supply as a patch on the neighbouring
#2719 packet), caller_sites.txt holds a verbatim 32-byte window
starting exactly at each of the 27 call sites, and frames.txt holds
the routine FDE plus all 26 caller FDEs. census.py re-confirms every
site against a fresh objdump run.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

SITES = [
    0x5D5D1CA, 0x5D5D690, 0x5D5FE8D, 0x5D5FFAB, 0x5D68CF5,
    0x5D68FF1, 0x5D6AD47, 0x5D6B203, 0x5DEFDA6, 0x5DF0073,
    0x5DF3666, 0x5DF3952, 0x5DF650F, 0x5DF67E1, 0x5E45B9B,
    0x5E46E6A, 0x5E56F39, 0x5E570A7, 0x5E57149, 0x5E57209,
    0x5E84693, 0x5E84823, 0x5E84A1D, 0x5E84A6A, 0x5E84CF3,
    0x5E84CFD, 0x5EDB89D, 0x5EDC311,
]
FDE_RANGES = [
              "0000000005d56f50..0000000005d573e1",
              "0000000005d5d18a..0000000005d5d2c1",
              "0000000005d5d2d0..0000000005d5e1e0",
              "0000000005d5fe8a..0000000005d5feb2",
              "0000000005d5fec0..0000000005d6008a",
              "0000000005d68cea..0000000005d68dba",
              "0000000005d68dc0..0000000005d6980a",
              "0000000005d6ad0c..0000000005d6ad8a",
              "0000000005d6ad90..0000000005d6b4d5",
              "0000000005defd82..0000000005defdfc",
              "0000000005defe00..0000000005df03d6",
              "0000000005df365a..0000000005df36d8",
              "0000000005df36e0..0000000005df3b74",
              "0000000005df64b6..0000000005df6530",
              "0000000005df6530..0000000005df6d1d",
              "0000000005e45b64..0000000005e46100",
              "0000000005e46100..0000000005e4968b",
              "0000000005e56f2e..0000000005e56f5e",
              "0000000005e56f60..0000000005e57146",
              "0000000005e57146..0000000005e5716e",
              "0000000005e57170..0000000005e57283",
              "0000000005e8467a..0000000005e846c7",
              "0000000005e846d0..0000000005e84a0d",
              "0000000005e84a0e..0000000005e84a76",
              "0000000005e84a80..0000000005e8503f",
              "0000000005edb856..0000000005edbab9",
              "0000000005edbac0..0000000005edc3b3",
              ]


def normalize(text):
    return text.replace("work/hl-node-115.bin", "hl-node-115.bin")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else HERE
    out = subprocess.run(
        ["objdump", "-d", "--start-address=0x5d56f50",
         "--stop-address=0x5d573e1", "work/hl-node-115.bin"],
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
