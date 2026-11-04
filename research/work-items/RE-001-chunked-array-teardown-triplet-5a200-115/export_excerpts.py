#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-chunked-array-teardown-triplet-5a200-115/export_excerpts.py

The excerpt headers are normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.

main_5a200.txt, main_5a270.txt and main_5a2e0.txt hold the three whole
routines. Caller evidence is kept reviewable: caller_sites.txt holds a
verbatim 32-byte window starting exactly at each of the 12 call sites,
and frames.txt holds the 3 routine FDEs plus the 4 caller FDEs.
census.py re-confirms the sites against a fresh objdump run.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

ROUTINES = [
    ("main_5a200.txt", "0x5d5a200", "0x5d5a265"),
    ("main_5a270.txt", "0x5d5a270", "0x5d5a2d5"),
    ("main_5a2e0.txt", "0x5d5a2e0", "0x5d5a345"),
]
SITES = [
    0x5D84B8B, 0x5D87F13, 0x5D8865B, 0x6135281, 0x6135602, 0x6135F08,
    0x5D84B7F, 0x5D87F07, 0x5D8864F,
    0x5D84B73, 0x5D87EFB, 0x5D88643,
]
FDE_RANGES = [
              "0000000005d5a200..0000000005d5a265",
              "0000000005d5a270..0000000005d5a2d5",
              "0000000005d5a2e0..0000000005d5a345",
              "0000000005d8479c..0000000005d85475",
              "0000000005d878f0..0000000005d887b0",
              "0000000006135242..00000000061356f3",
              "0000000006135f04..000000000613602d",
              ]


def normalize(text):
    return text.replace("work/hl-node-115.bin", "hl-node-115.bin")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else HERE
    for name, start, stop in ROUTINES:
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={start}",
             f"--stop-address={stop}", "work/hl-node-115.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        with open(os.path.join(outdir, name), "w") as fh:
            fh.write(normalize(out))
        print(f"wrote {name}")
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
