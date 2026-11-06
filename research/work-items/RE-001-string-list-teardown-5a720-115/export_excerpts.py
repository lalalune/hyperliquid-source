#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-string-list-teardown-5a720-115/export_excerpts.py

The excerpt headers are normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.

main.txt holds the whole routine 0x5d5a720..0x5d5a7e5. Caller
evidence is kept reviewable: caller_sites.txt holds a verbatim
32-byte window starting exactly at each of the 3 call sites, and
frames.txt holds the routine FDE plus the 2 caller FDEs.
census.py re-confirms the sites against a fresh objdump run.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

ROUTINES = [
    ("main.txt", "0x5d5a720", "0x5d5a7e5"),
]
SITES = [
    0x5D849FB, 0x5D87CEA, 0x5D88432,
]
FDE_RANGES = [
              "0000000005d5a720..0000000005d5a7e5",
              "0000000005d8479c..0000000005d85475",
              "0000000005d878f0..0000000005d887b0",
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
