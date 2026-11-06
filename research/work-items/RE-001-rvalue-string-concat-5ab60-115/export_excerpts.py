#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-rvalue-string-concat-5ab60-115/export_excerpts.py

The excerpt headers are normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.

main.txt holds the whole routine 0x5d5ab60..0x5d5ad13. Caller
evidence is kept reviewable: caller_sites.txt holds a verbatim
32-byte window starting exactly at each call site, and
frames.txt holds the routine FDE plus the four caller FDEs.
census.py re-confirms the sites against a fresh objdump run.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

ROUTINES = [
    ("main.txt", "0x5d5ab60", "0x5d5ad13"),
]
SITES = [
    0x5D7BA4D, 0x5D7C25A, 0x5D7C2B1, 0x5D7C736,
    0x60D32F9, 0x60D333A, 0x60D338A, 0x60D3694, 0x60D3BB7, 0x60D4065,
    0x6119234, 0x61192A0, 0x6119305,
    0x6120F83, 0x6120FD3,
]
FDE_RANGES = [
              "0000000005d5ab60..0000000005d5ad13",
              "0000000005d7b620..0000000005d7d442",
              "00000000060d2820..00000000060d49d3",
              "0000000006117ed0..0000000006119dad",
              "000000000611fb10..00000000061213db",
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
