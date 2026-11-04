#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-rebuild-replace-56120-115/export_excerpts.py

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
    ("main.txt", "0x5d56120", "0x5d562df"),
    ("init.txt", "0x5fe7210", "0x5fe72e8"),
    ("ctor.txt", "0x5fe7080", "0x5fe70ab"),
    ("singleton.txt", "0x5fe2680", "0x5fe2756"),
]
# Routine FDE first, then the init / ctor / singleton FDEs, then the
# release helper's and base destructor's FDEs (bodies pinned in the
# RE-001 three-release and derived-destructor packets), then the four
# distinct caller-function FDEs.
FDE_RANGES = ["0000000005d56120..0000000005d562df",
              "0000000005fe7210..0000000005fe72e8",
              "0000000005fe7080..0000000005fe70ab",
              "0000000005fe2680..0000000005fe2756",
              "0000000005d350c0..0000000005d35145",
              "0000000005fe70b0..0000000005fe7135",
              "0000000005d5ef80..0000000005d5f414",
              "0000000005d77770..0000000005d7833f",
              "0000000005d81820..0000000005d8205c",
              "0000000005d85480..0000000005d878e2"]


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
