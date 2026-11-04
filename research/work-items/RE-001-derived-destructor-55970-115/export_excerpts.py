#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-derived-destructor-55970-115/export_excerpts.py

Excerpt headers are normalized to the bare binary name (the only
modification to objdump output); verify.py regenerates with this
script and compares byte-for-byte.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("complete.txt", "0x5d55970", "0x5d559b9"),
    ("deleting.txt", "0x5d559c0", "0x5d55a16"),
    ("base.txt", "0x5fe70b0", "0x5fe7135"),
]
FDE_RANGES = ["0000000005d55970..0000000005d559b9",
              "0000000005d559c0..0000000005d55a16",
              "0000000005fe70b0..0000000005fe7135",
              "0000000005d55a20..0000000005d55a9b",
              "0000000005d56120..0000000005d562df",
              "0000000005e01a56..0000000005e01d2e",
              "0000000005f74bc6..0000000005f74ea0",
              "0000000005fb17b0..0000000005fb1862",
              "0000000005fb1870..0000000005fb191a",
              "0000000005fe71cc..0000000005fe7207",
              "0000000005fe72f0..0000000005fe73a2",
              "0000000005fe73b0..0000000005fe745a",
              "0000000005feec10..0000000005feecea",
              "0000000005feecf0..0000000005feedca",
              "0000000005ff3000..0000000005ff3045",
              "0000000005ff3050..0000000005ff30a2",
              "0000000005ffbff0..0000000005ffc003",
              "0000000005ffc010..0000000005ffc035",
              "0000000005ffc040..0000000005ffc057",
              "0000000005ffc330..0000000005ffc3e3",
              "0000000006028a0e..0000000006028a5d",
              "0000000006028bb0..0000000006028cea",
              "00000000061edb70..00000000061edc22",
              "00000000061edc30..00000000061edcda",
              "00000000061f03b0..00000000061f0462",
              "00000000061f0470..00000000061f051a"]


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
