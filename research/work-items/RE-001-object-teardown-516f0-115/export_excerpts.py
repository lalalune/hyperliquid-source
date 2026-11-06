#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpt and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-object-teardown-516f0-115/export_excerpts.py

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
    ("main.txt", "0x5d516f0", "0x5d519c5"),
]
FDE_RANGES = [
              "0000000005d516f0..0000000005d519c5",
              "0000000005d5ef80..0000000005d5f414",
              "0000000005d5f420..0000000005d5f5fb",
              "0000000005d5f600..0000000005d5f83d",
              "0000000005d5f840..0000000005d5fc1e",
              "0000000005d68cea..0000000005d68dba",
              "0000000005d68dc0..0000000005d6980a",
              "0000000005d69926..0000000005d699fe",
              "0000000005d69a00..0000000005d6a6d9",
              "0000000005d6a6da..0000000005d6a731",
              "0000000005d6a740..0000000005d6ad0c",
              "0000000005d6ad0c..0000000005d6ad8a",
              "0000000005d6ad90..0000000005d6b4d5",
              "0000000005d6b4d6..0000000005d6b52e",
              "0000000005d6b530..0000000005d6b7d4",
              "0000000005d72e50..0000000005d72ecf",
              "0000000005d72ed0..0000000005d73e60",
              "0000000005d7761c..0000000005d77761",
              "0000000005d77770..0000000005d7833f",
              "0000000005d7f2b6..0000000005d7f3a8",
              "0000000005d7f3b0..0000000005d7fb40",
              "0000000005d80440..0000000005d81813",
              "0000000005d81820..0000000005d8205c",
              "0000000005da8658..0000000005da886d",
              "0000000005ddc128..0000000005ddc294",
              "0000000005ddc2a0..0000000005ddce31",
              "0000000005de3252..0000000005de3339",
              "0000000005de3340..0000000005de404e",
              "0000000005de404e..0000000005de44b7",
              "0000000005de44c0..0000000005de7ed0",
              "0000000005deca70..0000000005decc65",
              "0000000005decc70..0000000005dedffa",
              "0000000005e45b64..0000000005e46100",
              "0000000005e51d68..0000000005e51d90",
              "0000000005e51d90..0000000005e51fb6",
              "0000000005e5293e..0000000005e52a43",
              "0000000005e52a50..0000000005e53cb0",
              "0000000005e5df10..0000000005e5e097",
              "0000000005e5e0a0..0000000005e5ee1b",
              "0000000005e68cec..0000000005e68fc3",
              "0000000005e68fd0..0000000005e6b82a",
              "0000000005e6b82a..0000000005e6bb07",
              "0000000005e6bb10..0000000005e6e054",
              "0000000005e8a7ae..0000000005e8a882",
              "0000000005e8a890..0000000005e8c518",
              "0000000005e8ee70..0000000005e8ef82",
              "0000000005e8ef90..0000000005e904bd",
              "0000000005e91cd2..0000000005e91ec7",
              "0000000005e91ed0..0000000005e9406a",
              "0000000005ee93ba..0000000005ee94b9",
              "0000000005f101b2..0000000005f103e6",
              "0000000005f14d85..0000000005f14e79",
              "0000000005f1683e..0000000005f16972",
              "0000000005f6eac0..0000000005f6eb13",
              "0000000005f728f0..0000000005f72dc2",
              "0000000005f7a0b0..0000000005f7a8c1",
              "0000000005f89d5e..0000000005f89ef0",
              "0000000005f89ef0..0000000005f8bb08",
              "0000000005f957aa..0000000005f95b7e",
              "0000000005f95b80..0000000005f98c8d",
              "0000000005f9da84..0000000005f9dae5",
              "0000000005f9daf0..0000000005f9eccd",
              "0000000005fa0cce..0000000005fa0e33",
              "0000000005fa0e40..0000000005fa1d4a",
              "0000000005fa3aee..0000000005fa3d67",
              "0000000005fa3d70..0000000005fa460b"]


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
