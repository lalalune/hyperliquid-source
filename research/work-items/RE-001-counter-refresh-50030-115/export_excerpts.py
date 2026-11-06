#!/usr/bin/env python3
"""Regenerate the verbatim objdump excerpt and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-counter-refresh-50030-115/export_excerpts.py

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
    ("main.txt", "0x5d50030", "0x5d5016a"),
]
FDE_RANGES = [
              "0000000005d50030..0000000005d5016a",
              "0000000005d53578..0000000005d53669",
              "0000000005d53670..0000000005d54629",
              "0000000005d60df2..0000000005d60f99",
              "0000000005d60fa0..0000000005d623e0",
              "0000000005d789ce..0000000005d78b40",
              "0000000005d78b40..0000000005d7a806",
              "0000000005db0c9e..0000000005db0df0",
              "0000000005db0df0..0000000005db1f15",
              "0000000005e10910..0000000005e109df",
              "0000000005e109e0..0000000005e114d4",
              "0000000005e183ac..0000000005e183e2",
              "0000000005e183f0..0000000005e18b3b",
              "0000000005e1b5ca..0000000005e1b9be",
              "0000000005e1b9c0..0000000005e20481",
              "0000000005e21ac0..0000000005e21af5",
              "0000000005e21b00..0000000005e22615",
              "0000000005e260da..0000000005e2610f",
              "0000000005e26110..0000000005e262c4",
              "0000000005e2657a..0000000005e265b2",
              "0000000005e265c0..0000000005e26a03",
              "0000000005e7c960..0000000005e7ca7e",
              "0000000005e7ca80..0000000005e7d919",
              "0000000005e86342..0000000005e863ad",
              "0000000005e863b0..0000000005e86b38",
              "0000000005e870e4..0000000005e8715c",
              "0000000005e87160..0000000005e87935",
              "0000000005e89c44..0000000005e89c8f",
              "0000000005e89c90..0000000005e8a4a9",
              "0000000005e8ee70..0000000005e8ef82",
              "0000000005e8ef90..0000000005e904bd",
              "0000000005e908be..0000000005e909cc",
              "0000000005e909d0..0000000005e91cd2",
              "0000000005e91cd2..0000000005e91ec7",
              "0000000005e91ed0..0000000005e9406a",
              "0000000005ea2de2..0000000005ea2e36",
              "0000000005ea2e40..0000000005ea3c83",
              "0000000005ea855a..0000000005ea85ae",
              "0000000005ea85b0..0000000005ea93f1",
              "0000000005f3dd0c..0000000005f3de65",
              "0000000005f3de70..0000000005f3f664",
              "0000000006035282..00000000060352b4",
              "00000000060352c0..0000000006035564",
              "0000000006035990..00000000060359c2",
              "00000000060359d0..0000000006035d5b",
              "0000000006036584..000000000603660d",
              "0000000006036610..0000000006036be1",
              "0000000006036be2..0000000006036c61",
              "0000000006036c70..0000000006037b11",
              "000000000603f9d5..000000000603f9fc",
              "0000000006043992..0000000006043b44",
              "0000000006043b50..000000000604566a",
              "0000000006045ab4..0000000006045be2",
              "0000000006046e26..0000000006046f62",
              "0000000006046f70..00000000060484f7",
              "00000000060e716a..00000000060e71f6",
              "00000000060e7200..00000000060e7844",
              "0000000006107ff0..0000000006108b64",
              "0000000006108b70..0000000006108fca",
              "0000000006111830..00000000061123a8",
              "00000000061123b0..000000000611281d",
              "0000000006113360..0000000006113eb2",
              "0000000006113ec0..00000000061142bd",
              "0000000006114ec0..0000000006115a48",
              "0000000006115a50..0000000006115ed5",
              "0000000006116ae0..0000000006117668",
              "0000000006117670..0000000006117af5",
              ]


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
