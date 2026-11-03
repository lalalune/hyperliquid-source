#!/usr/bin/env python3
"""Regenerate the whole-function objdump excerpts for this packet.

Run from the clone root:
  python3 research/work-items/RE-001-slot-lookup-append-115/export_excerpts.py

Writes excerpts/lookup.txt (0x5f45cf0..0x5f45e5d),
excerpts/leaf.txt (0x5f6b620..0x5f6b660) and
excerpts/append.txt (0x5f78060..0x5f780bf), exactly as objdump emits
them, from work/hl-node-115.bin.
"""
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "work", "hl-node-115.bin")
WINDOWS = {
    "lookup": (0x5F45CF0, 0x5F45E5D),
    "leaf": (0x5F6B620, 0x5F6B660),
    "append": (0x5F78060, 0x5F780BF),
}


def main():
    os.makedirs(os.path.join(HERE, "excerpts"), exist_ok=True)
    for name, (start, stop) in WINDOWS.items():
        proc = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT)
        with open(os.path.join(HERE, "excerpts", name + ".txt"), "w") as f:
            f.write(proc.stdout)
        print("wrote excerpts/%s.txt (%d bytes)" % (name, len(proc.stdout)))


if __name__ == "__main__":
    main()
