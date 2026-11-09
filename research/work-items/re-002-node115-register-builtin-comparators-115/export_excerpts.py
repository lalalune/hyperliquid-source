#!/usr/bin/env python3
"""Regenerate the verbatim excerpts and raw hex in this packet.

Run from the repository root:
    python3 research/work-items/re-002-node115-register-builtin-comparators-115/export_excerpts.py

Uses the repo-relative binary path work/hl-node-115.bin; objdump
addresses are the window virtual addresses used throughout. The
.objdump.txt is one whole FDE, verbatim; the .hex is the same FDE's
raw bytes as one lowercase hex line.
"""

import hashlib
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "work", "hl-node-115.bin")
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

EXCERPTS = [
    ("register_builtin_comparators115", "0x61c1210", "0x61c1a1a"),
    ("manager-bytewise115", "0x61bd810", "0x61bd83d"),
    ("manager-reverse115", "0x61bd840", "0x61bd86d"),
    ("manager-u64ts115", "0x61bd870", "0x61bd89d"),
]


def _va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", BIN]).decode().replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


def main():
    data = open(BIN, "rb").read()
    assert hashlib.sha256(data).hexdigest() == DIGEST, "artifact mismatch"
    for name, start, stop in EXCERPTS:
        s, e = int(start, 16), int(stop, 16)
        raw = data[_va_to_off(s):_va_to_off(e)]
        with open(os.path.join(HERE, name + ".hex"), "w") as fh:
            fh.write(raw.hex() + "\n")
        out = subprocess.run(
            ["objdump", "-d", "-M", "intel",
             "--start-address=" + start, "--stop-address=" + stop,
             "artifacts/node/115/hl-node"],
            cwd=ROOT, capture_output=True, text=True, check=True)
        with open(os.path.join(HERE, name + ".objdump.txt"), "w") as fh:
            fh.write(out.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin"))
        print(name, len(raw), "bytes")


if __name__ == "__main__":
    main()
