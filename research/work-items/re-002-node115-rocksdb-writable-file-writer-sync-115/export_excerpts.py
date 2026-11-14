#!/usr/bin/env python3
"""Regenerate the verbatim excerpts and raw hex in this packet.

Run from the repository root:
    python3 research/work-items/re-002-node115-rocksdb-writable-file-writer-sync-115/export_excerpts.py

Uses the repo-relative binary path work/hl-node-115.bin; objdump
addresses are the window virtual addresses used throughout. Each
.objdump.txt is one whole FDE, verbatim; each .hex is the same FDE's
raw bytes as one lowercase hex line. Two FDEs: the helper
(0x6052800..0x60529ee, 494 B, 11 census relocations) and its .cold
FDE (0x60527a6..0x60527fd, 87 B, 6 kind-4 relocations). The function
has a 0x30 stack frame and a canary; both FDEs carry an LSDA.
"""

import hashlib
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, 'artifacts', 'node', '115', 'hl-node')
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

EXCERPTS = [
    ("sync-6052800", "0x6052800",
     "0x60529ee"),
    ("sync-60527a6-cold", "0x60527a6",
     "0x60527fd"),
]


def _va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", BIN]).decode()
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
            ["objdump", "-d", "--start-address=" + start,
             "--stop-address=" + stop, "artifacts/node/115/hl-node"],
            cwd=ROOT, capture_output=True, text=True, check=True)
        with open(os.path.join(HERE, name + ".objdump.txt"), "w") as fh:
            # Preserve the original display-only filename in retained excerpts.
            # Instruction and byte output is unchanged.
            fh.write(out.stdout.replace("artifacts/node/115/hl-node:", "work/hl-node-115.bin:", 1))
        print(name, len(raw), "bytes")


if __name__ == "__main__":
    main()
