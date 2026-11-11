"""Export verbatim objdump excerpts for RE-001-registrar-map-115.

Run from the repository root:
    python3 research/work-items/RE-001-registrar-map-115/export_excerpts.py

Writes one file per window next to this script, using the relative binary
path work/hl-node-115.bin so the objdump header line matches verify.py.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"

# (filename, start, stop). Whole-function windows, except where noted.
WINDOWS = [
    # The behaviour centre: _GLOBAL__sub_I_build_version.cc (0x10d B).
    ("static-init-620b470.objdump.txt", "0x620b470", "0x620b57d"),
    # The string-install helper the init calls three times (0xe3 B).
    ("string-assign-5f204e0.objdump.txt", "0x5f204e0", "0x5f205c3"),
    # The registrar-map destroying function (0xbd B), registered via
    # __cxa_atexit by the static init's tail jump.
    ("map-dtor-620a500.objdump.txt", "0x620a500", "0x620a5bd"),
    # The ObjectRegistry ctor (0xc7 B), re-shipped byte-identical from
    # #4015: it is the map's only consumer (the replay loop).
    ("ctor-61f91b0.objdump.txt", "0x61f91b0", "0x61f9277"),
]


def main():
    for name, start, stop in WINDOWS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=" + start,
             "--stop-address=" + stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(out)
        print("wrote", name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
