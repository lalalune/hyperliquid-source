"""Export verbatim objdump excerpts for RE-001-configoptions-default-ctor-115.

Run from the repository root:
    python3 research/work-items/RE-001-configoptions-default-ctor-115/export_excerpts.py

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
    # The behaviour centre: default ctor (162 B) and dtor (58 B).
    ("ctor-60bb890.objdump.txt", "0x60bb890", "0x60bb932"),
    ("dtor-5e33fb0.objdump.txt", "0x5e33fb0", "0x5e33fea"),
    # The ctor's LSDA landing pad (its own FDE 0x60bb856..0x60bb88a).
    ("landing-60bb856.objdump.txt", "0x60bb856", "0x60bb88a"),
    # Sole NewInstance callee, re-shipped byte-identical from #4015.
    ("newinstance-61f9400.objdump.txt", "0x61f9400", "0x61f963e"),
    # The nine construction-site hosts, whole-function.
    ("setoptions-5d8ea70.objdump.txt", "0x5d8ea70", "0x5d8f4b5"),
    ("write-5e34010.objdump.txt", "0x5e34010", "0x5e34108"),
    ("read-5e34160.objdump.txt", "0x5e34160", "0x5e347c1"),
    ("addcipher-5ffabd0.objdump.txt", "0x5ffabd0", "0x5ffae04"),
    ("getmutable-60a1d60.objdump.txt", "0x60a1d60", "0x60a1f03"),
    ("mutableeq-60a2080.objdump.txt", "0x60a2080", "0x60a2357"),
    ("persist-60d4a00.objdump.txt", "0x60d4a00", "0x60d4b7e"),
    ("bbtopen-611fb10.objdump.txt", "0x611fb10", "0x61213db"),
    ("asstring-61c8370.objdump.txt", "0x61c8370", "0x61c84fa"),
    # Site-1 direct consumer (no catalogue label): the apply helper.
    ("setoptions-helper-60c4550.objdump.txt", "0x60c4550", "0x60c46b8"),
    # Bounded prologue of the inner Persist: the field-by-field copy of an
    # incoming ConfigOptions (layout corroboration), not a whole function.
    ("persist-copy-60d2820.objdump.txt", "0x60d2820", "0x60d290f"),
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
