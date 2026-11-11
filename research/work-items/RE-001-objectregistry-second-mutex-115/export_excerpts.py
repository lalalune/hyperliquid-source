"""Export verbatim objdump excerpts for RE-001-objectregistry-second-mutex-115.

Run from the repository root:
    python3 research/work-items/RE-001-objectregistry-second-mutex-115/export_excerpts.py

Writes one file per window next to this script, using the relative binary
path work/hl-node-115.bin so the objdump header line matches verify.py.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"

# (filename, start, stop). Whole-function windows (FDE ranges).
WINDOWS = [
    # The ObjectRegistry ctor (0xc7 B), re-shipped byte-identical from
    # #4015: zeroes both mutexes (+0x70..0x98 and +0x98..0xc0) with the
    # same 16+16+8 pattern.
    ("ctor-61f91b0.objdump.txt", "0x61f91b0", "0x61f9277"),
    # The clone / NewInstance (0x23e B), re-shipped byte-identical from
    # #4015: zeroes both mutexes identically and installs the parent.
    ("clone-61f9400.objdump.txt", "0x61f9400", "0x61f963e"),
    # The control-block _M_dispose (0x27b B), re-shipped byte-identical
    # from #4015: destroys parent/map/names/libraries, never either mutex.
    ("dispose-61f8760.objdump.txt", "0x61f8760", "0x61f89db"),
    # AddLibrary (0x37d B), re-shipped byte-identical from #4015: locks
    # registry+0x98 (lea 0x98(%rbp),%r14; pthread_mutex_lock@0x61f8f09).
    ("add-library-61f8dc0.objdump.txt", "0x61f8dc0", "0x61f913d"),
    # The TTL registration (0x339 B), re-shipped byte-identical from
    # #4015: locks registry+0x98 (lea 0x98(%rbp),%r15; lock@0x6206b73).
    ("ttl-register-62069f0.objdump.txt", "0x62069f0", "0x6206d29"),
    # The big registry method (0x1390 B), re-shipped byte-identical from
    # #4028: locks registry+0x98 (lea 0x98(%rbx); lock@0x5ff8a28).
    ("big-method-5ff88c0.objdump.txt", "0x5ff88c0", "0x5ff9c50"),
    # The std::mutex-destructor helper (0x90 B): the binary's ONLY
    # pthread_mutex_destroy call site (0x60d5189). Never called from
    # registry code (74 callers, all in non-registry FDEs).
    ("destroy-helper-60d5170.objdump.txt", "0x60d5170", "0x60d5200"),
    # A +0x70 mutex lock that is NOT the registry's: a TableCache-area
    # routine locking its own object+0x70 (0xd6 B).
    ("lock70-5f44c80.objdump.txt", "0x5f44c80", "0x5f44d56"),
    # Another +0x70 lock that is NOT the registry's: a cache routine
    # locking its own object+0x70 (0xa3 B).
    ("lock70-5f44db0.objdump.txt", "0x5f44db0", "0x5f44e53"),
    # Another +0x70 lock that is NOT the registry's: a list-hook helper
    # locking its own object+0x70 (0x1b4 B).
    ("lock70-606a450.objdump.txt", "0x606a450", "0x606a604"),
    # Another +0x70 lock that is NOT the registry's: a routine whose
    # object carries a flag byte at +0x98 (not a mutex) and a mutex at
    # +0x70 (0x23e B).
    ("lock70-606a650.objdump.txt", "0x606a650", "0x606a88e"),
    # Another +0x70 lock that is NOT the registry's: a list-hook helper
    # locking its own object+0x70 (0x182 B).
    ("lock70-606a900.objdump.txt", "0x606a900", "0x606aa82"),
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
