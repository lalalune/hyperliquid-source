"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-objectlibrary-registry-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout. No
windows are re-shipped from earlier PRs: every excerpt here is
read fresh from work/hl-node-115.bin. The find-or-insert cold
FDE (0x5fd1ffa..0x5fd20c4) is shipped as its own excerpt: it is
the function's exception landing pad, a separate FDE whose first
block destroys the partially built node before resuming the unwind.
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("getter-61f8b60.objdump.txt", "0x61f8b60", "0x61f8d12"),
    ("count-61f8700.objdump.txt", "0x61f8700", "0x61f8760"),
    ("find-or-insert-5fd1da0.objdump.txt", "0x5fd1da0", "0x5fd1ffa"),
    ("find-or-insert-cold-5fd1ffa.objdump.txt", "0x5fd1ffa", "0x5fd20c4"),
    ("rehash-5fd1c60.objdump.txt", "0x5fd1c60", "0x5fd1d9d"),
    ("vector-insert-5fd17c0.objdump.txt", "0x5fd17c0", "0x5fd1962"),
    ("insert-5fd24c0.objdump.txt", "0x5fd24c0", "0x5fd2748"),
    ("default-init-5fd20d0.objdump.txt", "0x5fd20d0", "0x5fd241d"),
    ("register-5fd27c0.objdump.txt", "0x5fd27c0", "0x5fd297f"),
    ("cb-d1-5fefc70.objdump.txt", "0x5fefc70", "0x5fefc75"),
    ("cb-d0-5fefd00.objdump.txt", "0x5fefd00", "0x5fefd0e"),
    ("cb-dispose-5ff7900.objdump.txt", "0x5ff7900", "0x5ff7952"),
    ("cb-destroy-5fefd50.objdump.txt", "0x5fefd50", "0x5fefd5e"),
    ("cb-getdeleter-5feff70.objdump.txt", "0x5feff70", "0x5feffb7"),
    ("map-destroy-5ff7820.objdump.txt", "0x5ff7820", "0x5ff78ff"),
    ("pattern-d2-5ff2030.objdump.txt", "0x5ff2030", "0x5ff2145"),
    ("pattern-d0-5ff2150.objdump.txt", "0x5ff2150", "0x5ff225f"),
    ("pattern-match-61f8670.objdump.txt", "0x61f8670", "0x61f86f2"),
    ("str-match-61f8430.objdump.txt", "0x61f8430", "0x61f8670"),
    ("elem-match-61f8280.objdump.txt", "0x61f8280", "0x61f842b"),
    ("pattern-accessor-61f8120.objdump.txt", "0x61f8120", "0x61f8129"),
    ("node-env-d2-5fcc700.objdump.txt", "0x5fcc700", "0x5fcc742"),
    ("node-env-d0-5fcd840.objdump.txt", "0x5fcd840", "0x5fcd88a"),
    ("node-env-fwd2-5fcc7e0.objdump.txt", "0x5fcc7e0", "0x5fcc7ee"),
    ("node-env-fwd3-5fcc7f0.objdump.txt", "0x5fcc7f0", "0x5fcc7fe"),
    ("node-clock-d2-5fcc6b0.objdump.txt", "0x5fcc6b0", "0x5fcc6f2"),
    ("node-clock-d0-5fcd7f0.objdump.txt", "0x5fcd7f0", "0x5fcd83a"),
    ("node-clock-fwd2-5fcc7c0.objdump.txt", "0x5fcc7c0", "0x5fcc7ce"),
    ("node-clock-fwd3-5fcc7d0.objdump.txt", "0x5fcc7d0", "0x5fcc7de"),
    ("node-envptr-d1-5fcc6a0.objdump.txt", "0x5fcc6a0", "0x5fcc6a5"),
    ("node-envptr-d0-5fcc830.objdump.txt", "0x5fcc830", "0x5fcc83e"),
]


def main():
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=" + start, "--stop-address=" + stop,
             "work/hl-node-115.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(out)
        print("wrote", name, len(out.splitlines()), "lines")
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    blocks = []
    for _name, start, _stop in EXCERPTS:
        want = int(start, 16)
        found = None
        for line in frames.splitlines():
            m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
            if m and int(m.group(1), 16) == want:
                found = line
                break
        if found is None:
            raise SystemExit("no FDE header for %#x" % want)
        blocks.append(found)
    with open(os.path.join(HERE, "frames.txt"), "w") as fh:
        fh.write("\n".join(blocks) + "\n")
    print("wrote frames.txt", len(blocks), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
