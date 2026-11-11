"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-objectregistry-lifecycle-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout. No
windows are re-shipped from earlier PRs: every excerpt here is
read fresh from work/hl-node-115.bin. The four landing-pad FDEs
(add-library 0x61f8d12, ctor 0x61f913e, getter 0x61f9278, clone
0x61f93c6) are shipped as their own excerpts: each is the
function's exception landing pad, a separate FDE that releases
the partially built objects before resuming the unwind.
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("cb-d1-61f8130.objdump.txt", "0x61f8130", "0x61f8135"),
    ("cb-d0-61f8140.objdump.txt", "0x61f8140", "0x61f814e"),
    ("cb-dispose-61f8760.objdump.txt", "0x61f8760", "0x61f89db"),
    ("cb-destroy-61f8170.objdump.txt", "0x61f8170", "0x61f817e"),
    ("cb-getdeleter-61f8180.objdump.txt", "0x61f8180", "0x61f81c7"),
    ("rec-destroy-61f81d0.objdump.txt", "0x61f81d0", "0x61f8271"),
    ("lockguard-61f814e.objdump.txt", "0x61f814e", "0x61f8165"),
    ("vec-sp-destroy-61f89e0.objdump.txt", "0x61f89e0", "0x61f8ac1"),
    ("vec-insert-5ff7960.objdump.txt", "0x5ff7960", "0x5ff7b45"),
    ("add-library-61f8dc0.objdump.txt", "0x61f8dc0", "0x61f913d"),
    ("add-library-landingpads-61f8d12.objdump.txt", "0x61f8d12", "0x61f8db1"),
    ("reg-ctor-61f91b0.objdump.txt", "0x61f91b0", "0x61f9277"),
    ("ctor-landingpad-61f913e.objdump.txt", "0x61f913e", "0x61f91a6"),
    ("reg-getter-61f92b0.objdump.txt", "0x61f92b0", "0x61f93c5"),
    ("getter-landingpad-61f9278.objdump.txt", "0x61f9278", "0x61f92a2"),
    ("clone-61f9400.objdump.txt", "0x61f9400", "0x61f963e"),
    ("clone-landingpad-61f93c6.objdump.txt", "0x61f93c6", "0x61f93f2"),
    ("ttl-register-62069f0.objdump.txt", "0x62069f0", "0x6206d29"),
    ("registrar-init-620b470.objdump.txt", "0x620b470", "0x620b57d"),
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
