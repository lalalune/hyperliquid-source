"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-composite-env-wrapper-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout. The
four re-shipped windows (accessor-5fcf430, invoker-composite-5fcf450,
append-6099ce0, grow-6099790) are regenerated here: their bytes are
identical to the excerpts PR #3948 shipped, so this packet re-ships
them with credit and the regeneration reproduces them.
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("builder-5fd7360.objdump.txt", "0x5fd7360", "0x5fd7466"),
    ("install-5fceb20.objdump.txt", "0x5fceb20", "0x5fcebb7"),
    ("string-init-5fd5cc0.objdump.txt", "0x5fd5cc0", "0x5fd5cd4"),
    ("wrapper-d2-5fd72d0.objdump.txt", "0x5fd72d0", "0x5fd730b"),
    ("wrapper-d0-5fd7510.objdump.txt", "0x5fd7510", "0x5fd7558"),
    ("basedtor-5fcf4d0.objdump.txt", "0x5fcf4d0", "0x5fcf585"),
    ("wslot5-5fd7560.objdump.txt", "0x5fd7560", "0x5fd76b1"),
    ("wslot12-5fd5e00.objdump.txt", "0x5fd5e00", "0x5fd5f07"),
    ("wslot14-5fd4e60.objdump.txt", "0x5fd4e60", "0x5fd4e6c"),
    ("wslot16-5fd6240.objdump.txt", "0x5fd6240", "0x5fd6271"),
    ("wslot17-5fd4e70.objdump.txt", "0x5fd4e70", "0x5fd4e79"),
    ("holder-init-5fe2860.objdump.txt", "0x5fe2860", "0x5fe2c2f"),
    ("node-slot2-5fcc7e0.objdump.txt", "0x5fcc7e0", "0x5fcc7ee"),
    ("cb-dispose-6025950.objdump.txt", "0x6025950", "0x6025964"),
    ("cb-destroy-6025b90.objdump.txt", "0x6025b90", "0x6025b9e"),
    ("helper-5fcf390.objdump.txt", "0x5fcf390", "0x5fcf399"),
    ("fwd-45-5fd4e80.objdump.txt", "0x5fd4e80", "0x5fd4ec7"),
    ("fwd-46-5fd4ed0.objdump.txt", "0x5fd4ed0", "0x5fd4ee1"),
    ("fwd-47-5fd4ef0.objdump.txt", "0x5fd4ef0", "0x5fd4f01"),
    ("fwd-48-5fd4f10.objdump.txt", "0x5fd4f10", "0x5fd4f21"),
    ("fwd-49-5fd4f30.objdump.txt", "0x5fd4f30", "0x5fd4f41"),
    ("fwd-50-5fd4f70.objdump.txt", "0x5fd4f70", "0x5fd4f81"),
    ("fwd-51-5fd4f90.objdump.txt", "0x5fd4f90", "0x5fd4fa1"),
    ("fwd-52-5fd4f50.objdump.txt", "0x5fd4f50", "0x5fd4f61"),
    ("fwd-59-5fd4fb0.objdump.txt", "0x5fd4fb0", "0x5fd4ff7"),
    ("fwd-63-5fd5000.objdump.txt", "0x5fd5000", "0x5fd5011"),
    ("fwd-64-5fd5020.objdump.txt", "0x5fd5020", "0x5fd5031"),
    ("fwd-65-5fd5040.objdump.txt", "0x5fd5040", "0x5fd508a"),
    ("fwd-66-5fd5090.objdump.txt", "0x5fd5090", "0x5fd50a1"),
    ("fwd-67-5fd50b0.objdump.txt", "0x5fd50b0", "0x5fd50c1"),
    ("fwd-68-5fd50f0.objdump.txt", "0x5fd50f0", "0x5fd5137"),
    ("fwd-69-5fd50d0.objdump.txt", "0x5fd50d0", "0x5fd50e1"),
    ("fwd-71-5fd51d0.objdump.txt", "0x5fd51d0", "0x5fd5217"),
    ("fwd-79-5fd5140.objdump.txt", "0x5fd5140", "0x5fd5187"),
    ("fwd-80-5fd5190.objdump.txt", "0x5fd5190", "0x5fd51a1"),
    ("fwd-81-5fd51b0.objdump.txt", "0x5fd51b0", "0x5fd51c1"),
    ("accessor-5fcf430.objdump.txt", "0x5fcf430", "0x5fcf439"),
    ("invoker-composite-5fcf450.objdump.txt", "0x5fcf450", "0x5fcf4cb"),
    ("append-6099ce0.objdump.txt", "0x6099ce0", "0x6099e34"),
    ("grow-6099790.objdump.txt", "0x6099790", "0x6099cad"),
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
