"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-systemclock-installers-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout. The
five vtable installers (vtable_install_1..5) and the three entry
thunks (entry_install_1..3) are regenerated here: their bytes are
identical to the excerpts open PR #3352 shipped (now merged), so
this packet re-ships them with credit and the regeneration
reproduces them.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("append-6099ce0.objdump.txt", "0x6099ce0", "0x6099e34"),
    ("grow-6099790.objdump.txt", "0x6099790", "0x6099cad"),
    ("emu-ctor-6029390.objdump.txt", "0x6029390", "0x60294f5"),
    ("lastuse-5d35070.objdump.txt", "0x5d35070", "0x5d350bc"),
    ("landing-602934c.objdump.txt", "0x602934c", "0x6029383"),
    ("reg-sysclocks-5fd27c0.objdump.txt", "0x5fd27c0", "0x5fd297f"),
    ("default-init-5fd20d0.objdump.txt", "0x5fd20d0", "0x5fd241d"),
    ("insert-5fd24c0.objdump.txt", "0x5fd24c0", "0x5fd2748"),
    ("invoker-mockenv-5fcd5b0.objdump.txt", "0x5fcd5b0", "0x5fcd5db"),
    ("invoker-timeemu-5fcd550.objdump.txt", "0x5fcd550", "0x5fcd5a9"),
    ("invoker-composite-5fcf450.objdump.txt", "0x5fcf450", "0x5fcf4cb"),
    ("factory-60297a0.objdump.txt", "0x60297a0", "0x60298f7"),
    ("accessor-5fcf430.objdump.txt", "0x5fcf430", "0x5fcf439"),
    ("node-dtor-5fcc700.objdump.txt", "0x5fcc700", "0x5fcc742"),
    ("vtable_install_1.txt", "0x5fd0090", "0x5fd0178"),
    ("vtable_install_2.txt", "0x6029110", "0x602922b"),
    ("vtable_install_3.txt", "0x6029230", "0x602934b"),
    ("vtable_install_4.txt", "0x6029500", "0x602961b"),
    ("vtable_install_5.txt", "0x6029620", "0x602973b"),
    ("entry_install_1.txt", "0x5fcc5d0", "0x5fcc5fd"),
    ("entry_install_2.txt", "0x5fcc600", "0x5fcc62d"),
    ("entry_install_3.txt", "0x5fcc630", "0x5fcc65d"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0075d930 ", "0075d8e0 ", "00756b8c ", "00346ba0 ", "00756bd0 ",
    "0074e54c ", "0074e43c ", "0074e4b4 ", "003620b0 ", "0074ddb4 ",
    "0074e048 ", "00756bf0 ", "00362454 ", "0074dca0 ", "0074e1dc ",
    "00366338 ", "00366374 ", "003663b0 ", "003663e0 ", "00361c9c ",
    "00361cb0 ", "00361cc4 ",
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
    for prefix in FRAME_PREFIXES:
        for line in frames.splitlines():
            if line.startswith(prefix):
                blocks.append(line)
                break
    with open(os.path.join(HERE, "frames.txt"), "w") as fh:
        fh.write("\n".join(blocks) + "\n")
    print("wrote frames.txt", len(blocks), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
