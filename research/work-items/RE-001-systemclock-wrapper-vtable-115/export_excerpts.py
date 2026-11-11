"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-systemclock-wrapper-vtable-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout. The
constructor 0x5fd0090 IS regenerated here: its bytes are identical
to the excerpt open PR #3352 shipped (vtable_install_1.txt), so this
packet re-ships it with credit and the regeneration reproduces it.
The destructor D0 0x6029500 and the EmulatedSystemClock destructors
0x6029110/0x6029620 are cited by contract, not re-shipped: they are
not vtable slots of the wrapper (slots 0/1 are null) and their full
teardown is the wrapper-destructor work, not this vtable map.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("getoption-609d760.objdump.txt", "0x609d760", "0x609d954"),
    ("areequivalent-609dc40.objdump.txt", "0x609dc40", "0x609de39"),
    ("slot04-emptystring-5d32560.objdump.txt", "0x5d32560", "0x5d3257b"),
    ("prepareoptions-5fcf590.objdump.txt", "0x5fcf590", "0x5fcf658"),
    ("validateoptions-6096790.objdump.txt", "0x6096790", "0x6096f0c"),
    ("getoptionsptr-5d2e090.objdump.txt", "0x5d2e090", "0x5d2e0de"),
    ("slot08-emptystatus-60956f0.objdump.txt", "0x60956f0", "0x609570c"),
    ("configureoptions-609d0e0.objdump.txt", "0x609d0e0", "0x609d75e"),
    ("parseoption-60986b0.objdump.txt", "0x60986b0", "0x6098a9c"),
    ("optionsareequal-6095710.objdump.txt", "0x6095710", "0x609579a"),
    ("serializeoptions-5fcdae0.objdump.txt", "0x5fcdae0", "0x5fcdf63"),
    ("getoptionname-609d980.objdump.txt", "0x609d980", "0x609dc18"),
    ("getid-5d32a30.objdump.txt", "0x5d32a30", "0x5d32a51"),
    ("slot17-wrapped-5fcc3f0.objdump.txt", "0x5fcc3f0", "0x5fcc3f9"),
    ("nowmicros-5d4d490.objdump.txt", "0x5d4d490", "0x5d4d552"),
    ("nownanos-fwd-5fcc340.objdump.txt", "0x5fcc340", "0x5fcc351"),
    ("cpumicros-fwd-5fcc360.objdump.txt", "0x5fcc360", "0x5fcc371"),
    ("cpunanos-fwd-5fcc380.objdump.txt", "0x5fcc380", "0x5fcc391"),
    ("sleep-5dd41a0.objdump.txt", "0x5dd41a0", "0x5dd4262"),
    ("timetostring-5fcc3a0.objdump.txt", "0x5fcc3a0", "0x5fcc3e7"),
    ("emu-name-60257a0.objdump.txt", "0x60257a0", "0x60257ac"),
    ("emu-nowmicros-60259e0.objdump.txt", "0x60259e0", "0x6025a08"),
    ("emu-nownanos-60259a0.objdump.txt", "0x60259a0", "0x60259d2"),
    ("emu-cpumicros-6025a30.objdump.txt", "0x6025a30", "0x6025a46"),
    ("emu-cpunanos-6025a10.objdump.txt", "0x6025a10", "0x6025a26"),
    ("emu-sleep-6025b40.objdump.txt", "0x6025b40", "0x6025b7f"),
    ("emu-getcurrenttime-6025eb0.objdump.txt", "0x6025eb0", "0x6025feb"),
    ("posix-name-5fe0fe0.objdump.txt", "0x5fe0fe0", "0x5fe0fec"),
    ("posix-slot17-null-5d2ca00.objdump.txt", "0x5d2ca00", "0x5d2ca07"),
    ("posix-slot18-5fe0ff0.objdump.txt", "0x5fe0ff0", "0x5fe0ffc"),
    ("posix-cpumicros-5fe1480.objdump.txt", "0x5fe1480", "0x5fe14e4"),
    ("posix-cpunanos-5fe1430.objdump.txt", "0x5fe1430", "0x5fe147c"),
    ("ctor-5fd0090.objdump.txt", "0x5fd0090", "0x5fd0178"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0036b19c ", "0075dd6c ", "00346504 ", "003624a0 ", "0075d4ac ",
    "00345764 ", "0036ae98 ", "0075dc7c ", "0075d728 ", "0036aeac ",
    "0074de40 ", "0075dcf4 ", "003465c4 ", "00361bc4 ", "003490fc ",
    "00361b64 ", "00361b78 ", "00361b8c ", "0034e610 ", "00361ba0 ",
    "00365d78 ", "00365f24 ", "00365f08 ", "00365f54 ", "00365f40 ",
    "00366010 ", "007560c8 ", "00363138 ", "00344b84 ", "0036314c ",
    "003633b8 ", "0036339c ", "0074e1dc ",
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
        block = []
        in_block = False
        for line in frames.splitlines():
            if line.startswith(prefix):
                in_block = True
            elif in_block and line == "":
                break
            if in_block:
                block.append(line)
        blocks.extend(block)
        blocks.append("")
    with open(os.path.join(HERE, "frames.txt"), "w") as fh:
        fh.write("\n".join(blocks))
    print("wrote frames.txt", len(blocks), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
