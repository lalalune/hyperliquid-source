"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-hashlinklist-insert-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
The index-builder, index-insert and log-gate excerpts are
regenerated here from the same binary and ranges pinned in open PR
#3575 (RE-001-chain-histogram-snapshot-115); they are re-shipped
byte-identical as the host's callees. The hex-encode excerpt is
regenerated from the same binary and range pinned in open PR #3561
(RE-001-serializer-115); it is re-shipped byte-identical as the
host's log-path callee.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

EXCERPTS = [
    ("host-605f700.objdump.txt", "0x605f700", "0x605fe21"),
    ("host-cleanup-605f6d6.objdump.txt", "0x605f6d6", "0x605f700"),
    ("ctor-605eb40.objdump.txt", "0x605eb40", "0x605ec19"),
    ("dtor-605ea00.objdump.txt", "0x605ea00", "0x605ea23"),
    ("varint32-61bd4f0.objdump.txt", "0x61bd4f0", "0x61bd53b"),
    ("transform-5e9af30.objdump.txt", "0x5e9af30", "0x5e9b142"),
    ("wyhash-61c38a0.objdump.txt", "0x61c38a0", "0x61c3bb9"),
    ("hex-encode-61c7e30.objdump.txt", "0x61c7e30", "0x61c7fb6"),
    ("index-builder-605f290.objdump.txt", "0x605f290", "0x605f33a"),
    ("index-insert-605f340.objdump.txt", "0x605f340", "0x605f6d5"),
    ("log-gate-5fcef60.objdump.txt", "0x5fcef60", "0x5fcf043"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "0075a430 ",  # host 0x605f700..0x605fe21
    "0075a484 ",  # host cleanup 0x605f6d6..0x605f700
    "0075a348 ",  # ctor 0x605eb40..0x605ec19
    "00367960 ",  # dtor 0x605ea00..0x605ea23
    "0037652c ",  # varint32 decoder 0x61bd4f0..0x61bd53b
    "00354dfc ",  # canonical transform 0x5e9af30..0x5e9b142
    "00376e1c ",  # hash 0x61c38a0..0x61c3bb9
    "0076c584 ",  # hex encode 0x61c7e30..0x61c7fb6
    "00367b98 ",  # index builder 0x605f290..0x605f33a
    "00367bb4 ",  # index insert 0x605f340..0x605f6d5
    "00362334 ",  # log gate 0x5fcef60..0x5fcf043
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
        if not block:
            print("FAIL: no FDE block for prefix %s" % prefix.strip())
            return 1
        blocks.append("\n".join(block))
    with open(os.path.join(HERE, "frames.txt"), "w") as fh:
        fh.write("\n\n".join(blocks) + "\n")
    print("wrote frames.txt", len(blocks), "blocks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
