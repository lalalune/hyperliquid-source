#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-level-report-94/export_excerpts.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. Output files are written next to this script and are
byte-identical to the shipped excerpts when run against the
digest-pinned binary with the same binutils version (GNU binutils
2.42 here). The excerpts are whole functions (plus int3 padding to
the next FDE), never trimmed windows.
"""

import argparse
import os
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- stop is the next FDE start, so the file
    # holds the whole function plus its int3 padding. The main
    # function has no padding: its FDE ends exactly where the
    # cleanup FDE starts.
    "window.objdump.txt": ("0x514c580", "0x514c74e"),
    "cleanup.objdump.txt": ("0x514c74e", "0x514c780"),
    "trampoline.objdump.txt": ("0x51cbcd0", "0x51cbcf0"),
    "sum.objdump.txt": ("0x50047b0", "0x50047f0"),
}

PLT_STUBS = (
    # (stub address, stub size) for every PLT entry the packet cites.
    ("0x5660120", 16),  # strlen
    ("0x5660600", 16),  # basic_string::_M_append
    ("0x56605f0", 16),  # __snprintf_chk
    ("0x56604a0", 16),  # __throw_length_error
    ("0x5660430", 16),  # __stack_chk_fail
    ("0x5660110", 16),  # _Unwind_Resume
)


def objdump(binary, args):
    result = subprocess.run(["objdump"] + args + [binary],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("objdump failed: %s" % result.stderr.strip())
    return result.stdout


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    args = ap.parse_args(argv)
    for name, (start, stop) in RANGES.items():
        text = objdump(args.binary, [
            "-d",
            "--start-address=%s" % start,
            "--stop-address=%s" % stop])
        with open(os.path.join(PACKET_DIR, name), "w") as f:
            f.write(text)
    plt_text = ""
    for stub, size in PLT_STUBS:
        start = int(stub, 16)
        plt_text += objdump(args.binary, [
            "-d",
            "--start-address=%s" % stub,
            "--stop-address=%#x" % (start + size)])
    with open(os.path.join(PACKET_DIR, "plt.objdump.txt"), "w") as f:
        f.write(plt_text)
    print("wrote %d excerpts" % (len(RANGES) + 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
