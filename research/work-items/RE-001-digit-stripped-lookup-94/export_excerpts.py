#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-digit-stripped-lookup-94/export_excerpts.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. The excerpts are whole functions (plus int3 padding to
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
    # holds the whole function plus its int3 padding.
    "window.objdump.txt": ("0x514e160", "0x514e3c0"),
    "callee.objdump.txt": ("0x5427800", "0x5427990"),
    "helper.objdump.txt": ("0x5427770", "0x5427790"),
    "caller.objdump.txt": ("0x4fc35d0", "0x4fc37f0"),
}

PLT_STUBS = (
    # (stub address, stub size) for every PLT entry the packet cites.
    ("0x5660150", 16),  # memcmp
    ("0x56605a0", 16),  # _Hash_bytes
    ("0x5660440", 16),  # operator delete (sized)
    ("0x5660430", 16),  # __stack_chk_fail
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
