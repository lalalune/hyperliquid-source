#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-blockcache-chain-lookup-94/export_excerpts.py \\
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
    "window.objdump.txt": ("0x514e550", "0x514e7e0"),
    "walker.objdump.txt": ("0x514ba10", "0x514bb10"),
    "helper.objdump.txt": ("0x52f5290", "0x52f5430"),
    "cleanup.objdump.txt": ("0x514e528", "0x514e550"),
    "caller.objdump.txt": ("0x514e7e0", "0x514e870"),
}

PLT_STUBS = (
    # (stub address, stub size) for every PLT entry the packet cites.
    ("0x5660470", 16),  # _M_dispose
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
        plt_text += objdump(args.binary, [
            "-d",
            "--start-address=%s" % stub,
            "--stop-address=%s" % hex(int(stub, 16) + size)])
    with open(os.path.join(PACKET_DIR, "plt.objdump.txt"), "w") as f:
        f.write(plt_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
