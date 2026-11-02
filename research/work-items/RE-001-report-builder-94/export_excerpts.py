#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-report-builder-94/export_excerpts.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. The excerpts are whole functions (plus int3 padding
to the next FDE where padding exists), never trimmed windows.
The cleanup excerpt is the exception-cleanup block immediately
before the window; it has its own FDE (0x5157c0c..0x5157d2a)
plus 6 int3 padding bytes to the window start. The caller excerpt
starts at the unlock call 0x5159099 (an instruction boundary)
and ends at 0x51590c8, just after the sized-delete call, so it
holds no partial instruction.
"""

import argparse
import os
import subprocess

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- stop is the next FDE start, so the
    # file holds the whole function plus its int3 padding.
    "window.objdump.txt": ("0x5157d30", "0x5158ebe"),
    "cleanup.objdump.txt": ("0x5157c0c", "0x5157d30"),
    "teardown.objdump.txt": ("0x514bf60", "0x514bfd1"),
    "find.objdump.txt": ("0x5153a70", "0x5153bb6"),
    "insert.objdump.txt": ("0x5153650", "0x515383b"),
    "itoa.objdump.txt": ("0x4faf340", "0x4faf6ad"),
    "dblfmt.objdump.txt": ("0x514c050", "0x514c1b5"),
    "accessor.objdump.txt": ("0x514df50", "0x514df75"),
    "caller.objdump.txt": ("0x5159099", "0x51590c8"),
}


def objdump(binary, args):
    result = subprocess.run(["objdump"] + args + [binary],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("objdump failed: %s" % result.stderr.strip())
    return result.stdout


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    ap.add_argument("--out", default=None,
                    help="write excerpts here instead of the packet dir")
    args = ap.parse_args(argv)
    out_dir = args.out or PACKET_DIR
    os.makedirs(out_dir, exist_ok=True)
    for name, (start, stop) in RANGES.items():
        text = objdump(args.binary, [
            "-d",
            "--start-address=%s" % start,
            "--stop-address=%s" % stop])
        with open(os.path.join(out_dir, name), "w") as fh:
            fh.write(text)


if __name__ == "__main__":
    main()
