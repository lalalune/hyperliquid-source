"""Regenerate the verbatim objdump excerpts in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-shard-member-access-94/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

WINDOWS = {
    "window.txt": (0x516A390, 0x516AA1C),
    "thunk.txt": (0x516AA20, 0x516AA43),
    "index_helpers.txt": (0x53356A0, 0x53356C0),
    "rng_state.txt": (0x5423A50, 0x5423AE7),
    "zero_init.txt": (0x541CA90, 0x541CAA4),
    "wrapper_global.txt": (0x5190D50, 0x5190E3F),
    "wrapper_shard.txt": (0x5190F70, 0x519109E),
}


def main():
    for name, (start, stop) in WINDOWS.items():
        out = subprocess.run(
            [
                "objdump", "-d",
                "--start-address=%#x" % start,
                "--stop-address=%#x" % stop,
                "work/hl-node-94.bin",
            ],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(out)
        print("wrote", name, len(out.splitlines()), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
