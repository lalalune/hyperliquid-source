"""Regenerate the verbatim disassembly excerpts for the
RE-001-teardown-pair-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-teardown-pair-115/export_excerpts.py

Writes main-release.txt: the whole FDE window 0x5f78000..0x5f78021
of the digest-verified node #115 work binary, exactly as objdump
emits it; main-clear.txt: the whole FDE window 0x5f78030..0x5f78059;
site-landing.txt: the landing-pad triple in 0x5f7ede0..0x5f7f280
(release call, clear call, release call, plus the surrounding
exception-handling calls); site-cleanup.txt: the cleanup sequence
in 0x5f7f280..0x5f7f375 (release, clear, release, plus the immediate
post-call step); site-loop.txt: the loop-back release site
0x5f7f2fa in the same cleanup function. The excerpts are stored
verbatim; verify.py checks that a fresh run reproduces them
byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main-release.txt", 0x5F78000, 0x5F78021),
    ("main-clear.txt", 0x5F78030, 0x5F78059),
    ("site-landing.txt", 0x5F7F223, 0x5F7F25B),
    ("site-cleanup.txt", 0x5F7F280, 0x5F7F2AD),
    ("site-loop.txt", 0x5F7F2EF, 0x5F7F301),
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / name).write_text(text)
        print("wrote %s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
