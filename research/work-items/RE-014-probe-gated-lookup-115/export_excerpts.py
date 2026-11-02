"""Regenerate the verbatim objdump excerpts for RE-014-probe-gated-lookup-115.

Run from the repository root. The target binary is the digest-verified
local copy at work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
per provenance/artifacts.json; work/ is git-ignored, so the binary
itself is not committed). objdump 2.x, x86-64, Intel syntax is the
tool default used here; excerpts are whole functions, unmodified.
"""
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work" / "hl-node-115.bin"
OUT = Path(__file__).resolve().parent
EXPECT = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = {
    "window-5f0d050.objdump.txt": (0x5F0D050, 0x5F0D704),
    "hash-61c34a0.objdump.txt": (0x61C34A0, 0x61C3525),
    "thunk-5f0b050.objdump.txt": (0x5F0B050, 0x5F0B073),
    "move-5f05310.objdump.txt": (0x5F05310, 0x5F05379),
    "timer-5f05950.objdump.txt": (0x5F05950, 0x5F059AB),
}


def main():
    digest = hashlib.sha256(BIN.read_bytes()).hexdigest()
    if digest != EXPECT:
        print("binary digest mismatch:", digest)
        return 1
    for name, (start, stop) in WINDOWS.items():
        cmd = ["objdump", "-d",
               "--start-address=%#x" % start,
               "--stop-address=%#x" % stop, str(BIN)]
        text = subprocess.run(cmd, capture_output=True, text=True,
                              check=True).stdout
        (OUT / name).write_text(text)
        print(name, start, stop, len(text.splitlines()), "lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
