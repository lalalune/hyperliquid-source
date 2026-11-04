"""Regenerate the verbatim excerpts and frame records of this packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-ingest-behind-check-115/export_excerpts.py

Regenerates gate.txt, wrapper.txt and reporter.txt with the objdump
commands recorded in README.md, and frames.txt from the FDE blocks of
those three windows. Callers.tsv is NOT regenerated here; census.py
owns it (it needs a full disassembly pass).
"""

import re
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

WINDOWS = [
    ("gate.txt", 0x5EBD1C0, 0x5EBD323),
    ("wrapper.txt", 0x5EBD130, 0x5EBD1B8),
    ("reporter.txt", 0x61CF670, 0x61CF767),
]


def dump(start, stop):
    # Run from the repository root with the relative binary path so
    # the objdump header line stays stable.
    return subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout


def main():
    for name, start, stop in WINDOWS:
        (PACKET / name).write_text(dump(start, stop))
    frames = subprocess.run(["objdump", "--dwarf=frames", str(BINARY)],
                            capture_output=True, text=True,
                            check=True).stdout
    wanted = {(start, stop) for _, start, stop in WINDOWS}
    kept = []
    for block in frames.split("\n\n"):
        match = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", block)
        if match and (int(match.group(1), 16),
                      int(match.group(2), 16)) in wanted:
            kept.append(block.strip())
    assert len(kept) == 3, "expected 3 FDE blocks, got %d" % len(kept)
    (PACKET / "frames.txt").write_text("\n\n".join(kept) + "\n")
    print("regenerated %d excerpts and %d FDE blocks"
          % (len(WINDOWS), len(kept)))


if __name__ == "__main__":
    main()
