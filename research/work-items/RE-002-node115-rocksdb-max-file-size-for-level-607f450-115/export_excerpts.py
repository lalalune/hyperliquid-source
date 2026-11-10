#!/usr/bin/env python3
"""Regenerate main.txt for max_file_size_for_level 0x607f450..0x607f48a (node #115).

main.txt is the raw `objdump -d` listing of the whole routine, verbatim
instruction text (with the encoded bytes), with the objdump symbol
header normalized to the bare binary name so the file carries no
machine-specific path or demangled decoration.

Reproduce with:
  objdump -d --start-address=0x607f450 --stop-address=0x607f48a \\
      artifacts/node/115/hl-node
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-max-file-size-for-level-607f450-115")

START = 0x607f450
END = 0x607f48a

HEADER = re.compile(r"^[0-9a-f]+ <.*>:$")
INSN = re.compile(r"^\s*[0-9a-f]+:\t")
ANNOT = re.compile(r" <[^>]*>")


def excerpt():
    out = subprocess.check_output([
        "objdump", "-d",
        f"--start-address={hex(START)}", f"--stop-address={hex(END)}",
        str(BINARY)]).decode()
    lines = []
    for line in out.splitlines():
        if HEADER.match(line):
            lines.append(f"{START:016x} <hl-node>:")
        elif INSN.match(line):
            # Drop objdump's nearest-symbol annotations on branch
            # targets (the image is stripped); keep the raw bytes and
            # the genuine instruction text.
            lines.append(ANNOT.sub("", line))
    return "\n".join(lines) + "\n"


def main():
    text = excerpt()
    PACKET.mkdir(parents=True, exist_ok=True)
    (PACKET / "main.txt").write_text(text)
    n = sum(1 for l in text.splitlines() if ":\t" in l)
    print(f"wrote main.txt ({len(text.splitlines())} lines, {n} instructions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
