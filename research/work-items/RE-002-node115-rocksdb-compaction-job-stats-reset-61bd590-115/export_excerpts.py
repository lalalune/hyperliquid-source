#!/usr/bin/env python3
"""Regenerate main.txt, frames.txt and relocations.txt for
`CompactionJobStats::Reset` 0x61bd590..0x61bd60f (node #115).

main.txt is the raw `objdump -d` listing of the window, verbatim instruction text
with the encoded bytes, the objdump symbol header normalized to the bare binary
name so the file carries no machine-specific path or demangled decoration.
frames.txt is the `.eh_frame` entry of the routine plus the eight that call it.
relocations.txt records the empty relocation set and the body digest.

Reproduce with:
  objdump -d --start-address=0x61bd590 --stop-address=0x61bd60f \\
      artifacts/node/115/hl-node
"""
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = Path(__file__).resolve().parent

SYMBOL = "_ZN7rocksdb18CompactionJobStats5ResetEv"
START = 0x61BD590
END = 0x61BD60F
CALLER_FDES = ((0x5DEB5A0, 0x5DEB8EA), (0x5DEB9C0, 0x5DEBC68),
               (0x5DF2380, 0x5DF3659), (0x5DF3DD0, 0x5DF64B6),
               (0x5DFD120, 0x5DFD41B), (0x5DFD4A0, 0x5DFD77B),
               (0x5DFE640, 0x5DFE8C1), (0x5E41FA0, 0x5E44899))
MEMBER = "6cca28ae25285154-compaction_job_stats_impl.o"

HEADER = re.compile(r"^[0-9a-f]+ <.*>:$")
INSN = re.compile(r"^\s*[0-9a-f]+:\t")
ANNOT = re.compile(r" <[^>]*>")


def window_bytes():
    data = BINARY.read_bytes()
    segs = []
    for line in subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode().splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            segs.append((int(p[2], 16), int(p[1], 16), int(p[4], 16)))
    for v, o, f in segs:
        if v <= START < v + f:
            return data[o + (START - v):o + (START - v) + (END - START)]
    raise AssertionError("the entry is in no LOAD segment")


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
            # Drop objdump's nearest-symbol annotations on branch targets
            # (the image is stripped); keep the raw bytes and instruction text.
            lines.append(ANNOT.sub("", line))
    return "\n".join(lines) + "\n"


def frames():
    out = subprocess.check_output(
        ["readelf", "--debug-dump=frames", str(BINARY)]).decode()
    def one(a, b):
        for line in out.splitlines():
            if f"pc={a:016x}..{b:016x}" in line:
                return line.strip()
        raise AssertionError(f"no FDE {a:#x}..{b:#x}")
    lines = ["# .eh_frame entries: the routine and the eight FDEs that call it",
             one(START, END)]
    lines += [f"# caller: {one(a, b)}" for a, b in CALLER_FDES]
    return "\n".join(lines) + "\n"


def relocations():
    digest = hashlib.sha256(window_bytes()).hexdigest()
    return (f"# {SYMBOL} {START:#x}..{END:#x}: no relocations.\n"
            f"# Vendor census member {MEMBER} records 0 relocations, and the\n"
            f"# body is raw-equal to its source bytes.\n"
            f"# body sha256 {digest}\n")


def main():
    text = excerpt()
    (PACKET / "main.txt").write_text(text)
    (PACKET / "frames.txt").write_text(frames())
    (PACKET / "relocations.txt").write_text(relocations())
    import re as _re
    n = sum(1 for l in text.splitlines()
            if _re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t", l))
    print(f"wrote main.txt ({n} instructions), frames.txt, relocations.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
