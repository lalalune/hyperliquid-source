#!/usr/bin/env python3
"""Whole-binary census of `+0x21b` displacements (node #115).

Question: is DBOptions+0x21b ever read or written as a struct field?
Method: stream ``objdump -d work/hl-node-115.bin`` (no 390 MB dump file
-- /tmp is a 512 MB tmpfs) and record every instruction whose disassembly
contains a ``0x21b(%reg)`` displacement (positive displacement only;
``-0x21b(%rbp)`` is a stack local and is excluded), together with the
register and the enclosing function (resolved from the .eh_frame FDE
ranges, since objdump headers are sparse in this stripped binary).

Classification:
- ``0x21b(%rsp)`` -- a stack slot, not a struct-field access.
- ``0x21b(%rbx/%rbp/...)`` -- a struct-field access; the packet records
  which struct it belongs to (the five %rbx sites are all in one
  function, 0x5a897e0..0x5a8a1cc, operating on a string-heavy struct
  that is NOT DBOptions: it stores std::strings at +0x18/+0x28/+0x38/
  +0x40, where DBOptions holds numbers, and writes a 'D' tag byte at
  +0x110, where DBOptions holds db_write_buffer_size).

Usage: python3 census_21b.py  (run from the repo root)
Writes census-21b.tsv next to this file and prints the summary.
"""
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = "work/hl-node-115.bin"
OUT = HERE / "census-21b.tsv"

INSN = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$")
# Positive displacement only: the lookbehind rejects "-0x21b(%rbp)".
DISP = re.compile(r"(?<!-)0x21b\(%([a-z0-9]+)\)")
FDE = re.compile(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)")


def fde_ranges():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    ranges = []
    for m in FDE.finditer(out):
        ranges.append((int(m.group(1), 16), int(m.group(2), 16)))
    ranges.sort()
    return ranges


def enclosing(ranges, addr):
    lo, hi = 0, len(ranges) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        s, e = ranges[mid]
        if s <= addr < e:
            return (s, e)
        if addr < s:
            hi = mid - 1
        else:
            lo = mid + 1
    return None


def main():
    ranges = fde_ranges()
    proc = subprocess.Popen(
        ["objdump", "-d", BIN], cwd=ROOT,
        stdout=subprocess.PIPE, text=True,
    )
    total_text = 0
    sites = []
    for line in proc.stdout:
        if "0x21b" in line:
            total_text += 1
        m = INSN.match(line)
        if not m:
            continue
        d = DISP.search(m.group(2))
        if d:
            addr = int(m.group(1), 16)
            fn = enclosing(ranges, addr)
            sites.append((addr, d.group(1), fn))
    proc.wait()
    with open(OUT, "w") as f:
        f.write("address\tregister\tenclosing_fde\n")
        for addr, reg, fn in sites:
            f.write(f"0x{addr:x}\t{reg}\t"
                    f"{f'0x{fn[0]:x}..0x{fn[1]:x}' if fn else 'none'}\n")
    rsp = [s for s in sites if s[1] == "rsp"]
    other = [s for s in sites if s[1] != "rsp"]
    print(f"+0x21b-displacement instructions: {len(sites)} "
          f"({len(rsp)} %rsp stack slots, {len(other)} struct-field uses)")
    print(f"total '0x21b' text matches (incl. false positives): {total_text}")
    for addr, reg, fn in sites:
        print(f"  0x{addr:x}  %{reg}  "
              f"{f'FDE 0x{fn[0]:x}..0x{fn[1]:x}' if fn else 'no FDE'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
