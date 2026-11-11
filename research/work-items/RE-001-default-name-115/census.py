#!/usr/bin/env python3
"""Reproducible caller census for RE-001-default-name-115 (node #115).

One objdump pass over the whole binary counts every direct call/jump
and every lea that references one of the packet's routines or the
global default name, and records the enclosing FDE for each site.
Run from the repository root:

    python3 research/work-items/RE-001-default-name-115/census.py

Writes callers.tsv next to this script (sorted by site address) and
prints the per-target counts to stdout. verify.py re-runs this script
and requires callers.tsv to come out byte-identical.
"""

import bisect
import collections
import re
import subprocess
import sys
from pathlib import Path

BINARY = Path(__file__).resolve().parents[3] / "work" / "hl-node-115.bin"

TARGETS = {
    0x61D2970: "initializer",
    0x6077820: "create_host",
    0x607E710: "resolver_host",
    0x6086B70: "twin_a",
    0x60A7420: "twin_b",
    0x60BF5F0: "matcher_wrapper",
    0x6137290: "release_host",
    0x5E4BCF0: "string_equal",
    0x5D66E30: "map_find_name",
    0x60BF980: "kind_validator",
    0x6075BC0: "once_init_create",
    0x6138A10: "once_init_release",
    0x6130140: "canonical_name",
    0x609E510: "find_entry",
    0x609A410: "find_norm",
    0x60BB9A0: "matcher",
    0x61CF670: "status_builder",
    0x6508980: "default_name",
}


def load_fdes(binary):
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(binary)],
        capture_output=True, text=True, check=True).stdout
    fdes = []
    for m in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def main():
    fdes = load_fdes(BINARY)
    starts = [s for s, _ in fdes]

    def enclosing(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i < 0:
            return None
        s, e = fdes[i]
        return (s, e) if s <= addr < e else None

    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    rows = []
    counts = collections.Counter()
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\t(.*)", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        insn = m.group(2).strip()
        mm = re.search(r"\b(call|jmp)\s+([0-9a-f]+)\s", insn)
        if mm:
            t = int(mm.group(2), 16)
            if t in TARGETS:
                enc = enclosing(addr)
                rows.append((addr, t, TARGETS[t],
                             "%#x..%#x" % enc if enc else "?",
                             mm.group(1)))
                counts[(TARGETS[t], mm.group(1))] += 1
        lm = re.search(r"\blea\b.*#\s+([0-9a-f]+)", insn)
        if lm:
            t = int(lm.group(1), 16)
            if t in TARGETS:
                enc = enclosing(addr)
                rows.append((addr, t, TARGETS[t],
                             "%#x..%#x" % enc if enc else "?",
                             "lea"))
                counts[(TARGETS[t], "lea")] += 1
    rows.sort()
    out_path = Path(__file__).resolve().parent / "callers.tsv"
    with open(out_path, "w") as f:
        f.write("site\ttarget\tcaller\tkind\n")
        for addr, t, name, enc, kind in rows:
            f.write("%#x\t%#x\t%s\t%s\n" % (addr, t, enc, kind))
    for (name, kind), n in sorted(counts.items()):
        print("%-24s %-4s %d" % (name, kind, n))
    print("rows: %d" % len(rows))


if __name__ == "__main__":
    main()
