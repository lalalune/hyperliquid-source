#!/usr/bin/env python3
"""Whole-binary census of references to the six option maps (node #115).

Targets (globals in .data, from the static initializer 0x60aa2b0):
  0x6506dc0  MutableDBOptions OptionTypeInfo map (19 entries, blocks 0-18)
  0x6506d80  DBOptions OptionTypeInfo map (81 pairs, blocks 19-91 + specials)
  0x6506ec0  WalRecoveryMode enum-name map (4 pairs)
  0x6506e80  AccessHint enum-name map (4 pairs)
  0x6506e40  InfoLogLevel enum-name map (2 pairs)
  0x6506e00  lowest_used_cache_tier enum-name map (6 pairs)
  0x6506f00  'Version' section string
  0x6506f20  'DBOptions' section string
  0x6506f40  'CFOptions' section string
  0x6506f60  'TableOptions/' section string
  0x6506f80  'Unknown' section string

Method: stream ``objdump -d work/hl-node-115.bin`` (no 390 MB dump file
-- /tmp is a 512 MB tmpfs) and record every instruction whose disassembly
carries a ``# <target>`` RIP-relative comment, together with the enclosing
function (resolved from the .eh_frame FDE ranges).

Usage: python3 census_consumers.py  (run from the repo root)
Writes consumers.tsv next to this file and prints a summary.
"""

import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = "work/hl-node-115.bin"
OUT = HERE / "consumers.tsv"

INSN = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$")
COMMENT = re.compile(r"# ([0-9a-f]+)\s")
FDE = re.compile(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)")

TARGETS = {
    0x6506DC0: "mutable-map",
    0x6506D80: "dboptions-map",
    0x6506EC0: "walrecovery-enum-map",
    0x6506E80: "accesshint-enum-map",
    0x6506E40: "infologlevel-enum-map",
    0x6506E00: "lowestcachetier-enum-map",
    0x6506F00: "str-Version",
    0x6506F20: "str-DBOptions",
    0x6506F40: "str-CFOptions",
    0x6506F60: "str-TableOptions/",
    0x6506F80: "str-Unknown",
}


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
    sites = []
    for line in proc.stdout:
        m = INSN.match(line)
        if not m:
            continue
        c = COMMENT.search(m.group(2))
        if not c:
            continue
        tgt = int(c.group(1), 16)
        if tgt in TARGETS:
            addr = int(m.group(1), 16)
            fn = enclosing(ranges, addr)
            sites.append((addr, tgt, m.group(2).strip(), fn))
    proc.wait()
    with open(OUT, "w") as f:
        f.write("address\ttarget\ttarget_name\tinstruction\t"
                "enclosing_fde\n")
        for addr, tgt, text, fn in sites:
            f.write(f"0x{addr:x}\t0x{tgt:x}\t{TARGETS[tgt]}\t{text}\t"
                    f"{f'0x{fn[0]:x}..0x{fn[1]:x}' if fn else 'none'}\n")
    from collections import Counter, defaultdict
    by_target = defaultdict(list)
    for addr, tgt, text, fn in sites:
        by_target[tgt].append((addr, fn))
    for tgt in sorted(TARGETS):
        rows = by_target.get(tgt, [])
        fdes = sorted({fn for _, fn in rows if fn})
        print(f"0x{tgt:x} {TARGETS[tgt]}: {len(rows)} sites, "
              f"{len(fdes)} FDEs")
        for s, e in fdes:
            n = sum(1 for _, fn in rows if fn == (s, e))
            print(f"    FDE 0x{s:x}..0x{e:x} ({n} sites)")
    print(f"total sites: {len(sites)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
