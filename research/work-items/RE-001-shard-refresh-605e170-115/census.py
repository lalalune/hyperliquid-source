#!/usr/bin/env python3
"""Census of code transfers to the node #115 shard refresh
routine 0x605e170.

Scans the executable LOAD segment of work/hl-node-115.bin for
E8/E9 rel32 transfers whose target is the routine, then confirms
each candidate site by side: a candidate is kept only when an
objdump disassembly of its smallest enclosing FDE shows a
call/jmp instruction starting exactly at the candidate address
with the routine as its target (the per-site method of the
sibling RE packets). Also reports whole-file qword hits for the
routine address and .rela.dyn R_X86_64_RELATIVE slots whose
addend is the routine. Prints counts and writes callers.tsv
next to this script when run with --write.
"""
import bisect
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work/hl-node-115.bin"
EXEC_OFF = 0x1418300
EXEC_VA = 0x1419300
EXEC_SIZE = 0x4FD88A0
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8
TARGET = 0x605E170


def scan(target):
    data = BIN.read_bytes()[EXEC_OFF:EXEC_OFF + EXEC_SIZE]
    raw = []
    for op in (0xE8, 0xE9):
        i = 0
        while True:
            i = data.find(bytes([op]), i)
            if i < 0:
                break
            if i + 5 <= len(data):
                rel = struct.unpack_from("<i", data, i + 1)[0]
                if EXEC_VA + i + 5 + rel == target:
                    raw.append((EXEC_VA + i, op))
            i += 1
    return sorted(raw)


def fde_ranges():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True).stdout
    ranges = []
    for line in text.splitlines():
        m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m and "FDE cie=" in line:
            ranges.append((int(m.group(1), 16), int(m.group(2), 16)))
    return sorted(ranges)


def enclosing(ranges, va):
    starts = [r[0] for r in ranges]
    i = bisect.bisect_right(starts, va) - 1
    best = None
    while i >= 0:
        lo, hi = ranges[i]
        if lo <= va < hi and (best is None or hi - lo < best[1] - best[0]):
            best = (lo, hi)
        if hi <= va and best is not None:
            break
        i -= 1
    return best


def confirmed(raw, ranges):
    out = []
    cache = {}
    for va, op in raw:
        fde = enclosing(ranges, va)
        if fde is None:
            continue
        if fde not in cache:
            text = subprocess.run(
                ["objdump", "-d", f"--start-address={hex(fde[0])}",
                 f"--stop-address={hex(fde[1])}", str(BIN)],
                capture_output=True, text=True, check=True).stdout
            cache[fde] = text
        kind = "call" if op == 0xE8 else "jmp"
        pat = re.compile(
            r"^\s*%x:\s+[0-9a-f ]+\t%s\s+%x\s" % (va, kind, TARGET))
        if any(pat.match(line) for line in cache[fde].splitlines()):
            out.append((va, kind, fde))
    return out


def qword_and_slots(target):
    data = BIN.read_bytes()
    pat = struct.pack("<Q", target)
    hits = []
    start = 0
    while True:
        j = data.find(pat, start)
        if j < 0:
            break
        hits.append(j)
        start = j + 1
    slots = []
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if (info & 0xFFFFFFFF) == 8 and add == target:
            slots.append(ro)
    return hits, slots


def main():
    ranges = fde_ranges()
    raw = scan(TARGET)
    sites = confirmed(raw, ranges)
    hits, slots = qword_and_slots(TARGET)
    calls = [s for s in sites if s[1] == "call"]
    jmps = [s for s in sites if s[1] == "jmp"]
    print(f"target {TARGET:#x}")
    print(f"  raw scan candidates: {len(raw)}")
    print(f"  confirmed direct calls: {len(calls)}")
    for va, kind, fde in calls:
        print(f"    {va:#x} in FDE {fde[0]:#x}..{fde[1]:#x}")
    print(f"  confirmed tail jumps: {len(jmps)}")
    print(f"  qword hits (file offsets): "
          f"{' '.join(hex(h) for h in hits) if hits else '(none)'}")
    print(f"  RELATIVE slots: "
          f"{' '.join(hex(s) for s in slots) if slots else '(none)'}")
    if "--write" in sys.argv:
        lines = ["site\tkind\tcaller_fde_start\tcaller_fde_end"]
        for va, kind, fde in sites:
            lines.append(f"{va:#x}\t{kind}\t{fde[0]:#x}\t{fde[1]:#x}")
        out = Path(__file__).parent / "callers.tsv"
        out.write_text("\n".join(lines) + "\n")
        print(f"wrote {out.name} ({len(sites)} sites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
