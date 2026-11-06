#!/usr/bin/env python3
"""Census of code transfers to the node #115 MessagePack string
writer 0x57cf5d0.

Scans the executable LOAD segment of work/hl-node-115.bin for
E8/E9 rel32 transfers whose target is the routine, then confirms
the candidates against objdump's own disassembly: a candidate is
kept only when a single streaming objdump pass over the binary
shows a call/jmp instruction starting exactly at the candidate
address with the routine as its target. Each confirmed site is
assigned the smallest enclosing FDE from readelf
--debug-dump=frames-interp. Prints counts and writes callers.tsv
next to this script when run with --write.
"""
import bisect
import json
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
TARGET = 0x57CF5D0


def scan(target):
    data = (BIN).read_bytes()[EXEC_OFF:EXEC_OFF + EXEC_SIZE]
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
    return raw


def confirmed(raw, target):
    pat = re.compile(
        r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+%x\s"
        % target)
    seen = {}
    proc = subprocess.Popen(
        ["objdump", "-d", str(BIN)],
        stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        m = pat.match(line)
        if m:
            seen[int(m.group(1), 16)] = m.group(2)
    proc.wait()
    out = []
    for va, op in raw:
        kind = "call" if op == 0xE8 else "jmp"
        if seen.get(va) == kind:
            out.append((va, kind))
    return out


def fde_ranges():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True).stdout
    ranges = sorted(
        (int(a, 16), int(b, 16))
        for a, b in re.findall(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", text))
    return ranges


def main():
    ranges = fde_ranges()
    starts = [s for s, _ in ranges]
    rows = confirmed(scan(TARGET), TARGET)
    lines = ["site\tkind\tcaller_fde_start\tcaller_fde_end"]
    for va, kind in rows:
        i = bisect.bisect_right(starts, va) - 1
        s, e = ranges[i]
        assert s <= va < e, hex(va)
        lines.append(f"0x{va:x}\t{kind}\t0x{s:x}\t0x{e:x}")
    if "--write" in sys.argv:
        (Path(__file__).parent / "callers.tsv").write_text(
            "\n".join(lines) + "\n")
    counts = {"direct_calls": sum(1 for _, k in rows if k == "call"),
              "tail_jumps": sum(1 for _, k in rows if k == "jmp"),
              "total": len(rows)}
    if "--sites" in sys.argv:
        counts["sites"] = [[hex(va), kind] for va, kind in rows]
    print(json.dumps({"main": counts}))


if __name__ == "__main__":
    main()
