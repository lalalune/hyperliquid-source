#!/usr/bin/env python3
"""Census of code transfers to the node #115 list append routine
0x5d54b50 and its matching erase routine 0x5d54ba0.

Scans the executable LOAD segment of work/hl-node-115.bin for E8/E9
rel32 transfers whose target is either routine, confirms each
candidate by disassembling exactly at the candidate address with
objdump, and names the smallest enclosing FDE (from
readelf --debug-dump=frames-interp) as the caller function. Prints
counts and writes callers.tsv and erase_callers.tsv next to this
script when run with --write.
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
TARGETS = {"append": 0x5D54B50, "erase": 0x5D54BA0}


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
    out = []
    for va, op in raw:
        text = subprocess.run(
            ["objdump", "-d", f"--start-address={va}",
             f"--stop-address={va + 8}", str(BIN)],
            capture_output=True, text=True).stdout
        m = re.search(
            r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\t(call|jmp)\s+([0-9a-f]+)",
            text, re.M)
        if (m and int(m.group(1), 16) == va
                and int(m.group(3), 16) == target):
            out.append((va, "call" if op == 0xE8 else "jmp"))
    return out


def fde_ranges():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    ranges = sorted(
        (int(a, 16), int(b, 16))
        for a, b in re.findall(r"pc=0*([0-9a-f]+)\.\.0*([0-9a-f]+)", text))
    return ranges


def main():
    ranges = fde_ranges()
    starts = [s for s, _ in ranges]
    result = {}
    rows_by_name = {}
    for name, target in TARGETS.items():
        rows = confirmed(scan(target), target)
        rows_by_name[name] = rows
        result[name] = {
            "direct_calls": sum(1 for _, k in rows if k == "call"),
            "tail_jumps": sum(1 for _, k in rows if k == "jmp"),
            "total": len(rows),
        }
        if "--sites" in sys.argv:
            result[name]["sites"] = [[hex(va), kind] for va, kind in rows]
    if "--write" in sys.argv:
        for name, fname in (("append", "callers.tsv"),
                            ("erase", "erase_callers.tsv")):
            lines = ["site\tkind\tcaller_fde_start\tcaller_fde_end"]
            for va, kind in rows_by_name[name]:
                i = bisect.bisect_right(starts, va) - 1
                s, e = ranges[i]
                assert s <= va < e, hex(va)
                lines.append(f"0x{va:x}\t{kind}\t0x{s:x}\t0x{e:x}")
            (Path(__file__).parent / fname).write_text(
                "\n".join(lines) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
