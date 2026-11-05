#!/usr/bin/env python3
"""Census of every code reference to the node #115 table-footer magic
constants, plus direct transfers to the two pinned routines.

Three reference classes are scanned over the whole binary:
  * rip_relative -- REX.W instructions with a RIP-relative ModRM whose
    computed target is one of the four constant slots
    (0x97a0a0, 0x97a0a8, 0x97bdf0, 0x97bdf8);
  * movabs -- REX.W movabs instructions whose imm64 equals one of the
    four constant values;
  * stored -- raw 8-byte occurrences of each constant value anywhere
    in the file (the slots themselves included).
Every rip_relative / movabs candidate is confirmed by disassembling
exactly at the candidate address with objdump and checking the
printed target / immediate. Direct transfers to the pinned routines
(0x6168620 Build, 0x6168780 DecodeFrom) are found with the executable
LOAD segment E8/E9 rel32 scan and objdump confirmation, and each site
is attributed to the smallest enclosing FDE (readelf frames).

Prints a JSON summary; with --write also writes refs.tsv,
callers.tsv, decode_callers.tsv and stored.tsv next to this script;
with --sites the JSON carries the exact site lists.
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

SLOTS = {
    0x97A0A0: "block_legacy_slot",
    0x97A0A8: "block_current_slot",
    0x97BDF0: "pair2_written_slot",
    0x97BDF8: "pair2_current_slot",
}
VALUES = {
    0xDB4775248B80FB57: "block_legacy",
    0x88E241B785F4CFF7: "block_current",
    0x4F3418EB7A8F13B8: "pair2_written",
    0x8242229663BF9564: "pair2_current",
}
ROUTINES = {"build": 0x6168620, "decode": 0x6168780}
RIP_OPS = (0x8B, 0x8D, 0x03, 0x2B, 0x3B, 0x39, 0x23, 0x63)


def fde_ranges():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    return sorted(
        (int(a, 16), int(b, 16))
        for a, b in re.findall(r"pc=0*([0-9a-f]+)\.\.0*([0-9a-f]+)", text))


def enclosing(ranges, starts, va):
    i = bisect.bisect_right(starts, va) - 1
    if i < 0:
        return None
    s, e = ranges[i]
    return (s, e) if s <= va < e else None


def rip_candidates(data):
    out = []
    n = len(data)
    for i in range(EXEC_OFF, EXEC_OFF + EXEC_SIZE - 7):
        if data[i] not in (0x48, 0x49, 0x4C, 0x4D):
            continue
        if data[i + 1] not in RIP_OPS:
            continue
        if data[i + 2] & 0xC7 != 0x05:
            continue
        disp = struct.unpack_from("<i", data, i + 3)[0]
        va = i - EXEC_OFF + EXEC_VA
        tgt = va + 7 + disp
        if tgt in SLOTS:
            out.append((va, tgt))
    return out


def movabs_candidates(data):
    out = []
    for value in VALUES:
        pat = struct.pack("<Q", value)
        for rex in (0x48, 0x49):
            for reg in range(8):
                needle = bytes([rex, 0xB8 + reg]) + pat
                i = data.find(needle, EXEC_OFF)
                while 0 <= i < EXEC_OFF + EXEC_SIZE:
                    out.append((i - EXEC_OFF + EXEC_VA, value))
                    i = data.find(needle, i + 1)
    return sorted(out)


def confirm_rip(va, target):
    text = subprocess.run(
        ["objdump", "-d", f"--start-address={va}",
         f"--stop-address={va + 8}", str(BIN)],
        capture_output=True, text=True).stdout
    m = re.search(r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\t[a-z0-9]+\s+[^#]*#\s*"
                  r"([0-9a-f]+)", text, re.M)
    return bool(m and int(m.group(1), 16) == va
                and int(m.group(2), 16) == target)


def confirm_movabs(va, value):
    text = subprocess.run(
        ["objdump", "-d", f"--start-address={va}",
         f"--stop-address={va + 10}", str(BIN)],
        capture_output=True, text=True).stdout
    m = re.search(r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\tmovabs\s+\$0x"
                  r"([0-9a-f]+)", text, re.M)
    return bool(m and int(m.group(1), 16) == va
                and int(m.group(2), 16) == value)


def scan_transfers(target):
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


def stored_occurrences(data):
    out = {}
    for value, name in VALUES.items():
        pat = struct.pack("<Q", value)
        offs = []
        i = data.find(pat)
        while i >= 0:
            offs.append(i)
            i = data.find(pat, i + 1)
        out[name] = offs
    return out


def main():
    data = BIN.read_bytes()
    ranges = fde_ranges()
    starts = [s for s, _ in ranges]

    refs = []
    for va, tgt in rip_candidates(data):
        if confirm_rip(va, tgt):
            refs.append((va, "rip_relative", SLOTS[tgt]))
    for va, value in movabs_candidates(data):
        if confirm_movabs(va, value):
            refs.append((va, "movabs", VALUES[value]))
    refs.sort()

    result = {"refs": {"total": len(refs)}}
    if "--sites" in sys.argv:
        result["refs"]["sites"] = [
            [hex(va), kind, name] for va, kind, name in refs]

    transfers = {}
    for name, target in ROUTINES.items():
        rows = scan_transfers(target)
        transfers[name] = rows
        result[name] = {
            "direct_calls": sum(1 for _, k in rows if k == "call"),
            "tail_jumps": sum(1 for _, k in rows if k == "jmp"),
            "total": len(rows),
        }
        if "--sites" in sys.argv:
            result[name]["sites"] = [[hex(va), kind] for va, kind in rows]

    stored = stored_occurrences(data)
    result["stored"] = {
        name: [hex(o) for o in offs] for name, offs in stored.items()}

    if "--write" in sys.argv:
        here = Path(__file__).parent
        lines = ["site\tkind\ttarget\tcaller_fde_start\tcaller_fde_end"]
        for va, kind, name in refs:
            enc = enclosing(ranges, starts, va)
            s, e = enc if enc else (0, 0)
            lines.append(f"0x{va:x}\t{kind}\t{name}\t0x{s:x}\t0x{e:x}")
        (here / "refs.tsv").write_text("\n".join(lines) + "\n")
        for name, fname in (("build", "callers.tsv"),
                            ("decode", "decode_callers.tsv")):
            lines = ["site\tkind\tcaller_fde_start\tcaller_fde_end"]
            for va, kind in transfers[name]:
                enc = enclosing(ranges, starts, va)
                s, e = enc if enc else (0, 0)
                lines.append(f"0x{va:x}\t{kind}\t0x{s:x}\t0x{e:x}")
            (here / fname).write_text("\n".join(lines) + "\n")
        lines = ["value_name\tfile_offset"]
        for name in VALUES.values():
            for off in stored[name]:
                lines.append(f"{name}\t0x{off:x}")
        (here / "stored.tsv").write_text("\n".join(lines) + "\n")

    print(json.dumps(result, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
