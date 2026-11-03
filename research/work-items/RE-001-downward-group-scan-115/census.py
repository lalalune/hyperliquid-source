#!/usr/bin/env python3
"""Reproduce the whole-file census for the five windows of this work item.

Usage: python3 research/work-items/RE-001-downward-group-scan-115/census.py
Run from the repository root. Prints JSON: for each window, its direct-call
sites (E8 rel32), tail-jump sites (E9 rel32) in .text, whole-file 8-byte
qword hits (file offsets), and R_X86_64_RELATIVE relocation addends.
One linear pass over .text collects every window's call/jump sites.
"""
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work" / "hl-node-115.bin"
TEXT_ADDR, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
TARGETS = {"scanner": 0x5D52BB0, "stub": 0x60D5390,
           "index_leaf": 0x5F6C740, "group_sum": 0x5F6C300,
           "leaf": 0x5DA4DE0}


def elf_sections(data):
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, names_index = struct.unpack_from("<HHH", data, 58)
    raw = []
    for i in range(count):
        name, typ, flags, addr, off, size, link, info, align, entry = struct.unpack_from(
            "<IIQQQQIIQQ", data, shoff + i * entsize)
        raw.append((name, typ, flags, addr, off, size))
    names = raw[names_index]
    table = data[names[4]:names[4] + names[5]]
    out = []
    for name, typ, flags, addr, off, size in raw:
        end = table.find(b"\0", name)
        out.append(dict(name=table[name:end].decode(), type=typ, flags=flags,
                        address=addr, offset=off, size=size))
    return out


def main():
    data = BIN.read_bytes()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    result = {label: {"address": hex(target), "direct_calls": [],
                      "tail_jumps": [], "qword_file_offsets": [],
                      "relative_addends": []}
              for label, target in TARGETS.items()}
    by_target = {target: label for label, target in TARGETS.items()}
    for j in range(len(text) - 5):
        op = text[j]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", text, j + 1)[0]
            label = by_target.get(j + TEXT_ADDR + 5 + rel)
            if label is not None:
                (result[label]["direct_calls"] if op == 0xE8
                 else result[label]["tail_jumps"]).append(hex(j + TEXT_ADDR))
    for label, target in TARGETS.items():
        pat = struct.pack("<Q", target)
        qwords, s = [], 0
        while True:
            i = data.find(pat, s)
            if i < 0:
                break
            qwords.append(hex(i))
            s = i + 1
        result[label]["qword_file_offsets"] = qwords
    for sec in elf_sections(data):
        if "rela" not in sec["name"]:
            continue
        for i in range(sec["size"] // 24):
            off, info, add = struct.unpack_from("<QQq", data, sec["offset"] + i * 24)
            if (info & 0xFFFFFFFF) == 8 and add in by_target:
                result[by_target[add]]["relative_addends"].append(hex(off))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
