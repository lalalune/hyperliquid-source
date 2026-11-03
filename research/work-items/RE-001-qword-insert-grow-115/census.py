#!/usr/bin/env python3
"""Census of references to the realloc-insert window in work/hl-node-115.bin.

Displayed address = file offset + 0x1000 for .text (PIE .text VMA
0x1419300, file offset 0x1418300). Direct calls are E8 rel32 and tail
jumps E9 rel32 scanned over the whole .text section; stored qwords are
8-byte little-endian values scanned over the whole file;
R_X86_64_RELATIVE addends are read from .rela.dyn and .rela.plt.
Usage: census.py <binary-path>
"""
import struct
import sys

WINDOWS = {
    "grow 0x5d9ee20": 0x5D9EE20,
}

TEXT_OFF, TEXT_SIZE = 0x1418300, 0x4FD7700
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8
RELAPLT_OFF, RELAPLT_SIZE = 0x16A8B0, 0x1A10


def scan_calls(data, target):
    calls, tails = [], []
    seg = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    for opcode, out in ((0xE8, calls), (0xE9, tails)):
        pos = 0
        needle = bytes([opcode])
        while True:
            i = seg.find(needle, pos)
            if i < 0:
                break
            pos = i + 1
            if i + 5 > len(seg):
                break
            rel = struct.unpack_from("<i", seg, i + 1)[0]
            disp = TEXT_OFF + i + 0x1000  # instruction displayed address
            if disp + 5 + rel == target:
                out.append(disp)
    return calls, tails


def scan_qwords(data, target):
    pat = struct.pack("<Q", target)
    out, pos = [], 0
    while True:
        i = data.find(pat, pos)
        if i < 0:
            break
        pos = i + 1
        out.append(i)
    return out


def scan_rela(data, off, size, target):
    out = []
    for i in range(off, off + size, 24):
        r_off, r_info, r_add = struct.unpack_from("<QQq", data, i)
        if (r_info & 0xFFFFFFFF) == 8 and r_add == target:  # R_X86_64_RELATIVE
            out.append(r_off)
    return out


def main():
    data = open(sys.argv[1], "rb").read()
    for name, target in WINDOWS.items():
        calls, tails = scan_calls(data, target)
        qwords = scan_qwords(data, target)
        rela = (scan_rela(data, RELA_OFF, RELA_SIZE, target)
                + scan_rela(data, RELAPLT_OFF, RELAPLT_SIZE, target))
        print("%s: direct_calls=%s tail_jumps=%s qword_file_offsets=%s "
              "relative_reloc_offsets=%s"
              % (name, [hex(c) for c in calls], [hex(t) for t in tails],
                 [hex(q) for q in qwords], [hex(r) for r in rela]))


if __name__ == "__main__":
    main()
