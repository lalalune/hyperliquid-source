"""Caller census for RE-001-configoptions-default-ctor-115.

Scans work/hl-node-115.bin for every reference to the pinned targets:
  0x60bb890  rocksdb::ConfigOptions::ConfigOptions() (default ctor)
  0x5e33fb0  rocksdb::ConfigOptions::~ConfigOptions() (D1)
  0x61f9400  rocksdb::ObjectRegistry::NewInstance()

For each target records direct `call rel32` sites, `jmp rel32` tail-call
sites, and 8-byte qword hits (file offsets) of the target address.
Also resolves the containing FDE for a call site, for attribution.

Run from the repository root:
    python3 research/work-items/RE-001-configoptions-default-ctor-115/census.py
"""

import bisect
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "work", "hl-node-115.bin")

CTOR = 0x60BB890
DTOR = 0x5E33FB0
NEWINSTANCE = 0x61F9400

TARGETS = [CTOR, DTOR, NEWINSTANCE]


def load_text(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr = struct.unpack_from("<IIQQ", data, off)
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        if p_type == 1 and p_flags & 1:  # PT_LOAD, executable
            return p_vaddr, p_offset, p_filesz
    raise RuntimeError("no executable PT_LOAD segment")


def scan(path=BIN):
    data = open(path, "rb").read()
    text_vaddr, text_off, text_size = load_text(data)
    seg = data[text_off:text_off + text_size]
    calls = {t: [] for t in TARGETS}
    tails = {t: [] for t in TARGETS}
    hits = {t: [] for t in TARGETS}
    for op, table in ((b"\xe8", calls), (b"\xe9", tails)):
        for m in re.finditer(re.escape(op), seg):
            pos = m.start()
            rel = struct.unpack_from("<i", data, text_off + pos + 1)[0]
            src = text_vaddr + pos
            if src + 5 + rel in table:
                table[src + 5 + rel].append(src)
    for t in TARGETS:
        qv = struct.pack("<Q", t)
        hits[t] = [m.start() for m in re.finditer(re.escape(qv), data)]
    for t in TARGETS:
        calls[t].sort()
        tails[t].sort()
        hits[t].sort()
    slots = {t: [] for t in TARGETS}
    return calls, tails, hits, slots


def fde_map(path=BIN):
    out = subprocess.run(["objdump", "--dwarf=frames", path],
                         capture_output=True, text=True, check=True).stdout
    fdes = []
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def fde_of(fdes, addr):
    starts = [f[0] for f in fdes]
    i = bisect.bisect_right(starts, addr) - 1
    if i >= 0 and fdes[i][0] <= addr < fdes[i][1]:
        return fdes[i]
    return None


def main():
    calls, tails, hits, slots = scan()
    for t in TARGETS:
        print(hex(t), "direct_calls=%d" % len(calls[t]),
              "tail_jumps=%d" % len(tails[t]),
              "qword_hits=%d" % len(hits[t]))
        for c in calls[t]:
            print("  call", hex(c))
        for c in tails[t]:
            print("  tail", hex(c))
        for h in hits[t]:
            print("  qword fileoff", hex(h))
    return 0


if __name__ == "__main__":
    sys.exit(main())
