"""Caller and displacement census for RE-001-dboptions-log-readahead-size-115.

Two parts:

1. Call census (raw-byte scan, fast). For each pinned function records
   direct `call rel32` sites, `jmp rel32` tail-call sites, and 8-byte
   qword hits (file offsets) of the target address:
     0x60b2db0  rocksdb::DBOptions::DBOptions() (default ctor)
     0x5d38750  rocksdb::DBOptions::DBOptions(const DBOptions&)
     0x60b3280  rocksdb::DBOptions::DBOptions(const Options&)
     0x60c3480  rocksdb::DBOptions::operator=(const DBOptions&)
     0x60a3b60  rocksdb::ImmutableDBOptions::ImmutableDBOptions(const DBOptions&)
     0x5da6bc0  rocksdb::ImmutableDBOptions::ImmutableDBOptions(const ImmutableDBOptions&)
     0x60c2e20  rocksdb::BuildDBOptions
     0x60d4a00  rocksdb::PersistRocksDBOptions (outer, DBOptions-first)
     0x60d2820  rocksdb::PersistRocksDBOptions (inner, ConfigOptions-first)
     0x60d13a0  rocksdb::RocksDBOptionsParser::VerifyRocksDBOptionsFromFile
     0x60cfb60  rocksdb::RocksDBOptionsParser::Parse

2. Displacement census (objdump scan of the RocksDB .text range
   0x5c00000..0x6400000). Counts every instruction that touches
   displacement 0x220 (the DBOptions log_readahead_size slot) and every
   instruction that touches displacement 0x1a0 (the ImmutableDBOptions
   log_readahead_size slot), grouped by containing FDE. Only positive
   displacements count (a negative -0x220(%rbp) is a stack slot, not a
   struct field). The DBOptions/ImmutableDBOptions-typed sites are the
   ones this work item pins; most other hits belong to unrelated structs
   that happen to share the displacement.

Run from the repository root:
    python3 research/work-items/RE-001-dboptions-log-readahead-size-115/census.py
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

DBOPTIONS_CTOR = 0x60B2DB0
DBOPTIONS_COPY = 0x5D38750
DBOPTIONS_OPTIONS = 0x60B3280
DBOPTIONS_ASSIGN = 0x60C3480
IMMUTABLE_CTOR = 0x60A3B60
IMMUTABLE_COPY = 0x5DA6BC0
BUILD_DBOPTIONS = 0x60C2E20
PERSIST_OUTER = 0x60D4A00
PERSIST_INNER = 0x60D2820
VERIFY_FROM_FILE = 0x60D13A0
PARSE = 0x60CFB60

TARGETS = [DBOPTIONS_CTOR, DBOPTIONS_COPY, DBOPTIONS_OPTIONS,
           DBOPTIONS_ASSIGN, IMMUTABLE_CTOR, IMMUTABLE_COPY,
           BUILD_DBOPTIONS, PERSIST_OUTER, PERSIST_INNER,
           VERIFY_FROM_FILE, PARSE]

TEXT_START = 0x5C00000
TEXT_STOP = 0x6400000


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


def disp_census(path=BIN):
    """Count positive-displacement 0x220(%reg) and 0x1a0(%reg) instructions
    in the RocksDB .text range 0x5c00000..0x6400000.

    Only positive displacements count: a negative -0x220(%rbp) is a stack
    slot, not a struct field. Hits are grouped by their containing FDE
    (objdump prints almost no function headers in this stripped range, so
    symbol headers cannot delimit functions).

    Returns ({disp: total}, {disp: {fde_start: count}}).
    """
    out = subprocess.run(
        ["objdump", "-d",
         "--start-address=" + hex(TEXT_START),
         "--stop-address=" + hex(TEXT_STOP), path],
        capture_output=True, text=True, check=True).stdout
    fdes = fde_map(path)
    totals = {0x220: 0, 0x1A0: 0}
    by_func = {0x220: {}, 0x1A0: {}}
    pat = {0x220: re.compile(r"(^|[^0-9a-fx-])0x220\(%r"),
           0x1A0: re.compile(r"(^|[^0-9a-fx-])0x1a0\(%r")}
    addr_re = re.compile(r"^\s+([0-9a-f]+):\t")
    for line in out.splitlines():
        m = addr_re.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        for disp in (0x220, 0x1A0):
            if pat[disp].search(line):
                totals[disp] += 1
                fde = fde_of(fdes, addr)
                key = fde[0] if fde else None
                by_func[disp][key] = by_func[disp].get(key, 0) + 1
    return totals, by_func


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
    calls, tails, hits, _slots = scan()
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
    totals, by_func = disp_census()
    for disp in (0x220, 0x1A0):
        print("disp %#x: %d instructions in %d functions"
              % (disp, totals[disp], len(by_func[disp])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
