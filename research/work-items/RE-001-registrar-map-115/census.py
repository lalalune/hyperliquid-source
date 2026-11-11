"""Caller census for RE-001-registrar-map-115.

Scans work/hl-node-115.bin for every reference to the pinned targets:
  0x620b470  _GLOBAL__sub_I_build_version.cc (registrar-map static init)
  0x5f204e0  std::string assign-from-const-char* helper
  0x620a500  registrar-map destroying function (atexit-registered)
  0x61f91b0  rocksdb::ObjectRegistry::ObjectRegistry() (ctor, re-shipped #4015)
  0x61f92b0  rocksdb::ObjectRegistry::Default() (singleton getter, #4015)
  0x6509540  the global registrar unordered_map object (data address)

Method (same family as the RE-001-objectregistry-lifecycle-115 packet):
  * Byte-level scan of the executable LOAD segment for E8/E9 rel32
    call/tail sites of each code target, and for the 7-byte RIP-relative
    lea pattern (48/49/4c 8d modrm rel32) naming the map address.
  * Every byte-scan candidate is confirmed by a targeted objdump read of
    that one instruction, so data bytes inside other instructions can
    never fake a site.
  * 8-byte qword scan of the whole file for stored pointers to each
    target, and a 4-byte immediate scan of .text for the map address.
  * Containing FDE per site from `readelf --debug-dump=frames-interp`.
  * `readelf -r` checks for the .init_array RELATIVE reloc, the string
    dtor GLOB_DAT, and the __dso_handle RELATIVE self-pointers.

Writes callers.tsv (one row per verified site) and relocations.txt
into this packet directory.

Run from the repository root:
    python3 research/work-items/RE-001-registrar-map-115/census.py
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
BIN_REL = "work/hl-node-115.bin"

STATIC_INIT = 0x620B470
STRING_ASSIGN = 0x5F204E0
MAP_DTOR = 0x620A500
CTOR = 0x61F91B0
GETTER = 0x61F92B0
MAP_ADDR = 0x6509540

CODE_TARGETS = [STATIC_INIT, STRING_ASSIGN, MAP_DTOR, CTOR, GETTER]


def load_exec_segment(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr = struct.unpack_from("<IIQQ", data, off)
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        if p_type == 1 and p_flags & 1:  # PT_LOAD, executable
            return p_vaddr, p_offset, p_filesz
    raise RuntimeError("no executable PT_LOAD segment")


def objdump_window(start, stop):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, BIN_REL],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return out


def confirm_call(addr, target):
    out = objdump_window(addr, addr + 5)
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t.*\bcall\s+%x\b" % target, line)
        if m and int(m.group(1), 16) == addr:
            return True
    return False


def confirm_tail(addr, target):
    out = objdump_window(addr, addr + 5)
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t.*\bjmp\s+%x\b" % target, line)
        if m and int(m.group(1), 16) == addr:
            return True
    return False


def confirm_lea(addr, target):
    out = objdump_window(addr, addr + 7)
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t.*\blea\b.*#\s+%x\b" % target, line)
        if m and int(m.group(1), 16) == addr:
            return True
    return False


def scan(data):
    text_vaddr, text_off, text_size = load_exec_segment(data)
    seg = data[text_off:text_off + text_size]
    calls = {t: [] for t in CODE_TARGETS}
    tails = {t: [] for t in CODE_TARGETS}
    for op, table in ((b"\xe8", calls), (b"\xe9", tails)):
        for m in re.finditer(re.escape(op), seg):
            pos = m.start()
            rel = struct.unpack_from("<i", seg, pos + 1)[0]
            src = text_vaddr + pos
            dst = src + 5 + rel
            if dst in table:
                table[dst].append(src)
    # RIP-relative lea candidates naming the map address.
    lea_cands = []
    for prefix in (b"\x48\x8d", b"\x49\x8d", b"\x4c\x8d"):
        pat = re.escape(prefix) + rb"[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]"
        for m in re.finditer(pat, seg):
            pos = m.start()
            rel = struct.unpack_from("<i", seg, pos + 3)[0]
            addr = text_vaddr + pos
            if addr + 7 + rel == MAP_ADDR:
                lea_cands.append(addr)
    # Absolute-immediate references to the map address in .text.
    imm_hits = [text_vaddr + m.start()
                for m in re.finditer(re.escape(struct.pack("<I", MAP_ADDR)), seg)]
    # Stored 8-byte pointers to each target anywhere in the file.
    qwords = {}
    for t in CODE_TARGETS + [MAP_ADDR]:
        qv = struct.pack("<Q", t)
        qwords[t] = [m.start() for m in re.finditer(re.escape(qv), data)]
    for t in CODE_TARGETS:
        calls[t].sort()
        tails[t].sort()
    lea_cands.sort()
    return calls, tails, lea_cands, imm_hits, qwords


def fde_map():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", BIN],
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


def relocations():
    out = subprocess.run(["readelf", "-rW", BIN],
                         capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+(R_X86_64_\S+)\s+([0-9a-f]+)(?:\s+(.*))?$", line)
        if not m:
            continue
        off, typ, addend, sym = int(m.group(1), 16), m.group(2), m.group(3), (m.group(4) or "").strip()
        if addend in ("620b470", "64efa20") or off in (0x64ED5D8, 0x64EFA20, 0x64FE448):
            rows.append((off, typ, addend, sym))
    return rows


def main():
    data = open(BIN, "rb").read()
    calls, tails, lea_cands, imm_hits, qwords = scan(data)
    fdes = fde_map()
    relocs = relocations()
    print("census for RE-001-registrar-map-115")
    for t in CODE_TARGETS:
        good_calls = [c for c in calls[t] if confirm_call(c, t)]
        good_tails = [c for c in tails[t] if confirm_tail(c, t)]
        print("%#x calls=%d %s tails=%d %s qwords=%d %s" % (
            t, len(good_calls), [hex(c) for c in good_calls],
            len(good_tails), [hex(c) for c in good_tails],
            len(qwords[t]), [hex(h) for h in qwords[t]]))
        if len(good_calls) != len(calls[t]) or len(good_tails) != len(tails[t]):
            print("  NOTE: %d call / %d tail candidates rejected by objdump confirmation"
                  % (len(calls[t]) - len(good_calls), len(tails[t]) - len(good_tails)))
    good_leas = [a for a in lea_cands if confirm_lea(a, MAP_ADDR)]
    print("%#x lea sites=%d %s imm32=%d qwords=%d %s" % (
        MAP_ADDR, len(good_leas), [hex(a) for a in good_leas],
        len(imm_hits), len(qwords[MAP_ADDR]), [hex(h) for h in qwords[MAP_ADDR]]))
    if len(good_leas) != len(lea_cands):
        print("  NOTE: %d lea candidates rejected by objdump confirmation"
              % (len(lea_cands) - len(good_leas)))
    print("relocations of interest:")
    for off, typ, addend, sym in relocs:
        print("  %#x %s addend=%s %s" % (off, typ, addend, sym))
    rows = []
    for t in CODE_TARGETS:
        for c in [x for x in calls[t] if confirm_call(x, t)]:
            f = fde_of(fdes, c)
            rows.append((hex(c), "call", hex(t),
                         "%#x..%#x" % f if f else "no-fde"))
        for c in [x for x in tails[t] if confirm_tail(x, t)]:
            f = fde_of(fdes, c)
            rows.append((hex(c), "tail-jump", hex(t),
                         "%#x..%#x" % f if f else "no-fde"))
    for a in good_leas:
        f = fde_of(fdes, a)
        rows.append((hex(a), "lea", hex(MAP_ADDR),
                     "%#x..%#x" % f if f else "no-fde"))
    rows.sort(key=lambda r: int(r[0], 16))
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("site\tkind\ttarget\tcontaining_fde\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        fh.write("offset\ttype\taddend\tsymbol\n")
        for off, typ, addend, sym in relocs:
            fh.write("%#x\t%s\t%s\t%s\n" % (off, typ, addend, sym))
    print("wrote callers.tsv (%d rows) and relocations.txt (%d rows)"
          % (len(rows), len(relocs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
