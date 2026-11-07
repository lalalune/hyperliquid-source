#!/usr/bin/env python3
"""Reproduce every census in the RE-001-logger-vtable-full-map-115 packet.

Run from the repository root:
  python3 research/work-items/RE-001-logger-vtable-full-map-115/census.py

Reproduces, from work/hl-node-115.bin only:
  vtables.tsv -- vtable slot reads for the two Logger vtables
                (EnvLogger, AutoRollLogger), taken from the .rela.dyn
                entries.  The file bytes of .data.rel.ro are ZERO; the
                real slot values live only in the relocation entries
                (R_X86_64_RELATIVE addends).
  callers.tsv -- every direct (E8 rel32) call site of the slot
                 functions, the rollover path, the writer methods and
                 the construction entry points (byte-level scan of
                 .text).
  guards.tsv  -- the three devirtualization guards in this packet:
                 the shared_ptr dispose's EnvLogger-D0 check, the
                 AutoRollLogger ctor's GetFileSize-slot check, and the
                 roll path's GetFileSize-slot check.
  frames.txt  -- the FDE ranges for all 41 excerpted functions,
                 parsed from readelf --debug-dump=frames-interp.

Section map (readelf -S): .text vaddr 0x1419300, file offset
0x1418300 (offset = vaddr - 0x1000); .rodata offset == vaddr;
.data.rel.ro file offset = vaddr - 0x2000.
"""

import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"

TEXT_VADDR = 0x1419300
TEXT_OFF = 0x1418300

# (class, vtable vaddr, slots to read)
# Logger's 11 virtuals per env.h (dtors, Close, LogHeader, Logv,
# Logv(level), GetLogFileSize, Flush, GetInfoLogLevel, SetInfoLogLevel,
# CloseImpl).  The qwords past slot 10 are NOT pinned here: slots
# 11/13/14 have no relocation and read as zero, slot 12 points at
# data 0x64cd8d0, and the EnvLogger tail holds the shared Configurable
# GetOption / AreEquivalent (0x609d760 / 0x609dc40) at offsets 0x78 /
# 0x80 -- whether the binary's Logger carries additional virtuals past
# CloseImpl or these qwords belong to adjacent objects is an open
# unknown (see README); nothing in this packet calls past slot 10.
VTABLES = [
    ("EnvLogger", 0x64CDA68, range(0, 11)),
    ("AutoRollLogger", 0x64D1F00, range(0, 11)),
]

# (target, note) for the direct-caller census.
CALLER_TARGETS = [
    (0x5FCFB90, "EnvLogger D0 destructor"),
    (0x5FCFDE0, "EnvLogger D1 destructor"),
    (0x60576B0, "AutoRollLogger D0 destructor"),
    (0x6057D00, "AutoRollLogger D1 destructor"),
    (0x5FCE280, "EnvLogger Logv"),
    (0x5FCE130, "EnvLogger Flush"),
    (0x5FCCED0, "EnvLogger GetLogFileSize"),
    (0x5FCEAE0, "EnvLogger CloseImpl"),
    (0x5FCE770, "EnvLogger CloseImpl worker"),
    (0x6058770, "AutoRollLogger Logv"),
    (0x6057440, "AutoRollLogger Flush"),
    (0x6057590, "AutoRollLogger GetLogFileSize"),
    (0x60551D0, "AutoRollLogger CloseImpl"),
    (0x6058110, "AutoRollLogger roll"),
    (0x60572A0, "AutoRollLogger re-log queued headers"),
    (0x6054680, "WritableFileWriter Append"),
    (0x6051A20, "WritableFileWriter Flush/Sync"),
    (0x6052B80, "WritableFileWriter Close"),
    (0x5FD0DE0, "EnvLogger factory"),
    (0x605A210, "AutoRollLogger ctor"),
    (0x5FCC410, "Logger Close (shared slot 2)"),
]

# (guard name, compare instruction addr, GOT slot / compared fn,
#  expected addend-or-fn)
GUARDS = [
    ("shared_ptr dispose checks EnvLogger D0", 0x5FCF689, 0x64ED970, 0x5FCFB90),
    ("AutoRollLogger ctor checks GetFileSize slot", 0x605A487, 0x64ECF80, 0x5D4D490),
    ("roll path checks GetFileSize slot", 0x6058153, None, 0x5D4D490),
]

# (label, vaddr) -- string literals checked verbatim.
LITERALS = [
    ("log timestamp format", 0x968038),
    ("writer error part 1", 0x451480),
    ("writer error part 2", 0x452BF0),
    ("Close of log file failed with error:", 0x966D00),
    ("EnvLogger typeinfo name", 0x972160),
    ("AutoRollLogger typeinfo name", 0x974E10),
    ("Logger base typeinfo name", 0x9720C0),
    ("empty string", 0x4376FD),
]

# (file name, start, stop) -- must match export_excerpts.py.
EXCERPTS = [
    ("logger-logheader-5fcc200.objdump.txt", 0x5FCC200, 0x5FCC218),
    ("logger-logv-levelled-5fcd400.objdump.txt", 0x5FCD400, 0x5FCD419),
    ("logger-logv-levelled-core-5fcd2c0.objdump.txt", 0x5FCD2C0, 0x5FCD3F5),
    ("logger-getinfologlevel-5fcc220.objdump.txt", 0x5FCC220, 0x5FCC229),
    ("logger-setinfologlevel-5fcc230.objdump.txt", 0x5FCC230, 0x5FCC239),
    ("logger-close-5fcc410.objdump.txt", 0x5FCC410, 0x5FCC473),
    ("logger-closeimpl-5fceae0.objdump.txt", 0x5FCEAE0, 0x5FCEB1F),
    ("logger-logv-5fce280.objdump.txt", 0x5FCE280, 0x5FCE766),
    ("logger-d0-5fcfb90.objdump.txt", 0x5FCFB90, 0x5FCFDDF),
    ("logger-d1-5fcfde0.objdump.txt", 0x5FCFDE0, 0x5FD003F),
    ("logger-getlogfilesize-5fcced0.objdump.txt", 0x5FCCED0, 0x5FCCF05),
    ("logger-flush-5fce130.objdump.txt", 0x5FCE130, 0x5FCE27D),
    ("logger-closeimpl-worker-5fce770.objdump.txt", 0x5FCE770, 0x5FCEADD),
    ("autoroll-logheader-6057000.objdump.txt", 0x6057000, 0x60571B4),
    ("autoroll-getinfologlevel-60552e0.objdump.txt", 0x60552E0, 0x6055345),
    ("autoroll-d0-60576b0.objdump.txt", 0x60576B0, 0x6057CF1),
    ("autoroll-d1-6057d00.objdump.txt", 0x6057D00, 0x6057D1B),
    ("autoroll-logv-6058770.objdump.txt", 0x6058770, 0x6058A60),
    ("autoroll-getlogfilesize-6057590.objdump.txt", 0x6057590, 0x60576B0),
    ("autoroll-flush-6057440.objdump.txt", 0x6057440, 0x605758E),
    ("autoroll-setinfologlevel-6055280.objdump.txt", 0x6055280, 0x60552D8),
    ("autoroll-closeimpl-60551d0.objdump.txt", 0x60551D0, 0x605523B),
    ("helper-get-perf-level-606ddd0.objdump.txt", 0x606DDD0, 0x606DDF0),
    ("helper-set-perf-level-606ddb0.objdump.txt", 0x606DDB0, 0x606DDCB),
    ("helper-tls-init-606d9f0.objdump.txt", 0x606D9F0, 0x606DA30),
    ("helper-mutex-destroy-60d5170.objdump.txt", 0x60D5170, 0x60D5200),
    ("helper-mutex-lock-60d5230.objdump.txt", 0x60D5230, 0x60D52C5),
    ("helper-mutex-unlock-60d52f0.objdump.txt", 0x60D52F0, 0x60D5385),
    ("helper-mutex-noop-60d5390.objdump.txt", 0x60D5390, 0x60D5395),
    ("writer-append-6054680.objdump.txt", 0x6054680, 0x605518B),
    ("writer-flush-6051a20.objdump.txt", 0x6051A20, 0x605257C),
    ("writer-close-6052b80.objdump.txt", 0x6052B80, 0x6054600),
    ("logger-sharedptr-dispose-5fcf660.objdump.txt", 0x5FCF660, 0x5FCF88C),
    ("logger-factory-5fd0de0.objdump.txt", 0x5FD0DE0, 0x5FD176A),
    ("autoroll-ctor-605a210.objdump.txt", 0x605A210, 0x605AE90),
    ("autoroll-roll-6058110.objdump.txt", 0x6058110, 0x60586F3),
    ("autoroll-timecheck-6057310.objdump.txt", 0x6057310, 0x605743C),
    ("autoroll-relog-60572a0.objdump.txt", 0x60572A0, 0x6057304),
    ("autoroll-mkname-6056790.objdump.txt", 0x6056790, 0x6056B94),
    ("autoroll-mkname2-6056ba0.objdump.txt", 0x6056BA0, 0x6056E42),
    ("autoroll-format-6056e50.objdump.txt", 0x6056E50, 0x6056FC3),
]


def parse_rela_dyn(data):
    """Return {offset: (type, sym_name, addend)} for .rela.dyn entries.

    R_X86_64_RELATIVE (8) entries carry the slot value in the addend.
    R_X86_64_64 (1) entries carry an imported symbol name.
    """
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", data, 0x3A)
    order = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, typ, flags, addr, offset, size, link, info,
         align, entsize) = struct.unpack_from("<IIQQQQIIQQ", data, off)
        order.append((name, typ, addr, offset, size, link, entsize))
    strtab_off = order[e_shstrndx][3]

    def sec_name(n):
        end = data.index(b"\x00", strtab_off + n)
        return data[strtab_off + n:end].decode()

    named = {}
    for (name, typ, addr, offset, size, link, entsize) in order:
        named[sec_name(name)] = (typ, addr, offset, size, link, entsize)
    _, _, dynsym_off, dynsym_size, _, dynsym_entsize = named[".dynsym"]
    _, _, dynstr_off, dynstr_size, _, _ = named[".dynstr"]

    def sym_name(idx):
        (st_name,) = struct.unpack_from(
            "<I", data, dynsym_off + idx * dynsym_entsize)
        end = data.index(b"\x00", dynstr_off + st_name)
        return data[dynstr_off + st_name:end].decode()

    _, _, rela_off, rela_size, _, _ = named[".rela.dyn"]
    rela = {}
    for i in range(rela_size // 24):
        r_off, r_info, r_add = struct.unpack_from(
            "<QQq", data, rela_off + i * 24)
        r_sym, r_type = r_info >> 32, r_info & 0xFFFFFFFF
        rela[r_off] = (r_type, sym_name(r_sym) if r_sym else "", r_add)
    return rela


def slot_value(rela, addr):
    """Render the runtime value of a vtable slot at `addr`."""
    entry = rela.get(addr)
    if entry is None:
        return None
    r_type, sym, addend = entry
    if r_type == 8:  # R_X86_64_RELATIVE
        return f"{addend:#x}"
    if r_type == 1:  # R_X86_64_64
        return sym or f"sym64+{addend:#x}"
    return f"type{r_type}+{addend:#x}"


def read_rodata_str(data, vaddr, limit=200):
    raw = data[vaddr:vaddr + limit]
    end = raw.find(b"\x00")
    return raw[:end if end >= 0 else limit].decode("latin1")


def _text_bounds(data):
    """(file offset, vaddr, size) of .text."""
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", data, 0x3A)
    strtab_off = struct.unpack_from(
        "<Q", data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name,) = struct.unpack_from("<I", data, off)
        end = data.index(b"\x00", strtab_off + name)
        if data[strtab_off + name:end] == b".text":
            size = struct.unpack_from("<Q", data, off + 0x20)[0]
            return TEXT_OFF, TEXT_VADDR, size
    raise AssertionError(".text not found")


def direct_callers_all(data, targets):
    """Single-pass scan of .text: every E8 rel32 site whose target is
    in `targets`.  Returns {target: [site, ...]}.  A per-target
    byte-by-byte scan would cost one 84 MB Python pass per target;
    this pass uses bytes.find (C speed) and only decodes E8 sites."""
    off, vaddr, size = _text_bounds(data)
    wanted = set(targets)
    out = {t: [] for t in targets}
    text = data[off:off + size]
    pos = text.find(b"\xe8")
    while pos != -1 and pos + 5 <= size:
        rel = struct.unpack_from("<i", text, pos + 1)[0]
        tgt = vaddr + pos + 5 + rel
        if tgt in wanted:
            out[tgt].append(vaddr + pos)
        pos = text.find(b"\xe8", pos + 1)
    return out


def direct_callers(data, target):
    """All E8 rel32 sites in .text whose target is `target`."""
    return direct_callers_all(data, [target])[target]


def fde_ranges():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    ranges = []
    for line in out.splitlines():
        m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            ranges.append((int(m.group(1), 16), int(m.group(2), 16)))
    return ranges


def main():
    data = BIN.read_bytes()
    rela = parse_rela_dyn(data)
    print(f".rela.dyn entries: {len(rela)}")

    # vtables.tsv
    rows = ["class\tvtable\tslot\tslot_offset\tfunction"]
    for cls, vt, slots in VTABLES:
        for i in slots:
            val = slot_value(rela, vt + i * 8)
            assert val is not None, f"no reloc at {cls} slot {i}"
            rows.append(f"{cls}\t{vt:#x}\t{i}\t{i * 8:#x}\t{val}")
    (HERE / "vtables.tsv").write_text("\n".join(rows) + "\n")
    print(f"wrote vtables.tsv ({len(rows) - 1} rows)")

    # Logger tail qwords (slots 11-16): recorded raw, no identity
    # asserted -- see the VTABLES comment above.
    for cls, vt in [("EnvLogger", 0x64CDA68), ("AutoRollLogger", 0x64D1F00)]:
        tail = []
        for i in range(11, 17):
            val = slot_value(rela, vt + i * 8)
            tail.append(f"slot {i}: {val if val is not None else 'none'}")
        print(f"{cls} tail: " + ", ".join(tail))

    # callers.tsv (one pass for all targets)
    rows = ["target\tsite\tnote"]
    all_sites = direct_callers_all(
        data, [target for target, _note in CALLER_TARGETS])
    for target, note in CALLER_TARGETS:
        for site in all_sites[target]:
            rows.append(f"{target:#x}\t{site:#x}\t{note}")
    (HERE / "callers.tsv").write_text("\n".join(rows) + "\n")
    print(f"wrote callers.tsv ({len(rows) - 1} rows)")

    # guards.tsv
    rows = ["guard\tcmp_addr\tgot_slot\tgot_addend\texpected"]
    for name, cmp_addr, got, expected in GUARDS:
        if got is None:
            rows.append(f"{name}\t{cmp_addr:#x}\t-\t-\t{expected:#x}")
            continue
        entry = rela.get(got)
        assert entry is not None, f"no reloc at GOT {got:#x}"
        r_type, sym, addend = entry
        assert r_type == 8, f"GOT {got:#x} is not RELATIVE"
        rows.append(f"{name}\t{cmp_addr:#x}\t{got:#x}\t{addend:#x}\t{expected:#x}")
    (HERE / "guards.tsv").write_text("\n".join(rows) + "\n")
    print(f"wrote guards.tsv ({len(rows) - 1} rows)")

    # literals (printed; records.json pins them via gen_records.py)
    for label, vaddr in LITERALS:
        print(f"literal {label} @ {vaddr:#x}: {read_rodata_str(data, vaddr)!r}")

    # frames.txt
    ranges = fde_ranges()
    lines = ["# FDE ranges for every function excerpted in this packet, from",
             "# readelf --debug-dump=frames-interp work/hl-node-115.bin"]
    for name, start, stop in EXCERPTS:
        hit = [r for r in ranges if r[0] == start and r[1] == stop]
        assert hit, f"no FDE {start:#x}..{stop:#x} for {name}"
        lines.append(f"FDE pc={start:#x}..{stop:#x}")
    (HERE / "frames.txt").write_text("\n".join(lines) + "\n")
    print(f"wrote frames.txt ({len(EXCERPTS)} FDEs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
