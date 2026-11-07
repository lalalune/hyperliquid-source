#!/usr/bin/env python3
"""Reproduce every census in the RE-001-dump-slot-method-names-115 packet.

Run from the repository root:
  python3 research/work-items/RE-001-dump-slot-method-names-115/census.py

Reproduces, from work/hl-node-115.bin only:
  vtables.tsv -- vtable slot reads for the 13 vtables named in the
                packet (Logger x2, TableFactory x3, Cache x7,
                CompactOnDeletionCollectorFactory x1), taken from the
                .rela.dyn entries.  The file bytes of .data.rel.ro
                are ZERO; the real slot values live only in the
                relocation entries (R_X86_64_RELATIVE addends, and
                R_X86_64_64 __cxa_pure_virtual slots in the base
                Cache vtable).
  callers.tsv -- every direct (E8 rel32) call site of the host ctor
                 0x5d954b0, the dump 0x60b50c0, the base ToString
                 0x60b1ea0 and the base Cache GetPrintableOptions
                 0x5d3f6c0 (byte-level scan of .text).
  guards.tsv  -- the two devirtualization guards in the dump: the
                 GOT slot, its RELATIVE addend, and the comparison
                 instruction address.
  frames.txt  -- the FDE ranges for all 31 excerpted functions,
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
# Logger vtables stop at slot 10: Logger's 11 virtuals per env.h
# (dtors, Close, LogHeader, Logv, Logv(level), GetLogFileSize,
# Flush, GetInfoLogLevel, SetInfoLogLevel, CloseImpl).  The qwords
# past slot 10 are NOT pinned here: slots 11/13/14 have no
# relocation and read as zero, slot 12 points at data 0x64cd8d0, and
# the EnvLogger tail holds the shared Configurable GetOption /
# AreEquivalent (0x609d760 / 0x609dc40) at offsets 0x78 / 0x80 --
# whether the binary's Logger carries additional virtuals past
# CloseImpl or these qwords belong to adjacent objects is an open
# unknown (see README); the dump never calls past slot 10.
VTABLES = [
    ("EnvLogger", 0x64CDA68, range(0, 11)),
    ("AutoRollLogger", 0x64D1F00, range(0, 11)),
    ("BlockBasedTableFactory", 0x64D39B8, range(0, 16)),
    ("CuckooTableFactory", 0x64D5CF0, range(0, 16)),
    ("PlainTableFactory", 0x64D6628, range(0, 16)),
    ("Cache", 0x64C8C60, [2, 25]),
    ("LRUCache", 0x64C89B8, [2, 25]),
    ("ShardedCache<LRUCacheShard>", 0x64C88B0, [2, 25]),
    ("ShardedCacheBase", 0x64C8B48, [2, 25]),
    ("CacheWrapper", 0x64C8DA0, [2, 25]),
    ("CacheWithSecondaryAdapter", 0x64C8EA0, [2, 25]),
    ("ChargedCache", 0x64C9E00, [2, 25]),
    ("CompactOnDeletionCollectorFactory", 0x64D9088, range(0, 21)),
]

# (target, note) for the direct-caller census.
CALLER_TARGETS = [
    (0x5D954B0, "ColumnFamilyData ctor (host of the dump)"),
    (0x60B50C0, "ColumnFamilyOptions::Dump"),
    (0x60B1EA0, "base TablePropertiesCollectorFactory::ToString"),
    (0x5D3F6C0, "base Cache::GetPrintableOptions"),
]

# (guard name, dump instruction addr, GOT slot, expected addend)
GUARDS = [
    ("blob_cache GetPrintableOptions", 0x60B6246, 0x64ECD20, 0x5D3F6C0),
    ("collector ToString", 0x60B5D7D, 0x64EDCA8, 0x60B1EA0),
]

# (label, vaddr) -- string literals checked verbatim.
LITERALS = [
    ("BlockBasedTable", 0x44ECC8),
    ("LRUCache", 0x44B256),
    ("ChargedCache", 0x43B462),
    ("CompactOnDeletionCollector", 0x436389),
    ("NickName empty string", 0x4376FD),
    ("host header format", 0x958358),
    ("host skip format", 0x95AE28),
    ("blob_cache name format", 0x95D490),
    ("blob_cache options format", 0x95C868),
]

# (file name, start, stop) -- must match export_excerpts.py.
EXCERPTS = [
    ("dump-60b50c0.objdump.txt", 0x60B50C0, 0x60B79A6),
    ("helper-5fceda0.objdump.txt", 0x5FCEDA0, 0x5FCEE93),
    ("helper-nolevel-5fceea0.objdump.txt", 0x5FCEEA0, 0x5FCEF5B),
    ("host-5d954b0.objdump.txt", 0x5D954B0, 0x5D96890),
    ("logger-logheader-5fcc200.objdump.txt", 0x5FCC200, 0x5FCC218),
    ("logger-logv-levelled-5fcd400.objdump.txt", 0x5FCD400, 0x5FCD419),
    ("logger-logv-levelled-core-5fcd2c0.objdump.txt", 0x5FCD2C0, 0x5FCD3F5),
    ("logger-getinfologlevel-5fcc220.objdump.txt", 0x5FCC220, 0x5FCC229),
    ("logger-setinfologlevel-5fcc230.objdump.txt", 0x5FCC230, 0x5FCC239),
    ("logger-close-5fcc410.objdump.txt", 0x5FCC410, 0x5FCC473),
    ("logger-closeimpl-5fceae0.objdump.txt", 0x5FCEAE0, 0x5FCEB1F),
    ("logger-logv-5fce280.objdump.txt", 0x5FCE280, 0x5FCE766),
    ("autoroll-logheader-6057000.objdump.txt", 0x6057000, 0x60571B4),
    ("autoroll-getinfologlevel-60552e0.objdump.txt", 0x60552E0, 0x6055345),
    ("factory-bbt-getprintable-60da1f0.objdump.txt", 0x60DA1F0, 0x60DAA91),
    ("factory-cuckoo-getprintable-615aca0.objdump.txt", 0x615ACA0, 0x615AEE1),
    ("factory-plain-getprintable-6192d70.objdump.txt", 0x6192D70, 0x6193183),
    ("factory-bbt-name-60b1d90.objdump.txt", 0x60B1D90, 0x60B1D9C),
    ("configurable-getoption-609d760.objdump.txt", 0x609D760, 0x609D954),
    ("cache-base-getprintable-5d3f6c0.objdump.txt", 0x5D3F6C0, 0x5D3F6DB),
    ("cache-lru-getprintable-5d3f210.objdump.txt", 0x5D3F210, 0x5D3F4AD),
    ("cache-lru-name-5d3a950.objdump.txt", 0x5D3A950, 0x5D3A95C),
    ("cache-secondary-name-5d42bb0.objdump.txt", 0x5D42BB0, 0x5D42C5A),
    ("cache-secondary-getprintable-5d42460.objdump.txt", 0x5D42460, 0x5D425A9),
    ("cache-charged-name-5db68c0.objdump.txt", 0x5DB68C0, 0x5DB68CC),
    ("collector-tostring-base-60b1ea0.objdump.txt", 0x60B1EA0, 0x60B1F93),
    ("collector-compactondelete-tostring-61fb370.objdump.txt", 0x61FB370, 0x61FB74F),
    ("collector-compactondelete-name-61f9880.objdump.txt", 0x61F9880, 0x61F988C),
    ("collector-compactondelete-create-61fb010.objdump.txt", 0x61FB010, 0x61FB055),
    ("customizable-inner-5d2ca00.objdump.txt", 0x5D2CA00, 0x5D2CA07),
    ("customizable-nickname-5d2ca10.objdump.txt", 0x5D2CA10, 0x5D2CA1C),
]


def parse_rela_dyn(data):
    """Return {offset: (type, sym_name, addend)} for .rela.dyn entries.

    R_X86_64_RELATIVE (8) entries carry the slot value in the addend.
    R_X86_64_64 (1) entries carry an imported symbol name (used for
    __cxa_pure_virtual slots, e.g. base Cache::Name).
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


def direct_callers(data, target):
    """All E8 rel32 sites in .text whose target is `target`."""
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", data, 0x3A)
    strtab_off = struct.unpack_from(
        "<Q", data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
    text_size = None
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name,) = struct.unpack_from("<I", data, off)
        end = data.index(b"\x00", strtab_off + name)
        if data[strtab_off + name:end] == b".text":
            text_size = struct.unpack_from("<Q", data, off + 0x20)[0]
            break
    assert text_size is not None
    sites = []
    for off in range(TEXT_OFF, TEXT_OFF + text_size - 5):
        if data[off] == 0xE8:
            rel = struct.unpack_from("<i", data, off + 1)[0]
            tgt = TEXT_VADDR + (off - TEXT_OFF) + 5 + rel
            if tgt == target:
                sites.append(TEXT_VADDR + (off - TEXT_OFF))
    return sites


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

    # callers.tsv
    rows = ["target\tsite\tnote"]
    for target, note in CALLER_TARGETS:
        for site in direct_callers(data, target):
            rows.append(f"{target:#x}\t{site:#x}\t{note}")
    (HERE / "callers.tsv").write_text("\n".join(rows) + "\n")
    print(f"wrote callers.tsv ({len(rows) - 1} rows)")

    # guards.tsv
    rows = ["guard\tdump_cmp_addr\tgot_slot\tgot_addend\texpected"]
    for name, cmp_addr, got, expected in GUARDS:
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
