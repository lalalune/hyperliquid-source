#!/usr/bin/env python3
"""Census and tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-filter-policy-dispatch-115/census.py

Regenerates callers.tsv, literals.tsv, frames.txt and vtables.tsv.
The lea scans must reproduce the exact site sets found by hand: the
FilterPolicy dispatch 0x6136b40 has exactly one E8 caller (the dispatcher
0x6137290 at 0x61374a0) and the name lookup 0x6136650 exactly two (its own
recursion at 0x6136802 and the dispatch at 0x6136b83). The dispatch is the
same template as #4428's BlockCipher dispatch 0x5ff9fe0 and #4453's
SystemClock dispatch 0x5fd4080, instantiated for the "FilterPolicy"
factory type, with two template differences: the lookup inlines the
unordered_map find (no call to the map-find helper 0x5fd2980), and the
shared tail copies the 16-byte temp Status inline instead of calling the
Status move-assign helper 0x5fcdf70.
"""
import bisect
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

DISPATCH = 0x6136B40          # registry factory dispatch (FilterPolicy)
LOOKUP = 0x6136650            # name lookup (FilterPolicy)
DISPATCHER = 0x6137290         # sole caller of DISPATCH (cited, #4402 shape)
WRAPPER = 0x60DAFB0           # dispatcher wrapper (cited, #4402 shape)
STATUS_CTOR = 0x61CF670        # Status ctor (code, subcode, msg1, msg2)
RELEASE = 0x5D350C0            # shared_ptr control-block release
STR_CTOR = 0x612F730           # std::string ctor from a C string (this TU's copy)
STR_CTOR_OTHER = 0x5FCD890     # the same ctor's other copy (sibling dispatches)
REGISTRAR = 0x6137FE0          # builtin FilterPolicy registrar (cited)
PER_FACTORY_REGISTRAR = 0x6137810  # per-factory registrar (cited)
REG_INIT = 0x6138A10           # pthread_once init calling REGISTRAR (cited)
REGISTER_HELPER = 0x5FD1DA0    # registry register helper (cited)
MAP_FIND = 0x5FD2980           # map lookup helper (NOT called here: inlined)
MOVE_ASSIGN = 0x5FCDF70        # Status move-assign (NOT called here: inline tail)

CTRL_VTABLE = 0x64D37F0        # _Sp_counted_ptr<const FilterPolicy*> vtable
COUNTS_QWORD = 0x459B20        # (use, weak) == (1, 1)

# Literals with a complete binary-wide lea census.
EXPECTED_LEA_FULL = {
    0x4487C0: [0x5FD424C, 0x5FFA1BC, 0x5FFB4BC, 0x6136D24],
    0x439466: [0x5FD2F85, 0x5FD3034, 0x5FD436B, 0x5FD443C, 0x5FFA31B,
               0x5FFA3EC, 0x5FFB62B, 0x5FFB6F4, 0x6136E7B, 0x6136F6C],
    0x44D20E: [0x6136D62, 0x6136EB5, 0x6136FBC, 0x6137B6C, 0x6138179],
}
# Literals used binary-wide; only the sites inside the pinned FDEs are
# asserted here (the rest belong to other dispatches).
EXPECTED_LEA_IN_PACKET = {
    0x432138: [0x6136DAF],
}
# The pinned FDEs (start, end) for the in-packet filter.
PINNED_FDES = [(0x6136650, 0x6136B35), (0x6136B40, 0x613721B)]

EXPECTED_E8 = {
    DISPATCH: [0x61374A0],
    LOOKUP: [0x6136802, 0x6136B83],
    DISPATCHER: [0x60DAFE0],
}
# Shared helpers: only the sites inside the pinned FDEs are asserted.
EXPECTED_E8_IN_PACKET = {
    STATUS_CTOR: [0x6136E05, 0x6136F0A, 0x6136F59, 0x6137021],
    STR_CTOR: [0x6136D3C, 0x6136E8A, 0x6136F91],
    RELEASE: [0x6136CAB],
}
# Helpers the sibling dispatches call but this one does NOT: the lookup
# inlines the unordered_map find and the shared tail copies inline.
EXPECTED_E8_NOT_IN_PACKET = [MAP_FIND, MOVE_ASSIGN]

# The FilterPolicy control-block vtable: slots and typeinfo.
VTABLE_SLOTS = {
    CTRL_VTABLE: [(0, 0x60B1DA0), (1, 0x60B1E60), (2, 0x60B1DD0),
                  (3, 0x60B1E70), (4, 0x60B1DF0)],
}
TYPEINFOS = {
    CTRL_VTABLE: (0x64D3758,
                  b"St15_Sp_counted_ptrIPKN7rocksdb12FilterPolicyE"
                  b"LN9__gnu_cxx12_Lock_policyE2EE"),
}

LITERALS = {
    0x4487C0: b"Cannot make a shared ",
    0x44D20E: b"FilterPolicy",
    0x432138: b" from unguarded one ",
    0x439466: b"Could not load ",
    0x442AC3: b":false",
    0x4384F5: b":true",
}


def scan_lea_refs(data: bytes, targets) -> dict[int, list[int]]:
    """All RIP-relative lea sites (48/49/4c/4d 8d modrm rip-rel) per target."""
    seg = data[TEXT_OFF:]
    pat = re.compile(rb"[\x48\x49\x4c\x4d]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
    found: dict[int, list[int]] = {t: [] for t in targets}
    for m in pat.finditer(seg):
        i = m.start()
        rel = struct.unpack_from("<i", seg, i + 3)[0]
        va = TEXT_VA + i
        tgt = va + 7 + rel
        if tgt in found:
            found[tgt].append(va)
    return found


def scan_e8_callers(data: bytes, target: int) -> list[int]:
    """All E8 rel32 call sites targeting `target`."""
    seg = data[TEXT_OFF:]
    out = []
    for m in re.finditer(rb"\xe8", seg):
        i = m.start()
        if i + 5 > len(seg):
            continue
        rel = struct.unpack_from("<i", seg, i + 1)[0]
        va = TEXT_VA + i
        if va + 5 + rel == target:
            out.append(va)
    return out


def rela_dyn(data: bytes) -> dict[int, tuple[int, int, int]]:
    """Parse .rela.dyn (file offset 0x6be8, 24-byte entries)."""
    base, size = 0x6BE8, 0x163CC8
    out = {}
    for off in range(base, base + size, 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QqQ", data, off)
        out.setdefault(r_offset, (r_info & 0xFFFFFFFF, r_info >> 32, r_addend))
    return out


def cstr(data: bytes, va: int) -> bytes:
    # .rodata maps file offset == vaddr in this binary.
    return data[va:va + 200].split(b"\x00")[0]


def sections(data: bytes):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, _ = struct.unpack_from("<HHH", data, 0x3A)
    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        _, _, _, addr, offset, size, _, _, _, _ = struct.unpack_from(
            "<IIQQQQIIQQ", data, off)
        out.append((addr, offset, size))
    return out


def read_va(data: bytes, secs, va: int, n: int) -> bytes:
    for addr, offset, size in secs:
        if addr <= va < addr + size:
            return data[offset + va - addr: offset + va - addr + n]
    raise ValueError(f"no section contains {va:#x}")


def vtable_slot(data: bytes, secs, relocs, vtable: int, slot: int) -> int:
    """A vtable slot's target: RELATIVE reloc addend, else the raw qword."""
    off = vtable + slot * 8
    rel = relocs.get(off)
    if rel is not None and rel[0] == 8:
        return rel[2]
    return struct.unpack_from("<Q", read_va(data, secs, off, 8))[0]


def vtable_len(data: bytes, secs, relocs, vtable: int) -> int:
    """Slot count: consecutive slots holding 0 or a .text address."""
    n = 0
    while True:
        v = vtable_slot(data, secs, relocs, vtable, n)
        if v != 0 and not (TEXT_VA <= v < 0x63F0A00):
            break
        n += 1
        if n > 100:
            raise AssertionError(f"vtable {vtable:#x} runs past 100 slots")
    return n


def in_pinned_fdes(va: int) -> bool:
    return any(s <= va < e for s, e in PINNED_FDES)


def main() -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records

    data = BIN.read_bytes()
    secs = sections(data)
    assert __import__("hashlib").sha256(data).hexdigest() == DIGEST

    refs = scan_lea_refs(
        data, list(EXPECTED_LEA_FULL) + list(EXPECTED_LEA_IN_PACKET))
    for addr, want in EXPECTED_LEA_FULL.items():
        assert sorted(refs[addr]) == sorted(want), (
            f"lea refs for {addr:#x}: got {[hex(x) for x in sorted(refs[addr])]}")
    for addr, want in EXPECTED_LEA_IN_PACKET.items():
        got = sorted(s for s in refs[addr] if in_pinned_fdes(s))
        assert got == sorted(want), (
            f"in-packet lea refs for {addr:#x}: got {[hex(x) for x in got]}")

    for target, want in EXPECTED_E8.items():
        got = scan_e8_callers(data, target)
        assert sorted(got) == sorted(want), (
            f"E8 callers of {target:#x}: got {[hex(x) for x in sorted(got)]}")
    for target, want in EXPECTED_E8_IN_PACKET.items():
        got = scan_e8_callers(data, target)
        for site in want:
            assert site in got, f"in-packet site {site:#x} missing for {target:#x}"
        got_in = sorted(s for s in got if in_pinned_fdes(s))
        assert got_in == sorted(want), (
            f"in-packet E8 callers of {target:#x}: "
            f"got {[hex(x) for x in got_in]}")
    for target in EXPECTED_E8_NOT_IN_PACKET:
        got = scan_e8_callers(data, target)
        got_in = sorted(s for s in got if in_pinned_fdes(s))
        assert got_in == [], (
            f"{target:#x} must have no in-packet caller, got "
            f"{[hex(x) for x in got_in]}")

    _, frames = eh_frame_records(data)
    fdes = sorted((f["start"], f["end"]) for f in frames)
    starts = [s for s, _ in fdes]

    def enclosing(addr: int) -> tuple[int, int]:
        i = bisect.bisect_right(starts, addr) - 1
        s, e = fdes[i]
        assert s <= addr < e, f"no FDE encloses {addr:#x}"
        return s, e

    frame_rows = [
        ("function", "fde_start", "fde_end"),
        ("0x6136650", "0x6136650", "0x6136b35"),
        ("0x6136b40", "0x6136b40", "0x613721b"),
        ("0x61cf670", "0x61cf670", "0x61cf767"),
        ("0x5d350c0", "0x5d350c0", "0x5d35145"),
        ("0x612f730", "0x612f730", "0x612f813"),
        ("0x6137290", "0x6137290", "0x6137688"),
        ("0x60dafb0", "0x60dafb0", "0x60db041"),
        ("0x6137fe0", "0x6137fe0", "0x61389e4"),
        ("0x6137810", "0x6137810", "0x6137d58"),
        ("0x6138a10", "0x6138a10", "0x6138a8b"),
        ("0x61f8670", "0x61f8670", "0x61f86f2"),
    ]
    for _, s, e in frame_rows[1:]:
        es, ee = enclosing(int(s, 16))
        assert (es, ee) == (int(s, 16), int(e, 16)), f"FDE mismatch for {s}"
    (HERE / "frames.txt").write_text(
        "\n".join("\t".join(r) for r in frame_rows) + "\n")

    # Vtable slots + typeinfos from .rela.dyn / raw vtable bytes.
    relocs = rela_dyn(data)
    for vtable, slots in VTABLE_SLOTS.items():
        for slot, want in slots:
            got = vtable_slot(data, secs, relocs, vtable, slot)
            assert got == want, (
                f"vtable {vtable:#x} slot {slot}: got {got:#x}, want {want:#x}")
    for vtable, (typeinfo, name) in TYPEINFOS.items():
        ti = relocs.get(vtable - 0x8)
        assert ti is not None and ti[2] == typeinfo, (
            f"vtable {vtable:#x} typeinfo: {ti}")
        got_name = relocs.get(typeinfo + 0x8)
        assert got_name is not None and cstr(data, got_name[2]) == name, (
            f"typeinfo name for {vtable:#x}: {got_name}")
    # Like the BlockCipher vtable (#4428), this one has a trailing zero
    # slot after the 5 function slots (vtable_len counts it: 6).
    assert vtable_len(data, secs, relocs, CTRL_VTABLE) == 6, (
        f"control-block vtable length "
        f"{vtable_len(data, secs, relocs, CTRL_VTABLE)}")
    assert vtable_slot(data, secs, relocs, CTRL_VTABLE, 5) == 0, (
        "trailing vtable slot is not zero")
    # The counts qword (use, weak) == (1, 1) at 0x459b20.
    assert read_va(data, secs, COUNTS_QWORD, 8) == struct.pack(
        "<Q", 0x100000001), "counts qword mismatch"
    # The string ctor used here (0x612f730) is a second copy of the same
    # ctor the sibling dispatches call as 0x5fcd890: identical first bytes.
    assert read_va(data, secs, STR_CTOR, 16) == read_va(
        data, secs, STR_CTOR_OTHER, 16), "string ctor copies differ"

    # ---- tables ----
    rows = [("target", "site", "kind", "enclosing_fde")]
    for addr in sorted(EXPECTED_LEA_FULL):
        for site in sorted(refs[addr]):
            s, e = enclosing(site)
            rows.append((f"{addr:#x}", f"{site:#x}", "lea",
                         f"{s:#x}..{e:#x}"))
    for addr in sorted(EXPECTED_LEA_IN_PACKET):
        for site in sorted(s for s in refs[addr] if in_pinned_fdes(s)):
            s, e = enclosing(site)
            rows.append((f"{addr:#x}", f"{site:#x}", "lea",
                         f"{s:#x}..{e:#x}"))
    for target, want in EXPECTED_E8.items():
        for site in sorted(want):
            s, e = enclosing(site)
            rows.append((f"{target:#x}", f"{site:#x}", "call",
                         f"{s:#x}..{e:#x}"))
    for target, want in EXPECTED_E8_IN_PACKET.items():
        for site in sorted(want):
            s, e = enclosing(site)
            rows.append((f"{target:#x}", f"{site:#x}", "call",
                         f"{s:#x}..{e:#x}"))
    (HERE / "callers.tsv").write_text(
        "\n".join("\t".join(r) for r in rows) + "\n")

    lit_rows = [("address", "literal", "length", "note")]
    for addr, text in LITERALS.items():
        note = ""
        if addr == 0x44D20E:
            note = ("built SSO in 0x6136650: movabs 'FilterPo' + 'licy' "
                    "(0x7963696c)")
        if addr in (0x442AC3, 0x4384F5):
            note = "built by the registrar 0x6137fe0 (cited, not pinned)"
        lit_rows.append((f"{addr:#x}", text.decode(), str(len(text)), note))
    (HERE / "literals.tsv").write_text(
        "\n".join("\t".join(r) for r in lit_rows) + "\n")

    vt_rows = [("vtable", "slot", "target", "role")]
    for vtable, slots in VTABLE_SLOTS.items():
        for slot, target in slots:
            vt_rows.append((f"{vtable:#x}", str(slot), f"{target:#x}",
                            "control-block method"))
    vt_rows.append((f"{CTRL_VTABLE:#x}", "5", "0x0", "trailing zero slot"))
    vt_rows.append((f"{CTRL_VTABLE:#x}", "typeinfo",
                    f"{TYPEINFOS[CTRL_VTABLE][0]:#x}",
                    TYPEINFOS[CTRL_VTABLE][1].decode()))
    (HERE / "vtables.tsv").write_text(
        "\n".join("\t".join(r) for r in vt_rows) + "\n")

    print(f"census OK: {len(rows) - 1} caller rows, "
          f"{len(lit_rows) - 1} literals, {len(vt_rows) - 1} vtable rows")


if __name__ == "__main__":
    main()
