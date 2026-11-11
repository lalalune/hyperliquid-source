#!/usr/bin/env python3
"""Census and tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-filter-policy-registrations-115/census.py

Regenerates callers.tsv, literals.tsv, frames.txt and vtables.tsv.
The builtin registrar 0x6137fe0 registers nine FilterPolicy factories
under the single map key 'FilterPolicy': one inlined (the
ReadOnlyBuiltinFilterPolicy creator 0x612de10) and eight through the
per-factory registrar 0x6137810. The nine creator invokers have no direct
E8 callers anywhere -- they are reached only through the factory record's
+0x18 invoker pointer. The nine lambda managers are one 0x2d-byte
template, byte-identical except the op-0 lea rel32.
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

REGISTRAR = 0x6137FE0          # builtin FilterPolicy registrar (pinned)
PER_FACTORY = 0x6137810        # per-factory registrar (pinned)
REG_INIT = 0x6138A10           # pthread_once init calling REGISTRAR (cited)
REGISTER_HELPER = 0x5FD1DA0    # registry register helper (cited)
ENTRY_BUILDER = 0x6134BE0      # PatternEntry builder (cited)
VEC_APPEND = 0x61350B0         # names-vector append (cited)
STR_CTOR = 0x612F730           # std::string ctor from a C string (cited)
STR_COPY = 0x612DF20           # string copy helper (cited)
RELEASE = 0x5D350C0            # shared_ptr control-block release (cited)
SPLIT = 0x61D2380              # ':'-split helper (cited)
PARSE_DOUBLE = 0x61D1E30       # double parse helper (cited)
PARSE_INT = 0x61D1B90          # int parse helper (cited)
BASE_CTOR = 0x612FC30          # shared filter-policy base ctor (cited)
BLOOM_CTOR = 0x6130160         # BloomFilterPolicy ctor wrapper (cited)
BLOOM_HELPER = 0x6131DF0       # Bloom factory helper, ignores edi (cited)
RIBBON_HELPER = 0x6131EC0      # Ribbon factory helper (cited)
RIBBON_CTOR = 0x6131E40        # RibbonFilterPolicy ctor (cited)
NAME_FN_BUILTIN = 0x612D290    # tiny name fn, no callers (cited)

INVOKERS = [
    0x612DE10, 0x6134130, 0x61338A0, 0x6134010, 0x6133EF0,
    0x6133DC0, 0x61339E0, 0x6133B30, 0x6133C80,
]
MANAGERS = [0x612D2A0 + k * 0x30 for k in range(9)]

# Literals with a complete binary-wide lea census.
EXPECTED_LEA_FULL = {
    0x44481B: [0x612D294, 0x612FC24, 0x6130144],
    0x43C831: [0x6130184],
    0x44FF67: [0x61301A4],
    0x43E8EB: [0x6131E74],
    0x4466F4: [0x6131E94],
    0x442AC3: [0x6130C06, 0x61382E6],
    0x4384F5: [0x61383E0],
    0x95DEA0: [0x6131524],
    0x965BC0: [0x6131544],
    0x96A630: [0x6131564],
    0x44D20E: [0x6136D62, 0x6136EB5, 0x6136FBC, 0x6137B6C, 0x6138179],
}
# The pinned FDEs (start, end) for the in-packet filter.
PINNED_FDES = [
    (0x6137810, 0x6137D58), (0x6137FE0, 0x61389E4),
    (0x612DE10, 0x612DE51), (0x6134130, 0x6134238),
    (0x61338A0, 0x61339A8), (0x6134010, 0x61340FC),
    (0x6133EF0, 0x6133FDC), (0x6133DC0, 0x6133EBC),
    (0x61339E0, 0x6133AF8), (0x6133B30, 0x6133C48),
    (0x6133C80, 0x6133D98), (0x612D2A0, 0x612D2CD),
]

EXPECTED_E8 = {
    PER_FACTORY: [0x613825F, 0x6138356, 0x6138450, 0x61384E3,
                  0x61385EB, 0x6138662, 0x61386C9, 0x6138730],
    REGISTRAR: [0x6138A48],
    ENTRY_BUILDER: [0x6138225, 0x61382C0, 0x61383BF, 0x61384B9,
                    0x6138544, 0x6138654, 0x61386BB, 0x6138722],
    VEC_APPEND: [0x613824C, 0x61382DC, 0x61383DB, 0x61384D5, 0x6138560],
    BLOOM_CTOR: [0x6131E16, 0x61338F8, 0x6134188],
    BLOOM_HELPER: [0x6134051],
    RIBBON_HELPER: [0x6133E15, 0x6133F2E],
    BASE_CTOR: [0x6130168, 0x6131E4F, 0x6133A38, 0x6133B88, 0x6133CD8],
}
# Helpers called only from inside the pinned FDEs are asserted per-site.
EXPECTED_E8_IN_PACKET = {
    SPLIT: [0x6133A0C, 0x6133B5C, 0x6133CAC, 0x6133DEA, 0x6133F1A,
            0x613403A, 0x61338CC, 0x613415C],
    PARSE_DOUBLE: [0x6133A19, 0x6133B69, 0x6133CB9, 0x6133DF7,
                   0x6133F27, 0x6134047, 0x61338D9, 0x6134169],
    PARSE_INT: [0x6133E09],
    STR_COPY: [0x61378C0, 0x61380DA, 0x613832A, 0x6138424, 0x61385B3],
}
# The nine invokers and the tiny builtin name fn have no direct E8 caller.
EXPECTED_E8_NONE = INVOKERS + [NAME_FN_BUILTIN, REG_INIT]

# Policy vtables: the stored vptr, its slots and typeinfo.
# Slots 0/1 are the per-class Name/CreateFilter; slots 2..9 are shared.
VTABLE_SLOTS = {
    0x64D4AF0: [(0, 0x61321A0), (1, 0x61321C0),
                (14, 0x6130150), (15, 0x5D32A30), (16, 0x612FB20),
                (17, 0x5D2CA00), (18, 0x5D2CA10), (20, 0x612CF60)],
    0x64D4F20: [(0, 0x6132150), (1, 0x6132170),
                (14, 0x6130190), (15, 0x6130BC0), (16, 0x61300D0),
                (17, 0x5D2CA00), (18, 0x61301B0), (20, 0x6136510)],
    0x64D4FE0: [(0, 0x6132100), (1, 0x6132120),
                (14, 0x6131530), (15, 0x6130A20), (16, 0x61300D0),
                (17, 0x5D2CA00), (18, 0x5D2CA10), (20, 0x61302B0)],
    0x64D50A0: [(0, 0x61320B0), (1, 0x61320D0),
                (14, 0x6131550), (15, 0x6130A20), (16, 0x61300D0),
                (17, 0x5D2CA00), (18, 0x5D2CA10), (20, 0x6136540)],
    0x64D5160: [(0, 0x6132060), (1, 0x6132080),
                (14, 0x6131570), (15, 0x6130A20), (16, 0x61300D0),
                (17, 0x5D2CA00), (18, 0x5D2CA10), (20, 0x6135EF0)],
    0x64D52E0: [(0, 0x6132010), (1, 0x6132030),
                (14, 0x6131E80), (15, 0x6130D90), (16, 0x61300D0),
                (17, 0x5D2CA00), (18, 0x6131EA0), (20, 0x6136560)],
    0x64D8ED0: [(0, 0x5FF2030), (1, 0x5FF2150), (2, 0x61F8670),
                (3, 0x61F8120)],
    0x64D53A0: [(0, 0x612D450), (1, 0x612E010), (2, 0x612D4E0),
                (3, 0x612D4F0)],
}
SHARED_POLICY_SLOTS = [(2, 0x609D760), (3, 0x609DC40), (4, 0x5D32560),
                       (5, 0x6095E70), (6, 0x6096790), (7, 0x5D2E090),
                       (8, 0x60956F0), (9, 0x609D0E0),
                       (10, 0x60986B0), (11, 0x6095710), (12, 0x609DE80),
                       (13, 0x609D980), (19, 0x612D290), (21, 0x61318A0)]
TYPEINFOS = {
    0x64D4AF0: (0x64D4888, b"N7rocksdb27ReadOnlyBuiltinFilterPolicyE"),
    0x64D4F20: (0x64D48B8, b"N7rocksdb17BloomFilterPolicyE"),
    0x64D4FE0: (0x64D48E8, b"N7rocksdb4test23LegacyBloomFilterPolicyE"),
    0x64D50A0: (0x64D4900, b"N7rocksdb4test26FastLocalBloomFilterPolicyE"),
    0x64D5160: (0x64D4918, b"N7rocksdb4test29Standard128RibbonFilterPolicyE"),
    0x64D52E0: (0x64D48D0, b"N7rocksdb18RibbonFilterPolicyE"),
    0x64D8ED0: (0x64D8E90, b"N7rocksdb13ObjectLibrary12PatternEntryE"),
    0x64D53A0: (0x64D4A08,
                b"N7rocksdb13ObjectLibrary12FactoryEntryIKNS_12FilterPolicyEEE"),
}
MANAGER_TYPEINFOS = [
    (0x612D2A0, 0x64D4A20), (0x612D2D0, 0x64D4A30),
    (0x612D300, 0x64D4A40), (0x612D330, 0x64D4A50),
    (0x612D360, 0x64D4A60), (0x612D390, 0x64D4A70),
    (0x612D3C0, 0x64D4A80), (0x612D3F0, 0x64D4A90),
    (0x612D420, 0x64D4AA0),
]
MANAGER_TYPEINFO_NAME = (
    b"*ZN7rocksdb12_GLOBAL__N_1L29RegisterBuiltinFilterPoliciesE"
    b"RNS_13ObjectLibraryERKNSt7__cxx1112basic_stringIcSt11char_"
    b"traitsIcESaIcEEEEUlSA_PSt10unique_ptrIKNS_12FilterPolicyESt"
    b"14default_deleteISD_EEPS8")

LITERALS = {
    0x44481B: b"rocksdb.BuiltinBloomFilter",
    0x43C831: b"bloomfilter",
    0x44FF67: b"rocksdb.BloomFilter",
    0x43E8EB: b"ribbonfilter",
    0x4466F4: b"rocksdb.RibbonFilter",
    0x442AC3: b":false",
    0x4384F5: b":true",
    0x95DEA0: b"rocksdb.internal.LegacyBloomFilter",
    0x965BC0: b"rocksdb.internal.FastLocalBloomFilter",
    0x96A630: b"rocksdb.internal.Standard128RibbonFilter",
    0x44D20E: b"FilterPolicy",
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

    refs = scan_lea_refs(data, list(EXPECTED_LEA_FULL))
    for addr, want in EXPECTED_LEA_FULL.items():
        assert sorted(refs[addr]) == sorted(want), (
            f"lea refs for {addr:#x}: got {[hex(x) for x in sorted(refs[addr])]}")

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
    for target in EXPECTED_E8_NONE:
        got = scan_e8_callers(data, target)
        assert got == [], (
            f"{target:#x} must have no E8 caller, got "
            f"{[hex(x) for x in got]}")

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
        ("0x6137810", "0x6137810", "0x6137d58"),
        ("0x6137fe0", "0x6137fe0", "0x61389e4"),
        ("0x612de10", "0x612de10", "0x612de51"),
        ("0x6134130", "0x6134130", "0x6134238"),
        ("0x61338a0", "0x61338a0", "0x61339a8"),
        ("0x6134010", "0x6134010", "0x61340fc"),
        ("0x6133ef0", "0x6133ef0", "0x6133fdc"),
        ("0x6133dc0", "0x6133dc0", "0x6133ebc"),
        ("0x61339e0", "0x61339e0", "0x6133af8"),
        ("0x6133b30", "0x6133b30", "0x6133c48"),
        ("0x6133c80", "0x6133c80", "0x6133d98"),
        ("0x612d2a0", "0x612d2a0", "0x612d2cd"),
        ("0x612d290", "0x612d290", "0x612d29c"),
        ("0x6138a10", "0x6138a10", "0x6138a8b"),
        ("0x6134be0", "0x6134be0", "0x61350ab"),
        ("0x61350b0", "0x61350b0", "0x61350f4"),
        ("0x612df20", "0x612df20", "0x612dfc3"),
        ("0x5fd1da0", "0x5fd1da0", "0x5fd1ffa"),
        ("0x6130160", "0x6130160", "0x613017d"),
        ("0x6131df0", "0x6131df0", "0x6131e31"),
        ("0x6131ec0", "0x6131ec0", "0x6131f05"),
        ("0x6131e40", "0x6131e40", "0x6131e6c"),
        ("0x612fc30", "0x612fc30", "0x61300b1"),
        ("0x61d2380", "0x61d2380", "0x61d296e"),
        ("0x61d1e30", "0x61d1e30", "0x61d1ee6"),
        ("0x61d1b90", "0x61d1b90", "0x61d1e0e"),
        ("0x612d2d0", "0x612d2d0", "0x612d2fd"),
        ("0x612d300", "0x612d300", "0x612d32d"),
        ("0x612d330", "0x612d330", "0x612d35d"),
        ("0x612d360", "0x612d360", "0x612d38d"),
        ("0x612d390", "0x612d390", "0x612d3bd"),
        ("0x612d3c0", "0x612d3c0", "0x612d3ed"),
        ("0x612d3f0", "0x612d3f0", "0x612d41d"),
        ("0x612d420", "0x612d420", "0x612d44d"),
        ("0x612fc20", "0x612fc20", "0x612fc2c"),
        ("0x6130140", "0x6130140", "0x613014c"),
        ("0x6130180", "0x6130180", "0x613018c"),
        ("0x61301a0", "0x61301a0", "0x61301ac"),
        ("0x6131e70", "0x6131e70", "0x6131e7c"),
        ("0x6131e90", "0x6131e90", "0x6131e9c"),
        ("0x6131520", "0x6131520", "0x613152c"),
        ("0x6131540", "0x6131540", "0x613154c"),
        ("0x6131560", "0x6131560", "0x613156c"),
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
    for vtable, slots in VTABLE_SLOTS.items():
        if vtable in (0x64D4AF0, 0x64D4F20, 0x64D4FE0, 0x64D50A0, 0x64D5160,
                      0x64D52E0):
            for slot, want in SHARED_POLICY_SLOTS:
                got = vtable_slot(data, secs, relocs, vtable, slot)
                assert got == want, (
                    f"policy vtable {vtable:#x} shared slot {slot}: "
                    f"got {got:#x}, want {want:#x}")
            assert vtable_len(data, secs, relocs, vtable) == 23, (
                f"policy vtable {vtable:#x} length "
                f"{vtable_len(data, secs, relocs, vtable)}")
            assert vtable_slot(data, secs, relocs, vtable, 22) == 0, (
                f"policy vtable {vtable:#x} trailing slot is not zero")
    for vtable in (0x64D8ED0, 0x64D53A0):
        assert vtable_len(data, secs, relocs, vtable) == 5, (
            f"vtable {vtable:#x} length "
            f"{vtable_len(data, secs, relocs, vtable)}")
        assert vtable_slot(data, secs, relocs, vtable, 4) == 0, (
            f"vtable {vtable:#x} trailing slot is not zero")
    for vtable, (typeinfo, name) in TYPEINFOS.items():
        ti = relocs.get(vtable - 0x8)
        assert ti is not None and ti[2] == typeinfo, (
            f"vtable {vtable:#x} typeinfo: {ti}")
        got_name = relocs.get(typeinfo + 0x8)
        assert got_name is not None and cstr(data, got_name[2]) == name, (
            f"typeinfo name for {vtable:#x}: {got_name}")

    # The nine managers: one 0x2d-byte template, differing only in the
    # op-0 lea rel32 (bytes 0x23..0x26); op-0 typeinfo addresses step 0x10.
    for mgr, want_ti in MANAGER_TYPEINFOS:
        b = read_va(data, secs, mgr, 0x2D)
        template = read_va(data, secs, MANAGERS[0], 0x2D)
        assert b[:0x20] == template[:0x20], (
            f"manager {mgr:#x} head differs from the template")
        assert b[0x27:] == template[0x27:], (
            f"manager {mgr:#x} tail differs from the template")
        assert b[0x20:0x23] == b"\x48\x8d\x05", (
            f"manager {mgr:#x} has no op-0 lea at +0x20")
        rel = struct.unpack_from("<i", b, 0x23)[0]
        assert mgr + 0x20 + 7 + rel == want_ti, (
            f"manager {mgr:#x} op-0 typeinfo: "
            f"got {mgr + 0x20 + 7 + rel:#x}, want {want_ti:#x}")
        got_name = relocs.get(want_ti + 0x8)
        assert got_name is not None and cstr(data, got_name[2]) == MANAGER_TYPEINFO_NAME, (
            f"manager {mgr:#x} typeinfo name: {got_name}")

    # ---- tables ----
    rows = [("target", "site", "kind", "enclosing_fde")]
    for addr in sorted(EXPECTED_LEA_FULL):
        for site in sorted(refs[addr]):
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
    notes = {
        0x44481B: "also returned by the uncalled name fn 0x612d290 (lea 0x612d294)",
        0x442AC3: "option element of registration 3 (tag 2)",
        0x4384F5: "option element of registration 4 (tag 2)",
        0x44D20E: "the map key for all nine registrations",
    }
    for addr, text in LITERALS.items():
        lit_rows.append((f"{addr:#x}", text.decode(), str(len(text)),
                         notes.get(addr, "")))
    (HERE / "literals.tsv").write_text(
        "\n".join("\t".join(r) for r in lit_rows) + "\n")

    vt_rows = [("vtable", "slot", "target", "role")]
    for vtable, slots in VTABLE_SLOTS.items():
        for slot, target in slots:
            vt_rows.append((f"{vtable:#x}", str(slot), f"{target:#x}",
                            "vtable method"))
    for vtable in (0x64D4AF0, 0x64D4F20, 0x64D4FE0, 0x64D50A0, 0x64D5160,
                   0x64D52E0):
        for slot, target in SHARED_POLICY_SLOTS:
            vt_rows.append((f"{vtable:#x}", str(slot), f"{target:#x}",
                            "shared FilterPolicy base slot"))
    for vtable in (0x64D8ED0, 0x64D53A0):
        vt_rows.append((f"{vtable:#x}", "4", "0x0", "trailing zero slot"))
    for vtable in (0x64D4AF0, 0x64D4F20, 0x64D4FE0, 0x64D50A0, 0x64D5160,
                   0x64D52E0):
        vt_rows.append((f"{vtable:#x}", "22", "0x0", "trailing zero slot"))
    for vtable, (typeinfo, name) in TYPEINFOS.items():
        vt_rows.append((f"{vtable:#x}", "typeinfo", f"{typeinfo:#x}",
                        name.decode()))
    (HERE / "vtables.tsv").write_text(
        "\n".join("\t".join(r) for r in vt_rows) + "\n")

    print(f"census OK: {len(rows) - 1} caller rows, "
          f"{len(lit_rows) - 1} literals, {len(vt_rows) - 1} vtable rows")


if __name__ == "__main__":
    main()
