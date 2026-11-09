#!/usr/bin/env python3
"""Census and tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-provider-dispatch-factory-115/census.py

Regenerates callers.tsv, maps.tsv, vtables.tsv, literals.tsv and
frames.txt. The lea scans must reproduce the exact site sets found by hand:
the block_size map 0x65052c0 is referenced by the three factories, the
initializer and this dispatch factory; the registry map 0x6505278 only by
the two dispatchers; the ROT13 vtable 0x64cfea0 by the three factories plus
this dispatch factory; the control-block vtable 0x64d0128 only by this
dispatch factory. The dispatch factory 0x5ffabd0 has no direct E8 caller
and no lea site: it is reached only as slot 21 of the CTREncryptionProvider
vtable 0x64cffb0.
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

FACTORY = 0x5FFABD0          # dispatch factory, CTR vtable slot 21
DISPATCHER = 0x5FFA710        # registry dispatcher (configure + reset)
WRAPPER = 0x5FFAE10          # "id"-guard wrapper -> dispatcher
TWIN_DISPATCHER = 0x5FFBA10   # byte-identical twin of the dispatcher
TWIN_WRAPPER = 0x5FFBDE0      # byte-identical twin of the wrapper
REG_DISPATCH = 0x5FF9FE0      # registry factory dispatch (cited callee)
REG_INIT = 0x5FF9C50          # registry map initializer (cited)
CONFIG_INIT = 0x60BB890       # ConfigOptions default init (cited)
STR_CTOR = 0x5FF0300          # std::string ctor from C string (cited)
CONFIGURE_HOST = 0x609E510    # options-map host (pinned by #4349)
NULL_CONFIGURE = 0x609E2D0    # null-checked configure entry (#4334)
REGISTER_OPTIONS = 0x6099CE0  # RegisterOptions helper (pinned by #4372)
RELEASE = 0x5D350C0           # shared_ptr control-block release (#4395)
STATUS_CTOR = 0x61CF670       # Status ctor (code, location, message)
MOVE_ASSIGN = 0x5FEFE90       # Status move-assign

MAP_BLOCK = 0x65052C0         # block_size map (one entry, pinned #4389)
MAP_REGISTRY = 0x6505278      # provider registry map (init 0x5ff9c50)

VT_CTR = 0x64CFFB0            # CTREncryptionProvider vtable
VT_ROT13 = 0x64CFEA0          # ROT13BlockCipher vtable
VT_CTRL = 0x64D0128           # _Sp_counted_ptr<ROT13BlockCipher> vtable

GOT_SINGLE_THREADED = 0x64ED290
GOT_WRAPPER = 0x64ED9B0       # holds 0x5ffae10
GOT_TWIN_WRAPPER = 0x64ED9A8  # holds 0x5ffbde0
GOT_ONCE_GUARDS = (0x64ED818, 0x64ED820, 0x64ED828)

EXPECTED_LEA = {
    MAP_BLOCK: [0x5FF6AE1, 0x5FF6E41, 0x5FF7261, 0x5FF7367, 0x5FF7F9E,
                0x5FFACDE],
    MAP_REGISTRY: [0x5FFA786, 0x5FFBA86],
    VT_ROT13: [0x5FF6A6B, 0x5FF6E19, 0x5FF7209, 0x5FF7350, 0x5FFACC1],
    VT_CTRL: [0x5FFAD31],
    REG_INIT: [0x5FFA77F, 0x5FFBA7F],
    FACTORY: [],
    DISPATCHER: [],
    WRAPPER: [],
}
EXPECTED_E8 = {
    FACTORY: [],
    DISPATCHER: [0x5FFAD95, 0x5FFAE40],
    TWIN_DISPATCHER: [0x5FFBE10],
    WRAPPER: [],
    TWIN_WRAPPER: [],
    REG_DISPATCH: [0x5FFA962],
    CONFIG_INIT: [0x5D8EACF, 0x5E3406F, 0x5E34458, 0x5FFAD84, 0x60A1DCF,
                  0x60A20CD, 0x60D4A48, 0x612073B, 0x61C83AA],
    STR_CTOR: [0x5FF113B, 0x5FF6E3C, 0x5FF7362, 0x5FF7DBF, 0x5FF7E6A,
               0x5FF810B, 0x5FF8918, 0x5FF8AE3, 0x5FF8B84, 0x5FF912E,
               0x5FF92F0, 0x5FF937C, 0x5FFA1D4, 0x5FFA32A, 0x5FFA411,
               0x5FFACD9, 0x5FFAD7C, 0x5FFB4D4, 0x5FFB63A, 0x5FFB719],
}
# In-packet E8 sites of shared helpers (subset checks, not full lists).
EXPECTED_E8_RELEASE_IN_PACKET = [
    0x5FFAD44, 0x5FFADA7,  # dispatch factory: old-cipher release, both paths
    0x5FFA918, 0x5FFBC18,  # dispatcher + twin: reset-path release
    0x5FFAE81, 0x5FFBE51,  # wrapper + twin: "id"-path release
    0x5FFA14B,            # registry factory dispatch
]
EXPECTED_E8_REGISTER_OPTIONS_IN_PACKET = [0x5FFACEE]
EXPECTED_E8_CONFIGURE_HOST_IN_PACKET = [0x5FFA85A, 0x5FFBB5A]
EXPECTED_E8_NULL_CONFIGURE_IN_PACKET = [0x5FFAA45, 0x5FFBD45]
EXPECTED_E8_STATUS_CTOR_IN_PACKET = [
    0x5FFAC3B,  # factory gate error
    0x5FFAA27, 0x5FFBD27,  # dispatcher + twin: "Cannot reset object "
    0x5FFA29D, 0x5FFA389, 0x5FFA3D9, 0x5FFA4A1,  # registry factory dispatch
]

# Vtable typeinfos from .rela.dyn (R_X86_64_RELATIVE at vtable - 0x8).
TYPEINFOS = {
    VT_CTR: (0x64CF740,
             b"N7rocksdb21CTREncryptionProviderE"),
    VT_ROT13: (0x64CF770,
               b"*N7rocksdb12_GLOBAL__N_116ROT13BlockCipherE"),
    VT_CTRL: (0x64CF820,
              b"*St15_Sp_counted_ptrIPN7rocksdb12_GLOBAL__N_116ROT13BlockCipherE"
              b"LN9__gnu_cxx12_Lock_policyE2EE"),
}
# Pinned vtable slots (slot -> target).
VTABLE_SLOTS = {
    VT_CTR: [(0, 0x5FF2F00), (1, 0x5FF30B0), (9, 0x609D0E0),
             (10, 0x60986B0), (12, 0x609DE80), (13, 0x609D980),
             (15, 0x5D32A30), (16, 0x5FF1030), (17, 0x5D2CA00),
             (18, 0x5D2CA10), (19, 0x5FEFA30), (20, 0x5FF5140),
             (21, 0x5FFABD0), (22, 0x5FF3890), (23, 0x5FF02E0),
             (24, 0x5FEFA40), (25, 0x5FF49B0)],
    VT_CTRL: [(0, 0x5FEFB60), (1, 0x5FEFD10), (2, 0x5FF0580),
              (3, 0x5FEFD20), (4, 0x5FEFC60)],
}
# Slot identities on the CTR vtable (slot -> role).
SLOT_IDENTITIES = {
    0: "complete dtor 0x5ff2f00",
    1: "deleting dtor 0x5ff30b0 (#4395)",
    9: "ConfigureOptions entry 0x609d0e0 (#4334)",
    10: "ConfigureOption core 0x60986b0 (#4328)",
    12: "slot-12 serializer 0x609de80 (#4328)",
    13: "GetOptionName 0x609d980 (#4334)",
    15: "GetId 0x5d32a30 (#4328)",
    16: "name-match predicate override 0x5ff1030 (base 0x5d2e770, #4349)",
    17: "Inner 0x5d2ca00 (#4349)",
    18: "NickName() 0x5d2ca10 (#4349)",
    19: "0x5fefa30 (role open)",
    20: "0x5ff5140 (role open)",
    21: "dispatch factory 0x5ffabd0 (pinned here)",
    22: "0x5ff3890 (role open)",
    23: "0x5ff02e0 (role open)",
    24: "0x5fefa40 (role open)",
    25: "0x5ff49b0 (role open)",
}

# The maps referenced by this packet.
MAPS = {
    # map: (key, key source, insert site, atexit site, pack, flags, offset)
    0x65052C0: ("block_size", "literal 0x43a5f7", 0x5FF7FC4, 0x5FF8016,
                0x100000016, 0x400, 0),
}
# The registry map: built by the pthread_once initializer 0x5ff9c50;
# its entries are the (factory, paired-function) pairs of #4395.
REGISTRY_MAP = (0x6505278, "0x5ff9c50")


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


def main() -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records

    data = BIN.read_bytes()
    secs = sections(data)
    assert __import__("hashlib").sha256(data).hexdigest() == DIGEST

    refs = scan_lea_refs(data, list(EXPECTED_LEA))
    for addr, want in EXPECTED_LEA.items():
        assert sorted(refs[addr]) == sorted(want), (
            f"lea refs for {addr:#x}: got {[hex(x) for x in sorted(refs[addr])]}")

    for target, want in EXPECTED_E8.items():
        got = scan_e8_callers(data, target)
        assert sorted(got) == sorted(want), (
            f"E8 callers of {target:#x}: got {[hex(x) for x in sorted(got)]}")
    for target, sites in (
            (RELEASE, EXPECTED_E8_RELEASE_IN_PACKET),
            (REGISTER_OPTIONS, EXPECTED_E8_REGISTER_OPTIONS_IN_PACKET),
            (CONFIGURE_HOST, EXPECTED_E8_CONFIGURE_HOST_IN_PACKET),
            (NULL_CONFIGURE, EXPECTED_E8_NULL_CONFIGURE_IN_PACKET),
            (STATUS_CTOR, EXPECTED_E8_STATUS_CTOR_IN_PACKET)):
        got = scan_e8_callers(data, target)
        for site in sites:
            assert site in got, f"in-packet site {site:#x} missing for {target:#x}"

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
        ("0x5ffabd0", "0x5ffabd0", "0x5ffae04"),
        ("0x5ffa710", "0x5ffa710", "0x5ffaad9"),
        ("0x5ffae10", "0x5ffae10", "0x5ffaea1"),
        ("0x5ffba10", "0x5ffba10", "0x5ffbdd9"),
        ("0x5ffbde0", "0x5ffbde0", "0x5ffbe71"),
        ("0x5ff9fe0", "0x5ff9fe0", "0x5ffa674"),
        ("0x60bb890", "0x60bb890", "0x60bb932"),
        ("0x5ff0300", "0x5ff0300", "0x5ff03e3"),
        ("0x609e510", "0x609e510", "0x609f073"),
        ("0x6099ce0", "0x6099ce0", "0x6099e34"),
        ("0x5d350c0", "0x5d350c0", "0x5d35145"),
        ("0x61cf670", "0x61cf670", "0x61cf767"),
        ("0x5fefe90", "0x5fefe90", "0x5fefef9"),
        ("0x609e2d0", "0x609e2d0", "0x609e3e2"),
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
    assert vtable_len(data, secs, relocs, VT_CTR) == 27, (
        f"CTR vtable length {vtable_len(data, secs, relocs, VT_CTR)}")
    assert vtable_len(data, secs, relocs, VT_CTRL) == 6, (
        f"control-block vtable length {vtable_len(data, secs, relocs, VT_CTRL)}")
    # GOT slots.
    got = relocs.get(GOT_SINGLE_THREADED)
    assert got is not None and got[0] == 6 and got[2] == 0, (
        f"GOT __libc_single_threaded: got {got}")
    for slot, want in ((GOT_WRAPPER, WRAPPER),
                       (GOT_TWIN_WRAPPER, TWIN_WRAPPER)):
        got = relocs.get(slot)
        assert got is not None and got[0] == 8 and got[2] == want, (
            f"GOT slot {slot:#x}: got {got}")

    # ---- tables ----
    # callers.tsv: every lea/E8 site in the packet with its enclosing FDE.
    rows = [("target", "site", "kind", "enclosing_fde")]
    for addr in sorted(refs):
        for site in sorted(refs[addr]):
            s, e = enclosing(site)
            rows.append((f"{addr:#x}", f"{site:#x}", "lea", f"{s:#x}..{e:#x}"))
    for target in sorted(EXPECTED_E8):
        for site in sorted(EXPECTED_E8[target]):
            s, e = enclosing(site)
            rows.append((f"{target:#x}", f"{site:#x}", "e8", f"{s:#x}..{e:#x}"))
    for target, sites in (
            (RELEASE, EXPECTED_E8_RELEASE_IN_PACKET),
            (REGISTER_OPTIONS, EXPECTED_E8_REGISTER_OPTIONS_IN_PACKET),
            (CONFIGURE_HOST, EXPECTED_E8_CONFIGURE_HOST_IN_PACKET),
            (NULL_CONFIGURE, EXPECTED_E8_NULL_CONFIGURE_IN_PACKET),
            (STATUS_CTOR, EXPECTED_E8_STATUS_CTOR_IN_PACKET)):
        for site in sites:
            s, e = enclosing(site)
            rows.append((f"{target:#x}", f"{site:#x}", "e8", f"{s:#x}..{e:#x}"))
    (HERE / "callers.tsv").write_text(
        "\n".join("\t".join(r) for r in rows) + "\n")

    # maps.tsv
    rows = [("map", "key", "key_source", "insert_site", "atexit_site",
             "pack_record+0xa8", "flags_record+0xb0", "offset_record+0x00",
             "entries")]
    for m, (key, src, ins, atexit, pack, flags, off) in MAPS.items():
        rows.append((f"{m:#x}", key, src, f"{ins:#x}", f"{atexit:#x}",
                     f"{pack:#x}", f"{flags:#x}", f"{off:#x}", "1"))
    rows.append((f"{REGISTRY_MAP[0]:#x}", "(registry entries)",
                 f"init {REGISTRY_MAP[1]}", "", "",
                 "", "", "", "(see #4395)"))
    (HERE / "maps.tsv").write_text(
        "\n".join("\t".join(r) for r in rows) + "\n")

    # vtables.tsv: CTR vtable slots 0..26 and control-block vtable slots 0..5.
    rows = [("vtable", "slot", "target", "slot_name")]
    for slot in range(27):
        v = vtable_slot(data, secs, relocs, VT_CTR, slot)
        rows.append(("0x64cffb0", str(slot), f"{v:#x}",
                     SLOT_IDENTITIES.get(slot, "")))
    for slot in range(6):
        v = vtable_slot(data, secs, relocs, VT_CTRL, slot)
        rows.append(("0x64d0128", str(slot), f"{v:#x}",
                     "control-block slot" if v else "trailing zero"))
    (HERE / "vtables.tsv").write_text(
        "\n".join("\t".join(r) for r in rows) + "\n")

    # literals.tsv
    rows = [
        ("address", "bytes", "string"),
        ("0x4487d6", "ROT13", "dispatch name compared by strcmp"),
        ("0x968090", "Cannot add keys to CTREncryptionProvider (40 bytes)",
         "gate error message (kNotSupported)"),
        ("0x443890", "ROT13BlockCipherOptions",
         "group name registered by the ROT13 path"),
        ("0x43a5f7", "block_size", "block-map entry key (cited, #4389)"),
        ("0x433f9f", "Cannot reset object  (20 bytes)",
         "reset error message (kNotSupported)"),
        ("0x4487c0", "Cannot make a shared  (21 bytes)",
         "registry factory dispatch error (cited)"),
        ("0x43fa43", "BlockCipher",
         "registry factory dispatch error fragment (cited)"),
        ("0x432138", " from unguarded one  (20 bytes)",
         "registry factory dispatch error fragment (cited)"),
        ("0x439466", "Could not load  (15 bytes)",
         "registry factory dispatch error fragment (cited)"),
    ]
    (HERE / "literals.tsv").write_text(
        "\n".join("\t".join(r) for r in rows) + "\n")

    # Sanity: the literal strings really are in the binary.
    assert cstr(data, 0x4487D6) == b"ROT13"
    assert cstr(data, 0x968090) == b"Cannot add keys to CTREncryptionProvider"
    assert cstr(data, 0x443890) == b"ROT13BlockCipherOptions"
    assert cstr(data, 0x433F9F) == b"Cannot reset object "
    assert cstr(data, 0x4487C0) == b"Cannot make a shared "
    assert cstr(data, 0x43FA43) == b"BlockCipher"
    assert cstr(data, 0x432138) == b" from unguarded one "
    assert cstr(data, 0x439466) == b"Could not load "
    print("census OK")


if __name__ == "__main__":
    main()
