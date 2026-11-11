#!/usr/bin/env python3
"""Census and tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-encrypted-fs-factory-115/census.py

Regenerates callers.tsv, literals.tsv, maps.tsv, vtables.tsv and
frames.txt. The lea scans must reproduce the exact site sets found by hand:
the provider map 0x6505300 is referenced only by the static initializer
0x5ff7c90 and the factory 0x5ff6690 pinned here; the target map 0x65051e0
only by the FileSystemWrapper ctor 0x5fe7210 and the static initializer
0x5feb760; the empty map 0x6505220 only by that same initializer. The
EncryptedFileSystemImpl vtable 0x64cfca0 is stored by the factory and its
two dtors only; the FileSystemWrapper vtable (lea base 0x64cf1f0, vptr
+0x10) by the wrapper ctor, the two dtors and 16 other wrapper ctors.
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

FACTORY = 0x5FF6690
WRAPPER_CTOR = 0x5FE7210
FS_CTOR = 0x5FE7080
GROUP_DTOR = 0x5FE70B0
DTOR = 0x5FF3000
DEL_DTOR = 0x5FF3050
REG_FACTORY = 0x5FE7A20
NAME_FN = 0x5FEF930
RECORD_CTOR = 0x5FE7EE0
STATIC_INIT = 0x5FEB760
BUILDER = 0x5FEBF50
MANAGER = 0x5FE5700
REGISTER_OPTIONS = 0x6099CE0
INSERT = 0x5D405B0
MAP_DTOR = 0x5D3F820
RELEASE = 0x5D350C0

MAP_PROVIDER = 0x6505300
MAP_TARGET = 0x65051E0
MAP_EMPTY = 0x6505220

VT_IMPL = 0x64CFCA0
VT_WRAPPER_BASE = 0x64CF1F0  # lea base; vptr is VT_WRAPPER = base + 0x10
VT_WRAPPER = 0x64CF200
VT_FS_BASE = 0x64CEFF8       # lea base; vptr is VT_FS = base + 0x10
VT_FS = 0x64CF008
VT_CONFIG_BASE = 0x64D3420   # lea base; vptr is VT_CONFIG = base + 0x10
VT_CONFIG = 0x64D3430

GOT_SINGLE_THREADED = 0x64ED290
GOT_CALLBACKS = (0x64ED8C8, 0x64ED960)  # -> 0x5fd5460 / 0x5fd7470

EXPECTED_LEA = {
    MAP_PROVIDER: [0x5FF6763, 0x5FF7DDC],
    MAP_TARGET: [0x5FE727B, 0x5FEB99D],
    MAP_EMPTY: [0x5FEB765],
    VT_IMPL: [0x5FF3004, 0x5FF3054, 0x5FF66D6],
    VT_FS_BASE: [0x5FE7084],
    REG_FACTORY: [0x5FEC0C6],
    FACTORY: [],
    WRAPPER_CTOR: [],
}
EXPECTED_LEA_WRAPPER_BASE = [
    0x5D55994, 0x5D559E4, 0x5D55A5E, 0x5D56278, 0x5E01C36, 0x5F74E1E,
    0x5FB17BD, 0x5FB187D, 0x5FE7237, 0x5FE72FD, 0x5FE73BD, 0x5FEEC45,
    0x5FEED25, 0x5FF3020, 0x5FF3070, 0x61EDB7D, 0x61EDC3D, 0x61F03BD,
    0x61F047D,
]
# The Configurable vtable is shared binary-wide; only assert the in-packet
# site and the subset #4395 asserted are present.
EXPECTED_LEA_CONFIG_SUBSET = [
    0x5FE70B4, 0x5FF30D7, 0x5FF6B79, 0x5FF6EC3, 0x5FF6FD0,
]

EXPECTED_E8 = {
    FACTORY: [0x5FE7A67],
    WRAPPER_CTOR: [0x5D561B3, 0x5E023E0, 0x5F75028, 0x5FB1F3D, 0x5FE7758,
                   0x5FF66D1, 0x60072B8, 0x61EDB28, 0x61F0398],
    FS_CTOR: [0x5FE7232, 0x5FFC351, 0x6002A9F, 0x6028A8A],
    DTOR: [],
    DEL_DTOR: [],
    REG_FACTORY: [],
    RECORD_CTOR: [0x5FEB7CA],
}
# E8 sites of the insert helper inside the static initializer.
EXPECTED_E8_INSERT_IN_INIT = [0x5FEB9CD]
# E8 sites of the shared_ptr release helper inside the pinned functions.
EXPECTED_E8_RELEASE_IN_PACKET = [
    0x5FF67FB, 0x5FF301B, 0x5FF3037, 0x5FF306B, 0x5FF3087,
]
# RegisterOptions sites: the ctor's and the factory's (37 binary-wide).
EXPECTED_E8_REGISTER_OPTIONS_IN_PACKET = [0x5FE7292, 0x5FF677E]

# Vtable typeinfos from .rela.dyn (R_X86_64_RELATIVE at vtable - 0x8).
TYPEINFOS = {
    VT_IMPL: (0x64CF758,
              b"*N7rocksdb12_GLOBAL__N_123EncryptedFileSystemImplE"),
    VT_WRAPPER: (0x64CED40, b"N7rocksdb17FileSystemWrapperE"),
    VT_FS: (0x64CED28, b"N7rocksdb10FileSystemE"),
    VT_CONFIG: (0x64D3410, b"N7rocksdb12ConfigurableE"),
}
# First two slots of each pinned vtable (slot 0 = complete dtor,
# slot 1 = deleting dtor), from .rela.dyn / raw vtable bytes.
VTABLE_SLOTS = {
    VT_IMPL: [(0, 0x5FF3000), (1, 0x5FF3050)],
    VT_WRAPPER: [(0, 0x0), (1, 0x0)],  # pure virtual in the abstract base
    VT_FS: [(0, 0x0), (1, 0x0)],       # pure virtual in the abstract base
    VT_CONFIG: [(0, 0x60957A0), (1, 0x6095830)],
}
# Slot identities pinned by this packet (slot -> (impl, wrapper, base)).
# A None entry means "pure virtual (0x0) in that vtable".
SLOT_IDENTITIES = {
    5: (0x5FE7D00, 0x5FE7D00, 0x6095E70),
    9: (0x609D0E0, 0x609D0E0, 0x609D0E0),    # ConfigureOptions entry (#4334)
    10: (0x60986B0, 0x60986B0, 0x60986B0),   # ConfigureOption core (#4328)
    12: (0x5FE6910, 0x5FE6910, 0x609DE80),   # slot-12 serializer (#4328)
    13: (0x609D980, 0x609D980, 0x609D980),   # GetOptionName (#4334)
    14: (0x5FEF930, 0x0, 0x0),              # Name() (#4328); impl returns
                                            # "EncryptedFileSystem"
    15: (0x5D32A30, 0x5D32A30, 0x5D32A30),   # GetId (#4328)
    16: (0x5FF0990, 0x5D2E770, 0x5D2E770),   # name-match predicate (#4349)
    17: (0x5FE55C0, 0x5FE55C0, 0x5D2CA00),   # Inner (#4349)
    18: (0x5D2CA10, 0x5D2CA10, 0x5D2CA10),   # NickName (#4349)
}

# The two maps the static initializers build (one entry each).
MAPS = {
    # map: (key, key source, insert site, atexit site, pack, flags, offset)
    0x6505300: ("provider", "literal 0x4453a1", 0x5FF7E23, 0x5FF7E5B,
                0x100000016, 0x400, 0),
    0x65051E0: ("target", "immediates 0x67726174 + 0x7465", 0x5FEB9CD,
                0x5FEBA18, 0x100000016, 0x2400, 0),
}
# Record pack (type 22, verification 1) shared by both maps; the target
# record's flags add 0x2000 via the record ctor's ecx argument.
PACK = 0x100000016

# Registry pairs in RegisterBuiltinFileSystems 0x5febf50.
REGISTRY = [
    # (name, name length, factory, manager)
    ("TimedFS", 7, 0x5FE74A0, 0x5FE56A0),
    ("ReadOnlyFilesystem", 18, 0x5FE7720, 0x5FE56D0),
    ("EncryptedFileSystem", 19, 0x5FE7A20, 0x5FE5700),
    ("CountedFileSystem", 17, 0x5FE75E0, 0x5FE5730),
    ("MemoryFileSystem", 16, 0x5FE58B0, 0x5FE5760),
]


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

    refs = scan_lea_refs(
        data, list(EXPECTED_LEA) + [VT_WRAPPER_BASE, VT_CONFIG_BASE])
    for addr, want in EXPECTED_LEA.items():
        assert sorted(refs[addr]) == sorted(want), (
            f"lea refs for {addr:#x}: got {[hex(x) for x in sorted(refs[addr])]}")
    assert sorted(refs[VT_WRAPPER_BASE]) == sorted(EXPECTED_LEA_WRAPPER_BASE), (
        "lea refs for wrapper vtable base 0x64cf1f0 mismatch")
    for site in EXPECTED_LEA_CONFIG_SUBSET:
        assert site in refs[VT_CONFIG_BASE], (
            f"Configurable vtable lea site {site:#x} missing")

    for target, want in EXPECTED_E8.items():
        got = scan_e8_callers(data, target)
        assert sorted(got) == sorted(want), (
            f"E8 callers of {target:#x}: got {[hex(x) for x in sorted(got)]}")
    got = scan_e8_callers(data, INSERT)
    for site in EXPECTED_E8_INSERT_IN_INIT:
        assert site in got, f"insert call site {site:#x} missing"
    got = scan_e8_callers(data, RELEASE)
    for site in EXPECTED_E8_RELEASE_IN_PACKET:
        assert site in got, f"release call site {site:#x} missing"
    got = scan_e8_callers(data, REGISTER_OPTIONS)
    assert len(got) == 37, f"RegisterOptions sites: {len(got)} != 37"
    for site in EXPECTED_E8_REGISTER_OPTIONS_IN_PACKET:
        assert site in got, f"RegisterOptions site {site:#x} missing"

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
        ("0x5ff6690", "0x5ff6690", "0x5ff682e"),
        ("0x5fe7210", "0x5fe7210", "0x5fe72e8"),
        ("0x5fe7080", "0x5fe7080", "0x5fe70ab"),
        ("0x5fe70b0", "0x5fe70b0", "0x5fe7135"),
        ("0x5ff3000", "0x5ff3000", "0x5ff3045"),
        ("0x5ff3050", "0x5ff3050", "0x5ff30a2"),
        ("0x5fe7a20", "0x5fe7a20", "0x5fe7cfc"),
        ("0x5fef930", "0x5fef930", "0x5fef93c"),
        ("0x5fe7ee0", "0x5fe7ee0", "0x5fe808a"),
        ("0x5feb760", "0x5feb760", "0x5feba2e"),
        ("0x5febf50", "0x5febf50", "0x5fec408"),
        ("0x5fe5700", "0x5fe5700", "0x5fe572d"),
        ("0x6099ce0", "0x6099ce0", "0x6099e34"),
        ("0x5d350c0", "0x5d350c0", "0x5d35145"),
        ("0x5d405b0", "0x5d405b0", "0x5d40f32"),
        ("0x5d3f820", "0x5d3f820", "0x5d3f94d"),
        ("0x61cfed0", "0x61cfed0", "0x61d04c0"),
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
    # Slot identities: the three FileSystem vtables share most slots.
    for slot, (impl, wrapper, base) in SLOT_IDENTITIES.items():
        assert vtable_slot(data, secs, relocs, VT_IMPL, slot) == impl, (
            f"impl slot {slot}")
        assert vtable_slot(data, secs, relocs, VT_WRAPPER, slot) == wrapper, (
            f"wrapper slot {slot}")
        assert vtable_slot(data, secs, relocs, VT_FS, slot) == base, (
            f"base slot {slot}")
    # Extents: 62 function slots for each FileSystem vtable, 14 for
    # Configurable. vtable_len counts a trailing 0x0 slot where present
    # (impl: 63, Configurable: 15); wrapper/base abut the next vtable's
    # typeinfo slot, so they count exactly 62.
    assert vtable_len(data, secs, relocs, VT_IMPL) == 63, (
        f"impl vtable length {vtable_len(data, secs, relocs, VT_IMPL)}")
    for vt in (VT_WRAPPER, VT_FS):
        assert vtable_len(data, secs, relocs, vt) == 62, (
            f"vtable {vt:#x} length {vtable_len(data, secs, relocs, vt)}")
    assert vtable_len(data, secs, relocs, VT_CONFIG) == 15, (
        f"Configurable vtable length {vtable_len(data, secs, relocs, VT_CONFIG)}")
    # GOT slots.
    got = relocs.get(GOT_SINGLE_THREADED)
    assert got is not None and got[0] == 6 and got[2] == 0, (
        f"GOT __libc_single_threaded: got {got}")
    for slot, want in zip(GOT_CALLBACKS, (0x5FD5460, 0x5FD7470)):
        got = relocs.get(slot)
        assert got is not None and got[0] == 8 and got[2] == want, (
            f"GOT callback slot {slot:#x}: got {got}")

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
    for site in EXPECTED_E8_RELEASE_IN_PACKET + EXPECTED_E8_REGISTER_OPTIONS_IN_PACKET:
        s, e = enclosing(site)
        rows.append((f"{RELEASE if site in EXPECTED_E8_RELEASE_IN_PACKET else REGISTER_OPTIONS:#x}",
                     f"{site:#x}", "e8", f"{s:#x}..{e:#x}"))
    (HERE / "callers.tsv").write_text(
        "\n".join("\t".join(r) for r in rows) + "\n")

    # maps.tsv
    rows = [("map", "key", "key_source", "insert_site", "atexit_site",
             "pack_record+0xa8", "flags_record+0xb0", "offset_record+0x00",
             "entries")]
    for m, (key, src, ins, atexit, pack, flags, off) in MAPS.items():
        rows.append((f"{m:#x}", key, src, f"{ins:#x}", f"{atexit:#x}",
                     f"{pack:#x}", f"{flags:#x}", f"{off:#x}", "1"))
    (HERE / "maps.tsv").write_text(
        "\n".join("\t".join(r) for r in rows) + "\n")

    # vtables.tsv: all 62 slots of the three FileSystem vtables + the
    # 14 slots of the Configurable vtable.
    slot_names = {
        0: "complete dtor", 1: "deleting dtor",
        9: "ConfigureOptions entry", 10: "ConfigureOption core",
        12: "slot-12 serializer", 13: "GetOptionName",
        14: "Name()", 15: "GetId", 16: "name-match predicate",
        17: "Inner", 18: "NickName()",
    }
    rows = [("vtable", "slot", "impl", "wrapper", "base", "slot_name")]
    for slot in range(62):
        iv = vtable_slot(data, secs, relocs, VT_IMPL, slot)
        wv = vtable_slot(data, secs, relocs, VT_WRAPPER, slot)
        bv = vtable_slot(data, secs, relocs, VT_FS, slot)
        rows.append(("0x64cfca0", str(slot), f"{iv:#x}", f"{wv:#x}",
                     f"{bv:#x}", slot_names.get(slot, "")))
    rows.append(("vtable", "slot", "configurable", "", "", "slot_name"))
    for slot in range(14):
        cv = vtable_slot(data, secs, relocs, VT_CONFIG, slot)
        rows.append(("0x64d3430", str(slot), f"{cv:#x}", "",
                     "", slot_names.get(slot, "")))
    (HERE / "vtables.tsv").write_text(
        "\n".join("\t".join(r) for r in rows) + "\n")

    # literals.tsv
    rows = [
        ("address", "bytes", "string"),
        ("0x4539b0", "EncryptionProvid (16 bytes, movdqa)",
         "first 16 chars of the group name"),
        ("0x4539b0+0x10", "immediate 0x7265 ('er')",
         "last 2 chars: group name is 'EncryptionProvider' (18)"),
        ("0x4453a1", "provider", "provider-map entry key"),
        ("0x44470e", "EncryptedFileSystem", "Name() return (slot 14)"),
        ("0x4552d0", "EncryptedFileSys (16 bytes, movdqa)",
         "registry name part 1"),
        ("0x4552d0+0x10", "immediate 0x6d657473 ('stem')",
         "registry name part 2: 'EncryptedFileSystem' (19)"),
        ("0x4552c0", "ReadOnlyFileSyst (16 bytes, movdqa)",
         "sibling registry name part 1"),
        ("0x4552c0+0x10", "immediate 0x6d65 ('em')",
         "sibling registry name part 2: 'ReadOnlyFilesystem' (18)"),
        ("0x4510e0", "CountedFileSyste (16 bytes, movdqa)",
         "sibling registry name part 1"),
        ("0x4510e0+0x10", "immediate 0x6d ('m')",
         "sibling registry name part 2: 'CountedFileSystem' (17)"),
        ("0x4565b0", "MemoryFileSystem", "sibling registry name (16)"),
        ("immediates", "0x656d6954 + 0x53466465",
         "sibling registry name 'TimedFS' (7)"),
        ("immediates", "0x67726174 + 0x7465",
         "target-map entry key 'target' (6)"),
        ("0x439496", "cipher", "cipher-map entry key (cited, #4395)"),
        ("0x43a5f7", "block_size", "block-map entry key (cited, #4389)"),
    ]
    (HERE / "literals.tsv").write_text(
        "\n".join("\t".join(r) for r in rows) + "\n")

    # Sanity: the literal strings really are in the binary.
    assert cstr(data, 0x4539B0).startswith(b"EncryptionProvid")
    assert cstr(data, 0x4453A1) == b"provider"
    assert cstr(data, 0x44470E) == b"EncryptedFileSystem"
    assert cstr(data, 0x4552D0).startswith(b"EncryptedFileSys")
    assert cstr(data, 0x4552C0).startswith(b"ReadOnlyFileSyst")
    assert cstr(data, 0x4510E0).startswith(b"CountedFileSyste")
    assert cstr(data, 0x4565B0).startswith(b"MemoryFileSystem")
    print("census OK")


if __name__ == "__main__":
    main()
