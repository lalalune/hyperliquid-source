#!/usr/bin/env python3
"""Census and tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-ctr-rot13-provider-115/census.py

Regenerates callers.tsv, literals.tsv, maps.tsv, vtables.tsv and
frames.txt. The lea scans must reproduce the exact site sets found by hand:
the ROT13BlockCipher map 0x65052c0 is referenced by the two factories
pinned here, the two RegisterOptions sites in #4389's factory, the static
initializer 0x5ff7c90 and the small host 0x5ffabd0; the Cipher map
0x6505280 only by the holder 0x5ff6880 and the initializer; the provider
map 0x6505300 only by the initializer and the unpinned host 0x5ff6690.
The in-place control-block vtable 0x64d0160 is stored by exactly the two
factories; the CTR vtable (lea base 0x64cffa0, vptr +0x10) by the holder,
the destructor and the two factories' destroy dances.
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

MAP_BLOCK = 0x65052C0
MAP_CIPHER = 0x6505280
MAP_PROVIDER = 0x6505300
VT_INPLACE = 0x64D0160
VT_CTR = 0x64CFFB0          # vptr; the lea base in code is 0x64cffa0
VT_CTR_BASE = 0x64CFFA0
VT_CONFIG = 0x64D3430       # vptr; the lea base in code is 0x64d3420
VT_CONFIG_BASE = 0x64D3420
VT_ROT13 = 0x64CFEA0
FACTORY_TEST = 0x5FF6A00
FACTORY_CTR = 0x5FF6D60
HOLDER = 0x5FF6880

EXPECTED_LEA = {
    MAP_BLOCK: [0x5FF6AE1, 0x5FF6E41, 0x5FF7261, 0x5FF7367, 0x5FF7F9E, 0x5FFACDE],
    MAP_CIPHER: [0x5FF68FD, 0x5FF811A],
    MAP_PROVIDER: [0x5FF6763, 0x5FF7DDC],
    VT_INPLACE: [0x5FF6A61, 0x5FF6E0F],
    VT_CTR_BASE: [0x5FF2F04, 0x5FF30B4, 0x5FF31DA, 0x5FF689F,
                 0x5FF6B5B, 0x5FF6EA5, 0x5FF6FB2, 0x5FFB3ED],
    VT_ROT13: [0x5FF6A6B, 0x5FF6E19, 0x5FF7209, 0x5FF7350, 0x5FFACC1],
    FACTORY_TEST: [0x5FF90F6],
    FACTORY_CTR: [0x5FF8AA0],
}
# The Configurable vtable is shared binary-wide; only assert the four
# in-packet sites are present.
EXPECTED_LEA_CONFIG_SUBSET = [0x5FF30D7, 0x5FF6B79, 0x5FF6EC3, 0x5FF6FD0]

# E8 callers of the holder init 0x5ff6880 (all inside the two factories).
EXPECTED_E8_HOLDER = [0x5FF6B30, 0x5FF6E7A, 0x5FF6F8B]
# E8 callers of the release helper inside the excerpted functions.
EXPECTED_E8_RELEASE_IN_PACKET = [0x5FF6B74, 0x5FF6BF7, 0x5FF6EBE,
                                 0x5FF6F3F, 0x5FF6FCB, 0x5FF30D2]

# The three maps the initializer 0x5ff7c90 builds, each with one entry.
MAPS = {
    # map: (key, key literal, insert site, atexit site)
    0x6505300: ("provider", 0x4453A1, 0x5FF7E23, 0x5FF7E5B),
    0x65052C0: ("block_size", 0x43A5F7, 0x5FF7FC4, 0x5FF8016),
    0x6505280: ("cipher", 0x439496, 0x5FF814C, 0x5FF8199),
}
# Record pack (type 22, verification 1) and flags, shared by all three.
PACK = 0x100000016
FLAGS = 0x400

# Vtable typeinfos from .rela.dyn (R_X86_64_RELATIVE).
TYPEINFOS = {
    VT_INPLACE: (0x64CF838,
                 b"*St23_Sp_counted_ptr_inplaceIN7rocksdb12_GLOBAL__N_1"
                 b"16ROT13BlockCipherESaIvELN9__gnu_cxx12_Lock_policyE2EE"),
    VT_CTR: (0x64CF740, b"N7rocksdb21CTREncryptionProviderE"),
    VT_CONFIG: (0x64D3410, b"N7rocksdb12ConfigurableE"),
}
# First two slots of each pinned vtable (slot 0 = complete dtor, slot 1 =
# deleting dtor), from .rela.dyn.
VTABLE_SLOTS = {
    VT_INPLACE: [(0, 0x5FEFC50), (1, 0x5FEFD30)],
    VT_CTR: [(0, 0x5FF2F00), (1, 0x5FF30B0)],
    VT_CONFIG: [(0, 0x60957A0), (1, 0x6095830)],
}
# GOT slot 0x64ed998 holds the CTR deleting destructor 0x5ff30b0.
GOT_DTOR = (0x64ED998, 0x5FF30B0)
# GOT slot 0x64ed290 is __libc_single_threaded (R_X86_64_GLOB_DAT).
GOT_SINGLE_THREADED = 0x64ED290


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


def main() -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records

    data = BIN.read_bytes()
    refs = scan_lea_refs(data, list(EXPECTED_LEA) + [VT_CONFIG_BASE])
    for addr, want in EXPECTED_LEA.items():
        assert sorted(refs[addr]) == sorted(want), (
            f"lea refs for {addr:#x}: got {[hex(x) for x in sorted(refs[addr])]}")
    for site in EXPECTED_LEA_CONFIG_SUBSET:
        assert site in refs[VT_CONFIG_BASE], (
            f"Configurable vtable lea site {site:#x} missing")

    e8_holder = scan_e8_callers(data, HOLDER)
    assert sorted(e8_holder) == sorted(EXPECTED_E8_HOLDER), (
        f"E8 callers of holder: got {[hex(x) for x in sorted(e8_holder)]}")
    for target in (FACTORY_TEST, FACTORY_CTR, 0x5FF30B0):
        assert scan_e8_callers(data, target) == [], (
            f"unexpected E8 caller of {target:#x}")
    e8_release = scan_e8_callers(data, 0x5D350C0)
    for site in EXPECTED_E8_RELEASE_IN_PACKET:
        assert site in e8_release, f"release call site {site:#x} missing"

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
        ("0x5ff6a00", "0x5ff6a00", "0x5ff6c70"),
        ("0x5ff6880", "0x5ff6880", "0x5ff6978"),
        ("0x5ff30b0", "0x5ff30b0", "0x5ff3153"),
        ("0x5ff6d60", "0x5ff6d60", "0x5ff70a7"),
        ("0x5d350c0", "0x5d350c0", "0x5d35145"),
        ("0x5ff88c0", "0x5ff88c0", "0x5ff9c50"),
        ("0x6099ce0", "0x6099ce0", "0x6099e34"),
        ("0x5ff0300", "0x5ff0300", "0x5ff03e3"),
        ("0x61d1390", "0x61d1390", "0x61d13db"),
        ("0x5ff7120", "0x5ff7120", "0x5ff7419"),
        ("0x5ff7c90", "0x5ff7c90", "0x5ff8256"),
        ("0x5ffabd0", "0x5ffabd0", "0x5ffae04"),
    ]
    for _, s, e in frame_rows[1:]:
        es, ee = enclosing(int(s, 16))
        assert (es, ee) == (int(s, 16), int(e, 16)), f"FDE mismatch for {s}"
    (HERE / "frames.txt").write_text(
        "\n".join("\t".join(r) for r in frame_rows) + "\n")

    # Vtable slots + typeinfos from .rela.dyn.
    relocs = rela_dyn(data)
    for vtable, slots in VTABLE_SLOTS.items():
        for slot, want in slots:
            got = relocs.get(vtable + slot * 8)
            assert got is not None and got[0] == 8 and got[2] == want, (
                f"vtable {vtable:#x} slot {slot}: got {got}, want {want:#x}")
    for vtable, (typeinfo, name) in TYPEINFOS.items():
        ti = relocs.get(vtable - 0x8)
        assert ti is not None and ti[2] == typeinfo, (
            f"vtable {vtable:#x} typeinfo: {ti}")
        got_name = relocs.get(typeinfo + 0x8)
        assert got_name is not None and cstr(data, got_name[2]) == name, (
            f"typeinfo name for {vtable:#x}: {got_name}")
    # ROT13 vtable typeinfo (pinned by #4389; re-checked here).
    ti = relocs.get(VT_ROT13 - 0x8)
    assert ti is not None and ti[2] == 0x64CF770, f"ROT13 typeinfo: {ti}"
    name = relocs.get(0x64CF770 + 0x8)
    assert name is not None and cstr(data, name[2]) == (
        b"*N7rocksdb12_GLOBAL__N_116ROT13BlockCipherE"), f"ROT13 name: {name}"
    # GOT slot for the CTR deleting destructor.
    got = relocs.get(GOT_DTOR[0])
    assert got is not None and got[0] == 8 and got[2] == GOT_DTOR[1], (
        f"GOT dtor slot: got {got}")
    got = relocs.get(GOT_SINGLE_THREADED)
    assert got is not None and got[0] == 6 and got[2] == 0, (
        f"GOT __libc_single_threaded: got {got}")

    # callers.tsv: every lea site with its enclosing function.
    rows = ["site\ttarget\tenclosing_fde\tnote"]
    notes = {
        0x5FF6AE1: "factory 0x5ff6a00 RegisterOptions (group ROT13BlockCipherOptions)",
        0x5FF6E41: "factory 0x5ff6d60 RegisterOptions (group ROT13BlockCipherOptions)",
        0x5FF7261: "factory 0x5ff7120 RegisterOptions, colon path (#4389)",
        0x5FF7367: "factory 0x5ff7120 RegisterOptions, no-colon path (#4389)",
        0x5FF7F9E: "initializer insert into 0x65052c0 (key block_size)",
        0x5FFACDE: "small host 0x5ffabd0 RegisterOptions (same map)",
        0x5FF68FD: "holder 0x5ff6880 RegisterOptions (group Cipher)",
        0x5FF811A: "initializer insert into 0x6505280 (key cipher)",
        0x5FF6763: "unpinned host 0x5ff6690 references the provider map",
        0x5FF7DDC: "initializer insert into 0x6505300 (key provider)",
        0x5FF6A61: "factory 0x5ff6a00 stores in-place vtable 0x64d0160",
        0x5FF6E0F: "factory 0x5ff6d60 stores in-place vtable 0x64d0160",
        0x5FF6A6B: "factory 0x5ff6a00 stores ROT13 vtable 0x64cfea0",
        0x5FF6E19: "factory 0x5ff6d60 stores ROT13 vtable 0x64cfea0",
        0x5FF7209: "factory 0x5ff7120 stores ROT13 vtable, colon path (#4389)",
        0x5FF7350: "factory 0x5ff7120 stores ROT13 vtable, no-colon path (#4389)",
        0x5FFACC1: "small host 0x5ffabd0 stores ROT13 vtable 0x64cfea0",
        0x5FF90F6: "registry builder 0x5ff88c0 takes factory address (name 1://test)",
        0x5FF8AA0: "registry builder 0x5ff88c0 takes factory address (name CTR)",
    }
    for target in (MAP_BLOCK, MAP_CIPHER, MAP_PROVIDER, VT_INPLACE,
                   VT_CTR_BASE, VT_ROT13, FACTORY_TEST, FACTORY_CTR):
        for site in sorted(refs[target]):
            s, e = enclosing(site)
            rows.append(f"{site:#x}\t{target:#x}\t{s:#x}..{e:#x}\t"
                        f"{notes.get(site, '')}")
    (HERE / "callers.tsv").write_text("\n".join(rows) + "\n")

    lit_rows = [
        "address\tbytes\tmeaning",
        "0x453e50\tROT13BlockCipher\tgroup-name literal chunk 1 (16 bytes, movdqa)",
        "0x736e6f6974704f72\trOptions\tgroup-name literal chunk 2 (movabs, 8 bytes)",
        "0x443890\tROT13BlockCipherOptions\tgroup-name literal, 0x5ff6d60 path",
        "0x4429ae\t1://test\tregistry name of factory 0x5ff6a00",
        "0x447699\tCTR\tregistry name of factory 0x5ff6d60",
        "0x4487d6\tROT13\tregistry name of factory 0x5ff7120 (#4389)",
        "0x439496\tcipher\tinitializer key, map 0x6505280",
        "0x43a5f7\tblock_size\tinitializer key, map 0x65052c0",
        "0x4453a1\tprovider\tinitializer key, map 0x6505300",
        "0x459b20\t(1, 1)\tuse_count 1, weak_count 1 (two int32s)",
        "0x458f68\t0x100000016\trecord pack: type 22, verification 1",
        "0x68706943\tCiph\t'Cipher' group-name chunk 1 (movl)",
        "0x7265\ter\t'Cipher' group-name chunk 2 (mov, 2 bytes)",
        "0x742f2f3a\t://t\t'://test' suffix chunk 1 (movl)",
        "0x74736574\ttest\t'://test' suffix chunk 2 (movl)",
        "0x968090\tCannot add keys to CTREncryptionProvider\t"
        "kNotSupported message in small host 0x5ffabd0 (cited)",
    ]
    (HERE / "literals.tsv").write_text("\n".join(lit_rows) + "\n")

    map_rows = ["map\tkey\tkey_literal\tinsert_site\tatexit_site\t"
                "pack_record+0xa8\tflags_record+0xb0\tentries"]
    for addr, (key, lit, insert, atexit) in MAPS.items():
        s, _ = enclosing(insert)
        assert s == 0x5FF7C90, f"insert {insert:#x} not in the initializer"
        map_rows.append(
            f"{addr:#x}\t{key}\t{lit:#x}\t{insert:#x}\t{atexit:#x}\t"
            f"{PACK:#x}\t{FLAGS:#x}\t1")
    (HERE / "maps.tsv").write_text("\n".join(map_rows) + "\n")

    vt_rows = [
        "vtable\ttypeinfo\ttypeinfo_name\tnote",
        "0x64d0160\t0x64cf838\t"
        "*St23_Sp_counted_ptr_inplaceIN7rocksdb12_GLOBAL__N_116ROT13BlockCipherESaIvELN9__gnu_cxx12_Lock_policyE2EE\t"
        "in-place shared_ptr control block; slot 0 0x5fefc50, slot 1 0x5fefd30",
        "0x64cffb0\t0x64cf740\tN7rocksdb21CTREncryptionProviderE\t"
        "CTR provider (lea base 0x64cffa0 + 0x10); slot 0 0x5ff2f00, slot 1 0x5ff30b0 (deleting dtor)",
        "0x64d3430\t0x64d3410\tN7rocksdb12ConfigurableE\t"
        "Configurable base (lea base 0x64d3420 + 0x10); slot 0 0x60957a0, slot 1 0x6095830",
        "0x64cfea0\t0x64cf770\t*N7rocksdb12_GLOBAL__N_116ROT13BlockCipherE\t"
        "ROT13 cipher, pinned by #4389; cited only",
    ]
    (HERE / "vtables.tsv").write_text("\n".join(vt_rows) + "\n")

    print("wrote callers.tsv, literals.tsv, maps.tsv, vtables.tsv, frames.txt")


if __name__ == "__main__":
    main()
