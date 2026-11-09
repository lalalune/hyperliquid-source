#!/usr/bin/env python3
"""Census and tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-rot13-factory-115/census.py

Regenerates callers.tsv, literals.tsv, maps.tsv, vtables.tsv and
frames.txt. The lea scans must reproduce the exact site sets found by hand:
the ROT13BlockCipher map 0x65052c0 is referenced by the three factory
functions, the two RegisterOptions sites in 0x5ff7120, the static
initializer 0x5ff7c90 and the small host 0x5ffabd0; the vtable 0x64cfea0
is stored by the same five object constructions.
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

MAP = 0x65052C0
VTABLE = 0x64CFEA0
FACTORY = 0x5FF7120

EXPECTED_LEA_MAP = [0x5FF6AE1, 0x5FF6E41, 0x5FF7261, 0x5FF7367, 0x5FF7F9E, 0x5FFACDE]
EXPECTED_LEA_VTABLE = [0x5FF6A6B, 0x5FF6E19, 0x5FF7209, 0x5FF7350, 0x5FFACC1]
EXPECTED_LEA_FACTORY = [0x5FF92B8]
EXPECTED_LEA_SIBLING_MAPS = {
    0x6505300: [0x5FF6763, 0x5FF7DDC],
    0x6505280: [0x5FF68FD, 0x5FF811A],
}

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

# ROT13 vtable 0x64cfea0, 22 slots, from .rela.dyn (R_X86_64_RELATIVE).
VTABLE_SLOTS = [
    (0, 0x5FF0130), (1, 0x5FF0250), (2, 0x609D760), (3, 0x609DC40),
    (4, 0x5D32560), (5, 0x6095E70), (6, 0x6096790), (7, 0x5D2E090),
    (8, 0x60956F0), (9, 0x609D0E0), (10, 0x60986B0), (11, 0x6095710),
    (12, 0x609DE80), (13, 0x609D980), (14, 0x5FEF990), (15, 0x5D32A30),
    (16, 0x5D2E770), (17, 0x5D2CA00), (18, 0x5D2CA10), (19, 0x5FEF9A0),
    (20, 0x5FEF9B0), (21, 0x5FEF9F0),
]
TYPEINFO = 0x64CF770
TYPEINFO_NAME = b"*N7rocksdb12_GLOBAL__N_116ROT13BlockCipherE"
BASE_VTABLE = 0x64D3430
BASE_TYPEINFO_NAME = b"N7rocksdb12ConfigurableE"


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
    targets = [MAP, VTABLE, FACTORY, *EXPECTED_LEA_SIBLING_MAPS]
    refs = scan_lea_refs(data, targets)
    assert sorted(refs[MAP]) == sorted(EXPECTED_LEA_MAP), (
        f"lea refs for map {MAP:#x}: got {[hex(x) for x in sorted(refs[MAP])]}")
    assert sorted(refs[VTABLE]) == sorted(EXPECTED_LEA_VTABLE), (
        f"lea refs for vtable {VTABLE:#x}: "
        f"got {[hex(x) for x in sorted(refs[VTABLE])]}")
    assert sorted(refs[FACTORY]) == sorted(EXPECTED_LEA_FACTORY), (
        f"lea refs for factory {FACTORY:#x}: "
        f"got {[hex(x) for x in sorted(refs[FACTORY])]}")
    for addr, want in EXPECTED_LEA_SIBLING_MAPS.items():
        assert sorted(refs[addr]) == sorted(want), (
            f"lea refs for sibling map {addr:#x}: "
            f"got {[hex(x) for x in sorted(refs[addr])]}")

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
        ("0x5ff7120", "0x5ff7120", "0x5ff7419"),
        ("0x5ff7c90", "0x5ff7c90", "0x5ff8256"),
        ("0x5d405b0", "0x5d405b0", "0x5d40f32"),
        ("0x5d3f820", "0x5d3f820", "0x5d3f94d"),
        ("0x61d1540", "0x61d1540", "0x61d178b"),
        ("0x5ff0130", "0x5ff0130", "0x5ff01b5"),
        ("0x5ff0250", "0x5ff0250", "0x5ff02db"),
        ("0x5fef990", "0x5fef990", "0x5fef99c"),
        ("0x5fef9a0", "0x5fef9a0", "0x5fef9a9"),
        ("0x5fef9b0", "0x5fef9b0", "0x5fef9e3"),
        ("0x5fef9f0", "0x5fef9f0", "0x5fefa23"),
        ("0x5ff0300", "0x5ff0300", "0x5ff03e3"),
        ("0x5e32b10", "0x5e32b10", "0x5e32c65"),
        ("0x5e332c0", "0x5e332c0", "0x5e3354f"),
        ("0x5ff88c0", "0x5ff88c0", "0x5ff9c50"),
        ("0x6099ce0", "0x6099ce0", "0x6099e34"),
    ]
    for _, s, e in frame_rows[1:]:
        es, ee = enclosing(int(s, 16))
        assert (es, ee) == (int(s, 16), int(e, 16)), f"FDE mismatch for {s}"
    (HERE / "frames.txt").write_text(
        "\n".join("\t".join(r) for r in frame_rows) + "\n")

    # Vtable slots + typeinfo from .rela.dyn.
    relocs = rela_dyn(data)
    for slot, want in VTABLE_SLOTS:
        got = relocs.get(VTABLE + slot * 8)
        assert got is not None and got[0] == 8 and got[2] == want, (
            f"vtable slot {slot}: got {got}, want {want:#x}")
    ti = relocs.get(VTABLE - 0x8)
    assert ti is not None and ti[2] == TYPEINFO, f"vtable typeinfo: {ti}"
    name = relocs.get(TYPEINFO + 0x8)
    assert name is not None and cstr(data, name[2]) == TYPEINFO_NAME, (
        f"typeinfo name: {name}")
    base_ti = relocs.get(BASE_VTABLE - 0x8)
    assert base_ti is not None
    base_name = relocs.get(base_ti[2] + 0x8)
    assert base_name is not None and cstr(data, base_name[2]) == BASE_TYPEINFO_NAME, (
        f"base typeinfo name: {base_name}")
    # ROT13's direct base class is rocksdb::BlockCipher.
    base_cls = relocs.get(TYPEINFO + 0x10)
    assert base_cls is not None
    base_cls_name = relocs.get(base_cls[2] + 0x8)
    assert base_cls_name is not None and cstr(data, base_cls_name[2]) == (
        b"N7rocksdb11BlockCipherE"), f"base class: {base_cls_name}"

    # GOT callback pairs the initializer loads per record.
    got_pairs = {
        0x64ED980: 0x5FEFAE0, 0x64ED9A8: 0x5FFBDE0,
        0x64ED988: 0x5FEFB10, 0x64ED9B0: 0x5FFAE10,
    }
    for slot, want in got_pairs.items():
        got = relocs.get(slot)
        assert got is not None and got[0] == 8 and got[2] == want, (
            f"GOT {slot:#x}: got {got}, want {want:#x}")

    # callers.tsv: every lea site with its enclosing function.
    rows = ["site\ttarget\tenclosing_fde\tnote"]
    notes = {
        0x5FF7261: "RegisterOptions site 1 (group ROT13BlockCipherOptions)",
        0x5FF7367: "RegisterOptions site 2 (group ROT13BlockCipherOptions)",
        0x5FF7F9E: "initializer insert into 0x65052c0 (key block_size)",
        0x5FF6AE1: "sibling factory 0x5ff6a00 RegisterOptions (same map)",
        0x5FF6E41: "sibling factory 0x5ff6d60 RegisterOptions (same map)",
        0x5FFACDE: "small host 0x5ffabd0 RegisterOptions (same map)",
        0x5FF7209: "factory stores vtable 0x64cfea0 (colon path)",
        0x5FF7350: "factory stores vtable 0x64cfea0 (no-colon path)",
        0x5FF6A6B: "sibling factory 0x5ff6a00 stores vtable 0x64cfea0",
        0x5FF6E19: "sibling factory 0x5ff6d60 stores vtable 0x64cfea0",
        0x5FFACC1: "small host 0x5ffabd0 stores vtable 0x64cfea0",
        0x5FF92B8: "registry builder 0x5ff88c0 takes factory address (name ROT13)",
    }
    for target in (MAP, VTABLE, FACTORY):
        for site in sorted(refs[target]):
            s, e = enclosing(site)
            rows.append(f"{site:#x}\t{target:#x}\t{s:#x}..{e:#x}\t"
                        f"{notes.get(site, '')}")
    (HERE / "callers.tsv").write_text("\n".join(rows) + "\n")

    lit_rows = [
        "address\tbytes\tmeaning",
        "0x453e50\tROT13BlockCipher\tgroup-name literal chunk 1 (16 bytes, movdqa)",
        "0x736e6f6974704f72\trOptions\tgroup-name literal chunk 2 (movabs, 8 bytes)",
        "0x443890\tROT13BlockCipherOptions\tgroup-name literal, no-colon path",
        "0x4487d6\tROT13\tName() slot 14 return + registry name",
        "0x4453a1\tprovider\tinitializer key, map 0x6505300",
        "0x43a5f7\tblock_size\tinitializer key, map 0x65052c0",
        "0x439496\tcipher\tinitializer key, map 0x6505280",
        "0x458f68\t0x100000016\trecord pack: type 22, verification 1",
        "0x43e542\tbasic_string::substr\tout_of_range message (defensive ':' check)",
        "0x958cf8\t%s: __pos (which is %zu) > this->size() (which is %zu)\t"
        "out_of_range format string",
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

    slot_notes = {
        0: "D2 destructor 0x5ff0130 (restores Configurable vtable, frees groups)",
        1: "D0 destructor 0x5ff0250 (D2 + operator delete)",
        2: "shared Configurable slot (0x609d760, cited)",
        3: "shared Configurable slot (0x609dc40, cited)",
        4: "shared Configurable slot (0x5d32560, cited)",
        5: "shared Configurable slot (0x6095e70, cited)",
        6: "shared Configurable slot (0x6096790, cited)",
        7: "shared Configurable slot (0x5d2e090, cited)",
        8: "empty-Status stub 0x60956f0 (pinned by #4320, cited)",
        9: "slot 9 0x609d0e0 (pinned by #4334, cited)",
        10: "slot-10 ConfigureOption core 0x60986b0 (pinned by #4328, cited)",
        11: "shared Configurable slot (0x6095710, cited)",
        12: "slot 12 0x609de80 (pinned by #4328, cited)",
        13: "GetOptionName 0x609d980 (pinned by #4328, cited)",
        14: "Name() returns literal 0x4487d6 (ROT13)",
        15: "GetId 0x5d32a30 (pinned by #4328, cited)",
        16: "base predicate 0x5d2e770 (pinned by #4349, cited)",
        17: "Inner 0x5d2ca00 (pinned by #4349, cited)",
        18: "NickName 0x5d2ca10 (pinned by #4349, cited)",
        19: "returns object+0x20 (the block size N)",
        20: "ROT13 transform 0x5fef9b0 (addb $0xd over object+0x20 bytes)",
        21: "ROT13 transform 0x5fef9f0 (same body as slot 20)",
    }
    vt_rows = ["slot\taddress\tnote"]
    for slot, addr in VTABLE_SLOTS:
        vt_rows.append(f"{slot}\t{addr:#x}\t{slot_notes[slot]}")
    (HERE / "vtables.tsv").write_text("\n".join(vt_rows) + "\n")

    print("wrote callers.tsv, literals.tsv, maps.tsv, vtables.tsv, frames.txt")


if __name__ == "__main__":
    main()
