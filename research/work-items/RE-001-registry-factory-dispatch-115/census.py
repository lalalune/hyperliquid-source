#!/usr/bin/env python3
"""Census and tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-registry-factory-dispatch-115/census.py

Regenerates callers.tsv, literals.tsv, frames.txt and vtables.tsv.
The lea scans must reproduce the exact site sets found by hand: the
BlockCipher dispatch 0x5ff9fe0 has exactly one E8 caller (the dispatcher
0x5ffa710 at 0x5ffa962) and the EncryptionProvider twin dispatch 0x5ffb250
exactly one (the twin dispatcher 0x5ffba10 at 0x5ffbc62) -- the twins are
NOT the same dispatch, which corrects #4402's "byte-identical" note. The
lookup 0x5ff9c60 has exactly two E8 callers (its own recursion at
0x5ff9e1c and the dispatch at 0x5ffa023); the twin lookup 0x5ffaeb0 two
(0x5ffb08c, 0x5ffb294). The managers 0x5fefa50/0x5fefa80/0x5fefab0 have no
E8 callers: they are reached only through the record's manager pointer.
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

DISPATCH = 0x5FF9FE0         # registry factory dispatch (BlockCipher)
LOOKUP = 0x5FF9C60           # name lookup (BlockCipher)
TWIN_DISPATCH = 0x5FFB250    # registry factory dispatch (EncryptionProvider)
TWIN_LOOKUP = 0x5FFAEB0      # name lookup (EncryptionProvider)
DISPATCHER = 0x5FFA710        # sole caller of DISPATCH (#4402)
TWIN_DISPATCHER = 0x5FFBA10  # sole caller of TWIN_DISPATCH (#4402)
MAP_FIND = 0x5FD2980          # map lookup helper (cited, not pinned)
STATUS_CTOR = 0x61CF670       # Status ctor (code, subcode, msg1, msg2)
MOVE_ASSIGN = 0x5FEFE90       # Status move-assign
RELEASE = 0x5D350C0           # shared_ptr control-block release
STR_CTOR = 0x5FF0300          # std::string ctor from a C string
CONFIG_INIT = 0x60BB890       # ConfigOptions default init (cited, #4402)
REGISTRY_BUILDER = 0x61F9400  # builds the fresh registry (cited)
REGISTRY_GETTER = 0x61F92B0   # default-registry getter (PR #4015)
MANAGER_CTR = 0x5FEFA50       # std::function manager, CTR creator
MANAGER_TEST = 0x5FEFA80      # std::function manager, 1://test creator
MANAGER_ROT13 = 0x5FEFAB0     # std::function manager, ROT13 creator
REGISTRY_BUILDER_LAMBDA = 0x5FF88C0  # RegisterEncryptionBuiltins host
THUNK = 0x5FF9C50             # pthread_once tail-call thunk

CTRL_VTABLE = 0x64D0198       # _Sp_counted_ptr<BlockCipher*> vtable
COUNTS_QWORD = 0x459B20       # (use, weak) == (1, 1)

# Literals with a complete binary-wide lea census.
EXPECTED_LEA_FULL = {
    0x4487C0: [0x5FD424C, 0x5FFA1BC, 0x5FFB4BC, 0x6136D24],
    0x43FA43: [0x5FF978A, 0x5FFA1FA, 0x5FFA334, 0x5FFA43C],
    0x439466: [0x5FD2F85, 0x5FD3034, 0x5FD436B, 0x5FD443C, 0x5FFA31B,
               0x5FFA3EC, 0x5FFB62B, 0x5FFB6F4, 0x6136E7B, 0x6136F6C],
    0x43E76F: [0x5FF8FB1, 0x5FFB4FA, 0x5FFB644, 0x5FFB744],
}
# Literals used binary-wide; only the sites inside the pinned FDEs are
# asserted here (the rest belong to other dispatches).
EXPECTED_LEA_IN_PACKET = {
    0x432138: [0x5FFA247, 0x5FFB547],
    0x4474D2: [0x5FFA4F9, 0x5FFA518, 0x5FFA537,
               0x5FFB808, 0x5FFB827, 0x5FFB846],
}
# The pinned FDEs (start, end) for the in-packet filter.
PINNED_FDES = [(0x5FF9C60, 0x5FF9FD7), (0x5FF9FE0, 0x5FFA674),
               (0x5FFAEB0, 0x5FFB247), (0x5FFB250, 0x5FFB981)]

EXPECTED_E8 = {
    DISPATCH: [0x5FFA962],
    TWIN_DISPATCH: [0x5FFBC62],
    LOOKUP: [0x5FF9E1C, 0x5FFA023],
    TWIN_LOOKUP: [0x5FFB08C, 0x5FFB294],
    MAP_FIND: [0x5FD2B97, 0x5FD3DD7, 0x5FF9D37, 0x5FFAFA6, 0x61E84E2,
               0x61E868B, 0x61E8B8D, 0x61E8D5D, 0x61E8F2D, 0x61EA495,
               0x61EA656, 0x61EAB5B, 0x61EAD3B, 0x61EAF1B],
}
# Shared helpers: only the sites inside the pinned FDEs are asserted.
EXPECTED_E8_IN_PACKET = {
    STATUS_CTOR: [0x5FFA29D, 0x5FFA389, 0x5FFA3D9, 0x5FFA4A1,
                  0x5FFB59B, 0x5FFB697, 0x5FFB6DF, 0x5FFB7A1],
    RELEASE: [0x5FFA14B, 0x5FFB3A2, 0x5FFB406],
    MOVE_ASSIGN: [0x5FFA2DC, 0x5FFB5F4],
    STR_CTOR: [0x5FFA1D4, 0x5FFA32A, 0x5FFA411,
               0x5FFB4D4, 0x5FFB63A, 0x5FFB719],
}

# The BlockCipher control-block vtable: slots and typeinfo.
VTABLE_SLOTS = {
    CTRL_VTABLE: [(0, 0x5FEFB50), (1, 0x5FEFCE0), (2, 0x5FEFC20),
                  (3, 0x5FEFCF0), (4, 0x5FEFC40)],
}
TYPEINFOS = {
    CTRL_VTABLE: (0x64CF850,
                  b"St15_Sp_counted_ptrIPN7rocksdb11BlockCipherE"
                  b"LN9__gnu_cxx12_Lock_policyE2EE"),
}
# The std::function manager typeinfo addresses (op 0 stores them).
MANAGER_TYPEINFOS = {
    MANAGER_CTR: 0x64CF7B8,
    MANAGER_TEST: 0x64CF7C8,
    MANAGER_ROT13: 0x64CF7D8,
}

LITERALS = {
    0x4487C0: b"Cannot make a shared ",
    0x43FA43: b"BlockCipher",
    0x432138: b" from unguarded one ",
    0x439466: b"Could not load ",
    0x43E76F: b"EncryptionProvider",
    0x4474D2: b"basic_string::append",
    0x4539B0: b"EncryptionProvid",  # first 16 bytes, movdqa-loaded
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
        ("0x5ff9c60", "0x5ff9c60", "0x5ff9fd7"),
        ("0x5ff9fe0", "0x5ff9fe0", "0x5ffa674"),
        ("0x5ffaeb0", "0x5ffaeb0", "0x5ffb247"),
        ("0x5ffb250", "0x5ffb250", "0x5ffb981"),
        ("0x5fefa50", "0x5fefa50", "0x5fefa7d"),
        ("0x5fd2980", "0x5fd2980", "0x5fd2ab7"),
        ("0x61cf670", "0x61cf670", "0x61cf767"),
        ("0x5ff88c0", "0x5ff88c0", "0x5ff9c50"),
        ("0x5ff9c50", "0x5ff9c50", "0x5ff9c59"),
        ("0x5ffa710", "0x5ffa710", "0x5ffaad9"),
        ("0x5ffba10", "0x5ffba10", "0x5ffbdd9"),
        ("0x60bb890", "0x60bb890", "0x60bb932"),
        ("0x61f9400", "0x61f9400", "0x61f963e"),
        ("0x5d350c0", "0x5d350c0", "0x5d35145"),
        ("0x5fefe90", "0x5fefe90", "0x5fefef9"),
        ("0x5ff0300", "0x5ff0300", "0x5ff03e3"),
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
    assert vtable_len(data, secs, relocs, CTRL_VTABLE) == 6, (
        f"control-block vtable length "
        f"{vtable_len(data, secs, relocs, CTRL_VTABLE)}")
    # The counts qword (use, weak) == (1, 1) at 0x459b20.
    assert read_va(data, secs, COUNTS_QWORD, 8) == struct.pack(
        "<Q", 0x100000001), "counts qword mismatch"

    # ---- tables ----
    # callers.tsv: lea sites for the full-census literals (all of them),
    # in-packet lea sites for the shared literals, and the E8 sites above,
    # each with its enclosing FDE.
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
        if addr == 0x4539B0:
            note = "movdqa-loaded 16-byte chunk + 'er' (0x7265) in 0x5ffaeb0"
        if addr == 0x43FA43:
            note = "built by movabs in 0x5ff9c60; lea sites are the dispatch"
        lit_rows.append((f"{addr:#x}", text.decode(), str(len(text)), note))
    (HERE / "literals.tsv").write_text(
        "\n".join("\t".join(r) for r in lit_rows) + "\n")

    vt_rows = [("vtable", "slot", "target", "role")]
    for vtable, slots in VTABLE_SLOTS.items():
        for slot, target in slots:
            vt_rows.append((f"{vtable:#x}", str(slot), f"{target:#x}",
                            "control-block method"))
    vt_rows.append((f"{CTRL_VTABLE:#x}", "typeinfo",
                    f"{TYPEINFOS[CTRL_VTABLE][0]:#x}",
                    TYPEINFOS[CTRL_VTABLE][1].decode()))
    (HERE / "vtables.tsv").write_text(
        "\n".join("\t".join(r) for r in vt_rows) + "\n")

    print(f"census OK: {len(rows) - 1} caller rows, "
          f"{len(lit_rows) - 1} literals, {len(vt_rows) - 1} vtable rows")


if __name__ == "__main__":
    main()
