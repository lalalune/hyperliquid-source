#!/usr/bin/env python3
"""Census and tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-ttl-option-maps-115/census.py

Regenerates callers.tsv, literals.tsv, maps.tsv and frames.txt. The
static initializer 0x6206ef0 inserts exactly one entry into each of four
static OptionTypeInfo maps: 'user_operator' into 0x6509480, 'ttl' into
0x6509440, 'user_filter_factory' into 0x6509400 and 'user_filter' into
0x65093c0. A fifth map, 0x65094c0, is zeroed and atexit-registered by the
initializer but receives no insert there.

CORRECTION (slopbot review on PR #4498, re-verified against the binary):
the 'ttl' entry does NOT inherit the preceding block's pack/flags. The
other three blocks build their record at -0x110(%rbp) and load the pack
from a GOT slot; the ttl block builds its record directly at
-0x1d0(%rbp) and writes its OWN values into the record's +0xa8/+0xb0
slots: movq $0x2 at 0x62071a8 (-0x128 = -0x1d0+0xa8) and movl $0x0 at
0x62071b3 (-0x120 = -0x1d0+0xb0). Under the #4389-calibrated layout
(+0xa8 = pack, +0xb0 = flags) the ttl entry carries pack 0x2 (type 2,
verification 0) and flags 0x0 -- not 0x100000016/0x400. The ttl block
calls no record init (0x5e32b10) and loads no GOT pack.

Context (already pinned by merged work, NOT re-pinned here): the maps
are the option maps of the TTL family -- the filter/factory/merge-op
ctors and their RegisterOptions groups are pinned by merged PR #4065
(RE-001-register-ttl-objects-115), and the runtime methods and vtables
by merged PR #4087 (RE-001-ttl-runtime-methods-115). What neither
packet records is the maps' contents: the entry keys, packs, flags and
insert sites pinned here.
"""
import bisect
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

INITIALIZER = 0x6206EF0         # TTL option-map initializer (pinned)
INSERT_HELPER = 0x5D405B0       # map insert helper (cited, #4389)
RECORD_INIT = 0x5E32B10         # record builder (cited, #4389)
RECORD_FINALIZE = 0x5E332C0     # record finalizer (cited, #4389)
STR_CTOR = 0x62010F0           # std::string ctor from a C string (cited)
REGISTER_OPTIONS = 0x6099CE0   # Configurable::RegisterOptions (cited, #3257)

# Literals with a complete binary-wide lea census.
EXPECTED_LEA_FULL = {
    0x4322BE: [0x608A88C, 0x608DA05, 0x6207100],  # "ttl"
    0x4385BB: [0x620752A],                 # "user_filter"
    0x44FFE6: [0x62073C3],                 # "user_filter_factory"
    0x44C438: [0x6207057],                 # "user_operator"
    # Static OptionTypeInfo maps.
    0x6509440: [0x6202A87, 0x6205872, 0x6207245],  # "TTL" map
    0x65093C0: [0x6202AD8, 0x6207556],      # "UserFilter" map
    0x6509400: [0x6205814, 0x62073DC],      # "UserOptions" map
    0x6509480: [0x62055E7, 0x620707E],      # "TtlMergeOptions" map
    0x65094C0: [0x6206EF5],                # fifth map, zeroed only
}
# The pinned FDE (start, end) for the in-packet filter.
PINNED_FDES = [(0x6206EF0, 0x620769F)]
# Helpers called only from inside the pinned FDE are asserted per-site.
EXPECTED_E8_IN_PACKET = {
    INSERT_HELPER: [0x62070C2, 0x620726B, 0x620740B, 0x6207575],
}

# The four map entries inserted by the initializer 0x6206ef0.
# map: (key, key literal, insert site, atexit site, pack, flags)
MAPS = {
    0x6509480: ("user_operator", 0x44C438, 0x62070C2, 0x62070F4,
                0x100000016, 0x400),
    0x6509440: ("ttl", 0x4322BE, 0x620726B, 0x62072D4,
                0x2, 0x0),
    0x6509400: ("user_filter_factory", 0x44FFE6, 0x620740B, 0x620743B,
                0x300000016, 0x400),
    0x65093C0: ("user_filter", 0x4385BB, 0x6207575, 0x62075BE,
                0x100000016, 0x1200),
}

LITERALS = {
    0x4322BE: b"ttl",
    0x4385BB: b"user_filter",
    0x44FFE6: b"user_filter_factory",
    0x44C438: b"user_operator",
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


def read_va(data: bytes, secs, va: int, n: int) -> bytes:
    for addr, offset, size in secs:
        if addr <= va < addr + size:
            return data[offset + va - addr: offset + va - addr + n]
    raise ValueError(f"no section contains {va:#x}")


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


def cstr(data: bytes, va: int) -> bytes:
    # .rodata maps file offset == vaddr in this binary.
    return data[va:va + 200].split(b"\x00")[0]


def in_pinned_fdes(va: int) -> bool:
    return any(s <= va < e for s, e in PINNED_FDES)


def main() -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records

    import hashlib
    data = BIN.read_bytes()
    secs = sections(data)
    assert hashlib.sha256(data).hexdigest() == DIGEST

    refs = scan_lea_refs(data, list(EXPECTED_LEA_FULL))
    for addr, want in EXPECTED_LEA_FULL.items():
        assert sorted(refs[addr]) == sorted(want), (
            f"lea refs for {addr:#x}: got {[hex(x) for x in sorted(refs[addr])]}")

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
        ("0x6206ef0", "0x6206ef0", "0x620769f"),
        ("0x5d405b0", "0x5d405b0", "0x5d40f32"),
        ("0x5e32b10", "0x5e32b10", "0x5e32c65"),
        ("0x5e332c0", "0x5e332c0", "0x5e3354f"),
        ("0x62010f0", "0x62010f0", "0x62011d3"),
        ("0x5d3f820", "0x5d3f820", "0x5d3f94d"),
        ("0x6099ce0", "0x6099ce0", "0x6099e34"),
    ]
    for _, s, e in frame_rows[1:]:
        es, ee = enclosing(int(s, 16))
        assert (es, ee) == (int(s, 16), int(e, 16)), f"FDE mismatch for {s}"
    (HERE / "frames.txt").write_text(
        "\n".join("\t".join(r) for r in frame_rows) + "\n")

    # Record packs: the GOT qwords the initializer loads for the records.
    # 0x458f68 holds 0x100000016 (type 22, verification 1); 0x4594e8 holds
    # 0x300000016 (type 22, verification 3).
    for slot, want in ((0x458F68, 0x100000016), (0x4594E8, 0x300000016)):
        got = struct.unpack_from("<Q", data, slot)[0]
        assert got == want, f"pack GOT slot {slot:#x}: got {got:#x}"

    # The ttl block builds its record directly at -0x1d0(%rbp) and
    # writes its OWN pack/flags into the record's +0xa8/+0xb0 slots:
    # movq $0x2 at 0x62071a8 (-0x128 = -0x1d0+0xa8) and movl $0x0 at
    # 0x62071b3 (-0x120 = -0x1d0+0xb0). It loads no GOT pack and sets
    # no pack/flags in the other blocks' -0x110 record slots -- the
    # absence of those stores is NOT inheritance, it is a different
    # record buffer.
    ttl_block = read_va(data, secs, 0x62070F9, 0x620726B - 0x62070F9)
    assert b"\x48\x89\x45\x98" not in ttl_block, "ttl block sets pack"
    assert b"\xc7\x45\xa0" not in ttl_block, "ttl block sets flags"
    assert read_va(data, secs, 0x62071A8, 11) == bytes.fromhex(
        "48c785d8feffff02000000"), "ttl pack store"
    assert read_va(data, secs, 0x62071B3, 10) == bytes.fromhex(
        "c785e0feffff00000000"), "ttl flags store"

    # ---- tables ----
    rows = [("target", "site", "kind", "enclosing_fde")]
    for addr in sorted(EXPECTED_LEA_FULL):
        for site in sorted(refs[addr]):
            s, e = enclosing(site)
            rows.append((f"{addr:#x}", f"{site:#x}", "lea",
                         f"{s:#x}..{e:#x}"))
    for target, want in EXPECTED_E8_IN_PACKET.items():
        for site in sorted(want):
            s, e = enclosing(site)
            rows.append((f"{target:#x}", f"{site:#x}", "call",
                         f"{s:#x}..{e:#x}"))
    (HERE / "callers.tsv").write_text(
        "\n".join("\t".join(r) for r in rows) + "\n")

    lit_rows = ["address\tliteral\tnote"]
    notes = {
        0x4322BE: "initializer key, map 0x6509440",
        0x4385BB: "initializer key, map 0x65093c0",
        0x44FFE6: "initializer key, map 0x6509400",
        0x44C438: "initializer key, map 0x6509480",
    }
    for addr, text in LITERALS.items():
        assert cstr(data, addr) == text, f"literal {addr:#x}"
        lit_rows.append(f"{addr:#x}\t{text.decode()}\t{notes[addr]}")
    (HERE / "literals.tsv").write_text("\n".join(lit_rows) + "\n")

    map_rows = ["map\tkey\tkey_literal\tinsert_site\tatexit_site\t"
                "pack_record+0xa8\tflags_record+0xb0\tentries"]
    for addr, (key, lit, insert, atexit, pack, flags) in MAPS.items():
        s, _ = enclosing(insert)
        assert s == INITIALIZER, f"insert {insert:#x} not in the initializer"
        map_rows.append(
            f"{addr:#x}\t{key}\t{lit:#x}\t{insert:#x}\t{atexit:#x}\t"
            f"{pack:#x}\t{flags:#x}\t1")
    (HERE / "maps.tsv").write_text("\n".join(map_rows) + "\n")

    print("wrote callers.tsv, literals.tsv, maps.tsv, frames.txt")


if __name__ == "__main__":
    main()
