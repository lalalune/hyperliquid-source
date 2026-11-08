#!/usr/bin/env python3
"""Census and tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-composite-env-maps-115/census.py

Regenerates maps.tsv (the three .bss OptionTypeInfo maps and their single
entries), literals.tsv, frames.txt and the lea-reference census for the
three map addresses. The lea scan must reproduce the exact site sets
found by hand: each map is referenced only by the CompositeEnvWrapper
ctor 0x5fd7360 (RegisterOptions call, pinned by merged #3950) and by the
static initializer 0x5fe0760 (insert + __cxa_atexit registration).
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

MAPS = {
    # map address: (group base in the wrapper, key, key literal, insert site)
    0x6504C60: ("object+0x48 (Env*)", "target", 0x44A390, 0x5FE0B4A),
    0x6504C20: ("object+0x28 (FileSystem shared_ptr)", "file_system", 0x44B349, 0x5FE0D4B),
    0x6504BE0: ("object+0x38 (SystemClock shared_ptr)", "clock", 0x4496D9, 0x5FE0ED1),
}

# RIP-relative lea sites expected per map (host ctor + initializer).
EXPECTED_LEA = {
    0x6504C60: [0x5FD73B9, 0x5FE0B34, 0x5FE0BE4],
    0x6504C20: [0x5FD73E7, 0x5FE0D36, 0x5FE0D75],
    0x6504BE0: [0x5FD740D, 0x5FE0E9B],
}

# Record packs / flags at record+0xa0 / record+0xa8 (stack-built records).
PACKS = {
    0x6504C60: (0x10000001A, 0x2000),  # type 26, verification 1
    0x6504C20: (0x100000016, 0x400),   # type 22, verification 1
    0x6504BE0: (0x100000016, 0x400),   # type 22, verification 1
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


def main() -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records

    data = BIN.read_bytes()
    refs = scan_lea_refs(data, MAPS)
    for addr, want in EXPECTED_LEA.items():
        got = sorted(refs[addr])
        assert got == sorted(want), (
            f"lea refs for {addr:#x}: got {[hex(x) for x in got]}, "
            f"want {[hex(x) for x in want]}")

    _, frames = eh_frame_records(data)
    fdes = sorted((f["start"], f["end"]) for f in frames)
    starts = [s for s, _ in fdes]

    def enclosing(addr: int) -> tuple[int, int]:
        i = bisect.bisect_right(starts, addr) - 1
        s, e = fdes[i]
        assert s <= addr < e, f"no FDE encloses {addr:#x}"
        return s, e

    # frames.txt: the functions this packet pins + cited ones.
    frame_rows = [
        ("function", "fde_start", "fde_end"),
        ("0x5fe0760", "0x5fe0760", "0x5fe0fbc"),
        ("0x5d405b0", "0x5d405b0", "0x5d40f32"),
        ("0x5d3f820", "0x5d3f820", "0x5d3f94d"),
        ("0x5fd5ff0", "0x5fd5ff0", "0x5fd60a7"),
        ("0x5fd7360", "0x5fd7360", "0x5fd7466"),
        ("0x6099ce0", "0x6099ce0", "0x6099e34"),
    ]
    for _, s, e in frame_rows[1:]:
        es, ee = enclosing(int(s, 16))
        assert (es, ee) == (int(s, 16), int(e, 16)), f"FDE mismatch for {s}"
    (HERE / "frames.txt").write_text(
        "\n".join("\t".join(r) for r in frame_rows) + "\n")

    atexit = {0x6504C60: 0x5FE0BEE, 0x6504C20: 0x5FE0D7F, 0x6504BE0: 0x5FE0F1A}
    rows = ["map\tgroup_base\tkey\tkey_literal\tinsert_site\t"
            "atexit_site\tpack_record+0xa0\tflags_record+0xa8\tentries"]
    for addr, (base, key, lit, insert) in MAPS.items():
        pack, flags = PACKS[addr]
        s, _ = enclosing(insert)
        assert s == 0x5FE0760, f"insert {insert:#x} not in the initializer"
        rows.append(
            f"{addr:#x}\t{base}\t{key}\t{lit:#x}\t{insert:#x}\t"
            f"{atexit[addr]:#x}\t{pack:#x}\t{flags:#x}\t1")
    (HERE / "maps.tsv").write_text("\n".join(rows) + "\n")

    lit_rows = [
        "address\tbytes\tmeaning",
        "0x44a390\ttarget\t\"target\" map key, 6 bytes + NUL (insert 0x5fe0b4a)",
        "0x44b349\tfile_system\t\"file_system\" map key, 11 bytes + NUL (insert 0x5fe0d4b)",
        "0x4496d9\tclock\t\"clock\" map key, 5 bytes + NUL (insert 0x5fe0ed1)",
        "0x458f68\t0x100000016\tfile_system/clock record pack (type 22, verification 1)",
        "0x4593c0\t0x10000001a\ttarget record pack (type 26, verification 1)",
    ]
    (HERE / "literals.tsv").write_text("\n".join(lit_rows) + "\n")
    print("wrote maps.tsv, literals.tsv, frames.txt "
          f"({sum(len(v) for v in refs.values())} lea refs checked)")


if __name__ == "__main__":
    main()
