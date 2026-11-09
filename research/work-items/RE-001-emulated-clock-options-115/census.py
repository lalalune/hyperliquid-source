#!/usr/bin/env python3
"""Census and tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-emulated-clock-options-115/census.py

Regenerates callers.tsv, literals.tsv, maps.tsv and frames.txt.

What this packet pins (all new ground -- see README.md for the
duplicate audit): the CONTENTS of the two option maps the
EmulatedSystemClock ctor registers -- "time_elapse_only_sleep" in
0x6505960 and "mock_sleep" in 0x6505920 -- as populated by the static
initializer 0x6029d10 (reached at load time via the .init_array jump
stub 0x602e4c0), plus the four accessor functions the records bind
(getters 0x6025e50 / 0x6026100, setters 0x6026ba0 / 0x6026ad0), the
bool parser 0x61d1480 they share, and the two vtable methods whose
behavior the flags drive: SleepForMicroseconds 0x6025b40 (slot 23)
and GetCurrentTime 0x6025eb0 (slot 24).

The initializer also inserts a third entry, "supports_direct_io"
into 0x65058e0, whose group belongs to another host (0x6028a60,
RegisterOptions site 0x6028b3a); that entry is recorded here as a
lead, not claimed as this packet's option.
"""
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

INITIALIZER = 0x6029D10        # static option-map initializer (pinned)
INIT_STUB = 0x602E4C0          # .init_array jump stub -> INITIALIZER
INIT_STUB_JMP = 0x602E4C4      # the E9 opcode inside the stub
INSERT_HELPER = 0x5D405B0      # map insert helper (cited, #4389/#4498)
RECORD_INIT = 0x5E32920        # OptionTypeInfo record builder (cited)
RECORD_OP = 0x5D400F0          # record transform before insert (cited)
KEY_BUILDER = 0x60261F0        # key-string builder (cited)
BOOL_PARSE = 0x61D1480         # bool-from-string parser (pinned)
EMULATED_VTABLE = 0x64D1650    # EmulatedSystemClock vtable (cited, #3948)

# The two pinned map entries: (map, key, key literal, insert site,
# key-lea site, getter, setter, getter-manager, setter-manager).
ENTRIES = [
    (0x6505960, "time_elapse_only_sleep", 0x4476C8, 0x6029E6B, 0x6029D11,
     0x6025E50, 0x6026BA0, 0x6025850, 0x6025820),
    (0x6505920, "mock_sleep", 0x4331D7, 0x6029FFF, 0x6029F0B,
     0x6026100, 0x6026AD0, 0x60258B0, 0x6025880),
]
# Third insert in the same initializer: lead, not claimed here.
THIRD_ENTRY = (0x65058E0, "supports_direct_io", 0x44657E, 0x602A19A,
               0x602A093)

# Binary-wide lea censuses (exact).
EXPECTED_LEA_FULL = {
    0x4476C8: [0x6029D11],     # "time_elapse_only_sleep"
    0x4331D7: [0x6029F0B],     # "mock_sleep"
    0x44657E: [0x602A093],     # "supports_direct_io"
    0x6505960: [0x602942B, 0x6029E50],
    0x6505920: [0x6029471, 0x6029FE0],
    0x65058E0: [0x6028B16, 0x602A17B],
}
# "true"/"false" are shared literals; only the in-packet sites are
# asserted here (the full binary-wide lists are long).
EXPECTED_LEA_IN_PACKET = {
    0x430E89: [0x6025E5B, 0x602610B],   # "false"
    0x43F883: [0x6025E72, 0x6026126],   # "true"
}
# No direct E8 callers anywhere: reached only through the vtable /
# the record function objects.
EXPECTED_E8_NONE = [
    0x6025E50, 0x6026100, 0x6026BA0, 0x6026AD0,
    0x6025820, 0x6025850, 0x6025880, 0x60258B0,
    0x6025B40, 0x6025EB0, INITIALIZER,
]
EXPECTED_E8_CALLERS = {
    BOOL_PARSE: [0x6026B14, 0x6026BE4, 0x6082F3F, 0x60830BB,
                 0x608315A, 0x60BF3BD],
}
EXPECTED_E8_IN_PACKET = {
    RECORD_INIT: [0x6029DFB, 0x6029FB4],
    INSERT_HELPER: [0x6029E6B, 0x6029FFF, 0x602A19A],
    KEY_BUILDER: [0x6029D59, 0x6029F15, 0x602A09D],
}
# EmulatedSystemClock vtable slots (vendor census names, RE-002):
# slot 19 NowMicros 0x60259e0, slot 20 NowNanos 0x60259a0,
# slot 23 SleepForMicroseconds 0x6025b40, slot 24 GetCurrentTime 0x6025eb0.
EXPECTED_VTABLE_SLOTS = {
    19: 0x60259E0, 20: 0x60259A0, 23: 0x6025B40, 24: 0x6025EB0,
}
# Lambda-manager typeinfo names (read via .rela.dyn).
MANAGER_TYPEINFOS = {
    0x6025820: (0x64D1300,
                b"*N7rocksdb12_GLOBAL__N_1L21time_elapse_type_infoMUlRKNS_"
                b"13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_"
                b"traitsIcESaIcEEESC_PvE_E"),
    0x6025850: (0x64D1310,
                b"*N7rocksdb12_GLOBAL__N_1L21time_elapse_type_infoMUlRKNS_"
                b"13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_"
                b"traitsIcESaIcEEEPKvPSA_E_E"),
    0x6025880: (0x64D1320,
                b"*N7rocksdb12_GLOBAL__N_1L20mock_sleep_type_infoMUlRKNS_"
                b"13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_"
                b"traitsIcESaIcEEESC_PvE_E"),
    0x60258B0: (0x64D1330,
                b"*N7rocksdb12_GLOBAL__N_1L20mock_sleep_type_infoMUlRKNS_"
                b"13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_"
                b"traitsIcESaIcEEEPKvPSA_E_E"),
}

PINNED_FDES = [
    (0x6029D10, 0x602A25D),   # initializer
    (0x602E4C0, 0x602E4C9),   # .init_array jump stub
    (0x6025E50, 0x6025EA5),   # time_elapse_only_sleep getter
    (0x6026100, 0x6026155),   # mock_sleep getter
    (0x6026BA0, 0x6026C4B),   # time_elapse_only_sleep setter
    (0x6026AD0, 0x6026B77),   # mock_sleep setter
    (0x6025820, 0x602584D),   # time_elapse setter manager
    (0x6025850, 0x602587D),   # time_elapse getter manager
    (0x6025880, 0x60258AD),   # mock_sleep setter manager
    (0x60258B0, 0x60258DD),   # mock_sleep getter manager
    (0x6025B40, 0x6025B7F),   # SleepForMicroseconds (slot 23)
    (0x6025EB0, 0x6025FEB),   # GetCurrentTime (slot 24)
    (0x61D1480, 0x61D1504),   # bool parser
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


def scan_e9_jumps(data: bytes, target: int) -> list[int]:
    """All E9 rel32 jump sites targeting `target`."""
    seg = data[TEXT_OFF:]
    out = []
    for m in re.finditer(rb"\xe9", seg):
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


def typeinfo_name(data: bytes, secs, relocs, ti: int) -> bytes:
    rel = relocs.get(ti + 8)
    nameptr = (rel[2] if (rel is not None and rel[0] == 8)
               else struct.unpack_from("<Q", read_va(data, secs, ti + 8, 8))[0])
    return data[nameptr:nameptr + 300].split(b"\x00")[0]


def main() -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records

    data = BIN.read_bytes()
    secs = sections(data)
    relocs = rela_dyn(data)

    # 1. lea censuses.
    leas = scan_lea_refs(data, list(EXPECTED_LEA_FULL)
                         + list(EXPECTED_LEA_IN_PACKET))
    for tgt, want in EXPECTED_LEA_FULL.items():
        assert leas[tgt] == want, f"lea {tgt:#x}: {leas[tgt]} != {want}"
    for tgt, want in EXPECTED_LEA_IN_PACKET.items():
        assert all(s in leas[tgt] for s in want), (
            f"lea {tgt:#x}: in-packet sites {want} missing from {leas[tgt]}")

    # 2. E8 censuses.
    for tgt in EXPECTED_E8_NONE:
        got = scan_e8_callers(data, tgt)
        assert got == [], f"E8 callers of {tgt:#x}: {got}"
    for tgt, want in EXPECTED_E8_CALLERS.items():
        got = scan_e8_callers(data, tgt)
        assert got == want, f"E8 callers of {tgt:#x}: {got} != {want}"
    for tgt, want in EXPECTED_E8_IN_PACKET.items():
        got = scan_e8_callers(data, tgt)
        assert all(s in got for s in want), (
            f"E8 {tgt:#x}: in-packet sites {want} missing from {got}")

    # 3. E9 jump stub -> initializer.
    jumps = scan_e9_jumps(data, INITIALIZER)
    assert jumps == [INIT_STUB_JMP], f"E9 jumps to initializer: {jumps}"
    # The stub is installed in .init_array (RELATIVE reloc addend).
    init_rela = [a for (o, (_, _, a)) in
                 ((k, v) for k, v in relocs.items())
                 if 0x63F36C8 <= o < 0x63F36C8 + 0x540]
    assert INIT_STUB in init_rela, ".init_array lacks the init stub"

    # 4. Emulated vtable slots 19/20/23/24.
    for slot, want in EXPECTED_VTABLE_SLOTS.items():
        got = vtable_slot(data, secs, relocs, EMULATED_VTABLE, slot)
        assert got == want, f"vtable slot {slot}: {got:#x} != {want:#x}"

    # 5. Manager typeinfo names.
    for mgr, (ti, want_name) in MANAGER_TYPEINFOS.items():
        got = typeinfo_name(data, secs, relocs, ti)
        assert got == want_name, f"manager {mgr:#x} typeinfo: {got}"

    # 6. FDEs.
    _, frames = eh_frame_records(data)
    fdes = {(f["start"], f["end"]) for f in frames}
    for s, e in PINNED_FDES:
        assert (s, e) in fdes, f"FDE {s:#x}..{e:#x} not found"

    # Regenerate tables.
    import bisect as _bisect
    fde_list = sorted((f["start"], f["end"]) for f in frames)
    fde_starts = [s for s, _ in fde_list]

    def enclosing(addr):
        i = _bisect.bisect_right(fde_starts, addr) - 1
        return fde_list[i]

    callers = ["site\ttarget\tenclosing_fde\tnote"]
    for tgt, want in EXPECTED_E8_IN_PACKET.items():
        for site in sorted(scan_e8_callers(data, tgt)):
            s, e = enclosing(site)
            note = ("in initializer 0x6029d10" if site in want
                    else "elsewhere (cited only)")
            callers.append(f"{site:#x}\t{tgt:#x}\t{s:#x}..{e:#x}\t{note}")
    for tgt in EXPECTED_E8_NONE:
        callers.append(f"-\t{tgt:#x}\t-\tno direct E8 callers binary-wide")
    (HERE / "callers.tsv").write_text("\n".join(callers) + "\n")

    literals = ["address\tbytes\tmeaning"]
    for (m, key, lit, _ins, _lea, _g, _s, _gm, _sm) in ENTRIES:
        literals.append(f"{lit:#x}\t{key}\toption key for map {m:#x}")
    literals.append(f"{THIRD_ENTRY[2]:#x}\t{THIRD_ENTRY[1]}\t"
                    f"option key for map {THIRD_ENTRY[0]:#x} (lead)")
    literals.append("0x430e89\tfalse\tbool getter literal (shared)")
    literals.append("0x43f883\ttrue\tbool getter literal (shared)")
    (HERE / "literals.tsv").write_text("\n".join(literals) + "\n")

    maps = ["map\tkey\tkey_literal\tinsert_site\tkey_lea_site\t"
            "getter\tsetter\tgetter_manager\tsetter_manager"]
    for (m, key, lit, ins, lea, g, s, gm, sm) in ENTRIES:
        maps.append(f"{m:#x}\t{key}\t{lit:#x}\t{ins:#x}\t{lea:#x}\t"
                    f"{g:#x}\t{s:#x}\t{gm:#x}\t{sm:#x}")
    maps.append(f"{THIRD_ENTRY[0]:#x}\t{THIRD_ENTRY[1]}\t"
                f"{THIRD_ENTRY[2]:#x}\t{THIRD_ENTRY[3]:#x}\t"
                f"{THIRD_ENTRY[4]:#x}\t-\t-\t-\t-")
    (HERE / "maps.tsv").write_text("\n".join(maps) + "\n")

    frames_out = ["function\tfde_start\tfde_end"]
    names = {
        0x6029D10: "static option-map initializer",
        0x602E4C0: ".init_array jump stub",
        0x6025E50: "time_elapse_only_sleep getter",
        0x6026100: "mock_sleep getter",
        0x6026BA0: "time_elapse_only_sleep setter",
        0x6026AD0: "mock_sleep setter",
        0x6025820: "time_elapse setter manager",
        0x6025850: "time_elapse getter manager",
        0x6025880: "mock_sleep setter manager",
        0x60258B0: "mock_sleep getter manager",
        0x6025B40: "SleepForMicroseconds (slot 23)",
        0x6025EB0: "GetCurrentTime (slot 24)",
        0x61D1480: "bool parser",
    }
    for s, e in PINNED_FDES:
        frames_out.append(f"{names[s]}\t{s:#x}\t{e:#x}")
    (HERE / "frames.txt").write_text("\n".join(frames_out) + "\n")
    print("wrote callers.tsv, literals.tsv, maps.tsv, frames.txt")


if __name__ == "__main__":
    main()
