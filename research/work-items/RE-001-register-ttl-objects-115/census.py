"""Census for the RE-001-register-ttl-objects-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-register-ttl-objects-115/census.py

Scans the .text bytes once for direct calls (E8), tail jumps (E9),
rip-relative lea and movabs references to every pinned routine,
reads the R_X86_64_RELATIVE records for the vtable/typeinfo sites,
and the FDE ranges from a frame dump.  Writes callers.tsv,
relocations.txt and frames.txt next to this script.  Deterministic:
verify.py re-runs it and diffs the outputs.
"""

import bisect
import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

# Pinned routines: (addr, label).
ROUTINES = [
    (0x6205D20, "trigger-create-column-family"),
    (0x6202DA0, "once-wrapper"),
    (0x62069F0, "register-fn"),
    (0x6201000, "register-manager"),
    (0x6200A30, "register-invoker"),
    (0x6208290, "creator"),
    (0x62080A4, "creator-cold"),
    (0x62009A0, "mgr-mo"),
    (0x62009D0, "mgr-cff"),
    (0x6200A00, "mgr-cf"),
    (0x62056B0, "invoke-mo"),
    (0x620566B, "invoke-mo-cold"),
    (0x6205C60, "invoke-cff"),
    (0x6202CA0, "invoke-cf"),
    (0x6202C60, "invoke-cf-cold"),
    (0x6205560, "ctor-mo"),
    (0x6205790, "ctor-cff"),
    (0x620573E, "ctor-cff-cold"),
    (0x6202A10, "ctor-cf"),
    (0x6202976, "ctor-cf-cold"),
    (0x6201040, "string-build"),
    (0x62010F0, "string-assign"),
    (0x61F06F0, "fe-mo-d2"),
    (0x61F0990, "fe-mo-d0"),
    (0x61F0770, "fe-mo-matches"),
    (0x61F0780, "fe-mo-accessor"),
    (0x6200A60, "fe-cff-d2"),
    (0x6201240, "fe-cff-d0"),
    (0x6200B10, "fe-cff-matches"),
    (0x6200B20, "fe-cff-accessor"),
    (0x61E7CF0, "fe-cf-d2"),
    (0x61E7E00, "fe-cf-d0"),
    (0x61E7D70, "fe-cf-matches"),
    (0x61E7D80, "fe-cf-accessor"),
    # Cited from earlier packets (not re-excerpted here).
    (0x61F92B0, "reg-getter"),
    (0x5FD1DA0, "find-or-insert"),
    (0x5FD17C0, "vec-insert"),
    (0x5FF8260, "register-helper"),
    (0x5FF7960, "vec-insert-libraries"),
    (0x5FF2030, "pattern-d2"),
    (0x5FF2150, "pattern-d0"),
    (0x61F8670, "pattern-matches"),
    (0x61F8120, "pattern-accessor"),
    (0x61F8700, "count"),
    (0x5D350C0, "shared-ptr-release"),
    (0x6099CE0, "register-options"),
    (0x5FF7900, "libcb-dispose"),
]

# Vtable / typeinfo sites whose RELATIVE records are pinned.
RELOC_SITES = [
    (0x64D8EC0, "PatternEntry vtable header offset_to_top"),
    (0x64D8EC8, "PatternEntry vtable header typeinfo"),
    (0x64D8ED0, "PatternEntry vtable slot 0 D2"),
    (0x64D8ED8, "PatternEntry vtable slot 1 D0"),
    (0x64D8EE0, "PatternEntry vtable slot 2 Matches"),
    (0x64D8EE8, "PatternEntry vtable slot 3 accessor"),
    (0x64D8690, "FactoryEntry-MergeOperator vtable header offset_to_top"),
    (0x64D8698, "FactoryEntry-MergeOperator vtable header typeinfo"),
    (0x64D86A0, "FactoryEntry-MergeOperator vtable slot 0 D2"),
    (0x64D86A8, "FactoryEntry-MergeOperator vtable slot 1 D0"),
    (0x64D86B0, "FactoryEntry-MergeOperator vtable slot 2 Matches"),
    (0x64D86B8, "FactoryEntry-MergeOperator vtable slot 3 accessor"),
    (0x64D9D28, "FactoryEntry-CompactionFilterFactory vtable header offset_to_top"),
    (0x64D9D30, "FactoryEntry-CompactionFilterFactory vtable header typeinfo"),
    (0x64D9D38, "FactoryEntry-CompactionFilterFactory vtable slot 0 D2"),
    (0x64D9D40, "FactoryEntry-CompactionFilterFactory vtable slot 1 D0"),
    (0x64D9D48, "FactoryEntry-CompactionFilterFactory vtable slot 2 Matches"),
    (0x64D9D50, "FactoryEntry-CompactionFilterFactory vtable slot 3 accessor"),
    (0x64D7D90, "FactoryEntry-CompactionFilter vtable header offset_to_top"),
    (0x64D7D98, "FactoryEntry-CompactionFilter vtable header typeinfo"),
    (0x64D7DA0, "FactoryEntry-CompactionFilter vtable slot 0 D2"),
    (0x64D7DA8, "FactoryEntry-CompactionFilter vtable slot 1 D0"),
    (0x64D7DB0, "FactoryEntry-CompactionFilter vtable slot 2 Matches"),
    (0x64D7DB8, "FactoryEntry-CompactionFilter vtable slot 3 accessor"),
    (0x64D00E0, "LibCB-ObjectLibrary vtable header offset_to_top"),
    (0x64D00E8, "LibCB-ObjectLibrary vtable header typeinfo"),
    (0x64D00F0, "LibCB-ObjectLibrary vtable slot 0 D2"),
    (0x64D00F8, "LibCB-ObjectLibrary vtable slot 1 D0"),
    (0x64D0100, "LibCB-ObjectLibrary vtable slot 2 _M_dispose"),
    (0x64D0108, "LibCB-ObjectLibrary vtable slot 3 _M_destroy"),
    (0x64D0110, "LibCB-ObjectLibrary vtable slot 4 _M_get_deleter"),
    (0x64D9548, "TtlMergeOperator vtable header offset_to_top"),
    (0x64D9550, "TtlMergeOperator vtable header typeinfo"),
    (0x64D9708, "TtlCompactionFilterFactory vtable header offset_to_top"),
    (0x64D9710, "TtlCompactionFilterFactory vtable header typeinfo"),
    (0x64D9620, "TtlCompactionFilter vtable header offset_to_top"),
    (0x64D9628, "TtlCompactionFilter vtable header typeinfo"),
    (0x64EE088, "register std::function invoker GOT slot"),
    (0x64EE090, "register std::function manager GOT slot"),
    (0x64D9350 + 8, "manager MergeOperator typeinfo name pointer"),
    (0x64D9360 + 8, "manager CompactionFilterFactory typeinfo name pointer"),
    (0x64D9370 + 8, "manager CompactionFilter typeinfo name pointer"),
    (0x64D85E0 + 8, "FactoryEntry-MergeOperator typeinfo name pointer"),
    (0x64D9338 + 8, "FactoryEntry-CompactionFilterFactory typeinfo name pointer"),
    (0x64D7D50 + 8, "FactoryEntry-CompactionFilter typeinfo name pointer"),
    (0x64D8E90 + 8, "PatternEntry typeinfo name pointer"),
    (0x64CF808 + 8, "LibCB-ObjectLibrary typeinfo name pointer"),
]

TEXT_OFF = 0x1418300
TEXT_VA = 0x1419300
TEXT_SZ = 0x4FD7700


def read_fdes():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    fdes = []
    for m in re.finditer(
            r"FDE cie=\S+ pc=000000000([0-9a-f]+)\.\.000000000([0-9a-f]+)",
            out):
        fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def enclosing(fdes, starts, addr):
    i = bisect.bisect_right(starts, addr) - 1
    if i >= 0 and fdes[i][0] <= addr < fdes[i][1]:
        return "0x%x..0x%x" % fdes[i]
    return "-"


def read_relocations():
    out = subprocess.run(
        ["readelf", "-r", "-W", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    rel = {}
    for line in out.splitlines():
        m = re.match(
            r"\s*([0-9a-f]+)\s+([0-9a-f]+)\s+(R_X86_64_RELATIVE)\s+([0-9a-f]+)",
            line)
        if m:
            rel[int(m.group(1), 16)] = int(m.group(4), 16)
    return rel


def main():
    data = BINARY.read_bytes()
    seg = data[TEXT_OFF:TEXT_OFF + TEXT_SZ]
    targets = {addr: label for addr, label in ROUTINES}
    fdes = read_fdes()
    starts = [a for a, _ in fdes]
    rel = read_relocations()

    rows = []
    # Direct calls and tail jumps: single opcode byte + rel32.
    for opcode, kind in ((0xE8, "call"), (0xE9, "jmp")):
        for m in re.finditer(re.escape(bytes([opcode])), seg):
            i = m.start()
            if i + 5 > len(seg):
                continue
            dest = TEXT_VA + i + 5 + struct.unpack("<i", seg[i + 1:i + 5])[0]
            if dest in targets:
                rows.append((dest, kind, TEXT_VA + i,
                             enclosing(fdes, starts, TEXT_VA + i)))
    # Rip-relative lea: REX (48/4c/49/4d) + 8d + modrm mod=00 rm=101.
    for m in re.finditer(rb"[\x48\x4c\x49\x4d]\x8d", seg):
        i = m.start()
        if i + 7 > len(seg) or (seg[i + 2] & 0xC7) != 0x05:
            continue
        dest = TEXT_VA + i + 7 + struct.unpack("<i", seg[i + 3:i + 7])[0]
        if dest in targets:
            rows.append((dest, "lea", TEXT_VA + i,
                         enclosing(fdes, starts, TEXT_VA + i)))
    # movabs: REX.W/B + b8..bf + imm64.
    for m in re.finditer(rb"[\x48\x49][\xb8-\xbf]", seg):
        i = m.start()
        if i + 10 > len(seg):
            continue
        imm = struct.unpack("<Q", seg[i + 2:i + 10])[0]
        if imm in targets:
            rows.append((imm, "movabs", TEXT_VA + i,
                         enclosing(fdes, starts, TEXT_VA + i)))
    # RELATIVE addends equal to a pinned routine.
    for off, addend in sorted(rel.items()):
        if addend in targets:
            rows.append((addend, "reloc", off, "-"))

    rows.sort(key=lambda r: (r[0], r[1], r[2]))
    with open(PACKET / "callers.tsv", "w") as fh:
        fh.write("routine\tkind\tsite\tenclosing_fde\n")
        for dest, kind, site, fde in rows:
            fh.write("0x%x\t%s\t0x%x\t%s\n" % (dest, kind, site, fde))

    with open(PACKET / "relocations.txt", "w") as fh:
        for off, what in RELOC_SITES:
            addend = rel.get(off)
            fh.write("0x%x\t%s\t%s\n" % (
                off, what,
                ("0x%x" % addend) if isinstance(addend, int) else "none"))
    # Typeinfo name strings (read from .rodata, vaddr == file offset).
    for ti in (0x64D8E90, 0x64D9350, 0x64D9360, 0x64D9370,
               0x64D85E0, 0x64D9338, 0x64D7D50, 0x64CF808):
        name_ptr = rel.get(ti + 8)
        name = ""
        if isinstance(name_ptr, int):
            end = data.find(b"\x00", name_ptr)
            name = data[name_ptr:end].decode()
        with open(PACKET / "relocations.txt", "a") as fh:
            fh.write("0x%x\ttypeinfo name\t%s\n" % (ti, name))

    windows = [
        (0x6205D20, 0x6205E08), (0x6202DA0, 0x6202E78),
        (0x62069F0, 0x6206D29), (0x6201000, 0x6201035),
        (0x6200A30, 0x6200A3F), (0x6208290, 0x6208AFA),
        (0x62080A4, 0x620828D), (0x62009A0, 0x62009CD),
        (0x62009D0, 0x62009FD), (0x6200A00, 0x6200A2D),
        (0x62056B0, 0x620573D), (0x620566B, 0x62056A4),
        (0x6205C60, 0x6205CEF), (0x6202CA0, 0x6202D1A),
        (0x6202C60, 0x6202C99), (0x6205560, 0x620566B),
        (0x6205790, 0x62058F7), (0x620573E, 0x6205788),
        (0x6202A10, 0x6202B50), (0x6202976, 0x6202A0A),
        (0x6201040, 0x62010E3), (0x62010F0, 0x62011D3),
        (0x61F06F0, 0x61F0732), (0x61F0990, 0x61F09DA),
        (0x61F0770, 0x61F077E), (0x61F0780, 0x61F078E),
        (0x6200A60, 0x6200AA2), (0x6201240, 0x620128A),
        (0x6200B10, 0x6200B1E), (0x6200B20, 0x6200B2E),
        (0x61E7CF0, 0x61E7D32), (0x61E7E00, 0x61E7E4A),
        (0x61E7D70, 0x61E7D7E), (0x61E7D80, 0x61E7D8E),
    ]
    with open(PACKET / "frames.txt", "w") as fh:
        for start, stop in windows:
            have = (start, stop) in fdes
            fh.write("0x%x..0x%x\t%s\n" % (start, stop,
                                            "FDE" if have else "NO-FDE"))


if __name__ == "__main__":
    main()
