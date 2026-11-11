"""Census for the RE-001-register-encryption-builtins-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-register-encryption-builtins-115/census.py

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
    (0x5FF88C0, "host"),
    (0x5FF844A, "host-cold"),
    (0x5FF9C50, "thunk"),
    (0x5FF0300, "string-ctor"),
    (0x5FEFD80, "string-range"),
    (0x5FF7420, "vec-grow"),
    (0x5FF8260, "register-helper"),
    (0x5FEFA50, "mgr-e_"),
    (0x5FEFA80, "mgr-e0"),
    (0x5FEFAB0, "mgr-cipher"),
    (0x5FF6A00, "invoke-e0"),
    (0x5FF6D60, "invoke-e_"),
    (0x5FF7120, "invoke-cipher"),
    (0x5FEFBC0, "fe-enc-d2"),
    (0x5FF0060, "fe-enc-d0"),
    (0x5FEFCA0, "fe-enc-matches"),
    (0x5FEFCB0, "fe-enc-accessor"),
    (0x5FEFB70, "fe-cipher-d2"),
    (0x5FF0010, "fe-cipher-d0"),
    (0x5FEFC80, "fe-cipher-matches"),
    (0x5FEFC90, "fe-cipher-accessor"),
    (0x5FF7900, "libcb-dispose"),
    (0x61D1390, "endswith"),
    (0x61D1EF0, "cipher-jmp"),
    (0x5FFA710, "once-a"),
    (0x5FFBA10, "once-b"),
    # Cited from earlier packets (not re-excerpted here).
    (0x61F92B0, "reg-getter"),
    (0x5FD1DA0, "find-or-insert"),
    (0x5FD17C0, "vec-insert"),
    (0x5FF2030, "pattern-d2"),
    (0x5FF2150, "pattern-d0"),
    (0x61F8670, "pattern-matches"),
    (0x61F8120, "pattern-accessor"),
]

# Vtable / typeinfo sites whose RELATIVE records are pinned.
RELOC_SITES = [
    (0x64D8EC0, "PatternEntry vtable header offset_to_top"),
    (0x64D8EC8, "PatternEntry vtable header typeinfo"),
    (0x64D8ED0, "PatternEntry vtable slot 0 D2"),
    (0x64D8ED8, "PatternEntry vtable slot 1 D0"),
    (0x64D8EE0, "PatternEntry vtable slot 2 Matches"),
    (0x64D8EE8, "PatternEntry vtable slot 3 accessor"),
    (0x64D0080, "FactoryEntry-EncProvider vtable header offset_to_top"),
    (0x64D0088, "FactoryEntry-EncProvider vtable header typeinfo"),
    (0x64D0090, "FactoryEntry-EncProvider vtable slot 0 D2"),
    (0x64D0098, "FactoryEntry-EncProvider vtable slot 1 D0"),
    (0x64D00A0, "FactoryEntry-EncProvider vtable slot 2 Matches"),
    (0x64D00A8, "FactoryEntry-EncProvider vtable slot 3 accessor"),
    (0x64D00B0, "FactoryEntry-BlockCipher vtable header offset_to_top"),
    (0x64D00B8, "FactoryEntry-BlockCipher vtable header typeinfo"),
    (0x64D00C0, "FactoryEntry-BlockCipher vtable slot 0 D2"),
    (0x64D00C8, "FactoryEntry-BlockCipher vtable slot 1 D0"),
    (0x64D00D0, "FactoryEntry-BlockCipher vtable slot 2 Matches"),
    (0x64D00D8, "FactoryEntry-BlockCipher vtable slot 3 accessor"),
    (0x64D00E0, "LibCB-ObjectLibrary vtable header offset_to_top"),
    (0x64D00E8, "LibCB-ObjectLibrary vtable header typeinfo"),
    (0x64D00F0, "LibCB-ObjectLibrary vtable slot 0 D2"),
    (0x64D00F8, "LibCB-ObjectLibrary vtable slot 1 D0"),
    (0x64D0100, "LibCB-ObjectLibrary vtable slot 2 _M_dispose"),
    (0x64D0108, "LibCB-ObjectLibrary vtable slot 3 _M_destroy"),
    (0x64D0110, "LibCB-ObjectLibrary vtable slot 4 _M_get_deleter"),
    (0x64D8E98, "PatternEntry typeinfo name pointer"),
    (0x64D8E90, "PatternEntry typeinfo vtable pointer"),
    (0x64CF7B8 + 8, "manager E_ typeinfo name pointer"),
    (0x64CF7C8 + 8, "manager E0 typeinfo name pointer"),
    (0x64CF7D8 + 8, "manager Cipher typeinfo name pointer"),
    (0x64CF7E8 + 8, "manager AsCustomSharedPtr typeinfo name pointer"),
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
    for ti in (0x64D8E90, 0x64CF788, 0x64CF7A0, 0x64CF808,
               0x64CF7B8, 0x64CF7C8, 0x64CF7D8, 0x64CF7E8):
        name_ptr = rel.get(ti + 8)
        name = ""
        if isinstance(name_ptr, int):
            end = data.find(b"\x00", name_ptr)
            name = data[name_ptr:end].decode()
        with open(PACKET / "relocations.txt", "a") as fh:
            fh.write("0x%x\ttypeinfo name\t%s\n" % (ti, name))

    windows = [
        (0x5FF88C0, 0x5FF9C50), (0x5FF844A, 0x5FF88B7),
        (0x5FF9C50, 0x5FF9C59), (0x5FF0300, 0x5FF03E3),
        (0x5FEFD80, 0x5FEFE23), (0x5FF7420, 0x5FF7811),
        (0x5FF8260, 0x5FF8449), (0x5FEFA50, 0x5FEFA7D),
        (0x5FEFA80, 0x5FEFAAD), (0x5FEFAB0, 0x5FEFADD),
        (0x5FF6A00, 0x5FF6C70), (0x5FF6D60, 0x5FF70A7),
        (0x5FF7120, 0x5FF7419), (0x5FEFBC0, 0x5FEFC02),
        (0x5FF0060, 0x5FF00AA), (0x5FEFCA0, 0x5FEFCAE),
        (0x5FEFCB0, 0x5FEFCBE), (0x5FEFB70, 0x5FEFBB2),
        (0x5FF0010, 0x5FF005A), (0x5FEFC80, 0x5FEFC8E),
        (0x5FEFC90, 0x5FEFC9E), (0x5FF7900, 0x5FF7952),
        (0x61D1390, 0x61D13DB), (0x61D1EF0, 0x61D1EF9),
        (0x5FFA710, 0x5FFAAD9), (0x5FFBA10, 0x5FFBDD9),
    ]
    with open(PACKET / "frames.txt", "w") as fh:
        for start, stop in windows:
            have = (start, stop) in fdes
            fh.write("0x%x..0x%x\t%s\n" % (start, stop,
                                            "FDE" if have else "NO-FDE"))


if __name__ == "__main__":
    main()
