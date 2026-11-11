"""Census for the RE-001-ttl-runtime-methods-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-ttl-runtime-methods-115/census.py

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
    (0x6203B80, "mo-d2"),
    (0x6203C30, "mo-d0"),
    (0x6200B70, "mo-prepare"),
    (0x6200E10, "mo-validate"),
    (0x6200930, "mo-name"),
    (0x6202520, "mo-isinstanceof"),
    (0x6200940, "mo-slot17"),
    (0x6206610, "mo-fullmergev2"),
    (0x62065E6, "mo-fullmergev2-cold"),
    (0x6201C90, "mo-partialmerge-multi"),
    (0x6201B74, "mo-partialmerge-multi-cold"),
    (0x62018F0, "cf-d2"),
    (0x62019A0, "cf-d0"),
    (0x6200BF0, "cf-prepare"),
    (0x6200CF0, "cf-validate"),
    (0x6200900, "cf-name"),
    (0x6202440, "cf-isinstanceof"),
    (0x62008E0, "cf-slot17"),
    (0x6203520, "cf-filter"),
    (0x6203400, "cf-expiry"),
    (0x5D2E4A0, "cf-filterv2"),
    (0x5D2F8A0, "cf-filterv3"),
    (0x6203AD0, "cff-d2"),
    (0x6203CE0, "cff-d0"),
    (0x6200C70, "cff-prepare"),
    (0x6200D80, "cff-validate"),
    (0x6200910, "cff-name"),
    (0x6200920, "cff-slot17"),
    (0x5D2CA70, "cff-slot19"),
    (0x6202BA0, "cff-create"),
    (0x6202B50, "cff-create-cold"),
    (0x5D2CA10, "shared-empty-string"),
    (0x5D2CA00, "shared-null"),
    (0x5D2CD80, "shared-ret0-mo19"),
    (0x5D2CD90, "shared-ret0-mo21"),
    (0x5D2CDA0, "shared-ret0-mo23"),
    (0x5D2CDB0, "shared-ret0-mo24"),
    (0x5D2CA30, "shared-ret0-cf20"),
    (0x5D2CA40, "shared-ret0-cf23"),
    (0x5DF72F0, "shared-ret1-cf24"),
    (0x5D2CA50, "shared-ret0-cf25"),
    (0x5D2CA60, "shared-ret8-cf26"),
    (0x5D2E770, "shared-isinst-default"),
    (0x5FCEDA0, "merge-error-logger"),
    # Cited helpers (not re-excerpted here).
    (0x6095E70, "base-prepare"),
    (0x6096790, "base-validate"),
    (0x5FCF430, "clock-resolver"),
    (0x61CF670, "validate-error-builder"),
    (0x5D36370, "vector-copy"),
    (0x5D36020, "vector-destroy"),
    (0x5D350C0, "shared-ptr-release"),
    (0x5D4B100, "canonical-get-current-time"),
    (0x5FE2230, "posix-clock-get-current-time"),
    (0x6202A10, "cf-ctor-c2"),
    (0x6205560, "mo-ctor-c1"),
    (0x6205790, "cff-ctor-c2"),
    (0x61F4D60, "put-operator-fullmerge"),
]

# Vtable / typeinfo sites whose RELATIVE records are pinned.
RELOC_SITES = []
MO_VT = 0x64D9558
CF_VT = 0x64D9630
CFF_VT = 0x64D9718
MO_NAMES = ["D2", "D0", "GetOption", "AreEquivalent", "empty-string",
            "PrepareOptions", "ValidateOptions", "GetOptionsPtr",
            "empty-Status", "ConfigureOptions", "ParseOption",
            "OptionsAreEqual", "SerializeOptions", "GetOptionName",
            "Name", "GetId", "IsInstanceOf", "slot17-wrapped",
            "slot18-short-name", "FullMerge", "FullMergeV2",
            "PartialMerge", "PartialMergeMulti", "AllowSingleOperand",
            "ShouldMerge"]
CF_NAMES = ["D2", "D0", "GetOption", "AreEquivalent", "empty-string",
            "PrepareOptions", "ValidateOptions", "GetOptionsPtr",
            "empty-Status", "ConfigureOptions", "ParseOption",
            "OptionsAreEqual", "SerializeOptions", "GetOptionName",
            "Name", "GetId", "IsInstanceOf", "slot17-wrapped",
            "slot18-short-name", "Filter", "FilterMergeOperand",
            "FilterV2", "FilterV3", "PrepareBlobOutput",
            "IgnoreSnapshots", "IsStackedBlobDbInternalCompactionFilter",
            "slot26-ret8"]
CFF_NAMES = ["D2", "D0", "GetOption", "AreEquivalent", "empty-string",
             "PrepareOptions", "ValidateOptions", "GetOptionsPtr",
             "empty-Status", "ConfigureOptions", "ParseOption",
             "OptionsAreEqual", "SerializeOptions", "GetOptionName",
             "Name", "GetId", "IsInstanceOf", "slot17-wrapped",
             "slot18-short-name", "slot19-esi-eq-1",
             "CreateCompactionFilter"]
for label, vt, names in (("TtlMergeOperator", MO_VT, MO_NAMES),
                         ("TtlCompactionFilter", CF_VT, CF_NAMES),
                         ("TtlCompactionFilterFactory", CFF_VT, CFF_NAMES)):
    RELOC_SITES.append((vt - 0x10, label + " vtable header offset_to_top"))
    RELOC_SITES.append((vt - 8, label + " vtable header typeinfo"))
    for i, name in enumerate(names):
        RELOC_SITES.append((vt + 8 * i, label + " vtable slot %d %s" % (i, name)))
RELOC_SITES += [
    (0x64D9308 + 8, "TtlMergeOperator typeinfo name pointer"),
    (0x64D92F0 + 8, "TtlCompactionFilterFactory typeinfo name pointer"),
    (0x64D92D8 + 8, "TtlCompactionFilter typeinfo name pointer"),
    (0x64ED3E8, "GetCurrentTime canonical GOT slot"),
    (0x64ECFF0, "FilterMergeOperand canonical GOT slot"),
    (0x64ED0B8, "FilterV2 canonical GOT slot"),
    (0x64D97C0, "DBWithTTLImpl vtable header offset_to_top (boundary)"),
    (0x64D97C8, "DBWithTTLImpl vtable header typeinfo (boundary)"),
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
    for ti in (0x64D9308, 0x64D92F0, 0x64D92D8):
        name_ptr = rel.get(ti + 8)
        name = ""
        if isinstance(name_ptr, int):
            end = data.find(b"\x00", name_ptr)
            name = data[name_ptr:end].decode()
        with open(PACKET / "relocations.txt", "a") as fh:
            fh.write("0x%x\ttypeinfo name\t%s\n" % (ti, name))

    windows = [
        (0x6203B80, 0x6203C25), (0x6203C30, 0x6203CD3),
        (0x6200B70, 0x6200BE1), (0x6200E10, 0x6200ED8),
        (0x6200930, 0x620093C), (0x6202520, 0x62025F9),
        (0x6200940, 0x6200949), (0x6206610, 0x6206923),
        (0x62065E6, 0x620660E), (0x6201C90, 0x62022B1),
        (0x6201B74, 0x6201C81), (0x62018F0, 0x6201995),
        (0x62019A0, 0x6201A43), (0x6200BF0, 0x6200C61),
        (0x6200CF0, 0x6200D7F), (0x6200900, 0x620090C),
        (0x6202440, 0x6202519), (0x62008E0, 0x62008E9),
        (0x6203520, 0x6203627), (0x6203400, 0x6203513),
        (0x5D2E4A0, 0x5D2E53D), (0x5D2F8A0, 0x5D2F999),
        (0x6203AD0, 0x6203B75), (0x6203CE0, 0x6203D83),
        (0x6200C70, 0x6200CE1), (0x6200D80, 0x6200E0F),
        (0x6200910, 0x620091C), (0x6200920, 0x6200929),
        (0x5D2CA70, 0x5D2CA7B), (0x6202BA0, 0x6202C60),
        (0x6202B50, 0x6202B9A), (0x5D2CA10, 0x5D2CA1C),
        (0x5D2CA00, 0x5D2CA07), (0x5D2CD80, 0x5D2CD87),
        (0x5D2CD90, 0x5D2CD97), (0x5D2CDA0, 0x5D2CDA7),
        (0x5D2CDB0, 0x5D2CDB7), (0x5D2CA30, 0x5D2CA37),
        (0x5D2CA40, 0x5D2CA47), (0x5DF72F0, 0x5DF72FA),
        (0x5D2CA50, 0x5D2CA57), (0x5D2CA60, 0x5D2CA6A),
        (0x5D2E770, 0x5D2E832), (0x5FCEDA0, 0x5FCEE93),
    ]
    with open(PACKET / "frames.txt", "w") as fh:
        for start, stop in windows:
            have = (start, stop) in fdes
            fh.write("0x%x..0x%x\t%s\n" % (start, stop,
                                            "FDE" if have else "NO-FDE"))


if __name__ == "__main__":
    main()
