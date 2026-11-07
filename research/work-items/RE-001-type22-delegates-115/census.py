#!/usr/bin/env python3
"""Caller census for RE-001 type22-delegates-115 (byte scan of .text).

Scans the .text segment of node #115 for direct CALL rel32 (E8 + int32)
sites targeting the pinned routines, plus REX.W lea rip-relative sites
referencing the .bss string at 0x6508980, plus the two Configurable vtable
maps read from R_X86_64_RELATIVE relocations.

Re-run to reproduce; verify.py re-runs this scan and diffs the TSVs.
"""
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work" / "hl-node-115.bin"
OUT = Path(__file__).resolve().parent

TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
BSS_STRING = 0x6508980

TARGETS = {
    0x609A740: "type-22 apply delegate (RE-001)",
    0x60971C0: "serializer helper (RE-001)",
    0x609B700: "apply-created dispatch (RE-001, cited from #4320)",
    0x609B8A0: "create-by-name (RE-001, cited from #4320)",
    0x609A410: "id-configure helper (RE-001, open unknown)",
    0x6097150: "configure slot-9 entry (RE-001, cited from #4320)",
    0x61D1390: "ends_with (RE-001)",
    0x61D13E0: "string_compare (RE-001)",
    0x609DE80: "slot-12 nested serializer (RE-001)",
    0x5D32A30: "slot-15 GetId (RE-001)",
    0x60986B0: "slot-10 ConfigureOption core (RE-001)",
}


def call_sites(data: bytes, target: int) -> list[int]:
    seg = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    sites = []
    i = 0
    while True:
        i = seg.find(b"\xe8", i)
        if i == -1 or i + 5 > len(seg):
            break
        rel = struct.unpack_from("<i", seg, i + 1)[0]
        site = TEXT_VADDR + i
        if site + 5 + rel == target:
            sites.append(site)
        i += 1
    return sites


def lea_sites(data: bytes, target: int) -> list[int]:
    seg = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    sites = []
    i = 0
    while True:
        i = seg.find(b"\x48\x8d", i)
        if i == -1:
            break
        if i + 7 <= len(seg) and (seg[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", seg, i + 3)[0]
            site = TEXT_VADDR + i
            if site + 7 + disp == target:
                sites.append(site)
        i += 1
    return sites


def vtable(vaddr: int, slots: int, relocs: dict[int, int]) -> list[int | None]:
    return [relocs.get(vaddr + 8 * s) for s in range(slots)]


def main() -> int:
    data = BIN.read_bytes()
    rows = ["target\ttarget_hex\tcaller\trole"]
    for target, role in sorted(TARGETS.items()):
        for site in call_sites(data, target):
            rows.append(f"{target:#x}\t{target:#x}\t{site:#x}\t{role}")
    (OUT / "callers.tsv").write_text("\n".join(rows) + "\n")

    lea = lea_sites(data, BSS_STRING)
    rows = ["address\tlea_site\trole"]
    for site in lea:
        rows.append(f"{BSS_STRING:#x}\t{site:#x}\t.bss string referenced (serializer null-object string, identity open)")
    (OUT / "bss-string-lea.tsv").write_text("\n".join(rows) + "\n")

    relocs: dict[int, int] = {}
    out = subprocess.run(["readelf", "-rW", str(BIN)],
                         capture_output=True, text=True, check=True).stdout
    for m in re.finditer(r"^([0-9a-f]{16})\s+[0-9a-f]{16}\s+R_X86_64_RELATIVE\s+([0-9a-f]+)",
                         out, re.M):
        relocs[int(m.group(1), 16)] = int(m.group(2), 16)
    rows = ["vtable\tslot\toffset\ttarget\tnote"]
    for slot, tgt in enumerate(vtable(0x64D39B8, 22, relocs)):
        rows.append(f"0x64d39b8\t{slot}\t{slot * 8:#x}\t{tgt if tgt is None else hex(tgt)}\t{'BBT Configurable vtable' if slot not in (12, 15) else 'slot 12 = 0x609de80 / slot 15 = GetId 0x5d32a30' if slot in (12, 15) else ''}")
    for slot, tgt in enumerate(vtable(0x64CDAD0, 21, relocs)):
        note = "no RELATIVE reloc" if tgt is None else ""
        if slot == 12:
            note = "slot 12 = 0x609de80 (shared with BBT)"
        elif slot == 15:
            note = "slot 15 = GetId 0x5d32a30 (shared with BBT)"
        rows.append(f"0x64cdad0\t{slot}\t{slot * 8:#x}\t{tgt if tgt is None else hex(tgt)}\t{note}")
    (OUT / "vtables.tsv").write_text("\n".join(rows) + "\n")
    print("callers.tsv:", sum(1 for _ in open(OUT / 'callers.tsv')) - 1, "sites")
    print("bss-string-lea.tsv:", len(lea), "sites")
    print("vtables.tsv:", sum(1 for _ in open(OUT / 'vtables.tsv')) - 1, "slots")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
