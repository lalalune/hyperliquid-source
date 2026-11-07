#!/usr/bin/env python3
"""Caller censuses for RE-001 options-map-host-e510-115.

Byte-level E8 rel32 scan of .text for direct call sites, REX.W lea
rip-relative scan for the .bss string at 0x6508980, RELATIVE-reloc
counts for the shared base predicate 0x5d2e770, and the two
Configurable vtable maps read from R_X86_64_RELATIVE relocations.

Run from the repo root:
    python3 research/work-items/RE-001-options-map-host-e510-115/census.py
"""
import re
import struct
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
BSS_STRING = 0x6508980

TARGETS = {
    0x609E510: "options-map host (RE-001, this packet)",
    0x609A410: "id-configure helper (RE-001, #4334)",
    0x6098510: "delimiter pre-step (RE-001, #4337)",
    0x60985E0: "reset-and-serialize wrapper (RE-001, #4337)",
    0x60C1190: "map parser (RE-001, #4320)",
    0x5D2E770: "base slot-16 name predicate (RE-001, this packet)",
}

SHARED_HELPERS = {
    0x5D35070: "shared_ptr counted-base release helper",
    0x5D36110: "unordered_map<string,string> destructor",
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
        site = TEXT_VA + i
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
            site = TEXT_VA + i
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
    (HERE / "callers.tsv").write_text("\n".join(rows) + "\n")

    lea = lea_sites(data, BSS_STRING)
    rows = ["address\tlea_site\trole"]
    for site in lea:
        rows.append(f"{BSS_STRING:#x}\t{site:#x}\t.bss string referenced (default name, identity open)")
    (HERE / "bss-string-lea.tsv").write_text("\n".join(rows) + "\n")

    rows = ["target\tcount\tin_packet_site\tnote"]
    for target, note in sorted(SHARED_HELPERS.items()):
        sites = call_sites(data, target)
        in_packet = "0x609ef91" if target == 0x5D35070 else "0x609e939"
        rows.append(f"{target:#x}\t{len(sites)}\t{in_packet}\t{note}")
    (HERE / "shared-helper-counts.tsv").write_text("\n".join(rows) + "\n")

    out = subprocess.run(["readelf", "-rW", str(BIN)],
                         capture_output=True, text=True, check=True).stdout
    relocs: dict[int, int] = {}
    for m in re.finditer(r"^([0-9a-f]{16})\s+[0-9a-f]{16}\s+R_X86_64_RELATIVE\s+([0-9a-f]+)",
                         out, re.M):
        relocs[int(m.group(1), 16)] = int(m.group(2), 16)
    base_pred_slots = sum(1 for v in relocs.values() if v == 0x5D2E770)
    rows = ["vtable\tslot\toffset\ttarget\tnote"]
    slot_notes = {
        12: "slot 12 = 0x609de80 (shared)",
        14: "slot 14 = Name",
        15: "slot 15 = GetId 0x5d32a30 (shared)",
        16: "slot 16 = base name predicate 0x5d2e770 (shared)",
        17: "slot 17 = Inner (0x5d2ca00, returns nullptr)",
        18: "slot 18 = NickName (0x5d2ca10, returns empty string)",
    }
    for vaddr, name, slots in [(0x64D39B8, "BBT Configurable vtable", 22),
                               (0x64CDAD0, "second Configurable vtable", 21)]:
        for slot, tgt in enumerate(vtable(vaddr, slots, relocs)):
            note = name
            if tgt is None:
                note = "no RELATIVE reloc"
            elif slot in slot_notes:
                note = slot_notes[slot]
            rows.append(f"{vaddr:#x}\t{slot}\t{slot * 8:#x}\t"
                        f"{tgt if tgt is None else hex(tgt)}\t{note}")
    (HERE / "vtables.tsv").write_text("\n".join(rows) + "\n")
    print("callers.tsv:", sum(1 for _ in open(HERE / "callers.tsv")) - 1, "sites")
    print("bss-string-lea.tsv:", len(lea), "sites")
    print("shared-helper-counts.tsv written")
    print("vtables.tsv:", sum(1 for _ in open(HERE / "vtables.tsv")) - 1, "slots")
    print("base predicate 0x5d2e770 vtable slots binary-wide:", base_pred_slots)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
