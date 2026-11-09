#!/usr/bin/env python3
"""Caller census for RE-001 id-configure-helpers-115 (byte scan of .text).

Scans the .text segment of node #115 for direct CALL rel32 (E8 + int32)
sites targeting the pinned routines, plus the shared slot-9 target from
the two Configurable vtables read from R_X86_64_RELATIVE relocations.
The map-clear helper 0x5d5b300 is shared binary-wide (~100 callers); only
its calls from the pinned/host functions of this packet are listed, with
the binary-wide count recorded in records.json.

Re-run to reproduce; verify.py re-runs this scan and diffs the TSVs.
"""
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
OUT = Path(__file__).resolve().parent

TEXT_VADDR, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700

TARGETS = {
    0x609A410: "id-configure helper (RE-001, centerpiece)",
    0x6097150: "configure slot-9 entry (RE-001, centerpiece)",
    0x6097110: "slot-9 tail (RE-001, centerpiece; re-shipped from #4320)",
    0x609D0E0: "vtable slot 9 (RE-001, centerpiece)",
    0x609A1B0: "unordered_map find (RE-001, helper)",
    0x609A2F0: "unordered_map erase (RE-001, helper)",
    0x6098510: "delimiter pre-step (RE-001, helper)",
    0x609E2D0: "null-checked slot-9 entry (RE-001, helper)",
    0x609C8C0: "map-copy-and-apply (RE-001, helper)",
    0x609BCB0: "per-entry apply (RE-001, helper)",
}

# 0x5d5b300 (map clear) sites inside the pinned/host functions only.
MAP_CLEAR_SITES = {
    0x609A509: "inside 0x609a410 (parse-failure path)",
    0x609A661: "inside 0x609a410 (no-id, empty-id path)",
    0x609A087: "inside setter 0x6099e70 (re-shipped from #4320)",
    0x609B35D: "inside delegate 0x609a740 (shipped in #4328)",
    0x609CB05: "inside 0x609c8c0 (map-copy tail)",
    0x609E9FE: "inside 0x609e510 (sibling id-configure caller)",
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


def main() -> int:
    data = BIN.read_bytes()
    rows = ["target\ttarget_hex\tcaller\trole"]
    for target, role in sorted(TARGETS.items()):
        for site in call_sites(data, target):
            rows.append(f"{target:#x}\t{target:#x}\t{site:#x}\t{role}")
    for site in sorted(MAP_CLEAR_SITES):
        rows.append(f"0x5d5b300\t0x5d5b300\t{site:#x}\tunordered_map clear ({MAP_CLEAR_SITES[site]})")
    (OUT / "callers.tsv").write_text("\n".join(rows) + "\n")

    # Slot 9 (offset 0x48) in both Configurable vtables.
    relocs: dict[int, int] = {}
    out = subprocess.run(["readelf", "-rW", str(BIN)],
                         capture_output=True, text=True, check=True).stdout
    for m in re.finditer(r"^([0-9a-f]{16})\s+[0-9a-f]{16}\s+R_X86_64_RELATIVE\s+([0-9a-f]+)",
                         out, re.M):
        relocs[int(m.group(1), 16)] = int(m.group(2), 16)
    rows = ["vtable\tslot\toffset\ttarget\tnote"]
    for vt in (0x64D39B8, 0x64CDAD0):
        tgt = relocs.get(vt + 0x48)
        rows.append(f"{vt:#x}\t9\t0x48\t{tgt if tgt is None else hex(tgt)}\t{'BBT Configurable vtable' if vt == 0x64D39B8 else 'second Configurable vtable'}; slot 9 = 0x609d0e0 (shared)")
    (OUT / "slot9-vtables.tsv").write_text("\n".join(rows) + "\n")

    # Binary-wide count of map-clear callers (not enumerated in callers.tsv).
    n_clear = len(call_sites(data, 0x5D5B300))
    (OUT / "map-clear-count.txt").write_text(
        f"0x5d5b300 direct call sites binary-wide: {n_clear}\n")
    print("callers.tsv:", sum(1 for _ in open(OUT / 'callers.tsv')) - 1, "sites")
    print("slot9-vtables.tsv: 2 slots")
    print("map-clear binary-wide:", n_clear, "sites")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
