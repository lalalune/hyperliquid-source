#!/usr/bin/env python3
"""Caller censuses for RE-001 parse-then-apply-wrapper-115.

Byte-level E8 rel32 scan of .text for direct call sites, and REX.W lea
rip-relative scan for the two static OptionTypeInfo maps passed as the
wrapper's arg4.

Run from the repo root:
    python3 research/work-items/RE-001-parse-then-apply-wrapper-115/census.py
"""
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700

TARGETS = {
    0x60C1BB0: "parse-then-apply wrapper (RE-001, this packet)",
    0x60C1190: "map parser (RE-001, #4320/#4349)",
    0x60C18B0: "apply loop (RE-001, #4237)",
    0x60C0E90: "unordered_map<string,string>::operator[] overflow insert (RE-001, this packet)",
    0x60C1D50: "prefix-match forwarder, wrapper caller C (RE-001, this packet)",
}

STATIC_MAPS = {
    0x6501CE0: "static OptionTypeInfo map, wrapper caller B arg4",
    0x6501D20: "static OptionTypeInfo map, wrapper caller A arg4",
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
    for rex in (0x48, 0x49, 0x4C, 0x4D):
        i = 0
        pat = bytes([rex, 0x8D])
        while True:
            i = seg.find(pat, i)
            if i == -1:
                break
            if i + 7 <= len(seg) and (seg[i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", seg, i + 3)[0]
                site = TEXT_VA + i
                if site + 7 + disp == target:
                    sites.append(site)
            i += 1
    return sorted(set(sites))


def main() -> int:
    data = BIN.read_bytes()
    rows = ["target\ttarget_hex\tcaller\trole"]
    for target, role in sorted(TARGETS.items()):
        for site in call_sites(data, target):
            rows.append(f"{target:#x}\t{target:#x}\t{site:#x}\t{role}")
    (HERE / "callers.tsv").write_text("\n".join(rows) + "\n")

    rows = ["target\tcount\tin_packet_site\tnote"]
    for target, note in sorted({0x5D36110: "unordered_map<string,string> destructor"}.items()):
        sites = call_sites(data, target)
        in_packet = "0x60c1c53" if target == 0x5D36110 else ""
        rows.append(f"{target:#x}\t{len(sites)}\t{in_packet}\t{note}")
    (HERE / "shared-helper-counts.tsv").write_text("\n".join(rows) + "\n")

    rows = ["address\tlea_site\trole"]
    for target, role in sorted(STATIC_MAPS.items()):
        for site in lea_sites(data, target):
            rows.append(f"{target:#x}\t{site:#x}\t{role}")
    (HERE / "static-maps-lea.tsv").write_text("\n".join(rows) + "\n")
    print("callers.tsv:", sum(1 for _ in open(HERE / "callers.tsv")) - 1, "sites")
    print("shared-helper-counts.tsv written")
    print("static-maps-lea.tsv:", sum(1 for _ in open(HERE / "static-maps-lea.tsv")) - 1, "sites")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
