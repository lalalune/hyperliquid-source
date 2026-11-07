#!/usr/bin/env python3
"""Caller censuses for this packet, by byte-level E8 rel32 scan of .text.

Run from the repo root:
    python3 research/work-items/RE-001-map-serializer-7630-115/census.py
"""
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300

TARGETS = {
    0x6097630: "map serializer (S0 writer)",
    0x6098510: "delimiter pre-step",
    0x60985E0: "reset-and-serialize wrapper",
}


def scan_callers(data: bytes, target: int) -> list[int]:
    b = data[TEXT_OFF:]
    hits, idx = [], 0
    while True:
        i = b.find(b"\xe8", idx)
        if i < 0:
            break
        if i + 5 <= len(b):
            rel = struct.unpack_from("<i", b, i + 1)[0]
            site = TEXT_VA + i
            if site + 5 + rel == target:
                hits.append(site)
        idx = i + 1
    return hits


def main() -> None:
    data = BIN.read_bytes()
    for target, label in TARGETS.items():
        sites = scan_callers(data, target)
        print(f"{target:#x} ({label}): {[hex(s) for s in sites]}")


if __name__ == "__main__":
    main()
