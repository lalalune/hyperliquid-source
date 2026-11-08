#!/usr/bin/env python3
"""Caller census and frame/literal tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-cfoptions-groups-115/census.py

Regenerates callers.tsv (every direct E8 call site of RegisterOptions
0x6099ce0, with its enclosing FDE), literals.tsv (the group-name
literals, the two maps, and their binary-wide lea sites) and frames.txt
(FDE ranges for the cited functions). The 37-site census must match
#3257 (RE-001-record-pushback-115) and #4372, which first published it.
"""
import bisect
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300

TARGET = 0x6099CE0

# Sites analysed in this packet (ConfigurableCFOptions ctor 0x6086e00).
ANALYSED = {
    0x608749A: "MutableCFOptions group (this packet)",
    0x6087CE8: "ImmutableCFOptions group (this packet)",
}
# Sites analysed by #3257 and #4372.
PRIOR = {
    0x60DB9DB: "BlockTableOptions group (#3257)",
    0x60644FC: "SkipListFactoryOptions group (#3257)",
    0x5FD0124: "empty-key group (#3257)",
    0x60A492A: "MutableDBOptions group (#4372)",
    0x60A50F2: "ImmutableDBOptions group (#4372)",
}

# Name literals and maps cited in the two traced registrations.
LEA_TARGETS = {
    0x43FA91: "MutableCFOptions",
    0x433249: "ImmutableCFOptions",
    0x6506B20: "MutableCFOptions OptionTypeInfo map",
    0x6506AE0: "ImmutableCFOptions OptionTypeInfo map",
}


def scan_callers(data: bytes, target: int) -> list[int]:
    seg = data[TEXT_OFF:]
    hits, idx = [], 0
    while True:
        i = seg.find(b"\xe8", idx)
        if i < 0:
            break
        if i + 5 <= len(seg):
            rel = struct.unpack_from("<i", seg, i + 1)[0]
            site = TEXT_VA + i
            if site + 5 + rel == target:
                hits.append(site)
        idx = i + 1
    return hits


def scan_lea(data: bytes, target: int) -> list[int]:
    seg = data[TEXT_OFF:]
    hits, i = [], 0
    while True:
        i = seg.find(b"\x8d", i)
        if i < 0:
            break
        if i >= 1 and seg[i - 1] in (0x48, 0x49, 0x4C, 0x4D) and i + 7 <= len(seg):
            if seg[i + 1] & 0xC7 == 0x05:  # mod=00, rm=101 RIP-relative
                rel = struct.unpack_from("<i", seg, i + 2)[0]
                site = TEXT_VA + i - 1
                if site + 7 + rel == target:
                    hits.append(site)
        i += 1
    return hits


def main() -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records

    data = BIN.read_bytes()
    sites = scan_callers(data, TARGET)
    assert len(sites) == 37, f"expected 37 RegisterOptions sites, got {len(sites)}"

    _, frames = eh_frame_records(data)
    fdes = sorted((f["start"], f["end"]) for f in frames)
    starts = [s for s, _ in fdes]

    def enclosing(addr: int) -> tuple[int, int]:
        i = bisect.bisect_right(starts, addr) - 1
        s, e = fdes[i]
        assert s <= addr < e, f"no FDE encloses {addr:#x}"
        return s, e

    rows = ["site\ttarget\tenclosing_fde\tnote"]
    for site in sites:
        s, e = enclosing(site)
        note = ANALYSED.get(site, PRIOR.get(site, "not individually analysed"))
        rows.append(f"{site:#x}\t{TARGET:#x}\t{s:#x}..{e:#x}\t{note}")
    (HERE / "callers.tsv").write_text("\n".join(rows) + "\n")

    lea = {t: scan_lea(data, t) for t in LEA_TARGETS}
    assert lea[0x43FA91] == [0x6087473], f"MutableCFOptions lea sites: {lea[0x43FA91]}"
    assert lea[0x433249] == [0x6087CC1], f"ImmutableCFOptions lea sites: {lea[0x433249]}"
    assert lea[0x6506B20] == [0x608748A, 0x608EC34, 0x608F329], f"map 0x6506b20 lea sites: {lea[0x6506B20]}"
    assert lea[0x6506AE0] == [0x6087CDE, 0x6090E46], f"map 0x6506ae0 lea sites: {lea[0x6506AE0]}"

    literals = [
        "address\tbytes\tmeaning",
        "0x43fa91\tMutableCFOptions\tgroup-name literal, 16 bytes (sole lea site 0x6087473, feeds call 1)",
        "0x433249\tImmutableCFOptions\tgroup-name literal, 18 bytes (sole lea site 0x6087cc1, feeds call 2)",
        "0x6506b20\t-\tMutableCFOptions OptionTypeInfo map, 62 entries (#4263); lea sites 0x608748a (this packet), 0x608ec34, 0x608f329 (static initializer 0x6089b50)",
        "0x6506ae0\t-\tImmutableCFOptions OptionTypeInfo map, 31 entries (#4263); lea sites 0x6087cde (this packet), 0x6090e46 (static initializer 0x6089b50)",
    ]
    (HERE / "literals.tsv").write_text("\n".join(literals) + "\n")

    frames_out = [
        "function\tfde_start\tfde_end",
        "0x6086e00\t0x6086e00\t0x608818d",
        "0x6099ce0\t0x6099ce0\t0x6099e34",
        "0x6099790\t0x6099790\t0x6099cad",
        "0x607d9f0\t0x607d9f0\t0x607dad3",
    ]
    (HERE / "frames.txt").write_text("\n".join(frames_out) + "\n")
    print(f"wrote callers.tsv ({len(sites)} sites), literals.tsv, frames.txt")
    for t, ss in lea.items():
        print(f"  lea {t:#x}: {[hex(s) for s in ss]}")


if __name__ == "__main__":
    main()
