#!/usr/bin/env python3
"""Caller census and frame/literal tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-dboptions-groups-115/census.py

Regenerates callers.tsv (every direct E8 call site of RegisterOptions
0x6099ce0, with its enclosing FDE), literals.tsv (the group-name
literals and maps cited in the two traced registrations) and frames.txt
(FDE ranges for the cited functions). The 37-site census must match
#3257 (RE-001-record-pushback-115), which first published it.
"""
import bisect
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300

TARGET = 0x6099CE0

# Sites analysed in this packet (DBOptionsConfigurable ctor 0x60a47f0).
ANALYSED = {
    0x60A492A: "MutableDBOptions group (this packet)",
    0x60A50F2: "ImmutableDBOptions group (this packet)",
}
# Sites analysed by #3257.
PRIOR = {
    0x60DB9DB: "BlockTableOptions group (#3257)",
    0x60644FC: "SkipListFactoryOptions group (#3257)",
    0x5FD0124: "empty-key group (#3257)",
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

    literals = [
        "address\tbytes\tmeaning",
        "0x4541e0\tMutableDBOptions\tgroup-name literal, 16 bytes (first RegisterOptions arg string)",
        "0x450aa0\tImmutableDBOptio\tgroup-name literal chunk 1, 16 bytes (movdqa at 0x60a50aa)",
        "0x60a50c9\t0x736e (\"ns\")\tgroup-name chunk 2, 2-byte immediate mov at buffer+16 (completes ImmutableDBOptions)",
        "0x6506dc0\t-\tMutableDBOptions OptionTypeInfo map, 19 entries (#4237)",
        "0x6506d80\t-\tDBOptions (ImmutableDBOptions) OptionTypeInfo map, 81 entries (#4237)",
    ]
    (HERE / "literals.tsv").write_text("\n".join(literals) + "\n")

    frames_out = [
        "function\tfde_start\tfde_end",
        "0x60a47f0\t0x60a47f0\t0x60a636b",
        "0x6099ce0\t0x6099ce0\t0x6099e34",
        "0x6099790\t0x6099790\t0x6099cad",
    ]
    (HERE / "frames.txt").write_text("\n".join(frames_out) + "\n")
    print(f"wrote callers.tsv ({len(sites)} sites), literals.tsv, frames.txt")


if __name__ == "__main__":
    main()
