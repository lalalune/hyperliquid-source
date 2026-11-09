#!/usr/bin/env python3
"""Caller census and frame/literal tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-chrootfs-group-115/census.py

Regenerates callers.tsv (every direct E8 call site of RegisterOptions
0x6099ce0, with its enclosing FDE), literals.tsv (the chroot_dir map
and its binary-wide lea sites, plus the ChrootFileSystem typeinfo
string) and frames.txt (FDE ranges for the cited functions). The
37-site census must match #3257 (RE-001-record-pushback-115), #4372
and #4551, which published it before.
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

# The site analysed in this packet (ChrootFileSystem ctor 0x5feeab0).
ANALYSED = {
    0x5FEEB6A: "chroot_dir group (this packet)",
}
# Sites analysed by earlier packets (open PRs marked as such).
PRIOR = {
    0x5FD0124: "empty-key group (#3257)",
    0x5FD73CB: "CompositeEnvWrapper target group (#4379, open)",
    0x5FD73F1: "CompositeEnvWrapper file_system group (#4379, open)",
    0x5FD7417: "CompositeEnvWrapper clock group (#4379, open)",
    0x5FE7292: "FileSystemWrapper wrapped-FS group (#4398, open)",
    0x5FF677E: "EncryptedFileSystemImpl factory group (#4395, open)",
    0x5FF6926: "CTREncryptionProvider holder group (#4395, open)",
    0x5FF6AF6: "CTR provider factory group (#4395, open)",
    0x5FF6E51: "ROT13 provider factory group (#4395, open)",
    0x5FF7279: "ROT13BlockCipher block_size group (#4389, open)",
    0x5FF7377: "ROT13BlockCipher group (#4389, open)",
    0x5FFACEE: "encryption-provider dispatch factory group (#4402, open)",
    0x6029454: "EmulatedSystemClock group (merged systemclock installers)",
    0x6029494: "EmulatedSystemClock group (merged systemclock installers)",
    0x60644FC: "SkipListFactoryOptions group (#3257)",
    0x60A492A: "MutableDBOptions group (#4372, open)",
    0x60A50F2: "ImmutableDBOptions group (#4372, open)",
    0x608749A: "MutableCFOptions group (#4551, open)",
    0x6087CE8: "ImmutableCFOptions group (#4551, open)",
    0x60DB9DB: "BlockTableOptions group (#3257)",
    0x6202AA4: "TTL group (merged #4065)",
    0x6202AFC: "TTL group (merged #4065)",
    0x620561A: "TTL group (merged #4065)",
    0x6205847: "TTL group (merged #4065)",
    0x6205895: "TTL group (merged #4065)",
}

# The chroot_dir map and the ChrootFileSystem vtable base.
LEA_TARGETS = {
    0x6505240: "chroot_dir OptionTypeInfo map",
    0x64CF468: "ChrootFileSystem vtable base (address point 0x64cf478)",
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
    assert lea[0x6505240] == [0x5FEEB46, 0x5FEF1CA], \
        f"map 0x6505240 lea sites: {lea[0x6505240]}"
    assert lea[0x64CF468] == [0x5FEEADD, 0x5FEEC1D, 0x5FEECFD], \
        f"vtable-base lea sites: {lea[0x64CF468]}"

    literals = [
        "address\tbytes\tmeaning",
        "0x6505240\t-\tchroot_dir OptionTypeInfo map, exactly 1 entry (this packet); lea sites 0x5feeb46 (host ctor, RegisterOptions arg) and 0x5fef1ca (static initializer 0x5fef080, insert arg)",
        "0x64cf468\t-\tChrootFileSystem vtable base; address point 0x64cf478 (typeinfo N7rocksdb16ChrootFileSystemE at 0x64cf450, RE-002-node115-rocksdb-fs-chroot-vtable); lea sites 0x5feeadd (host ctor), 0x5feec1d (dtor 0x5feec10), 0x5feecfd (0x5feecf0, cited only)",
        "0x9732f0\tN7rocksdb16ChrootFileSystemE\tChrootFileSystem typeinfo name, 28 bytes",
    ]
    (HERE / "literals.tsv").write_text("\n".join(literals) + "\n")

    frames_out = [
        "function\tfde_start\tfde_end",
        "0x5feeab0\t0x5feeab0\t0x5feec0d",
        "0x5fef080\t0x5fef080\t0x5fef25f",
        "0x5fe7870\t0x5fe7870\t0x5fe79ab",
        "0x6099ce0\t0x6099ce0\t0x6099e34",
        "0x5fe7210\t0x5fe7210\t0x5fe72e8",
        "0x5fe7080\t0x5fe7080\t0x5fe70ab",
        "0x60072b0\t0x60072b0\t0x60072cd",
        "0x5d400f0\t0x5d400f0\t0x5d40477",
        "0x5d405b0\t0x5d405b0\t0x5d40f32",
        "0x5d3f950\t0x5d3f950\t0x5d3f9d3",
    ]
    (HERE / "frames.txt").write_text("\n".join(frames_out) + "\n")
    print(f"wrote callers.tsv ({len(sites)} sites), literals.tsv, frames.txt")
    for t, ss in lea.items():
        print(f"  lea {t:#x}: {[hex(s) for s in ss]}")


if __name__ == "__main__":
    main()
