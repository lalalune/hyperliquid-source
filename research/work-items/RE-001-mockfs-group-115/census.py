#!/usr/bin/env python3
"""Caller census and frame/literal/vtable tables for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-mockfs-group-115/census.py

Regenerates callers.tsv (every direct E8 call site of RegisterOptions
0x6099ce0, with its enclosing FDE), literals.tsv (the supports_direct_io
map and its binary-wide lea sites, the MockFileSystem typeinfo string,
and the two sibling EmulatedSystemClock maps for context), frames.txt
(FDE ranges for the cited functions) and vtables.tsv (the 61
MockFileSystem vtable slots, read from the .rela.dyn RELATIVE
relocations — the file bytes there are zero; the relocations carry the
values). The 37-site census must match #3257, #4372, #4551 and #4565,
which published it before.
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

# The site analysed in this packet (MockFileSystem ctor 0x6028a60).
ANALYSED = {
    0x6028B3A: "supports_direct_io group (this packet)",
}
# Sites analysed by earlier packets (open PRs marked as such).
PRIOR = {
    0x5FD0124: "empty-key group (#3257)",
    0x5FD73CB: "CompositeEnvWrapper target group (#4379, open)",
    0x5FD73F1: "CompositeEnvWrapper file_system group (#4379, open)",
    0x5FD7417: "CompositeEnvWrapper clock group (#4379, open)",
    0x5FE7292: "FileSystemWrapper wrapped-FS group (#4398, open)",
    0x5FEEB6A: "chroot_dir group (#4565, open)",
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

# The supports_direct_io map, the MockFileSystem vtable base, the
# key literal, and the two sibling EmulatedSystemClock maps (#4528).
LEA_TARGETS = {
    0x65058E0: "supports_direct_io OptionTypeInfo map",
    0x64D19F8: "MockFileSystem vtable base (address point 0x64d1a08)",
    0x44657E: "supports_direct_io key literal",
    0x6505960: "time_elapse_only_sleep map (#4528)",
    0x6505920: "mock_sleep map (#4528)",
}

# Direct E8 caller sets asserted by this packet.
CALLERS = {
    0x6028A60: [0x5FE58DA, 0x6028DDB],  # invoker 0x5fe58b0, MockEnv::Create
    0x6028D80: [0x602982A],            # MockEnv::Create(Env*) 0x60297a0
    0x5FE58B0: [],                     # invoker: vtable-reachable only
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


def load_relocs(data: bytes) -> dict[int, tuple[int, int]]:
    """Parse .rela.dyn (offset 0x6be8, 24-byte entries)."""
    relocs = {}
    base, count = 0x6BE8, 0x163CC8 // 24
    for i in range(count):
        off, info, add = struct.unpack_from("<QQq", data, base + i * 24)
        relocs[off] = (info & 0xFFFFFFFF, add)
    return relocs


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
    assert lea[0x65058E0] == [0x6028B16, 0x602A17B], \
        f"map 0x65058e0 lea sites: {lea[0x65058E0]}"
    assert lea[0x64D19F8] == [0x6028A8F, 0x6028BB4], \
        f"vtable-base lea sites: {lea[0x64D19F8]}"
    assert lea[0x44657E] == [0x602A093], \
        f"key literal lea sites: {lea[0x44657E]}"
    assert lea[0x6505960] == [0x602942B, 0x6029E50], \
        f"time_elapse map lea sites: {lea[0x6505960]}"
    assert lea[0x6505920] == [0x6029471, 0x6029FE0], \
        f"mock_sleep map lea sites: {lea[0x6505920]}"

    callers = {t: scan_callers(data, t) for t in CALLERS}
    for target, want in CALLERS.items():
        assert callers[target] == want, \
            f"callers of {target:#x}: {[hex(s) for s in callers[target]]}"

    literals = [
        "address\tbytes\tmeaning",
        "0x65058e0\t-\tsupports_direct_io OptionTypeInfo map, exactly 1 entry (this packet); lea sites 0x6028b16 (host ctor, RegisterOptions arg) and 0x602a17b (static initializer 0x6029d10, insert arg)",
        "0x64d19f8\t-\tMockFileSystem vtable base; address point 0x64d1a08 (typeinfo N7rocksdb14MockFileSystemE at 0x64d1210, name string at 0x974450); lea sites 0x6028a8f (host ctor) and 0x6028bb4 (dtor 0x6028bb0)",
        "0x44657e\tsupports_direct_io\tsupports_direct_io key literal, 18 bytes; sole lea site 0x602a093 (static initializer 0x6029d10)",
        "0x974450\tN7rocksdb14MockFileSystemE\tMockFileSystem typeinfo name, 26 bytes (via RELATIVE reloc at typeinfo+8)",
        "0x6505960\t-\ttime_elapse_only_sleep map (open PR #4528); lea sites 0x602942b (EmulatedSystemClock ctor 0x6029390, RegisterOptions arg) and 0x6029e50 (initializer, insert arg)",
        "0x6505920\t-\tmock_sleep map (open PR #4528); lea sites 0x6029471 (EmulatedSystemClock ctor 0x6029390, RegisterOptions arg) and 0x6029fe0 (initializer, insert arg)",
    ]
    (HERE / "literals.tsv").write_text("\n".join(literals) + "\n")

    # MockFileSystem vtable slots from .rela.dyn RELATIVE relocations.
    relocs = load_relocs(data)
    tip = relocs.get(0x64D1A00, (None, None))[1]
    assert tip == 0x64D1210, f"typeinfo object: {tip:#x}"
    name_addr = relocs.get(tip + 8, (None, None))[1]
    assert data[name_addr:name_addr + 26] == b"N7rocksdb14MockFileSystemE", \
        "typeinfo name mismatch"
    assert relocs.get(0x64D19F8) is None, "offset-to-top must have no reloc"
    slots = []
    addr = 0x64D1A08
    while True:
        r = relocs.get(addr)
        if not r or r[0] != 8:
            break
        slots.append((addr, r[1]))
        addr += 8
    assert len(slots) == 61, f"expected 61 vtable slots, got {len(slots)}"
    fde_starts = {s for s, _ in fdes}
    vrows = ["slot\taddress\ttarget\tfde_start"]
    for i, (addr, target) in enumerate(slots):
        assert target in fde_starts, f"slot {i} target {target:#x} is no FDE start"
        vrows.append(f"{i}\t{addr:#x}\t{target:#x}\t{target in fde_starts}")
    (HERE / "vtables.tsv").write_text("\n".join(vrows) + "\n")

    frames_out = [
        "function\tfde_start\tfde_end",
        "0x6028a60\t0x6028a60\t0x6028ba4",
        "0x6028a0e\t0x6028a0e\t0x6028a5d",
        "0x6029d10\t0x6029d10\t0x602a25d",
        "0x5fe58b0\t0x5fe58b0\t0x5fe590c",
        "0x6028bb0\t0x6028bb0\t0x6028cea",
        "0x6028d80\t0x6028d80\t0x6028e80",
        "0x60297a0\t0x60297a0\t0x60298f7",
        "0x60289f0\t0x60289f0\t0x6028a0d",
        "0x5fe7080\t0x5fe7080\t0x5fe70ab",
        "0x5fe70b0\t0x5fe70b0\t0x5fe7135",
        "0x6099ce0\t0x6099ce0\t0x6099e34",
        "0x5d400f0\t0x5d400f0\t0x5d40477",
        "0x5d405b0\t0x5d405b0\t0x5d40f32",
        "0x5d3f950\t0x5d3f950\t0x5d3f9d3",
        "0x5d3f820\t0x5d3f820\t0x5d3f94d",
        "0x5e32920\t0x5e32920\t0x5e32b06",
        "0x60261f0\t0x60261f0\t0x60262c0",
        "0x60d50c0\t0x60d50c0\t0x60d5157",
        "0x60d5170\t0x60d5170\t0x60d5200",
        "0x60d5230\t0x60d5230\t0x60d52c5",
        "0x60d52f0\t0x60d52f0\t0x60d5385",
        "0x6027720\t0x6027720\t0x6027a7d",
        "0x5fe2680\t0x5fe2680\t0x5fe2756",
        "0x6029390\t0x6029390\t0x60294f5",
        "0x5fd7360\t0x5fd7360\t0x5fd7466",
    ]
    for row in frames_out[1:]:
        _, s, e = row.split("\t")
        assert (int(s, 16), int(e, 16)) in fdes, f"FDE mismatch: {row}"
    (HERE / "frames.txt").write_text("\n".join(frames_out) + "\n")
    print(f"wrote callers.tsv ({len(sites)} sites), literals.tsv, "
          f"vtables.tsv ({len(slots)} slots), frames.txt")
    for t, ss in lea.items():
        print(f"  lea {t:#x}: {[hex(s) for s in ss]}")
    for t, ss in callers.items():
        print(f"  callers {t:#x}: {[hex(s) for s in ss]}")


if __name__ == "__main__":
    main()
