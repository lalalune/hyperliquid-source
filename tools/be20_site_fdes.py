#!/usr/bin/env python3
"""Deterministic generator for RE-004-be20-site-fdes-94.

Verifies, against node #94 only, that the 35 panic-Location citation
sites from #179 (RE-004-be20-location-run-94) fall into 11 .eh_frame
FDEs, and that the 13 continuation sites plus entry 11's site share
one FDE (0x4e79b00..0x4e7a541). Writes only to --out.

Method notes:
- FDE ranges come from a full .eh_frame record walk (CIE/FDE
  parsing), NOT from the .eh_frame_hdr binary search table: the
  table's table_enc is datarel (0x3b), so a naive pcrel read of
  its entries yields wrong starts. The record walk is checked
  against itself (121299 FDEs, zero overlaps).
- Code address A maps to file offset A - 0x1000 (.text);
  .data.rel.ro uses VA - 0x2000 (not needed here, sites are code).
- The sites' 7-byte lea encodings are #179's subject: they are
  re-verified here as a precondition of the assignment, but they
  are NOT re-claimed. Only the funnel block bytes (minus the
  interleaved entry-11 lea) are claimed as segments.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

NODE_SIZE = 91774280
NODE_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
RUN_BASE = 0x574BF38
RUN_STRIDE = 0x18

# site, entry, reg, follow, target -- site/entry/reg/follow/target
# reproduce #179 sites.tsv verbatim (its subject, not re-claimed).
SITES = [
    (0x4E77E70, 0, "rdx", "indirect", 0x576E468),
    (0x4E7851F, 1, "rdi", "indirect", 0x576E1B0),
    (0x4E7852C, 2, "rdi", "indirect", 0x576E118),
    (0x4E78A87, 3, "rcx", "indirect", 0x576E2E0),
    (0x4E7A441, 4, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A44A, 5, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A4B6, 6, "rdi", "fallthrough-cont", 0x4E7A4BD),
    (0x4E7A4AD, 7, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A453, 8, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A492, 9, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A489, 10, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A4CE, 11, "rdi", "indirect", 0x576E150),
    (0x4E7A46E, 12, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A477, 13, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A49B, 14, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A480, 15, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A4A4, 16, "rdi", "jmp-cont", 0x4E7A4BD),
    (0x4E7A465, 17, "rdi", "jmp-cont", 0x4E7A4C6),
    (0x4E79AEE, 18, "rdi", "indirect", 0x576E150),
    (0x4E7A5EA, 19, "rdi", "indirect", 0x576E118),
    (0x4E7A819, 19, "rdi", "indirect", 0x576E118),
    (0x4E7B0AE, 19, "rdi", "indirect", 0x576E118),
    (0x4E7A5F7, 20, "rdi", "indirect", 0x576E150),
    (0x4E7A826, 20, "rdi", "indirect", 0x576E150),
    (0x4E7B0BB, 20, "rdi", "indirect", 0x576E150),
    (0x4E7A5DD, 21, "rdi", "indirect", 0x576E118),
    (0x4E7A7FF, 21, "rdi", "indirect", 0x576E118),
    (0x4E7B094, 21, "rdi", "indirect", 0x576E118),
    (0x4E7A80C, 22, "rdi", "indirect", 0x576E150),
    (0x4E7AB2E, 22, "rdi", "indirect", 0x576E150),
    (0x4E7B0A1, 22, "rdi", "indirect", 0x576E150),
    (0x4E7B475, 22, "rdi", "indirect", 0x576E150),
    (0x4E7AC5E, 23, "rdi", "indirect", 0x576E118),
    (0x4E7AC4B, 24, "rcx", "indirect", 0x576E2E0),
    (0x4E7B482, 25, "rdi", "indirect", 0x576E118),
]

# fde_start, fde_end -- the 11 enclosing FDEs (this packet's claim).
FDES = [
    (0x4E77AE0, 0x4E77E8F),
    (0x4E77E90, 0x4E78653),
    (0x4E786A0, 0x4E78B7F),
    (0x4E798E0, 0x4E79AFB),
    (0x4E79B00, 0x4E7A541),
    (0x4E7A550, 0x4E7A604),
    (0x4E7A610, 0x4E7A833),
    (0x4E7A990, 0x4E7AB3B),
    (0x4E7AB40, 0x4E7AC6B),
    (0x4E7AE70, 0x4E7B0C8),
    (0x4E7B210, 0x4E7B48F),
]

# name, start, end -- claimed segments (funnel block only; the
# interleaved entry-11 lea 0x4e7a4ce..0x4e7a4d5 is excluded).
SEGMENTS = [
    ("funnel-head", 0x4E7A4BD, 0x4E7A4CE),
    ("entry11-follow", 0x4E7A4D5, 0x4E7A4E6),
]

LEA_OP = {"rdi": bytes([0x48, 0x8D, 0x3D]),
          "rcx": bytes([0x48, 0x8D, 0x0D]),
          "rdx": bytes([0x48, 0x8D, 0x15])}


def fail(msg):
    raise SystemExit("be20_site_fdes: FAIL: " + msg)


def uleb(buf, off):
    r = 0
    s = 0
    while True:
        b = buf[off]
        off += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            break
        s += 7
    return r, off


def sleb(buf, off):
    r = 0
    s = 0
    while True:
        b = buf[off]
        off += 1
        r |= (b & 0x7F) << s
        s += 7
        if not (b & 0x80):
            if b & 0x40:
                r -= 1 << s
            break
    return r, off


def read_enc(buf, off, enc, base):
    fmt = enc & 0x0F
    if fmt == 0x01:
        v, off = uleb(buf, off)
    elif fmt == 0x02:
        v, off = struct.unpack_from("<H", buf, off)[0], off + 2
    elif fmt == 0x03:
        v, off = struct.unpack_from("<I", buf, off)[0], off + 4
    elif fmt == 0x04:
        v, off = struct.unpack_from("<Q", buf, off)[0], off + 8
    elif fmt == 0x09:
        v, off = sleb(buf, off)
    elif fmt == 0x0A:
        v, off = struct.unpack_from("<h", buf, off)[0], off + 2
    elif fmt == 0x0B:
        v, off = struct.unpack_from("<i", buf, off)[0], off + 4
    elif fmt == 0x0C:
        v, off = struct.unpack_from("<q", buf, off)[0], off + 8
    else:
        fail("unsupported DW_EH_PE format %#x" % fmt)
    if enc & 0x10:
        v += base
    return v, off


def skip_enc(buf, off, enc):
    """Advance past one encoded value without interpreting it."""
    fmt = enc & 0x0F
    if fmt == 0x01:
        _, off = uleb(buf, off)
    elif fmt == 0x02:
        off += 2
    elif fmt == 0x03:
        off += 4
    elif fmt == 0x04:
        off += 8
    elif fmt == 0x09:
        _, off = sleb(buf, off)
    elif fmt == 0x0A:
        off += 2
    elif fmt == 0x0B:
        off += 4
    elif fmt == 0x0C:
        off += 8
    else:
        fail("unsupported DW_EH_PE format %#x" % fmt)
    return off


def find_eh_frame(data):
    if data[:4] != b"\x7fELF":
        fail("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        fail("expected 64-bit little-endian ELF")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    if e_shoff == 0 or e_shnum == 0:
        fail("no section headers")
    shstr = e_shoff + e_shstrndx * e_shentsize
    str_off = struct.unpack_from("<Q", data, shstr + 0x18)[0]
    for i in range(e_shnum):
        so = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", data, so)[0]
        end = data.index(b"\x00", str_off + name_off)
        name = data[str_off + name_off:end].decode()
        if name == ".eh_frame":
            return struct.unpack_from("<Q", data, so + 0x18)[0]
    fail(".eh_frame section not found")


def parse_fdes(data, eh_off):
    cies = {}
    fdes = []
    off = eh_off
    while True:
        if off + 8 > len(data):
            fail("truncated .eh_frame")
        ln = struct.unpack_from("<I", data, off)[0]
        if ln == 0:
            break
        if ln == 0xFFFFFFFF:
            ln = struct.unpack_from("<Q", data, off + 4)[0]
            hdr = 12
        else:
            hdr = 4
        cie_ptr = struct.unpack_from("<I", data, off + hdr)[0]
        rec_end = off + hdr + ln
        if cie_ptr == 0:
            p = off + hdr + 4
            p += 1  # version
            aug = bytearray()
            while data[p] != 0:
                aug.append(data[p])
                p += 1
            p += 1
            _, p = uleb(data, p)
            _, p = sleb(data, p)
            _, p = uleb(data, p)
            fde_enc = 0x00
            if aug.startswith(b"z"):
                alen, p = uleb(data, p)
                ap = p
                q = ap
                for ch in aug[1:]:
                    if ch == 0x52:  # 'R'
                        fde_enc = data[q]
                        q += 1
                    elif ch == 0x50:  # 'P'
                        penc = data[q]
                        q += 1
                        q = skip_enc(data, q, penc)
                    elif ch in (0x4C, 0x42, 0x47):  # 'L', 'B', 'G'
                        q += 1
                p = ap + alen
            cies[off] = fde_enc
        else:
            cie_off = off + hdr - cie_ptr
            enc = cies.get(cie_off)
            if enc is None:
                fail("FDE references unknown CIE at %#x" % cie_off)
            p = off + hdr + 4
            init, p = read_enc(data, p, enc, p)
            rng, p = read_enc(data, p, enc & 0x0F, p)
            fdes.append((init, init + rng))
        off = rec_end
    return fdes


def code(data, va, ln):
    return data[va - 0x1000:va - 0x1000 + ln]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--node", default=None)
    args = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    node_path = Path(args.node) if args.node else root / "artifacts" / "node" / "94" / "hl-node"
    data = node_path.read_bytes()
    if len(data) != NODE_SIZE:
        fail("node size %d != %d" % (len(data), NODE_SIZE))
    if hashlib.sha256(data).hexdigest() != NODE_SHA256:
        fail("node digest mismatch")

    # 1. Full .eh_frame walk: FDE count, overlap, exact ranges.
    fdes = parse_fdes(data, find_eh_frame(data))
    if len(fdes) != 121299:
        fail("FDE count %d != 121299" % len(fdes))
    fdes.sort()
    for i in range(len(fdes) - 1):
        if fdes[i][1] > fdes[i + 1][0]:
            fail("overlapping FDEs at %#x" % fdes[i][0])
    fset = set(fdes)
    for st, en in FDES:
        if (st, en) not in fset:
            fail("FDE %#x..%#x not found in .eh_frame" % (st, en))
    import bisect
    starts = [f[0] for f in fdes]

    # 2. Each site: lea encoding + follow shape + enclosing FDE.
    rows = []
    gaps = []
    for site, entry, reg, follow, target in SITES:
        entry_va = RUN_BASE + RUN_STRIDE * entry
        lb = code(data, site, 7)
        if lb[:3] != LEA_OP[reg]:
            fail("site %#x lea opcode mismatch" % site)
        disp = struct.unpack_from("<i", lb, 3)[0]
        if site + 7 + disp != entry_va:
            fail("site %#x lea resolves to %#x, not entry %#x"
                 % (site, site + 7 + disp, entry_va))
        if follow == "indirect":
            # First ff 15 (call [rip+disp32]) within 24 bytes after the
            # lea must resolve to the recorded GOT slot. Most sites
            # call immediately (gap 0); four sites set up arguments
            # first: entry 0 (mov esi,0xf, gap 5), entry 3 (mov/xor
            # setup, gap 9), entry 11 (restore pair, gap 9),
            # entry 24 (register moves, gap 6).
            window = code(data, site + 7, 24)
            idx = None
            for i in range(len(window) - 5):
                if window[i] == 0xFF and window[i + 1] == 0x15:
                    idx = i
                    break
            if idx is None:
                fail("site %#x has no indirect call within 24 bytes" % site)
            fdisp = struct.unpack_from("<i", window, idx + 2)[0]
            call_at = site + 7 + idx
            if call_at + 6 + fdisp != target:
                fail("site %#x GOT resolves to %#x, not %#x"
                     % (site, call_at + 6 + fdisp, target))
            gap = idx
            gaps.append(gap)
        elif follow == "jmp-cont":
            fb = code(data, site + 7, 2)
            if fb[0] != 0xEB:
                fail("site %#x follow is not jmp rel8" % site)
            rel = fb[1] if fb[1] < 0x80 else fb[1] - 0x100
            if site + 9 + rel != target:
                fail("site %#x jmp resolves to %#x, not %#x"
                     % (site, site + 9 + rel, target))
        elif follow == "fallthrough-cont":
            if site + 7 != target:
                fail("site %#x fallthrough does not reach %#x" % (site, target))
        else:
            fail("unknown follow %r" % follow)
        i = bisect.bisect_right(starts, site) - 1
        fst, fen = fdes[i]
        if not (fst <= site < fen):
            fail("site %#x outside FDE %#x..%#x" % (site, fst, fen))
        rows.append((site, entry, reg, follow, target, fst, fen))

    # 3. Funnel anatomy (checked, only the two segments are claimed).
    if code(data, 0x4E7A45C, 9) != bytes.fromhex("488b1c244c8b742408"):
        fail("entry-17 inline restore pair mismatch")
    if code(data, 0x4E7A4CE, 7) != bytes.fromhex("488d3d6b1b8d00"):
        fail("entry-11 lea boundary mismatch (excluded bytes)")
    seg_rows = []
    for name, st, en in SEGMENTS:
        b = code(data, st, en - st)
        seg_rows.append((name, st, en, en - st, st - 0x1000,
                         hashlib.sha256(b).hexdigest(), "claim"))

    # 4. Per-FDE site counts and entry multi-FDE map.
    from collections import Counter, defaultdict
    fde_counts = Counter((fst, fen) for (_, _, _, _, _, fst, fen) in rows)
    entry_fdes = defaultdict(set)
    for (_, entry, _, _, _, fst, fen) in rows:
        entry_fdes[entry].add((fst, fen))
    fde_rows = []
    for st, en in FDES:
        ents = sorted(e for e in range(26)
                      if any(r[1] == e and r[5] == st and r[6] == en for r in rows))
        fde_rows.append((st, en, en - st, fde_counts[(st, en)],
                         ";".join(str(e) for e in ents)))
    if sum(fde_counts.values()) != 35:
        fail("site total %d != 35" % sum(fde_counts.values()))
    if len(fde_rows) != 11:
        fail("FDE total %d != 11" % len(fde_rows))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "sites.tsv", "w") as f:
        f.write("site\tentry\treg\tfollow\ttarget\tfde_start\tfde_end\n")
        for r in rows:
            f.write("0x%x\t%d\t%s\t%s\t0x%x\t0x%x\t0x%x\n" % r)
    with open(out / "fdes.tsv", "w") as f:
        f.write("fde_start\tfde_end\tsize\tsite_count\tentries\n")
        for r in fde_rows:
            f.write("0x%x\t0x%x\t%d\t%d\t%s\n" % r)
    with open(out / "segments.txt", "w") as f:
        for r in seg_rows:
            f.write("%s\t0x%x\t0x%x\t%d\t0x%x\t%s\t%s\n" % r)
    evidence = {
        "node": {"id": 94, "size": NODE_SIZE, "sha256": NODE_SHA256},
        "method": ".eh_frame record walk (CIE/FDE parse); hdr search table "
                  "not used (its table_enc is datarel)",
        "fde_total": 121299,
        "fde_overlaps": 0,
        "sites": 35,
        "fdes": 11,
        "fde_site_counts": {("0x%x..0x%x" % (st, en)): c
                            for (st, en), c in sorted(fde_counts.items())},
        "multi_fde_entries": {str(e): len(v) for e, v in sorted(entry_fdes.items())
                              if len(v) > 1},
        "registers": dict(Counter(r[2] for r in rows)),
        "follows": dict(Counter(r[3] for r in rows)),
        "got_histogram": dict(Counter("0x%x" % r[4] for r in rows
                                      if r[3] == "indirect")),
        "indirect_gaps": dict(Counter(gaps)),
        "segments": [{"name": r[0], "start": "0x%x" % r[1], "end": "0x%x" % r[2],
                      "length": r[3], "kind": r[6]} for r in seg_rows],
        "claim_bytes": sum(r[3] for r in seg_rows),
        "anchors": 0,
    }
    with open(out / "evidence.json", "w") as f:
        json.dump(evidence, f, indent=2, sort_keys=True)
        f.write("\n")
    print("be20_site_fdes: OK (%d sites, %d FDEs, %d segments)"
          % (len(rows), len(fde_rows), len(seg_rows)))


if __name__ == "__main__":
    main()
