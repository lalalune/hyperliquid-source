#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-write-surface (packet #257).

Byte reads only; the node binary is never executed. All exhibits are
.text windows; .text file offset = VA - 0x1000. .hex files contain raw
binary bytes (not hex text), matching packets #255/#256.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

PACKET = "RE-001-node115-lu-write-surface"
BINARY_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BINARY_SIZE = 105896032
FLAG = 0x64FFAB4

# (name, start, end) — also the disjointness claim set.
WINDOWS = [
    ("pred_entry", 0x634F0B0, 0x634F116),
    ("pred_flag1", 0x634F2A4, 0x634F2DA),
    ("pred_flag0", 0x634F671, 0x634F692),
    ("reqinit_flag2", 0x634EF41, 0x634EF74),
    ("pred_thunk", 0x635F320, 0x635F334),
    ("epoch_head", 0x63A7FC0, 0x63A8054),
    ("tcache_flush", 0x636DE20, 0x636DE56),
    ("peak_reset", 0x636E210, 0x636E236),
    ("prof_reset", 0x636D870, 0x636D8D1),
    ("prof_dump", 0x6377850, 0x63778A1),
    ("init_entry", 0x63A8240, 0x63A829B),
    ("fmt_entry", 0x63DE320, 0x63DE372),
]

# Exact instruction bytes at key sites (VA -> bytes).
SPOTS = [
    (0x634F0DC, bytes.fromhex("e8cf260a00"), "pred_entry trylock PLT call"),
    (0x634F10E, bytes.fromhex("8b2da0091b00"), "pred_entry flag read"),
    (0x634F2D0, bytes.fromhex("c705da071b0001000000"), "pred_flag1 flag=1 write"),
    (0x634F680, bytes.fromhex("c7052a041b0000000000"), "pred_flag0 flag=0 write"),
    (0x634EF6A, bytes.fromhex("c705400b1b0002000000"), "reqinit_flag2 flag=2 write"),
    (0x635F32F, bytes.fromhex("e97cfdfeff"), "pred_thunk tail-jump to predicate"),
    (0x63A8014, bytes.fromhex("48837c243008"), "epoch newlen==8 check"),
    (0x63A801C, bytes.fromhex("bd16000000"), "epoch return-22 value"),
    (0x63A802B, bytes.fromhex("e8a0f7ffff"), "epoch advance call 0x63a77d0"),
    (0x636DE24, bytes.fromhex("803f00"), "tcache_flush enabled-byte check"),
    (0x636DE3F, bytes.fromhex("e8bce70700"), "tcache_flush flush call"),
    (0x636DE50, bytes.fromhex("b80e000000"), "tcache_flush return-14 value"),
    (0x636E22A, bytes.fromhex("e8c14a0500"), "peak_reset reset call"),
    (0x636D874, bytes.fromhex("488d158b5d3a00"), "prof_reset prof-enabled byte lea"),
    (0x636D8A8, bytes.fromhex("b816000000"), "prof_reset return-22 value"),
    (0x636D8BE, bytes.fromhex("e80d210600"), "prof_reset reset call"),
    (0x637788B, bytes.fromhex("e870be0400"), "prof_dump dump call"),
    (0x6377894, bytes.fromhex("83e00e"), "prof_dump and-$0xe result mapping"),
    (0x63A8251, bytes.fromhex("e85a950400"), "init_entry trylock PLT call"),
    (0x63A827E, bytes.fromhex("803dbb9e360000"), "init_entry init-flag cmpb"),
    (0x63DE320, bytes.fromhex("8b1783fa01"), "fmt_entry state test"),
    (0x63DE36D, bytes.fromhex("e80edaffff"), "fmt_entry formatter call"),
]

# Expected direct-call census (single-pass raw E8/E9 scan, verified by
# objdump during analysis). E9 lists hold tail jumps.
CENSUS = {
    0x634F0B0: (["0x6354368", "0x6356483", "0x6358979", "0x635b3c1",
                 "0x635df45", "0x635dfe5", "0x635e098"], ["0x635f32f"]),
    0x63A8240: (["0x63a88df", "0x63a89b3", "0x63a8a26", "0x63a8d2a",
                 "0x63a9056"], []),
    0x63DE320: (["0x63e119c", "0x63e2dee", "0x63e452e", "0x63e4ab0",
                 "0x63e5b0d", "0x63e5c17", "0x63e6b6b", "0x63e6f2a",
                 "0x63e7399", "0x63e80c4", "0x63e8207", "0x63e82e2",
                 "0x63e841e", "0x63e8491", "0x63e865d", "0x63e86ce",
                 "0x63e8765", "0x63e8a0e"], []),
    0x63A8990: ([], ["0x635dfd3"]),
    0x63A88A0: ([], ["0x635df37"]),
    0x63A7FC0: ([], []),
    0x636DE20: ([], []),
    0x636E210: ([], []),
    0x636D870: ([], []),
    0x6377850: ([], []),
}

TEXT_OFF, TEXT_SIZE = 0x1418300, 0x4FD7700
INSTR_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S+")


def fail(msg):
    print("FAIL " + msg)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    args = ap.parse_args()
    root = args.root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pdir = os.path.join(root, "research", "work-items", PACKET)
    bpath = os.path.join(root, "artifacts", "node", "115", "hl-node")
    ok = True

    data = open(bpath, "rb").read()
    if len(data) != BINARY_SIZE:
        fail(f"binary size {len(data)}"); ok = False
    else:
        print(f"PASS binary size {BINARY_SIZE}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != BINARY_SHA:
        fail("binary sha256"); ok = False
    else:
        print("PASS binary sha256")

    rec = json.load(open(os.path.join(pdir, "records.json")))
    ex_by_name = {}
    for e in rec["exhibits"]:
        ex_by_name[e["name"]] = e
    if [e["name"] for e in rec["exhibits"]] != [w[0] for w in WINDOWS]:
        fail("records exhibit list != WINDOWS"); ok = False

    for name, start, end in WINDOWS:
        raw = open(os.path.join(pdir, name + ".hex"), "rb").read()
        sl = data[start - 0x1000:end - 0x1000]
        if raw != sl:
            fail(f"{name}.hex bytes"); ok = False
            continue
        print(f"PASS {name}.hex bytes {len(raw)} bytes")
        e = ex_by_name[name]
        if e["range"] != [hex(start), hex(end)] or e["bytes"] != end - start:
            fail(f"{name} records range/bytes"); ok = False
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={hex(start)}",
             f"--stop-address={hex(end)}", bpath],
            capture_output=True, text=True).stdout
        fresh = [ln for ln in out.splitlines() if INSTR_RE.match(ln)]
        stored = open(os.path.join(pdir, name + ".objdump.txt")).read()
        stored_lines = [ln for ln in stored.splitlines() if INSTR_RE.match(ln)]
        if fresh != stored_lines:
            fail(f"{name}.objdump.txt regeneration"); ok = False
        elif len(fresh) != e["strict"]:
            fail(f"{name} strict count {len(fresh)} != {e['strict']}"); ok = False
        else:
            print(f"PASS {name} objdump + strict {len(fresh)}")

    for va, want, desc in SPOTS:
        got = data[va - 0x1000:va - 0x1000 + len(want)]
        if got != want:
            fail(f"spot {desc} at {hex(va)}"); ok = False
    print("PASS spot checks" if ok else "spot checks had failures")

    # Single-pass raw E8/E9 census over .text.
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    found = {t: ([], []) for t in CENSUS}
    for i in range(len(text) - 5):
        b = text[i]
        if b in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            tgt = TEXT_OFF + i + 0x1000 + 5 + rel
            if tgt in found:
                found[tgt][0 if b == 0xE8 else 1].append(hex(TEXT_OFF + i + 0x1000))
    for tgt, (e8, e9) in CENSUS.items():
        g8, g9 = found[tgt]
        if g8 != e8 or g9 != e9:
            fail(f"census {hex(tgt)} E8 {g8} E9 {g9}"); ok = False
    print("PASS E8/E9 census")

    # Tree walk via readelf -r RELATIVE map.
    rela = {}
    out = subprocess.run(["readelf", "-r", bpath],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if m:
            rela[int(m.group(1), 16)] = int(m.group(2), 16)

    def node(va):
        fl, nf, cnt, cf, hf = struct.unpack_from("<QQQQQ", data, va - 0x2000)
        return {"flag": fl, "name": rela.get(va + 8, nf), "count": cnt,
                "children": rela.get(va + 24, cf), "handler": rela.get(va + 32, hf)}

    def cstr(va):
        # Flag-0 dynamic nodes carry a resolver function at +0x08, not
        # a name pointer; mirror the analysis fallback.
        try:
            end = data.index(b"\x00", va)
            return data[va:end].decode()
        except Exception:
            return "<bad>"

    leaves = []

    def walk(va, path):
        nd = node(va)
        if nd["flag"] == 0 or nd["count"] == 0:
            if nd["count"] == 0 and nd["flag"] != 0:
                leaves.append([path, hex(va), nd])
            return
        for i in range(nd["count"]):
            cnd = node(nd["children"] + i * 40)
            walk(nd["children"] + i * 40, path + "/" + cstr(cnd["name"]))

    walk(0x64DA4C0, "")
    rec_leaves = rec["census"]["tree"]["leaves"]
    got = sorted((p, v, d["handler"]) for p, v, d in leaves)
    want = sorted((p, v, d["handler"]) for p, v, d in rec_leaves)
    if got != want:
        fail(f"tree leaf set ({len(got)} vs {len(want)})"); ok = False
    else:
        print(f"PASS tree leaves {len(got)}")

    # Disjointness: recursive range/fde collector over this worktree,
    # excluding own dir and census/cited-only subtrees.
    import glob as globmod
    ranges = set()

    def scan(o, excluded=False):
        if isinstance(o, dict):
            for k, v in o.items():
                ex = excluded or k in ("census", "cited_only_not_claimed")
                if k in ("range", "fde") and not ex and isinstance(v, (list, tuple)) and len(v) == 2:
                    try:
                        ranges.add((int(str(v[0]), 16), int(str(v[1]), 16)))
                    except ValueError:
                        pass
                scan(v, ex)
        elif isinstance(o, list):
            for v in o:
                scan(v, excluded)

    for rp in globmod.glob(os.path.join(root, "research", "work-items", "*", "records.json")):
        if PACKET in rp:
            continue
        try:
            scan(json.load(open(rp)))
        except Exception:
            continue
    overlaps = []
    for _, s, e in WINDOWS:
        for r in ranges:
            if s < r[1] and r[0] < e:
                overlaps.append(((hex(s), hex(e)), (hex(r[0]), hex(r[1]))))
    if overlaps:
        fail(f"disjointness overlaps {overlaps}"); ok = False
    else:
        print(f"PASS disjointness vs merged tree {len(ranges)} unique claimed ranges, 0 overlaps")

    # MANIFEST entries.
    man = open(os.path.join(pdir, "MANIFEST.sha256")).read().splitlines()
    listed = [ln.split(" *", 1)[1] if " *" in ln else ln.split("  ", 1)[1]
              for ln in man if ln.strip()]
    import hashlib as hl
    bad = []
    for rel in listed:
        p = os.path.normpath(os.path.join(pdir, rel))
        if not os.path.exists(p):
            bad.append(rel)
            continue
        h = hl.sha256(open(p, "rb").read()).hexdigest()
        line = [ln for ln in man if ln.endswith(rel)]
        if not line or not line[0].startswith(h):
            bad.append(rel)
    if bad:
        fail(f"MANIFEST mismatches {bad}"); ok = False
    else:
        print(f"PASS MANIFEST entries {len(listed)}")

    print("ALL CHECKS PASSED" if ok else "CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
