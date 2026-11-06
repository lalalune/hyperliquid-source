#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub-rsikey.

Byte reads only; never executes the target binary. Run from the repository root:
    python3 tools/node115_lu_bintableinit_caller_walk_rsp_locksub_rsikey_4sites.py
Exit 0 when every check passes, nonzero otherwise.
"""

import bisect
import hashlib
import json
import os
import re
import struct
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research", "work-items",
    "RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub-rsikey")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub-rsikey"
START, END = 0x63D5940, 0x63D605C
HEX_NAME = "bintableinit_caller_walk_rsp_locksub_rsikey_4sites.hex"
OBJ_NAME = "bintableinit_caller_walk_rsp_locksub_rsikey_4sites.objdump.txt"
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
CALL_RE = re.compile(r"\tcall\s+([0-9a-f]+)")
BSR_RE = re.compile(r"\tbsr\s")
RET_RE = re.compile(r"\tret\s*$")
LOCKSUB_RE = re.compile(r"\tlock sub\s")
SKIP_KEYS = {
    "census", "cited", "cited_not_claimed", "survey", "callers",
    "largest_caller_fde", "fde", "next_caller", "other_remaining_4raw_fdes",
    "raw_e8_ranking", "prior_pointer_verified", "scan", "walk", "entry",
    "exits", "gate_bytes", "size_class", "binary", "slug", "title", "packet",
}

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" ({detail})" if detail else ""))


def parse_int(v):
    if isinstance(v, int):
        return v
    return int(str(v), 16)


def parse_range(r):
    if isinstance(r, str):
        a, b = r.split("..")
        return parse_int(a), parse_int(b)
    return parse_int(r[0]), parse_int(r[1])


def read_sections(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, _typ, _flags, addr, off, size = struct.unpack_from("<IIQQQQ", data, o)
        secs.append([name, addr, off, size])
    shstr = secs[e_shstrndx]
    named = {}
    for s in secs:
        e = data.index(b"\0", shstr[2] + s[0])
        named[data[shstr[2] + s[0]:e].decode()] = s
    return named


def uleb(data, p):
    r = 0
    s = 0
    while True:
        b = data[p]
        p += 1
        r |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            return r, p


def sleb(data, p):
    r = 0
    s = 0
    while True:
        b = data[p]
        p += 1
        r |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            if b & 0x40:
                r |= -(1 << s)
            return r, p


def parse_eh_frame(data, sec):
    _name, addr, off, size = sec
    fdes = []
    cies = {}
    o = off
    end = off + size
    while o < end:
        length = struct.unpack_from("<I", data, o)[0]
        if length == 0:
            break
        cie_id = struct.unpack_from("<I", data, o + 4)[0]
        if cie_id == 0:
            p = o + 8
            ver = data[p]
            p += 1
            z = data.index(b"\0", p)
            aug = data[p:z].decode()
            p = z + 1
            _, p = uleb(data, p)
            _, p = sleb(data, p)
            if ver == 1:
                p += 1
            else:
                _, p = uleb(data, p)
            enc = None
            if aug.startswith("z"):
                alen, p = uleb(data, p)
                adata = data[p:p + alen]
                pos = 0
                for ch in aug[1:]:
                    if ch == "R":
                        enc = adata[pos]
                        pos += 1
                    elif ch in "LB":
                        pos += 1
                    elif ch == "P":
                        e2 = adata[pos]
                        pos += 1
                        fmt = e2 & 0x0F
                        if fmt in (0x01, 0x09):
                            q = pos
                            while adata[q] & 0x80:
                                q += 1
                            pos = q + 1
                        else:
                            pos += {0x00: 8, 0x02: 2, 0x03: 4, 0x04: 8,
                                    0x0A: 2, 0x0B: 4, 0x0C: 8}[fmt]
                p += alen
            cies[o] = enc
        else:
            cie_off = (o + 4) - cie_id
            enc = cies.get(cie_off)
            if enc != 0x1B:
                raise SystemExit(f"unexpected FDE encoding {enc} at file offset {o:#x}")
            field_va = addr + (o + 8 - off)
            init = struct.unpack_from("<i", data, o + 8)[0] + field_va
            rng = struct.unpack_from("<I", data, o + 12)[0]
            fdes.append((init, init + rng))
        o += 4 + length
    fdes.sort()
    return fdes


def collect_ranges(obj, out, in_claim):
    if isinstance(obj, dict):
        if in_claim and ("range" in obj or ("start" in obj and "end" in obj)):
            try:
                if "range" in obj:
                    out.append(parse_range(obj["range"]))
                else:
                    out.append((parse_int(obj["start"]), parse_int(obj["end"])))
            except (ValueError, TypeError, KeyError, IndexError):
                pass
            for k, v in obj.items():
                if k in ("exhibits", "windows", "window"):
                    collect_ranges(v, out, True)
            return
        for k, v in obj.items():
            if k in SKIP_KEYS:
                continue
            if k in ("exhibits", "windows", "window"):
                collect_ranges(v, out, True)
            else:
                collect_ranges(v, out, in_claim)
    elif isinstance(obj, list):
        for v in obj:
            collect_ranges(v, out, in_claim)


def main():
    data = open(BINARY, "rb").read()
    check("binary size", len(data) == 105896032, f"{len(data)} bytes")
    check("binary sha256",
          hashlib.sha256(data).hexdigest() ==
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    sections = read_sections(data)
    check("sections present",
          all(k in sections for k in (".text", ".eh_frame", ".rela.dyn", ".rela.plt")))
    fdes = parse_eh_frame(data, sections[".eh_frame"])
    check("eh_frame FDE count sane", len(fdes) > 100000, f"{len(fdes)} FDEs")
    mine = [f for f in fdes if f[0] == START]
    check("window is an FDE", len(mine) == 1 and mine[0][1] == END,
          f"{mine[0][0]:#x}..{mine[0][1]:#x}" if mine else "missing")
    prev = [f for f in fdes if f[1] <= START][-1]
    nxt = [f for f in fdes if f[0] >= END][0]
    check("previous FDE", prev == (0x63D5850, 0x63D5940),
          f"{prev[0]:#x}..{prev[1]:#x}")
    check("next FDE", nxt == (0x63D6060, 0x63D6199),
          f"{nxt[0]:#x}..{nxt[1]:#x}")
    check("gap before is 0", START - prev[1] == 0)
    check("padding after is 4", nxt[0] - END == 4)
    check("padding bytes are int3",
          data[END - 0x1000:END - 0x1000 + 4] == b"\xcc\xcc\xcc\xcc")

    hexb = open(os.path.join(PACKET, HEX_NAME), "rb").read()
    check("hex exhibit size", len(hexb) == 1820, f"{len(hexb)} bytes")
    check("hex exhibit bytes", hexb == data[START - 0x1000:START - 0x1000 + 1820])
    obj_lines = open(os.path.join(PACKET, OBJ_NAME)).read().splitlines()
    strict = [l for l in obj_lines if STRICT_RE.match(l)]
    check("strict count", len(strict) == 378, f"{len(strict)} lines")
    calls = []
    for l in obj_lines:
        m = CALL_RE.search(l)
        if m:
            calls.append((l.split(":")[0].strip(), m.group(1)))
    check("total calls", len(calls) == 9, f"{len(calls)}")
    bti = [c for c in calls if c[1] == "63d9880"]
    miss = [c for c in calls if c[1] == "63d9700"]
    check("bin_table_init sites", [c[0] for c in bti] ==
          ["63d5a96", "63d5af6", "63d5b5e", "63d5de6"])
    check("lu-miss sites", [c[0] for c in miss] ==
          ["63d5e81", "63d5f19", "63d5fa9", "63d6052"])
    check("ret count", sum(1 for l in obj_lines if RET_RE.search(l)) == 0)
    check("bsr count", sum(1 for l in obj_lines if BSR_RE.search(l)) == 0)
    locksubs = [l for l in obj_lines if LOCKSUB_RE.search(l)]
    check("lock sub count", len(locksubs) == 1, f"{len(locksubs)}")
    check("lock sub address", locksubs and locksubs[0].split(":")[0].strip() == "63d5a17")
    check("lock sub operands", locksubs and "lock sub %r14,0x38(%r8)" in locksubs[0])

    # Site branch shapes: each block is the target of exactly one je, on a
    # null-context test, with rdi = plain rsp in the block. The test sits on
    # the strict line immediately before the je (byte-continuation lines
    # skipped when walking back).
    jumps = []
    for i, l in enumerate(obj_lines):
        m = re.search(r"\t(j\w+)\s+([0-9a-f]+)", l)
        if m:
            jumps.append((i, m.group(1), m.group(2)))
    expected = {
        "63d5a90": ("je", "rdi"), "63d5af0": ("je", "rbx"),
        "63d5b58": ("je", "rbx"), "63d5de0": ("je", "rbx"),
    }
    for block, (mn, reg) in expected.items():
        got = [(i, m) for i, m, t in jumps if t == block]
        check(f"block {block} single je", len(got) == 1 and got[0][1] == mn,
              f"{got}")
        if got:
            j = got[0][0]
            k = j - 1
            while k >= 0 and not STRICT_RE.match(obj_lines[k]):
                k -= 1
            check(f"block {block} test {reg}",
                  k >= 0 and re.search(rf"test\s+%{reg},%{reg}", obj_lines[k]) is not None)
        idx = next(i for i, l in enumerate(obj_lines)
                   if l.strip().startswith(block + ":"))
        block_lines = obj_lines[idx:idx + 3]
        check(f"block {block} rdi plain rsp",
              any("mov    %rsp," in l for l in block_lines) and
              any(re.search(r"mov\s+%r1[245],%rdi", l) for l in block_lines))

    # Canary checks: three sub %fs:0x28, each followed by jne to 0x63d602a.
    canary = [i for i, l in enumerate(obj_lines) if "sub    %fs:0x28,%rax" in l]
    check("canary check count", len(canary) == 3, f"{len(canary)}")
    ok_canary = True
    for i in canary:
        following = obj_lines[i:i + 4]
        if not any("jne    63d602a" in l for l in following):
            ok_canary = False
    check("canary checks target stack_chk_fail", ok_canary)
    check("stack_chk_fail call present",
          any("call   63f0d70" in l for l in obj_lines))

    # Tail-jump exits: exactly the three known targets leave the window.
    exits = set()
    for l in obj_lines:
        m = re.search(r"\tjmp\s+([0-9a-f]+)", l)
        if m:
            t = int(m.group(1), 16)
            if t < START or t >= END:
                exits.add(m.group(1))
    check("tail-jump exits", exits == {"63637f0", "63bd6c0", "6363260"}, f"{exits}")

    # .rela census from section bytes (24-byte entries; RELATIVE type is 8).
    for sec_name, want_total, want_rel in ((".rela.dyn", 60723, 59534),
                                           (".rela.plt", 278, 0)):
        sec = sections[sec_name]
        n = sec[3] // 24
        rel = 0
        for i in range(n):
            r_info = struct.unpack_from("<Q", data, sec[2] + i * 24 + 8)[0]
            if (r_info & 0xFFFFFFFF) == 8:
                rel += 1
        check(f"{sec_name} entries", n == want_total, f"{n}")
        check(f"{sec_name} RELATIVE", rel == want_rel, f"{rel}")

    # Records consistency.
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    check("records window", rec["window"]["start"] == "0x63d5940" and
          rec["window"]["end"] == "0x63d605c")
    check("records census", rec["window"]["strict"] == 378 and
          rec["window"]["calls"] == 9 and rec["window"]["size"] == 1820)
    check("records sites", [s["site"] for s in rec["bin_table_init_sites"]] ==
          ["0x63d5a96", "0x63d5af6", "0x63d5b5e", "0x63d5de6"])
    check("records next caller", rec["next_caller"]["range"] == "0x63ec900..0x63ed06d")
    check("records slug", rec["slug"] == SLUG)

    # Disjointness: range-only collector over merged tree + prior worktrees.
    priors = []
    roots = [os.path.join(ROOT, "research", "work-items")]
    import glob as globmod
    for pat in globmod.glob(os.path.join(os.path.expanduser("~"), "workspace",
                                         "hl-wt-calls*", "research", "work-items")):
        roots.append(pat)
    seen_files = set()
    for root in roots:
        for path in globmod.glob(os.path.join(root, "*", "records.json")):
            if path in seen_files:
                continue
            seen_files.add(path)
            try:
                collect_ranges(json.load(open(path)), priors, False)
            except (ValueError, KeyError, OSError):
                pass
    check("priors scanned", len(priors) > 1000, f"{len(priors)} ranges")
    bad = [(START, END, p) for p in priors
           if START < p[1] and p[0] < END and p != (START, END)]
    check("disjointness NONE", not bad, f"{bad[:3]}")

    # Slug uniqueness: no COMMITTED directory with this slug. The packet dir
    # itself exists in this worktree (uncommitted), so a plain exists() check
    # would false-positive on self; git ls-tree HEAD answers the real
    # question. In a non-git temp copy, fall back to scanning other trees.
    import subprocess as _sp
    res = _sp.run(["git", "-C", ROOT, "ls-tree", "HEAD", "--",
                   f"research/work-items/{SLUG}"],
                  capture_output=True, text=True)
    if res.returncode == 0:
        check("slug unique in committed tree", res.stdout.strip() == "",
              res.stdout.strip()[:80])
    else:
        import glob as _glob
        others = []
        for p in _glob.glob(os.path.join(
                os.path.expanduser("~"), "workspace", "hl-wt-calls*",
                "research", "work-items", SLUG)):
            if os.path.abspath(p) == os.path.abspath(PACKET):
                continue
            try:
                r = json.load(open(os.path.join(p, "records.json")))
                if r.get("slug") == SLUG and r.get("window", {}).get("start") == "0x63d5940":
                    continue  # same packet (original worktree vs temp copy)
            except (ValueError, KeyError, OSError):
                pass
            others.append(p)
        check("slug unique (dir scan)", not others, f"{others[:2]}")

    # Raw-e8 ranking: byte scan grouped by enclosing FDE.
    text = sections[".text"]
    tdata = data[text[2]:text[2] + text[3]]
    tbase = text[1]
    starts = [a for a, _b in fdes]
    cnt = Counter()
    for i in range(len(tdata) - 5):
        if tdata[i] == 0xE8:
            rel = struct.unpack_from("<i", tdata, i + 1)[0]
            if tbase + i + 5 + rel == 0x63D9880:
                j = bisect.bisect_right(starts, tbase + i) - 1
                if j >= 0 and fdes[j][0] <= tbase + i < fdes[j][1]:
                    cnt[fdes[j]] += 1
    top = sorted(cnt.items(), key=lambda kv: -kv[1])[:5]
    check("raw ranking top", [c for _f, c in top] == [10, 8, 6, 6, 5],
          f"{[c for _f, c in top]}")
    four = {f for f, c in cnt.items() if c == 4}
    check("raw 4-count set", four == {
        (0x63CB150, 0x63CBA04), (0x63C8D60, 0x63C94FC),
        (0x636BD90, 0x636C49C), (0x6350210, 0x6352F5E),
        (0x6365660, 0x63673D9), (0x63D3080, 0x63D379C),
        (0x63D5940, 0x63D605C), (0x63EC900, 0x63ED06D)},
          f"{sorted(hex(a) for a, _b in four)}")
    check("raw total", sum(cnt.values()) == 108, f"{sum(cnt.values())}")

    # MANIFEST digests.
    manifest_ok = True
    for line in open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(None, 1)
        rel = rel.lstrip("*")
        path = os.path.normpath(os.path.join(PACKET, rel))
        if not os.path.exists(path) or \
                hashlib.sha256(open(path, "rb").read()).hexdigest() != digest:
            manifest_ok = False
    check("MANIFEST digests", manifest_ok)

    failed = [n for n, ok in checks if not ok]
    print(f"PASS count: {len(checks) - len(failed)}, FAIL count: {len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
