#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-6sites-dump.

Byte reads only. Never executes the target binary. Checks the target
binary identity, the .eh_frame bounds of FDE 0x63d4bbe..0x63d5428,
the raw-byte exhibit, the objdump exhibit census (454 strict lines,
69 calls, 6 bin_table_init sites, 0 lu-miss sites, 1 ret), the
rbp == 0 branch shape at every site, records.json consistency, the
.rela.dyn census, disjointness against prior packets, the slug
collision check, and the raw-e8 census ranking.

Environment overrides (used by the unit tests):
  HL278_ROOT: worktree root (default: parent of this file's dir).
  HL278_PRIOR_ROOTS: colon-separated dirs holding prior records.json
    files (default: this worktree's research/work-items plus every
    ~/workspace/hl-wt-calls*/research/work-items directory).
"""

import bisect
import glob
import hashlib
import json
import os
import re
import struct
import sys
from collections import Counter

SLUG = "RE-001-node115-lu-bintableinit-caller-6sites-dump"
ROOT = os.environ.get("HL278_ROOT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items", SLUG)
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
EXPECTED_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECTED_SIZE = 105896032
FDE_START = 0x63D4BBE
FDE_END = 0x63D5428
BTI = 0x63D9880
LU_MISS = 0x63D9700
EMIT = 0x63D481A
EXPECTED_STRICT = 454
EXPECTED_CALLS = 69
EXPECTED_SITES = [0x63D4EED, 0x63D4F2B, 0x63D50AF, 0x63D50E7, 0x63D5267, 0x63D529C]
EXPECTED_REJOINS = [0x63D4EF2, 0x63D4F30, 0x63D50B4, 0x63D50EC, 0x63D526C, 0x63D52A1]
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
CALL_RE = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\tcall\s+([0-9a-f]+)")
RET_RE = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\tret\s*$")

FAILURES = []
PASSES = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + detail) if detail else ""))
    if ok:
        PASSES.append(name)
    else:
        FAILURES.append(name)


# ---------------------------------------------------------------- ELF parsing
def uleb(buf, p):
    r = 0
    s = 0
    while True:
        b = buf[p]
        p += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            break
        s += 7
    return r, p


def sleb(buf, p):
    r = 0
    s = 0
    while True:
        b = buf[p]
        p += 1
        r |= (b & 0x7F) << s
        s += 7
        if not (b & 0x80):
            if b & 0x40:
                r |= -(1 << s)
            break
    return r, p


FSIZE = {0x02: 2, 0x03: 4, 0x04: 8, 0x0A: 2, 0x0B: 4, 0x0C: 8, 0x00: 8}


def read_enc(buf, p, enc):
    fmt = enc & 0x0F
    if fmt == 0x01:
        return uleb(buf, p)
    if fmt == 0x09:
        return sleb(buf, p)
    n = FSIZE[fmt]
    signed = fmt in (0x0A, 0x0B, 0x0C)
    return int.from_bytes(buf[p:p + n], "little", signed=signed), p + n


def parse_sections(data):
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", data[0x3A:0x40])
    raw = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, _typ, _flags, addr, off, size = struct.unpack("<IIQQQQ", data[o:o + 40])
        raw.append((name, addr, off, size))
    str_off = raw[e_shstrndx][2]
    str_size = raw[e_shstrndx][3]
    strtab = data[str_off:str_off + str_size]
    secs = {}
    for name, addr, off, size in raw:
        end = strtab.index(b"\0", name)
        secs[strtab[name:end].decode()] = (addr, off, size)
    return secs


def parse_fdes(data, secs):
    eh_addr, eh_off, eh_size = secs[".eh_frame"]
    cies = {}
    fdes = []
    p = eh_off
    end = eh_off + eh_size
    while p < end:
        entry_off = p
        length = struct.unpack("<I", data[p:p + 4])[0]
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            raise ValueError("extended .eh_frame entry unsupported")
        cie_id = struct.unpack("<I", data[p + 4:p + 8])[0]
        if cie_id == 0:
            q = p + 8
            ver = data[q]
            q += 1
            aug_end = data.index(b"\0", q)
            aug = data[q:aug_end].decode()
            q = aug_end + 1
            _, q = uleb(data, q)
            _, q = sleb(data, q)
            if ver == 1:
                q += 1
            else:
                _, q = uleb(data, q)
            enc = None
            if aug.startswith("z"):
                _alen, q = uleb(data, q)
                qi = q
                if "P" in aug:
                    penc = data[qi]
                    qi += 1
                    _, qi = read_enc(data, qi, penc)
                if "L" in aug:
                    qi += 1
                if "R" in aug:
                    enc = data[qi]
                    qi += 1
                if "B" in aug:
                    qi += 1
            cies[entry_off] = enc
        else:
            cie_off = (entry_off + 4) - cie_id
            enc = cies.get(cie_off)
            if enc is None:
                raise ValueError("FDE at %s has unknown CIE" % hex(entry_off))
            f = p + 8
            field_va = eh_addr + (f - eh_off)
            init, f2 = read_enc(data, f, enc)
            if enc & 0x70 == 0x10:
                init += field_va
            rng, _ = read_enc(data, f2, enc & 0x0F)
            fdes.append((init, init + rng))
        p = entry_off + 4 + length
    fdes.sort()
    return fdes


# ------------------------------------------------------- prior-range collector
# Range-only collection (packets #253/#259 lessons): string range fields
# and [start, end] lists are collected wherever they appear outside
# skipped subtrees; dict start/end pairs are collected ONLY inside
# exhibits/windows containers or a dict literally named "window".
# Enclosing-fde annotations, census/cited-only metadata, next-caller
# pointers, and scan descriptors (direct_reference_scan, text_scan)
# are never claims and are never collected.
SKIP_KEYS = {"cited_not_claimed", "cited", "census", "raw_e8_census_top",
             "next_caller", "next_question", "fde",
             "direct_reference_scan", "text_scan", "cfg_edges"}
RANGE_RE = re.compile(r"^0x[0-9a-f]+\.\.0x[0-9a-f]+$")


def is_addr(v):
    if isinstance(v, str):
        return re.match(r"^0x[0-9a-f]+$", v) is not None and len(v) > 4
    return isinstance(v, int) and v > 0x100000


def _pair(s, e):
    s = int(s, 16) if isinstance(s, str) else s
    e = int(e, 16) if isinstance(e, str) else e
    return (s, e) if s < e else None


def collect_ranges(node, path="", in_window=False, parent_key=""):
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k in SKIP_KEYS:
                continue
            out += collect_ranges(
                v, path + "/" + k,
                in_window or k in ("exhibits", "windows"), k)
        if "start" in node and "end" in node \
                and is_addr(node["start"]) and is_addr(node["end"]) \
                and (in_window or parent_key == "window"):
            pair = _pair(node["start"], node["end"])
            if pair:
                out.append(pair + (path,))
    elif isinstance(node, list):
        if len(node) == 2 and is_addr(node[0]) and is_addr(node[1]):
            pair = _pair(node[0], node[1])
            if pair:
                out.append(pair + (path,))
        for item in node:
            out += collect_ranges(item, path, in_window, parent_key)
    elif isinstance(node, str) and RANGE_RE.match(node):
        s, e = node.split("..")
        out.append((int(s, 16), int(e, 16), path))
    return out


def prior_records():
    roots = os.environ.get("HL278_PRIOR_ROOTS")
    if roots:
        dirs = roots.split(os.pathsep)
    else:
        dirs = [os.path.join(ROOT, "research", "work-items")]
        dirs += glob.glob(os.path.join(os.path.expanduser("~"), "workspace",
                                       "hl-wt-calls*", "research", "work-items"))
    found = []
    for d in dirs:
        for path in glob.glob(os.path.join(d, "*", "records.json")):
            found.append(path)
    return found


def main():
    with open(BINARY, "rb") as fh:
        data = fh.read()
    check("binary size", len(data) == EXPECTED_SIZE, str(len(data)))
    check("binary sha256",
          hashlib.sha256(data).hexdigest() == EXPECTED_SHA)

    secs = parse_sections(data)
    fdes = parse_fdes(data, secs)
    check("fde count sane", len(fdes) > 100000, str(len(fdes)))
    check("target fde present", (FDE_START, FDE_END) in fdes)
    idx = bisect.bisect_left([f[0] for f in fdes], FDE_START)
    if idx > 0:
        prev = fdes[idx - 1]
        check("gap before fde", prev[1] == FDE_START,
              "prev ends %s" % hex(prev[1]))
    if idx + 1 < len(fdes):
        nxt = fdes[idx + 1]
        check("padding after fde", nxt[0] == FDE_END,
              "next starts %s" % hex(nxt[0]))
    check("fde byte size", FDE_END - FDE_START == 2154,
          str(FDE_END - FDE_START))

    hex_path = os.path.join(PACKET, "bintableinit_caller_dump_6sites.hex")
    with open(hex_path, "rb") as fh:
        exhibit = fh.read()
    expect = data[FDE_START - 0x1000:FDE_START - 0x1000 + 2154]
    check("hex exhibit bytes", exhibit == expect,
          "len %d vs %d" % (len(exhibit), len(expect)))
    check("hex exhibit length", len(exhibit) == 2154)

    obj_path = os.path.join(PACKET, "bintableinit_caller_dump_6sites.objdump.txt")
    with open(obj_path) as fh:
        obj_lines = fh.read().splitlines()
    strict = [ln for ln in obj_lines if STRICT_RE.match(ln)]
    check("strict count", len(strict) == EXPECTED_STRICT, str(len(strict)))
    calls = []
    for ln in obj_lines:
        m = CALL_RE.match(ln)
        if m:
            calls.append((int(m.group(1), 16), int(m.group(2), 16)))
    check("call count", len(calls) == EXPECTED_CALLS, str(len(calls)))
    bti = sorted(a for a, t in calls if t == BTI)
    check("bin_table_init sites", bti == EXPECTED_SITES,
          ",".join(hex(a) for a in bti))
    check("lu-miss sites", [a for a, t in calls if t == LU_MISS] == [])
    emit = [a for a, t in calls if t == EMIT]
    check("emit helper sites", len(emit) == 14, str(len(emit)))
    rets = [int(m.group(1), 16) for ln in obj_lines
            for m in [RET_RE.match(ln)] if m]
    check("ret count and address", rets == [0x63D5427],
          ",".join(hex(r) for r in rets))
    check("stack_chk_fail call present",
          any(t == 0x63F0D70 for _a, t in calls))
    check("canary check present",
          any("0xa08(%rsp)" in ln for ln in obj_lines))
    # rbp == 0 branch shape: test %rbp,%rbp then jne within the
    # preceding lines of every bin_table_init call site.
    for site, rejoin in zip(EXPECTED_SITES, EXPECTED_REJOINS):
        si = next(i for i, ln in enumerate(obj_lines)
                  if ln.strip().startswith("%x:" % site))
        window = obj_lines[max(0, si - 6):si]
        has_test = any("test   %rbp,%rbp" in ln for ln in window)
        has_jne = any("\tjne" in ln and ("%x" % rejoin) in ln
                      for ln in obj_lines[max(0, si - 4):si])
        check("rbp==0 branch at %s" % hex(site), has_test and has_jne)

    with open(os.path.join(PACKET, "records.json")) as fh:
        rec = json.load(fh)
    check("records fde", rec["fde"]["start"] == "0x63d4bbe"
          and rec["fde"]["end"] == "0x63d5428"
          and rec["fde"]["bytes"] == 2154
          and rec["fde"]["strict"] == 454
          and rec["fde"]["calls"] == 69
          and rec["fde"]["rets"] == 1)
    check("records sites",
          [s["site"] for s in rec["bin_table_init_sites"]] ==
          ["0x63d4eed", "0x63d4f2b", "0x63d50af",
           "0x63d50e7", "0x63d5267", "0x63d529c"])
    check("records target sha", rec["target"]["sha256"] == EXPECTED_SHA)
    check("records pointer correction",
          rec["pointer_correction"]["recorded"] == 2410
          and rec["pointer_correction"]["verified"] == 2154)

    rela_addr, rela_off, rela_size = secs[".rela.dyn"]
    total = rela_size // 24
    rel_count = 0
    for i in range(total):
        info = struct.unpack("<Q", data[rela_off + i * 24 + 8:
                                        rela_off + i * 24 + 16])[0]
        if info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
            rel_count += 1
    check("rela.dyn total", total == 60723, str(total))
    check("rela.dyn relative", rel_count == 59534, str(rel_count))

    # Disjointness: own records excluded by identical bytes.
    with open(os.path.join(PACKET, "records.json"), "rb") as fh:
        own_bytes = fh.read()
    overlaps = []
    for path in prior_records():
        with open(path, "rb") as fh:
            raw = fh.read()
        if raw == own_bytes:
            continue
        try:
            prior = json.loads(raw)
        except ValueError:
            continue
        for (s, e, pth) in collect_ranges(prior):
            if s < FDE_END and FDE_START < e:
                overlaps.append((path, hex(s), hex(e), pth))
    check("disjoint from priors", not overlaps, str(overlaps[:3]))

    # Slug collision: another directory with this slug but different bytes.
    collision = False
    roots = os.environ.get("HL278_PRIOR_ROOTS")
    dirs = roots.split(os.pathsep) if roots else [
        os.path.join(ROOT, "research", "work-items")] + glob.glob(
        os.path.join(os.path.expanduser("~"), "workspace",
                      "hl-wt-calls*", "research", "work-items"))
    for d in dirs:
        cand = os.path.join(d, SLUG, "records.json")
        if os.path.exists(cand):
            with open(cand, "rb") as fh:
                if fh.read() != own_bytes:
                    collision = True
    check("slug no collision", not collision)

    # Raw-e8 census for bin_table_init, grouped by enclosing FDE.
    text_addr, text_off, text_size = secs[".text"]
    text = data[text_off:text_off + text_size]
    starts = [f[0] for f in fdes]
    cnt = Counter()
    i = -1
    while True:
        i = text.find(b"\xe8", i + 1)
        if i < 0:
            break
        if i + 5 > len(text):
            break
        va = text_addr + i
        rel = struct.unpack("<i", text[i + 1:i + 5])[0]
        if va + 5 + rel == BTI:
            j = bisect.bisect_right(starts, va) - 1
            if j >= 0 and fdes[j][0] <= va < fdes[j][1]:
                cnt[fdes[j]] += 1
    check("raw-e8 this fde", cnt[(FDE_START, FDE_END)] == 6,
          str(cnt[(FDE_START, FDE_END)]))
    expect_rank = {(0x63CBA10, 0x63CCD22): 10, (0x63C9C80, 0x63CB146): 8,
                   (0x63CE8C0, 0x63CF8BC): 6, (FDE_START, FDE_END): 6,
                   (0x63BD8C0, 0x63BE4CE): 5}
    check("raw-e8 ranking",
          all(cnt[k] == v for k, v in expect_rank.items()),
          str({hex(k[0]): cnt[k] for k in expect_rank}))

    # MANIFEST entries resolve and hash-match; MANIFEST excludes itself.
    manifest = os.path.join(PACKET, "MANIFEST.sha256")
    with open(manifest) as fh:
        entries = [ln.split() for ln in fh if ln.strip()]
    check("manifest entry count", len(entries) == 7, str(len(entries)))
    ok = True
    for digest, rel in entries:
        target = os.path.normpath(os.path.join(PACKET, rel))
        if not os.path.exists(target):
            ok = False
            break
        with open(target, "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() != digest:
                ok = False
                break
    check("manifest digests", ok)
    check("manifest excludes itself",
          not any("MANIFEST.sha256" in rel for _d, rel in entries))

    print("PASS count: %d, FAIL count: %d" % (len(PASSES), len(FAILURES)))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
