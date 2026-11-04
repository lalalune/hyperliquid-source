#!/usr/bin/env python3
"""Static verifier for packet #285 (packet dir RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub).

Byte reads only; never executes the target binary. Usage:
  python3 tools/node115_lu_bintableinit_caller_walk_rsp_locksub_4sites.py [--root <repo-root>]

Exit 0 when every check passes, non-zero otherwise. Each check prints
PASS or FAIL; a summary line prints the totals.
"""

import hashlib
import json
import os
import re
import struct
import sys
from collections import Counter

SLUG = "RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub"
WINDOW_START = 0x63D3080
WINDOW_END = 0x63D379C
WINDOW_BYTES = 1820
STRICT_EXPECTED = 379
CALLS_EXPECTED = 9
BTI_EXPECTED = 4
MISS_EXPECTED = 4
RET_EXPECTED = 0
BSR_EXPECTED = 0
BIN_TARGET = 0x63D9880
MISS_TARGET = 0x63D9700
BIN_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BIN_SIZE = 105896032
RELA_DYN_TOTAL = 60723
RELA_DYN_RELATIVE = 59534
RELA_PLT_TOTAL = 278

BTI_SITES = [
    {"site": 0x63D31D6, "block": 0x63D31D0, "je": 0x63D30B9, "arg_reg": "r12"},
    {"site": 0x63D3236, "block": 0x63D3230, "je": 0x63D3113, "arg_reg": "r15"},
    {"site": 0x63D329E, "block": 0x63D3298, "je": 0x63D316B, "arg_reg": "r14"},
    {"site": 0x63D3526, "block": 0x63D3520, "je": 0x63D3314, "arg_reg": "r15"},
]
MISS_SITES = [0x63D35C1, 0x63D3659, 0x63D36E9, 0x63D3792]
RANKING = [
    (0x63CBA10, 0x63CCD22, 10),
    (0x63C9C80, 0x63CB146, 8),
    (0x63CE8C0, 0x63CF8BC, 6),
    (0x63D4BBE, 0x63D5428, 6),
    (0x63BD8C0, 0x63BE4CE, 5),
    (0x63CB150, 0x63CBA04, 4),
    (0x63C8D60, 0x63C94FC, 4),
    (0x636BD90, 0x636C49C, 4),
    (0x6350210, 0x6352F5E, 4),
    (0x6365660, 0x63673D9, 4),
    (0x63D3080, 0x63D379C, 4),
]
REMAINING_4RAW = [
    (0x63D5940, 0x63D605C),
    (0x63EC900, 0x63ED06D),
]

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS %s" % name)
    else:
        FAIL += 1
        print("FAIL %s %s" % (name, detail))


def parse_addr(line):
    m = re.match(r"\s*([0-9a-f]+):", line)
    return int(m.group(1), 16) if m else None


def parse_elf_sections(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, _typ, _flags, addr, offset, size = struct.unpack_from("<IIQQQQ", data, off)
        secs.append((name, addr, offset, size))
    strtab_off = secs[e_shstrndx][2]
    named = {}
    for name_off, addr, offset, size in secs:
        end = data.index(b"\x00", strtab_off + name_off)
        named[data[strtab_off + name_off:end].decode()] = (addr, offset, size)
    return named


def parse_eh_fdes(data, eh):
    """Parse .eh_frame FDEs. Encoding is PC-relative sdata4 (CIE zPLR),
    fixed 4-byte range fields (not ULEB) -- verified against readelf."""
    eh_addr, eh_off, eh_size = eh
    ehdata = data[eh_off:eh_off + eh_size]
    fdes = []
    pos = 0
    while pos + 8 <= len(ehdata):
        length, cid = struct.unpack_from("<II", ehdata, pos)
        if length == 0:
            break
        if cid != 0:
            init, rng = struct.unpack_from("<iI", ehdata, pos + 8)
            field_va = eh_addr + (pos + 8)
            start = field_va + init
            fdes.append((start, start + rng))
        pos += 4 + length
    fdes.sort()
    return fdes


def collect_ranges(obj, out, skip_keys):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in skip_keys:
                continue
            if k in ("exhibits", "windows"):
                items = v if isinstance(v, list) else list(v.values()) if isinstance(v, dict) else []
                for e in items:
                    if isinstance(e, dict):
                        if "range" in e:
                            r = e["range"]
                            if isinstance(r, list):
                                out.append((int(r[0], 16), int(r[1], 16)))
                            else:
                                a, b = r.split("..")
                                out.append((int(a, 16), int(b, 16)))
                        elif "start" in e and "end" in e:
                            out.append((int(e["start"], 16), int(e["end"], 16)))
            elif k == "window" and isinstance(v, dict):
                if "range" in v:
                    r = v["range"]
                    if isinstance(r, list):
                        out.append((int(r[0], 16), int(r[1], 16)))
                    else:
                        a, b = r.split("..")
                        out.append((int(a, 16), int(b, 16)))
                elif "start" in v and "end" in v:
                    out.append((int(v["start"], 16), int(v["end"], 16)))
            else:
                collect_ranges(v, out, skip_keys)
    elif isinstance(obj, list):
        for item in obj:
            collect_ranges(item, out, skip_keys)


def main(argv):
    root = None
    if "--root" in argv:
        root = argv[argv.index("--root") + 1]
    if root is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    packet_dir = os.path.join(root, "research", "work-items", SLUG)
    bin_path = os.path.join(root, "artifacts", "node", "115", "hl-node")

    # 1. binary size + SHA-256
    with open(bin_path, "rb") as f:
        data = f.read()
    check("binary-size", len(data) == BIN_SIZE, "got %d" % len(data))
    check("binary-sha256", hashlib.sha256(data).hexdigest() == BIN_SHA256)

    # 2. .eh_frame bounds for the window
    secs = parse_elf_sections(data)
    fdes = parse_eh_fdes(data, secs[".eh_frame"])
    starts = [s for s, _ in fdes]
    import bisect
    j = bisect.bisect_right(starts, WINDOW_START) - 1
    check("eh-frame-window", j >= 0 and fdes[j] == (WINDOW_START, WINDOW_END),
          "got %s" % (fdes[j] if j >= 0 else None,))
    prev_end = fdes[j - 1][1] if j > 0 else None
    next_start = fdes[j + 1][0] if j + 1 < len(fdes) else None
    check("gap-before-15", prev_end == 0x63D3071, "prev end %s" % prev_end)
    check("next-fde", next_start == 0x63D37A0, "next start %s" % next_start)
    text_addr, text_off, _text_size = secs[".text"]
    gap = data[0x63D3071 - 0x1000:WINDOW_START - 0x1000]
    pad = data[WINDOW_END - 0x1000:0x63D37A0 - 0x1000]
    check("gap-15xcc", gap == b"\xcc" * 15, gap.hex())
    check("padding-4xcc", pad == b"\xcc" * 4, pad.hex())

    # 3. exhibit bytes
    hex_path = os.path.join(packet_dir, "bintableinit_caller_walk_rsp_locksub_4sites.hex")
    with open(hex_path, "rb") as f:
        exhibit = f.read()
    check("exhibit-length", len(exhibit) == WINDOW_BYTES, "got %d" % len(exhibit))
    check("exhibit-bytes", exhibit == data[WINDOW_START - 0x1000:WINDOW_END - 0x1000])

    # 4. objdump census
    obj_path = os.path.join(packet_dir, "bintableinit_caller_walk_rsp_locksub_4sites.objdump.txt")
    with open(obj_path, "r") as f:
        obj_lines = f.read().splitlines()
    strict_pat = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
    strict = [l for l in obj_lines if strict_pat.match(l)]
    check("strict-count", len(strict) == STRICT_EXPECTED, "got %d" % len(strict))
    calls = []
    for l in obj_lines:
        m = re.search(r"\tcall\s+([0-9a-f]+)", l)
        if m:
            calls.append((parse_addr(l), int(m.group(1), 16)))
    check("call-total", len(calls) == CALLS_EXPECTED, "got %d" % len(calls))
    bti = [a for a, t in calls if t == BIN_TARGET]
    miss = [a for a, t in calls if t == MISS_TARGET]
    check("bti-sites", bti == [s["site"] for s in BTI_SITES], [hex(x) for x in bti])
    check("miss-sites", miss == MISS_SITES, [hex(x) for x in miss])
    rets = [l for l in obj_lines if re.search(r"\tret\s*$", l)]
    check("ret-count", len(rets) == RET_EXPECTED, "got %d" % len(rets))
    bsr = [l for l in obj_lines if re.search(r"\tbsr\s", l)]
    check("bsr-count", len(bsr) == BSR_EXPECTED, "got %d" % len(bsr))

    # 5. site branch shapes: exactly one je per block; block is
    # mov %rsp,%rX ; mov %rX,%rdi ; call bin_table_init
    indexed = [(parse_addr(l), l) for l in obj_lines if parse_addr(l) is not None]
    for s in BTI_SITES:
        jes = [(a, l) for a, l in indexed
               if re.search(r"\tje\s+%x(?=\s)" % s["block"], l)]
        check("site-%x-one-je" % s["site"], len(jes) == 1, "%d jes" % len(jes))
        if jes:
            check("site-%x-je-source" % s["site"], jes[0][0] == s["je"],
                  "got %s" % hex(jes[0][0]))
        blk_lines = []
        for i, (a, l) in enumerate(indexed):
            if a == s["block"]:
                blk_lines = [ll for _, ll in indexed[i:i + 4]]
                break
        rsp_ok = any("mov    %%rsp,%%%s" % s["arg_reg"] in ll for ll in blk_lines)
        rdi_ok = any("mov    %%%s,%%rdi" % s["arg_reg"] in ll for ll in blk_lines)
        call_ok = any(re.search(r"\tcall\s+%x(?=\s)" % BIN_TARGET, ll) for ll in blk_lines)
        check("site-%x-plain-rsp-call" % s["site"], rsp_ok and rdi_ok and call_ok)

    # 6. canary + stack_chk_fail (3 checks, fs:0x28, canary 0x188(%rsp))
    check("canary-store", any("mov    %fs:0x28,%rax" in l and "0x188(%rsp)" in
          obj_lines[i + 2] for i, l in enumerate(obj_lines[:-2])
          if "mov    %fs:0x28,%rax" in l))
    check("stack-chk-fail-call", any(re.search(r"\tcall\s+63f0d70", l) for l in obj_lines))
    check("canary-checks-3", sum(1 for l in obj_lines if "sub    %fs:0x28,%rax" in l) == 3)

    # 7. lock sub present exactly once (walk B refcount decrement)
    locksubs = [l for l in obj_lines if "lock sub" in l]
    check("lock-sub-present-once", len(locksubs) == 1, "%d" % len(locksubs))
    if locksubs:
        check("lock-sub-address", parse_addr(locksubs[0]) == 0x63D315C,
              locksubs[0].strip())

    # 8. .rela.dyn / .rela.plt census (pure section parse; no readelf dependency)
    dyn_addr, dyn_off, dyn_size = secs[".rela.dyn"]
    plt_addr, plt_off, plt_size = secs[".rela.plt"]
    total = dyn_size // 24
    rel = 0
    for i in range(total):
        _off, info, _add = struct.unpack_from("<QQq", data, dyn_off + i * 24)
        if info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
            rel += 1
    check("rela-dyn-total", total == RELA_DYN_TOTAL, "got %d" % total)
    check("rela-dyn-relative", rel == RELA_DYN_RELATIVE, "got %d" % rel)
    check("rela-plt-total", plt_size // 24 == RELA_PLT_TOTAL, "got %d" % (plt_size // 24))

    # 9. records consistency
    with open(os.path.join(packet_dir, "records.json"), "r") as f:
        rec = json.load(f)
    check("records-slug", rec.get("slug") == SLUG)
    check("records-window", rec["window"]["start"] == "0x63d3080" and
          rec["window"]["end"] == "0x63d379c")
    check("records-census", rec["window"]["bytes"] == WINDOW_BYTES and
          rec["window"]["strict"] == STRICT_EXPECTED and
          rec["window"]["calls"] == CALLS_EXPECTED and
          rec["window"]["bin_table_init_sites"] == BTI_EXPECTED and
          rec["window"]["lu_miss_sites"] == MISS_EXPECTED and
          rec["window"]["ret"] == RET_EXPECTED and
          rec["window"]["bsr"] == BSR_EXPECTED)
    check("records-sites", [s["site"] for s in rec["bin_table_init_sites"]] ==
          ["0x63d31d6", "0x63d3236", "0x63d329e", "0x63d3526"])
    check("records-miss-sites", [s["site"] for s in rec["lu_miss_sites"]] ==
          ["0x63d35c1", "0x63d3659", "0x63d36e9", "0x63d3792"])
    check("records-prior-pointer", rec["prior_pointer_verified"]["verified_bytes"] == 1820 and
          rec["prior_pointer_verified"]["verified_sites"] == 4)

    # 10. disjointness over merged tree + prior worktrees (self excluded by exact equality)
    skip = {"census", "cited", "survey", "callers", "largest_caller_fde",
            "next_caller", "prior_pointer_verified", "raw_e8_ranking",
            "other_remaining_4raw_fdes", "scan", "fde"}
    priors = []
    roots = [os.path.join(root, "research", "work-items")]
    home = os.path.expanduser("~")
    import glob as globmod
    for d in globmod.glob(os.path.join(home, "workspace", "hl-wt-calls*", "research", "work-items")):
        roots.append(d)
    for rdir in roots:
        if not os.path.isdir(rdir):
            continue
        for rfile in globmod.glob(os.path.join(rdir, "*", "records.json")):
            try:
                with open(rfile, "r") as f:
                    collect_ranges(json.load(f), priors, skip)
            except Exception:
                continue
    overlap = [(m, p) for p in priors
               for m in [(WINDOW_START, WINDOW_END)]
               if m[0] < p[1] and p[0] < m[1] and p != (WINDOW_START, WINDOW_END)]
    check("disjointness", not overlap, "overlaps: %s" % overlap[:3])
    check("priors-scanned", len(priors) > 1000, "got %d" % len(priors))

    # 11. slug collision: exactly one dir of this name in the merged tree
    merged_dirs = [d for d in os.listdir(os.path.join(root, "research", "work-items"))
                   if d == SLUG]
    check("slug-unique", len(merged_dirs) == 1)

    # 12. raw-e8 census grouped by enclosing FDE (C-level find loop)
    tdata = data[text_off:text_off + secs[".text"][2]]
    tva = text_addr
    by_fde = Counter()
    idx = tdata.find(b"\xe8")
    while idx != -1 and idx + 5 <= len(tdata):
        rel = struct.unpack_from("<i", tdata, idx + 1)[0]
        va = tva + idx
        if va + 5 + rel == BIN_TARGET:
            j2 = bisect.bisect_right(starts, va) - 1
            if j2 >= 0 and fdes[j2][0] <= va < fdes[j2][1]:
                by_fde[fdes[j2]] += 1
        idx = tdata.find(b"\xe8", idx + 1)
    rank_ok = all(by_fde.get((s, e), 0) == c for s, e, c in RANKING)
    check("raw-e8-ranking", rank_ok,
          {"%x..%x" % (s, e): by_fde.get((s, e), 0) for s, e, _ in RANKING})
    four = sorted([f for f, c in by_fde.items() if c == 4])
    claimed_four = sorted([(s, e) for s, e, _ in RANKING if _ == 4])
    check("raw-e8-remaining", [f for f in four if f not in claimed_four] == REMAINING_4RAW,
          ["%x..%x" % f for f in four if f not in claimed_four])

    # 13. MANIFEST digests
    man_path = os.path.join(packet_dir, "MANIFEST.sha256")
    man_ok = True
    with open(man_path, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            digest, path = line.split(None, 1)
            path = path.lstrip("* ")
            full = os.path.normpath(os.path.join(packet_dir, path))
            with open(full, "rb") as fh:
                actual = hashlib.sha256(fh.read()).hexdigest()
            if actual != digest:
                man_ok = False
                print("  MANIFEST mismatch: %s" % path)
    check("manifest-digests", man_ok)

    print("PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
