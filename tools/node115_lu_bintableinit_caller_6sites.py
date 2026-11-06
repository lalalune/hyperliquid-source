#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-6sites.

Byte reads only; never executes the binary. Exit 0 iff every check
passes. Prior roots for the disjointness scan come from
HL277_PRIOR_ROOTS (colon-separated) when set, else the worktree
merged tree plus all hl-wt-calls* worktrees.
"""

import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research", "work-items",
    "RE-001-node115-lu-bintableinit-caller-6sites")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-6sites"

EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032
FDE_START, FDE_END = 0x63CE8C0, 0x63CF8BC
PREV_END, NEXT_START = 0x63CE8B8, 0x63CF8C0
EXPECT_STRICT = 882
EXPECT_CALLS = 22
EXPECT_RETS = 1
BTI_SITES = ["0x63cf130", "0x63cf19a", "0x63cf1c8",
             "0x63cf27a", "0x63cf28c", "0x63cf3c0"]
MISS_SITES = ["0x63cf64e", "0x63cf676", "0x63cf7d6",
              "0x63cf7f9", "0x63cf88f", "0x63cf8b2"]
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")

passes = []
fails = []


def check(name, ok, detail=""):
    (passes if ok else fails).append(name)
    print(("PASS " if ok else "FAIL ") + name
          + ((" | " + str(detail)) if detail else ""))


def parse_eh_frame(data):
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", data[0x3A:0x40])

    def sh(i):
        o = e_shoff + i * e_shentsize
        return struct.unpack("<IIQQQQ", data[o:o + 40])

    shstr_off = sh(e_shstrndx)[4]

    def nm(n):
        e = data.index(b"\x00", shstr_off + n)
        return data[shstr_off + n:e].decode()

    for i in range(e_shnum):
        name, _typ, _flags, addr, off, size = sh(i)
        if nm(name) == ".eh_frame":
            break
    else:
        return {}
    fdes = {}
    pos = 0
    while pos < size:
        ln = struct.unpack("<I", data[off + pos:off + pos + 4])[0]
        if ln == 0:
            break
        cie_ptr = struct.unpack("<I", data[off + pos + 4:off + pos + 8])[0]
        if cie_ptr != 0:
            init = struct.unpack("<i", data[off + pos + 8:off + pos + 12])[0]
            rng = struct.unpack("<I", data[off + pos + 12:off + pos + 16])[0]
            pc = addr + pos + 8 + init
            fdes[pc] = (pc, pc + rng)
        pos += 4 + ln
    return fdes


def strict_lines(objdump_path):
    out = []
    with open(objdump_path) as fh:
        for line in fh:
            if STRICT_RE.match(line):
                out.append(line.rstrip("\n"))
    return out


def addr_of(line):
    return int(line.strip().split(":")[0], 16)


SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde")


def collect(obj, out):
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in SKIP_KEYS or key == "fde":
                continue
            if key in ("exhibits", "windows"):
                items = val if isinstance(val, list) else (
                    val.values() if isinstance(val, dict) else [])
                for entry in items:
                    if not isinstance(entry, dict):
                        continue
                    if "range" in entry:
                        r = entry["range"]
                        if isinstance(r, list):
                            out.append((int(r[0], 16), int(r[1], 16)))
                        else:
                            a, b = r.split("..")
                            out.append((int(a, 16), int(b, 16)))
                    elif "start" in entry and "end" in entry:
                        out.append((int(entry["start"], 16),
                                    int(entry["end"], 16)))
            else:
                collect(val, out)
    elif isinstance(obj, list):
        for val in obj:
            collect(val, out)


def main():
    with open(BINARY, "rb") as fh:
        blob = fh.read()
    check("binary-size", len(blob) == EXPECT_SIZE, len(blob))
    check("binary-sha256",
          hashlib.sha256(blob).hexdigest() == EXPECT_SHA)

    fdes = parse_eh_frame(blob)
    check("eh-frame-fde",
          fdes.get(FDE_START) == (FDE_START, FDE_END),
          fdes.get(FDE_START))
    ends = sorted(end for _s, end in fdes.values())
    prevs = [e for e in ends if e <= FDE_START]
    check("eh-frame-prev-gap",
          prevs and prevs[-1] == PREV_END
          and FDE_START - PREV_END == 8, prevs[-1] if prevs else None)
    starts = sorted(fdes)
    nxt = [s for s in starts if s >= FDE_END]
    check("eh-frame-next-padding",
          nxt and nxt[0] == NEXT_START
          and NEXT_START - FDE_END == 4, nxt[0] if nxt else None)

    with open(os.path.join(PACKET, "records.json")) as fh:
        records = json.load(fh)
    hex_bytes = open(os.path.join(
        PACKET, "bintableinit_caller_6sites.hex"), "rb").read()
    check("exhibit-bytes",
          hex_bytes == blob[FDE_START - 0x1000:FDE_END - 0x1000]
          and len(hex_bytes) == FDE_END - FDE_START, len(hex_bytes))
    ex0 = records["exhibits"][0]
    check("records-exhibit-meta",
          ex0["name"] == "bintableinit_caller_6sites"
          and ex0["range"] == "0x63ce8c0..0x63cf8bc"
          and ex0["bytes"] == FDE_END - FDE_START
          and ex0["strict"] == EXPECT_STRICT
          and ex0["calls"] == EXPECT_CALLS
          and ex0["rets"] == EXPECT_RETS, ex0)
    check("records-bti-sites",
          [s["site"] for s in records["bin_table_init_sites"]]
          == BTI_SITES)
    check("records-miss-sites",
          [s["site"] for s in records["lu_miss_sites"]] == MISS_SITES)
    check("records-fde",
          records["fde"]["start"] == "0x63ce8c0"
          and records["fde"]["end"] == "0x63cf8bc"
          and records["fde"]["bytes"] == FDE_END - FDE_START)

    lines = strict_lines(os.path.join(
        PACKET, "bintableinit_caller_6sites.objdump.txt"))
    check("strict-recount", len(lines) == EXPECT_STRICT, len(lines))

    calls = []
    rets = []
    for i, line in enumerate(lines):
        if re.search(r"\tcall\s", line):
            m = re.search(r"\tcall\s+([0-9a-f]+)", line)
            calls.append((addr_of(line), m.group(1) if m else "?"))
        elif re.search(r"\tret\s*$", line):
            rets.append(addr_of(line))
    check("call-total", len(calls) == EXPECT_CALLS, len(calls))
    check("ret-count", rets == [0x63CEC83], [hex(r) for r in rets])
    by_target = {}
    for a, t in calls:
        by_target.setdefault(t, []).append(a)
    bti = sorted(by_target.get("63d9880", []))
    check("bti-sites",
          [hex(a) for a in bti] == BTI_SITES, [hex(a) for a in bti])
    miss = sorted(by_target.get("63d9700", []))
    check("miss-sites",
          [hex(a) for a in miss] == MISS_SITES, [hex(a) for a in miss])
    for tgt, want in (("6364880", 1), ("63d2a80", 1), ("63f17b0", 1),
                      ("63f0b70", 1), ("63bf680", 1), ("63637f0", 1),
                      ("634ebb0", 1), ("63bd6c0", 1), ("6363260", 1),
                      ("63f0d70", 1)):
        check("callee-" + tgt, len(by_target.get(tgt, [])) == want,
              len(by_target.get(tgt, [])))

    # bin_table_init arg pattern: lea 0x20(%rsp) + mov to %rdi
    # within the 5 lines preceding each site; each site block is
    # reached from a test %rbp,%rbp + je branch.
    ok_args = True
    ok_branch = True
    text = "\n".join(lines)
    for site in BTI_SITES:
        idx = next(i for i, l in enumerate(lines)
                   if addr_of(l) == int(site, 16))
        window = lines[max(0, idx - 5):idx]
        if not (any("lea" in l and "0x20(%rsp)" in l for l in window)
                and any(re.search(r"\tmov\s+%r\w+,%rdi", l)
                        for l in window)):
            ok_args = False
        lea_addr = next(addr_of(l) for l in lines[max(0, idx - 5):idx]
                        if "lea" in l and "0x20(%rsp)" in l)
        found = False
        for j, l in enumerate(lines):
            m = re.search(r"\tje\s+([0-9a-f]+)", l)
            if m and int(m.group(1), 16) == lea_addr:
                prev = lines[j - 1] if j > 0 else ""
                if "test" in prev and "%rbp,%rbp" in prev:
                    found = True
        if not found:
            ok_branch = False
    check("bti-arg-pattern", ok_args)
    check("bti-rbp0-branch", ok_branch)

    # lu-miss arg pattern within the 8 lines preceding each site.
    ok_miss = True
    for site in MISS_SITES:
        idx = next(i for i, l in enumerate(lines)
                   if addr_of(l) == int(site, 16))
        window = lines[max(0, idx - 8):idx]
        joined = "\n".join(window)
        if not ("6511a00" in joined and "xor" in joined
                and "%r9d" in joined and "mov    %rbx,%rcx" in joined
                and "mov    $0x1,%r8d" in joined
                and "mov    %rbp,%rdi" in joined):
            ok_miss = False
    check("miss-arg-pattern", ok_miss)

    # canary + stack_chk_fail
    check("canary-check",
          any("sub" in l and "%fs:0x28" in l and addr_of(l) == 0x63CEC60
              for l in lines))
    check("stack-chk-fail-call",
          any(a == 0x63CF740 for a, t in calls))

    # radix walk markers
    joined = "\n".join(lines)
    for name, pat in (
            ("top-index-shr-1a", "shr    $0x1a"),
            ("tag-mask", "0xffffffffc0000000"),
            ("second-level-mask", "0x1ffff8"),
            ("second-table", "6727a00"),
            ("leaf-fff-index", "0xfff"),
            ("lock-refcount", "lock ")):
        check("marker-" + name, pat in joined)

    # disjointness against prior claimed ranges
    roots_env = os.environ.get("HL277_PRIOR_ROOTS")
    if roots_env:
        roots = roots_env.split(":")
    else:
        roots = [os.path.join(ROOT, "research", "work-items")]
        roots += glob.glob("/home/hatch/workspace/hl-wt-calls*/"
                           "research/work-items")
    priors = []
    seen_slugs = set()
    for root in roots:
        for path in glob.glob(os.path.join(root, "*/records.json")):
            slug = os.path.basename(os.path.dirname(path))
            if slug == SLUG or slug in seen_slugs:
                continue
            seen_slugs.add(slug)
            try:
                with open(path) as fh:
                    collect(json.load(fh), priors)
            except Exception:
                pass
    overlap = [(FDE_START, FDE_END, p) for p in priors
               if FDE_START < p[1] and p[0] < FDE_END]
    check("disjointness", not overlap, overlap[:3])
    for name, lo, hi in (
            ("232-merged", 0x63B8820, 0x63B8D85),
            ("252-r28-wait", 0x63EC890, 0x63EC8A3),
            ("215-handler", 0x63D9700, 0x63D987B),
            ("261-tcache", 0x63721C0, 0x6372246),
            ("262-bti", 0x63D9880, 0x63D9A64),
            ("275-caller", 0x63CBA10, 0x63CCD22),
            ("276-caller", 0x63C9C80, 0x63CB146)):
        check("explicit-" + name,
              not (FDE_START < hi and lo < FDE_END))

    # raw-e8 census for target 0x63d9880, grouped by enclosing FDE
    text_sec = None
    import subprocess as sp
    sec = sp.run(["readelf", "-SW", BINARY],
                 capture_output=True, text=True).stdout
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
                  r"([0-9a-f]+)", sec)
    tva, toff, tsize = (int(m.group(1), 16), int(m.group(2), 16),
                        int(m.group(3), 16))
    text_sec = blob[toff:toff + tsize]
    starts_sorted = sorted(fdes)
    counts = {}
    i = 0
    while True:
        i = text_sec.find(b"\xe8", i)
        if i < 0:
            break
        if i + 5 <= len(text_sec):
            rel = struct.unpack("<i", text_sec[i + 1:i + 5])[0]
            va = tva + i
            if va + 5 + rel == 0x63D9880:
                j = bisect.bisect_right(starts_sorted, va) - 1
                if j >= 0:
                    f = fdes[starts_sorted[j]]
                    if f[0] <= va < f[1]:
                        counts[f] = counts.get(f, 0) + 1
        i += 1
    check("raw-e8-this-fde",
          counts.get((FDE_START, FDE_END)) == 6,
          counts.get((FDE_START, FDE_END)))
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])[:5]
    check("raw-e8-ranking",
          ranked[0][1] == 10 and ranked[1][1] == 8
          and ranked[2][1] == 6 and ranked[3][1] == 6
          and ranked[4][1] == 5,
          [(hex(s), c) for (s, _e), c in ranked])

    # slug collision: a directory with this slug elsewhere counts
    # only if its records.json differs from this packet's (the same
    # packet checked out in another worktree is not a collision).
    collision = False
    own_records = open(os.path.join(PACKET, "records.json"), "rb").read()
    for root in roots:
        cand = os.path.join(root, SLUG)
        if os.path.isdir(cand) and os.path.abspath(cand) != \
                os.path.abspath(PACKET):
            other = os.path.join(cand, "records.json")
            if not os.path.exists(other) or \
                    open(other, "rb").read() != own_records:
                collision = True
    check("slug-no-collision", not collision)

    print("PASS: %d FAIL: %d" % (len(passes), len(fails)))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
