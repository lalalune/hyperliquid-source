#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-ret.

Byte reads only; never executes the target binary. All checks are strict:
any FAIL makes the exit code non-zero. Run from the repository root.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research/work-items/RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-ret"
)
BINARY = os.path.join(ROOT, "artifacts/node/115/hl-node")
RECORDS = os.path.join(PACKET, "records.json")

WINDOW_START = 0x636BD90
WINDOW_END = 0x636C49C
BIN_SIZE = 105896032
BIN_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BIN_TABLE_INIT = 0x63D9880
LU_MISS = 0x63D9700
SLUG = "RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-ret"

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


def text_off(va):
    return va - 0x1000


def objdump_lines():
    with open(os.path.join(PACKET, "bintableinit_caller_walk_rsp_ret_4sites.objdump.txt")) as f:
        return f.read().splitlines()


STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
CALL_RE = re.compile(r"\tcall\s")


def parse_addr(line):
    m = re.match(r"^\s*([0-9a-f]+):", line)
    return int(m.group(1), 16) if m else None


def call_target(line):
    m = re.search(r"call\s+([0-9a-f]+)\s", line)
    return int(m.group(1), 16) if m else None


def main():
    global PASS, FAIL
    data = open(BINARY, "rb").read()
    check("binary-size", len(data) == BIN_SIZE, "got %d" % len(data))
    check("binary-sha256", hashlib.sha256(data).hexdigest() == BIN_SHA)

    # .eh_frame bounds via readelf (PC-relative sdata4 FDEs).
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", BINARY],
        capture_output=True, text=True, check=True,
    ).stdout
    fdes = []
    for m in re.finditer(r"pc=000000000([0-9a-f]+)\.\.000000000([0-9a-f]+)", frames):
        fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    check("eh-frame-window", (WINDOW_START, WINDOW_END) in fdes)
    prevs = [f for f in fdes if f[1] <= WINDOW_START]
    nexts = [f for f in fdes if f[0] >= WINDOW_END]
    check("gap-before-zero", prevs and max(prevs)[1] == WINDOW_START)
    check("next-fde", nexts and min(nexts)[0] == 0x636C4A0)
    pad = data[text_off(WINDOW_END):text_off(0x636C4A0)]
    check("padding-cc", pad == b"\xcc" * 4, pad.hex())

    # Exhibit bytes.
    raw = open(os.path.join(PACKET, "bintableinit_caller_walk_rsp_ret_4sites.hex"), "rb").read()
    check("hex-length", len(raw) == WINDOW_END - WINDOW_START == 1804)
    check("hex-bytes", raw == data[text_off(WINDOW_START):text_off(WINDOW_END)])

    lines = objdump_lines()
    strict = [l for l in lines if STRICT_RE.match(l)]
    check("strict-count", len(strict) == 379, "got %d" % len(strict))
    calls = [l for l in lines if CALL_RE.search(l)]
    check("call-count", len(calls) == 9, "got %d" % len(calls))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret-count", len(rets) == 1, "got %d" % len(rets))
    check("ret-address", rets and parse_addr(rets[0]) == 0x636BF08)
    bti = [l for l in calls if call_target(l) == BIN_TABLE_INIT]
    check("bti-count", len(bti) == 4, "got %d" % len(bti))
    check("bti-sites", [parse_addr(l) for l in bti] == [0x636BF96, 0x636BFF6, 0x636C04E, 0x636C233])
    miss = [l for l in calls if call_target(l) == LU_MISS]
    check("lu-miss-count", len(miss) == 4, "got %d" % len(miss))
    check("lu-miss-sites", [parse_addr(l) for l in miss] == [0x636C2C9, 0x636C359, 0x636C3E9, 0x636C492])
    check("stack-chk-fail-call", any(call_target(l) == 0x63F0D70 for l in calls))
    check("no-bsr", not any(re.search(r"\tbsr\s", l) for l in lines))

    # Branch shape: each bti site block is the target of exactly one je,
    # and each site sets rdi = rsp (mov rsp,reg then mov reg,rdi).
    je_targets = {}
    for l in lines:
        m = re.search(r"\tje\s+([0-9a-f]+)", l)
        if m:
            je_targets[int(m.group(1), 16)] = je_targets.get(int(m.group(1), 16), 0) + 1
    blocks = {0x636BF90: "r12", 0x636BFF0: "r15", 0x636C048: "r14", 0x636C22D: "r15"}
    for block, reg in blocks.items():
        check("je-target-%x" % block, je_targets.get(block, 0) == 1, "got %d" % je_targets.get(block, 0))
    strict_by_addr = {}
    for l in strict:
        strict_by_addr[parse_addr(l)] = l
    strict_addrs = sorted(strict_by_addr)
    for block, reg in blocks.items():
        first = strict_by_addr.get(block, "")
        nxt = strict_by_addr.get(strict_addrs[strict_addrs.index(block) + 1], "") if block in strict_addrs else ""
        check("rdi-rsp-%x" % block,
              "mov" in first and ("%%rsp,%%%s" % reg) in first
              and "mov" in nxt and ("%%%s,%%rdi" % reg) in nxt,
              (first.strip(), nxt.strip()))
    # Branch registers: site 1 from test rdi,rdi; sites 2-4 from test rbp,rbp.
    # (Match by parsed address + mnemonic, since objdump puts byte fields
    # between the address and the mnemonic.)
    def line_at(addr):
        for l in lines:
            if parse_addr(l) == addr:
                return l
        return ""
    check("branch-site1", "test" in line_at(0x636BDCA) and "%rdi,%rdi" in line_at(0x636BDCA), line_at(0x636BDCA).strip())
    check("branch-site2", "test" in line_at(0x636BE24) and "%rbp,%rbp" in line_at(0x636BE24), line_at(0x636BE24).strip())
    check("branch-site3", "test" in line_at(0x636BE7C) and "%rbp,%rbp" in line_at(0x636BE7C), line_at(0x636BE7C).strip())
    check("branch-site4", "test" in line_at(0x636BF25) and "%rbp,%rbp" in line_at(0x636BF25), line_at(0x636BF25).strip())
    # Threshold gate (value >> 0x30) vs 0x23, not a bsr block.
    check("threshold-gate", "cmp" in line_at(0x636BF14) and "$0x23" in line_at(0x636BF14), line_at(0x636BF14).strip())
    # Canary at 0x188(%rsp).
    check("canary-slot", "mov" in line_at(0x636BDAA) and "0x188(%rsp)" in line_at(0x636BDAA), line_at(0x636BDAA).strip())

    # Records consistency.
    rec = json.load(open(RECORDS))
    check("records-window", rec["window"]["range"] == "0x636bd90..0x636c49c")
    check("records-strict", rec["window"]["strict"] == 379)
    check("records-calls", rec["window"]["calls"] == 9)
    check("records-ret", rec["window"]["ret"] == 1)
    check("records-bti", rec["window"]["bin_table_init_sites"] == 4)
    check("records-miss", rec["window"]["lu_miss_sites"] == 4)
    check("records-bsr", rec["window"]["bsr"] == 0)
    check("records-gap", rec["window"]["gap_before"] == 0)
    check("records-padding", rec["window"]["padding_after"] == 4)
    check("records-pointer", rec["prior_pointer_verified"]["verified_bytes"] == 1804)
    check("records-pointer-sites", rec["prior_pointer_verified"]["verified_sites"] == 4)
    check("records-slug", rec["slug"] == SLUG)

    # .rela.dyn census (distinct from .rela.plt).
    rela = subprocess.run(["readelf", "-r", BINARY], capture_output=True, text=True, check=True).stdout
    dyn = rela.split("Relocation section '.rela.dyn'")[1].split("Relocation section")[0]
    dyn_total = len(re.findall(r"^[0-9a-f]{12} ", dyn, re.M))
    dyn_rel = dyn.count("R_X86_64_RELATIVE")
    check("rela-dyn-total", dyn_total == 60723, "got %d" % dyn_total)
    check("rela-dyn-relative", dyn_rel == 59534, "got %d" % dyn_rel)
    plt = rela.split("Relocation section '.rela.plt'")[1].split("Relocation section")[0] if ".rela.plt" in rela else ""
    check("rela-plt-separate", len(re.findall(r"^[0-9a-f]{12} ", plt, re.M)) == 278)

    # Disjointness: range-only collector over merged tree + prior worktrees.
    # Self-exclusion is by exact window equality, never by slug.
    def collect(obj, out):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ("census", "cited", "survey", "callers", "largest_caller_fde", "fde"):
                    continue
                if k in ("exhibits", "windows"):
                    items = v if isinstance(v, list) else v.values() if isinstance(v, dict) else []
                    for e in items:
                        if isinstance(e, dict):
                            if "range" in e:
                                r = e["range"]
                                out.append((int(r[0], 16), int(r[1], 16)) if isinstance(r, list)
                                           else tuple(int(x, 16) for x in r.split("..")))
                            elif "start" in e and "end" in e:
                                out.append((int(e["start"], 16), int(e["end"], 16)))
                else:
                    collect(v, out)
        elif isinstance(obj, list):
            for v in obj:
                collect(v, out)

    priors = []
    for root in [os.path.join(ROOT, "research/work-items")]:
        for dirpath, _, files in os.walk(root):
            if "records.json" in files:
                try:
                    collect(json.load(open(os.path.join(dirpath, "records.json"))), priors)
                except Exception:
                    pass
    import glob as globmod
    for d in globmod.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*/records.json"):
        try:
            collect(json.load(open(d)), priors)
        except Exception:
            pass
    mine = (WINDOW_START, WINDOW_END)
    bad = [p for p in priors if p != mine and mine[0] < p[1] and p[0] < mine[1]]
    check("disjointness", not bad, str(bad[:3]))

    # Slug collision: exactly one directory with this slug in the merged
    # tree (this packet itself), and no other dir shares the stem.
    merged = os.path.join(ROOT, "research/work-items")
    slug_dirs = [d for d in os.listdir(merged) if d == SLUG]
    check("slug-unique", slug_dirs == [SLUG], str(slug_dirs))
    others = [d for d in os.listdir(merged) if d != SLUG and "caller-4sites-walk-rsp-ret" in d]
    check("slug-stem-unique", not others, str(others))

    # Raw-e8 census grouped by enclosing .eh_frame FDE.
    sec = subprocess.run(["readelf", "-S", BINARY], capture_output=True, text=True, check=True).stdout
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", sec)
    taddr, toff, tsize = int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16)
    tdata = data[toff:toff + tsize]
    from collections import Counter
    cnt = Counter()
    for i in range(len(tdata) - 5):
        if tdata[i] == 0xE8:
            rel = struct.unpack_from("<i", tdata, i + 1)[0]
            va = taddr + i
            if va + 5 + rel == BIN_TABLE_INIT:
                for s, e in fdes:
                    if s <= va < e:
                        cnt[(s, e)] += 1
                        break
    check("raw-e8-this", cnt.get((WINDOW_START, WINDOW_END), 0) == 4)
    check("raw-e8-ranking", cnt.get((0x63CBA10, 0x63CCD22), 0) == 10
          and cnt.get((0x63C9C80, 0x63CB146), 0) == 8
          and cnt.get((0x63BD8C0, 0x63BE4CE), 0) == 5)

    # MANIFEST digests.
    import hashlib as hl
    man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
    ok = True
    for line in man:
        if not line.strip():
            continue
        digest, path = line.split(None, 1)
        path = path.strip().lstrip("*")
        full = os.path.normpath(os.path.join(PACKET, path)) if not path.startswith("../../../") \
            else os.path.normpath(os.path.join(PACKET, path))
        if hl.sha256(open(full, "rb").read()).hexdigest() != digest:
            ok = False
    check("manifest-digests", ok)

    print("PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
