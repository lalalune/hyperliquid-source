#!/usr/bin/env python3
"""Static verifier for packet RE-001-node115-lu-opt-groups61-64-leaves.

Byte reads only; never executes the binary. Checks:
  - target binary size + SHA-256
  - .rela.dyn node-slot resolution (handler + name) for groups 61-64
  - exhibit .hex bytes equal binary slices; strict recounts match records
  - FDE bounds from readelf --debug-dump=frames
  - value mechanisms (lea targets, .data table reads, stub bytes)
  - ret/call counts and jump containment per FDE
  - disjointness of all 4 windows from every prior claimed range
  - opt-children exhaustion: index-65 entry is not a node entry

Environment overrides (used by the unit tests):
  HL274_BINARY: path to the node binary (default: <root>/artifacts/node/115/hl-node)
  HL274_PACKET_DIR: packet dir (default: <root>/research/work-items/<slug>)
  HL274_PRIOR_ROOTS: colon-separated prior-roots list; when set, REPLACES
    the default prior roots (merged tree + hl-wt-calls* worktrees).
"""

import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lu-opt-groups61-64-leaves"
BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BINARY_SIZE = 105896032
OPT_ARRAY = 0x64de2e0
EXPECTED = [
    # name, node, handler start, handler end, value kind
    ("prof_sys_thread_name", 0x64dec68, 0x6374540, 0x63745c6, "byte"),
    ("prof_time_resolution", 0x64dec90, 0x63745d0, 0x63747dd, "u64-indirect-table"),
    ("lg_san_uaf_align", 0x64decb8, 0x6378080, 0x637808a, "const-return-stub"),
    ("zero_realloc", 0x64dece0, 0x63747e0, 0x63749ed, "u64-indirect-table"),
]
EXPECTED_NAMES = {
    "prof_sys_thread_name": 0x4498cc,
    "prof_time_resolution": 0x4363ed,
    "lg_san_uaf_align": 0x440c38,
    "zero_realloc": 0x440bf4,
}
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde")

passes = 0
failures = []


def check(cond, msg):
    global passes
    if cond:
        passes += 1
        print("PASS: " + msg)
    else:
        failures.append(msg)
        print("FAIL: " + msg)


def num(x):
    return x if isinstance(x, int) else int(x, 16)


def collect_ranges(obj, out):
    """Range-only collector: string ranges, [start,end] lists (hex or int),
    start/end pairs inside exhibits/windows lists or dicts. Never collects
    enclosing-fde annotation fields or census/cited-only metadata subtrees."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SKIP_KEYS or k == "fde":
                continue
            if k in ("exhibits", "windows"):
                items = v if isinstance(v, list) else v.values() if isinstance(v, dict) else []
                for e in items:
                    if isinstance(e, dict):
                        if "range" in e:
                            r = e["range"]
                            if isinstance(r, list):
                                out.append((num(r[0]), num(r[1])))
                            else:
                                out.append(tuple(int(x, 16) for x in r.split("..")))
                        elif "start" in e and "end" in e:
                            out.append((num(e["start"]), num(e["end"])))
            else:
                collect_ranges(v, out)
    elif isinstance(obj, list):
        for v in obj:
            collect_ranges(v, out)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    binary_path = os.environ.get("HL274_BINARY") or os.path.join(root, "artifacts/node/115/hl-node")
    packet_dir = os.environ.get("HL274_PACKET_DIR") or os.path.join(root, "research/work-items", SLUG)

    # 1. Binary identity
    data = open(binary_path, "rb").read()
    check(len(data) == BINARY_SIZE, "binary size %d" % BINARY_SIZE)
    check(hashlib.sha256(data).hexdigest() == BINARY_SHA256, "binary SHA-256 match")

    # 2. records.json shape
    rec = json.load(open(os.path.join(packet_dir, "records.json")))
    check(rec["packet"] == SLUG, "records packet slug")
    check(rec["base"] == "05bc2de303c05525b71e7e257426e741bc66a390", "records base hash")
    exhibits = {e["name"]: e for e in rec["exhibits"]}
    check(len(exhibits) == 4, "4 exhibits in records")

    # 3. .rela.dyn node-slot resolution
    rela_out = subprocess.run(["readelf", "-r", binary_path], capture_output=True, text=True).stdout
    rel = {}
    n_relative = 0
    for line in rela_out.splitlines():
        m = re.match(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if m:
            rel[int(m.group(1), 16)] = int(m.group(2), 16)
            n_relative += 1
    check(n_relative == 59534, ".rela.dyn RELATIVE count 59534 (got %d)" % n_relative)
    for name, node, hs, he, _kind in EXPECTED:
        check(rel.get(node + 0x20) == hs, "%s node+0x20 resolves to handler 0x%x" % (name, hs))
        naddr = rel.get(node + 0x08)
        check(naddr == EXPECTED_NAMES[name], "%s node+0x08 name addend 0x%x" % (name, EXPECTED_NAMES[name]))
        if naddr is not None:
            end = data.index(b"\0", naddr)
            check(data[naddr:end].decode() == name, "%s name string decodes" % name)

    # 4. Exhibit bytes + strict recounts
    for name, _node, hs, he, _kind in EXPECTED:
        raw = open(os.path.join(packet_dir, name + ".hex"), "rb").read()
        check(raw == data[hs - 0x1000:he - 0x1000], "%s .hex equals binary slice" % name)
        check(len(raw) == he - hs, "%s length == FDE size" % name)
        txt = open(os.path.join(packet_dir, name + ".objdump.txt")).read().splitlines()
        strict = sum(1 for l in txt if STRICT_RE.match(l))
        check(strict == exhibits[name]["strict"], "%s strict recount %d" % (name, strict))
        check(exhibits[name]["bytes"] == he - hs, "%s records bytes" % name)
    check(rec["totals"]["bytes"] == 1194, "total bytes 1194")
    check(rec["totals"]["strict"] == 337, "total strict 337")

    # 5. FDE bounds from readelf frames dump
    frames = subprocess.run(["readelf", "--debug-dump=frames", binary_path],
                            capture_output=True, text=True).stdout
    fdes = {}
    for line in frames.splitlines():
        m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            fdes[int(m.group(1), 16)] = int(m.group(2), 16)
    for name, _node, hs, he, _kind in EXPECTED:
        check(fdes.get(hs) == he, "%s FDE 0x%x..0x%x" % (name, hs, he))

    # 6. Value mechanisms
    obj = {}
    for name, _node, hs, he, _kind in EXPECTED:
        obj[name] = open(os.path.join(packet_dir, name + ".objdump.txt")).read()
    check("# 67125f0" in obj["prof_sys_thread_name"], "g61 lea target .bss 0x67125f0")
    check("# 6712370" in obj["prof_time_resolution"], "g62 index lea .bss 0x6712370")
    check("# 64ffca0" in obj["prof_time_resolution"], "g62 table lea .data 0x64ffca0")
    check("# 64ffb58" in obj["zero_realloc"], "g64 index lea .data 0x64ffb58")
    check("# 64ffb40" in obj["zero_realloc"], "g64 table lea .data 0x64ffb40")
    check(open(os.path.join(packet_dir, "lg_san_uaf_align.hex"), "rb").read().hex()
          == "f30f1efab802000000c3", "g63 stub bytes endbr64+mov $0x2+ret")
    # .data table reads (.data file offset = VA - 0x3000)
    def dq(va):
        return struct.unpack_from("<Q", data, va - 0x3000)[0]
    def du32(va):
        return struct.unpack_from("<I", data, va - 0x3000)[0]
    check([dq(0x64ffca0 + 8 * i) for i in range(4)] == [0, 0, 0x1ffffffff, 0],
          "g62 table first 4 qwords")
    check(du32(0x64ffb58) == 1, "g64 file-initial index u32 == 1")
    check(dq(0x64ffb48) == 0, "g64 file-initial selected entry table[1] == 0")

    # 7. ret/call counts + jump containment
    for name, _node, hs, he, _kind in EXPECTED:
        txt = obj[name]
        rets = len(re.findall(r"\tret\b", txt))
        calls = re.findall(r"\tcall\s+([0-9a-f]+)", txt)
        check(rets == 1, "%s exactly 1 ret" % name)
        if name == "lg_san_uaf_align":
            check(calls == [], "%s zero calls" % name)
        else:
            check(calls == ["63f0d70"], "%s single call is __stack_chk_fail PLT" % name)
        bad = []
        for l in txt.splitlines():
            m = re.match(r"\s*([0-9a-f]+):\t[0-9a-f ]+\t(j\w+|call)\s+([0-9a-f]+)", l)
            if m:
                tgt = int(m.group(3), 16)
                if m.group(2) == "call":
                    if tgt != 0x63f0d70:
                        bad.append(l.strip())
                elif not (hs <= tgt < he):
                    bad.append(l.strip())
        check(not bad, "%s all jumps inside FDE" % name)

    # 8. Disjointness vs prior claims
    prior_roots_env = os.environ.get("HL274_PRIOR_ROOTS")
    if prior_roots_env is not None:
        roots = [r for r in prior_roots_env.split(":") if r]
    else:
        roots = [os.path.join(root, "research/work-items")]
        roots += sorted(glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items"))
    priors = []
    seen_slugs = set()
    for rdir in roots:
        if not os.path.isdir(rdir):
            continue
        for d in sorted(glob.glob(os.path.join(rdir, "*"))):
            slug = os.path.basename(d)
            if slug == SLUG or slug in seen_slugs:
                continue
            rp = os.path.join(d, "records.json")
            if not os.path.isfile(rp):
                continue
            try:
                collect_ranges(json.load(open(rp)), priors)
                seen_slugs.add(slug)
            except Exception:
                continue
    mine = [(hs, he) for _n, _nd, hs, he, _k in EXPECTED]
    bad = [(m, p) for m in mine for p in priors if m[0] < p[1] and p[0] < m[1]]
    check(not bad, "all 4 windows disjoint from %d prior ranges" % len(priors))
    for a, b in mine:
        for c, d in mine:
            if (a, b) < (c, d):
                check(not (a < d and c < b), "windows disjoint from each other")
    explicit = [(0x63b8820, 0x63b8d85, "#232 merged FDE"),
                (0x63ec890, 0x63ec8a3, "#252 r28_wait"),
                (0x63d9700, 0x63d987b, "#215 handler"),
                (0x63721c0, 0x6372246, "#261 tcache"),
                (0x63737c0, 0x6373846, "#261 opt_prof"),
                (0x63749f0, 0x6374bfa, "#261 thread_allocated"),
                (0x6373850, 0x6373a5a, "#262 prof_prefix"),
                (0x6373a60, 0x6373ae6, "#262 prof_active"),
                (0x6373b80, 0x6373d97, "#262 lg_prof_sample"),
                (0x6378090, 0x637809a, "#269 xmalloc")]
    for es, ee, label in explicit:
        check(not any(a < ee and es < b for a, b in mine), "disjoint from %s" % label)

    # 9. Opt-children exhaustion: index-65 entry is not a node entry
    check(rel.get(0x64ded08 + 0x08) is None, "index-65 entry has no name-slot relocation")
    check(rel.get(0x64ded08 + 0x20) == 0x43fce3, "index-65 +0x20 resolves to .rodata, not .text")

    # 10. Slug collision: the slug must not already exist in HEAD's tree
    # (the worktree HEAD is origin/main; the packet dir itself is untracked).
    ls = subprocess.run(["git", "-C", root, "ls-tree", "HEAD",
                         "research/work-items/" + SLUG],
                        capture_output=True, text=True).stdout.strip()
    check(ls == "", "no slug collision in HEAD tree")

    print("VERIFIER OK: %d PASS, %d FAIL" % (passes, len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
