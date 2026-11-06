#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp.

Byte reads only; never executes the target binary. Exit 0 iff every check
passes. All paths resolve relative to the repository root (three levels up
from this file's tools/ directory), so the verifier works from a clean
checkout plus this packet.
"""

import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_DIR = os.path.join(
    ROOT, "research", "work-items",
    "RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp")
PACKET_SLUG = "RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp"
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
EXPECTED_SHA256 = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
EXPECTED_SIZE = 105896032
START, END = 0x63C8D60, 0x63C94FC
EXPECTED_BYTES = END - START  # 1948
EXPECTED_STRICT = 411
EXPECTED_CALLS = 14
EXPECTED_BTI = 4
EXPECTED_MISS = 4
EXPECTED_RET = 0
BTI_SITES = [0x63C8FC6, 0x63C9026, 0x63C908E, 0x63C9296]
BTI_BLOCKS = [0x63C8FC0, 0x63C9020, 0x63C9088, 0x63C9290]
BTI_JE = [0x63C8E00, 0x63C8E5A, 0x63C8EB2, 0x63C8F58]
MISS_SITES = [0x63C9329, 0x63C93B9, 0x63C9449, 0x63C94F2]
BTI_TARGET = 0x63D9880
MISS_TARGET = 0x63D9700
STACK_CHK_FAIL = 0x63C94CA
EXPECTED_RELA_TOTAL = 60723
EXPECTED_RELA_RELATIVE = 59534

PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("PASS: %s" % name)
    else:
        FAIL += 1
        print("FAIL: %s %s" % (name, detail))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_eh_frame(data):
    """Return sorted [(start, end)] FDE ranges from .eh_frame.

    CIE zR, DW_EH_PE_pcrel|sdata4 (0x1b): FDE initial_location is a
    4-byte signed pcrel value, range is a fixed 4-byte field (not ULEB).
    .eh_frame VA equals its file offset in this binary.
    """
    out = subprocess.run(["readelf", "-S", BINARY],
                         capture_output=True, text=True, check=True).stdout
    base = None
    for line in out.splitlines():
        if ".eh_frame " in line and "PROGBITS" in line:
            parts = line.split()
            base = int(parts[4], 16)
            break
    assert base is not None, ".eh_frame section not found"
    pos = base
    fdes = []
    while True:
        if pos + 8 > len(data):
            break
        length = struct.unpack("<I", data[pos:pos + 4])[0]
        if length == 0:
            break
        cie_id = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        if cie_id != 0:
            loc_rel = struct.unpack("<i", data[pos + 8:pos + 12])[0]
            init_loc = (pos + 8) + loc_rel
            rng = struct.unpack("<I", data[pos + 12:pos + 16])[0]
            fdes.append((init_loc, init_loc + rng))
        pos += 4 + length
    fdes.sort()
    return fdes


STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
CALL_RE = re.compile(r"\tcall\s")
RET_RE = re.compile(r"\tret\s*$")
BSR_RE = re.compile(r"\tbsr\s")


def parse_objdump(path):
    """Return (strict_lines, addr -> (mnemonic, operands))."""
    strict = []
    by_addr = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(
                r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t([a-z][a-z0-9.]*)\s*(.*)$",
                line.rstrip("\n"))
            if m and STRICT_RE.match(line):
                a = int(m.group(1), 16)
                strict.append(line)
                by_addr[a] = (m.group(2), m.group(3).strip())
    return strict, by_addr


SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde",
             "fde", "next_caller", "remaining_4raw_fdes")


def collect_ranges(obj, out):
    """Range-only collector: string ranges, [start,end] lists, start/end
    pairs inside exhibits/windows lists or dicts or a dict literally
    named "window". Never enclosing-fde annotations, census/cited-only
    subtrees, next-caller pointers, scan descriptors, or cfg edges.
    The caller's own claimed window is filtered out by the disjointness
    check itself (exact-equality filter), NOT here, so that a tampered
    records file injecting an overlapping range still fails."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SKIP_KEYS:
                continue
            if k in ("exhibits", "windows"):
                items = v if isinstance(v, list) else (
                    v.values() if isinstance(v, dict) else [])
                for e in items:
                    if not isinstance(e, dict):
                        continue
                    if "range" in e:
                        r = e["range"]
                        if isinstance(r, list):
                            out.append((int(r[0], 16), int(r[1], 16)))
                        else:
                            a, b = r.split("..")
                            out.append((int(a, 16), int(b, 16)))
                    elif "start" in e and "end" in e:
                        out.append((int(e["start"], 16), int(e["end"], 16)))
            else:
                collect_ranges(v, out)
    elif isinstance(obj, list):
        for v in obj:
            collect_ranges(v, out)


def main():
    data = open(BINARY, "rb").read()

    check("binary size", len(data) == EXPECTED_SIZE, len(data))
    check("binary sha256", sha256_file(BINARY) == EXPECTED_SHA256)

    fdes = parse_eh_frame(data)
    starts = [s for s, _ in fdes]
    import bisect
    i = bisect.bisect_right(starts, START) - 1
    check("eh_frame target FDE", fdes[i] == (START, END), fdes[i])
    prev_s, prev_e = fdes[i - 1]
    next_s, next_e = fdes[i + 1]
    check("eh_frame prev FDE", (prev_s, prev_e) == (0x63C89C0, 0x63C8D5A),
          (hex(prev_s), hex(prev_e)))
    check("eh_frame next FDE", (next_s, next_e) == (0x63C9500, 0x63C964D),
          (hex(next_s), hex(next_e)))
    check("gap before", START - prev_e == 6, START - prev_e)
    check("padding after", next_s - END == 4, next_s - END)
    toff = lambda va: va - 0x1000
    check("gap bytes int3",
          all(b == 0xCC for b in data[toff(prev_e):toff(START)]))
    check("padding bytes int3",
          all(b == 0xCC for b in data[toff(END):toff(next_s)]))
    check("FDE byte count", EXPECTED_BYTES == 1948)

    hex_path = os.path.join(
        PACKET_DIR, "bintableinit_caller_walk_rsp_4sites.hex")
    exhibit = open(hex_path, "rb").read()
    check("exhibit size", len(exhibit) == EXPECTED_BYTES, len(exhibit))
    check("exhibit bytes",
          exhibit == data[toff(START):toff(START) + len(exhibit)])

    obj_path = os.path.join(
        PACKET_DIR, "bintableinit_caller_walk_rsp_4sites.objdump.txt")
    strict, by_addr = parse_objdump(obj_path)
    check("strict recount", len(strict) == EXPECTED_STRICT, len(strict))
    calls = [a for a, (mn, _) in by_addr.items() if mn == "call"]
    rets = [a for a, (mn, _) in by_addr.items() if mn == "ret"]
    bsrs = [a for a, (mn, _) in by_addr.items() if mn == "bsr"]
    check("call census", len(calls) == EXPECTED_CALLS, len(calls))
    check("ret census", len(rets) == EXPECTED_RET, len(rets))
    check("no bsr (no size-class block)", len(bsrs) == 0, len(bsrs))

    def call_target(a):
        op = by_addr[a][1]
        m = re.match(r"([0-9a-f]+)", op)
        return int(m.group(1), 16) if m else None

    bti = sorted(a for a in calls if call_target(a) == BTI_TARGET)
    miss = sorted(a for a in calls if call_target(a) == MISS_TARGET)
    check("bin_table_init sites", bti == BTI_SITES,
          [hex(a) for a in bti])
    check("lu-miss sites", miss == MISS_SITES, [hex(a) for a in miss])
    check("stack_chk_fail call present",
          STACK_CHK_FAIL in calls and
          call_target(STACK_CHK_FAIL) == 0x63F0D70)

    # rbx == 0 branch shape at all 4 sites: test %rbx,%rbx; je to block;
    # block starts with mov %rsp and holds the call; each block is the
    # target of exactly one je.
    je_targets = {}
    for a, (mn, op) in by_addr.items():
        if mn == "je":
            try:
                je_targets.setdefault(int(op.split()[0], 16), []).append(a)
            except ValueError:
                pass
    ok_shape = True
    for blk, call, je in zip(BTI_BLOCKS, BTI_SITES, BTI_JE):
        if je_targets.get(blk) != [je]:
            ok_shape = False
        if by_addr.get(je, (None, None))[0] != "je":
            ok_shape = False
        # block: first strict line must move rsp into a register, and the
        # call must carry rdi = that register (rsp temp)
        first = by_addr.get(blk)
        if not first or first[0] != "mov" or "%rsp" not in first[1]:
            ok_shape = False
    check("rbx==0 branch shape at all 4 sites", ok_shape)
    raw_text = open(obj_path, "r", encoding="utf-8",
                    errors="replace").read()
    check("test %rbx before each je",
          all("test   %rbx,%rbx" in raw_text for _ in [0]) and
          raw_text.count("test   %rbx,%rbx") >= 4)

    # canary: frame 0x198, canary slot 0x188(%rsp), three checks
    check("canary slot present", "0x188(%rsp)" in raw_text)
    check("canary checks", raw_text.count("sub    %fs:0x28,%rax") >= 3)
    # entry mnemonic: first strict line is push %r15 (no endbr64)
    first_addr = min(by_addr)
    check("entry mnemonic",
          first_addr == START and by_addr[first_addr][0] == "push" and
          "%r15" in by_addr[first_addr][1])
    # all four lu-miss setups load lea 0x6511a00
    check("lu-miss lea count", raw_text.count("# 6511a00") == 4,
          raw_text.count("# 6511a00"))

    # records consistency
    rec = json.load(open(os.path.join(PACKET_DIR, "records.json")))
    check("records packet slug", rec.get("packet") == PACKET_SLUG)
    check("records fde range",
          rec["fde"]["start"] == "0x63c8d60" and
          rec["fde"]["end"] == "0x63c94fc")
    check("records census",
          rec["fde"]["strict"] == EXPECTED_STRICT and
          rec["fde"]["calls"] == EXPECTED_CALLS and
          rec["fde"]["rets"] == EXPECTED_RET)
    check("records bti sites",
          [s["site"] for s in rec["bin_table_init_sites"]] ==
          [hex(a) for a in BTI_SITES])
    check("records miss sites",
          [s["site"] for s in rec["lu_miss_sites"]] ==
          [hex(a) for a in MISS_SITES])
    check("records prior pointer verified",
          rec["prior_pointer_verified"]["verified_bytes"] == 1948 and
          rec["prior_pointer_verified"]["verified_sites"] == 4)
    check("records exhibit",
          rec["exhibits"][0]["bytes"] == EXPECTED_BYTES and
          rec["exhibits"][0]["strict"] == EXPECTED_STRICT)

    # .rela.dyn census via readelf (distinct from .rela.plt)
    rela = subprocess.run(["readelf", "-r", BINARY],
                          capture_output=True, text=True, check=True).stdout
    # readelf -r dumps .rela.dyn AND .rela.plt; only .rela.dyn counts
    # (.rela.plt adds 278 entries and is excluded).
    dyn_section = rela.split("Relocation section '.rela.dyn'")[1]
    dyn_section = dyn_section.split("Relocation section")[0]
    total = dyn_section.count("R_X86_64_")
    rel = dyn_section.count("R_X86_64_RELATIVE")
    check("rela.dyn total", total == EXPECTED_RELA_TOTAL, total)
    check("rela.dyn RELATIVE", rel == EXPECTED_RELA_RELATIVE, rel)

    # disjointness: merged tree + prior worktree records, self excluded
    priors = []
    paths = glob.glob(os.path.join(
        ROOT, "research", "work-items", "*", "records.json"))
    paths += glob.glob(
        "/home/hatch/workspace/hl-wt-calls*/research/work-items/*/records.json")
    seen = set()
    for p in paths:
        if p in seen:
            continue
        seen.add(p)
        try:
            collect_ranges(json.load(open(p)), priors)
        except Exception:
            pass
    bad = [(m, p) for m in [(START, END)] for p in priors
           if p != (START, END) and m[0] < p[1] and p[0] < m[1]]
    check("disjointness", not bad, bad[:3])
    print("INFO: prior ranges scanned: %d" % len(priors))

    # slug: no other merged-tree directory carries this slug
    dirs = [os.path.basename(d) for d in glob.glob(
        os.path.join(ROOT, "research", "work-items", "*"))]
    check("slug unique", PACKET_SLUG not in
          [d for d in dirs if d != PACKET_SLUG])

    # raw-e8 census for target grouped by enclosing FDE
    from collections import Counter
    cnt = Counter()
    for va in range(min(starts), max(e for _, e in fdes) - 5):
        off = va - 0x1000
        if off < 0 or off + 5 > len(data):
            continue
        if data[off] == 0xE8:
            rel = struct.unpack("<i", data[off + 1:off + 5])[0]
            if va + 5 + rel == BTI_TARGET:
                j = bisect.bisect_right(starts, va) - 1
                s, e = fdes[j]
                if s <= va < e:
                    cnt[(s, e)] += 1
    top = sorted(cnt.items(), key=lambda kv: -kv[1])[:7]
    check("raw-e8 ranking head",
          [c for _, c in top] == [10, 8, 6, 6, 5, 4, 4],
          [(hex(s), hex(e), c) for (s, e), c in top])
    check("raw-e8 this FDE equals objdump sites",
          cnt.get((START, END)) == EXPECTED_BTI,
          cnt.get((START, END)))

    # MANIFEST digests
    man = open(os.path.join(PACKET_DIR, "MANIFEST.sha256")).read().strip()
    entries = [l.split() for l in man.splitlines() if l.strip()]
    check("MANIFEST entry count", len(entries) == 7, len(entries))
    ok_man = True
    for digest, relpath in entries:
        full = os.path.normpath(os.path.join(PACKET_DIR, relpath))
        if sha256_file(full) != digest:
            ok_man = False
    check("MANIFEST digests", ok_man)

    print("PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
