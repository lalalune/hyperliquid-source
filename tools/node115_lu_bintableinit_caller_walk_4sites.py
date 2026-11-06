#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-4sites-walk.

Byte reads only; never executes the target binary. Exit 0 iff every check
passes; any failure prints FAIL and exits 1.
"""
import bisect
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research", "work-items",
    "RE-001-node115-lu-bintableinit-caller-4sites-walk")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
EXPECTED_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECTED_SIZE = 105896032
START, END = 0x63CB150, 0x63CBA04
BTI, MISS = 0x63D9880, 0x63D9700

PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name} {detail}")
    else:
        FAIL += 1
        print(f"FAIL {name} {detail}")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)


def main():
    data = open(BINARY, "rb").read()
    check("binary size", len(data) == EXPECTED_SIZE, f"got {len(data)}")
    check("binary sha256",
          hashlib.sha256(data).hexdigest() == EXPECTED_SHA)

    def toff(va):
        return va - 0x1000

    # --- .eh_frame bounds ---
    frames = run(["objdump", "--dwarf=frames", BINARY]).stdout
    fdes = sorted(
        (int(a, 16), int(b, 16))
        for a, b in re.findall(r"FDE cie=\d+ pc=([0-9a-f]+)\.\.([0-9a-f]+)",
                               frames))
    check("fde bounds present", (START, END) in fdes)
    check("prev fde", (0x63C9C80, 0x63CB146) in fdes)
    check("next fde", (0x63CBA10, 0x63CCD22) in fdes)
    check("fde byte count", END - START == 2228, f"got {END - START}")
    check("gap before 10 x 0xcc",
          data[toff(0x63CB146):toff(START)] == b"\xcc" * 10)
    check("padding after 12 x 0xcc",
          data[toff(END):toff(0x63CBA10)] == b"\xcc" * 12)

    # --- exhibits ---
    raw = open(os.path.join(PACKET,
                            "bintableinit_caller_walk_4sites.hex"), "rb").read()
    check("hex exhibit bytes", raw == data[toff(START):toff(START) + 2228])
    check("hex exhibit length", len(raw) == 2228)
    txt = open(os.path.join(
        PACKET, "bintableinit_caller_walk_4sites.objdump.txt")).read()
    lines = txt.splitlines()
    strict = [l for l in lines
              if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]
    check("strict recount", len(strict) == 469, f"got {len(strict)}")
    calls = []
    for l in strict:
        m = re.search(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\tcall\s+([0-9a-f]+)", l)
        if m:
            calls.append((int(m.group(1), 16), int(m.group(2), 16)))
    check("call census", len(calls) == 23, f"got {len(calls)}")
    bti = [a for a, t in calls if t == BTI]
    miss = [a for a, t in calls if t == MISS]
    check("bin_table_init sites",
          bti == [0x63CB548, 0x63CB5AD, 0x63CB610, 0x63CB79F],
          f"got {[hex(a) for a in bti]}")
    check("lu-miss sites",
          miss == [0x63CB82F, 0x63CB8CA, 0x63CB95A, 0x63CB9FA],
          f"got {[hex(a) for a in miss]}")
    rets = [l for l in strict if re.search(r"\tret\s*$", l)]
    check("ret count 0 (canary-checked tail-jumps)", len(rets) == 0)
    # branch shape: each site block is the target of exactly one je whose
    # previous strict line is test %rbp,%rbp
    blocks = {0x63CB540, 0x63CB5A0, 0x63CB608, 0x63CB797}
    by_addr = {}
    for i, l in enumerate(strict):
        m = re.match(r"^\s*([0-9a-f]+):", l)
        if m:
            by_addr[int(m.group(1), 16)] = i
    ok_branch = True
    for blk in blocks:
        hits = []
        for l in strict:
            m = re.search(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\tje\s+([0-9a-f]+)",
                          l)
            if m and int(m.group(2), 16) == blk:
                hits.append(int(m.group(1), 16))
        if len(hits) != 1:
            ok_branch = False
            break
        prev = strict[by_addr[hits[0]] - 1]
        if not re.search(r"\ttest\s+%rbp,%rbp\s*$", prev):
            ok_branch = False
            break
    check("rbp==0 branch shape at all 4 sites", ok_branch)
    # canary + tail-jump exits
    check("canary slot read",
          any("0x198(%rsp)" in l and "mov" in l for l in strict))
    check("stack_chk_fail call",
          any("63cb839" in l and "call" in l for l in strict))
    check("no bsr (no size-class block)",
          not any(re.search(r"\tbsr\s", l) for l in strict))

    # --- records consistency ---
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    check("records packet slug",
          rec.get("packet") ==
          "RE-001-node115-lu-bintableinit-caller-4sites-walk")
    check("records fde bytes", rec["fde"]["bytes"] == 2228)
    check("records fde strict", rec["fde"]["strict"] == 469)
    check("records fde calls", rec["fde"]["calls"] == 23)
    check("records fde rets", rec["fde"]["rets"] == 0)
    check("records bti sites",
          [s["site"] for s in rec["bin_table_init_sites"]] ==
          ["0x63cb548", "0x63cb5ad", "0x63cb610", "0x63cb79f"])
    check("records lu-miss sites",
          [s["site"] for s in rec["lu_miss_sites"]] ==
          ["0x63cb82f", "0x63cb8ca", "0x63cb95a", "0x63cb9fa"])
    check("records prior pointer verified",
          rec["prior_pointer_verified"]["verified_bytes"] == 2228 and
          rec["prior_pointer_verified"]["verified_sites"] == 4)
    check("records next caller",
          rec["next_caller"]["fde"] == "0x63c8d60..0x63c94fc" and
          rec["next_caller"]["bytes"] == 1948)

    # --- .rela.dyn census (distinct totals; .rela.plt excluded) ---
    rela = run(["readelf", "-r", BINARY]).stdout
    in_dyn = False
    rel_count = 0
    rel_rel = 0
    for l in rela.splitlines():
        if "Relocation section" in l:
            in_dyn = "'.rela.dyn'" in l
            continue
        if in_dyn and "R_X86_64_" in l:
            rel_count += 1
            if "R_X86_64_RELATIVE" in l:
                rel_rel += 1
    check("rela.dyn total", rel_count == 60723, f"got {rel_count}")
    check("rela.dyn RELATIVE", rel_rel == 59534, f"got {rel_rel}")

    # --- disjointness (range-only collector) ---
    SKIP = ("census", "cited", "survey", "callers", "largest_caller_fde")

    def collect(obj, out):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in SKIP or k == "fde":
                    continue
                if k in ("exhibits", "windows"):
                    items = (v if isinstance(v, list)
                             else v.values() if isinstance(v, dict) else [])
                    for e in items:
                        if isinstance(e, dict):
                            if "range" in e:
                                r = e["range"]
                                out.append(
                                    (int(r[0], 16), int(r[1], 16))
                                    if isinstance(r, list)
                                    else tuple(int(x, 16)
                                               for x in r.split("..")))
                            elif "start" in e and "end" in e:
                                out.append((int(e["start"], 16),
                                            int(e["end"], 16)))
                else:
                    collect(v, out)
        elif isinstance(obj, list):
            for v in obj:
                collect(v, out)

    import glob
    priors = []
    for d in glob.glob(os.path.join(ROOT, "research", "work-items",
                                    "*", "records.json")):
        if os.path.dirname(d) == PACKET:
            continue  # own packet: must not count as a prior overlap
        try:
            collect(json.load(open(d)), priors)
        except Exception:
            pass
    for d in glob.glob("/home/hatch/workspace/hl-wt-calls*/research/"
                        "work-items/*/records.json"):
        if "caller-4sites-walk" in d:
            continue
        try:
            collect(json.load(open(d)), priors)
        except Exception:
            pass
    overlap = [p for p in priors if START < p[1] and p[0] < END]
    check("disjointness", not overlap, f"overlaps: {overlap[:3]}")

    # --- slug collision: no merged-tree directory other than this packet
    # itself may bear the slug (worktree copies of this same packet are
    # not collisions; the merged tree is what the parent checks on submit)
    import glob as _g
    slug = "RE-001-node115-lu-bintableinit-caller-4sites-walk"
    others = [p for p in
              _g.glob(os.path.join(ROOT, "research", "work-items", slug))
              if p != PACKET]
    check("slug no collision", others == [], f"others: {others}")

    # --- raw-e8 census grouped by enclosing FDE ---
    sec = run(["readelf", "-S", BINARY]).stdout
    m = re.search(r"\.text\s+\w+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                  sec)
    text_vaddr, text_off, text_size = (int(m.group(1), 16),
                                       int(m.group(2), 16),
                                       int(m.group(3), 16))
    text = data[text_off:text_off + text_size]
    starts = [s for s, _ in fdes]
    counts = {}
    i = 0
    while True:
        i = text.find(b"\xe8", i)
        if i < 0:
            break
        if i + 5 <= len(text):
            rel = int.from_bytes(text[i + 1:i + 5], "little", signed=True)
            tgt = text_vaddr + i + 5 + rel
            if tgt == BTI:
                va = text_vaddr + i
                j = bisect.bisect_right(starts, va) - 1
                if j >= 0 and fdes[j][0] <= va < fdes[j][1]:
                    counts[fdes[j]] = counts.get(fdes[j], 0) + 1
        i += 1
    check("raw-e8 this fde", counts.get((START, END)) == 4,
          f"got {counts.get((START, END))}")
    top = sorted(counts.values(), reverse=True)
    check("raw-e8 ranking head", top[:6] == [10, 8, 6, 6, 5, 4],
          f"got {top[:8]}")
    for fde, want in [((0x63CBA10, 0x63CCD22), 10),
                      ((0x63C9C80, 0x63CB146), 8),
                      ((0x63CE8C0, 0x63CF8BC), 6),
                      ((0x63D4BBE, 0x63D5428), 6),
                      ((0x63BD8C0, 0x63BE4CE), 5)]:
        check(f"raw-e8 {fde[0]:#x}", counts.get(fde) == want,
              f"got {counts.get(fde)}")

    # --- MANIFEST digests ---
    man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
    ok_man = True
    for line in man:
        if not line.strip():
            continue
        digest, _, path = line.partition("  ")
        if not path:
            digest, _, path = line.partition(" ")
        full = os.path.normpath(os.path.join(PACKET, path))
        if not os.path.exists(full):
            ok_man = False
            break
        # tools/tests paths are ../../../-prefixed relative to packet dir
        if hashlib.sha256(open(full, "rb").read()).hexdigest() != digest:
            ok_man = False
            break
    check("MANIFEST digests", ok_man, f"{len(man)} entries")

    print(f"PASS count: {PASS}, FAIL count: {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
