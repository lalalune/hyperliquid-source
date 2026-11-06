#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-opt-leaves-bin-cleanup.

Byte reads only; never executes the node binary. Usage:
  python3 tools/node115_lu_opt_leaves_bin_cleanup.py [packet_dir] [binary]
Defaults: the packet dir under this repo and artifacts/node/115/hl-node.
Exit 0 only if every check passes; any failure is reported and the exit
code is 1 (failure propagation is `ok = ok and check(...)`, never the
`ok = fail(...) or ok` shape that packet #257 caught).
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032
STRICT = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
SKIP_KEYS = {"census", "cited", "survey", "largest_caller_fde",
             "callers", "caller_fdes", "fde"}
EXPLICIT = [(0x63b8820, 0x63b8d85, "#232 merged FDE"),
            (0x63ec890, 0x63ec8a3, "#252 r28_wait"),
            (0x63d9700, 0x63d987b, "#215 handler FDE")]

failures = []


def fail(msg):
    failures.append(msg)
    print("FAIL:", msg)


def check(cond, msg):
    if not cond:
        fail(msg)
    return cond


def va_to_off(data, va):
    """Program-header VA -> file offset; None if VA is outside file data."""
    e_phoff = struct.unpack("<Q", data[0x20:0x28])[0]
    e_phentsize = struct.unpack("<H", data[0x36:0x38])[0]
    e_phnum = struct.unpack("<H", data[0x38:0x3a])[0]
    for i in range(e_phnum):
        p = e_phoff + i * e_phentsize
        p_type, _flags, p_offset, p_vaddr, _p, p_filesz, _m, _a = \
            struct.unpack("<IIQQQQQQ", data[p:p + 56])
        if p_type == 1 and p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None


def objdump_lines(binary, start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % end, binary],
        capture_output=True, text=True).stdout
    lines = out.splitlines()
    # Strip the 2 header lines: blank + path-embedding file-format line.
    if len(lines) >= 2 and lines[0] == "" and "file format" in lines[1]:
        lines = lines[2:]
    return lines


def strict_count(lines):
    return sum(1 for line in lines if STRICT.match(line))


def rip_target(insn_va, next_va, disp):
    return next_va + disp


def collect_ranges(node, out, in_exhibits=False):
    """Range-only collector (packets #253/#259/#260/#261/#262 method).

    Collects ONLY exhibited windows: string `range` fields, [start, end]
    lists, and start/end pairs inside `exhibits` lists or dicts, and
    `windows` lists or dicts. Never collects enclosing-`fde` annotation
    fields and never descends into census/cited-only metadata subtrees.
    """
    if isinstance(node, dict):
        for key, val in node.items():
            if key in SKIP_KEYS:
                continue
            if key == "range" and isinstance(val, str):
                m = re.match(r"0x([0-9a-f]+)\.\.0x([0-9a-f]+)$", val)
                if m:
                    out.append((int(m.group(1), 16), int(m.group(2), 16)))
                continue
            if key in ("exhibits", "windows"):
                collect_ranges(val, out, in_exhibits=True)
                continue
            if in_exhibits and key in ("start", "end"):
                continue
            collect_ranges(val, out, in_exhibits)
    elif isinstance(node, list):
        if in_exhibits and len(node) == 2 and all(
                isinstance(x, int) for x in node):
            out.append((node[0], node[1]))
            return
        for item in node:
            if isinstance(item, dict) and in_exhibits and \
                    isinstance(item.get("start"), int) and \
                    isinstance(item.get("end"), int):
                out.append((item["start"], item["end"]))
                # Still walk the item for nested range fields, but the
                # start/end pair itself is already collected.
                for key, val in item.items():
                    if key not in ("start", "end"):
                        collect_ranges(val, out, in_exhibits)
            else:
                collect_ranges(item, out, in_exhibits)


def overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def main():
    ok = True
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    packet = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        repo, "research/work-items/RE-001-node115-lu-opt-leaves-bin-cleanup")
    binary = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        repo, "artifacts/node/115/hl-node")
    data = open(binary, "rb").read()
    ok = check(len(data) == SIZE, "binary size %d != %d" % (len(data), SIZE)) and ok
    ok = check(hashlib.sha256(data).hexdigest() == SHA,
               "binary SHA-256 mismatch") and ok

    rec = json.load(open(os.path.join(packet, "records.json")))
    exhibits = rec["exhibits"]
    mine = []
    for ex in exhibits:
        s, e = ex["start"], ex["end"]
        mine.append((s, e))
        raw = open(os.path.join(packet, ex["hex"]), "rb").read()
        off = va_to_off(data, s)
        ok = check(off is not None, "%s: VA not in file" % ex["name"]) and ok
        if off is not None:
            ok = check(raw == data[off:off + (e - s)],
                       "%s: .hex bytes differ from binary slice" % ex["name"]) and ok
        ok = check(len(raw) == ex["size"] == e - s,
                   "%s: size mismatch" % ex["name"]) and ok
        stored = open(os.path.join(packet, ex["objdump"]), "r").read().splitlines()
        if len(stored) >= 2 and stored[0] == "" and "file format" in stored[1]:
            stored = stored[2:]
        regen = objdump_lines(binary, s, e)
        ok = check(stored == regen,
                   "%s: objdump regeneration differs" % ex["name"]) and ok
        n = strict_count(regen)
        ok = check(n == ex["strict_instructions"],
                   "%s: strict count %d != records %d"
                   % (ex["name"], n, ex["strict_instructions"])) and ok

    # Leaf entry/lea/return checks (shared layout, handler+0x22 lea).
    for leaf in rec["leaves"]:
        h = leaf["handler"]
        off = va_to_off(data, h)
        ok = check(data[off:off + 4] == bytes.fromhex("f30f1efa"),
                   "%s: entry is not endbr64" % leaf["leaf"]) and ok
        ok = check(data[off + 4:off + 8] == bytes.fromhex("4883ec18"),
                   "%s: entry is not sub $0x18,%%rsp" % leaf["leaf"]) and ok
        lea_off = off + 0x22
        ok = check(data[lea_off:lea_off + 3] == bytes.fromhex("488d05"),
                   "%s: lea opcode missing at +0x22" % leaf["leaf"]) and ok
        disp = struct.unpack_from("<i", data, lea_off + 3)[0]
        tgt = rip_target(h, h + 0x22 + 7, disp)
        ok = check(tgt == leaf["global_byte"],
                   "%s: lea target %#x != global %#x"
                   % (leaf["leaf"], tgt, leaf["global_byte"])) and ok
        if leaf["global_section"] == ".data":
            goff = va_to_off(data, leaf["global_byte"])
            ok = check(goff is not None and data[goff] == leaf["file_byte"],
                       "%s: .data file byte != %s"
                       % (leaf["leaf"], leaf["file_byte"])) and ok
        # .rela.dyn slot addend == handler (file slots are zero-filled).
        # .rela.dyn r_offset values are VAs; match the slot VA directly.
        rela = 0x6be8
        found = None
        for i in range(0x163cc8 // 24):
            roff, info, add = struct.unpack_from("<QQq", data, rela + i * 24)
            if (info & 0xffffffff) == 8 and roff == leaf["slot"]:
                found = add
        ok = check(found == h, "%s: .rela.dyn slot addend %#x != handler %#x"
                   % (leaf["leaf"], found if found is not None else -1, h)) and ok

    # bin_cleanup checks.
    c = rec["callees"]["bin_cleanup"]
    off = va_to_off(data, 0x63ec690)
    ok = check(data[off:off + 4] == bytes.fromhex("f30f1efa"),
               "bin_cleanup: entry is not endbr64") and ok
    ok = check(data[off + 0x12:off + 0x18] == bytes.fromhex("8b05a8c13300"),
               "bin_cleanup: count-global load bytes differ") and ok
    lines = objdump_lines(binary, 0x63ec690, 0x63ec797)
    text = "\n".join(lines)
    ok = check("cmp    $0x23,%ebp" in text or "cmp    $0x23,%ebx" in text or
               "$0x23" in text, "bin_cleanup: 36-split cmp missing") and ok
    ok = check("call   63f17b0" in text, "bin_cleanup: trylock call missing") and ok
    ok = check("call   63bf680" in text, "bin_cleanup: wait-helper call missing") and ok
    ok = check("lock add" in text, "bin_cleanup: lock-add path missing") and ok
    ok = check("movq   $0x0" in text, "bin_cleanup: slot-clear missing") and ok
    ok = check(any(l.strip().endswith("\tret") for l in lines),
               "bin_cleanup: ret missing") and ok

    # bin_setup_52f60 checks.
    lines = objdump_lines(binary, 0x6352f60, 0x6352fb6)
    text = "\n".join(lines)
    for tgt in ("6364420", "6364410", "6364400"):
        ok = check(("call   " + tgt) in text,
                   "52f60: getter call %s missing" % tgt) and ok
    ok = check("0x90(%r12)" in text, "52f60: +0x90 store missing") and ok
    ok = check("jmp    6360ed0" in text, "52f60: tail jmp missing") and ok

    # Head checks (entry bytes + key constants).
    off = va_to_off(data, 0x6352fc0)
    ok = check(data[off:off + 4] == bytes.fromhex("f30f1efa"),
               "52fc0 head: entry is not endbr64") and ok
    text = "\n".join(objdump_lines(binary, 0x6352fc0, 0x63530d5))
    ok = check("cmpl   $0x2" in text and "64ffb80" in text,
               "52fc0 head: >2 guard missing") and ok
    ok = check("call   63f17b0" in text, "52fc0 head: trylock call missing") and ok
    off = va_to_off(data, 0x63e91c0)
    ok = check(data[off] == 0x41,
               "e91c0 head: entry must NOT be endbr64 (starts with push)") and ok
    text = "\n".join(objdump_lines(binary, 0x63e91c0, 0x63e92cd))
    ok = check("call   63f0a90" in text, "e91c0 head: memset call missing") and ok
    ok = check("call   63eebd0" in text, "e91c0 head: 0x63eebd0 call missing") and ok
    ok = check("cmp    $0x23,%ebx" in text, "e91c0 head: 36-split cmp missing") and ok
    text = "\n".join(objdump_lines(binary, 0x6365150, 0x6365212))
    ok = check("cmp    $0x3800,%rdx" in text, "65150: 0x3800 threshold missing") and ok
    ok = check("cmp    $0x1000,%rdx" in text, "65150: 0x1000 threshold missing") and ok
    ok = check("67277c0" in text, "65150: class-table lea missing") and ok
    ok = check(any(l.strip().endswith("\tret") for l in
                   objdump_lines(binary, 0x6365150, 0x6365212)),
               "65150: fastpath ret missing") and ok

    # Totals.
    ok = check(rec["total_claimed_bytes"] == sum(e - s for s, e in mine),
               "total_claimed_bytes mismatch") and ok
    ok = check(rec["total_strict_instructions"] ==
               sum(ex["strict_instructions"] for ex in exhibits),
               "total_strict_instructions mismatch") and ok

    # Disjointness: my windows vs each other, explicit ranges, and all
    # prior claimed ranges from the merged tree + prior worktrees.
    for i in range(len(mine)):
        for j in range(i + 1, len(mine)):
            ok = check(not overlaps(mine[i], mine[j]),
                       "self-overlap %s vs %s" % (mine[i], mine[j])) and ok
    for s, e, label in EXPLICIT:
        for w in mine:
            ok = check(not overlaps(w, (s, e)),
                       "overlap with %s" % label) and ok
    prior = []
    roots = []
    wt_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Merged tree: this worktree's research/work-items (excluding mine).
    roots.append(os.path.join(wt_root, "research/work-items"))
    # Prior worktrees: sibling hl-wt-calls*-115 dirs.
    parent = os.path.dirname(wt_root)
    for name in sorted(os.listdir(parent)):
        if name.startswith("hl-wt-calls") and name.endswith("-115"):
            p = os.path.join(parent, name, "research/work-items")
            if os.path.isdir(p):
                roots.append(p)
    seen_slugs = set()
    for root in roots:
        if not os.path.isdir(root):
            continue
        for slug in sorted(os.listdir(root)):
            if slug == "RE-001-node115-lu-opt-leaves-bin-cleanup":
                continue
            if slug in seen_slugs:
                continue
            seen_slugs.add(slug)
            rpath = os.path.join(root, slug, "records.json")
            if not os.path.isfile(rpath):
                continue
            try:
                other = json.load(open(rpath))
            except Exception:
                continue
            ranges = []
            collect_ranges(other, ranges)
            for r in ranges:
                prior.append((r, slug))
    for w in mine:
        for (s, e), slug in prior:
            if overlaps(w, (s, e)):
                ok = check(False, "overlap with %s range %#x..%#x" % (slug, s, e)) and ok
    print("prior claimed ranges collected: %d (from %d packet dirs)"
          % (len(prior), len(seen_slugs)))

    # MANIFEST check.
    man = os.path.join(packet, "MANIFEST.sha256")
    if os.path.isfile(man):
        for line in open(man):
            parts = line.split()
            if len(parts) != 2:
                continue
            digest, rel = parts
            if rel == "MANIFEST.sha256":
                continue
            full = os.path.normpath(os.path.join(packet, rel))
            if not os.path.isfile(full):
                ok = check(False, "MANIFEST entry missing: %s" % rel) and ok
                continue
            actual = hashlib.sha256(open(full, "rb").read()).hexdigest()
            ok = check(actual == digest, "MANIFEST mismatch: %s" % rel) and ok
    else:
        ok = check(False, "MANIFEST.sha256 missing") and ok

    if failures:
        print("VERIFIER FAILED: %d failure(s)" % len(failures))
        return 1
    print("VERIFIER OK: %d exhibits, %d bytes, %d strict instructions"
          % (len(exhibits), rec["total_claimed_bytes"],
             rec["total_strict_instructions"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
