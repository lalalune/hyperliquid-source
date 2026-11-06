#!/usr/bin/env python3
"""Static verifier for packet RE-001-node115-lu-opt-groups26-30-leaves.

Byte reads only; never executes the binary. Exit 0 iff every check passes.
Env override: HL268_PRIOR_ROOTS (colon-separated) replaces the prior-record
roots, used by the tamper test to inject a fake overlapping prior record.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.environ.get(
    "HL268_PACKET_DIR",
    os.path.join(ROOT, "research", "work-items",
                 "RE-001-node115-lu-opt-groups26-30-leaves"))
BINARY = os.environ.get(
    "HL268_BINARY",
    os.path.join(ROOT, "artifacts", "node", "115", "hl-node"))
BINARY_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BINARY_SIZE = 105896032
BASE = "05bc2de303c05525b71e7e257426e741bc66a390"

PASS = 0
FAIL = 0


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def parse_records():
    with open(os.path.join(PACKET, "records.json")) as f:
        return json.load(f)


def read_binary():
    with open(BINARY, "rb") as f:
        return f.read()


STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")


def strict_lines(path):
    with open(path) as f:
        return sum(1 for line in f if STRICT_RE.match(line))


def objdump_lines(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % end, BINARY],
        capture_output=True, text=True, check=True).stdout.splitlines()
    # Strip the 2 path-embedding header lines: blank line + file-format line.
    return [l for l in out if l.strip() and "file format" not in l]


def parse_eh_frame(data):
    """Return list of (start, end) FDE ranges from .eh_frame (pcrel sdata4)."""
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, _typ, _fl, addr, offset, size = struct.unpack_from("<IIQQQQ", data, off)
        secs.append((name, addr, offset, size))
    shstr = secs[e_shstrndx]

    def nm(n):
        end = data.index(b"\x00", shstr[2] + n)
        return data[shstr[2] + n:end].decode()

    eh = None
    for name, addr, offset, size in secs:
        if nm(name) == ".eh_frame":
            eh = (addr, offset, size)
            break
    assert eh is not None
    eh_addr, eh_off, eh_size = eh

    def uleb(p):
        r = 0
        sh = 0
        while True:
            b = data[p]
            p += 1
            r |= (b & 0x7F) << sh
            if not (b & 0x80):
                break
            sh += 7
        return r, p

    def sleb(p):
        r = 0
        sh = 0
        while True:
            b = data[p]
            p += 1
            r |= (b & 0x7F) << sh
            sh += 7
            if not (b & 0x80):
                if b & 0x40:
                    r |= -(1 << sh)
                break
        return r, p

    off = eh_off
    end = eh_off + eh_size
    cies = {}
    fdes = []
    while off < end:
        ln = struct.unpack_from("<I", data, off)[0]
        if ln == 0 or ln == 0xFFFFFFFF:
            break
        cid = struct.unpack_from("<I", data, off + 4)[0]
        body = off + 8
        if cid == 0:
            ver = data[body]
            aug_end = data.index(b"\x00", body + 1)
            aug = data[body + 1:aug_end].decode()
            p = aug_end + 1
            _, p = uleb(p)
            _, p = sleb(p)
            if ver == 1:
                p += 1
            else:
                _, p = uleb(p)
            if "z" in aug:
                _alen, p = uleb(p)
                if "R" in aug:
                    cies[off] = data[p]
        else:
            cie_off = off + 4 - cid
            if cie_off in cies:
                field_va = eh_addr + (body - eh_off)
                init = struct.unpack_from("<i", data, body)[0] + field_va
                rng = struct.unpack_from("<I", data, body + 4)[0]
                fdes.append((init, init + rng))
        off += 4 + ln
    return fdes


def parse_rela(data):
    """Return (rel_offset -> addend) for RELATIVE entries, and total count."""
    rela_off, rela_size = 0x6BE8, 0x163CC8
    rel = {}
    total = rela_size // 24
    for i in range(total):
        off, info, add = struct.unpack_from("<QQq", data, rela_off + i * 24)
        if (info & 0xFFFFFFFF) == 8:
            rel[off] = add
    return rel, total


SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde")


def collect_ranges(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SKIP_KEYS or k == "fde":
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
                        s, en = e["start"], e["end"]
                        out.append((int(s, 16) if isinstance(s, str) else s,
                                    int(en, 16) if isinstance(en, str) else en))
            else:
                collect_ranges(v, out)
    elif isinstance(obj, list):
        for v in obj:
            collect_ranges(v, out)


def prior_ranges():
    roots = os.environ.get("HL268_PRIOR_ROOTS")
    if roots:
        dirs = roots.split(":")
    else:
        import glob
        dirs = glob.glob(os.path.join(ROOT, "research", "work-items", "*"))
        dirs += glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*")
    seen_slugs = set()
    priors = []
    for d in dirs:
        slug = os.path.basename(d.rstrip("/"))
        if slug == "RE-001-node115-lu-opt-groups26-30-leaves":
            continue
        if slug in seen_slugs:
            continue
        seen_slugs.add(slug)
        rec_path = os.path.join(d, "records.json")
        if not os.path.exists(rec_path):
            continue
        try:
            with open(rec_path) as f:
                collect_ranges(json.load(f), priors)
        except Exception:
            continue
    return priors, len(seen_slugs)


def main():
    rec = parse_records()
    data = read_binary()
    ok(len(data) == BINARY_SIZE, "binary size %d != %d" % (len(data), BINARY_SIZE))
    ok(hashlib.sha256(data).hexdigest() == BINARY_SHA, "binary sha256 mismatch")
    ok(rec.get("base") == BASE, "records base mismatch")
    ok(rec.get("binary_sha256") == BINARY_SHA, "records sha mismatch")

    exhibits = rec["exhibits"]
    ok(len(exhibits) == 5, "expected 5 exhibits, got %d" % len(exhibits))
    total_bytes = 0
    total_strict = 0
    fdes = parse_eh_frame(data)
    fde_starts = {a: b for a, b in fdes}
    rel, rela_total = parse_rela(data)
    ok(rela_total == 60723, "rela total %d != 60723" % rela_total)
    ok(len(rel) == 59534, "RELATIVE count %d != 59534" % len(rel))

    leaf_by_name = {l["leaf"]: l for l in rec["leaves"]}
    for e in exhibits:
        name = e["name"]
        s, en = e["range"].split("..")
        s, en = int(s, 16), int(en, 16)
        ok(e["start"] == s and e["end"] == en,
           "%s decimal start/end mismatch" % name)
        ok(e["size"] == en - s, "%s size mismatch" % name)
        raw = open(os.path.join(PACKET, e["hex"]), "rb").read()
        ok(len(raw) == en - s, "%s hex length mismatch" % name)
        ok(raw == data[s - 0x1000:en - 0x1000], "%s hex bytes mismatch" % name)
        got_strict = strict_lines(os.path.join(PACKET, e["objdump"]))
        ok(got_strict == e["strict_instructions"],
           "%s strict %d != records %d" % (name, got_strict, e["strict_instructions"]))
        regen = objdump_lines(s, en)
        stored = [l for l in open(os.path.join(PACKET, e["objdump"])).read().splitlines()
                  if l.strip() and "file format" not in l]
        ok(regen == stored, "%s objdump regen mismatch" % name)
        ok(fde_starts.get(s) == en, "%s FDE bounds %s != %s" %
           (name, fde_starts.get(s), hex(en)))
        total_bytes += en - s
        total_strict += e["strict_instructions"]
        # one ret, one stack_chk_fail call, jumps inside FDE
        text = open(os.path.join(PACKET, e["objdump"])).read()
        rets = len(re.findall(r"\tret\b", text))
        ok(rets == 1, "%s ret count %d != 1" % (name, rets))
        calls = re.findall(r"\tcall\s+([0-9a-f]+)", text)
        ok(len(calls) == 1 and calls[0] == "63f0d70",
           "%s calls %s != [stack_chk_fail]" % (name, calls))
        for m in re.finditer(r"\tj[a-z]+\s+([0-9a-f]+)", text):
            tgt = int(m.group(1), 16)
            ok(s <= tgt < en, "%s jump target %#x outside FDE" % (name, tgt))
        # value-load lea target matches the leaf value description
        leaf = leaf_by_name.get("opt/" + name)
        if leaf:
            m = re.search(r"lea\s+[0-9a-fx]+\(%rip\),%r\w+\s+#\s*([0-9a-f]+)", text)
            ok(m is not None, "%s no value lea found" % name)
            if m:
                ok(m.group(1) in leaf["value"],
                   "%s lea target %s not in value %r" % (name, m.group(1), leaf["value"]))
    ok(total_bytes == 2248, "total bytes %d != 2248" % total_bytes)
    ok(total_strict == 622, "total strict %d != 622" % total_strict)

    # leaf slots + names via .rela.dyn
    for leaf in rec["leaves"]:
        node = int(leaf["node"], 16)
        handler = leaf["handler"].split("..")[0]
        ok(rel.get(node + 0x20) == int(handler, 16),
           "%s handler slot mismatch" % leaf["leaf"])
        nameva = rel.get(node + 0x08)
        ok(nameva is not None, "%s name slot missing" % leaf["leaf"])
        if nameva is not None:
            end = data.index(b"\x00", nameva)
            ok(data[nameva:end].decode() == leaf["leaf"].split("/", 1)[1],
               "%s name mismatch" % leaf["leaf"])
        ok(leaf["direct_e8_entries"] == 0, "%s direct entries not 0" % leaf["leaf"])

    # whole-.text raw E8 census: 0 direct entries per handler
    text_off, text_size, text_va = 0x1418300, 0x4FD7700, 0x1419300
    handlers = {int(e["range"].split("..")[0], 16) for e in exhibits}
    hits = {h: 0 for h in handlers}
    for i in range(text_size - 5):
        if data[text_off + i] == 0xE8:
            rel32 = struct.unpack_from("<i", data, text_off + i + 1)[0]
            tgt = text_va + i + 5 + rel32
            if tgt in hits:
                hits[tgt] += 1
    for h, c in hits.items():
        ok(c == 0, "handler %#x has %d direct E8 entries" % (h, c))

    # .data file value for stats_interval
    v = struct.unpack_from("<Q", data, 0x64FFD00 - 0x3000)[0]
    ok(v == 0xFFFFFFFFFFFFFFFF, "stats_interval file value %#x" % v)

    # disjointness
    priors, ndirs = prior_ranges()
    mine = []
    for e in exhibits:
        a, b = e["range"].split("..")
        mine.append((int(a, 16), int(b, 16)))
    for a, b in mine:
        for p, q in priors:
            ok(not (a < q and p < b),
               "overlap %#x..%#x with prior %#x..%#x" % (a, b, p, q))
    for a, b in mine:
        for p, q in [(0x63B8820, 0x63B8D85), (0x63EC890, 0x63EC8A3),
                     (0x63D9700, 0x63D987B)]:
            ok(not (a < q and p < b), "overlap %#x..%#x with explicit %#x..%#x"
               % (a, b, p, q))
    for i in range(len(mine)):
        for j in range(i + 1, len(mine)):
            a, b = mine[i]
            p, q = mine[j]
            ok(not (a < q and p < b), "self-overlap %#x..%#x" % (a, b))

    # MANIFEST hashes
    man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
    ok(len(man) == 15, "MANIFEST entries %d != 15" % len(man))
    for line in man:
        h, path = line.split("  ", 1)
        full = os.path.normpath(os.path.join(PACKET, path))
        if not os.path.exists(full):
            ok(False, "MANIFEST file missing %s" % path)
            continue
        with open(full, "rb") as f:
            ok(hashlib.sha256(f.read()).hexdigest() == h,
               "MANIFEST hash mismatch %s" % path)

    print("VERIFIER %s: %d PASS, %d FAIL (%d prior dirs scanned)"
          % ("OK" if FAIL == 0 else "FAILED", PASS, FAIL, ndirs))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
