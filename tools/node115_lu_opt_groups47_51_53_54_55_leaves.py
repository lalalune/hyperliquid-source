#!/usr/bin/env python3
"""Static verifier for packet RE-001-node115-lu-opt-groups47-51-53-54-55-leaves.

Byte reads only; never executes the binary. Exit 0 iff every check passes.
Env overrides: HL272_PACKET_DIR, HL272_BINARY, HL272_PRIOR_ROOTS
(colon-separated, replaces the prior-record roots; used by the tamper test
to inject a fake overlapping prior record).

Five opt-children leaves in tree order: groups 47, 51, 53, 54, 55.
Groups 48 (opt/prof, #261), 49 (opt/prof_prefix, #262), 50 (opt/prof_active,
#262), and 52 (opt/lg_prof_sample, #262) were already claimed, so they are
skipped without re-claim (the packet #250/#270 lesson) and cited under the
records "cited" subtree, which the range collector excludes. All five
leaves share the #261 contract skeleton (write -> 1, exact-length read
stores value -> 0, short read -> 0x16): two u64 leaves, three byte leaves.
Group 47's handler (0x63735a0) is exactly packet #271's next-question FDE,
verified unclaimed before building.
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
PACKET = os.environ.get(
    "HL272_PACKET_DIR",
    os.path.join(ROOT, "research", "work-items",
                 "RE-001-node115-lu-opt-groups47-51-53-54-55-leaves"))
BINARY = os.environ.get(
    "HL272_BINARY",
    os.path.join(ROOT, "artifacts", "node", "115", "hl-node"))
BINARY_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BINARY_SIZE = 105896032
BASE = "05bc2de303c05525b71e7e257426e741bc66a390"
SLUG = "RE-001-node115-lu-opt-groups47-51-53-54-55-leaves"

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
    # Strip the path-embedding header lines: blank lines + file-format line.
    return [l for l in out if l.strip() and "file format" not in l]


def parse_eh_frame(data):
    """Return list of (start, end) FDE ranges from .eh_frame (pcrel sdata4).

    The range field is a fixed 4-byte value, NOT ULEB: an early ULEB parse
    cut two handlers mid-instruction (packet #270 lesson).
    """
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
                            out.append((int(r[0], 16) if isinstance(r[0], str) else r[0],
                                        int(r[1], 16) if isinstance(r[1], str) else r[1]))
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
    roots = os.environ.get("HL272_PRIOR_ROOTS")
    if roots:
        dirs = roots.split(":")
    else:
        dirs = glob.glob(os.path.join(ROOT, "research", "work-items", "*"))
        dirs += glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*")
    seen_slugs = set()
    priors = []
    for d in dirs:
        slug = os.path.basename(d.rstrip("/"))
        if slug == SLUG:
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


# Per-leaf expectations: (size, cmp_line, load_line, slot_va, file_value)
# size 1 = byte leaf (.bss slots have file_value None -> "runtime").
EXPECT = {
    "lg_extent_max_active_fit": (8, "cmp    $0x8,%rcx", "mov    (%rdx),%rdi", 0x64ffbe8, 0x6),
    "prof_thread_active_init": (1, "cmp    $0x1,%rdx", "movzbl (%rax),%esi", 0x64ffcf8, 0x1),
    "lg_prof_interval": (8, "cmp    $0x8,%rcx", "mov    (%rdx),%rdi", 0x64ffce8, 0xffffffffffffffff),
    "prof_gdump": (1, "cmp    $0x1,%rdx", "movzbl (%rax),%esi", 0x6713605, None),
    "prof_final": (1, "cmp    $0x1,%rdx", "movzbl (%rax),%esi", 0x6713604, None),
}


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
    ok(sum(1 for _ in rel) == 59534, "RELATIVE count != 59534")
    leaves = {l["leaf"].split("/", 1)[1]: l for l in rec["leaves"]}
    ok(len(leaves) == 5, "expected 5 leaves, got %d" % len(leaves))

    for e in exhibits:
        name = e["name"]
        a, b = e["range"].split("..")
        start, end = int(a, 16), int(b, 16)
        ok(e["start"] == start and e["end"] == end,
           "%s decimal start/end mismatch" % name)
        ok(e["size"] == end - start, "%s size mismatch" % name)
        total_bytes += e["size"]
        with open(os.path.join(PACKET, e["hex"]), "rb") as f:
            raw = f.read()
        ok(raw == data[start - 0x1000:end - 0x1000],
           "%s hex bytes differ from binary slice" % name)
        txt_path = os.path.join(PACKET, e["objdump"])
        ok(strict_lines(txt_path) == e["strict_instructions"],
           "%s strict recount mismatch" % name)
        total_strict += e["strict_instructions"]
        regen = objdump_lines(start, end)
        with open(txt_path) as f:
            stored = [l for l in f.read().splitlines()
                      if l.strip() and "file format" not in l]
        ok(regen == stored, "%s objdump regeneration differs" % name)
        ok(fde_starts.get(start) == end, "%s FDE end mismatch" % name)
        leaf = leaves[name]
        node = int(leaf["node"], 16)
        ok(rel.get(node + 0x20) == start, "%s node+0x20 slot mismatch" % name)
        nameva = rel.get(node + 0x08)
        ok(nameva is not None, "%s node+0x08 slot missing" % name)
        if nameva is not None:
            nm_end = data.index(b"\x00", nameva)
            ok(data[nameva:nm_end].decode() == name,
               "%s name addend resolves to %r" % (name, data[nameva:nm_end]))
        text = "\n".join(stored)
        lea_targets = re.findall(r"lea\s+0x[0-9a-f]+\(%rip\),%r\w+\s+# ([0-9a-f]+)",
                                 text)
        lea_targets = ["0x" + t for t in lea_targets]
        size, cmp_line, load_line, slot, fval = EXPECT[name]
        ok(leaf["value"].endswith(hex(slot)),
           "%s records value slot mismatch" % name)
        if fval is None:
            ok(leaf["file_value"] == "runtime",
               "%s .bss leaf file_value must be 'runtime'" % name)
        else:
            ok(leaf["file_value"] == hex(fval),
               "%s records file value mismatch" % name)
            fmt = {1: "B", 4: "I", 8: "Q"}[size]
            ok(struct.unpack_from("<" + fmt, data, slot - 0x3000)[0] == fval,
               "%s .data file value mismatch" % name)
        ok(hex(slot) in lea_targets,
           "%s lea target %s not found" % (name, hex(slot)))
        ok(load_line in text, "%s value load missing" % name)
        ok(cmp_line in text, "%s exact-size cmp missing" % name)
        ok("mov    $0x1" in text, "%s write->1 marker missing" % name)
        ok("mov    $0x16" in text, "%s short-read 0x16 marker missing" % name)
        strict = [l for l in stored if STRICT_RE.match(l)]
        ok(sum(1 for l in strict if l.rstrip().endswith("\tret")) == 1,
           "%s ret count != 1" % name)
        calls = re.findall(r"\tcall\s+([0-9a-f]+)", text)
        ok(calls == ["63f0d70"], "%s calls != [stack_chk_fail]: %r" % (name, calls))
        jmps = []
        for l in strict:
            m = re.search(r"\t(jmp|je|jne|jae|jb|ja|jbe|jge|jl|jle|jg|js|jns|jo|jno|jp|jnp)\s+([0-9a-f]+)", l)
            if m:
                jmps.append(int(m.group(2), 16))
        ok(all(start <= t < end for t in jmps),
           "%s jump target outside FDE" % name)
        ok(leaf["direct_e8_entries"] == 0, "%s direct entries not 0" % name)

    ok(total_bytes == 1472, "total bytes %d != 1472" % total_bytes)
    ok(total_strict == 402, "total strict %d != 402" % total_strict)
    ok(rec.get("remaining_unclassified_after") == 116, "remaining != 116")
    ok(rec.get("next_fde_after_last") == "0x6374170", "next FDE mismatch")

    # u64 pair + byte trio normalized-identical modulo lea displacement + jump targets.
    def norm_lines(start, end):
        out = []
        for l in objdump_lines(start, end):
            m = re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(.*)", l)
            if not m:
                continue
            t = m.group(1)
            if re.match(r"(jmp|je|jne|jae|jb|ja|jbe|jge|jl|jle|jg|js|jns|jo|jno|jp|jnp)\s", t):
                t = t.split()[0] + " TARGET"
            t = re.sub(r"lea\s+0x[0-9a-f]+\(%rip\)", "lea DISP(%rip)", t)
            t = re.sub(r"#.*$", "#", t)
            out.append(t)
        return out
    u64 = [norm_lines(0x63735a0, 0x63737b7), norm_lines(0x6373e30, 0x6374047)]
    ok(u64[0] == u64[1], "u64 pair not normalized-identical")
    byt = [norm_lines(0x6373af0, 0x6373b76), norm_lines(0x6374050, 0x63740d6),
           norm_lines(0x63740e0, 0x6374166)]
    ok(byt[0] == byt[1] == byt[2], "byte trio not normalized-identical")

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

    # disjointness
    priors, ndirs = prior_ranges()
    mine = []
    for e in exhibits:
        a, b = e["range"].split("..")
        mine.append((int(a, 16), int(b, 16)))
    for a, b in mine:
        for p, q in priors:
            ok(not (a < q and p < b),
               "overlap: %#x..%#x vs prior %#x..%#x" % (a, b, p, q))
    for a, b in mine:
        for p, q in mine:
            if (a, b) != (p, q):
                ok(not (a < q and p < b), "self-overlap %#x..%#x" % (a, b))
    ok(not any(a < 0x63b8d85 and 0x63b8820 < b for a, b in mine),
       "overlap with #232 merged FDE")
    ok(not any(a < 0x63ec8a3 and 0x63ec890 < b for a, b in mine),
       "overlap with #252 r28_wait window")
    ok(not any(a < 0x63d987b and 0x63d9700 < b for a, b in mine),
       "overlap with #215 handler FDE")
    ok(not any(a < 0x6372246 and 0x63721c0 < b for a, b in mine),
       "overlap with #261 group-36 tcache window")
    ok(not any(a < 0x6373846 and 0x63737c0 < b for a, b in mine),
       "overlap with #261 opt_prof window (skipped group 48)")
    ok(not any(a < 0x6373a5a and 0x6373850 < b for a, b in mine),
       "overlap with #262 prof_prefix window (skipped group 49)")
    ok(not any(a < 0x6373ae6 and 0x6373a60 < b for a, b in mine),
       "overlap with #262 prof_active window (skipped group 50)")
    ok(not any(a < 0x6373d97 and 0x6373b80 < b for a, b in mine),
       "overlap with #262 lg_prof_sample window (skipped group 52)")

    # MANIFEST hashes
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            digest, path = line.split(None, 1)
            if path.startswith("*"):
                path = path[1:]
            if path.startswith("../../../"):
                full = os.path.join(ROOT, path[9:])
            else:
                full = os.path.join(PACKET, path)
            with open(full, "rb") as hf:
                ok(hashlib.sha256(hf.read()).hexdigest() == digest,
                   "MANIFEST hash mismatch: %s" % path)

    print("VERIFIER OK: %d PASS, %d FAIL (%d prior dirs scanned)" % (PASS, FAIL, ndirs))
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
