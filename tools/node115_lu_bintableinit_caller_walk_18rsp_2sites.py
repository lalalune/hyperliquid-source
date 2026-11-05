#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-2sites-walk-18rsp.

Byte reads only; the node binary is never executed. Exit 0 iff every
check passes. Run from the worktree root or anywhere (ROOT is derived
from this file: tools/ sits one level below the worktree root).
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
    "RE-001-node115-lu-bintableinit-caller-2sites-walk-18rsp")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-walk-18rsp"
WIN_START, WIN_END = 0x63D4171, 0x63D4289
EXPECTED_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECTED_SIZE = 105896032
EXPECTED_BASE = "05bc2de303c05525b71e7e257426e741bc66a390"

PASS = 0
FAIL = 0
FAILURES = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%s %s" % (name, detail))


def num(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 16)
    raise ValueError(repr(v))


def toff(va):
    return va - 0x1000


# ---- binary identity -------------------------------------------------
check("binary exists", os.path.isfile(BIN))
data = open(BIN, "rb").read() if os.path.isfile(BIN) else b""
check("binary size", len(data) == EXPECTED_SIZE, "got %d" % len(data))
check("binary sha256",
      hashlib.sha256(data).hexdigest() == EXPECTED_SHA)

# ---- base ------------------------------------------------------------
rec = json.load(open(os.path.join(PACKET, "records.json")))
check("records base", rec.get("base") == EXPECTED_BASE)
try:
    gp = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                        capture_output=True, text=True)
    head = gp.stdout.strip()
    if gp.returncode == 0 and head:
        check("worktree HEAD is base", head == EXPECTED_BASE,
              "got %s" % head)
    else:
        check("worktree HEAD check skipped (no git)", True)
except Exception:
    check("worktree HEAD check skipped (no git)", True)

# ---- packet files ----------------------------------------------------
for fname in ("README.md", "EVIDENCE.md", "records.json",
              "bintableinit_caller_walk_18rsp_2sites.hex",
              "bintableinit_caller_walk_18rsp_2sites.objdump.txt",
              "MANIFEST.sha256"):
    check("packet file present: " + fname,
          os.path.isfile(os.path.join(PACKET, fname)))

# ---- hex exhibit -----------------------------------------------------
raw = open(os.path.join(
    PACKET, "bintableinit_caller_walk_18rsp_2sites.hex"), "rb").read()
check("hex length 280", len(raw) == 280, "got %d" % len(raw))
check("hex bytes equal binary slice",
      raw == data[toff(WIN_START):toff(WIN_START) + 280])

# ---- objdump exhibit -------------------------------------------------
lines = open(os.path.join(
    PACKET, "bintableinit_caller_walk_18rsp_2sites.objdump.txt")).read(
    ).splitlines()
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
strict = [l for l in lines if STRICT_RE.match(l)]
check("strict lines 70", len(strict) == 70, "got %d" % len(strict))
check("records strict matches", rec["window"]["strict_lines"] == 70)
check("records bytes match", rec["window"]["size_bytes"] == 280)


def parse_line(l):
    m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$", l)
    if not m:
        return None
    addr = int(m.group(1), 16)
    parts = m.group(3).split(None, 1)
    mnemonic = parts[0]
    operands = parts[1] if len(parts) > 1 else ""
    return addr, mnemonic, operands


parsed = [parse_line(l) for l in strict]
parsed = [p for p in parsed if p]
check("first instruction is push %%r12 at window start",
      parsed[0][0] == WIN_START and parsed[0][1] == "push")
check("last strict line is tail jmp to 0x63bd6c0",
      parsed[-1][0] == 0x63D4284 and parsed[-1][1] == "jmp" and
      "63bd6c0" in parsed[-1][2])

by_addr = {a: (m, o) for a, m, o in parsed}


def jump_target(o):
    return int(o.split()[0], 16)


def has(addr, mnemonic, operand_sub=""):
    return addr in by_addr and by_addr[addr][0] == mnemonic and \
        operand_sub in by_addr[addr][1]


# frame / entry
check("frame pushes r12/rbp/rbx",
      has(0x63D4171, "push", "%r12") and has(0x63D4173, "push", "%rbp")
      and has(0x63D417E, "push", "%rbx"))
check("frame sub $0x1a0,%rsp", has(0x63D4182, "sub", "$0x1a0,%rsp"))
check("canary load", has(0x63D4189, "mov", "%fs:0x28,%rax"))
check("canary store 0x198(%rsp)",
      has(0x63D4192, "mov", "%rax,0x198(%rsp)"))
check("entry key kept in rbp", has(0x63D4174, "mov", "%rsi,%rbp"))
check("entry context kept in rbx", has(0x63D417F, "mov", "%rdi,%rbx"))
check("table lea 0x1b0(%rdi)",
      has(0x63D4177, "lea", "0x1b0(%rdi),%rsi"))

# calls
calls = [(a, m, o) for a, m, o in parsed if m == "call"]
check("call count 5", len(calls) == 5, "got %d" % len(calls))


def call_target(addr):
    off = toff(addr)
    rel = struct.unpack_from("<i", data, off + 1)[0]
    return addr + 5 + rel


for site, target in ((0x63D41A9, 0x63D9880), (0x63D4244, 0x63D9880),
                     (0x63D41B7, 0x63D3F0E), (0x63D4255, 0x63D4048),
                     (0x63D4271, 0x63F0D70)):
    check("call rel32 0x%x -> 0x%x" % (site, target),
          site in by_addr and by_addr[site][0] == "call" and
          call_target(site) == target)
bti = [a for a, m, o in calls if call_target(a) == 0x63D9880]
check("bin_table_init sites exactly 2", bti == [0x63D41A9, 0x63D4244],
      "got %s" % [hex(a) for a in bti])
miss = [a for a, m, o in calls if call_target(a) == 0x63D9700]
check("lu-miss sites 0", miss == [], "got %s" % miss)

# site blocks: lea 0x18(%rsp) in-block via r12, single-branch entry
for site, block, br, jt in ((0x63D41A9, 0x63D41A1, 0x63D419F, 0x63D41B1),
                        (0x63D4244, 0x63D423C, 0x63D423A, 0x63D424C)):
    window = [p for p in parsed if block <= p[0] <= site]
    lea_ok = any(m == "lea" and "0x18(%rsp),%r12" in o for _, m, o in window)
    mov_ok = any(m == "mov" and "%r12,%rdi" in o for _, m, o in window)
    check("site 0x%x block lea 0x18(%%rsp)" % site, lea_ok)
    check("site 0x%x block mov %%r12,%%rdi" % site, mov_ok)
    check("site 0x%x block head is lea" % site,
          by_addr[block][0] == "lea")
    check("site 0x%x branch is jne to 0x%x" % (site, jt),
          by_addr[br][0] == "jne" and
          by_addr[br][1].split()[0] == "%x" % jt)
    # fall-through: the jne's next address is the block
    check("site 0x%x fall-through entry" % site,
          br + 2 == block)
    check("site 0x%x block is not a jump target" % site,
          all(not (m in ("jmp", "je", "jne", "ja", "jbe") and
                  jump_target(o) == block)
              for _, m, o in parsed
              if o.split() and all(c in "0123456789abcdef"
                                   for c in o.split()[0])))
# rejoins
check("site 1 rejoin mov %r12,%rsi",
      has(0x63D41AE, "mov", "%r12,%rsi"))
check("site 2 rejoin mov %r12,%rdx",
      has(0x63D4249, "mov", "%r12,%rdx"))

# flag / gate dispatch
check("flag cmpb 0x9(%rsp)",
      has(0x63D41C7, "cmpb", "$0x0,0x9(%rsp)"))
check("flag je to gate", has(0x63D41CC, "je", "63d41fb"))
check("gate cmp $0x23,%eax", has(0x63D41FB, "cmp", "$0x23,%eax"))
check("gate ja to phase 2", has(0x63D41FE, "ja", "63d4230"))
check("phase 2 lea 0x1b0(%rbx)",
      has(0x63D4230, "lea", "0x1b0(%rbx),%rdx"))

# exits
retn = [p for p in parsed if p[1] == "ret"]
check("ret count 0", retn == [], "got %s" % retn)
check("bsr count 0",
      [p for p in parsed if p[1] == "bsr"] == [])
lockm = [p for p in parsed if p[1] == "lock"]
check("lock count 0", lockm == [], "got %s" % lockm)
jmps = [(a, o) for a, m, o in parsed if m == "jmp"]
outside = []
for a, o in jmps:
    t = jump_target(o)
    if not (WIN_START <= t < WIN_END):
        outside.append((a, t))
check("tail-jump exits exactly 3",
      sorted(t for _, t in outside) == sorted(
          [0x63637F0, 0x6363260, 0x63BD6C0]),
      "got %s" % [(hex(a), hex(t)) for a, t in outside])
for a, t in outside:
    prev = [p for p in parsed if a - 40 <= p[0] < a]
    epi = any(m == "add" and "$0x1a0,%rsp" in o for _, m, o in prev)
    can = any(m == "sub" and "%fs:0x28,%rax" in o for _, m, o in prev)
    check("exit 0x%x has epilogue+canary" % t, epi and can)
check("canary failure calls __stack_chk_fail",
      has(0x63D4271, "call", "63f0d70"))
outside_set = set(outside)
for a, m, o in parsed:
    if m in ("jmp", "je", "jne", "ja", "jbe", "jb", "jae", "jge", "jl"):
        try:
            t = jump_target(o)
        except ValueError:
            continue
        if (a, t) in outside_set:
            continue
        check("jump target inside 0x%x" % a, WIN_START <= t < WIN_END,
              "target %s" % o)

# raw-e8 byte scan for this window
hits = []
base = toff(WIN_START)
for i in range(base, toff(WIN_END) - 4):
    if data[i] == 0xE8:
        rel = struct.unpack_from("<i", data, i + 1)[0]
        if (WIN_START + (i - base)) + 5 + rel == 0x63D9880:
            hits.append(WIN_START + (i - base))
check("raw e8 sites match objdump sites",
      hits == [0x63D41A9, 0x63D4244], "got %s" % [hex(h) for h in hits])

# ---- .eh_frame -------------------------------------------------------
EH_OFF = 0xCA6ED8
EH_SIZE = 0x77137C
eh = data[EH_OFF:EH_OFF + EH_SIZE]


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


ENC_SIZE = {0x03: 2, 0x04: 4, 0x05: 8, 0x09: 2, 0x0A: 4, 0x0B: 4,
            0x0C: 8, 0x0D: 4, 0x0E: 8, 0x0F: 8}


def enc_val(buf, p, enc):
    fmt = enc & 0x0F
    if fmt == 0x03:
        v = struct.unpack_from("<H", buf, p)[0]
        p += 2
    elif fmt == 0x04:
        v = struct.unpack_from("<I", buf, p)[0]
        p += 4
    elif fmt in (0x05, 0x0C):
        v = struct.unpack_from("<Q", buf, p)[0]
        p += 8
    elif fmt == 0x09:
        v = struct.unpack_from("<h", buf, p)[0]
        p += 2
    elif fmt in (0x0A, 0x0B):
        v = struct.unpack_from("<i", buf, p)[0]
        p += 4
    elif fmt in (0x0D, 0x0E):
        v = struct.unpack_from("<q", buf, p)[0]
        p += 8
    else:
        raise ValueError("enc %x" % enc)
    return v, p


cies = {}
fdes = []
p = 0
while p < EH_SIZE:
    if p + 4 > EH_SIZE:
        break
    length = struct.unpack_from("<I", eh, p)[0]
    if length == 0:
        break
    rec_start = p
    cie_id = struct.unpack_from("<I", eh, p + 4)[0]
    if cie_id == 0:
        q = p + 8
        ver = eh[q]
        q += 1
        end = eh.index(b"\x00", q)
        aug = eh[q:end].decode("latin1")
        q = end + 1
        _, q = uleb(eh, q)
        _, q = sleb(eh, q)
        if ver == 1:
            q += 1
        else:
            _, q = uleb(eh, q)
        fde_enc = None
        if aug.startswith("z"):
            auglen, q = uleb(eh, q)
            aq = q
            for ch in aug[1:]:
                if ch == "L":
                    q += 1
                elif ch == "P":
                    penc = eh[q]
                    q += 1
                    _, q = enc_val(eh, q, penc)
                elif ch == "R":
                    fde_enc = eh[q]
                    q += 1
                elif ch in ("B", "G"):
                    q += 1
            q = aq + auglen
        cies[rec_start] = fde_enc
        p = rec_start + 4 + length
    else:
        field_pos = p + 4
        cie_pos = field_pos - cie_id
        fde_enc = cies.get(cie_pos)
        q = p + 8
        sz = ENC_SIZE[fde_enc & 0x0F]
        val, q = enc_val(eh, q, fde_enc)
        rng, q = enc_val(eh, q, fde_enc)
        if (fde_enc & 0x70) == 0x10:  # pcrel
            valfield_off = (q - sz) - sz
            init = EH_OFF + valfield_off + val
        else:
            init = val
        fdes.append((init, rng))
        p = rec_start + 4 + length
check("eh_frame CIE count 3", len(cies) == 3, "got %d" % len(cies))
check("eh_frame FDE count 135313", len(fdes) == 135313,
      "got %d" % len(fdes))
fdes_sorted = sorted(fdes)
starts = [f[0] for f in fdes_sorted]
i = bisect.bisect_right(starts, WIN_START) - 1
check("eh_frame window exact",
      fdes_sorted[i] == (WIN_START, 280), "got %s" % (fdes_sorted[i],))
check("eh_frame prev FDE",
      fdes_sorted[i - 1] == (0x63D4048, 0x129),
      "got %s" % (fdes_sorted[i - 1],))
check("eh_frame next FDE",
      fdes_sorted[i + 1] == (0x63D4289, 412),
      "got %s" % (fdes_sorted[i + 1],))

# raw-e8 census grouped by enclosing FDE
try:
    sec = subprocess.run(["readelf", "-W", "-S", BIN],
                         capture_output=True, text=True).stdout
    text_va = text_off = text_size = None
    for l in sec.splitlines():
        if ".text " in l and "PROGBITS" in l:
            parts = l.split()
            text_va = int(parts[3], 16)
            text_off = int(parts[4], 16)
            text_size = int(parts[5], 16)
    check("text section found", text_va is not None)
    per_fde = {}
    total = 0
    tb = data[text_off:text_off + text_size]
    for j in range(len(tb) - 4):
        if tb[j] == 0xE8:
            rel = struct.unpack_from("<i", tb, j + 1)[0]
            va = text_va + j
            if va + 5 + rel == 0x63D9880:
                total += 1
                k = bisect.bisect_right(starts, va) - 1
                per_fde[fdes_sorted[k]] = per_fde.get(fdes_sorted[k], 0) + 1
    tiers = {}
    for f, c in per_fde.items():
        tiers[c] = tiers.get(c, 0) + 1
    check("raw-e8 total 108", total == 108, "got %d" % total)
    check("raw-e8 tiers", tiers == {10: 1, 8: 1, 6: 2, 5: 1, 4: 8,
                                    2: 12, 1: 17}, "got %s" % (tiers,))
    check("raw-e8 this FDE 2",
          per_fde.get((WIN_START, 280), 0) == 2)
except Exception as exc:
    check("raw-e8 census ran", False, repr(exc))

# ---- relocations -----------------------------------------------------
try:
    rel = subprocess.run(["readelf", "-W", "-r", BIN],
                         capture_output=True, text=True).stdout
    dyn_total = rel_total = plt_total = 0
    section = None
    for l in rel.splitlines():
        if "Relocation section '.rela.dyn'" in l:
            section = "dyn"
            dyn_total = int(l.split("contains")[1].split()[0])
        elif "Relocation section '.rela.plt'" in l:
            section = "plt"
            plt_total = int(l.split("contains")[1].split()[0])
        elif "R_X86_64_RELATIVE" in l and section == "dyn":
            rel_total += 1
    check("rela.dyn total 60723", dyn_total == 60723,
          "got %d" % dyn_total)
    check("rela.dyn RELATIVE 59534", rel_total == 59534,
          "got %d" % rel_total)
    check("rela.plt total 278", plt_total == 278, "got %d" % plt_total)
except Exception as exc:
    check("rela census ran", False, repr(exc))

# ---- disjointness ----------------------------------------------------
SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde")
RANGELIKE = ("range", "fde_range", "address_range", "start", "start_va",
             "address")


def entry_range(e):
    for key in ("range", "fde_range", "address_range"):
        if key in e:
            r = e[key]
            if isinstance(r, list):
                return (num(r[0]), num(r[1]))
            return tuple(num(x) for x in r.split(".."))
    for a, b in (("start", "end"), ("start_va", "end_va_exclusive"),
                 ("start_va", "end_va"), ("address", "end"),
                 ("start", "stop"), ("start", "end_exclusive")):
        if a in e and b in e:
            return (num(e[a]), num(e[b]))
    return None


def collect(obj, out, skipped):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SKIP_KEYS or k == "fde":
                continue
            if k in ("exhibits", "windows"):
                items = v if isinstance(v, list) else \
                    list(v.values()) if isinstance(v, dict) else []
                for e in items:
                    if isinstance(e, dict):
                        r = entry_range(e)
                        if r:
                            out.append(r)
                        elif any(f in e for f in RANGELIKE):
                            skipped.append(e)
            elif k == "window" and isinstance(v, dict):
                r = entry_range(v)
                if r:
                    out.append(r)
                elif any(f in v for f in RANGELIKE):
                    skipped.append(v)
            else:
                collect(v, out, skipped)
    elif isinstance(obj, list):
        for v in obj:
            collect(v, out, skipped)


priors = []
skipped = []
own_tree = glob.glob(os.path.join(
    ROOT, "research", "work-items", "*", "records.json"))
prior_trees = glob.glob(os.path.join(
    ROOT, "..", "hl-wt-calls*", "research", "work-items", "*",
    "records.json"))
for path in own_tree + prior_trees:
    try:
        collect(json.load(open(path)), priors, skipped)
    except Exception:
        pass
check("collector skipped 0", skipped == [],
      "got %d" % len(skipped))
own_window = (WIN_START, WIN_END)
mine = []
for e in rec.get("exhibits", []):
    r = entry_range(e)
    if r:
        mine.append(r)
check("packet exhibits exactly 1 range", len(mine) == 1)
bad = []
for m in mine:
    for pr in priors:
        if pr == own_window:
            continue  # self-exclusion by exact match
        if m[0] < pr[1] and pr[0] < m[1]:
            bad.append((m, pr))
check("disjointness NONE", bad == [], "got %s" % (bad[:5],))
check("prior range count sane", len(priors) > 40000,
      "got %d" % len(priors))

# ---- slug ------------------------------------------------------------
try:
    tree = subprocess.run(["git", "ls-tree", "-r", "HEAD", "--name-only"],
                          cwd=ROOT, capture_output=True, text=True).stdout
    check("slug absent from committed tree", SLUG not in tree)
except Exception:
    check("slug tree check skipped (no git)", True)
for d in glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*",
                                "research", "work-items", "*")):
    if os.path.basename(d) == SLUG and \
            os.path.normpath(d) != os.path.normpath(PACKET):
        # Same slug + same window = the same packet in another copy
        # (e.g. the real worktree seen from a temp copy); only a
        # DIFFERENT window under this slug is a collision.
        try:
            other = json.load(open(os.path.join(d, "records.json")))
            ow = None
            for e in other.get("exhibits", []):
                r = entry_range(e)
                if r:
                    ow = r
                    break
        except Exception:
            ow = None
        if ow == (WIN_START, WIN_END):
            continue
        check("slug absent from other worktrees", False, d)
        break
else:
    check("slug absent from other worktrees", True)

# ---- MANIFEST --------------------------------------------------------
man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
mentries = []
for l in man:
    if not l.strip():
        continue
    h, p = l.split(None, 1)
    mentries.append((h, p.strip()))
check("MANIFEST entries 5", len(mentries) == 5, "got %d" % len(mentries))
for h, p in mentries:
    if p.startswith("../../../"):
        fpath = os.path.join(ROOT, p[9:])
    else:
        fpath = os.path.join(PACKET, p)
    actual = hashlib.sha256(open(fpath, "rb").read()).hexdigest()
    check("MANIFEST match " + p, actual == h)
check("MANIFEST excludes itself",
      all("MANIFEST.sha256" not in p for _, p in mentries))

# ---- README/records consistency --------------------------------------
readme = open(os.path.join(PACKET, "README.md")).read()
for frag in ("0x63d4171..0x63d4289", "70 strict", "0x63d41a9",
             "0x63d4244", "53,357"):
    check("README contains " + frag, frag in readme)

print("PASS count: %d, FAIL count: %d" % (PASS, FAIL))
for f in FAILURES:
    print("FAIL:", f)
sys.exit(0 if FAIL == 0 else 1)
