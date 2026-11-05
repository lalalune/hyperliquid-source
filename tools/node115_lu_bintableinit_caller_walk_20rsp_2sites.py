#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-2sites-walk-20rsp.

Byte reads only; never executes the target binary. Exits 0 iff every check
passes. ROOT is derived from this file's location: tools/ sits one level
below the worktree root.
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
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-walk-20rsp"
PACKET = os.path.join(ROOT, "research", "work-items", SLUG)
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

START, END = 0x63CD910, 0x63CDDCE
PREV = (0x63CCD60, 0x63CD907)
NEXT = (0x63CDDD0, 0x63CE23B)
BTI_SITES = ["63cdaa8", "63cdbdf"]
MISS_SITES = ["63cdd20", "63cddba"]

passes, fails = [], []


def check(name, ok, detail=""):
    (passes if ok else fails).append(name)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else " :: " + str(detail)))


# ---------------------------------------------------------------- binary
data = open(BIN, "rb").read()
check("binary size", len(data) == 105896032, len(data))
check("binary sha256",
      hashlib.sha256(data).hexdigest() ==
      "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")


def toff(va):
    return va - 0x1000


# ---------------------------------------------------------------- .eh_frame
def uleb(d, p):
    r, s = 0, 0
    while True:
        b = d[p]; p += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            break
        s += 7
    return r, p


def sleb(d, p):
    r, s = 0, 0
    while True:
        b = d[p]; p += 1
        r |= (b & 0x7F) << s; s += 7
        if not (b & 0x80):
            if b & 0x40:
                r |= -(1 << s)
            break
    return r, p


ENC_SIZE = {0x02: 2, 0x03: 4, 0x04: 8, 0x0A: 2, 0x0B: 4, 0x0C: 8}


def read_encoded(d, p, enc):
    fmt = enc & 0x0F
    if fmt == 0x01:
        return uleb(d, p)
    if fmt == 0x09:
        return sleb(d, p)
    if fmt == 0x00:
        return struct.unpack_from("<Q", d, p)[0], p + 8
    n = ENC_SIZE[fmt]
    raw = d[p:p + n]
    if fmt in (0x02, 0x03, 0x04):
        return int.from_bytes(raw, "little"), p + n
    return int.from_bytes(raw, "little", signed=True), p + n


def parse_fdes():
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)

    def sh(i):
        off = e_shoff + i * e_shentsize
        name, _typ, _fl, addr, offset, size = struct.unpack_from("<IIQQQQ", data, off)
        return name, addr, offset, size

    str_off = sh(e_shstrndx)[2]

    def nm(i):
        n = sh(i)[0]
        end = data.index(b"\x00", str_off + n)
        return data[str_off + n:end].decode()

    secs = {}
    for i in range(e_shnum):
        _n, addr, off, size = sh(i)
        secs[nm(i)] = (addr, off, size)
    addr, off, size = secs[".eh_frame"]
    eh = data[off:off + size]
    cies, fdes = {}, []
    pos = 0
    while pos < size:
        start = pos
        ln = struct.unpack_from("<I", eh, pos)[0]
        if ln == 0:
            break
        hdr = 12 if ln == 0xFFFFFFFF else 8
        cie_id_pos = start + 4
        cie_id = struct.unpack_from("<I", eh, cie_id_pos)[0]
        body = start + hdr
        if cie_id == 0:
            ver = eh[body]; p = body + 1
            _ca, p = uleb(eh, p)
            _da, p = sleb(eh, p)
            if ver == 1:
                p += 1
            else:
                _rr, p = uleb(eh, p)
            aug_end = eh.index(b"\x00", p)
            aug = eh[p:aug_end].decode("latin1"); p = aug_end + 1
            fde_enc = 0x1B
            if aug.startswith("z"):
                _alen, p = uleb(eh, p)
                for ch in aug[1:]:
                    if ch == "L":
                        p += 1
                    elif ch == "P":
                        enc = eh[p]; p += 1
                        _v, p = read_encoded(eh, p, enc)
                    elif ch == "R":
                        fde_enc = eh[p]; p += 1
            cies[start] = fde_enc
        else:
            cie_off = cie_id_pos - cie_id
            enc = cies.get(cie_off, 0x1B)
            v, p = read_encoded(eh, body, enc)
            init = addr + body + v if enc & 0xF0 == 0x10 else v
            rng = struct.unpack_from("<I", eh, p)[0]
            fdes.append((init, init + rng))
        pos = start + (ln + 4 if ln != 0xFFFFFFFF else ln + 12)
    fdes.sort()
    return fdes, secs


fdes, secs = parse_fdes()
check("eh_frame total FDEs", len(fdes) == 135313, len(fdes))
import bisect as _bisect
_starts = [s for s, _ in fdes]
_i = _bisect.bisect_right(_starts, START) - 1
check("eh_frame window", fdes[_i] == (START, END), fdes[_i])
check("eh_frame prev FDE", fdes[_i - 1] == PREV, fdes[_i - 1])
check("eh_frame next FDE", fdes[_i + 1] == NEXT, fdes[_i + 1])
check("gap bytes all cc", data[toff(START) - 9:toff(START)] == b"\xcc" * 9)
check("padding bytes all cc", data[toff(END):toff(END) + 2] == b"\xcc" * 2)
check("window size", END - START == 1214, END - START)

# ---------------------------------------------------------------- exhibits
rec = json.load(open(os.path.join(PACKET, "records.json")))
hexb = open(os.path.join(PACKET, "bintableinit_caller_walk_20rsp_2sites.hex"), "rb").read()
check("hex exhibit raw bytes", hexb == data[toff(START):toff(START) + 1214]
      and len(hexb) == 1214, len(hexb))
obj = open(os.path.join(PACKET, "bintableinit_caller_walk_20rsp_2sites.objdump.txt")).read()
lines = obj.splitlines()
strict = [l for l in lines if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]
check("strict recount", len(strict) == 258, len(strict))

ADDR = {}
for l in strict:
    m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S+)(?:\s+(.*))?$", l)
    if m:
        ADDR[m.group(1)] = (m.group(2).strip(), m.group(3), m.group(4) or "")


def calls_to(target):
    return [a for a, (_b, mn, ops) in ADDR.items()
            if mn == "call" and target in ops]


check("bti sites", calls_to("63d9880") == BTI_SITES, calls_to("63d9880"))
check("lu-miss sites", calls_to("63d9700") == MISS_SITES, calls_to("63d9700"))
all_calls = [a for a, (_b, mn, _o) in ADDR.items() if mn == "call"]
check("total calls", len(all_calls) == 9, len(all_calls))
check("ret count", sum(1 for _b, mn, _o in ADDR.values() if mn == "ret") == 1)
check("ret site", "63cda97" in ADDR and ADDR["63cda97"][1] == "ret")
check("bsr count", sum(1 for _b, mn, _o in ADDR.values() if mn == "bsr") == 1)
check("bsr site", "63cdb3a" in ADDR and ADDR["63cdb3a"][1] == "bsr")
check("lock sub count",
      sum(1 for _b, mn, ops in ADDR.values()
          if mn == "lock" and ops.startswith("sub")) == 0)
check("lock add site",
      "63cda59" in ADDR and ADDR["63cda59"][1] == "lock"
      and ADDR["63cda59"][2] == "add %r8,0x38(%r14)",
      ADDR.get("63cda59"))
check("no 6713606 gate byte", "6713606" not in obj)

# rel32 targets for every e8 call
strict_addrs = sorted(ADDR.keys(), key=lambda a: int(a, 16))
rel_ok = True
for idx, a in enumerate(strict_addrs):
    b, mn, ops = ADDR[a]
    if mn != "call" or not b.startswith("e8"):
        continue
    byts = bytes(int(x, 16) for x in b.split())
    rel = int.from_bytes(byts[1:5], "little", signed=True)
    nxt = int(strict_addrs[idx + 1], 16) if idx + 1 < len(strict_addrs) else END
    tgt = int(a, 16) + 5 + rel
    if ops.split()[0] != format(tgt, "x"):
        rel_ok = False
check("call rel32 targets", rel_ok)

# site blocks: lea in block, exactly one je targets the block, test above je
for site, block, je_addr in (("63cdaa8", "63cdaa0", "63cd9bf"),
                             ("63cdbdf", "63cdbc8", "63cda19")):
    idx = strict_addrs.index(site)
    window = strict_addrs[max(0, idx - 12):idx]
    lea = any(ADDR[a][1] == "lea" and "0x20(%rsp)" in ADDR[a][2] for a in window)
    check("site " + site + " lea 0x20(rsp) in block", lea)
    jets = [a for a, (_b, mn, ops) in ADDR.items()
            if mn == "je" and ops.split()[0] == block]
    check("site " + site + " exactly one je to block", jets == [je_addr], jets)
    jidx = strict_addrs.index(je_addr)
    tst = any(ADDR[a][1] == "test" and "%r12,%r12" in ADDR[a][2]
              for a in strict_addrs[max(0, jidx - 3):jidx])
    check("site " + site + " null-context test above je", tst)

# no jump leaves the window
JMN = ("jmp", "je", "jne", "ja", "jb", "jbe", "jae", "jl", "jge", "jle", "jg",
       "js", "jns", "jo", "jno", "jp", "jnp", "jc", "jnc", "loop", "loope", "loopne")
leaks, indirect = [], []
for a, (_b, mn, ops) in ADDR.items():
    if mn in JMN:
        tok = ops.split()[0] if ops.split() else ""
        if re.fullmatch(r"[0-9a-f]+", tok):
            t = int(tok, 16)
            if not (START <= t < END):
                leaks.append((a, tok))
        else:
            indirect.append(a)
check("no jump leaves window", not leaks and not indirect, (leaks, indirect))

# frame / canary / epilogue
check("endbr64 first", ADDR.get("63cd910", ("", ""))[1] == "endbr64")
check("sub rsp", "63cd91e" in ADDR and "sub" in ADDR["63cd91e"][1]
      and "$0x1b8" in ADDR["63cd91e"][2])
check("canary store", "63cd92e" in ADDR and "0x1a8(%rsp)" in ADDR["63cd92e"][2])
check("canary check", "63cda74" in ADDR and "sub" in ADDR["63cda74"][1]
      and "%fs:0x28" in ADDR["63cda74"][2])
check("canary jne", "63cda7d" in ADDR and ADDR["63cda7d"][1] == "jne"
      and ADDR["63cda7d"][2].split()[0] == "63cddc9")
check("stack_chk_fail call", "63cddc9" in ADDR and "63f0d70" in ADDR["63cddc9"][2])
check("epilogue add rsp", "63cda83" in ADDR and "$0x1b8" in ADDR["63cda83"][2])
check("return value", "63cda8a" in ADDR and "%rbp,%rax" in ADDR["63cda8a"][2])

# other calls
check("strlen call", "63cd951" in ADDR and "63f0a80" in ADDR["63cd951"][2])
check("helper call", "63cd9a3" in ADDR and "6364880" in ADDR["63cd9a3"][2])
check("memcpy call", "63cda67" in ADDR and "63f0a60" in ADDR["63cda67"][2])
check("lazy-init call", "63cdb71" in ADDR and "634ebb0" in ADDR["63cdb71"][2])

# size class
check("size gate", "63cd979" in ADDR and "$0x1000" in ADDR["63cd979"][2])
check("threshold table", "63cd986" in ADDR and "67277c0" in ADDR["63cd986"][2])
check("size-class movabs", "63cdb10" in ADDR and "movabs" in ADDR["63cdb10"][1])
check("size-class overflow", "63cdc94" in ADDR and "$0xe8" in ADDR["63cdc94"][2])

# scans
check("scan1 slot0", "63cdab8" in ADDR and "0x100(%rsi)" in ADDR["63cdab8"][2])
check("scan1 slot1", "63cdbfd" in ADDR and "0x110(%rsi)" in ADDR["63cdbfd"][2])
check("scan2 slot0", "63cdb80" in ADDR and "0x100(%rdx)" in ADDR["63cdb80"][2])
check("scan2 slot1", "63cdc4b" in ADDR and "0x110(%rdx)" in ADDR["63cdc4b"][2])
check("reversed-operand cmps",
      any("cmp" in ADDR[a][1] and "%r11,0x140(%rsi)" in ADDR[a][2] for a in ADDR)
      and any("cmp" in ADDR[a][1] and "%r11,0x120(%rdx)" in ADDR[a][2] for a in ADDR))
check("lu-miss rejoin 1", "63cdd2a" in ADDR and ADDR["63cdd2a"][2].split()[0] == "63cda3e")
check("lu-miss rejoin 2", "63cddc4" in ADDR and ADDR["63cddc4"][2].split()[0] == "63cd9fc")

# ---------------------------------------------------------------- records
w = rec["window"]
check("records window", (w["start"], w["end"], w["bytes"], w["strict_lines"],
                         w["calls_total"], w["bsr"], w["ret"], w["lock_sub"],
                         w["lock_add"]) ==
      ("0x63cd910", "0x63cddce", 1214, 258, 9, 1, 1, 0, 1), w)
check("records sites", rec["exhibits"][0]["bin_table_init_sites"] ==
      ["0x" + s for s in BTI_SITES]
      and rec["exhibits"][0]["lu_miss_sites"] == ["0x" + s for s in MISS_SITES])
check("records frame", rec["frame"]["prev_fde"] == "0x63ccd60..0x63cd907"
      and rec["frame"]["next_fde"] == "0x63cddd0..0x63ce23b"
      and rec["frame"]["gap_before"] == 9 and rec["frame"]["padding_after"] == 2)
check("records census", rec["call_census"]["total"] == 9
      and rec["call_census"]["bin_table_init_0x63d9880"] == 2
      and rec["call_census"]["lu_miss_0x63d9700"] == 2)

# ---------------------------------------------------------------- rela.dyn
out = subprocess.run(["readelf", "-r", BIN], capture_output=True, text=True).stdout
sec, dyn_total, dyn_rel, plt_total = None, 0, 0, 0
for line in out.splitlines():
    if "Relocation section '.rela.dyn'" in line:
        sec = "dyn"
    elif "Relocation section '.rela.plt'" in line:
        sec = "plt"
    elif line.startswith("Relocation section"):
        sec = None
    elif re.match(r"[0-9a-f]+\s+[0-9a-f]+\s+\S+", line):
        if sec == "dyn":
            dyn_total += 1
            if "R_X86_64_RELATIVE" in line:
                dyn_rel += 1
        elif sec == "plt":
            plt_total += 1
check("rela.dyn total", dyn_total == 60723, dyn_total)
check("rela.dyn RELATIVE", dyn_rel == 59534, dyn_rel)
check("rela.plt entries", plt_total == 278, plt_total)
check("records rela", rec["rela_dyn"]["total"] == 60723
      and rec["rela_dyn"]["relative"] == 59534 and rec["rela_dyn"]["rela_plt"] == 278)

# ---------------------------------------------------------------- raw-e8
taddr, _toff, _tsz = secs[".text"]
text = data[_toff:_toff + _tsz]
from collections import Counter as _Counter
rawcnt = _Counter()
for i in range(len(text) - 5):
    if text[i] == 0xE8:
        tgt = (taddr + i) + 5 + int.from_bytes(text[i + 1:i + 5], "little", signed=True)
        if tgt == 0x63D9880:
            j = _bisect.bisect_right(_starts, taddr + i) - 1
            rawcnt[fdes[j]] += 1
tiers = dict(sorted(_Counter(rawcnt.values()).items()))
check("raw-e8 total", sum(rawcnt.values()) == 108, sum(rawcnt.values()))
check("raw-e8 tiers", tiers == {1: 17, 2: 12, 4: 8, 5: 1, 6: 2, 8: 1, 10: 1}, tiers)
check("raw-e8 this FDE", rawcnt.get((START, END), 0) == 2, rawcnt.get((START, END)))

# ---------------------------------------------------------------- disjointness
SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde")


def num(x):
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        return int(x, 16)
    raise TypeError(repr(x))


priors, skipped = [], [0]


def collect(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SKIP_KEYS or k == "fde":
                continue
            if k in ("exhibits", "windows"):
                items = v if isinstance(v, list) else v.values() if isinstance(v, dict) else []
                for e in items:
                    if not isinstance(e, dict):
                        continue
                    try:
                        if "range" in e:
                            r = e["range"]
                            priors.append((num(r[0]), num(r[1])) if isinstance(r, list)
                                          else tuple(num(x) for x in r.split("..")))
                        elif "start" in e and "end" in e:
                            priors.append((num(e["start"]), num(e["end"])))
                    except Exception:
                        skipped[0] += 1
            else:
                collect(v)
    elif isinstance(obj, list):
        for v in obj:
            collect(v)


for path in glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*", "research",
                                   "work-items", "*", "records.json")):
    try:
        collect(json.load(open(path)))
    except Exception:
        skipped[0] += 1
for path in glob.glob(os.path.join(ROOT, "research", "work-items", "*", "records.json")):
    if SLUG in path:
        continue
    try:
        collect(json.load(open(path)))
    except Exception:
        skipped[0] += 1
own_ranges = []
for e in rec.get("exhibits", []):
    r = e.get("range")
    if r:
        own_ranges.append(tuple(num(x) for x in r.split("..")) if isinstance(r, str)
                          else (num(r[0]), num(r[1])))
overlaps = [(o, p) for o in own_ranges for p in priors
            if o[0] < p[1] and p[0] < o[1] and p != o]
check("disjointness NONE", not overlaps, overlaps[:3])
check("collector skipped 0", skipped[0] == 0, skipped[0])
print("INFO priors scanned:", len(priors))

# ---------------------------------------------------------------- slug
slug_ok = True
try:
    tree = subprocess.run(["git", "ls-tree", "HEAD", "--name-only",
                           "research/work-items/"], cwd=ROOT,
                          capture_output=True, text=True, timeout=60).stdout
    if SLUG in tree:
        slug_ok = False
except Exception:
    pass
for d in glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*", "research",
                                "work-items", SLUG)):
    if SLUG in d and "calls292" not in d:
        slug_ok = False
check("slug unique", slug_ok)

# ---------------------------------------------------------------- MANIFEST
man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
man_ok = True
for line in man:
    if not line.strip():
        continue
    h, rel = line.split(None, 1)
    p = os.path.join(PACKET, rel.strip())
    if hashlib.sha256(open(p, "rb").read()).hexdigest() != h:
        man_ok = False
check("MANIFEST digests", man_ok and len([l for l in man if l.strip()]) == 5,
      len([l for l in man if l.strip()]))

print("PASS count: %d, FAIL count: %d" % (len(passes), len(fails)))
sys.exit(1 if fails else 0)
