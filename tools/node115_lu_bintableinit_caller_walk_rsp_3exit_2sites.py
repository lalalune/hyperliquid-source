#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp-3exit.

Byte reads only; never executes the target binary. Exit 0 iff every check passes.
"""
import bisect
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp-3exit")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp-3exit"
START, END = 0x63c89c0, 0x63c8d5a
EXPECTED_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECTED_SIZE = 105896032

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(detail)) if detail and not cond else ""))


# ---------------------------------------------------------------- ELF helpers
def uleb(data, pos):
    r, s = 0, 0
    while True:
        b = data[pos]
        pos += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            break
        s += 7
    return r, pos


def sleb(data, pos):
    r, s = 0, 0
    while True:
        b = data[pos]
        pos += 1
        r |= (b & 0x7F) << s
        s += 7
        if not (b & 0x80):
            if b & 0x40:
                r |= -(1 << s)
            break
    return r, pos


ENC_SIZE = {0x02: 2, 0x03: 4, 0x04: 8, 0x0A: 2, 0x0B: 4, 0x0C: 8}


def read_encoded(data, pos, enc):
    fmt = enc & 0x0F
    if fmt == 0x01:
        return uleb(data, pos)
    if fmt == 0x09:
        return sleb(data, pos)
    if fmt == 0x00:
        return struct.unpack_from("<Q", data, pos)[0], pos + 8
    n = ENC_SIZE[fmt]
    raw = data[pos:pos + n]
    if fmt in (0x02, 0x03, 0x04):
        return int.from_bytes(raw, "little"), pos + n
    return int.from_bytes(raw, "little", signed=True), pos + n


def parse_sections(data):
    assert data[:4] == b"\x7fELF"
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    def sh(i):
        off = e_shoff + i * e_shentsize
        name, _typ, _flags, addr, offset, size = struct.unpack_from("<IIQQQQ", data, off)
        return name, addr, offset, size
    str_off = sh(e_shstrndx)[2]
    def nm(i):
        n = sh(i)[0]
        end = data.index(b"\x00", str_off + n)
        return data[str_off + n:end].decode("latin1")
    secs = {}
    for i in range(e_shnum):
        _n, addr, off, size = sh(i)
        secs[nm(i)] = (addr, off, size)
    return secs


def parse_fdes(data, secs):
    addr, off, size = secs[".eh_frame"]
    eh = data[off:off + size]
    cies, fdes = {}, []
    pos = 0
    while pos < size:
        start = pos
        ln = struct.unpack_from("<I", eh, pos)[0]
        if ln == 0:
            break
        if ln == 0xFFFFFFFF:
            ln = struct.unpack_from("<Q", eh, pos + 4)[0]
            hdr = 12
            total = ln + 12
        else:
            hdr = 8
            total = ln + 4
        cie_id_pos = start + 4
        cie_id = struct.unpack_from("<I", eh, cie_id_pos)[0]
        body = start + hdr
        if cie_id == 0:
            ver = eh[body]
            p = body + 1
            _ca, p = uleb(eh, p)
            _da, p = sleb(eh, p)
            if ver == 1:
                p += 1  # return-address register is a single byte in v1 CIEs
            else:
                _rr, p = uleb(eh, p)
            aug_end = eh.index(b"\x00", p)
            aug = eh[p:aug_end].decode("latin1")
            p = aug_end + 1
            fde_enc = 0x1B
            if aug.startswith("z"):
                _alen, p = uleb(eh, p)
                for ch in aug[1:]:
                    if ch == "L":
                        p += 1
                    elif ch == "P":
                        enc = eh[p]
                        p += 1
                        _v, p = read_encoded(eh, p, enc)
                    elif ch == "R":
                        fde_enc = eh[p]
                        p += 1
            cies[start] = fde_enc
        else:
            cie_off = cie_id_pos - cie_id
            enc = cies.get(cie_off, 0x1B)
            v, p = read_encoded(eh, body, enc)
            if enc & 0xF0 == 0x10:  # pcrel: base is the loaded address of the field
                init = addr + body + v
            else:
                init = v
            rng = struct.unpack_from("<I", eh, p)[0]
            fdes.append((init, init + rng))
        pos = start + total
    fdes.sort()
    return fdes


def toff(va):
    return va - 0x1000  # .text file offset = VA - 0x1000


# ---------------------------------------------------------------- load binary
data = open(BIN, "rb").read()
check("binary size", len(data) == EXPECTED_SIZE, len(data))
check("binary sha256", hashlib.sha256(data).hexdigest() == EXPECTED_SHA)
secs = parse_sections(data)
fdes = parse_fdes(data, secs)
check("total FDE count", len(fdes) == 135313, len(fdes))
starts = [s for s, _ in fdes]


def enclosing(va):
    i = bisect.bisect_right(starts, va) - 1
    return fdes[i] if i >= 0 else None


check("window FDE bounds", enclosing(START) == (START, END), enclosing(START))
check("window size", END - START == 922, END - START)
prev = fdes[bisect.bisect_right(starts, START) - 2]
nxt = fdes[bisect.bisect_right(starts, START)]
check("prev FDE", prev == (0x63C8820, 0x63C89B7), prev)
check("gap bytes", data[toff(0x63C89B7):toff(START)] == b"\xcc" * 9)
check("next FDE", nxt == (0x63C8D60, 0x63C94FC), nxt)
check("padding bytes", data[toff(END):toff(0x63C8D60)] == b"\xcc" * 6)

# ---------------------------------------------------------------- exhibits
hexpath = os.path.join(PACKET, "bintableinit_caller_walk_rsp_3exit_2sites.hex")
raw = open(hexpath, "rb").read()
check("hex exhibit bytes", raw == data[toff(START):toff(END)], len(raw))
check("hex exhibit size", len(raw) == 922)

objpath = os.path.join(PACKET, "bintableinit_caller_walk_rsp_3exit_2sites.objdump.txt")
lines = open(objpath).read().splitlines()
strict = [l for l in lines if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]
check("strict recount", len(strict) == 201, len(strict))


# call census by rel32 target decode (robust against symbol suffixes)
def addr_of(line):
    return int(line.split(":")[0].strip(), 16)


def call_targets():
    out = []
    for l in strict:
        m = re.search(r"\tcall\s+([0-9a-f]+)\s", l)
        if m:
            out.append((addr_of(l), int(m.group(1), 16)))
    return out


ct = call_targets()
check("total calls", len(ct) == 5, len(ct))
check("bin_table_init calls", sum(1 for _, t in ct if t == 0x63D9880) == 2)
check("lu-miss calls", sum(1 for _, t in ct if t == 0x63D9700) == 2)
check("stack_chk_fail call", sum(1 for _, t in ct if t == 0x63F0D70) == 1)
bti = sorted(a for a, t in ct if t == 0x63D9880)
miss = sorted(a for a, t in ct if t == 0x63D9700)
check("bti sites", bti == [0x63C8A6E, 0x63C8C16], [hex(a) for a in bti])
check("lu-miss sites", miss == [0x63C8CA9, 0x63C8D50], [hex(a) for a in miss])
check("ret count", sum(1 for l in strict if re.search(r"\tret\s*$", l)) == 0)
check("bsr count", sum(1 for l in strict if re.search(r"\tbsr\s", l)) == 0)
check("lock sub count", sum(1 for l in strict if re.search(r"\tlock sub\s", l)) == 0)
check("lock add count", sum(1 for l in strict if re.search(r"\tlock add\s", l)) == 0)

# branch shapes at both sites (trace the stack temp, not just a narrow window)
s1 = [l for l in strict if 0x63C8A68 <= addr_of(l) <= 0x63C8A6E]
check("site1 block shape",
      any("mov" in l and "%rsp,%r12" in l for l in s1) and
      any("mov" in l and "%r12,%rdi" in l for l in s1))
check("site1 branch", any("je" in l and "63c8a68" in l for l in strict))
s2 = [l for l in strict if 0x63C8C10 <= addr_of(l) <= 0x63C8C16]
check("site2 block shape",
      any("mov" in l and "%rsp,%r14" in l for l in s2) and
      any("mov" in l and "%r14,%rdi" in l for l in s2))
check("site2 branch", any("je" in l and "63c8c10" in l for l in strict))
check("site1 rejoin", any("jmp" in l and "63c89f4" in l for l in strict))
check("site2 rejoin", any("jmp" in l and "63c8ae2" in l for l in strict))

# canary checks: three jne to the stack_chk_fail block
canary_jnes = [l for l in strict if re.search(r"\tjne\s+63c8d28\s", l)]
check("canary jne count", len(canary_jnes) == 3, len(canary_jnes))
check("canary address", any("0x188(%rsp)" in l for l in strict))

# exits: exactly three tail jumps, all after a full epilogue + canary check
jmps_out = []
for l in strict:
    m = re.search(r"\tjmp\s+([0-9a-f]+)\s", l)
    if m:
        tgt = int(m.group(1), 16)
        if not (START <= tgt < END):
            jmps_out.append((addr_of(l), tgt))
check("tail-jump exits", sorted(jmps_out) == [(0x63C8A5F, 0x63637F0),
                                              (0x63C8B3B, 0x63BD6C0),
                                              (0x63C8B73, 0x6363260)], jmps_out)

# reversed-operand compare in scan 1
check("reversed-operand cmp", any("cmp" in l and "%r13,0x140(%rsi)" in l for l in strict))

# ---------------------------------------------------------------- records
rec = json.load(open(os.path.join(PACKET, "records.json")))
ex = rec["exhibits"][0]
check("records window", ex["range"] == "0x63c89c0..0x63c8d5a")
check("records strict", ex["strict_lines"] == 201)
check("records calls", ex["calls_total"] == 5)
check("records bti", ex["bin_table_init_sites"] == ["0x63c8a6e", "0x63c8c16"])
check("records miss", ex["lu_miss_sites"] == ["0x63c8ca9", "0x63c8d50"])
check("records bytes", ex["bytes"] == 922)
check("records sha", rec["target_sha256"] == EXPECTED_SHA)
check("records base", rec["base"] == "05bc2de303c05525b71e7e257426e741bc66a390")

# ---------------------------------------------------------------- .rela.dyn
def dyn_entries():
    # parse PT_DYNAMIC + PT_LOAD via program headers; map VAs to file offsets
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    dyn_off = dyn_size = None
    loads = []
    for i in range(e_phnum):
        p_type, _flags, p_offset, p_vaddr, _pa, p_filesz, _ms, _al = struct.unpack_from(
            "<IIQQQQQQ", data, e_phoff + i * e_phentsize)
        if p_type == 2:  # PT_DYNAMIC
            dyn_off, dyn_size = p_offset, p_filesz
        elif p_type == 1:  # PT_LOAD
            loads.append((p_vaddr, p_offset, p_filesz))

    def va_to_off(va):
        for vaddr, off, filesz in loads:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        return va  # first segment is VA == offset; fall back to identity

    tags = {}
    for off in range(dyn_off, dyn_off + dyn_size, 16):
        tag, val = struct.unpack_from("<qQ", data, off)
        if tag == 0:
            break
        tags[tag] = val
    rela_off = va_to_off(tags[7])   # DT_RELA
    rela_sz = tags[8]               # DT_RELASZ
    jmprel = va_to_off(tags.get(23, 0))  # DT_JMPREL
    pltrelsz = tags.get(2, 0)       # DT_PLTRELSZ
    total = rela_sz // 24
    rel = 0
    for off in range(rela_off, rela_off + rela_sz, 24):
        _r_off, r_info, _add = struct.unpack_from("<QQq", data, off)
        if (r_info & 0xFFFFFFFF) == 8:  # R_X86_64_RELATIVE
            rel += 1
    plt = pltrelsz // 24 if jmprel else 0
    return total, rel, plt


total, rel, plt = dyn_entries()
check("rela.dyn total", total == 60723, total)
check("rela.dyn RELATIVE", rel == 59534, rel)
check("rela.plt entries", plt == 278, plt)

# ---------------------------------------------------------------- raw-e8 census
taddr, toff_, tsize = secs[".text"]
text = data[toff_:toff_ + tsize]
raw_count = {}
for i in range(len(text) - 5):
    if text[i] == 0xE8:
        rel32 = struct.unpack_from("<i", text, i + 1)[0]
        va = taddr + i
        if va + 5 + rel32 == 0x63D9880:
            enc = enclosing(va)
            if enc is not None:
                raw_count[enc] = raw_count.get(enc, 0) + 1
check("raw-e8 total", sum(raw_count.values()) == 108, sum(raw_count.values()))
check("raw-e8 this FDE", raw_count.get((START, END), 0) == 2)
tiers = {}
for v in raw_count.values():
    tiers[v] = tiers.get(v, 0) + 1
check("raw-e8 tiers", tiers == {10: 1, 8: 1, 6: 2, 5: 1, 4: 8, 2: 12, 1: 17}, tiers)

# ---------------------------------------------------------------- disjointness
SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde")


def num(x):
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        return int(x, 16)
    raise TypeError(repr(x))


priors, skipped = [], 0


def collect(obj):
    global skipped
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
                        skipped += 1
            else:
                collect(v)
    elif isinstance(obj, list):
        for v in obj:
            collect(v)


import glob
for path in glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*", "research", "work-items",
                                   "*", "records.json")):
    try:
        collect(json.load(open(path)))
    except Exception:
        skipped += 1
# also scan this worktree's own merged-tree records (the worktree checkout itself)
for path in glob.glob(os.path.join(ROOT, "research", "work-items", "*", "records.json")):
    if SLUG in path:
        continue
    try:
        collect(json.load(open(path)))
    except Exception:
        skipped += 1
overlaps = []
own_ranges = []
for e in rec.get("exhibits", []):
    r = e.get("range")
    if r:
        own_ranges.append(tuple(num(x) for x in r.split("..")))
w = rec.get("window")
if isinstance(w, dict) and w.get("range"):
    own_ranges.append(tuple(num(x) for x in w["range"].split("..")))
if not own_ranges:
    own_ranges = [(START, END)]
for os_, oe in own_ranges:
    for a, b in priors:
        if not (a == os_ and b == oe) and os_ < b and a < oe:
            overlaps.append(((os_, oe), (a, b)))
check("disjointness skipped", skipped == 0, skipped)
check("disjointness NONE", not overlaps, overlaps[:3])
check("disjointness priors scanned", len(priors) > 40000, len(priors))
print("INFO priors=%d skipped=%d overlaps=%d" % (len(priors), skipped, len(overlaps)))

# ---------------------------------------------------------------- slug
out = subprocess.run(["git", "ls-tree", "HEAD", "--name-only",
                      "research/work-items/"], cwd=ROOT,
                     capture_output=True, text=True).stdout
check("slug absent from committed tree", SLUG not in out)
own = [p for p in glob.glob(os.path.join(ROOT, "research", "work-items", SLUG))]
check("slug only own dir", own == [PACKET], own)

# ---------------------------------------------------------------- MANIFEST
man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
check("MANIFEST entry count", len(man) == 5, len(man))
ok = 0
for line in man:
    digest, relp = line.split(None, 1)
    relp = relp.strip().lstrip("*")
    if relp.startswith("../../../"):
        full = os.path.normpath(os.path.join(PACKET, relp))
    else:
        full = os.path.join(PACKET, relp)
    if hashlib.sha256(open(full, "rb").read()).hexdigest() == digest:
        ok += 1
check("MANIFEST digests", ok == 5, ok)

print("PASS count: %d, FAIL count: %d" % (len(PASS), len(FAIL)))
sys.exit(1 if FAIL else 0)
