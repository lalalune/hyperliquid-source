#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-2sites-strinsert-18rsp.

Byte reads only; never executes the node binary. ROOT is the worktree root
(tools/ sits one level below it).
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
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-strinsert-18rsp"
PACKET = os.path.join(ROOT, "research", "work-items", SLUG)
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
BASE = "05bc2de303c05525b71e7e257426e741bc66a390"
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
W_START, W_END = 0x63D4497, 0x63D463E
NAME = "bintableinit_caller_strinsert_18rsp_2sites"

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
        print("FAIL: %s %s" % (name, detail))


def parse_line(l):
    m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t([a-z][a-z0-9.]*)\s*(.*)$", l)
    if not m:
        return None
    return m.group(1), m.group(2).strip(), m.group(3), m.group(4)


def main():
    data = open(BIN, "rb").read()
    check("binary size 105896032", len(data) == 105896032, "got %d" % len(data))
    check("binary sha256", hashlib.sha256(data).hexdigest() == SHA)
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    check("records base", rec.get("base") == BASE)
    ex = rec["exhibits"][0]
    check("exhibit name", ex["name"] == NAME)
    check("exhibit range", ex["range"] == "0x63d4497..0x63d463e")
    check("exhibit bytes", ex["bytes"] == 423)
    check("exhibit strict", ex["strict"] == 106)
    check("exhibit calls_total", ex["calls_total"] == 11)
    check("exhibit ret", ex["ret"] == 1)
    check("exhibit ret_sites", ex["ret_sites"] == ["0x63d463d"])
    check("exhibit bti sites",
          ex["bin_table_init_sites"] == ["0x63d4534", "0x63d4570"])
    check("exhibit lu_miss empty", ex["lu_miss_sites"] == [])
    check("exhibit bsr", ex["bsr"] == 0)
    check("exhibit lock_sub", ex["lock_sub"] == 0)
    check("exhibit lock_add", ex["lock_add"] == 1)
    check("exhibit tail_jump_exits empty", ex["tail_jump_exits"] == [])

    raw = open(os.path.join(PACKET, NAME + ".hex"), "rb").read()
    check("hex length 423", len(raw) == 423)
    check("hex bytes match binary slice",
          raw == data[W_START - 0x1000:W_END - 0x1000])

    txt = open(os.path.join(PACKET, NAME + ".objdump.txt")).read().splitlines()
    strict = []
    for l in txt:
        p = parse_line(l)
        if p:
            strict.append(p)
    check("strict count 106", len(strict) == 106, "got %d" % len(strict))
    by_addr = {a: (mn, op) for a, b, mn, op in strict}

    def has(addr, mn=None, op_sub=None):
        if addr not in by_addr:
            return False
        m, o = by_addr[addr]
        if mn is not None and m != mn:
            return False
        if op_sub is not None and op_sub not in o:
            return False
        return True

    # call census from objdump mnemonics
    calls = [(a, op) for a, b, mn, op in strict if mn == "call"]
    check("call count 11", len(calls) == 11, "got %d" % len(calls))
    rets = [a for a, b, mn, op in strict if mn == "ret"]
    check("ret count 1 at 0x63d463d", rets == ["63d463d"],
          "got %s" % rets)
    bti = []
    for a, op in calls:
        m = re.search(r"call\s+([0-9a-f]+)", "call " + op)
        if m and m.group(1) == "63d9880":
            bti.append(a)
    check("bti sites 2", sorted(bti) == ["63d4534", "63d4570"],
          "got %s" % bti)
    miss = [a for a, op in calls
            if re.search(r"call\s+63d9700", "call " + op)]
    check("lu-miss sites 0", miss == [], "got %s" % miss)
    bsr = [a for a, b, mn, op in strict if mn == "bsr"]
    check("bsr 0", bsr == [], "got %s" % bsr)
    locks = [(a, op) for a, b, mn, op in strict if mn == "lock"]
    check("lock lines 1", len(locks) == 1, "got %s" % locks)
    check("lock add at 0x63d459e",
          locks and locks[0][0] == "63d459e" and
          locks[0][1].startswith("add %r14,0x38(%r9)"),
          "got %s" % (locks,))
    check("lock sub 0",
          not any(op.startswith("sub ") for a, op in locks))

    # rel32 targets for every call
    def rel32_target(addr_hex):
        for l in txt:
            p = parse_line(l)
            if p and p[0] == addr_hex:
                byts = bytes.fromhex(p[1].replace(" ", ""))
                imm = struct.unpack_from("<i", byts, 1)[0]
                return int(addr_hex, 16) + len(byts) + imm
        return None
    expected_calls = {
        "63d44c7": 0x63F0A80, "63d44d3": 0x63D3EEE, "63d44fc": 0x63D3B3D,
        "63d450f": 0x6364880, "63d4534": 0x63D9880, "63d4542": 0x63D3F0E,
        "63d4570": 0x63D9880, "63d4581": 0x63D4048, "63d45f0": 0x63F0D40,
        "63d460b": 0x63D39A0, "63d4627": 0x63F0D70,
    }
    for site, tgt in expected_calls.items():
        got = rel32_target(site)
        check("call rel32 %s -> %#x" % (site, tgt), got == tgt,
              "got %s" % (hex(got) if got else None))

    # site blocks
    check("site1 lea", has("63d452c", "lea", "0x18(%rsp),%r15"))
    check("site1 mov", has("63d4531", "mov", "%r15,%rdi"))
    check("site1 branch", has("63d452a", "jne", "63d453c"))
    check("site1 test", has("63d4527", "test", "%rbp,%rbp"))
    check("site1 rejoin", has("63d4539", "mov", "%r15,%rsi"))
    check("site2 lea", has("63d4568", "lea", "0x18(%rsp),%r15"))
    check("site2 mov", has("63d456d", "mov", "%r15,%rdi"))
    check("site2 branch", has("63d4566", "jne", "63d4578"))
    check("site2 test", has("63d4563", "test", "%rbp,%rbp"))
    check("site2 rejoin", has("63d4575", "mov", "%r15,%rdx"))

    # fall-through-only entry: no branch in window targets either block
    branch_targets = []
    for l in txt:
        m = re.search(r"\t(jmp|je|jne|ja|jb|jae|jbe|jns|js|jg|jl|jge|jle)\s+([0-9a-f]+)", l)
        if m:
            branch_targets.append(m.group(2))
    check("no jump targets site1 block", "63d452c" not in branch_targets)
    check("no jump targets site2 block", "63d4568" not in branch_targets)
    check("all branch targets inside window",
          all(W_START <= int(t, 16) < W_END for t in branch_targets),
          "outside: %s" % [t for t in branch_targets
                           if not (W_START <= int(t, 16) < W_END)])
    # non-end-anchored jmp regex: objdump prints trailing comments (#293)
    jmps = [l for l in txt if re.search(r"\tjmp\s+[0-9a-f]+", l)]
    check("unconditional jmps all inside",
          all(W_START <= int(re.search(r"\tjmp\s+([0-9a-f]+)", l).group(1), 16) < W_END
              for l in jmps),
          "jmps: %s" % jmps)
    check("unconditional jmp count 2", len(jmps) == 2, "got %d" % len(jmps))
    check("no tail-jump exits", len([l for l in jmps
          if not (W_START <= int(re.search(r"\tjmp\s+([0-9a-f]+)", l).group(1), 16) < W_END)]) == 0)

    # frame + canary
    check("canary store", has("63d44bd", "mov", "0x198(%rsp)"))
    check("canary load", has("63d4614", "mov", "0x198(%rsp),%rdx"))
    check("canary check sub", has("63d461c", "sub", "%fs:0x28,%rdx"))
    check("canary je", has("63d4625", "je", "63d462c"))
    check("stack_chk_fail call", has("63d4627", "call", "63f0d70"))
    check("epilogue add", has("63d462c", "add", "$0x1a8,%rsp"))

    # size class + tables + tail
    check("size gate cmp", has("63d44db", "cmp", "$0x1000,%r14"))
    check("size gate ja", has("63d44e2", "ja", "63d44f9"))
    check("threshold lea", has("63d44e4", "lea", "67277c0"))
    check("node-resolution lea", has("63d454b", "lea", "6727a00"))
    check("index lea", has("63d458a", "lea", "65096c0"))
    full = "\n".join(txt)
    check("no 0x6713606 reference", "6713606" not in full)
    check("tail lock add line present", "63d459e" in by_addr)
    check("strcpy call", has("63d45f0", "call", "63f0d40"))
    check("register call", has("63d460b", "call", "63d39a0"))
    check("return mov", has("63d4610", "mov", "0x8(%rbx),%rax"))
    check("null-return je to tail", has("63d451a", "je", "63d45a3"))

    # .eh_frame parse
    eh_off = None
    eh_size = None
    out = subprocess.run(["readelf", "-S", BIN], capture_output=True,
                         text=True).stdout
    m = re.search(r"\.eh_frame\s+\w+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                  out)
    check("readelf eh_frame section", m is not None)
    if m:
        eh_off = int(m.group(2), 16)
        eh_size = int(m.group(3), 16)
    check("eh_frame off 0xca6ed8", eh_off == 0xCA6ED8, "got %s" % eh_off)
    check("eh_frame size 0x77137c", eh_size == 0x77137C, "got %s" % eh_size)
    eh = data[eh_off:eh_off + eh_size]

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
    while p < eh_size:
        if p + 4 > eh_size:
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
            cie_pos = (p + 4) - cie_id
            fde_enc = cies.get(cie_pos)
            q = p + 8
            sz = ENC_SIZE[fde_enc & 0x0F]
            val, q = enc_val(eh, q, fde_enc)
            rng, q = enc_val(eh, q, fde_enc)
            if (fde_enc & 0x70) == 0x10:
                valfield_off = (q - sz) - sz
                init = eh_off + valfield_off + val
            else:
                init = val
            fdes.append((init, rng))
            p = rec_start + 4 + length
    check("eh_frame CIE count 3", len(cies) == 3, "got %d" % len(cies))
    check("eh_frame FDE count 135313", len(fdes) == 135313,
          "got %d" % len(fdes))
    fdes_s = sorted(fdes)
    i = bisect.bisect_left([a for a, _ in fdes_s], W_START)
    check("eh_frame window exact",
          fdes_s[i] == (W_START, 423), "got %s" % (fdes_s[i],))
    prevf = fdes_s[i - 1]
    nextf = fdes_s[i + 1]
    check("eh_frame prev FDE",
          prevf == (0x63D4425, 114), "got %s" % (prevf,))
    check("eh_frame prev padding 0",
          W_START - (prevf[0] + prevf[1]) == 0)
    check("eh_frame next FDE",
          nextf == (0x63D463E, 118), "got %s" % (nextf,))
    check("eh_frame next padding 0",
          nextf[0] - W_END == 0)

    # raw-e8 census grouped by enclosing FDE
    starts = [a for a, _ in fdes_s]
    mt = re.search(r"\.text\s+\w+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                   out)
    text_va = int(mt.group(1), 16)
    text_off = int(mt.group(2), 16)
    text_size = int(mt.group(3), 16)
    text = data[text_off:text_off + text_size]
    tiers = {}
    total = 0
    this_fde = 0
    for k in range(len(text) - 5):
        if text[k] != 0xE8:
            continue
        imm = struct.unpack_from("<i", text, k + 1)[0]
        va = text_va + k
        tgt = va + 5 + imm
        if tgt != 0x63D9880:
            continue
        total += 1
        j = bisect.bisect_right(starts, va) - 1
        fa, fr = fdes_s[j]
        if fa <= va < fa + fr:
            key = (fa, fr)
            tiers[key] = tiers.get(key, 0) + 1
            if fa == W_START:
                this_fde += 1
    from collections import Counter
    tier_counts = Counter(tiers.values())
    check("raw-e8 total 108", total == 108, "got %d" % total)
    check("raw-e8 tiers",
          dict(tier_counts) == {10: 1, 8: 1, 6: 2, 5: 1, 4: 8, 2: 12,
                                1: 17},
          "got %s" % dict(tier_counts))
    check("raw-e8 this FDE 2", this_fde == 2, "got %d" % this_fde)

    # .rela counts via readelf -W
    rout = subprocess.run(["readelf", "-W", "-r", BIN], capture_output=True,
                          text=True).stdout
    dyn_total = 0
    dyn_rel = 0
    plt_total = 0
    section = None
    for l in rout.splitlines():
        if ".rela.dyn" in l:
            section = "dyn"
            continue
        if ".rela.plt" in l:
            section = "plt"
            continue
        if section == "dyn" and re.match(r"^[0-9a-f]+\s+[0-9a-f]+\s+\S+", l):
            dyn_total += 1
            if "R_X86_64_RELATIVE" in l:
                dyn_rel += 1
        if section == "plt" and re.match(r"^[0-9a-f]+\s+[0-9a-f]+\s+\S+", l):
            plt_total += 1
    check("rela.dyn total 60723", dyn_total == 60723, "got %d" % dyn_total)
    check("rela.dyn RELATIVE 59534", dyn_rel == 59534, "got %d" % dyn_rel)
    check("rela.plt 278", plt_total == 278, "got %d" % plt_total)
    check("records census matches",
          rec["census"]["rela_dyn_total"] == dyn_total and
          rec["census"]["rela_dyn_relative"] == dyn_rel and
          rec["census"]["rela_plt"] == plt_total and
          rec["census"]["raw_e8_total"] == total and
          rec["census"]["total_fdes"] == len(fdes))

    # disjointness: exhibits-scoped collector, all range-bearing forms
    SKIP_KEYS = {"census", "cited", "survey", "callers", "largest_caller_fde",
                 "scan", "caller_scan", "next_caller", "next_question",
                 "cfg", "edges", "enclosing_fde"}

    def parse_num(v):
        if isinstance(v, bool):
            return None
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            try:
                return int(v.strip(), 16)
            except Exception:
                return None
        return None

    def parse_range_val(v):
        if isinstance(v, str) and ".." in v:
            a, b = v.split("..")
            x, y = parse_num(a), parse_num(b)
            return (x, y) if x is not None and y is not None else None
        if isinstance(v, list) and len(v) == 2:
            x, y = parse_num(v[0]), parse_num(v[1])
            return (x, y) if x is not None and y is not None else None
        return None

    PAIRS = [("start", "end"), ("start_va", "end_va"),
             ("start_va", "end_va_exclusive"), ("address", "end"),
             ("start", "stop"), ("start", "end_exclusive")]

    def collect(obj, out, skipped, self_window):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in SKIP_KEYS:
                    continue
                if k in ("exhibits", "windows"):
                    items = v if isinstance(v, list) else \
                        list(v.values()) if isinstance(v, dict) else []
                    for e in items:
                        if not isinstance(e, dict):
                            continue
                        got = False
                        for rk in ("range", "fde_range", "address_range"):
                            if rk in e:
                                r = parse_range_val(e[rk])
                                if r:
                                    if r != self_window:
                                        out.append(r)
                                    got = True
                                else:
                                    skipped.append((rk, e[rk]))
                        for a, b in PAIRS:
                            if a in e and b in e:
                                x, y = parse_num(e[a]), parse_num(e[b])
                                if x is not None and y is not None:
                                    if (x, y) != self_window:
                                        out.append((x, y))
                                    got = True
                                else:
                                    skipped.append((a, e[a]))
                        if not got:
                            collect(e, out, skipped, self_window)
                else:
                    collect(v, out, skipped, self_window)
        elif isinstance(obj, list):
            for v in obj:
                collect(v, out, skipped, self_window)

    priors = []
    skipped = []
    for d in glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*",
                                    "research", "work-items", "*",
                                    "records.json")):
        try:
            collect(json.load(open(d)), priors, skipped, (W_START, W_END))
        except Exception:
            pass
    for d in glob.glob(os.path.join(ROOT, "research", "work-items", "*",
                                    "records.json")):
        if SLUG in d:
            continue
        try:
            collect(json.load(open(d)), priors, skipped, (W_START, W_END))
        except Exception:
            pass
    check("disjointness skipped 0", len(skipped) == 0, "got %s" % skipped[:5])
    mine = []
    for e in rec.get("exhibits", []):
        if not isinstance(e, dict):
            continue
        r = None
        if "range" in e:
            r = parse_range_val(e["range"])
        if r is None:
            for a, b in PAIRS:
                if a in e and b in e:
                    x, y = parse_num(e[a]), parse_num(e[b])
                    if x is not None and y is not None:
                        r = (x, y)
                        break
        if r is not None:
            mine.append(r)
    check("mine exhibit ranges include window", (W_START, W_END) in mine,
          "got %s" % mine)
    bad = [(m, p) for m in mine for p in priors
           if m[0] < p[1] and p[0] < m[1]]
    check("disjointness NONE", bad == [], "got %s" % bad[:5])
    print("disjointness priors scanned: %d" % len(priors))

    # slug uniqueness: committed tree + worktrees, same slug+window excluded
    slug_hit = False
    git_out = subprocess.run(["git", "ls-tree", "HEAD", "--name-only",
                              "research/work-items/"], capture_output=True,
                             text=True, cwd=ROOT).stdout
    if SLUG in git_out.split():
        slug_hit = True
    check("slug not in committed tree", not slug_hit)
    for d in glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*",
                                    "research", "work-items", SLUG,
                                    "records.json")):
        try:
            r2 = json.load(open(d))
            same = False
            for e2 in r2.get("exhibits", []):
                if isinstance(e2, dict) and e2.get("range") == "0x63d4497..0x63d463e":
                    same = True
            if not same:
                slug_hit = True
        except Exception:
            slug_hit = True
    check("slug not in other worktrees", not slug_hit)

    # MANIFEST
    mres = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                          capture_output=True, text=True, cwd=PACKET)
    check("MANIFEST sha256 -c exit 0", mres.returncode == 0, mres.stderr[:200])
    ok_lines = mres.stdout.count(": OK")
    check("MANIFEST 5/5 OK", ok_lines == 5, "got %d" % ok_lines)

    # objdump regeneration (strip through 'file format' line)
    regen = subprocess.run(["objdump", "-d",
                            "--start-address=0x63d4497",
                            "--stop-address=0x63d463e", BIN],
                           capture_output=True, text=True).stdout.splitlines()

    def body(lines):
        for idx, l in enumerate(lines):
            if "file format" in l:
                return lines[idx + 1:]
        return lines
    check("objdump regeneration matches exhibit",
          body(regen) == body(txt),
          "regen %d lines vs exhibit body %d" % (len(body(regen)),
                                                 len(body(txt))))

    print("PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    if FAIL:
        for f in FAILURES:
            print("FAILED:", f)
        sys.exit(1)


if __name__ == "__main__":
    main()
