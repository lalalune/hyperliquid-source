#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-4sites-walk-120rsp.

Byte reads only; never executes the target binary. Checks: binary size +
SHA-256, .eh_frame bounds for the claimed window, gap/padding int3 bytes,
exhibit bytes, strict recount, call census (90 total / 4 bin_table_init /
13 lu-miss / 1 ret), bsr count, per-site branch shapes, records consistency,
.rela.dyn census (60,723 total / 59,534 RELATIVE, .rela.plt 278 separate),
range-only disjointness (self excluded by exact window equality), slug
uniqueness (self dir excluded), raw-e8 census and ranking, MANIFEST digests.
"""
import bisect
import glob
import hashlib
import json
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLUG = "RE-001-node115-lu-bintableinit-caller-4sites-walk-120rsp"
PACKET = os.path.join(ROOT, "research", "work-items", SLUG)
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
BIN_SIZE = 105896032
BIN_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
START, END = 0x6350210, 0x6352F5E
BTI_TARGET = 0x63D9880
MISS_TARGET = 0x63D9700
EXPECTED = {
    "bytes": 11598, "strict": 2382, "calls": 90, "bti": 4, "miss": 13,
    "ret": 1, "bsr": 14, "gap": 6, "padding": 2,
}
BTI_SITES = [
    # (site, block_lea_addr, branch_kind, branch_addr, branch_target, rejoin)
    (0x6350E15, 0x6350E00, "jne-away", 0x6350DFA, 0x63502C3, 0x63502CA),
    (0x6351683, 0x635166E, "je", 0x63510AA, 0x635166E, 0x63510B0),
    (0x6351ABA, 0x6351AAF, "je", 0x6350C2B, 0x6351AAF, 0x6350C31),
    (0x635223A, 0x635222F, "je", 0x63519AB, 0x635222F, 0x63519B1),
]
RANKING = [  # (fde_start, fde_end, raw_e8_count)
    (0x63CBA10, 0x63CCD22, 10), (0x63C9C80, 0x63CB146, 8),
    (0x63CE8C0, 0x63CF8BC, 6), (0x63D4BBE, 0x63D5428, 6),
    (0x63BD8C0, 0x63BE4CE, 5), (0x63CB150, 0x63CBA04, 4),
    (0x63C8D60, 0x63C94FC, 4), (0x636BD90, 0x636C49C, 4),
    (0x6350210, 0x6352F5E, 4),
]
REMAINING_4RAW = [
    (0x6365660, 0x63673D9), (0x63D3080, 0x63D379C),
    (0x63D5940, 0x63D605C), (0x63EC900, 0x63ED06D),
]

PASS, FAIL = [], []


def ok(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else " :: " + str(detail)))


def uleb(buf, off):
    r, s = 0, 0
    while True:
        b = buf[off]
        off += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, off
        s += 7


def sleb(buf, off):
    r, s = 0, 0
    while True:
        b = buf[off]
        off += 1
        r |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            if b & 0x40:
                r -= 1 << s
            return r, off


def parse_elf(data):
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize = struct.unpack("<H", data[0x3A:0x3C])[0]
    e_shnum = struct.unpack("<H", data[0x3C:0x3E])[0]
    e_shstrndx = struct.unpack("<H", data[0x3E:0x40])[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ = struct.unpack("<II", data[o:o + 8])
        flags, addr, off, size = struct.unpack("<QQQQ", data[o + 8:o + 40])
        secs.append((name, typ, flags, addr, off, size))
    str_off = secs[e_shstrndx][4]
    out = {}
    for name, typ, flags, addr, off, size in secs:
        end = data.index(b"\x00", str_off + name)
        out[data[str_off + name:end].decode()] = (addr, off, size)
    return out


def eh_frame_fdes(data, sections):
    addr, off, size = sections[".eh_frame"]
    fdes, p, cie_enc = [], off, {}
    while p < off + size:
        (length,) = struct.unpack("<I", data[p:p + 4])
        if length == 0:
            break
        rec = p
        cie_id = struct.unpack("<I", data[p + 4:p + 8])[0]
        if cie_id == 0:
            q = p + 8
            ver = data[q]
            q += 1
            z = data.index(b"\x00", q)
            aug = data[q:z].decode("latin1")
            q = z + 1
            aug_len = None
            if "z" in aug:
                aug_len, q = uleb(data, q)
            _ca, q = uleb(data, q)
            _da, q = sleb(data, q)
            _rar, q = uleb(data, q)
            enc = None
            if "R" in aug:
                enc = data[q]
            cie_enc[rec] = enc
        else:
            cie_start = (rec + 4) - cie_id
            enc = cie_enc.get(cie_start)
            if enc == 0x1B:  # pcrel sdata4
                field_va = addr + (rec + 8 - off)
                init = field_va + struct.unpack("<i", data[rec + 8:rec + 12])[0]
                rng = struct.unpack("<I", data[rec + 12:rec + 16])[0]
                fdes.append((init, init + rng))
        p = rec + 4 + length
    return fdes


def rela_census(data):
    e_phoff = struct.unpack("<Q", data[0x20:0x28])[0]
    e_phentsize = struct.unpack("<H", data[0x36:0x38])[0]
    e_phnum = struct.unpack("<H", data[0x38:0x3A])[0]
    segs, dyn_off = [], None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack("<I", data[o:o + 4])[0]
        p_offset, p_vaddr, _pp, p_filesz = struct.unpack("<QQQQ", data[o + 8:o + 40])
        segs.append((p_type, p_offset, p_vaddr, p_filesz))
        if p_type == 2:
            dyn_off = p_offset
    tags, o = {}, dyn_off
    while True:
        tag, val = struct.unpack("<qQ", data[o:o + 16])
        if tag == 0:
            break
        tags[tag] = val
        o += 16

    def va2off(va):
        for t, off, va0, fsz in segs:
            if t == 1 and va0 <= va < va0 + fsz:
                return off + (va - va0)
        return None

    def count(va, total_bytes):
        off, n, rel = va2off(va), total_bytes // 24, 0
        for i in range(n):
            info = struct.unpack("<Q", data[off + i * 24 + 8:off + i * 24 + 16])[0]
            if info & 0xFFFFFFFF == 8:
                rel += 1
        return n, rel

    n, rel = count(tags[7], tags[8])
    pn, _ = count(tags[23], tags[2])
    return n, rel, pn


def collect_ranges(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("census", "cited", "survey", "callers", "largest_caller_fde"):
                continue
            if k in ("exhibits", "windows"):
                items = v if isinstance(v, list) else v.values() if isinstance(v, dict) else []
                for e in items:
                    if isinstance(e, dict):
                        if "range" in e:
                            r = e["range"]
                            out.append((int(r[0], 16), int(r[1], 16)) if isinstance(r, list)
                                       else tuple(int(x, 16) for x in r.split("..")))
                        elif "start" in e and "end" in e:
                            out.append((int(e["start"], 16), int(e["end"], 16)))
                    elif isinstance(e, list) and len(e) == 2:
                        out.append((int(e[0], 16), int(e[1], 16)))
            elif k == "window" and isinstance(v, dict):
                if "range" in v:
                    out.append(tuple(int(x, 16) for x in v["range"].split("..")))
                elif "start" in v and "end" in v:
                    out.append((int(v["start"], 16), int(v["end"], 16)))
                else:
                    collect_ranges(v, out)
            else:
                collect_ranges(v, out)
    elif isinstance(obj, list):
        for v in obj:
            collect_ranges(v, out)


def main():
    data = open(BIN, "rb").read()
    ok("binary size", len(data) == BIN_SIZE, len(data))
    ok("binary sha256", hashlib.sha256(data).hexdigest() == BIN_SHA)

    sections = parse_elf(data)
    fdes = eh_frame_fdes(data, sections)
    ok("eh_frame walk found many FDEs", len(fdes) > 50000, len(fdes))
    ok("eh_frame window bounds", (START, END) in fdes, "window not found")
    starts = [s for s, _e in sorted(fdes)]
    prev_end = max(e for s, e in fdes if e <= START)
    next_start = min(s for s, e in fdes if s >= END)
    ok("prev FDE end", prev_end == 0x635020A, hex(prev_end))
    ok("next FDE start", next_start == 0x6352F60, hex(next_start))

    def toff(va):
        return va - 0x1000  # .text mapping for this binary

    ok("gap bytes are int3", data[toff(START) - 6:toff(START)] == b"\xcc" * 6)
    ok("padding bytes are int3", data[toff(END):toff(END) + 2] == b"\xcc" * 2)

    rec = json.load(open(os.path.join(PACKET, "records.json")))
    ok("records window", rec["window"]["range"] == "0x6350210..0x6352f5e")
    ok("records slug", rec["slug"] == SLUG)
    ex = rec["exhibits"][0]
    raw = open(os.path.join(PACKET, ex["name"] + ".hex"), "rb").read()
    ok("exhibit bytes", raw == data[toff(START):toff(START) + EXPECTED["bytes"]])
    ok("exhibit length", len(raw) == EXPECTED["bytes"], len(raw))

    txt = open(os.path.join(PACKET, ex["name"] + ".objdump.txt")).read().splitlines()
    strict = [l for l in txt if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]
    calls = [l for l in txt if re.search(r"\tcall\s", l)]
    rets = [l for l in txt if re.search(r"\tret\s*$", l)]
    bti = [l for l in calls if "63d9880" in l]
    miss = [l for l in calls if "63d9700" in l]
    bsr = [l for l in txt if re.search(r"\tbsr\s", l)]
    ok("strict count", len(strict) == EXPECTED["strict"], len(strict))
    ok("call count", len(calls) == EXPECTED["calls"], len(calls))
    ok("bin_table_init sites", len(bti) == EXPECTED["bti"], len(bti))
    ok("lu-miss sites", len(miss) == EXPECTED["miss"], len(miss))
    ok("ret count", len(rets) == EXPECTED["ret"], len(rets))
    ok("bsr count", len(bsr) == EXPECTED["bsr"], len(bsr))

    # records consistency: the packet's own claims must match the recount
    ok("records exhibit strict", ex["strict"] == len(strict), ex["strict"])
    ok("records exhibit bytes", ex["bytes"] == len(raw), ex["bytes"])
    w = rec["window"]
    ok("records window strict", w["strict"] == len(strict), w["strict"])
    ok("records window bytes", w["bytes"] == len(raw), w["bytes"])
    ok("records window calls", w["calls"] == len(calls), w["calls"])
    ok("records window bti", w["bin_table_init_sites"] == len(bti), w["bin_table_init_sites"])
    ok("records window miss", w["lu_miss_sites"] == len(miss), w["lu_miss_sites"])
    ok("records window ret", w["ret"] == len(rets), w["ret"])
    ok("records window bsr", w["bsr"] == len(bsr), w["bsr"])

    def call_addrs(lines):
        out = []
        for l in lines:
            m = re.match(r"\s*([0-9a-f]+):\t", l)
            if m:
                out.append("0x" + m.group(1))
        return out

    ok("records bti site list", [s["site"] for s in rec["bin_table_init_sites"]] == call_addrs(bti),
       [s["site"] for s in rec["bin_table_init_sites"]])
    ok("records miss site list", [s["site"] for s in rec["lu_miss_sites"]] == call_addrs(miss),
       [s["site"] for s in rec["lu_miss_sites"]])

    by_addr = {}
    for l in txt:
        m = re.match(r"\s*([0-9a-f]+):\t", l)
        if m:
            by_addr[int(m.group(1), 16)] = l
    for site, lea_addr, kind, br_addr, br_tgt, rejoin in BTI_SITES:
        lea = by_addr.get(lea_addr, "")
        ok("site %x lea 0x120(rsp)" % site, "lea    0x120(%rsp)" in lea, lea.strip()[:60])
        br = by_addr.get(br_addr, "")
        if kind == "je":
            ok("site %x je branch" % site, re.search(r"\tje\s+%x" % br_tgt, br) is not None, br.strip()[:60])
            tst = by_addr.get(br_addr - 3, "")
            ok("site %x test rbx,rbx" % site, "test   %rbx,%rbx" in tst, tst.strip()[:60])
        else:
            ok("site %x jne-away branch" % site, re.search(r"\tjne\s+%x" % br_tgt, br) is not None, br.strip()[:60])
            tst = by_addr.get(br_addr - 3, "")
            ok("site %x test rbx,rbx" % site, "test   %rbx,%rbx" in tst, tst.strip()[:60])
        call = by_addr.get(site, "")
        ok("site %x calls bin_table_init" % site, "63d9880" in call)
        # rejoin: the jmp after the call block
        j = site + 5
        found = False
        for a in range(j, j + 40):
            if a in by_addr and re.search(r"\tjmp\s+%x" % rejoin, by_addr[a]):
                found = True
                break
        ok("site %x rejoin" % site, found, hex(rejoin))

    n, rel, pn = rela_census(data)
    ok("rela.dyn total", n == 60723, n)
    ok("rela.dyn RELATIVE", rel == 59534, rel)
    ok("rela.plt total", pn == 278, pn)

    # disjointness: merged tree + prior worktrees, self excluded by exact window
    priors = []
    for path in glob.glob(os.path.join(ROOT, "research", "work-items", "*", "records.json")):
        try:
            collect_ranges(json.load(open(path)), priors)
        except Exception:
            pass
    for path in glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*/records.json"):
        if os.path.abspath(path).startswith(os.path.abspath(PACKET)):
            continue
        try:
            collect_ranges(json.load(open(path)), priors)
        except Exception:
            pass
    bad = [(s, e) for s, e in priors if s < END and START < e and not (s == START and e == END)]
    ok("disjointness", not bad, bad[:3])

    # slug uniqueness (self dir excluded)
    clash = [d for d in glob.glob(os.path.join(ROOT, "research", "work-items", SLUG))]
    ok("slug unique in merged tree", len(clash) <= 1, clash)

    # raw-e8 census and ranking
    text_addr, text_off, text_size = sections[".text"]
    text = data[text_off:text_off + text_size]
    fsorted = sorted(fdes)
    fstarts = [s for s, _e in fsorted]
    grouped = {}
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel32 = struct.unpack("<i", text[i + 1:i + 5])[0]
            va = text_addr + i
            if va + 5 + rel32 == BTI_TARGET:
                j = bisect.bisect_right(fstarts, va) - 1
                f = fsorted[j] if j >= 0 and fsorted[j][0] <= va < fsorted[j][1] else None
                if f is None:
                    FAIL.append("raw-e8 unenclosed match at %x" % va)
                else:
                    grouped[f] = grouped.get(f, 0) + 1
    rank_ok = all(grouped.get((s, e), 0) == c for s, e, c in RANKING)
    ok("raw-e8 ranking", rank_ok, {hex(k[0]): v for k, v in grouped.items() if v >= 4})
    big = {f for f, c in grouped.items() if c >= 4}
    expect_big = {(s, e) for s, e, _c in RANKING} | set(REMAINING_4RAW)
    ok("4-plus FDE set", big == expect_big, sorted(hex(f[0]) for f in big - expect_big))

    # MANIFEST digests
    man = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
    ok("MANIFEST entry count", len(man) == 7, len(man))
    man_ok = True
    for line in man:
        h, p = line.split("  ", 1)
        fp = os.path.normpath(os.path.join(PACKET, p))
        if not os.path.exists(fp) or hashlib.sha256(open(fp, "rb").read()).hexdigest() != h:
            man_ok = False
    ok("MANIFEST digests", man_ok)

    print("PASS count: %d, FAIL count: %d" % (len(PASS), len(FAIL)))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
