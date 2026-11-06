#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-2sites-lookup-10rsp.

Byte reads only; never executes the node binary. Checks, counted at the end:
base + binary identity, .eh_frame bounds, exhibit bytes, strict/call census,
site-block shapes, canary, jump closure, rel32 targets, rela counts, raw-e8
tiers, disjointness over every exhibit range, slug uniqueness, MANIFEST.
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
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-bintableinit-caller-2sites-lookup-10rsp")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-lookup-10rsp"
NAME = "bintableinit_caller_lookup_10rsp_2sites"
START, END = 0x63D61A0, 0x63D6575

PASS = 0
FAIL = 0
FAILURES = []


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(label + " :: " + detail)
        print("FAIL: " + label + " :: " + detail)


def read(path):
    with open(path, "rb") as f:
        return f.read()


def toff(va):
    return va - 0x1000


def strict_lines(text):
    out = []
    for line in text.splitlines():
        if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", line):
            out.append(line)
    return out


def addr_of(line):
    return int(line.split(":")[0].strip(), 16)


def mnemonic_of(line):
    parts = line.split("\t")
    return parts[2].split()[0] if len(parts) >= 3 else ""


def operands_of(line):
    parts = line.split("\t")
    if len(parts) >= 3:
        toks = parts[2].split(None, 1)
        return toks[1] if len(toks) > 1 else ""
    return ""


def parse_int(v):
    if isinstance(v, str):
        return int(v, 16)
    return int(v)


def parse_range(v):
    if isinstance(v, str) and ".." in v:
        a, b = v.split("..")
        return (int(a, 16), int(b, 16))
    if isinstance(v, list) and len(v) == 2:
        return (parse_int(v[0]), parse_int(v[1]))
    return None


SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde", "scan")
PAIR_KEYS = [("start", "end"), ("start_va", "end_va_exclusive"),
             ("start_va", "end_va"), ("address", "end"),
             ("start", "stop"), ("start", "end_exclusive")]


def collect_ranges(obj, out, skipped):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SKIP_KEYS or k == "fde" or k == "enclosing_fde":
                continue
            if k in ("exhibits", "windows"):
                items = v if isinstance(v, list) else (
                    list(v.values()) if isinstance(v, dict) else [])
                for e in items:
                    if not isinstance(e, dict):
                        continue
                    for rk in ("range", "fde_range", "address_range"):
                        if rk in e:
                            r = parse_range(e[rk])
                            if r is not None:
                                out.append(r)
                    for a, b in PAIR_KEYS:
                        if a in e and b in e:
                            try:
                                out.append((parse_int(e[a]), parse_int(e[b])))
                            except Exception:
                                skipped.append((a, b))
            else:
                collect_ranges(v, out, skipped)
    elif isinstance(obj, list):
        for v in obj:
            collect_ranges(v, out, skipped)


def uleb(data, p):
    r, sh = 0, 0
    while True:
        b = data[p]
        p += 1
        r |= (b & 0x7F) << sh
        if not (b & 0x80):
            break
        sh += 7
    return r, p


def sleb(data, p):
    r, sh = 0, 0
    while True:
        b = data[p]
        p += 1
        r |= (b & 0x7F) << sh
        sh += 7
        if not (b & 0x80):
            if b & 0x40:
                r -= (1 << sh)
            break
    return r, p


ENC_SIZE = {0x01: 2, 0x02: 4, 0x03: 8, 0x04: 8, 0x05: 8, 0x06: 8,
            0x07: 8, 0x08: 16, 0x09: 8, 0x0A: 8, 0x0B: 4, 0x0C: 4,
            0x0D: 8, 0x0E: 8}


def parse_eh_frame(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        nm, typ, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", data, off)
        secs.append((nm, typ, flags, addr, offset, size))
    strtab_off = secs[e_shstrndx][4]

    def secname(n):
        end = data.index(b"\x00", strtab_off + n)
        return data[strtab_off + n:end].decode()

    eh = None
    text = None
    for s in secs:
        if secname(s[0]) == ".eh_frame":
            eh = s
        if secname(s[0]) == ".text":
            text = s
    base_off, base_va, size = eh[4], eh[3], eh[5]
    cies = {}
    fdes = []
    p = base_off
    end = base_off + size
    while p < end:
        rec = p
        length = struct.unpack_from("<I", data, p)[0]
        if length == 0:
            break
        cie_id = struct.unpack_from("<I", data, p + 4)[0]
        if cie_id == 0:
            q = p + 8
            ver = data[q]
            q += 1
            aug_end = data.index(b"\x00", q)
            aug = data[q:aug_end].decode("latin1")
            q = aug_end + 1
            _ca, q = uleb(data, q)
            _da, q = sleb(data, q)
            if ver == 1:
                q += 1
            else:
                _ra, q = uleb(data, q)
            fde_enc = 0x1B
            if "z" in aug:
                alen, q = uleb(data, q)
                astart = q
                qi = q
                for ch in aug[1:]:
                    if ch == "P":
                        enc = data[qi]
                        qi += 1
                        qi += ENC_SIZE[enc & 0x0F]
                    elif ch == "L":
                        qi += 1
                    elif ch == "R":
                        fde_enc = data[qi]
                        qi += 1
                assert qi == astart + alen
                q = astart + alen
            cies[rec] = fde_enc
        else:
            cie_rec = rec + 4 - cie_id
            enc = cies.get(cie_rec, 0x1B)
            assert (enc & 0x70) == 0x10 and (enc & 0x0F) == 0x0B
            field_off = p + 8
            field_va = base_va + (field_off - base_off)
            init = struct.unpack_from("<i", data, field_off)[0] + field_va
            rng = struct.unpack_from("<I", data, field_off + 4)[0]
            fdes.append((init, init + rng))
        p = rec + 4 + length
    fdes.sort()
    return fdes, text


def main():
    node = read(BIN)
    check("binary size 105896032", len(node) == 105896032, str(len(node)))
    check("binary sha256",
          hashlib.sha256(node).hexdigest() ==
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    rec = json.loads(read(os.path.join(PACKET, "records.json")).decode())
    check("records base", rec["base"] ==
          "05bc2de303c05525b71e7e257426e741bc66a390")

    fdes, text = parse_eh_frame(node)
    check("total FDEs 135313", len(fdes) == 135313, str(len(fdes)))
    starts = [a for a, _ in fdes]
    i = bisect.bisect_left(starts, START)
    check("target FDE start", i < len(fdes) and fdes[i][0] == START)
    check("target FDE end", i < len(fdes) and fdes[i][1] == END)
    check("target FDE size 981", END - START == 981)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x63d6060..0x63d6199",
          prev == (0x63D6060, 0x63D6199), str(prev))
    check("prev gap 7", START - prev[1] == 7)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 7, gap.hex())
    check("next FDE 0x63d6575..0x63d6619",
          nxt == (0x63D6575, 0x63D6619), str(nxt))
    check("next padding 0", nxt[0] - END == 0)

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 981", len(hexb) == 981, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 199", len(lines) == 199, str(len(lines)))
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 6", len(calls) == 6, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63d62d0",
          rets and addr_of(rets[0]) == 0x63D62D0)

    def call_targets(lines):
        out = []
        for l in lines:
            m = re.search(r"\tcall\s+([0-9a-f]+)", l)
            if m:
                out.append((addr_of(l), int(m.group(1), 16)))
        return out

    ct = call_targets(calls)
    check("call rel32 targets",
          ct == [(0x63D61E5, 0x6364880), (0x63D62E0, 0x63D9880),
                 (0x63D6345, 0x63D9880), (0x63D64C9, 0x63D9700),
                 (0x63D6566, 0x63D9700), (0x63D6570, 0x63F0D70)],
          str(ct))
    bti = [a for a, t in ct if t == 0x63D9880]
    check("bti sites", bti == [0x63D62E0, 0x63D6345], str(bti))
    miss = [a for a, t in ct if t == 0x63D9700]
    check("lu-miss sites", miss == [0x63D64C9, 0x63D6566], str(miss))
    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str(len(bsr)))
    locks = [(mnemonic_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 1", len(locks) == 1, str(locks))
    check("lock add at 0x63d62a0",
          locks and locks[0][1].startswith("add ") and
          any(addr_of(l) == 0x63D62A0 for l in lines
              if mnemonic_of(l) == "lock"), str(locks))

    by_addr = {addr_of(l): l for l in lines}
    check("site1 lea 0x10 rsp in block",
          "lea" in by_addr[0x63D62D8] and "0x10(%rsp)" in by_addr[0x63D62D8])
    check("site1 mov rdi",
          "mov" in by_addr[0x63D62DD] and "%r12,%rdi" in by_addr[0x63D62DD])
    check("site1 rejoin mov rsi",
          "mov" in by_addr[0x63D62E5] and "%r12,%rsi" in by_addr[0x63D62E5])
    check("site2 lea 0x10 rsp in block",
          "lea" in by_addr[0x63D6338] and "0x10(%rsp)" in by_addr[0x63D6338])
    check("site2 mov rdi",
          "mov" in by_addr[0x63D633D] and "%rdx,%rdi" in by_addr[0x63D633D])
    check("site2 rejoin mov rdx",
          "mov" in by_addr[0x63D634A] and "0x8(%rsp),%rdx" in by_addr[0x63D634A])

    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 32", len(jmps) == 32, str(len(jmps)))
    outside = [(hex(a), hex(t)) for a, t in jmps
               if not (START <= t < END)]
    check("no jump leaves window", not outside, str(outside))
    for blk, je in ((0x63D62D8, 0x63D6200), (0x63D6338, 0x63D625A)):
        tg = [a for a, t in jmps if t == blk]
        check("block %s single je entry" % hex(blk), tg == [je], str(tg))

    check("canary at 0x198 rsp",
          "0x198(%rsp)" in by_addr[0x63D61CC])
    check("canary check sub fs",
          "sub" in by_addr[0x63D62AD] and "%fs:0x28" in by_addr[0x63D62AD])
    check("canary fail jne to stack_chk_fail",
          any(a == 0x63D62B6 and t == 0x63D6570 for a, t in jmps))

    check("key helper call at 0x63d61e5",
          (0x63D61E5, 0x6364880) in ct)
    check("key helper rdx 0x48",
          "mov" in by_addr[0x63D61A5] and "$0x48,%edx" in by_addr[0x63D61A5])
    check("key helper r8 zeroed",
          "xor" in by_addr[0x63D61A2] and "%r8d,%r8d" in by_addr[0x63D61A2])
    check("index table lea 0x65096c0",
          "lea" in by_addr[0x63D61BC] and "65096c0" in by_addr[0x63D61BC])
    check("threshold table lea 0x67277c0",
          "lea" in by_addr[0x63D61DA] and "67277c0" in by_addr[0x63D61DA])
    check("node table lea 0x6727a00",
          "lea" in by_addr[0x63D6241] and "6727a00" in by_addr[0x63D6241])
    check("no 0x6713606 reference",
          "6713606" not in obj)
    check("scan1 slot0 compare",
          "cmp" in by_addr[0x63D62F0] and "0x100(%rsi)" in by_addr[0x63D62F0])
    check("scan1 slot1 compare",
          "cmp" in by_addr[0x63D63A3] and "0x110(%rsi)" in by_addr[0x63D63A3])
    check("scan1 slot6 reversed compare",
          "cmp" in by_addr[0x63D6489] and "0x160(%rsi)" in by_addr[0x63D6489])
    check("scan2 slot0 compare",
          "cmp" in by_addr[0x63D6358] and "0x100(%rdx)" in by_addr[0x63D6358])
    check("scan2 slot1 compare",
          "cmp" in by_addr[0x63D63F2] and "0x110(%rdx)" in by_addr[0x63D63F2])
    check("scan2 slot2 reversed compare",
          "cmp" in by_addr[0x63D64D9] and "0x120(%rdx)" in by_addr[0x63D64D9])
    check("scan2 slot3 reversed compare",
          "cmp" in by_addr[0x63D64EC] and "0x130(%rdx)" in by_addr[0x63D64EC])
    check("lu-miss1 lea 0x6511a00",
          "lea" in by_addr[0x63D64B3] and "6511a00" in by_addr[0x63D64B3])
    check("lu-miss2 lea 0x6511a00",
          "lea" in by_addr[0x63D6550] and "6511a00" in by_addr[0x63D6550])

    # rela counts by direct ELF parse
    e_shoff = struct.unpack_from("<Q", node, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", node, 0x3A)
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        nm, typ, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", node, off)
        secs.append((nm, typ, flags, addr, offset, size))
    strtab_off = secs[e_shstrndx][4]

    def secname(n):
        end = node.index(b"\x00", strtab_off + n)
        return node[strtab_off + n:end].decode()

    dyn_total = plt_total = rel_count = 0
    for s in secs:
        nm = secname(s[0])
        if nm == ".rela.dyn":
            dyn_total = s[5] // 24
            for j in range(dyn_total):
                rtype = struct.unpack_from("<Q", node, s[4] + j * 24 + 8)[0] & 0xFFFFFFFF
                if rtype == 8:
                    rel_count += 1
        if nm == ".rela.plt":
            plt_total = s[5] // 24
    check("rela.dyn total 60723", dyn_total == 60723, str(dyn_total))
    check("rela.dyn RELATIVE 59534", rel_count == 59534, str(rel_count))
    check("rela.plt 278", plt_total == 278, str(plt_total))

    # raw-e8 census: scan .text for e8 with rel32 target 0x63d9880
    text_sec = None
    for s in secs:
        if secname(s[0]) == ".text":
            text_sec = s
    tva, toff_sec, tsize = text_sec[3], text_sec[4], text_sec[5]
    tbytes = node[toff_sec:toff_sec + tsize]
    counts = {}
    for i in range(len(tbytes) - 5):
        if tbytes[i] == 0xE8:
            rel = struct.unpack_from("<i", tbytes, i + 1)[0]
            tgt = tva + i + 5 + rel
            if tgt == 0x63D9880:
                va = tva + i
                k = bisect.bisect_right(starts, va) - 1
                if k >= 0 and fdes[k][0] <= va < fdes[k][1]:
                    counts[fdes[k][0]] = counts.get(fdes[k][0], 0) + 1
    tiers = {}
    for v in counts.values():
        tiers[v] = tiers.get(v, 0) + 1
    check("raw-e8 total 108", sum(counts.values()) == 108,
          str(sum(counts.values())))
    check("raw-e8 tiers",
          tiers == {10: 1, 8: 1, 6: 2, 5: 1, 4: 8, 2: 12, 1: 17},
          str(tiers))
    check("this FDE raw 2", counts.get(START, 0) == 2,
          str(counts.get(START, 0)))

    # disjointness over every exhibit range
    mine = []
    skipped = []
    collect_ranges(rec, mine, skipped)
    check("exhibit ranges collected", len(mine) >= 1, str(len(mine)))
    check("0 skipped records", len(skipped) == 0, str(skipped[:3]))
    priors = []
    pskipped = []
    for d in glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*",
                                    "research", "work-items", "*",
                                    "records.json")):
        dnorm = os.path.normpath(d)
        if os.path.normpath(PACKET) in dnorm or SLUG in dnorm:
            continue
        try:
            with open(d) as f:
                collect_ranges(json.load(f), priors, pskipped)
        except Exception:
            pass
    mine_set = set(mine)
    bad = []
    for m in mine_set:
        for p in priors:
            if m[0] < p[1] and p[0] < m[1]:
                bad.append((m, p))
                break
    check("disjointness NONE", not bad, str(bad[:3]))
    print("priors scanned: %d" % len(priors))

    # slug uniqueness: committed tree + worktree scan, same packet excluded
    slug_hit = False
    try:
        out = subprocess.run(["git", "ls-tree", "HEAD", "--name-only",
                              "research/work-items/"],
                             cwd=ROOT, capture_output=True, text=True,
                             timeout=60)
        if SLUG in out.stdout.split():
            slug_hit = True
    except Exception:
        pass
    if not slug_hit:
        for d in glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*",
                                        "research", "work-items", SLUG)):
            dnorm = os.path.normpath(d)
            if os.path.normpath(PACKET) in dnorm:
                continue
            same_window = False
            try:
                with open(os.path.join(d, "records.json")) as f:
                    r2 = json.load(f)
                ranges2 = []
                collect_ranges(r2, ranges2, [])
                if (START, END) in ranges2:
                    same_window = True
            except Exception:
                pass
            if not same_window:
                slug_hit = True
    check("slug unique", not slug_hit)

    # MANIFEST
    man = read(os.path.join(PACKET, "MANIFEST.sha256")).decode()
    ok = True
    for line in man.strip().splitlines():
        h, name = line.split(None, 1)
        name = name.strip().lstrip("*")
        if name == "MANIFEST.sha256":
            ok = False
            break
        if hashlib.sha256(read(os.path.join(PACKET, name))).hexdigest() != h:
            ok = False
            break
    check("MANIFEST hashes", ok)
    check("MANIFEST excludes itself", "MANIFEST.sha256" not in man)
    check("MANIFEST entries 5", len(man.strip().splitlines()) == 5,
          str(len(man.strip().splitlines())))

    print("PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    if FAILURES:
        for f in FAILURES:
            print("FAILED: " + f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
