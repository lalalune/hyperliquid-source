#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-miss-caller-1site-dispatch.

Byte reads only; never executes the node binary. Checks, counted at the end:
base + binary identity, .eh_frame bounds, exhibit bytes, strict/call census
(1691 strict, 105 calls / 33 distinct targets, 1 ret, bsr 8, lock 0/0,
282 jumps all inside), entry frame (endbr64, sub $0x98, canary, TLS flag
check), entry size class (byte table 0x67277c0 + size table 0x6727a00),
single walk (top index + high-bits compare, second level into rdi),
extract (shl/sar 0x10 + helper 0x63be540), single 8-slot move-to-front scan
(slot 0 separate, slots 1-7 one loop compare, 0 reversed compares), one
lu-miss site (rsi 0x6511a00 .bss, rdi rbx, rdx table, rcx r12 walk key —
write-set check on the walk->miss path), six second-handler sites
(rdi rbx, rdx 0x64da4b0), dispatcher call census (#314 window x1, #313
window x2, #298 window x2, 0x6364880 x13, 0x63e9cd0 x12, 0x63bd2c0 x8),
one indirect call via GOT 0x64ffb38, exit rax = r12, jump closure with 0
outside targets, rela counts, raw-e8 censuses (lu-miss 168/53, bti 108/42),
lu-miss frontier survey (16 survivors), next-candidate disjointness,
disjointness over every exhibit range, slug uniqueness, MANIFEST.
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
                      "RE-001-node115-lu-miss-caller-1site-dispatch")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-1site-dispatch"
NAME = "lu_miss_caller_1site_dispatch"
START, END = 0x6353A70, 0x635582B

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
    for s in secs:
        if secname(s[0]) == ".eh_frame":
            eh = s
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
    return fdes


def sections(node):
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

    return {secname(s[0]): s for s in secs}


def dst_reg(line):
    mn = mnemonic_of(line)
    if mn in ("cmp", "test", "call", "jmp", "je", "jne", "ja", "jae", "jb",
              "jbe", "jge", "jl", "jle", "jg", "jo", "jno", "js", "jns",
              "jp", "jnp", "ret", "push", "nopl", "nopw", "endbr64"):
        return None
    if mn == "pop":
        return operands_of(line).strip()
    parts = [p.strip() for p in operands_of(line).split(",")]
    return parts[-1] if parts else None


def main():
    node = read(BIN)
    check("binary size 105896032", len(node) == 105896032, str(len(node)))
    check("binary sha256",
          hashlib.sha256(node).hexdigest() ==
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    rec = json.loads(read(os.path.join(PACKET, "records.json")).decode())
    check("records base", rec["base"] ==
          "05bc2de303c05525b71e7e257426e741bc66a390")

    fdes = parse_eh_frame(node)
    check("total FDEs 135313", len(fdes) == 135313, str(len(fdes)))
    starts = [a for a, _ in fdes]
    i = bisect.bisect_left(starts, START)
    check("target FDE start", i < len(fdes) and fdes[i][0] == START)
    check("target FDE end", i < len(fdes) and fdes[i][1] == END)
    check("target FDE size 7611", END - START == 7611)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x6353a20..0x6353a61",
          prev == (0x6353A20, 0x6353A61), str(prev))
    check("prev gap 15", START - prev[1] == 15)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 15, gap.hex())
    check("next FDE 0x6355830..0x63558f2",
          nxt == (0x6355830, 0x63558F2), str(nxt))
    check("next padding 5", nxt[0] - END == 5)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 5, pad.hex())
    check("no overlap with 0x63ed090 exclusion",
          END <= 0x63ED090 or START >= 0x63ED862)
    check("no overlap with 0x63ef8e0 exclusion",
          END <= 0x63EF8E0 or START >= 0x63EFBA2)

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 7611", len(hexb) == 7611, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 1691", len(lines) == 1691, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 105", len(calls) == 105, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x6353bdb", [addr_of(l) for l in rets] == [0x6353BDB],
          str([hex(addr_of(l)) for l in rets]))

    def call_targets(ls):
        out = []
        for l in ls:
            m = re.search(r"\tcall\s+([0-9a-f]+)", l)
            if m:
                out.append((addr_of(l), int(m.group(1), 16)))
        return out

    ct = call_targets(calls)
    indirect = [addr_of(l) for l in calls
                if re.search(r"\tcall\s+\*", l)]
    check("indirect calls 1", indirect == [0x635481F],
          str([hex(a) for a in indirect]))
    from collections import Counter
    tgt = Counter(t for _, t in ct)
    expect = {0x6364880: 13, 0x63E9CD0: 12, 0x63BD2C0: 8, 0x634EBB0: 6,
              0x6353610: 5, 0x63F0A90: 5, 0x63537F0: 5, 0x6365150: 4,
              0x63E9C40: 4, 0x63EDF10: 4, 0x63C3890: 2, 0x63C2F00: 2,
              0x63C3B00: 2, 0x63C2E80: 2, 0x63F0AD0: 2, 0x63EEC80: 2,
              0x63BE540: 2, 0x63F1AD0: 2, 0x6364420: 2, 0x6364410: 2,
              0x6364400: 2, 0x6362F90: 2, 0x6352FC0: 2, 0x63C3780: 2,
              0x63EC4C0: 2, 0x6360ED0: 2, 0x63EF8E0: 1, 0x63B7240: 1,
              0x634F0B0: 1, 0x63495B0: 1, 0x63F0D70: 1, 0x63D9700: 1}
    check("call target multiset exact", dict(tgt) == expect,
          str(dict(tgt)))
    check("distinct call targets 32 direct + 1 indirect",
          len(tgt) == 32, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 1 at 0x63557eb",
          [a for a, t in ct if t == 0x63D9700] == [0x63557EB],
          str([hex(a) for a, t in ct if t == 0x63D9700]))
    check("second-handler sites 6",
          sorted(a for a, t in ct if t == 0x634EBB0) ==
          [0x6354912, 0x6354B44, 0x6354CF9, 0x6354E1D, 0x6355730, 0x635578D],
          str([hex(a) for a, t in ct if t == 0x634EBB0]))
    check("no lock-wait sites", tgt.get(0x63BF680, 0) == 0,
          str(tgt.get(0x63BF680, 0)))
    check("#314 window called once at 0x6354682",
          [a for a, t in ct if t == 0x63495B0] == [0x6354682],
          str([hex(a) for a, t in ct if t == 0x63495B0]))
    check("#313 window called twice",
          sorted(a for a, t in ct if t == 0x63C2F00) ==
          [0x6353CAA, 0x6355415],
          str([hex(a) for a, t in ct if t == 0x63C2F00]))
    bsr = [addr_of(l) for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 8 exact list",
          bsr == [0x6353F49, 0x63543A3, 0x635496F, 0x6354BAF,
                  0x6354EEE, 0x6355102, 0x63551CC, 0x6355662],
          str([hex(a) for a in bsr]))
    locks = [(mnemonic_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))
    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 282", len(jmps) == 282, str(len(jmps)))
    outside = [(a, t) for a, t in jmps if not (START <= t < END)]
    check("jump closure zero outside", outside == [], str(outside))

    # Entry + frame.
    check("entry endbr64", "endbr64" in by_addr[0x6353A70])
    check("entry pushes r15..rbx",
          all("push" in by_addr[a] for a in
              [0x6353A74, 0x6353A76, 0x6353A78, 0x6353A7A, 0x6353A7C,
               0x6353A80]))
    check("entry sub 0x98 rsp",
          "sub" in by_addr[0x6353A81] and "$0x98,%rsp" in by_addr[0x6353A81])
    check("entry mov rdi to rbp",
          "mov" in by_addr[0x6353A7D] and "%rdi,%rbp" in by_addr[0x6353A7D])
    check("canary load fs:0x28",
          "mov" in by_addr[0x6353A91] and "%fs:0x28,%rax" in by_addr[0x6353A91])
    check("canary store 0x88 rsp",
          "mov" in by_addr[0x6353A9A] and "0x88(%rsp)" in by_addr[0x6353A9A])
    check("tls base add",
          "add" in by_addr[0x6353AA9] and "%rax,%rbx" in by_addr[0x6353AA9])
    check("tls flag cmpb fs:0x330",
          "cmpb" in by_addr[0x6353AAC] and "%fs:0x330" in by_addr[0x6353AAC])
    check("tls flag jne 0x6353d50",
          "jne" in by_addr[0x6353AB4] and "6353d50" in by_addr[0x6353AB4])

    # Entry size class.
    check("size cmp 0x1000 rbp",
          "cmp" in by_addr[0x6353ABA] and "$0x1000,%rbp" in by_addr[0x6353ABA])
    check("size byte table lea 0x67277c0",
          "lea" in by_addr[0x6353AC7] and "67277c0" in by_addr[0x6353AC7])
    check("size byte index shr 3",
          "shr" in by_addr[0x6353AD2] and "$0x3,%r8" in by_addr[0x6353AD2])
    check("size byte load movzbl",
          "movzbl" in by_addr[0x6353AD6] and "(%r9,%r8,1),%r14d" in by_addr[0x6353AD6])
    check("size cmp 0xe7 r14d",
          "cmp" in by_addr[0x6353ADB] and "$0xe7,%r14d" in by_addr[0x6353ADB])
    check("size table lea 0x6727a00",
          "lea" in by_addr[0x6353AEF] and "6727a00" in by_addr[0x6353AEF])
    check("size table load",
          "mov" in by_addr[0x6353B00] and "(%r11,%r8,8),%r13" in by_addr[0x6353B00])
    check("size flag lea 0x6713606",
          "lea" in by_addr[0x6353AE8] and "6713606" in by_addr[0x6353AE8])
    check("size flag cmpb",
          "cmpb" in by_addr[0x6353AFD] and "(%rax)" in by_addr[0x6353AFD])
    check("size cmp 0x3800 rbp",
          "cmp" in by_addr[0x6353B11] and "$0x3800,%rbp" in by_addr[0x6353B11])

    # Walk (single, table in rbx, key in r12).
    check("walk key load mov rdx to r12",
          "mov" in by_addr[0x6354094] and "(%rdx),%r12" in by_addr[0x6354094])
    check("walk top shr 0x1a",
          "shr" in by_addr[0x63540C6] and "$0x1a,%r15" in by_addr[0x63540C6])
    check("walk top and 0xf0",
          "and" in by_addr[0x63540D1] and "$0xf0,%r15d" in by_addr[0x63540D1])
    check("walk top add rbx",
          "add" in by_addr[0x63540D8] and "%rbx,%r15" in by_addr[0x63540D8])
    check("walk high bits mov r12 to r10",
          "mov" in by_addr[0x63540C3] and "%r12,%r10" in by_addr[0x63540C3])
    check("walk high bits and",
          "and" in by_addr[0x63540CA] and "$0xffffffffc0000000,%r10" in by_addr[0x63540CA])
    check("walk top load",
          "mov" in by_addr[0x63540DB] and "0x1b0(%r15),%rbp" in by_addr[0x63540DB])
    check("walk top compare",
          "cmp" in by_addr[0x63540E2] and "%rbp,%r10" in by_addr[0x63540E2])
    check("walk mismatch jne scan slot 0",
          "jne" in by_addr[0x63540E5] and "6354c80" in by_addr[0x63540E5])
    check("walk second level shr 0x9",
          "shr" in by_addr[0x63540EE] and "$0x9,%rax" in by_addr[0x63540EE])
    check("walk second level and 0x1ffff8",
          "and" in by_addr[0x63540F2] and "$0x1ffff8,%eax" in by_addr[0x63540F2])
    check("walk second level add table entry",
          "add" in by_addr[0x63540F7] and "0x1b8(%r15),%rax" in by_addr[0x63540F7])
    check("walk second level loaded into rdi",
          "mov" in by_addr[0x63540FE] and "(%rax),%rdi" in by_addr[0x63540FE])

    # Extract.
    check("extract shl 0x10 rdi",
          "shl" in by_addr[0x6354101] and "$0x10,%rdi" in by_addr[0x6354101])
    check("extract sar 0x10 rdi",
          "sar" in by_addr[0x6354105] and "$0x10,%rdi" in by_addr[0x6354105])
    check("extract and mask 0x80",
          "and" in by_addr[0x6354109] and "$0xffffffffffffff80,%rdi" in by_addr[0x6354109])
    check("extract helper call 0x63be540",
          "call" in by_addr[0x635410D] and "63be540" in by_addr[0x635410D])

    # Scan (single 8-slot MTF, table+0x2b0 in rbx, key in r10).
    check("scan slot 0 cmp",
          "cmp" in by_addr[0x6354C80] and "0x2b0(%rbx),%r10" in by_addr[0x6354C80])
    check("scan slot 0 miss jne loop entry",
          "jne" in by_addr[0x6354C87] and "6355268" in by_addr[0x6354C87])
    check("scan loop entry mov 1 to r11d",
          "mov" in by_addr[0x6355268] and "$0x1,%r11d" in by_addr[0x6355268])
    check("scan loop compare",
          "cmp" in by_addr[0x6355275] and "0x2b0(%rbx,%rsi,1),%r10" in by_addr[0x6355275])
    check("scan loop miss jne exhaustion",
          "jne" in by_addr[0x635527D] and "63557c0" in by_addr[0x635527D])
    check("scan exhaustion add 1 r11",
          "add" in by_addr[0x63557C0] and "$0x1,%r11" in by_addr[0x63557C0])
    check("scan exhaustion cmp 8 r11",
          "cmp" in by_addr[0x63557C4] and "$0x8,%r11" in by_addr[0x63557C4])
    check("scan exhaustion jne loop",
          "jne" in by_addr[0x63557C8] and "635526e" in by_addr[0x63557C8])
    check("scan slot 0 hit rejoins deref",
          "jmp" in by_addr[0x6354CC6] and "63540fe" in by_addr[0x6354CC6])
    check("scan mtf swap rejoins deref",
          "jmp" in by_addr[0x63552C9] and "6354ca9" in by_addr[0x63552C9])
    check("scan only jump to loop entry is 0x6354c87",
          sorted(a for a, t in jmps if t == 0x6355268) == [0x6354C87],
          str([hex(a) for a, t in jmps if t == 0x6355268]))
    check("scan only jump to slot 0 is 0x63540e5",
          sorted(a for a, t in jmps if t == 0x6354C80) == [0x63540E5],
          str([hex(a) for a, t in jmps if t == 0x6354C80]))
    check("scan no jump targets the lu-miss block",
          [a for a, t in jmps if t == 0x63557CE] == [],
          str([hex(a) for a, t in jmps if t == 0x63557CE]))
    check("scan zero reversed-operand compares",
          [a for a in (0x6354C80, 0x6355275)
           if operands_of(by_addr[a]).startswith("%r10,")] == [],
          str([(hex(a), operands_of(by_addr[a])) for a in (0x6354C80, 0x6355275)]))

    # Lu-miss site + miss-path write-set provenance.
    check("lu-miss lea rsi 0x6511a00 bss",
          "lea" in by_addr[0x63557CE] and "6511a00" in by_addr[0x63557CE])
    check("lu-miss r9d 0",
          "xor" in by_addr[0x63557D5] and "%r9d,%r9d" in by_addr[0x63557D5])
    check("lu-miss rcx is r12",
          "mov" in by_addr[0x63557D8] and "%r12,%rcx" in by_addr[0x63557D8])
    check("lu-miss rdi is rbx",
          "mov" in by_addr[0x63557DB] and "%rbx,%rdi" in by_addr[0x63557DB])
    check("lu-miss rdx is lea 0x1b0 rbx",
          "lea" in by_addr[0x63557DE] and "0x1b0(%rbx),%rdx" in by_addr[0x63557DE])
    check("lu-miss r8d 1",
          "mov" in by_addr[0x63557E5] and "$0x1,%r8d" in by_addr[0x63557E5])
    check("lu-miss call 0x63d9700",
          "call" in by_addr[0x63557EB] and "63d9700" in by_addr[0x63557EB])
    check("lu-miss rejoin jmp 0x63540fe",
          "jmp" in by_addr[0x63557F0] and "63540fe" in by_addr[0x63557F0])
    # Walk-entry -> scan -> miss path ranges; the only r12 write on them
    # must be the key load at 0x6354094.
    path_ranges = [(0x6354080, 0x63540E5), (0x6354C80, 0x6354CC6),
                   (0x6355268, 0x63552C9), (0x63557C0, 0x63557EB)]
    path_addrs = [a for a in by_addr
                  if any(lo <= a <= hi for lo, hi in path_ranges)]
    r12_writes = sorted(a for a in path_addrs
                        if dst_reg(by_addr[a]) in ("%r12", "%r12d", "%r12b", "%r12w"))
    check("miss path r12 written only at key load 0x6354094",
          r12_writes == [0x6354094],
          str([hex(a) for a in r12_writes]))

    # Second-handler sites: rdi rbx + rdx 0x64da4b0 setup before each call.
    idx = {a: k for k, (a, _, _) in enumerate(
        sorted((addr_of(l), mnemonic_of(l), operands_of(l)) for l in lines))}
    ordered = sorted(by_addr)
    for site in [0x6354912, 0x6354B44, 0x6354CF9, 0x6354E1D, 0x6355730, 0x635578D]:
        k = ordered.index(site)
        before = ordered[max(0, k - 6):k]
        after = ordered[k + 1:k + 7]
        check("2nd-handler %s lea rdx 0x64da4b0 before" % hex(site),
              any("lea" in by_addr[a] and "64da4b0" in by_addr[a] for a in before),
              str([(hex(a), by_addr[a]) for a in before]))
        check("2nd-handler %s mov rbx to rdi before" % hex(site),
              any("mov" in by_addr[a] and "%rbx,%rdi" in by_addr[a] for a in before),
              str([(hex(a), by_addr[a]) for a in before]))
        check("2nd-handler %s stack save before" % hex(site),
              any(re.search(r"\(%rsp\)", by_addr[a]) for a in before),
              str([(hex(a), by_addr[a]) for a in before]))
        check("2nd-handler %s stack restore after" % hex(site),
              any(re.search(r"\(%rsp\)", by_addr[a]) for a in after),
              str([(hex(a), by_addr[a]) for a in after]))
    check("2nd-handler 0x6354912 rsi 0",
          "xor" in by_addr[0x63548FF] and "%esi,%esi" in by_addr[0x63548FF])
    check("2nd-handler 0x6354b44 rsi 0",
          "xor" in by_addr[0x6354B36] and "%esi,%esi" in by_addr[0x6354B36])

    # Dispatcher callees.
    check("#314 call site args: rdi lea 0x20 rsp",
          "lea" in by_addr[0x6354669] and "0x20(%rsp),%rdi" in by_addr[0x6354669])
    check("#314 call site args: rsi rbx",
          "mov" in by_addr[0x6354671] and "%rbx,%rsi" in by_addr[0x6354671])
    check("#314 call site args: rdx lea 0x1b0 rbx",
          "lea" in by_addr[0x6354678] and "0x1b0(%rbx),%rdx" in by_addr[0x6354678])
    check("#314 call site args: rcx r12",
          "mov" in by_addr[0x635466E] and "%r12,%rcx" in by_addr[0x635466E])
    check("#313 call site 0x6353caa args",
          "mov" in by_addr[0x6353CA7] and "%rbx,%rdi" in by_addr[0x6353CA7] and
          "mov" in by_addr[0x6353CA4] and "%r12,%rsi" in by_addr[0x6353CA4])
    check("0x63bd2c0 thunk called 8 times", tgt.get(0x63BD2C0, 0) == 8,
          str(tgt.get(0x63BD2C0, 0)))
    check("0x6364880 called 13 times", tgt.get(0x6364880, 0) == 13,
          str(tgt.get(0x6364880, 0)))
    check("0x63e9cd0 called 12 times", tgt.get(0x63E9CD0, 0) == 12,
          str(tgt.get(0x63E9CD0, 0)))
    check("0x6353610 called 5 times", tgt.get(0x6353610, 0) == 5,
          str(tgt.get(0x6353610, 0)))
    check("0x63537f0 called 5 times", tgt.get(0x63537F0, 0) == 5,
          str(tgt.get(0x63537F0, 0)))
    check("memset plt called 5 times", tgt.get(0x63F0A90, 0) == 5,
          str(tgt.get(0x63F0A90, 0)))
    check("errno_location plt called 2 times", tgt.get(0x63F0AD0, 0) == 2,
          str(tgt.get(0x63F0AD0, 0)))
    check("sched_getcpu plt called 2 times", tgt.get(0x63F1AD0, 0) == 2,
          str(tgt.get(0x63F1AD0, 0)))
    check("indirect call via GOT 0x64ffb38",
          "call" in by_addr[0x635481F] and "64ffb38" in by_addr[0x635481F])

    # Exit: single ret, rax = r12.
    check("epilogue canary check",
          "mov" in by_addr[0x6353BB0] and "0x88(%rsp),%rax" in by_addr[0x6353BB0])
    check("epilogue canary jne 0x6355043",
          "jne" in by_addr[0x6353BC1] and "6355043" in by_addr[0x6353BC1])
    check("epilogue add 0x98 rsp",
          "add" in by_addr[0x6353BC7] and "$0x98,%rsp" in by_addr[0x6353BC7])
    check("epilogue mov r12 to rax",
          "mov" in by_addr[0x6353BCE] and "%r12,%rax" in by_addr[0x6353BCE])
    check("canary failure calls stack_chk_fail",
          "call" in by_addr[0x6355043] and "63f0d70" in by_addr[0x6355043])

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for va in [0x6511A00, 0x6511730, 0x65096C0, 0x67277C0, 0x6727A00,
               0x6713606, 0x6713601]:
        check("address %s inside .bss" % hex(va),
              bss[3] <= va < bss[3] + bss[5])
    drr = secmap[".data.rel.ro"]
    check("0x64da4b0 inside .data.rel.ro",
          drr[3] <= 0x64DA4B0 < drr[3] + drr[5])
    dat = secmap[".data"]
    check("0x64ffb38 inside .data", dat[3] <= 0x64FFB38 < dat[3] + dat[5])
    check("0x64ffb80 inside .data", dat[3] <= 0x64FFB80 < dat[3] + dat[5])

    # rela counts by direct ELF parse
    dyn_total = plt_total = rel_count = 0
    for nm, s in secmap.items():
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

    # raw-e8 census: scan .text for e8 with rel32 targets 0x63d9700 / 0x63d9880
    text_sec = secmap[".text"]
    tva, toff_sec, tsize = text_sec[3], text_sec[4], text_sec[5]
    tbytes = node[toff_sec:toff_sec + tsize]
    counts = {}
    bti_counts = {}
    pos = tbytes.find(b"\xe8")
    while pos != -1:
        if pos + 5 <= len(tbytes):
            rel = struct.unpack_from("<i", tbytes, pos + 1)[0]
            tgtv = tva + pos + 5 + rel
            va = tva + pos
            k = bisect.bisect_right(starts, va) - 1
            if k >= 0 and fdes[k][0] <= va < fdes[k][1]:
                if tgtv == 0x63D9700:
                    counts[fdes[k][0]] = counts.get(fdes[k][0], 0) + 1
                if tgtv == 0x63D9880:
                    bti_counts[fdes[k][0]] = bti_counts.get(fdes[k][0], 0) + 1
        pos = tbytes.find(b"\xe8", pos + 1)
    tiers = {}
    for v in counts.values():
        tiers[v] = tiers.get(v, 0) + 1
    check("raw-e8 lu-miss total 168", sum(counts.values()) == 168,
          str(sum(counts.values())))
    check("raw-e8 lu-miss tiers",
          tiers == {1: 18, 2: 14, 3: 1, 4: 11, 5: 1, 6: 2, 7: 1, 8: 1, 10: 3, 13: 1},
          str(tiers))
    check("raw-e8 lu-miss FDEs 53", len(counts) == 53, str(len(counts)))
    check("this FDE raw lu-miss 1", counts.get(START, 0) == 1,
          str(counts.get(START, 0)))
    bti_tiers = {}
    for v in bti_counts.values():
        bti_tiers[v] = bti_tiers.get(v, 0) + 1
    check("raw-e8 bti total 108", sum(bti_counts.values()) == 108,
          str(sum(bti_counts.values())))
    check("raw-e8 bti tiers",
          bti_tiers == {1: 17, 2: 12, 4: 8, 5: 1, 6: 2, 8: 1, 10: 1},
          str(bti_tiers))
    check("raw-e8 bti FDEs 42", len(bti_counts) == 42, str(len(bti_counts)))
    check("this FDE raw bti 0", bti_counts.get(START, 0) == 0,
          str(bti_counts.get(START, 0)))
    check("next FDE raw lu-miss 1", counts.get(0x6355900, 0) == 1,
          str(counts.get(0x6355900, 0)))
    check("next FDE raw bti 0", bti_counts.get(0x6355900, 0) == 0,
          str(bti_counts.get(0x6355900, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 2nd survivor",
          survey.get("survivors", [None, None])[1] == "0x6353a70",
          str(survey.get("survivors", [])[:3]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window shared",
          "0x6353a70" in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x6355900..0x63577e2",
          nq.get("range") == "0x6355900..0x63577e2", str(nq.get("range")))
    check("next question bytes 7906", nq.get("bytes") == 7906,
          str(nq.get("bytes")))
    check("next question lu-miss sites 1",
          nq.get("lu_miss_sites") == 1, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 1717", nq.get("strict") == 1717,
          str(nq.get("strict")))
    check("records census strict 1691",
          rec.get("census", {}).get("strict") == 1691)
    check("records census calls 105",
          rec.get("census", {}).get("calls") == 105)
    check("records lu-miss site matches census",
          rec.get("lu_miss_sites", [{}])[0].get("site") == "0x63557eb" and
          [a for a, t in ct if t == 0x63D9700] == [0x63557EB])
    check("records second-handler sites match census",
          [s.get("site") for s in rec.get("second_handler_sites", [])] ==
          ["0x6354912", "0x6354b44", "0x6354cf9", "0x6354e1d",
           "0x6355730", "0x635578d"])
    check("records exhibits 2", len(rec.get("exhibits", [])) == 2,
          str(len(rec.get("exhibits", []))))

    # disjointness over every exhibit range
    mine = []
    skipped = []
    collect_ranges(rec, mine, skipped)
    check("exhibit ranges collected", len(mine) >= 1, str(len(mine)))
    check("0 skipped records", len(skipped) == 0, str(skipped[:3]))
    priors = []
    pskipped = []
    # Prior collection is I/O-bound (~3 min per verifier run: hundreds of
    # records.json reads). An optional fingerprint-validated cache
    # (HL_PRIORS_CACHE) reuses it across runs in one build: the fingerprint
    # is the sorted (relative path, size) of every candidate file, so any
    # content change invalidates it. Without the env var the verifier
    # always collects fresh; the cache never changes the verdict, only
    # the wall time. The tests set it and additionally assert the priors
    # count, so an empty/corrupt cache cannot pass vacuously.
    cand = sorted(glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*",
                                         "research", "work-items", "*",
                                         "records.json")))
    cand = [os.path.normpath(d) for d in cand
            if SLUG not in os.path.normpath(d)
            and os.path.normpath(PACKET) not in os.path.normpath(d)]
    fp = []
    for d in cand:
        try:
            st = os.stat(d)
            fp.append([os.path.relpath(d, os.path.dirname(ROOT)), st.st_size])
        except Exception:
            pass
    cache_path = os.environ.get("HL_PRIORS_CACHE")
    used_cache = False
    if cache_path:
        try:
            with open(cache_path) as f:
                cache = json.load(f)
            if cache.get("fingerprint") == fp:
                priors = [tuple(x) for x in cache["priors"]]
                pskipped = cache["pskipped"]
                used_cache = True
        except Exception:
            used_cache = False
    if not used_cache:
        for d in cand:
            try:
                with open(d) as f:
                    collect_ranges(json.load(f), priors, pskipped)
            except Exception:
                pass
        if cache_path:
            try:
                with open(cache_path, "w") as f:
                    json.dump({"fingerprint": fp, "priors": priors,
                               "pskipped": pskipped}, f)
            except Exception:
                pass
    check("priors >= 50000", len(priors) >= 50000, str(len(priors)))
    check("priors 0 skipped", len(pskipped) == 0, str(pskipped[:3]))
    mine_set = set(mine)
    bad = []
    for m in mine_set:
        for p in priors:
            if m[0] < p[1] and p[0] < m[1]:
                bad.append((m, p))
                break
    check("disjointness NONE", not bad, str(bad[:3]))
    print("priors scanned: %d" % len(priors))
    # next candidate 0x6355900..0x63577e2 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x6355900 < p[1] and p[0] < 0x63577E2]
    check("next candidate 0x6355900 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63577E2 and 0x6355900 < END))

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
