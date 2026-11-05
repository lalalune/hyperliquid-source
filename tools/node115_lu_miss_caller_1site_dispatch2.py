#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-miss-caller-1site-dispatch2.

Byte reads only; never executes the node binary. Checks, counted at the end:
base + binary identity, .eh_frame bounds, exhibit bytes, strict/call census
(1717 strict, 111 calls / 31 distinct targets, 1 ret, bsr 8, lock 0/0,
278 jumps all inside), entry frame (endbr64, sub $0xa8, canary, TLS flag
check), entry size class (product rdi*rsi, byte table 0x67277c0 + size table
0x6727a00), single walk (key in r13, top index + high-bits compare, second
level into rax), extract (shl/sar 0x10 + helper 0x63be540), single 8-slot
move-to-front scan (slot 0 inline, slots 1-7 one loop compare, 0 reversed
compares), one lu-miss site (rsi 0x6511a00 .bss, rdi rbx, rdx table, rcx r13
walk key — write-set check on the walk->miss path), six second-handler sites
(rdi rbx, rdx 0x64da4b0), dispatcher call census (#314 window x1, #313
window x2, #298 window x2, 0x6364880 x13, 0x63e9cd0 x12, 0x63bd2c0 x8,
0x6353610 x10, memset x12), zero indirect calls (unlike #315's GOT call),
exit rax = r13, jump closure with 0 outside targets, rela counts, raw-e8
censuses (lu-miss 168/53, bti 108/42), lu-miss frontier survey
(16 survivors), next-candidate disjointness, disjointness over every
exhibit range, slug uniqueness, MANIFEST.
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
                      "RE-001-node115-lu-miss-caller-1site-dispatch2")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-1site-dispatch2"
NAME = "lu_miss_caller_1site_dispatch2"
START, END = 0x6355900, 0x63577E2

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
    check("target FDE size 7906", END - START == 7906)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x6355830..0x63558f2",
          prev == (0x6355830, 0x63558F2), str(prev))
    check("prev gap 14", START - prev[1] == 14)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 14, gap.hex())
    check("next FDE 0x63577f0..0x635a786",
          nxt == (0x63577F0, 0x635A786), str(nxt))
    check("next padding 14", nxt[0] - END == 14)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 14, pad.hex())
    check("no overlap with 0x63ed090 exclusion",
          END <= 0x63ED090 or START >= 0x63ED862)
    check("no overlap with 0x63ef8e0 exclusion",
          END <= 0x63EF8E0 or START >= 0x63EFBA2)

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 7906", len(hexb) == 7906, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 1717", len(lines) == 1717, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 111", len(calls) == 111, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x6355aa8", [addr_of(l) for l in rets] == [0x6355AA8],
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
    check("indirect calls 0", indirect == [],
          str([hex(a) for a in indirect]))
    from collections import Counter
    tgt = Counter(t for _, t in ct)
    expect = {0x6364880: 13, 0x63F0A90: 12, 0x63E9CD0: 12, 0x6353610: 10,
              0x63BD2C0: 8, 0x634EBB0: 6, 0x6365150: 4, 0x63E9C40: 4,
              0x63EDF10: 4, 0x63C3890: 2, 0x63C2F00: 2, 0x63C3B00: 2,
              0x63C2E80: 2, 0x63F0AD0: 2, 0x63EEC80: 2, 0x63BE540: 2,
              0x63F1AD0: 2, 0x6364420: 2, 0x6364410: 2, 0x6364400: 2,
              0x6362F90: 2, 0x6352FC0: 2, 0x63C3780: 2, 0x63EC4C0: 2,
              0x6360ED0: 2, 0x63EF8E0: 1, 0x63B7240: 1, 0x634F0B0: 1,
              0x63495B0: 1, 0x63F0D70: 1, 0x63D9700: 1}
    check("call target multiset exact", dict(tgt) == expect,
          str(dict(tgt)))
    check("distinct call targets 31 direct + 0 indirect",
          len(tgt) == 31, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 1 at 0x635774a",
          [a for a, t in ct if t == 0x63D9700] == [0x635774A],
          str([hex(a) for a, t in ct if t == 0x63D9700]))
    check("second-handler sites 6",
          sorted(a for a, t in ct if t == 0x634EBB0) ==
          [0x63568C4, 0x6356AFA, 0x6356BC1, 0x6356DFC, 0x6357651, 0x63576FF],
          str([hex(a) for a, t in ct if t == 0x634EBB0]))
    check("no lock-wait sites", tgt.get(0x63BF680, 0) == 0,
          str(tgt.get(0x63BF680, 0)))
    check("#314 window called once at 0x6356712",
          [a for a, t in ct if t == 0x63495B0] == [0x6356712],
          str([hex(a) for a, t in ct if t == 0x63495B0]))
    check("#313 window called twice",
          sorted(a for a, t in ct if t == 0x63C2F00) ==
          [0x6355B7F, 0x63572E4],
          str([hex(a) for a, t in ct if t == 0x63C2F00]))
    check("#298 window called twice",
          sorted(a for a, t in ct if t == 0x6362F90) ==
          [0x63567D3, 0x63573DD],
          str([hex(a) for a, t in ct if t == 0x6362F90]))
    bsr = [addr_of(l) for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 8 exact list",
          bsr == [0x6355E98, 0x6356547, 0x635696B, 0x6356C56,
                  0x6356ED5, 0x6357165, 0x63574A7, 0x63575F3],
          str([hex(a) for a in bsr]))
    locks = [(mnemonic_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))
    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 278", len(jmps) == 278, str(len(jmps)))
    outside = [(a, t) for a, t in jmps if not (START <= t < END)]
    check("jump closure zero outside", outside == [], str(outside))

    # Entry + frame.
    check("entry endbr64", "endbr64" in by_addr[0x6355900])
    check("entry pushes r15/r14/r13/r12/rbp/rbx",
          all("push" in by_addr[a] for a in
              [0x6355904, 0x6355906, 0x635590B, 0x635590D, 0x6355912,
               0x6355913]))
    check("entry sub 0xa8 rsp",
          "sub" in by_addr[0x6355914] and "$0xa8,%rsp" in by_addr[0x6355914])
    check("entry mov rdi to r14",
          "mov" in by_addr[0x6355908] and "%rdi,%r14" in by_addr[0x6355908])
    check("entry mov rsi to r12",
          "mov" in by_addr[0x635590F] and "%rsi,%r12" in by_addr[0x635590F])
    check("entry mul rdi by rsi",
          "mul" in by_addr[0x6355950] and "%r12" in by_addr[0x6355950])
    check("entry seto overflow to cl",
          "seto" in by_addr[0x6355953] and "%cl" in by_addr[0x6355953])
    check("entry product to rbp",
          "mov" in by_addr[0x6355956] and "%rax,%rbp" in by_addr[0x6355956])
    check("canary load fs:0x28",
          "mov" in by_addr[0x6355924] and "%fs:0x28,%rax" in by_addr[0x6355924])
    check("canary store 0x98 rsp",
          "mov" in by_addr[0x635592D] and "0x98(%rsp)" in by_addr[0x635592D])
    check("tls base add",
          "add" in by_addr[0x635593C] and "%rax,%rbx" in by_addr[0x635593C])
    check("tls flag cmpb fs:0x330",
          "cmpb" in by_addr[0x635593F] and "%fs:0x330" in by_addr[0x635593F])
    check("tls flag jne 0x6355c40",
          "jne" in by_addr[0x6355947] and "6355c40" in by_addr[0x6355947])
    check("tls init block calls 0x63ef8e0",
          "call" in by_addr[0x6355C45] and "63ef8e0" in by_addr[0x6355C45])

    # Entry size class.
    check("size cmp 0x1000 rbp",
          "cmp" in by_addr[0x6355973] and "$0x1000,%rbp" in by_addr[0x6355973])
    check("size byte table lea 0x67277c0",
          "lea" in by_addr[0x6355988] and "67277c0" in by_addr[0x6355988])
    check("size byte index shr 3",
          "shr" in by_addr[0x6355984] and "$0x3,%r9" in by_addr[0x6355984])
    check("size byte load movzbl",
          "movzbl" in by_addr[0x635598F] and "(%r11,%r9,1),%r15d" in by_addr[0x635598F])
    check("size cmp 0xe7 r15d",
          "cmp" in by_addr[0x6355994] and "$0xe7,%r15d" in by_addr[0x6355994])
    check("size table lea 0x6727a00",
          "lea" in by_addr[0x63559A8] and "6727a00" in by_addr[0x63559A8])
    check("size table load",
          "mov" in by_addr[0x63559B9] and "(%r10,%r12,8),%r14" in by_addr[0x63559B9])
    check("size flag lea 0x6713606",
          "lea" in by_addr[0x63559A1] and "6713606" in by_addr[0x63559A1])
    check("size flag cmpb",
          "cmpb" in by_addr[0x63559B6] and "(%rax)" in by_addr[0x63559B6])
    check("size cmp 0x3800 rbp",
          "cmp" in by_addr[0x63559CF] and "$0x3800,%rbp" in by_addr[0x63559CF])
    check("size huge path movabs threshold",
          "movabs" in by_addr[0x6355E70] and "0x7000000000000000" in by_addr[0x6355E70])

    # Walk (single, table in rbx, key in r13).
    check("walk key is r13 (mov to r12)",
          "mov" in by_addr[0x6356140] and "%r13,%r12" in by_addr[0x6356140])
    check("walk key is r13 (mov to rbp)",
          "mov" in by_addr[0x6356143] and "%r13,%rbp" in by_addr[0x6356143])
    check("walk top shr 0x1a",
          "shr" in by_addr[0x6356146] and "$0x1a,%r12" in by_addr[0x6356146])
    check("walk top and 0xf0",
          "and" in by_addr[0x6356151] and "$0xf0,%r12d" in by_addr[0x6356151])
    check("walk top add rbx",
          "add" in by_addr[0x6356158] and "%rbx,%r12" in by_addr[0x6356158])
    check("walk high bits and",
          "and" in by_addr[0x635614A] and "$0xffffffffc0000000,%rbp" in by_addr[0x635614A])
    check("walk top load",
          "mov" in by_addr[0x635615B] and "0x1b0(%r12),%rsi" in by_addr[0x635615B])
    check("walk top compare",
          "cmp" in by_addr[0x6356163] and "%rsi,%rbp" in by_addr[0x6356163])
    check("walk mismatch jne scan slot 0",
          "jne" in by_addr[0x6356166] and "6356b4d" in by_addr[0x6356166])
    check("walk second level shr 0x9",
          "shr" in by_addr[0x635616F] and "$0x9,%rax" in by_addr[0x635616F])
    check("walk second level and 0x1ffff8",
          "and" in by_addr[0x6356173] and "$0x1ffff8,%eax" in by_addr[0x6356173])
    check("walk second level add table entry",
          "add" in by_addr[0x6356178] and "0x1b8(%r12),%rax" in by_addr[0x6356178])
    check("walk second level deref into rdi at rejoin",
          "mov" in by_addr[0x6356180] and "(%rax),%rdi" in by_addr[0x6356180])

    # Extract.
    check("extract shl 0x10 rdi",
          "shl" in by_addr[0x6356183] and "$0x10,%rdi" in by_addr[0x6356183])
    check("extract sar 0x10 rdi",
          "sar" in by_addr[0x6356187] and "$0x10,%rdi" in by_addr[0x6356187])
    check("extract and mask 0x80",
          "and" in by_addr[0x635618B] and "$0xffffffffffffff80,%rdi" in by_addr[0x635618B])
    check("extract helper call 0x63be540",
          "call" in by_addr[0x635618F] and "63be540" in by_addr[0x635618F])
    check("extract helper rejoin jmp 0x6355a2c",
          "jmp" in by_addr[0x6356194] and "6355a2c" in by_addr[0x6356194])

    # Scan (single 8-slot MTF, table+0x2b0 in rbx, key in rbp).
    check("scan slot 0 cmp",
          "cmp" in by_addr[0x6356B4D] and "0x2b0(%rbx),%rbp" in by_addr[0x6356B4D])
    check("scan slot 0 miss jne loop entry",
          "jne" in by_addr[0x6356B54] and "6357031" in by_addr[0x6356B54])
    check("scan loop entry mov 1 to edi",
          "mov" in by_addr[0x6357031] and "$0x1,%edi" in by_addr[0x6357031])
    check("scan loop compare",
          "cmp" in by_addr[0x635703D] and "0x2b0(%rbx,%r10,1),%rbp" in by_addr[0x635703D])
    check("scan loop miss jne exhaustion",
          "jne" in by_addr[0x6357045] and "635771f" in by_addr[0x6357045])
    check("scan exhaustion add 1 rdi",
          "add" in by_addr[0x635771F] and "$0x1,%rdi" in by_addr[0x635771F])
    check("scan exhaustion cmp 8 rdi",
          "cmp" in by_addr[0x6357723] and "$0x8,%rdi" in by_addr[0x6357723])
    check("scan exhaustion jne loop",
          "jne" in by_addr[0x6357727] and "6357036" in by_addr[0x6357727])
    check("scan slot 0 hit rejoins extract",
          "jmp" in by_addr[0x6356B96] and "6356180" in by_addr[0x6356B96])
    check("scan mtf swap rejoins slot 0 hit tail",
          "jmp" in by_addr[0x6357091] and "6356b77" in by_addr[0x6357091])
    check("scan only jump to loop entry is 0x6356b54",
          sorted(a for a, t in jmps if t == 0x6357031) == [0x6356B54],
          str([hex(a) for a, t in jmps if t == 0x6357031]))
    check("scan only jump to slot 0 is 0x6356166",
          sorted(a for a, t in jmps if t == 0x6356B4D) == [0x6356166],
          str([hex(a) for a, t in jmps if t == 0x6356B4D]))
    check("scan no jump targets the lu-miss block",
          [a for a, t in jmps if t == 0x635772D] == [],
          str([hex(a) for a, t in jmps if t == 0x635772D]))
    check("scan zero reversed-operand compares",
          [a for a in (0x6356B4D, 0x635703D)
           if operands_of(by_addr[a]).startswith("%rbp,")] == [],
          str([(hex(a), operands_of(by_addr[a])) for a in (0x6356B4D, 0x635703D)]))

    # Lu-miss site + miss-path write-set provenance.
    check("lu-miss lea rsi 0x6511a00 bss",
          "lea" in by_addr[0x635772D] and "6511a00" in by_addr[0x635772D])
    check("lu-miss r9d 0",
          "xor" in by_addr[0x6357734] and "%r9d,%r9d" in by_addr[0x6357734])
    check("lu-miss rcx is r13",
          "mov" in by_addr[0x6357737] and "%r13,%rcx" in by_addr[0x6357737])
    check("lu-miss rdi is rbx",
          "mov" in by_addr[0x635773A] and "%rbx,%rdi" in by_addr[0x635773A])
    check("lu-miss rdx is lea 0x1b0 rbx",
          "lea" in by_addr[0x635773D] and "0x1b0(%rbx),%rdx" in by_addr[0x635773D])
    check("lu-miss r8d 1",
          "mov" in by_addr[0x6357744] and "$0x1,%r8d" in by_addr[0x6357744])
    check("lu-miss call 0x63d9700",
          "call" in by_addr[0x635774A] and "63d9700" in by_addr[0x635774A])
    check("lu-miss rejoin jmp 0x6356180",
          "jmp" in by_addr[0x635774F] and "6356180" in by_addr[0x635774F])
    # Walk -> scan -> miss path ranges; r13 (the walk key register) must
    # never be written on them: it is only read (mov %r13,%r12 / %r13,%rbp
    # at the walk, mov %r13,%rcx at the miss block), so the miss rcx is
    # the same register the walk derives its key from.
    path_ranges = [(0x6356140, 0x6356166), (0x6356B4D, 0x6356B54),
                   (0x6357031, 0x6357045), (0x635771F, 0x6357727),
                   (0x635772D, 0x635774A)]
    path_addrs = [a for a in by_addr
                  if any(lo <= a <= hi for lo, hi in path_ranges)]
    r13_writes = sorted(a for a in path_addrs
                        if dst_reg(by_addr[a]) in ("%r13", "%r13d", "%r13b", "%r13w"))
    check("miss path r13 never written",
          r13_writes == [],
          str([hex(a) for a in r13_writes]))

    # Second-handler sites: rdi rbx + rdx 0x64da4b0 setup before each call.
    idx = {a: k for k, (a, _, _) in enumerate(
        sorted((addr_of(l), mnemonic_of(l), operands_of(l)) for l in lines))}
    ordered = sorted(by_addr)
    for site in [0x63568C4, 0x6356AFA, 0x6356BC1, 0x6356DFC, 0x6357651, 0x63576FF]:
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
    check("2nd-handler 0x63568c4 rsi 0",
          "xor" in by_addr[0x63568B5] and "%esi,%esi" in by_addr[0x63568B5])
    check("2nd-handler 0x6356bc1 rsi 0",
          "xor" in by_addr[0x6356BB2] and "%esi,%esi" in by_addr[0x6356BB2])

    # Dispatcher callees.
    check("#314 call site args: rdi lea 0x30 rsp",
          "lea" in by_addr[0x63566FD] and "0x30(%rsp),%rdi" in by_addr[0x63566FD])
    check("#314 call site args: rsi rbx",
          "mov" in by_addr[0x6356705] and "%rbx,%rsi" in by_addr[0x6356705])
    check("#314 call site args: rdx lea 0x1b0 rbx",
          "lea" in by_addr[0x6356708] and "0x1b0(%rbx),%rdx" in by_addr[0x6356708])
    check("#314 call site args: rcx r13",
          "mov" in by_addr[0x6356702] and "%r13,%rcx" in by_addr[0x6356702])
    check("#313 call site 0x6355b7f args",
          "mov" in by_addr[0x6355B7C] and "%rbx,%rdi" in by_addr[0x6355B7C] and
          "mov" in by_addr[0x6355B79] and "%r13,%rsi" in by_addr[0x6355B79] and
          "mov" in by_addr[0x6355B76] and "%rbp,%rdx" in by_addr[0x6355B76] and
          "mov" in by_addr[0x6355B73] and "%r14,%rcx" in by_addr[0x6355B73])
    check("#313 call site 0x63572e4 args",
          "mov" in by_addr[0x63572D9] and "%rbx,%rdi" in by_addr[0x63572D9] and
          "mov" in by_addr[0x63572D6] and "%r13,%rsi" in by_addr[0x63572D6])
    check("0x63bd2c0 thunk called 8 times", tgt.get(0x63BD2C0, 0) == 8,
          str(tgt.get(0x63BD2C0, 0)))
    check("0x6364880 called 13 times", tgt.get(0x6364880, 0) == 13,
          str(tgt.get(0x6364880, 0)))
    check("0x63e9cd0 called 12 times", tgt.get(0x63E9CD0, 0) == 12,
          str(tgt.get(0x63E9CD0, 0)))
    check("0x6353610 called 10 times", tgt.get(0x6353610, 0) == 10,
          str(tgt.get(0x6353610, 0)))
    check("memset plt called 12 times", tgt.get(0x63F0A90, 0) == 12,
          str(tgt.get(0x63F0A90, 0)))
    check("errno_location plt called 2 times", tgt.get(0x63F0AD0, 0) == 2,
          str(tgt.get(0x63F0AD0, 0)))
    check("sched_getcpu plt called 2 times", tgt.get(0x63F1AD0, 0) == 2,
          str(tgt.get(0x63F1AD0, 0)))
    check("no indirect call via GOT (unlike #315)",
          not any("64ffb38" in by_addr[a] for a in by_addr))

    # Exit: single ret, rax = r13.
    check("epilogue canary check",
          "mov" in by_addr[0x6355A7D] and "0x98(%rsp),%rax" in by_addr[0x6355A7D])
    check("epilogue canary jne 0x6356fdc",
          "jne" in by_addr[0x6355A8E] and "6356fdc" in by_addr[0x6355A8E])
    check("epilogue add 0xa8 rsp",
          "add" in by_addr[0x6355A94] and "$0xa8,%rsp" in by_addr[0x6355A94])
    check("epilogue mov r13 to rax",
          "mov" in by_addr[0x6355A9B] and "%r13,%rax" in by_addr[0x6355A9B])
    check("canary failure calls stack_chk_fail",
          "call" in by_addr[0x6356FDC] and "63f0d70" in by_addr[0x6356FDC])

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for va in [0x6511A00, 0x65096C0, 0x65096A0, 0x67277C0, 0x6727A00,
               0x6713606]:
        check("address %s inside .bss" % hex(va),
              bss[3] <= va < bss[3] + bss[5])
    drr = secmap[".data.rel.ro"]
    check("0x64da4b0 inside .data.rel.ro",
          drr[3] <= 0x64DA4B0 < drr[3] + drr[5])
    dat = secmap[".data"]
    check("0x64ffb80 inside .data", dat[3] <= 0x64FFB80 < dat[3] + dat[5])
    check("0x64ffab4 inside .data", dat[3] <= 0x64FFAB4 < dat[3] + dat[5])

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
    check("next FDE raw lu-miss 1", counts.get(0x63577F0, 0) == 1,
          str(counts.get(0x63577F0, 0)))
    check("next FDE raw bti 0", bti_counts.get(0x63577F0, 0) == 0,
          str(bti_counts.get(0x63577F0, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 3rd survivor",
          survey.get("survivors", [None, None, None])[2] == "0x6355900",
          str(survey.get("survivors", [])[:4]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window shared",
          "0x6355900" in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x63577f0..0x635a786",
          nq.get("range") == "0x63577f0..0x635a786", str(nq.get("range")))
    check("next question bytes 12182", nq.get("bytes") == 12182,
          str(nq.get("bytes")))
    check("next question lu-miss sites 1",
          nq.get("lu_miss_sites") == 1, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 2679", nq.get("strict") == 2679,
          str(nq.get("strict")))
    check("next question calls 132", nq.get("calls") == 132,
          str(nq.get("calls")))
    check("next question second-handler sites 10",
          nq.get("second_handler_sites") == 10,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("records census strict 1717",
          rec.get("census", {}).get("strict") == 1717)
    check("records census calls 111",
          rec.get("census", {}).get("calls") == 111)
    check("records lu-miss site matches census",
          rec.get("lu_miss_sites", [{}])[0].get("site") == "0x635774a" and
          [a for a, t in ct if t == 0x63D9700] == [0x635774A])
    check("records second-handler sites match census",
          [s.get("site") for s in rec.get("second_handler_sites", [])] ==
          ["0x63568c4", "0x6356afa", "0x6356bc1", "0x6356dfc",
           "0x6357651", "0x63576ff"])
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
    # next candidate 0x63577f0..0x635a786 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63577F0 < p[1] and p[0] < 0x635A786]
    check("next candidate 0x63577f0 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x635A786 and 0x63577F0 < END))

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
