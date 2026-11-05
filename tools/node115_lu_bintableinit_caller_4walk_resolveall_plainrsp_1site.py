#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall-plainrsp.

Byte reads only; never executes the node binary. Checks, counted at the end:
base + binary identity, .eh_frame bounds, exhibit bytes, strict/call census,
site-block shape (plain %rsp via rbx, rsi in callee-saved r14, table base in
rbx, result slots in rbp), four-walk resolve-all (walks 1-4 store resolved
second-level pointers to 0x0/0x8/0x10/0x18 rbp; NO null tests, all four walks
always run; eax is 0 at ret via the canary load-and-subtract), four 8-slot
scans (reversed-operand compares tracked: scan A none, scan B none, scan C
slots 3/4, scan D slot 6), four lu-miss sites (rsi entry r14 on all;
r8d=1/r9d=0 here, reversed from #309; rcx provenance per site), canary,
jump closure, rel32 targets, rela counts, raw-e8 tiers, disjointness over
every exhibit range, slug uniqueness, MANIFEST.
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
                      "RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall-plainrsp")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall-plainrsp"
NAME = "bintableinit_caller_4walk_resolveall_plainrsp_1site"
START, END = 0x63AFC60, 0x63B0324

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
    check("target FDE size 1732", END - START == 1732)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x63afbb0..0x63afc54",
          prev == (0x63AFBB0, 0x63AFC54), str(prev))
    check("prev gap 12", START - prev[1] == 12)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 12, gap.hex())
    check("next FDE 0x63b0330..0x63b03b2",
          nxt == (0x63B0330, 0x63B03B2), str(nxt))
    check("next padding 12", nxt[0] - END == 12)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 12, pad.hex())
    check("no overlap with 0x63adf40 exclusion",
          END <= 0x63ADF40 or START >= 0x63AE252)
    check("no overlap with 0x63ed090 exclusion",
          END <= 0x63ED090 or START >= 0x63ED862)
    check("no overlap with 0x63ef8e0 exclusion",
          END <= 0x63EF8E0 or START >= 0x63EFBA2)

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 1732", len(hexb) == 1732, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 342", len(lines) == 342, str(len(lines)))
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 6", len(calls) == 6, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63afe10", [addr_of(l) for l in rets] == [0x63AFE10],
          str([addr_of(l) for l in rets]))

    def call_targets(lines):
        out = []
        for l in lines:
            m = re.search(r"\tcall\s+([0-9a-f]+)", l)
            if m:
                out.append((addr_of(l), int(m.group(1), 16)))
        return out

    ct = call_targets(calls)
    check("call rel32 targets",
          ct == [(0x63AFE1E, 0x63D9880), (0x63B0162, 0x63D9700),
                 (0x63B01F2, 0x63D9700), (0x63B0282, 0x63D9700),
                 (0x63B0315, 0x63D9700), (0x63B031F, 0x63F0D70)],
          str(ct))
    bti = [a for a, t in ct if t == 0x63D9880]
    check("bti sites", bti == [0x63AFE1E], str(bti))
    miss = [a for a, t in ct if t == 0x63D9700]
    check("lu-miss sites",
          miss == [0x63B0162, 0x63B01F2, 0x63B0282, 0x63B0315], str(miss))
    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str(len(bsr)))
    locks = [(mnemonic_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))

    by_addr = {addr_of(l): l for l in lines}
    check("entry rcx to r15",
          "mov" in by_addr[0x63AFC66] and "%rcx,%r15" in by_addr[0x63AFC66])
    check("entry rsi to r14",
          "mov" in by_addr[0x63AFC6B] and "%rsi,%r14" in by_addr[0x63AFC6B])
    check("entry rdi to r13",
          "mov" in by_addr[0x63AFC70] and "%rdi,%r13" in by_addr[0x63AFC70])
    check("entry r8 to r12",
          "mov" in by_addr[0x63AFC75] and "%r8,%r12" in by_addr[0x63AFC75])
    check("entry rdx to rbp",
          "mov" in by_addr[0x63AFC79] and "%rdx,%rbp" in by_addr[0x63AFC79])
    check("walk table lea 0x1b0 rdi to rbx",
          "lea" in by_addr[0x63AFC7D] and "0x1b0(%rdi),%rbx" in by_addr[0x63AFC7D])
    check("frame sub 0x198 rsp",
          "sub" in by_addr[0x63AFC84] and "$0x198,%rsp" in by_addr[0x63AFC84])
    check("canary at 0x188 rsp",
          "0x188(%rsp)" in by_addr[0x63AFC94])
    check("entry eax zeroed",
          "xor" in by_addr[0x63AFC9C] and "%eax,%eax" in by_addr[0x63AFC9C])
    check("null-context test rdi",
          "test" in by_addr[0x63AFC9E] and "%rdi,%rdi" in by_addr[0x63AFC9E])
    check("null-context je to site block",
          "je" in by_addr[0x63AFCA1] and "63afe18" in by_addr[0x63AFCA1])
    check("site block mov rsp to rbx plain rsp",
          "mov" in by_addr[0x63AFE18] and "%rsp,%rbx" in by_addr[0x63AFE18])
    check("site block mov rbx to rdi",
          "mov" in by_addr[0x63AFE1B] and "%rbx,%rdi" in by_addr[0x63AFE1B])
    check("site rejoin jmp 0x63afca7",
          "jmp" in by_addr[0x63AFE23] and "63afca7" in by_addr[0x63AFE23])
    check("site block preceded by nopl",
          "nopl" in by_addr[0x63AFE11])
    check("rsi lives in r14: mov to r14 only entry + scan D hits",
          [addr_of(l) for l in lines
           if mnemonic_of(l) == "mov" and operands_of(l).endswith("%r14")] ==
          [0x63AFC6B, 0x63AFF18, 0x63AFFD7],
          str([hex(addr_of(l)) for l in lines
               if mnemonic_of(l) == "mov" and operands_of(l).endswith("%r14")]))

    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 55", len(jmps) == 55, str(len(jmps)))
    outside = [(a, t) for a, t in jmps
               if not (START <= t < END)]
    check("jump closure none outside window",
          outside == [], str(outside))
    tg = [a for a, t in jmps if t == 0x63AFE18]
    check("block 0x63afe18 single je entry", tg == [0x63AFCA1], str(tg))

    check("canary check mov 0x188 rsp to rax",
          "mov" in by_addr[0x63AFDE8] and "0x188(%rsp),%rax" in by_addr[0x63AFDE8])
    check("canary check sub fs",
          "sub" in by_addr[0x63AFDF0] and "%fs:0x28" in by_addr[0x63AFDF0])
    check("canary fail jne to stack_chk_fail",
          "jne" in by_addr[0x63AFDF9] and "63b031f" in by_addr[0x63AFDF9])

    check("walk1 key load 0x8 r15",
          "mov" in by_addr[0x63AFCA7] and "0x8(%r15),%rax" in by_addr[0x63AFCA7])
    check("walk1 page mov rax to rcx",
          "mov" in by_addr[0x63AFCAB] and "%rax,%rcx" in by_addr[0x63AFCAB])
    check("walk1 top mov rax to rdi",
          "mov" in by_addr[0x63AFCAE] and "%rax,%rdi" in by_addr[0x63AFCAE])
    check("walk1 top shr 0x1a",
          "shr" in by_addr[0x63AFCB1] and "$0x1a,%rax" in by_addr[0x63AFCB1])
    check("walk1 top and 0xf0",
          "and" in by_addr[0x63AFCB5] and "$0xf0,%eax" in by_addr[0x63AFCB5])
    check("walk1 high bits and",
          "and" in by_addr[0x63AFCBA] and "$0xffffffffc0000000,%rdi" in by_addr[0x63AFCBA])
    check("walk1 page and",
          "and" in by_addr[0x63AFCC1] and "$0xfffffffffffff000,%rcx" in by_addr[0x63AFCC1])
    check("walk1 add table rbx",
          "add" in by_addr[0x63AFCC8] and "%rbx,%rax" in by_addr[0x63AFCC8])
    check("walk1 top load",
          "mov" in by_addr[0x63AFCCB] and "(%rax),%rsi" in by_addr[0x63AFCCB])
    check("walk1 top compare",
          "cmp" in by_addr[0x63AFCCE] and "%rsi,%rdi" in by_addr[0x63AFCCE])
    check("walk1 mismatch jne scan A",
          "jne" in by_addr[0x63AFCD1] and "63afe30" in by_addr[0x63AFCD1])
    check("walk1 second level shr 0x9",
          "shr" in by_addr[0x63AFCD7] and "$0x9,%rcx" in by_addr[0x63AFCD7])
    check("walk1 second level and 0x1ffff8",
          "and" in by_addr[0x63AFCDB] and "$0x1ffff8,%ecx" in by_addr[0x63AFCDB])
    check("walk1 second level add table entry",
          "add" in by_addr[0x63AFCE1] and "0x8(%rax),%rcx" in by_addr[0x63AFCE1])
    check("walk1 second level mov rcx to rax",
          "mov" in by_addr[0x63AFCE5] and "%rcx,%rax" in by_addr[0x63AFCE5])
    check("walk1 store to 0x0 rbp",
          "mov" in by_addr[0x63AFCE8] and "%rax,0x0(%rbp)" in by_addr[0x63AFCE8])

    check("walk2 key load 0x10 r15",
          "mov" in by_addr[0x63AFCEC] and "0x10(%r15),%rdi" in by_addr[0x63AFCEC])
    check("walk2 key load 0x8 r15",
          "mov" in by_addr[0x63AFCF0] and "0x8(%r15),%r15" in by_addr[0x63AFCF0])
    check("walk2 key page and rdi",
          "and" in by_addr[0x63AFCF4] and "$0xfffffffffffff000,%rdi" in by_addr[0x63AFCF4])
    check("walk2 page and",
          "and" in by_addr[0x63AFCFB] and "$0xfffffffffffff000,%r15" in by_addr[0x63AFCFB])
    check("walk2 derived key lea -0x1000",
          "lea" in by_addr[0x63AFD02] and "-0x1000(%rdi,%r15,1),%r11" in by_addr[0x63AFD02])
    check("walk2 top mov r11 to rax",
          "mov" in by_addr[0x63AFD0A] and "%r11,%rax" in by_addr[0x63AFD0A])
    check("walk2 top mov r11 to rcx",
          "mov" in by_addr[0x63AFD0D] and "%r11,%rcx" in by_addr[0x63AFD0D])
    check("walk2 top shr 0x1a",
          "shr" in by_addr[0x63AFD10] and "$0x1a,%rax" in by_addr[0x63AFD10])
    check("walk2 high bits and",
          "and" in by_addr[0x63AFD14] and "$0xffffffffc0000000,%rcx" in by_addr[0x63AFD14])
    check("walk2 top and 0xf0",
          "and" in by_addr[0x63AFD1B] and "$0xf0,%eax" in by_addr[0x63AFD1B])
    check("walk2 add table rbx",
          "add" in by_addr[0x63AFD20] and "%rbx,%rax" in by_addr[0x63AFD20])
    check("walk2 top load",
          "mov" in by_addr[0x63AFD23] and "(%rax),%rsi" in by_addr[0x63AFD23])
    check("walk2 top compare",
          "cmp" in by_addr[0x63AFD26] and "%rsi,%rcx" in by_addr[0x63AFD26])
    check("walk2 mismatch jne scan B",
          "jne" in by_addr[0x63AFD29] and "63afe70" in by_addr[0x63AFD29])
    check("walk2 second level shr 0x9",
          "shr" in by_addr[0x63AFD2F] and "$0x9,%r11" in by_addr[0x63AFD2F])
    check("walk2 second level and 0x1ffff8",
          "and" in by_addr[0x63AFD33] and "$0x1ffff8,%r11d" in by_addr[0x63AFD33])
    check("walk2 second level add table entry",
          "add" in by_addr[0x63AFD3A] and "0x8(%rax),%r11" in by_addr[0x63AFD3A])
    check("walk2 second level mov r11 to rax",
          "mov" in by_addr[0x63AFD3E] and "%r11,%rax" in by_addr[0x63AFD3E])
    check("walk2 store to 0x8 rbp",
          "mov" in by_addr[0x63AFD41] and "%rax,0x8(%rbp)" in by_addr[0x63AFD41])

    check("walk3 key load 0x8 r12",
          "mov" in by_addr[0x63AFD45] and "0x8(%r12),%rax" in by_addr[0x63AFD45])
    check("walk3 page mov rax to rcx",
          "mov" in by_addr[0x63AFD4A] and "%rax,%rcx" in by_addr[0x63AFD4A])
    check("walk3 top mov rax to r15",
          "mov" in by_addr[0x63AFD4D] and "%rax,%r15" in by_addr[0x63AFD4D])
    check("walk3 top shr 0x1a",
          "shr" in by_addr[0x63AFD50] and "$0x1a,%rax" in by_addr[0x63AFD50])
    check("walk3 top and 0xf0",
          "and" in by_addr[0x63AFD54] and "$0xf0,%eax" in by_addr[0x63AFD54])
    check("walk3 high bits and",
          "and" in by_addr[0x63AFD59] and "$0xffffffffc0000000,%r15" in by_addr[0x63AFD59])
    check("walk3 page and",
          "and" in by_addr[0x63AFD60] and "$0xfffffffffffff000,%rcx" in by_addr[0x63AFD60])
    check("walk3 add table rbx",
          "add" in by_addr[0x63AFD67] and "%rbx,%rax" in by_addr[0x63AFD67])
    check("walk3 top load",
          "mov" in by_addr[0x63AFD6A] and "(%rax),%rdi" in by_addr[0x63AFD6A])
    check("walk3 top compare",
          "cmp" in by_addr[0x63AFD6D] and "%rdi,%r15" in by_addr[0x63AFD6D])
    check("walk3 mismatch jne scan C",
          "jne" in by_addr[0x63AFD70] and "63afeb8" in by_addr[0x63AFD70])
    check("walk3 second level shr 0x9",
          "shr" in by_addr[0x63AFD76] and "$0x9,%rcx" in by_addr[0x63AFD76])
    check("walk3 second level and 0x1ffff8",
          "and" in by_addr[0x63AFD7A] and "$0x1ffff8,%ecx" in by_addr[0x63AFD7A])
    check("walk3 second level add table entry",
          "add" in by_addr[0x63AFD80] and "0x8(%rax),%rcx" in by_addr[0x63AFD80])
    check("walk3 second level mov rcx to rax",
          "mov" in by_addr[0x63AFD84] and "%rcx,%rax" in by_addr[0x63AFD84])
    check("walk3 store to 0x10 rbp",
          "mov" in by_addr[0x63AFD87] and "%rax,0x10(%rbp)" in by_addr[0x63AFD87])

    check("walk4 key load 0x10 r12",
          "mov" in by_addr[0x63AFD8B] and "0x10(%r12),%r15" in by_addr[0x63AFD8B])
    check("walk4 key load 0x8 r12",
          "mov" in by_addr[0x63AFD90] and "0x8(%r12),%r12" in by_addr[0x63AFD90])
    check("walk4 key page and r15",
          "and" in by_addr[0x63AFD95] and "$0xfffffffffffff000,%r15" in by_addr[0x63AFD95])
    check("walk4 page and",
          "and" in by_addr[0x63AFD9C] and "$0xfffffffffffff000,%r12" in by_addr[0x63AFD9C])
    check("walk4 derived key lea -0x1000",
          "lea" in by_addr[0x63AFDA3] and "-0x1000(%r15,%r12,1),%rcx" in by_addr[0x63AFDA3])
    check("walk4 top mov rcx to rax",
          "mov" in by_addr[0x63AFDAB] and "%rcx,%rax" in by_addr[0x63AFDAB])
    check("walk4 top mov rcx to r11",
          "mov" in by_addr[0x63AFDAE] and "%rcx,%r11" in by_addr[0x63AFDAE])
    check("walk4 top shr 0x1a",
          "shr" in by_addr[0x63AFDB1] and "$0x1a,%rax" in by_addr[0x63AFDB1])
    check("walk4 high bits and",
          "and" in by_addr[0x63AFDB5] and "$0xffffffffc0000000,%r11" in by_addr[0x63AFDB5])
    check("walk4 top and 0xf0",
          "and" in by_addr[0x63AFDBC] and "$0xf0,%eax" in by_addr[0x63AFDBC])
    check("walk4 add table rbx",
          "add" in by_addr[0x63AFDC1] and "%rbx,%rax" in by_addr[0x63AFDC1])
    check("walk4 top load",
          "mov" in by_addr[0x63AFDC4] and "(%rax),%rdi" in by_addr[0x63AFDC4])
    check("walk4 top compare",
          "cmp" in by_addr[0x63AFDC7] and "%rdi,%r11" in by_addr[0x63AFDC7])
    check("walk4 mismatch jne scan D",
          "jne" in by_addr[0x63AFDCA] and "63aff00" in by_addr[0x63AFDCA])
    check("walk4 second level shr 0x9",
          "shr" in by_addr[0x63AFDD0] and "$0x9,%rcx" in by_addr[0x63AFDD0])
    check("walk4 second level mov rcx to rsi",
          "mov" in by_addr[0x63AFDD4] and "%rcx,%rsi" in by_addr[0x63AFDD4])
    check("walk4 second level and 0x1ffff8",
          "and" in by_addr[0x63AFDD7] and "$0x1ffff8,%esi" in by_addr[0x63AFDD7])
    check("walk4 second level add table entry",
          "add" in by_addr[0x63AFDDD] and "0x8(%rax),%rsi" in by_addr[0x63AFDDD])
    check("walk4 second level mov rsi to rax",
          "mov" in by_addr[0x63AFDE1] and "%rsi,%rax" in by_addr[0x63AFDE1])
    check("walk4 store to 0x18 rbp",
          "mov" in by_addr[0x63AFDE4] and "%rax,0x18(%rbp)" in by_addr[0x63AFDE4])

    check("no resolved-pointer null tests: no test rax,rax",
          not any("test" in l and "%rax,%rax" in l for l in lines))
    check("no resolved-pointer null tests: no cmpq $0x0 slots",
          not any("cmpq" in l and "$0x0," in l for l in lines))
    check("no sete in window",
          not any("sete" in l for l in lines))
    check("walk1 store falls through to walk2 key load",
          "mov" in by_addr[0x63AFCEC] and "0x10(%r15),%rdi" in by_addr[0x63AFCEC])
    check("walk3 store falls through to walk4 key load",
          "mov" in by_addr[0x63AFD8B] and "0x10(%r12),%r15" in by_addr[0x63AFD8B])

    check("no size table 0x6727a00 read",
          not any("0x6727a00" in l for l in lines))
    check("no threshold table 0x67277c0 read",
          not any("0x67277c0" in l for l in lines))
    check("no node-resolution table 0x65096c0",
          not any("0x65096c0" in l for l in lines))
    check("no 0x6511780 table read",
          not any("0x6511780" in l for l in lines))
    check("no shl/sar 0x10 match transform",
          not any(("shl" in l or "sar" in l) and "$0x10" in l for l in lines))

    slotA = [0x63AFE30, 0x63AFF46, 0x63B00E1, 0x63B00F4,
             0x63B0107, 0x63B011A, 0x63B012D, 0x63B013A]
    check("scan A all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slotA),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slotA
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan A reversed-operand slots none",
          [a for a in slotA
           if operands_of(by_addr[a]).startswith("%rdi,")] == [],
          str([(hex(a), operands_of(by_addr[a])) for a in slotA
               if operands_of(by_addr[a]).startswith("%rdi,")]))
    check("scan A slot 7 compares memory directly",
          "cmp" in by_addr[0x63B013A] and "0x170(%rbx),%rdi" in by_addr[0x63B013A])
    check("scan A slot 1 jne slots chain",
          "jne" in by_addr[0x63AFF4D] and "63b00db" in by_addr[0x63AFF4D])
    check("scan A slot 2 je shared mtf",
          "je" in by_addr[0x63B00E8] and "63aff53" in by_addr[0x63B00E8])
    check("scan A slot 0 mtf rejoin jmp 0x63afce8",
          "jmp" in by_addr[0x63AFE6B] and "63afce8" in by_addr[0x63AFE6B])
    check("scan A shared mtf rejoin jmp 0x63afe56",
          "jmp" in by_addr[0x63AFF9D] and "63afe56" in by_addr[0x63AFF9D])
    slotB = [0x63AFE70, 0x63B007E, 0x63B0292, 0x63B02A5,
             0x63B02B8, 0x63B02CB, 0x63B02DE, 0x63B02EB]
    check("scan B all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slotB),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slotB
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan B reversed-operand slots none",
          [a for a in slotB
           if operands_of(by_addr[a]).startswith("%rcx,")] == [],
          str([(hex(a), operands_of(by_addr[a])) for a in slotB
               if operands_of(by_addr[a]).startswith("%rcx,")]))
    check("scan B slot 7 compares memory directly",
          "cmp" in by_addr[0x63B02EB] and "0x170(%rbx),%rcx" in by_addr[0x63B02EB])
    check("scan B slot 1 jne slots chain",
          "jne" in by_addr[0x63B0085] and "63b028c" in by_addr[0x63B0085])
    check("scan B slot 2 je shared mtf",
          "je" in by_addr[0x63B0299] and "63b008b" in by_addr[0x63B0299])
    check("scan B slot 0 mtf rejoin jmp 0x63afd41",
          "jmp" in by_addr[0x63AFEAC] and "63afd41" in by_addr[0x63AFEAC])
    check("scan B shared mtf rejoin jmp 0x63afe96",
          "jmp" in by_addr[0x63B00D6] and "63afe96" in by_addr[0x63B00D6])
    slotC = [0x63AFEB8, 0x63B0015, 0x63B0201, 0x63B0213,
             0x63B0225, 0x63B0237, 0x63B0249, 0x63B0256]
    check("scan C all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slotC),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slotC
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan C reversed-operand slots 3 and 4",
          [a for a in slotC
           if operands_of(by_addr[a]).startswith("%r15,")] == [0x63B0213, 0x63B0225],
          str([(hex(a), operands_of(by_addr[a])) for a in slotC
               if operands_of(by_addr[a]).startswith("%r15,")]))
    check("scan C slot 7 compares memory directly",
          "cmp" in by_addr[0x63B0256] and "0x170(%rbx),%r15" in by_addr[0x63B0256])
    check("scan C slot 1 jne slots chain",
          "jne" in by_addr[0x63B001C] and "63b01fc" in by_addr[0x63B001C])
    check("scan C slot 2 je shared mtf",
          "je" in by_addr[0x63B0208] and "63b0022" in by_addr[0x63B0208])
    check("scan C slot 0 mtf rejoin jmp 0x63afd87",
          "jmp" in by_addr[0x63AFEF3] and "63afd87" in by_addr[0x63AFEF3])
    check("scan C shared mtf rejoin jmp 0x63afede",
          "jmp" in by_addr[0x63B006C] and "63afede" in by_addr[0x63B006C])
    slotD = [0x63AFF00, 0x63AFFAE, 0x63B0172, 0x63B0185,
             0x63B0198, 0x63B01AB, 0x63B01BE, 0x63B01CB]
    check("scan D all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slotD),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slotD
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan D reversed-operand slot 6",
          [a for a in slotD
           if operands_of(by_addr[a]).startswith("%r11,")] == [0x63B01BE],
          str([(hex(a), operands_of(by_addr[a])) for a in slotD
               if operands_of(by_addr[a]).startswith("%r11,")]))
    check("scan D slot 7 compares memory directly",
          "cmp" in by_addr[0x63B01CB] and "0x170(%rbx),%r11" in by_addr[0x63B01CB])
    check("scan D slot 1 jne slots chain",
          "jne" in by_addr[0x63AFFB5] and "63b016c" in by_addr[0x63AFFB5])
    check("scan D slot 2 je shared mtf",
          "je" in by_addr[0x63B0179] and "63affbb" in by_addr[0x63B0179])
    check("scan D slot 0 mtf rejoin jmp 0x63afde4",
          "jmp" in by_addr[0x63AFF3B] and "63afde4" in by_addr[0x63AFF3B])
    check("scan D shared mtf rejoin jmp 0x63aff26",
          "jmp" in by_addr[0x63B0005] and "63aff26" in by_addr[0x63B0005])

    check("lu-miss A r9d 0",
          "xor" in by_addr[0x63B0150] and "%r9d,%r9d" in by_addr[0x63B0150])
    check("lu-miss A r8d 1",
          "mov" in by_addr[0x63B0153] and "$0x1,%r8d" in by_addr[0x63B0153])
    check("lu-miss A rdx scan table rbx",
          "mov" in by_addr[0x63B0159] and "%rbx,%rdx" in by_addr[0x63B0159])
    check("lu-miss A rsi entry r14",
          "mov" in by_addr[0x63B015C] and "%r14,%rsi" in by_addr[0x63B015C])
    check("lu-miss A rdi context r13",
          "mov" in by_addr[0x63B015F] and "%r13,%rdi" in by_addr[0x63B015F])
    check("lu-miss A rcx not set in block, page key1 carried",
          not any(",%rcx" in by_addr[a] for a in
                  [0x63B0150, 0x63B0153, 0x63B0159, 0x63B015C, 0x63B015F]),
          str([by_addr[a] for a in
               [0x63B0150, 0x63B0153, 0x63B0159, 0x63B015C, 0x63B015F]]))
    check("lu-miss A rejoin jmp 0x63afce8",
          "jmp" in by_addr[0x63B0167] and "63afce8" in by_addr[0x63B0167])
    check("lu-miss B r9d 0",
          "xor" in by_addr[0x63B0300] and "%r9d,%r9d" in by_addr[0x63B0300])
    check("lu-miss B r8d 1",
          "mov" in by_addr[0x63B0303] and "$0x1,%r8d" in by_addr[0x63B0303])
    check("lu-miss B rcx derived key 2 in r11",
          "mov" in by_addr[0x63B0309] and "%r11,%rcx" in by_addr[0x63B0309])
    check("lu-miss B rdx scan table rbx",
          "mov" in by_addr[0x63B030C] and "%rbx,%rdx" in by_addr[0x63B030C])
    check("lu-miss B rsi entry r14",
          "mov" in by_addr[0x63B030F] and "%r14,%rsi" in by_addr[0x63B030F])
    check("lu-miss B rdi context r13",
          "mov" in by_addr[0x63B0312] and "%r13,%rdi" in by_addr[0x63B0312])
    check("lu-miss B rejoin jmp 0x63afd41",
          "jmp" in by_addr[0x63B031A] and "63afd41" in by_addr[0x63B031A])
    check("lu-miss C r9d 0",
          "xor" in by_addr[0x63B0270] and "%r9d,%r9d" in by_addr[0x63B0270])
    check("lu-miss C r8d 1",
          "mov" in by_addr[0x63B0273] and "$0x1,%r8d" in by_addr[0x63B0273])
    check("lu-miss C rdx scan table rbx",
          "mov" in by_addr[0x63B0279] and "%rbx,%rdx" in by_addr[0x63B0279])
    check("lu-miss C rsi entry r14",
          "mov" in by_addr[0x63B027C] and "%r14,%rsi" in by_addr[0x63B027C])
    check("lu-miss C rdi context r13",
          "mov" in by_addr[0x63B027F] and "%r13,%rdi" in by_addr[0x63B027F])
    check("lu-miss C rcx not set in block, page key3 carried",
          not any(",%rcx" in by_addr[a] for a in
                  [0x63B0270, 0x63B0273, 0x63B0279, 0x63B027C, 0x63B027F]),
          str([by_addr[a] for a in
               [0x63B0270, 0x63B0273, 0x63B0279, 0x63B027C, 0x63B027F]]))
    check("lu-miss C rejoin jmp 0x63afd87",
          "jmp" in by_addr[0x63B0287] and "63afd87" in by_addr[0x63B0287])
    check("lu-miss D r9d 0",
          "xor" in by_addr[0x63B01E0] and "%r9d,%r9d" in by_addr[0x63B01E0])
    check("lu-miss D r8d 1",
          "mov" in by_addr[0x63B01E3] and "$0x1,%r8d" in by_addr[0x63B01E3])
    check("lu-miss D rdx scan table rbx",
          "mov" in by_addr[0x63B01E9] and "%rbx,%rdx" in by_addr[0x63B01E9])
    check("lu-miss D rsi entry r14",
          "mov" in by_addr[0x63B01EC] and "%r14,%rsi" in by_addr[0x63B01EC])
    check("lu-miss D rdi context r13",
          "mov" in by_addr[0x63B01EF] and "%r13,%rdi" in by_addr[0x63B01EF])
    check("lu-miss D rcx not set in block, derived key carried",
          not any(",%rcx" in by_addr[a] for a in
                  [0x63B01E0, 0x63B01E3, 0x63B01E9, 0x63B01EC, 0x63B01EF]),
          str([by_addr[a] for a in
               [0x63B01E0, 0x63B01E3, 0x63B01E9, 0x63B01EC, 0x63B01EF]]))
    check("lu-miss D rejoin jmp 0x63afde4",
          "jmp" in by_addr[0x63B01F7] and "63afde4" in by_addr[0x63B01F7])

    check("eax writes exact list",
          [addr_of(l) for l in lines if "%eax" in l] ==
          [0x63AFC9C, 0x63AFCB5, 0x63AFD1B, 0x63AFD54, 0x63AFDBC],
          str([hex(addr_of(l)) for l in lines if "%eax" in l]))
    check("ret site 0x63afe10 is a ret",
          "ret" in by_addr[0x63AFE10])


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
    pos = tbytes.find(b"\xe8")
    while pos != -1:
        if pos + 5 <= len(tbytes):
            rel = struct.unpack_from("<i", tbytes, pos + 1)[0]
            if tva + pos + 5 + rel == 0x63D9880:
                va = tva + pos
                k = bisect.bisect_right(starts, va) - 1
                if k >= 0 and fdes[k][0] <= va < fdes[k][1]:
                    counts[fdes[k][0]] = counts.get(fdes[k][0], 0) + 1
        pos = tbytes.find(b"\xe8", pos + 1)
    tiers = {}
    for v in counts.values():
        tiers[v] = tiers.get(v, 0) + 1
    check("raw-e8 total 108", sum(counts.values()) == 108,
          str(sum(counts.values())))
    check("raw-e8 tiers",
          tiers == {10: 1, 8: 1, 6: 2, 5: 1, 4: 8, 2: 12, 1: 17},
          str(tiers))
    check("this FDE raw 1", counts.get(START, 0) == 1,
          str(counts.get(START, 0)))

    # survey consistency: 17 candidates, 1 exclusion, #214 overlap real
    survey = rec.get("survey", {})
    cands = survey.get("candidates", [])
    check("survey candidates 17", len(cands) == 17, str(len(cands)))
    excluded = [c for c in cands if "EXCLUDED" in c.get("status", "")]
    check("survey exclusions 1", len(excluded) == 1,
          str([c["start"] for c in excluded]))
    check("survey excluded candidate is 0x63adf40",
          excluded and excluded[0]["start"] == "0x63adf40")
    nn_ranges = []
    nn_skipped = []
    for d in glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*",
                                    "research", "work-items",
                                    "*lu-nextnode*", "records.json")):
        try:
            with open(d) as f:
                collect_ranges(json.load(f), nn_ranges, nn_skipped)
        except Exception:
            pass
    check("survey exclusion overlaps #214 claim",
          any(0x63ADF40 < b and a < 0x63AE252 for a, b in nn_ranges),
          str(nn_ranges[:5]))

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
    # is the sorted (path, size, mtime_ns) of every candidate file, so any
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
            fp.append([d, st.st_size, st.st_mtime_ns])
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
