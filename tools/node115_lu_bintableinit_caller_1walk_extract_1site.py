#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-1site-1walk-extract.

Byte reads only; never executes the node binary. Checks, counted at the end:
base + binary identity, .eh_frame bounds, exhibit bytes, strict/call census,
site-block shape (lea 0x10 rsp, rsi save/restore to 0x8 rsp, table base in
r15, outputs in rbp/rbx/r12), single-walk lookup with shl/sar 0x10 extract
(value -> page to *r12, index (desc >> 0x1c) & 0x3ff to *rbp, byte-indexed
40-byte-entry table field to *rbx; two early paths: small-value zero path
and flag-clear path), single 8-slot scan (reversed-operand compare: slot 6
only), one lu-miss site (rsi is the .bss address 0x6511a00, NOT entry rsi;
r8d=1/r9d=0; rcx is entry rsi), canary, jump closure, rel32 targets, rela
counts, .bss containment of both referenced tables, raw-e8 tiers,
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
                      "RE-001-node115-lu-bintableinit-caller-1site-1walk-extract")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-1site-1walk-extract"
NAME = "bintableinit_caller_1walk_extract_1site"
START, END = 0x63BC490, 0x63BC728

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
    check("target FDE size 664", END - START == 664)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x63bc480..0x63bc489",
          prev == (0x63BC480, 0x63BC489), str(prev))
    check("prev gap 7", START - prev[1] == 7)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 7, gap.hex())
    check("next FDE 0x63bc730..0x63bcb12",
          nxt == (0x63BC730, 0x63BCB12), str(nxt))
    check("next padding 8", nxt[0] - END == 8)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 8, pad.hex())
    check("no overlap with 0x63adf40 exclusion",
          END <= 0x63ADF40 or START >= 0x63AE252)
    check("no overlap with 0x63ed090 exclusion",
          END <= 0x63ED090 or START >= 0x63ED862)
    check("no overlap with 0x63ef8e0 exclusion",
          END <= 0x63EF8E0 or START >= 0x63EFBA2)

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 664", len(hexb) == 664, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 145", len(lines) == 145, str(len(lines)))
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 3", len(calls) == 3, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63bc59e", [addr_of(l) for l in rets] == [0x63BC59E],
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
          ct == [(0x63BC5E5, 0x63D9880), (0x63BC719, 0x63D9700),
                 (0x63BC723, 0x63F0D70)],
          str(ct))
    bti = [a for a, t in ct if t == 0x63D9880]
    check("bti sites", bti == [0x63BC5E5], str(bti))
    miss = [a for a, t in ct if t == 0x63D9700]
    check("lu-miss sites",
          miss == [0x63BC719], str(miss))
    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str(len(bsr)))
    locks = [(mnemonic_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))

    by_addr = {addr_of(l): l for l in lines}
    check("entry rdi to r14",
          "mov" in by_addr[0x63BC49F] and "%rdi,%r14" in by_addr[0x63BC49F])
    check("entry r8 to r12",
          "mov" in by_addr[0x63BC4A6] and "%r8,%r12" in by_addr[0x63BC4A6])
    check("entry rdx to rbp",
          "mov" in by_addr[0x63BC4AA] and "%rdx,%rbp" in by_addr[0x63BC4AA])
    check("entry rcx to rbx",
          "mov" in by_addr[0x63BC4AE] and "%rcx,%rbx" in by_addr[0x63BC4AE])
    check("walk table lea 0x1b0 rdi to r15",
          "lea" in by_addr[0x63BC496] and "0x1b0(%rdi),%r15" in by_addr[0x63BC496])
    check("frame sub 0x1a8 rsp",
          "sub" in by_addr[0x63BC4B1] and "$0x1a8,%rsp" in by_addr[0x63BC4B1])
    check("canary at 0x198 rsp",
          "0x198(%rsp)" in by_addr[0x63BC4C1])
    check("entry eax zeroed",
          "xor" in by_addr[0x63BC4C9] and "%eax,%eax" in by_addr[0x63BC4C9])
    check("null-context test rdi",
          "test" in by_addr[0x63BC4CB] and "%rdi,%rdi" in by_addr[0x63BC4CB])
    check("null-context je to site block",
          "je" in by_addr[0x63BC4CE] and "63bc5d8" in by_addr[0x63BC4CE])
    check("site lea 0x10 rsp in block",
          "lea" in by_addr[0x63BC5D8] and "0x10(%rsp),%r15" in by_addr[0x63BC5D8])
    check("site saves rsi to 0x8 rsp",
          "mov" in by_addr[0x63BC5DD] and "%rsi,0x8(%rsp)" in by_addr[0x63BC5DD])
    check("site mov r15 to rdi",
          "mov" in by_addr[0x63BC5E2] and "%r15,%rdi" in by_addr[0x63BC5E2])
    check("site restores rsi from 0x8 rsp",
          "mov" in by_addr[0x63BC5EA] and "0x8(%rsp),%rsi" in by_addr[0x63BC5EA])
    check("site rejoin jmp 0x63bc4d4",
          "jmp" in by_addr[0x63BC5EF] and "63bc4d4" in by_addr[0x63BC5EF])
    check("site block preceded by nopl",
          "nopl" in by_addr[0x63BC5D1])
    check("bti table temp 0x10 rsp referenced once",
          sum(1 for l in lines if "0x10(%rsp)" in l) == 1,
          str([l for l in lines if "0x10(%rsp)" in l]))
    check("rsi save/restore pair at 0x8 rsp",
          [addr_of(l) for l in lines if "0x8(%rsp)" in l] == [0x63BC5DD, 0x63BC5EA],
          str([hex(addr_of(l)) for l in lines if "0x8(%rsp)" in l]))
    check("no rep stos in window",
          not any("rep stos" in l for l in lines))

    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 20", len(jmps) == 20, str(len(jmps)))
    outside = [(a, t) for a, t in jmps
               if not (START <= t < END)]
    check("jump closure none outside window",
          outside == [], str(outside))
    tg = [a for a, t in jmps if t == 0x63BC5D8]
    check("block 0x63bc5d8 single je entry", tg == [0x63BC4CE], str(tg))
    check("epilogue rejoin from both early paths",
          sorted(a for a, t in jmps if t == 0x63BC576) == [0x63BC5AF, 0x63BC5CF],
          str([hex(a) for a, t in jmps if t == 0x63BC576]))
    check("second-level rejoin from slot-0 hit and lu-miss",
          sorted(a for a, t in jmps if t == 0x63BC50E) == [0x63BC62F, 0x63BC71E],
          str([hex(a) for a, t in jmps if t == 0x63BC50E]))
    check("shared mtf rejoin targets",
          sorted(a for a, t in jmps if t == 0x63BC647) ==
          [0x63BC6A0, 0x63BC6AF, 0x63BC6BE, 0x63BC6CD, 0x63BC6E0, 0x63BC6F5],
          str([hex(a) for a, t in jmps if t == 0x63BC647]))

    check("canary check mov 0x198 rsp to rax",
          "mov" in by_addr[0x63BC576] and "0x198(%rsp),%rax" in by_addr[0x63BC576])
    check("canary check sub fs",
          "sub" in by_addr[0x63BC57E] and "%fs:0x28" in by_addr[0x63BC57E])
    check("canary fail jne to stack_chk_fail",
          "jne" in by_addr[0x63BC587] and "63bc723" in by_addr[0x63BC587])
    check("epilogue add 0x1a8 rsp",
          "add" in by_addr[0x63BC58D] and "$0x1a8,%rsp" in by_addr[0x63BC58D])

    check("walk key mov rsi to rax",
          "mov" in by_addr[0x63BC4D4] and "%rsi,%rax" in by_addr[0x63BC4D4])
    check("walk key mov rsi to rcx",
          "mov" in by_addr[0x63BC4D7] and "%rsi,%rcx" in by_addr[0x63BC4D7])
    check("walk top shr 0x1a",
          "shr" in by_addr[0x63BC4DA] and "$0x1a,%rax" in by_addr[0x63BC4DA])
    check("walk high bits and",
          "and" in by_addr[0x63BC4DE] and "$0xffffffffc0000000,%rcx" in by_addr[0x63BC4DE])
    check("walk top and 0xf0",
          "and" in by_addr[0x63BC4E5] and "$0xf0,%eax" in by_addr[0x63BC4E5])
    check("walk add table r15",
          "add" in by_addr[0x63BC4EA] and "%r15,%rax" in by_addr[0x63BC4EA])
    check("walk top load",
          "mov" in by_addr[0x63BC4ED] and "(%rax),%rdi" in by_addr[0x63BC4ED])
    check("walk top compare",
          "cmp" in by_addr[0x63BC4F0] and "%rdi,%rcx" in by_addr[0x63BC4F0])
    check("walk mismatch jne scan",
          "jne" in by_addr[0x63BC4F3] and "63bc5f8" in by_addr[0x63BC4F3])
    check("walk second level shr 0x9",
          "shr" in by_addr[0x63BC4F9] and "$0x9,%rsi" in by_addr[0x63BC4F9])
    check("walk second level mov rsi to r15",
          "mov" in by_addr[0x63BC4FD] and "%rsi,%r15" in by_addr[0x63BC4FD])
    check("walk second level and 0x1ffff8",
          "and" in by_addr[0x63BC500] and "$0x1ffff8,%r15d" in by_addr[0x63BC500])
    check("walk second level add table entry",
          "add" in by_addr[0x63BC507] and "0x8(%rax),%r15" in by_addr[0x63BC507])
    check("walk second level mov r15 to rax",
          "mov" in by_addr[0x63BC50B] and "%r15,%rax" in by_addr[0x63BC50B])
    check("walk second level load",
          "mov" in by_addr[0x63BC50E] and "(%rax),%rcx" in by_addr[0x63BC50E])

    check("extract shl 0x10",
          "shl" in by_addr[0x63BC511] and "$0x10,%rcx" in by_addr[0x63BC511])
    check("extract mov rcx to rax",
          "mov" in by_addr[0x63BC515] and "%rcx,%rax" in by_addr[0x63BC515])
    check("extract sar 0x10",
          "sar" in by_addr[0x63BC518] and "$0x10,%rax" in by_addr[0x63BC518])
    check("extract and mask 0x7f",
          "and" in by_addr[0x63BC51C] and "$0xffffffffffffff80,%rax" in by_addr[0x63BC51C])
    check("extract cmp 0x7fffff",
          "cmp" in by_addr[0x63BC520] and "$0x7fffff,%rcx" in by_addr[0x63BC520])
    check("extract jbe zero path",
          "jbe" in by_addr[0x63BC527] and "63bc5b8" in by_addr[0x63BC527])
    check("extract page load 0x10 rax",
          "mov" in by_addr[0x63BC52D] and "0x10(%rax),%rdi" in by_addr[0x63BC52D])
    check("extract page and",
          "and" in by_addr[0x63BC531] and "$0xfffffffffffff000,%rdi" in by_addr[0x63BC531])
    check("extract page store to r12",
          "mov" in by_addr[0x63BC538] and "%rdi,(%r12)" in by_addr[0x63BC538])
    check("extract descriptor load",
          "mov" in by_addr[0x63BC53C] and "(%rax),%rdx" in by_addr[0x63BC53C])
    check("extract flag test 0x10 dh",
          "test" in by_addr[0x63BC53F] and "$0x10,%dh" in by_addr[0x63BC53F])
    check("extract flag je flag path",
          "je" in by_addr[0x63BC542] and "63bc5a0" in by_addr[0x63BC542])
    check("extract index shr 0x1c",
          "shr" in by_addr[0x63BC544] and "$0x1c,%rdx" in by_addr[0x63BC544])
    check("extract table lea rip",
          "lea" in by_addr[0x63BC548] and "0x3555f1(%rip),%r10" in by_addr[0x63BC548])
    check("extract table lea target 0x6711b40",
          0x63BC54F + 0x3555F1 == 0x6711B40)
    check("extract index and 0x3ff",
          "and" in by_addr[0x63BC54F] and "$0x3ff,%edx" in by_addr[0x63BC54F])
    check("extract index mov to r12d",
          "mov" in by_addr[0x63BC555] and "%edx,%r12d" in by_addr[0x63BC555])
    check("extract index store to 0x0 rbp",
          "mov" in by_addr[0x63BC558] and "%r12,0x0(%rbp)" in by_addr[0x63BC558])
    check("extract descriptor reload to rbp",
          "mov" in by_addr[0x63BC55C] and "(%rax),%rbp" in by_addr[0x63BC55C])
    check("extract byte shr 0x14",
          "shr" in by_addr[0x63BC55F] and "$0x14,%rbp" in by_addr[0x63BC55F])
    check("extract byte movzbl bpl to r8d",
          "movzbl" in by_addr[0x63BC563] and "%bpl,%r8d" in by_addr[0x63BC563])
    check("extract entry stride lea times 5",
          "lea" in by_addr[0x63BC567] and "(%r8,%r8,4),%r9" in by_addr[0x63BC567])
    check("extract entry lea times 8",
          "lea" in by_addr[0x63BC56B] and "(%r10,%r9,8),%r11" in by_addr[0x63BC56B])
    check("extract field load 0x10 r11",
          "mov" in by_addr[0x63BC56F] and "0x10(%r11),%r13d" in by_addr[0x63BC56F])
    check("extract field store to rbx",
          "mov" in by_addr[0x63BC573] and "%r13,(%rbx)" in by_addr[0x63BC573])
    check("zero path store r12 zero",
          "movq" in by_addr[0x63BC5B8] and "$0x0,(%r12)" in by_addr[0x63BC5B8])
    check("zero path store rbx zero",
          "movq" in by_addr[0x63BC5C0] and "$0x0,(%rbx)" in by_addr[0x63BC5C0])
    check("zero path store rbp zero",
          "movq" in by_addr[0x63BC5C7] and "$0x0,0x0(%rbp)" in by_addr[0x63BC5C7])
    check("zero path jmp epilogue",
          "jmp" in by_addr[0x63BC5CF] and "63bc576" in by_addr[0x63BC5CF])
    check("flag path store rbp zero",
          "movq" in by_addr[0x63BC5A0] and "$0x0,0x0(%rbp)" in by_addr[0x63BC5A0])
    check("flag path store rbx one",
          "movq" in by_addr[0x63BC5A8] and "$0x1,(%rbx)" in by_addr[0x63BC5A8])
    check("flag path jmp epilogue",
          "jmp" in by_addr[0x63BC5AF] and "63bc576" in by_addr[0x63BC5AF])
    check("no resolved-pointer null test rax",
          not any("test" in l and "%rax,%rax" in l for l in lines))
    check("no sete in window",
          not any("sete" in l for l in lines))
    check("no cmpq null slot tests",
          not any("cmpq" in l for l in lines))
    check("shl/sar 0x10 transform present (unlike #303-#310)",
          any("shl" in l and "$0x10" in l for l in lines) and
          any("sar" in l and "$0x10" in l for l in lines))

    check("no size table 0x6727a00 read",
          not any("0x6727a00" in l for l in lines))
    check("no threshold table 0x67277c0 read",
          not any("0x67277c0" in l for l in lines))
    check("no node-resolution table 0x65096c0",
          not any("0x65096c0" in l for l in lines))
    check("no 0x6511780 table read",
          not any("0x6511780" in l for l in lines))

    slots = [0x63BC5F8, 0x63BC63E, 0x63BC699, 0x63BC6A8,
             0x63BC6B7, 0x63BC6C6, 0x63BC6D9, 0x63BC6E6]
    check("scan all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slots),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slots
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan reversed-operand slot 6 only",
          [a for a in slots
           if operands_of(by_addr[a]).startswith("%rcx,")] == [0x63BC6D9],
          str([(hex(a), operands_of(by_addr[a])) for a in slots
               if operands_of(by_addr[a]).startswith("%rcx,")]))
    check("scan slot 7 compares memory directly",
          "cmp" in by_addr[0x63BC6E6] and "0x170(%r15),%rcx" in by_addr[0x63BC6E6])
    check("scan slot 0 hit mov top entry to slot",
          "mov" in by_addr[0x63BC601] and "%rdi,0x100(%r15)" in by_addr[0x63BC601])
    check("scan slot 0 hit mov second base to r14",
          "mov" in by_addr[0x63BC608] and "0x8(%rax),%r14" in by_addr[0x63BC608])
    check("scan slot 0 hit mov slot base to rdx",
          "mov" in by_addr[0x63BC60C] and "0x108(%r15),%rdx" in by_addr[0x63BC60C])
    check("scan slot 0 hit mov r14 to slot base",
          "mov" in by_addr[0x63BC613] and "%r14,0x108(%r15)" in by_addr[0x63BC613])
    check("scan slot 0 hit shr 0x9 rsi",
          "shr" in by_addr[0x63BC61A] and "$0x9,%rsi" in by_addr[0x63BC61A])
    check("scan slot 0 hit mov rcx to top entry",
          "mov" in by_addr[0x63BC61E] and "%rcx,(%rax)" in by_addr[0x63BC61E])
    check("scan slot 0 hit and 0x1ffff8 esi",
          "and" in by_addr[0x63BC621] and "$0x1ffff8,%esi" in by_addr[0x63BC621])
    check("scan slot 0 hit mov rdx to second entry",
          "mov" in by_addr[0x63BC627] and "%rdx,0x8(%rax)" in by_addr[0x63BC627])
    check("scan slot 0 hit lea second pointer",
          "lea" in by_addr[0x63BC62B] and "(%rdx,%rsi,1),%rax" in by_addr[0x63BC62B])
    check("scan slot 0 hit rejoin jmp 0x63bc50e",
          "jmp" in by_addr[0x63BC62F] and "63bc50e" in by_addr[0x63BC62F])
    check("scan slot 1 mov 1 r8d",
          "mov" in by_addr[0x63BC638] and "$0x1,%r8d" in by_addr[0x63BC638])
    check("scan slot 1 jne slots chain",
          "jne" in by_addr[0x63BC645] and "63bc693" in by_addr[0x63BC645])
    check("scan slot 2 je shared mtf",
          "je" in by_addr[0x63BC6A0] and "63bc647" in by_addr[0x63BC6A0])
    check("scan shared mtf mov r8d to r9d",
          "mov" in by_addr[0x63BC647] and "%r8d,%r9d" in by_addr[0x63BC647])
    check("scan shared mtf sub 1 r8d",
          "sub" in by_addr[0x63BC64A] and "$0x1,%r8d" in by_addr[0x63BC64A])
    check("scan shared mtf shl 4 r8 and r9",
          "shl" in by_addr[0x63BC64E] and "$0x4,%r8" in by_addr[0x63BC64E] and
          "shl" in by_addr[0x63BC652] and "$0x4,%r9" in by_addr[0x63BC652])
    check("scan shared mtf add table r15",
          "add" in by_addr[0x63BC656] and "%r15,%r8" in by_addr[0x63BC656] and
          "add" in by_addr[0x63BC659] and "%r15,%r9" in by_addr[0x63BC659])
    check("scan shared mtf swap slot entries",
          "mov" in by_addr[0x63BC65C] and "0x100(%r8),%r10" in by_addr[0x63BC65C] and
          "mov" in by_addr[0x63BC663] and "0x108(%r9),%rdx" in by_addr[0x63BC663] and
          "mov" in by_addr[0x63BC66A] and "%r10,0x100(%r9)" in by_addr[0x63BC66A])
    check("scan shared mtf mov top entry to slot",
          "mov" in by_addr[0x63BC67F] and "%rdi,0x100(%r8)" in by_addr[0x63BC67F])
    check("scan shared mtf mov second base to r13",
          "mov" in by_addr[0x63BC686] and "0x8(%rax),%r13" in by_addr[0x63BC686])
    check("scan shared mtf mov r13 to slot base",
          "mov" in by_addr[0x63BC68A] and "%r13,0x108(%r8)" in by_addr[0x63BC68A])
    check("scan shared mtf rejoin jmp 0x63bc61a",
          "jmp" in by_addr[0x63BC691] and "63bc61a" in by_addr[0x63BC691])
    check("scan slot 7 hit mov 7 r8d",
          "mov" in by_addr[0x63BC6EF] and "$0x7,%r8d" in by_addr[0x63BC6EF])
    check("scan slot 7 hit jmp shared mtf",
          "jmp" in by_addr[0x63BC6F5] and "63bc647" in by_addr[0x63BC6F5])
    check("scan slot 7 miss jne lu-miss",
          "jne" in by_addr[0x63BC6ED] and "63bc700" in by_addr[0x63BC6ED])

    check("lu-miss mov rsi to rcx",
          "mov" in by_addr[0x63BC700] and "%rsi,%rcx" in by_addr[0x63BC700])
    check("lu-miss lea rip to rsi",
          "lea" in by_addr[0x63BC703] and "0x1552f6(%rip),%rsi" in by_addr[0x63BC703])
    check("lu-miss lea target 0x6511a00",
          0x63BC70A + 0x1552F6 == 0x6511A00)
    check("lu-miss rsi is bss address, not entry rsi",
          not any("mov" in by_addr[a] and "%r14,%rsi" in by_addr[a] for a in
                  [0x63BC700, 0x63BC703, 0x63BC70A, 0x63BC70D, 0x63BC710, 0x63BC716]))
    check("lu-miss r9d 0",
          "xor" in by_addr[0x63BC70A] and "%r9d,%r9d" in by_addr[0x63BC70A])
    check("lu-miss rdx scan table r15",
          "mov" in by_addr[0x63BC70D] and "%r15,%rdx" in by_addr[0x63BC70D])
    check("lu-miss r8d 1",
          "mov" in by_addr[0x63BC710] and "$0x1,%r8d" in by_addr[0x63BC710])
    check("lu-miss rdi context r14",
          "mov" in by_addr[0x63BC716] and "%r14,%rdi" in by_addr[0x63BC716])
    check("lu-miss rejoin jmp 0x63bc50e",
          "jmp" in by_addr[0x63BC71E] and "63bc50e" in by_addr[0x63BC71E])
    check("r14 holds entry context on miss path (no mov to r14 on miss path)",
          [addr_of(l) for l in lines
           if mnemonic_of(l) == "mov" and operands_of(l).endswith("%r14")] ==
          [0x63BC49F, 0x63BC608],
          str([hex(addr_of(l)) for l in lines
               if mnemonic_of(l) == "mov" and operands_of(l).endswith("%r14")]))

    check("eax writes exact list",
          [addr_of(l) for l in lines if "%eax" in l] ==
          [0x63BC4C9, 0x63BC4E5],
          str([hex(addr_of(l)) for l in lines if "%eax" in l]))
    check("ret site 0x63bc59e is a ret",
          "ret" in by_addr[0x63BC59E])



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

    bss = None
    for s in secs:
        if secname(s[0]) == ".bss":
            bss = s
    check("bss section present", bss is not None)
    check("bss is NOBITS", bss is not None and bss[1] == 8,
          str(bss[1]) if bss else "")
    check("lu-miss rsi 0x6511a00 lies in .bss",
          bss is not None and bss[3] <= 0x6511A00 < bss[3] + bss[5],
          str(bss) if bss else "")
    check("extract table 0x6711b40 lies in .bss",
          bss is not None and bss[3] <= 0x6711B40 < bss[3] + bss[5],
          str(bss) if bss else "")

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
