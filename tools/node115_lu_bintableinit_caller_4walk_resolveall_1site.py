#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall.

Byte reads only; never executes the node binary. Checks, counted at the end:
base + binary identity, .eh_frame bounds, exhibit bytes, strict/call census,
site-block shape (lea 0x90 rsp, r8 save/restore, table base in rbp), four-walk
resolve-all (walks 1-4 store second-level pointers to 0x0/0x8/0x10/0x18 rbx;
walk 2 skipped when walk 1 second level is null, walk 4 skipped when walk 3
second level is null; epilogue reports 1 if any slot is null), four 8-slot
scans (reversed-operand compares tracked: scan B slots 5-6, scan C slots 3-6),
four lu-miss sites (rsi entry r14 on all; rcx provenance per site), canary,
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
                      "RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-1site-4walk-resolveall"
NAME = "bintableinit_caller_4walk_resolveall_1site"
START, END = 0x63AF460, 0x63AFBA4

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
    check("target FDE size 1860", END - START == 1860)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x63aefe0..0x63af45f",
          prev == (0x63aefe0, 0x63af45f), str(prev))
    check("prev gap 1", START - prev[1] == 1)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 1, gap.hex())
    check("next FDE 0x63afbb0..0x63afc54",
          nxt == (0x63AFBB0, 0x63AFC54), str(nxt))
    check("next padding 12", nxt[0] - END == 12)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 12, pad.hex())
    check("no overlap with 0x63ed090 exclusion",
          END <= 0x63ED090 or START >= 0x63ED862)
    check("no overlap with 0x63ef8e0 exclusion",
          END <= 0x63EF8E0 or START >= 0x63EFBA2)

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 1860", len(hexb) == 1860, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 369", len(lines) == 369, str(len(lines)))
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 6", len(calls) == 6, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63af65f", [addr_of(l) for l in rets] == [0x63AF65F],
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
          ct == [(0x63AF6C8, 0x63D9880), (0x63AF9CD, 0x63D9700),
                 (0x63AFA65, 0x63D9700), (0x63AFAFA, 0x63D9700),
                 (0x63AFB95, 0x63D9700), (0x63AFB9F, 0x63F0D70)],
          str(ct))
    bti = [a for a, t in ct if t == 0x63D9880]
    check("bti sites", bti == [0x63AF6C8], str(bti))
    miss = [a for a, t in ct if t == 0x63D9700]
    check("lu-miss sites",
          miss == [0x63AF9CD, 0x63AFA65, 0x63AFAFA, 0x63AFB95], str(miss))
    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str(len(bsr)))
    locks = [(mnemonic_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))

    by_addr = {addr_of(l): l for l in lines}
    check("entry rcx to r15",
          "mov" in by_addr[0x63AF466] and "%rcx,%r15" in by_addr[0x63AF466])
    check("entry rsi to r14",
          "mov" in by_addr[0x63AF46B] and "%rsi,%r14" in by_addr[0x63AF46B])
    check("entry rdi to r13",
          "mov" in by_addr[0x63AF470] and "%rdi,%r13" in by_addr[0x63AF470])
    check("entry r9 to r12",
          "mov" in by_addr[0x63AF475] and "%r9,%r12" in by_addr[0x63AF475])
    check("walk table lea 0x1b0 rdi to rbp",
          "lea" in by_addr[0x63AF479] and "0x1b0(%rdi),%rbp" in by_addr[0x63AF479])
    check("entry rdx to rbx",
          "mov" in by_addr[0x63AF481] and "%rdx,%rbx" in by_addr[0x63AF481])
    check("frame sub 0x228 rsp",
          "sub" in by_addr[0x63AF484] and "$0x228,%rsp" in by_addr[0x63AF484])
    check("canary at 0x218 rsp",
          "0x218(%rsp)" in by_addr[0x63AF494])
    check("null-context test rdi",
          "test" in by_addr[0x63AF49E] and "%rdi,%rdi" in by_addr[0x63AF49E])
    check("null-context je to site block",
          "je" in by_addr[0x63AF4A1] and "63af6b8" in by_addr[0x63AF4A1])
    check("site lea 0x90 rsp in block",
          "lea" in by_addr[0x63AF6B8] and "0x90(%rsp),%rbp" in by_addr[0x63AF6B8])
    check("site saves r8 to 0x8 rsp",
          "mov" in by_addr[0x63AF6C0] and "%r8,0x8(%rsp)" in by_addr[0x63AF6C0])
    check("site mov rbp to rdi",
          "mov" in by_addr[0x63AF6C5] and "%rbp,%rdi" in by_addr[0x63AF6C5])
    check("site restores r8 from 0x8 rsp",
          "mov" in by_addr[0x63AF6CD] and "0x8(%rsp),%r8" in by_addr[0x63AF6CD])
    check("site rejoin jmp 0x63af4a7",
          "jmp" in by_addr[0x63AF6D2] and "63af4a7" in by_addr[0x63AF6D2])
    check("site block preceded by nopw",
          "nopw" in by_addr[0x63AF667])
    check("bti table temp 0x90 rsp referenced once",
          sum(1 for l in lines if "0x90(%rsp)" in l) == 1,
          str([l for l in lines if "0x90(%rsp)" in l]))
    check("rep stos zeroes 0x10 rsp region",
          "lea" in by_addr[0x63AF4A9] and "0x10(%rsp),%rdi" in by_addr[0x63AF4A9])
    check("rep stos count 0x10 qwords",
          "mov" in by_addr[0x63AF4AE] and "$0x10,%ecx" in by_addr[0x63AF4AE])
    check("rep stos present",
          "rep" in by_addr[0x63AF4B7] and "stos" in by_addr[0x63AF4B7])
    check("entry r8 saved to 0x20 rsp",
          "mov" in by_addr[0x63AF4BA] and "%r8,0x20(%rsp)" in by_addr[0x63AF4BA])
    check("walk1 key saved to 0x18 rsp",
          "mov" in by_addr[0x63AF4BF] and "%rdx,0x18(%rsp)" in by_addr[0x63AF4BF])
    check("zero at 0x60 rsp",
          "movq" in by_addr[0x63AF4C4] and "$0x0,0x60(%rsp)" in by_addr[0x63AF4C4])

    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 61", len(jmps) == 61, str(len(jmps)))
    outside = [(a, t) for a, t in jmps
               if not (START <= t < END)]
    check("jump closure none outside window",
          outside == [], str(outside))
    tg = [a for a, t in jmps if t == 0x63AF6B8]
    check("block 0x63af6b8 single je entry", tg == [0x63AF4A1], str(tg))

    check("canary check sub fs",
          "sub" in by_addr[0x63AF63F] and "%fs:0x28" in by_addr[0x63AF63F])
    check("canary fail jne to stack_chk_fail",
          "jne" in by_addr[0x63AF648] and "63afb9f" in by_addr[0x63AF648])

    check("walk1 key load 0x18 rsp",
          "mov" in by_addr[0x63AF4CD] and "0x18(%rsp),%r11" in by_addr[0x63AF4CD])
    check("walk1 top shr 0x1a",
          "shr" in by_addr[0x63AF4D8] and "$0x1a,%r11" in by_addr[0x63AF4D8])
    check("walk1 top and 0xf0",
          "and" in by_addr[0x63AF4DC] and "$0xf0,%r11d" in by_addr[0x63AF4DC])
    check("walk1 high bits and",
          "and" in by_addr[0x63AF4E3] and "$0xffffffffc0000000,%rax" in by_addr[0x63AF4E3])
    check("walk1 page and",
          "and" in by_addr[0x63AF4E9] and "$0xfffffffffffff000,%r15" in by_addr[0x63AF4E9])
    check("walk1 add table rbp",
          "add" in by_addr[0x63AF4F0] and "%rbp,%r11" in by_addr[0x63AF4F0])
    check("walk1 top compare",
          "cmp" in by_addr[0x63AF4F6] and "%rcx,%rax" in by_addr[0x63AF4F6])
    check("walk1 mismatch jne scan A",
          "jne" in by_addr[0x63AF4F9] and "63af6e0" in by_addr[0x63AF4F9])
    check("walk1 second level shr 0x9",
          "shr" in by_addr[0x63AF4FF] and "$0x9,%r15" in by_addr[0x63AF4FF])
    check("walk1 second level and 0x1ffff8",
          "and" in by_addr[0x63AF503] and "$0x1ffff8,%r15d" in by_addr[0x63AF503])
    check("walk1 second level add table entry",
          "add" in by_addr[0x63AF50A] and "0x8(%r11),%r15" in by_addr[0x63AF50A])
    check("walk1 store to 0x0 rbx",
          "mov" in by_addr[0x63AF511] and "%rax,(%rbx)" in by_addr[0x63AF511])
    check("walk1 second level null test",
          "test" in by_addr[0x63AF514] and "%rax,%rax" in by_addr[0x63AF514])
    check("walk1 null je skips walk2",
          "je" in by_addr[0x63AF517] and "63af573" in by_addr[0x63AF517])

    check("walk2 derived key lea -0x1000",
          "lea" in by_addr[0x63AF531] and "-0x1000(%r11,%r15,1),%rdi" in by_addr[0x63AF531])
    check("walk2 top compare",
          "cmp" in by_addr[0x63AF555] and "%rsi,%rcx" in by_addr[0x63AF555])
    check("walk2 mismatch jne scan B",
          "jne" in by_addr[0x63AF558] and "63af728" in by_addr[0x63AF558])
    check("walk2 second level shr 0x9",
          "shr" in by_addr[0x63AF55E] and "$0x9,%rdi" in by_addr[0x63AF55E])
    check("walk2 second level and 0x1ffff8",
          "and" in by_addr[0x63AF562] and "$0x1ffff8,%edi" in by_addr[0x63AF562])
    check("walk2 second level add table entry",
          "add" in by_addr[0x63AF568] and "0x8(%rax),%rdi" in by_addr[0x63AF568])
    check("walk2 store to 0x8 rbx",
          "mov" in by_addr[0x63AF56F] and "%rax,0x8(%rbx)" in by_addr[0x63AF56F])

    check("walk3 key load 0x8 r12",
          "mov" in by_addr[0x63AF573] and "0x8(%r12),%rax" in by_addr[0x63AF573])
    check("walk3 top compare",
          "cmp" in by_addr[0x63AF59B] and "%rcx,%r11" in by_addr[0x63AF59B])
    check("walk3 mismatch jne scan C",
          "jne" in by_addr[0x63AF59E] and "63af670" in by_addr[0x63AF59E])
    check("walk3 second level shr 0x9",
          "shr" in by_addr[0x63AF5A4] and "$0x9,%rdx" in by_addr[0x63AF5A4])
    check("walk3 second level and 0x1ffff8",
          "and" in by_addr[0x63AF5A8] and "$0x1ffff8,%edx" in by_addr[0x63AF5A8])
    check("walk3 second level add table entry",
          "add" in by_addr[0x63AF5AE] and "0x8(%rax),%rdx" in by_addr[0x63AF5AE])
    check("walk3 store to 0x10 rbx",
          "mov" in by_addr[0x63AF5B5] and "%rax,0x10(%rbx)" in by_addr[0x63AF5B5])
    check("walk3 second level null test",
          "test" in by_addr[0x63AF5B9] and "%rax,%rax" in by_addr[0x63AF5B9])
    check("walk3 null je skips walk4",
          "je" in by_addr[0x63AF5BC] and "63af61b" in by_addr[0x63AF5BC])

    check("walk4 derived key lea -0x1000",
          "lea" in by_addr[0x63AF5D6] and "-0x1000(%rdx,%r12,1),%rcx" in by_addr[0x63AF5D6])
    check("walk4 top compare",
          "cmp" in by_addr[0x63AF5FA] and "%r15,%r11" in by_addr[0x63AF5FA])
    check("walk4 mismatch jne scan D",
          "jne" in by_addr[0x63AF5FD] and "63af770" in by_addr[0x63AF5FD])
    check("walk4 second level shr 0x9",
          "shr" in by_addr[0x63AF603] and "$0x9,%rcx" in by_addr[0x63AF603])
    check("walk4 second level and 0x1ffff8",
          "and" in by_addr[0x63AF60A] and "$0x1ffff8,%edi" in by_addr[0x63AF60A])
    check("walk4 second level add table entry",
          "add" in by_addr[0x63AF610] and "0x8(%rax),%rdi" in by_addr[0x63AF610])
    check("walk4 store to 0x18 rbx",
          "mov" in by_addr[0x63AF617] and "%rax,0x18(%rbx)" in by_addr[0x63AF617])

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

    slotA = [0x63AF6E0, 0x63AF81E, 0x63AF944, 0x63AF957,
             0x63AF96A, 0x63AF97D, 0x63AF990, 0x63AF99D]
    check("scan A all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slotA),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slotA
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan A reversed-operand slots none",
          [a for a in slotA
           if operands_of(by_addr[a]).startswith("%rax,")] == [],
          str([(hex(a), operands_of(by_addr[a])) for a in slotA
               if operands_of(by_addr[a]).startswith("%rax,")]))
    check("scan A slot 7 compares memory directly",
          "cmp" in by_addr[0x63AF99D] and "0x170(%rbp),%rax" in by_addr[0x63AF99D])
    check("scan A slot 1 jne slots chain",
          "jne" in by_addr[0x63AF825] and "63af93e" in by_addr[0x63AF825])
    check("scan A slot 2 je shared mtf",
          "je" in by_addr[0x63AF94B] and "63af82b" in by_addr[0x63AF94B])
    check("scan A slot 0 mtf rejoin jmp 0x63af511",
          "jmp" in by_addr[0x63AF71C] and "63af511" in by_addr[0x63AF71C])
    check("scan A shared mtf rejoin jmp 0x63af706",
          "jmp" in by_addr[0x63AF875] and "63af706" in by_addr[0x63AF875])
    slotB = [0x63AF728, 0x63AF8E2, 0x63AFB0A, 0x63AFB1D,
             0x63AFB30, 0x63AFB43, 0x63AFB56, 0x63AFB63]
    check("scan B all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slotB),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slotB
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan B reversed-operand slots 5 and 6",
          [a for a in slotB
           if operands_of(by_addr[a]).startswith("%rcx,")] == [0x63AFB43, 0x63AFB56],
          str([(hex(a), operands_of(by_addr[a])) for a in slotB
               if operands_of(by_addr[a]).startswith("%rcx,")]))
    check("scan B slot 7 compares memory directly",
          "cmp" in by_addr[0x63AFB63] and "0x170(%rbp),%rcx" in by_addr[0x63AFB63])
    check("scan B slot 1 jne slots chain",
          "jne" in by_addr[0x63AF8E9] and "63afb04" in by_addr[0x63AF8E9])
    check("scan B slot 2 je shared mtf",
          "je" in by_addr[0x63AFB11] and "63af8ef" in by_addr[0x63AFB11])
    check("scan B slot 0 mtf rejoin jmp 0x63af56f",
          "jmp" in by_addr[0x63AF763] and "63af56f" in by_addr[0x63AF763])
    check("scan B shared mtf rejoin jmp 0x63af74e",
          "jmp" in by_addr[0x63AF939] and "63af74e" in by_addr[0x63AF939])
    slotC = [0x63AF670, 0x63AF7B6, 0x63AF9DD, 0x63AF9F0,
             0x63AFA03, 0x63AFA16, 0x63AFA29, 0x63AFA36]
    check("scan C all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slotC),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slotC
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan C reversed-operand slots 3 and 6",
          [a for a in slotC
           if operands_of(by_addr[a]).startswith("%r11,")] == [0x63AF9F0, 0x63AFA29],
          str([(hex(a), operands_of(by_addr[a])) for a in slotC
               if operands_of(by_addr[a]).startswith("%r11,")]))
    check("scan C slot 7 compares memory directly",
          "cmp" in by_addr[0x63AFA36] and "0x170(%rbp),%r11" in by_addr[0x63AFA36])
    check("scan C slot 1 jne slots chain",
          "jne" in by_addr[0x63AF7BD] and "63af9d7" in by_addr[0x63AF7BD])
    check("scan C slot 2 je shared mtf",
          "je" in by_addr[0x63AF9E4] and "63af7c3" in by_addr[0x63AF9E4])
    check("scan C slot 0 mtf rejoin jmp 0x63af5b5",
          "jmp" in by_addr[0x63AF6AC] and "63af5b5" in by_addr[0x63AF6AC])
    check("scan C shared mtf rejoin jmp 0x63af696",
          "jmp" in by_addr[0x63AF80D] and "63af696" in by_addr[0x63AF80D])
    slotD = [0x63AF770, 0x63AF880, 0x63AFA75, 0x63AFA88,
             0x63AFA9B, 0x63AFAAE, 0x63AFAC1, 0x63AFACE]
    check("scan D all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slotD),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slotD
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan D reversed-operand slots none",
          [a for a in slotD
           if operands_of(by_addr[a]).startswith("%r11,")] == [],
          str([(hex(a), operands_of(by_addr[a])) for a in slotD
               if operands_of(by_addr[a]).startswith("%r11,")]))
    check("scan D slot 7 compares memory directly",
          "cmp" in by_addr[0x63AFACE] and "0x170(%rbp),%r11" in by_addr[0x63AFACE])
    check("scan D slot 1 jne slots chain",
          "jne" in by_addr[0x63AF887] and "63afa6f" in by_addr[0x63AF887])
    check("scan D slot 2 je shared mtf",
          "je" in by_addr[0x63AFA7C] and "63af88d" in by_addr[0x63AFA7C])
    check("scan D slot 0 mtf rejoin jmp 0x63af617",
          "jmp" in by_addr[0x63AF7AB] and "63af617" in by_addr[0x63AF7AB])
    check("scan D shared mtf rejoin jmp 0x63af796",
          "jmp" in by_addr[0x63AF8D7] and "63af796" in by_addr[0x63AF8D7])

    check("lu-miss A r9d 1",
          "mov" in by_addr[0x63AF9B8] and "$0x1,%r9d" in by_addr[0x63AF9B8])
    check("lu-miss A r8d 0",
          "xor" in by_addr[0x63AF9BE] and "%r8d,%r8d" in by_addr[0x63AF9BE])
    check("lu-miss A rcx page key1 in r15",
          "mov" in by_addr[0x63AF9C1] and "%r15,%rcx" in by_addr[0x63AF9C1])
    check("lu-miss A rdx scan table rbp",
          "mov" in by_addr[0x63AF9C4] and "%rbp,%rdx" in by_addr[0x63AF9C4])
    check("lu-miss A rsi entry r14",
          "mov" in by_addr[0x63AF9C7] and "%r14,%rsi" in by_addr[0x63AF9C7])
    check("lu-miss A rdi context r13",
          "mov" in by_addr[0x63AF9CA] and "%r13,%rdi" in by_addr[0x63AF9CA])
    check("lu-miss A rejoin jmp 0x63af511",
          "jmp" in by_addr[0x63AF9D2] and "63af511" in by_addr[0x63AF9D2])
    check("lu-miss B rcx derived key in rdi",
          "mov" in by_addr[0x63AFB80] and "%rdi,%rcx" in by_addr[0x63AFB80])
    check("lu-miss B r9d 1",
          "mov" in by_addr[0x63AFB83] and "$0x1,%r9d" in by_addr[0x63AFB83])
    check("lu-miss B r8d 0",
          "xor" in by_addr[0x63AFB89] and "%r8d,%r8d" in by_addr[0x63AFB89])
    check("lu-miss B rdx scan table rbp",
          "mov" in by_addr[0x63AFB8C] and "%rbp,%rdx" in by_addr[0x63AFB8C])
    check("lu-miss B rsi entry r14",
          "mov" in by_addr[0x63AFB8F] and "%r14,%rsi" in by_addr[0x63AFB8F])
    check("lu-miss B rdi context r13",
          "mov" in by_addr[0x63AFB92] and "%r13,%rdi" in by_addr[0x63AFB92])
    check("lu-miss B rejoin jmp 0x63af56f",
          "jmp" in by_addr[0x63AFB9A] and "63af56f" in by_addr[0x63AFB9A])
    check("lu-miss C rcx page key3 in rdx",
          "mov" in by_addr[0x63AFA50] and "%rdx,%rcx" in by_addr[0x63AFA50])
    check("lu-miss C r9d 1",
          "mov" in by_addr[0x63AFA53] and "$0x1,%r9d" in by_addr[0x63AFA53])
    check("lu-miss C r8d 0",
          "xor" in by_addr[0x63AFA59] and "%r8d,%r8d" in by_addr[0x63AFA59])
    check("lu-miss C rdx scan table rbp",
          "mov" in by_addr[0x63AFA5C] and "%rbp,%rdx" in by_addr[0x63AFA5C])
    check("lu-miss C rsi entry r14",
          "mov" in by_addr[0x63AFA5F] and "%r14,%rsi" in by_addr[0x63AFA5F])
    check("lu-miss C rdi context r13",
          "mov" in by_addr[0x63AFA62] and "%r13,%rdi" in by_addr[0x63AFA62])
    check("lu-miss C rejoin jmp 0x63af5b5",
          "jmp" in by_addr[0x63AFA6A] and "63af5b5" in by_addr[0x63AFA6A])
    check("lu-miss D r9d 1",
          "mov" in by_addr[0x63AFAE8] and "$0x1,%r9d" in by_addr[0x63AFAE8])
    check("lu-miss D r8d 0",
          "xor" in by_addr[0x63AFAEE] and "%r8d,%r8d" in by_addr[0x63AFAEE])
    check("lu-miss D rdx scan table rbp",
          "mov" in by_addr[0x63AFAF1] and "%rbp,%rdx" in by_addr[0x63AFAF1])
    check("lu-miss D rsi entry r14",
          "mov" in by_addr[0x63AFAF4] and "%r14,%rsi" in by_addr[0x63AFAF4])
    check("lu-miss D rdi context r13",
          "mov" in by_addr[0x63AFAF7] and "%r13,%rdi" in by_addr[0x63AFAF7])
    check("lu-miss D rcx not set in block, derived key carried",
          not any(",%rcx" in by_addr[a] for a in
                  [0x63AFAE8, 0x63AFAEE, 0x63AFAF1, 0x63AFAF4, 0x63AFAF7]),
          str([by_addr[a] for a in
               [0x63AFAE8, 0x63AFAEE, 0x63AFAF1, 0x63AFAF4, 0x63AFAF7]]))
    check("lu-miss D rejoin jmp 0x63af617",
          "jmp" in by_addr[0x63AFAFF] and "63af617" in by_addr[0x63AFAFF])

    check("epilogue cmpq slot0 null",
          "cmpq" in by_addr[0x63AF61B] and "$0x0,(%rbx)" in by_addr[0x63AF61B])
    check("epilogue je slot0 null to mov 1",
          "je" in by_addr[0x63AF61F] and "63af660" in by_addr[0x63AF61F])
    check("epilogue cmpq slot1 null",
          "cmpq" in by_addr[0x63AF621] and "$0x0,0x8(%rbx)" in by_addr[0x63AF621])
    check("epilogue je slot1 null to mov 1",
          "je" in by_addr[0x63AF626] and "63af660" in by_addr[0x63AF626])
    check("epilogue cmpq slot2 null",
          "cmpq" in by_addr[0x63AF628] and "$0x0,0x10(%rbx)" in by_addr[0x63AF628])
    check("epilogue je slot2 null to mov 1",
          "je" in by_addr[0x63AF62D] and "63af660" in by_addr[0x63AF62D])
    check("epilogue cmpq slot3 null",
          "cmpq" in by_addr[0x63AF62F] and "$0x0,0x18(%rbx)" in by_addr[0x63AF62F])
    check("epilogue sete al slot3 flag",
          "sete" in by_addr[0x63AF634] and "%al" in by_addr[0x63AF634])
    check("epilogue mov 1 eax any null",
          "mov" in by_addr[0x63AF660] and "$0x1,%eax" in by_addr[0x63AF660])
    check("eax writes exact list",
          [addr_of(l) for l in lines if "%eax" in l] ==
          [0x63AF49C, 0x63AF4A7, 0x63AF54A, 0x63AF582,
           0x63AF5EF, 0x63AF660, 0x63AF6A4, 0x63AF714],
          str([hex(addr_of(l)) for l in lines if "%eax" in l]))


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
