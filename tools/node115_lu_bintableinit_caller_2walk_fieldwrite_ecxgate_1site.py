#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-1site-2walk-fieldwrite-ecxgate.

Byte reads only; never executes the node binary. Checks, counted at the end:
base + binary identity, .eh_frame bounds, exhibit bytes, strict/call census,
site-block shape, ecx==0xe8 early return, two-walk field write (second walk
gated on r8b != 0 and page(0x10) > 0x1000; the two composed writes differ:
the first ORs in r8b, the second ORs in constant 1), two 8-slot scans
(reversed-operand compares tracked), canary, jump closure, rel32 targets,
rela counts, raw-e8 tiers, disjointness over every exhibit range, slug
uniqueness, MANIFEST.
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
                      "RE-001-node115-lu-bintableinit-caller-1site-2walk-fieldwrite-ecxgate")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-1site-2walk-fieldwrite-ecxgate"
NAME = "bintableinit_caller_2walk_fieldwrite_ecxgate_1site"
START, END = 0x63AEFE0, 0x63AF45F

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
    check("target FDE size 1151", END - START == 1151)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x63aed40..0x63aefdb",
          prev == (0x63AED40, 0x63AEFDB), str(prev))
    check("prev gap 5", START - prev[1] == 5)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 5, gap.hex())
    check("next FDE 0x63af460..0x63afba4",
          nxt == (0x63AF460, 0x63AFBA4), str(nxt))
    check("next padding 1", nxt[0] - END == 1)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 1, pad.hex())
    check("no overlap with 0x63ed090 exclusion",
          END <= 0x63ED090 or START >= 0x63ED862)
    check("no overlap with 0x63ef8e0 exclusion",
          END <= 0x63EF8E0 or START >= 0x63EFBA2)

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 1151", len(hexb) == 1151, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 243", len(lines) == 243, str(len(lines)))
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 4", len(calls) == 4, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63af0e9", [addr_of(l) for l in rets] == [0x63AF0E9],
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
          ct == [(0x63AF198, 0x63D9880), (0x63AF3A8, 0x63D9700),
                 (0x63AF3BF, 0x63F0D70), (0x63AF44D, 0x63D9700)],
          str(ct))
    bti = [a for a, t in ct if t == 0x63D9880]
    check("bti sites", bti == [0x63AF198], str(bti))
    miss = [a for a, t in ct if t == 0x63D9700]
    check("lu-miss sites", miss == [0x63AF3A8, 0x63AF44D], str(miss))
    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str(len(bsr)))
    locks = [(mnemonic_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))

    by_addr = {addr_of(l): l for l in lines}
    check("entry rsi to r15",
          "mov" in by_addr[0x63AEFE6] and "%rsi,%r15" in by_addr[0x63AEFE6])
    check("entry r8d to r14d",
          "mov" in by_addr[0x63AEFEB] and "%r8d,%r14d" in by_addr[0x63AEFEB])
    check("entry ecx to r12d",
          "mov" in by_addr[0x63AEFF2] and "%ecx,%r12d" in by_addr[0x63AEFF2])
    check("entry rdi to rbp",
          "mov" in by_addr[0x63AEFF6] and "%rdi,%rbp" in by_addr[0x63AEFF6])
    check("entry rdx to rbx",
          "mov" in by_addr[0x63AEFFA] and "%rdx,%rbx" in by_addr[0x63AEFFA])
    check("site lea 0x10 rsp in block",
          "lea" in by_addr[0x63AF190] and "0x10(%rsp),%r13" in by_addr[0x63AF190])
    check("site mov r13 to rdi",
          "mov" in by_addr[0x63AF195] and "%r13,%rdi" in by_addr[0x63AF195])
    check("site restore rdx from r13",
          "mov" in by_addr[0x63AF19D] and "%r13,%rdx" in by_addr[0x63AF19D])
    check("site rejoin jmp 0x63af027",
          "jmp" in by_addr[0x63AF1A0] and "63af027" in by_addr[0x63AF1A0])
    check("site block preceded by nopw",
          "nopw" in by_addr[0x63AF187])
    check("null-context test je to site block",
          "je" in by_addr[0x63AF021] and "63af190" in by_addr[0x63AF021])

    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 35", len(jmps) == 35, str(len(jmps)))
    outside = [(a, t) for a, t in jmps
               if not (START <= t < END)]
    check("jump closure none outside window",
          outside == [], str(outside))
    tg = [a for a, t in jmps if t == 0x63AF190]
    check("block 0x63af190 single je entry", tg == [0x63AF021], str(tg))

    check("canary at 0x198 rsp",
          "0x198(%rsp)" in by_addr[0x63AF014])
    check("canary check sub fs",
          "sub" in by_addr[0x63AF0C9] and "%fs:0x28" in by_addr[0x63AF0C9])
    check("canary fail jne to stack_chk_fail",
          any(a == 0x63AF0D2 and t == 0x63AF3BF for a, t in jmps))

    check("walk lea 0x1b0",
          "lea" in by_addr[0x63AEFFD] and "0x1b0(%rdi)" in by_addr[0x63AEFFD])
    check("no size table 0x6727a00 read",
          not any("6727a00" in l for l in lines))
    check("no threshold table 0x67277c0 read",
          not any("67277c0" in l for l in lines))
    check("no node-resolution table 0x65096c0",
          not any("65096c0" in l for l in lines))
    check("no 0x6511780 table read",
          not any("6511780" in l for l in lines))
    check("no shl/sar 0x10 match transform",
          not any(re.search(r"\t(shl|sar)\s+\$0x10,", l) for l in lines))

    check("ecx gate cmp 0xe8",
          "cmp" in by_addr[0x63AF027] and "$0xe8,%r12d" in by_addr[0x63AF027])
    check("ecx gate je epilogue",
          "je" in by_addr[0x63AF02E] and "63af0c1" in by_addr[0x63AF02E])

    check("phase1 key load 0x8 rbx",
          "mov" in by_addr[0x63AF034] and "0x8(%rbx),%rcx" in by_addr[0x63AF034])
    check("phase1 struct load",
          "mov" in by_addr[0x63AF038] and "(%rbx),%r13" in by_addr[0x63AF038])
    check("phase1 top shr 0x1a",
          "shr" in by_addr[0x63AF048] and "$0x1a,%rax" in by_addr[0x63AF048])
    check("phase1 high bits and",
          "and" in by_addr[0x63AF050] and "$0xffffffffc0000000,%rsi" in by_addr[0x63AF050])
    check("phase1 top and 0xf0",
          "and" in by_addr[0x63AF05B] and "$0xf0,%eax" in by_addr[0x63AF05B])
    check("phase1 top compare",
          "cmp" in by_addr[0x63AF06A] and "%rdi,%rsi" in by_addr[0x63AF06A])
    check("phase1 mismatch jne scan A",
          "jne" in by_addr[0x63AF06D] and "63af1a8" in by_addr[0x63AF06D])
    check("phase1 second level shr 0x9",
          "shr" in by_addr[0x63AF073] and "$0x9,%rcx" in by_addr[0x63AF073])
    check("phase1 second level and 0x1ffff8",
          "and" in by_addr[0x63AF077] and "$0x1ffff8,%ecx" in by_addr[0x63AF077])
    check("phase1 second level add table entry",
          "add" in by_addr[0x63AF07D] and "0x8(%rax),%rcx" in by_addr[0x63AF07D])
    check("phase1 second level null test",
          "test" in by_addr[0x63AF081] and "%rcx,%rcx" in by_addr[0x63AF081])
    check("phase1 second level null je skip write",
          "je" in by_addr[0x63AF084] and "63af0bc" in by_addr[0x63AF084])

    check("write1 movzbl r14b",
          "movzbl" in by_addr[0x63AF086] and "%r14b,%r11d" in by_addr[0x63AF086])
    check("write1 shl 0x30 ecx",
          "shl" in by_addr[0x63AF09E] and "$0x30,%rdi" in by_addr[0x63AF09E])
    check("write1 lea r13 times 4",
          "lea" in by_addr[0x63AF0A2] and "0x0(,%r13,4),%rsi" in by_addr[0x63AF0A2])
    check("write1 add r8 r8 bit double",
          "add" in by_addr[0x63AF0AA] and "%r8,%r8" in by_addr[0x63AF0AA])
    check("write1 movabs mask",
          "movabs" in by_addr[0x63AF091] and "$0xffffffffffff,%rax" in by_addr[0x63AF091])
    check("write1 store to second level",
          "mov" in by_addr[0x63AF0B9] and "%rax,(%rcx)" in by_addr[0x63AF0B9])

    check("second walk gate test r14b",
          "test" in by_addr[0x63AF0BC] and "%r14b,%r14b" in by_addr[0x63AF0BC])
    check("second walk gate jne second walk",
          "jne" in by_addr[0x63AF0BF] and "63af0f0" in by_addr[0x63AF0BF])

    check("second walk page load 0x10 rbx",
          "mov" in by_addr[0x63AF0F0] and "0x10(%rbx),%r14" in by_addr[0x63AF0F0])
    check("second walk page mask",
          "and" in by_addr[0x63AF0F4] and "$0xfffffffffffff000,%r14" in by_addr[0x63AF0F4])
    check("second walk cmp 0x1000",
          "cmp" in by_addr[0x63AF0FB] and "$0x1000,%r14" in by_addr[0x63AF0FB])
    check("second walk jbe epilogue",
          "jbe" in by_addr[0x63AF102] and "63af0c1" in by_addr[0x63AF102])
    check("second walk derived key lea -0x1000",
          "lea" in by_addr[0x63AF10F] and "-0x1000(%r14,%rcx,1),%rsi" in by_addr[0x63AF10F])
    check("second walk top compare",
          "cmp" in by_addr[0x63AF133] and "%r8,%rdi" in by_addr[0x63AF133])
    check("second walk mismatch jne scan B",
          "jne" in by_addr[0x63AF136] and "63af1e8" in by_addr[0x63AF136])
    check("second walk second level null test",
          "test" in by_addr[0x63AF14D] and "%rdx,%rdx" in by_addr[0x63AF14D])
    check("second walk second level null je epilogue",
          "je" in by_addr[0x63AF150] and "63af0c1" in by_addr[0x63AF150])

    check("write2 shl 0x30 r12",
          "shl" in by_addr[0x63AF156] and "$0x30,%r12" in by_addr[0x63AF156])
    check("write2 shl 0x2 r13",
          "shl" in by_addr[0x63AF15A] and "$0x2,%r13" in by_addr[0x63AF15A])
    check("write2 movabs mask",
          "movabs" in by_addr[0x63AF15E] and "$0xffffffffffff,%rdi" in by_addr[0x63AF15E])
    check("write2 or constant 1",
          "or" in by_addr[0x63AF17B] and "$0x1,%rdi" in by_addr[0x63AF17B])
    check("write2 store to second level",
          "mov" in by_addr[0x63AF17F] and "%rdi,(%rdx)" in by_addr[0x63AF17F])

    slotA = [0x63AF1A8, 0x63AF22E, 0x63AF323, 0x63AF336,
             0x63AF349, 0x63AF35C, 0x63AF36F, 0x63AF37C]
    check("scan A all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slotA),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slotA
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan A reversed-operand slots none",
          [a for a in slotA
           if operands_of(by_addr[a]).startswith("%rsi,")] == [],
          str([(hex(a), operands_of(by_addr[a])) for a in slotA
               if operands_of(by_addr[a]).startswith("%rsi,")]))
    check("scan A slot 7 compares memory directly",
          "cmp" in by_addr[0x63AF37C] and "0x170(%rdx),%rsi" in by_addr[0x63AF37C])
    check("scan A slot 1 jne slots chain",
          "jne" in by_addr[0x63AF235] and "63af31d" in by_addr[0x63AF235])
    check("scan A slot 2 je shared mtf",
          "je" in by_addr[0x63AF32A] and "63af23b" in by_addr[0x63AF32A])
    check("scan A slot 0 mtf rejoin jmp 0x63af081",
          "jmp" in by_addr[0x63AF1DE] and "63af081" in by_addr[0x63AF1DE])
    check("scan A shared mtf rejoin jmp 0x63af081",
          "jmp" in by_addr[0x63AF2A1] and "63af081" in by_addr[0x63AF2A1])
    slotB = [0x63AF1E8, 0x63AF2AC, 0x63AF3CA, 0x63AF3DD,
             0x63AF3F0, 0x63AF403, 0x63AF416, 0x63AF423]
    check("scan B all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slotB),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slotB
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan B reversed-operand slots none",
          [a for a in slotB
           if operands_of(by_addr[a]).startswith("%rdi,")] == [],
          str([(hex(a), operands_of(by_addr[a])) for a in slotB
               if operands_of(by_addr[a]).startswith("%rdi,")]))
    check("scan B slot 7 compares memory directly",
          "cmp" in by_addr[0x63AF423] and "0x170(%rdx),%rdi" in by_addr[0x63AF423])
    check("scan B slot 1 jne slots chain",
          "jne" in by_addr[0x63AF2B3] and "63af3c4" in by_addr[0x63AF2B3])
    check("scan B slot 2 je shared mtf",
          "je" in by_addr[0x63AF3D1] and "63af2b9" in by_addr[0x63AF3D1])
    check("scan B slot 0 mtf rejoin jmp 0x63af14d",
          "jmp" in by_addr[0x63AF223] and "63af14d" in by_addr[0x63AF223])
    check("scan B shared mtf rejoin jmp 0x63af14d",
          "jmp" in by_addr[0x63AF318] and "63af14d" in by_addr[0x63AF318])

    check("lu-miss A r9d 1",
          "mov" in by_addr[0x63AF390] and "$0x1,%r9d" in by_addr[0x63AF390])
    check("lu-miss A r8d 0",
          "xor" in by_addr[0x63AF396] and "%r8d,%r8d" in by_addr[0x63AF396])
    check("lu-miss A rsi entry r15",
          "mov" in by_addr[0x63AF399] and "%r15,%rsi" in by_addr[0x63AF399])
    check("lu-miss A rdi context rbp",
          "mov" in by_addr[0x63AF39C] and "%rbp,%rdi" in by_addr[0x63AF39C])
    check("lu-miss A save r10b to stack",
          "mov" in by_addr[0x63AF39F] and "%r10b,0xf(%rsp)" in by_addr[0x63AF39F])
    check("lu-miss A save table rdx to stack",
          "mov" in by_addr[0x63AF3A4] and "%rdx,(%rsp)" in by_addr[0x63AF3A4])
    check("lu-miss A restore r10b from stack",
          "movzbl" in by_addr[0x63AF3AD] and "0xf(%rsp),%r10d" in by_addr[0x63AF3AD])
    check("lu-miss A restore table rdx from stack",
          "mov" in by_addr[0x63AF3B3] and "(%rsp),%rdx" in by_addr[0x63AF3B3])
    check("lu-miss A return to rcx",
          "mov" in by_addr[0x63AF3B7] and "%rax,%rcx" in by_addr[0x63AF3B7])
    check("lu-miss A rejoin jmp 0x63af081",
          "jmp" in by_addr[0x63AF3BA] and "63af081" in by_addr[0x63AF3BA])

    check("lu-miss B rcx derived key",
          "mov" in by_addr[0x63AF437] and "%rsi,%rcx" in by_addr[0x63AF437])
    check("lu-miss B r9d 1",
          "mov" in by_addr[0x63AF43A] and "$0x1,%r9d" in by_addr[0x63AF43A])
    check("lu-miss B r8d 0",
          "xor" in by_addr[0x63AF440] and "%r8d,%r8d" in by_addr[0x63AF440])
    check("lu-miss B rsi entry r15",
          "mov" in by_addr[0x63AF443] and "%r15,%rsi" in by_addr[0x63AF443])
    check("lu-miss B rdi context rbp",
          "mov" in by_addr[0x63AF446] and "%rbp,%rdi" in by_addr[0x63AF446])
    check("lu-miss B save r10b to stack",
          "mov" in by_addr[0x63AF449] and "%r10b,(%rsp)" in by_addr[0x63AF449])
    check("lu-miss B restore r10b from stack",
          "movzbl" in by_addr[0x63AF452] and "(%rsp),%r10d" in by_addr[0x63AF452])
    check("lu-miss B return to rdx",
          "mov" in by_addr[0x63AF457] and "%rax,%rdx" in by_addr[0x63AF457])
    check("lu-miss B rejoin jmp 0x63af14d",
          "jmp" in by_addr[0x63AF45A] and "63af14d" in by_addr[0x63AF45A])

    check("eax zero at entry",
          "xor" in by_addr[0x63AF01C] and "%eax,%eax" in by_addr[0x63AF01C])
    check("eax writes are entry xor plus two top-index ands",
          [addr_of(l) for l in lines if "%eax" in l] ==
          [0x63AF01C, 0x63AF05B, 0x63AF128],
          str([hex(addr_of(l)) for l in lines if "%eax" in l]))
    check("epilogue rax writes are only the canary pair",
          [addr_of(l) for l in lines
           if 0x63AF0C1 <= addr_of(l) <= 0x63AF0E9 and "%rax" in l] ==
          [0x63AF0C1, 0x63AF0C9],
          str([hex(addr_of(l)) for l in lines
               if 0x63AF0C1 <= addr_of(l) <= 0x63AF0E9 and "%rax" in l]))

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
