#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-sizeclass.

Byte reads only; never executes the node binary. Checks, counted at the end:
base + binary identity, .eh_frame bounds, exhibit bytes, strict/call census,
init-guard (flag byte 0x67125f0, helper 0x63d7bd0), site-block shape
(lea 0x10 rsp via r15, no save/restore, table base lea 0x1b0 rbp),
single-walk extract (shl/sar 0x10 into helper 0x63be550), size class
(small byte-table path, bsr path, huge 0xe8 path, all to 0x8(rsp)),
trylock-guarded update (pthread_mutex_trylock, lock-wait helper 0x63bf680,
vector paddq update, helper 0x63d6690, unlock call, helper 0x63d6880 on
nonzero result, exit-flag byte 0x6717690), single 8-slot scan
(reversed-operand compares tracked: slots 5, 6), one lu-miss site
(rsi 0x6511a00 .bss, rcx entry key via r12 provenance), canary on both
exits (ret + tail jump to 0x63d72b0), jump closure with exactly one
outside target (the tail jump), rel32 targets, rela counts, raw-e8 tiers,
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
                      "RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-sizeclass")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-sizeclass"
NAME = "bintableinit_caller_1walk_extract_sizeclass_1site"
START, END = 0x63C2F00, 0x63C3328

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
    check("target FDE size 1064", END - START == 1064)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x63c2e80..0x63c2f00",
          prev == (0x63C2E80, 0x63C2F00), str(prev))
    check("prev gap 0", START - prev[1] == 0)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 0, gap.hex())
    check("next FDE 0x63c3330..0x63c349b",
          nxt == (0x63C3330, 0x63C349B), str(nxt))
    check("next padding 8", nxt[0] - END == 8)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 8, pad.hex())
    check("no overlap with 0x63ed090 exclusion",
          END <= 0x63ED090 or START >= 0x63ED862)
    check("no overlap with 0x63ef8e0 exclusion",
          END <= 0x63EF8E0 or START >= 0x63EFBA2)

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 1064", len(hexb) == 1064, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 230", len(lines) == 230, str(len(lines)))
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 10", len(calls) == 10, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63c30cf", [addr_of(l) for l in rets] == [0x63C30CF],
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
          ct == [(0x63C2FA3, 0x63BE550), (0x63C2FD7, 0x63F17B0),
                 (0x63C3068, 0x63D6690), (0x63C3086, 0x63F0B70),
                 (0x63C30D0, 0x63D7BD0), (0x63C30ED, 0x63D9880),
                 (0x63C314C, 0x63D6880), (0x63C3163, 0x63BF680),
                 (0x63C3319, 0x63D9700), (0x63C3323, 0x63F0D70)],
          str(ct))
    bti = [a for a, t in ct if t == 0x63D9880]
    check("bti sites", bti == [0x63C30ED], str(bti))
    miss = [a for a, t in ct if t == 0x63D9700]
    check("lu-miss sites", miss == [0x63C3319], str(miss))
    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 1", len(bsr) == 1, str(len(bsr)))
    check("bsr site 0x63c31a1", [addr_of(l) for l in bsr] == [0x63C31A1],
          str([addr_of(l) for l in bsr]))
    locks = [(mnemonic_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))

    by_addr = {addr_of(l): l for l in lines}
    # Entry register mapping + frame.
    check("entry rdx to r14",
          "mov" in by_addr[0x63C2F08] and "%rdx,%r14" in by_addr[0x63C2F08])
    check("entry rcx to r13",
          "mov" in by_addr[0x63C2F0D] and "%rcx,%r13" in by_addr[0x63C2F0D])
    check("entry rsi to r12",
          "mov" in by_addr[0x63C2F12] and "%rsi,%r12" in by_addr[0x63C2F12])
    check("entry rdi to rbp",
          "mov" in by_addr[0x63C2F16] and "%rdi,%rbp" in by_addr[0x63C2F16])
    check("entry r8 to rbx",
          "mov" in by_addr[0x63C2F1A] and "%r8,%rbx" in by_addr[0x63C2F1A])
    check("frame sub 0x1a8 rsp",
          "sub" in by_addr[0x63C2F1D] and "$0x1a8,%rsp" in by_addr[0x63C2F1D])
    check("canary at 0x198 rsp",
          "0x198(%rsp)" in by_addr[0x63C2F2D])
    check("entry xor eax",
          "xor" in by_addr[0x63C2F35] and "%eax,%eax" in by_addr[0x63C2F35])
    # Init-guard (first 1-raw caller with one): flag byte 0x67125f0.
    check("init-guard cmpb 0x67125f0",
          "cmpb" in by_addr[0x63C2F37] and "67125f0" in by_addr[0x63C2F37])
    check("init-guard jne to helper block",
          "jne" in by_addr[0x63C2F3E] and "63c30d0" in by_addr[0x63C2F3E])
    check("init helper call 0x63d7bd0",
          "call" in by_addr[0x63C30D0] and "63d7bd0" in by_addr[0x63C30D0])
    check("init helper re-lea table base",
          "lea" in by_addr[0x63C30D5] and "0x1b0(%rbp),%r15" in by_addr[0x63C30D5])
    check("init helper re-test rbp",
          "test" in by_addr[0x63C30DC] and "%rbp,%rbp" in by_addr[0x63C30DC])
    check("init helper jne rejoin walk",
          "jne" in by_addr[0x63C30DF] and "63c2f54" in by_addr[0x63C30DF])
    check("table base lea 0x1b0 rbp",
          "lea" in by_addr[0x63C2F44] and "0x1b0(%rbp),%r15" in by_addr[0x63C2F44])
    # Null-context site + bti block.
    check("null-context test rbp",
          "test" in by_addr[0x63C2F4B] and "%rbp,%rbp" in by_addr[0x63C2F4B])
    check("null-context je to site block",
          "je" in by_addr[0x63C2F4E] and "63c30e5" in by_addr[0x63C2F4E])
    check("site lea 0x10 rsp in block",
          "lea" in by_addr[0x63C30E5] and "0x10(%rsp),%r15" in by_addr[0x63C30E5])
    check("site mov r15 to rdi",
          "mov" in by_addr[0x63C30EA] and "%r15,%rdi" in by_addr[0x63C30EA])
    check("site rejoin jmp 0x63c2f54",
          "jmp" in by_addr[0x63C30F2] and "63c2f54" in by_addr[0x63C30F2])
    check("site block is exactly lea/mov/call/jmp",
          [mnemonic_of(by_addr[a]) for a in
           sorted(a for a in by_addr if 0x63C30E5 <= a <= 0x63C30F2)] ==
          ["lea", "mov", "call", "jmp"],
          str([hex(a) for a in sorted(a for a in by_addr
               if 0x63C30E5 <= a <= 0x63C30F2)]))
    check("site block has no save/restore",
          not any("0x8(%rsp)" in by_addr[a] or "0x18(%rsp)" in by_addr[a]
                  for a in [0x63C30E5, 0x63C30EA, 0x63C30ED, 0x63C30F2]))
    check("bti table temp 0x10 rsp referenced once",
          sum(1 for l in lines if "0x10(%rsp)" in l) == 1,
          str([l for l in lines if "0x10(%rsp)" in l]))
    check("no rep stos in FDE",
          not any("rep" in l and "stos" in l for l in lines))

    # Jump closure: exactly one outside target, the tail jump.
    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 31", len(jmps) == 31, str(len(jmps)))
    outside = [(a, t) for a, t in jmps
               if not (START <= t < END)]
    check("jump closure exactly one outside (tail jump)",
          outside == [(0x63C3132, 0x63D72B0)], str(outside))
    check("tail jump target 0x63d72b0",
          "63d72b0" in by_addr[0x63C3132])
    tg = [a for a, t in jmps if t == 0x63C30E5]
    check("block 0x63c30e5 single je entry", tg == [0x63C2F4E], str(tg))

    # Walk (single).
    check("walk key mov r12 to rax",
          "mov" in by_addr[0x63C2F54] and "%r12,%rax" in by_addr[0x63C2F54])
    check("walk key mov r12 to rcx",
          "mov" in by_addr[0x63C2F57] and "%r12,%rcx" in by_addr[0x63C2F57])
    check("walk top shr 0x1a",
          "shr" in by_addr[0x63C2F5A] and "$0x1a,%rax" in by_addr[0x63C2F5A])
    check("walk high bits and",
          "and" in by_addr[0x63C2F5E] and "$0xffffffffc0000000,%rcx" in by_addr[0x63C2F5E])
    check("walk top and 0xf0",
          "and" in by_addr[0x63C2F65] and "$0xf0,%eax" in by_addr[0x63C2F65])
    check("walk add table r15",
          "add" in by_addr[0x63C2F6A] and "%r15,%rax" in by_addr[0x63C2F6A])
    check("walk top load",
          "mov" in by_addr[0x63C2F6D] and "(%rax),%rdi" in by_addr[0x63C2F6D])
    check("walk top compare",
          "cmp" in by_addr[0x63C2F70] and "%rdi,%rcx" in by_addr[0x63C2F70])
    check("walk mismatch jne scan",
          "jne" in by_addr[0x63C2F73] and "63c31e0" in by_addr[0x63C2F73])
    check("walk second level shr 0x9",
          "shr" in by_addr[0x63C2F79] and "$0x9,%r12" in by_addr[0x63C2F79])
    check("walk second level and 0x1ffff8",
          "and" in by_addr[0x63C2F7D] and "$0x1ffff8,%r12d" in by_addr[0x63C2F7D])
    check("walk second level add table entry",
          "add" in by_addr[0x63C2F84] and "0x8(%rax),%r12" in by_addr[0x63C2F84])
    check("walk second level mov r12 to rax",
          "mov" in by_addr[0x63C2F88] and "%r12,%rax" in by_addr[0x63C2F88])
    check("walk second level loaded into r12",
          "mov" in by_addr[0x63C2F8B] and "(%rax),%r12" in by_addr[0x63C2F8B])

    # Extract (shl/sar 0x10, then straight into the helper call).
    check("extract mov r14 to rdx",
          "mov" in by_addr[0x63C2F8E] and "%r14,%rdx" in by_addr[0x63C2F8E])
    check("extract mov rbx to rsi",
          "mov" in by_addr[0x63C2F91] and "%rbx,%rsi" in by_addr[0x63C2F91])
    check("extract shl 0x10 r12",
          "shl" in by_addr[0x63C2F94] and "$0x10,%r12" in by_addr[0x63C2F94])
    check("extract sar 0x10 r12",
          "sar" in by_addr[0x63C2F98] and "$0x10,%r12" in by_addr[0x63C2F98])
    check("extract and mask",
          "and" in by_addr[0x63C2F9C] and "$0xffffffffffffff80,%r12" in by_addr[0x63C2F9C])
    check("extract mov r12 to rdi",
          "mov" in by_addr[0x63C2FA0] and "%r12,%rdi" in by_addr[0x63C2FA0])
    check("extract helper call 0x63be550",
          "call" in by_addr[0x63C2FA3] and "63be550" in by_addr[0x63C2FA3])

    # Size class (first 1-raw caller with a size class): three paths,
    # all store the class to 0x8(%rsp), consumed as r8d at 0x63c2ff8.
    check("size cmp 0x1000",
          "cmp" in by_addr[0x63C2FA8] and "$0x1000,%r13" in by_addr[0x63C2FA8])
    check("size ja bsr path",
          "ja" in by_addr[0x63C2FAF] and "63c3178" in by_addr[0x63C2FAF])
    check("small path lea byte table 0x67277c0",
          "lea" in by_addr[0x63C2FB5] and "67277c0" in by_addr[0x63C2FB5])
    check("small path lea 0x7",
          "lea" in by_addr[0x63C2FBC] and "0x7(%r13),%r11" in by_addr[0x63C2FBC])
    check("small path shr 0x3",
          "shr" in by_addr[0x63C2FC0] and "$0x3,%r11" in by_addr[0x63C2FC0])
    check("small path movzbl byte table",
          "movzbl" in by_addr[0x63C2FC4] and "(%r15,%r11,1),%edi" in by_addr[0x63C2FC4])
    check("small path store class 0x8 rsp",
          "mov" in by_addr[0x63C2FC9] and "%edi,0x8(%rsp)" in by_addr[0x63C2FC9])
    check("bsr path movabs threshold",
          "movabs" in by_addr[0x63C3178] and "$0x7000000000000000,%rcx" in by_addr[0x63C3178])
    check("bsr path cmp threshold",
          "cmp" in by_addr[0x63C3182] and "%r13,%rcx" in by_addr[0x63C3182])
    check("bsr path jb huge",
          "jb" in by_addr[0x63C3185] and "63c3220" in by_addr[0x63C3185])
    check("bsr path lea 2x-1",
          "lea" in by_addr[0x63C318B] and "-0x1(%r13,%r13,1),%rax" in by_addr[0x63C318B])
    check("bsr site 0x63c31a1",
          "bsr" in by_addr[0x63C31A1] and "%rax,%r8" in by_addr[0x63C31A1])
    check("bsr path store class 0x8 rsp",
          "mov" in by_addr[0x63C31CC] and "%r10d,0x8(%rsp)" in by_addr[0x63C31CC])
    check("bsr path jmp trylock",
          "jmp" in by_addr[0x63C31D1] and "63c2fcd" in by_addr[0x63C31D1])
    check("huge path movl 0xe8 class",
          "movl" in by_addr[0x63C3220] and "$0xe8,0x8(%rsp)" in by_addr[0x63C3220])
    check("huge path jmp trylock",
          "jmp" in by_addr[0x63C3228] and "63c2fcd" in by_addr[0x63C3228])
    check("size class consumed as r8d",
          "mov" in by_addr[0x63C2FF8] and "0x8(%rsp),%r8d" in by_addr[0x63C2FF8])
    check("no size table 0x6727a00 read",
          not any("0x6727a00" in l for l in lines))
    check("no node table 0x65096c0 read",
          not any("0x65096c0" in l for l in lines))
    check("no node table 0x6511780 read",
          not any("0x6511780" in l for l in lines))

    # Trylock-guarded update.
    check("trylock mutex load rbx",
          "mov" in by_addr[0x63C2FCD] and "(%rbx),%rax" in by_addr[0x63C2FCD])
    check("trylock mutex load rax",
          "mov" in by_addr[0x63C2FD0] and "(%rax),%r15" in by_addr[0x63C2FD0])
    check("trylock mutex lea 0x40 r15",
          "lea" in by_addr[0x63C2FD3] and "0x40(%r15),%rdi" in by_addr[0x63C2FD3])
    check("trylock call is pthread_mutex_trylock",
          "pthread_mutex_trylock" in by_addr[0x63C2FD7])
    check("trylock result test eax",
          "test" in by_addr[0x63C2FDC] and "%eax,%eax" in by_addr[0x63C2FDC])
    check("trylock failure jne lock-wait block",
          "jne" in by_addr[0x63C2FDE] and "63c3160" in by_addr[0x63C2FDE])
    check("lock-wait mov r15 to rdi",
          "mov" in by_addr[0x63C3160] and "%r15,%rdi" in by_addr[0x63C3160])
    check("lock-wait call 0x63bf680",
          "call" in by_addr[0x63C3163] and "63bf680" in by_addr[0x63C3163])
    check("lock-wait sets flag byte 1",
          "movb" in by_addr[0x63C3168] and "$0x1,0x68(%r15)" in by_addr[0x63C3168])
    check("lock-wait rejoins locked section",
          "jmp" in by_addr[0x63C316D] and "63c2fe4" in by_addr[0x63C316D])
    check("locked section addq 0x38 r15",
          "addq" in by_addr[0x63C2FE4] and "$0x1,0x38(%r15)" in by_addr[0x63C2FE4])
    check("locked section owner cmp",
          "cmp" in by_addr[0x63C2FE9] and "0x30(%r15),%rbp" in by_addr[0x63C2FE9])
    check("locked section owner je skip",
          "je" in by_addr[0x63C2FED] and "63c2ff8" in by_addr[0x63C2FED])
    check("locked section owner count",
          "addq" in by_addr[0x63C2FEF] and "$0x1,0x28(%r15)" in by_addr[0x63C2FEF])
    check("locked section owner store",
          "mov" in by_addr[0x63C2FF4] and "%rbp,0x30(%r15)" in by_addr[0x63C2FF4])
    check("vector lea 0x6713620",
          "lea" in by_addr[0x63C300D] and "6713620" in by_addr[0x63C300D])
    check("vector lea 0x6713d60",
          "lea" in by_addr[0x63C301E] and "6713d60" in by_addr[0x63C301E])
    check("vector flag cmpb 0x6713601",
          "cmpb" in by_addr[0x63C3025] and "6713601" in by_addr[0x63C3025])
    check("vector paddq 0x20 store",
          "paddq" in by_addr[0x63C3036] and "%xmm0,%xmm2" in by_addr[0x63C3036]
          and "movups" in by_addr[0x63C303E] and "%xmm2,0x20(%rbx)" in by_addr[0x63C303E])
    check("vector paddq 0x30 store",
          "paddq" in by_addr[0x63C303A] and "%xmm3,%xmm1" in by_addr[0x63C303A]
          and "movups" in by_addr[0x63C3042] and "%xmm1,0x30(%rbx)" in by_addr[0x63C3042])
    check("vector flag je skip 0x40 0x50",
          "je" in by_addr[0x63C3046] and "63c3062" in by_addr[0x63C3046])
    check("vector 0x40 0x50 stores",
          "movups" in by_addr[0x63C305A] and "%xmm0,0x40(%rbx)" in by_addr[0x63C305A]
          and "movups" in by_addr[0x63C305E] and "%xmm5,0x50(%rbx)" in by_addr[0x63C305E])
    check("helper 0x63d6690 call",
          "call" in by_addr[0x63C3068] and "63d6690" in by_addr[0x63C3068])
    check("helper result mov al to 0xf rsp",
          "mov" in by_addr[0x63C3077] and "%al,0xf(%rsp)" in by_addr[0x63C3077])
    check("unlock mov rbx deref to rdi",
          "mov" in by_addr[0x63C307B] and "(%rbx),%rdi" in by_addr[0x63C307B])
    check("unlock clears flag byte",
          "movb" in by_addr[0x63C307E] and "$0x0,0x68(%rdi)" in by_addr[0x63C307E])
    check("unlock add 0x40 rdi",
          "add" in by_addr[0x63C3082] and "$0x40,%rdi" in by_addr[0x63C3082])
    check("unlock call is pthread_mutex_unlock",
          "pthread_mutex_unlock" in by_addr[0x63C3086])
    check("post-unlock result test sil",
          "test" in by_addr[0x63C3090] and "%sil,%sil" in by_addr[0x63C3090])
    check("post-unlock nonzero jne helper 0x63d6880 block",
          "jne" in by_addr[0x63C3093] and "63c3140" in by_addr[0x63C3093])
    check("helper 0x63d6880 call",
          "call" in by_addr[0x63C314C] and "63d6880" in by_addr[0x63C314C])
    check("helper 0x63d6880 block args",
          "mov" in by_addr[0x63C3140] and "%r13,%rcx" in by_addr[0x63C3140]
          and "mov" in by_addr[0x63C3143] and "%r14,%rdx" in by_addr[0x63C3143]
          and "mov" in by_addr[0x63C3146] and "%r12,%rsi" in by_addr[0x63C3146]
          and "mov" in by_addr[0x63C3149] and "%rbp,%rdi" in by_addr[0x63C3149])
    check("helper 0x63d6880 block rejoins flag check",
          "jmp" in by_addr[0x63C3151] and "63c3099" in by_addr[0x63C3151])
    check("exit flag lea 0x6717690",
          "lea" in by_addr[0x63C3099] and "6717690" in by_addr[0x63C3099])
    check("exit flag cmpb",
          "cmpb" in by_addr[0x63C30A0] and "$0x0,0x0(%r13)" in by_addr[0x63C30A0])
    check("exit flag nonzero jne tail path",
          "jne" in by_addr[0x63C30A5] and "63c3100" in by_addr[0x63C30A5])

    # Scan (single 8-slot MTF, table+0x100 in r15, key in rcx).
    slot = [0x63C31E0, 0x63C3236, 0x63C3295, 0x63C32A4,
            0x63C32B3, 0x63C32C2, 0x63C32D5, 0x63C32E2]
    check("scan all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slot),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slot
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan reversed-operand slots 5 and 6",
          [a for a in slot
           if operands_of(by_addr[a]).startswith("%rcx,")] == [0x63C32C2, 0x63C32D5],
          str([(hex(a), operands_of(by_addr[a])) for a in slot
               if operands_of(by_addr[a]).startswith("%rcx,")]))
    check("scan slot 7 compares memory directly",
          "cmp" in by_addr[0x63C32E2] and "0x170(%r15),%rcx" in by_addr[0x63C32E2])
    check("scan slot 0 hit mov top entry",
          "mov" in by_addr[0x63C31E9] and "%rdi,0x100(%r15)" in by_addr[0x63C31E9])
    check("scan slot 0 hit swaps top entry",
          "mov" in by_addr[0x63C31FB] and "%rdi,0x108(%r15)" in by_addr[0x63C31FB])
    check("scan slot 0 hit shr key",
          "shr" in by_addr[0x63C3202] and "$0x9,%r12" in by_addr[0x63C3202])
    check("scan slot 0 hit stores masked key",
          "mov" in by_addr[0x63C3206] and "%rcx,(%rax)" in by_addr[0x63C3206])
    check("scan slot 0 hit recomputes second level",
          "lea" in by_addr[0x63C3214] and "(%rdx,%r12,1),%rax" in by_addr[0x63C3214])
    check("scan slot 0 hit rejoins second-level deref",
          "jmp" in by_addr[0x63C3218] and "63c2f8b" in by_addr[0x63C3218])
    check("scan slot 1 jne slot 2",
          "jne" in by_addr[0x63C323D] and "63c328f" in by_addr[0x63C323D])
    check("scan slots 2-6 je shared mtf",
          all("je" in by_addr[a] and "63c323f" in by_addr[a] for a in
              [0x63C329C, 0x63C32AB, 0x63C32BA, 0x63C32C9, 0x63C32DC]),
          str([(hex(a), by_addr[a]) for a in
               [0x63C329C, 0x63C32AB, 0x63C32BA, 0x63C32C9, 0x63C32DC]
               if "63c323f" not in by_addr[a]]))
    check("scan slot 7 jne lu-miss",
          "jne" in by_addr[0x63C32E9] and "63c3300" in by_addr[0x63C32E9])
    check("scan slot 7 hit sets index 7",
          "mov" in by_addr[0x63C32EB] and "$0x7,%r8d" in by_addr[0x63C32EB])
    check("scan slot 7 hit jmp shared mtf",
          "jmp" in by_addr[0x63C32F1] and "63c323f" in by_addr[0x63C32F1])
    check("scan shared mtf rejoins slot 0 block",
          "jmp" in by_addr[0x63C328A] and "63c3202" in by_addr[0x63C328A])

    # Lu-miss site.
    check("lu-miss lea rsi 0x6511a00 bss",
          "lea" in by_addr[0x63C3300] and "6511a00" in by_addr[0x63C3300])
    check("lu-miss r9d 0",
          "xor" in by_addr[0x63C3307] and "%r9d,%r9d" in by_addr[0x63C3307])
    check("lu-miss rcx entry key",
          "mov" in by_addr[0x63C330A] and "%r12,%rcx" in by_addr[0x63C330A])
    check("lu-miss rcx r12 provenance: entry rsi, writes only on match/hit paths",
          sorted(a for a in by_addr
                 if a < 0x63C3300
                 and operands_of(by_addr[a]).rstrip().endswith(("%r12", "%r12d"))
                 and mnemonic_of(by_addr[a]) in
                 ("mov", "shr", "shl", "sar", "and", "add", "lea", "sub",
                  "xor", "movabs")) ==
          [0x63C2F12, 0x63C2F79, 0x63C2F7D, 0x63C2F84, 0x63C2F8B,
           0x63C2F94, 0x63C2F98, 0x63C2F9C, 0x63C3202, 0x63C3209],
          str([hex(a) for a in sorted(a for a in by_addr
               if a < 0x63C3300
               and operands_of(by_addr[a]).rstrip().endswith(("%r12", "%r12d"))
               and mnemonic_of(by_addr[a]) in
               ("mov", "shr", "shl", "sar", "and", "add", "lea", "sub",
                "xor", "movabs"))]))
    check("lu-miss rdx scan table r15",
          "mov" in by_addr[0x63C330D] and "%r15,%rdx" in by_addr[0x63C330D])
    check("lu-miss r8d 1",
          "mov" in by_addr[0x63C3310] and "$0x1,%r8d" in by_addr[0x63C3310])
    check("lu-miss rdi context rbp",
          "mov" in by_addr[0x63C3316] and "%rbp,%rdi" in by_addr[0x63C3316])
    check("lu-miss rejoin jmp 0x63c2f8b",
          "jmp" in by_addr[0x63C331E] and "63c2f8b" in by_addr[0x63C331E])

    # Exits: ret path + tail-jump path; canary on both.
    check("ret path canary check sub fs",
          "sub" in by_addr[0x63C30AF] and "%fs:0x28" in by_addr[0x63C30AF])
    check("ret path canary fail jne to stack_chk_fail",
          "jne" in by_addr[0x63C30B8] and "63c3323" in by_addr[0x63C30B8])
    check("tail path canary check sub fs",
          "sub" in by_addr[0x63C3108] and "%fs:0x28" in by_addr[0x63C3108])
    check("tail path canary fail jne to stack_chk_fail",
          "jne" in by_addr[0x63C3111] and "63c3323" in by_addr[0x63C3111])
    check("ret path add rsp epilogue",
          "add" in by_addr[0x63C30BE] and "$0x1a8,%rsp" in by_addr[0x63C30BE])
    check("tail path add rsp epilogue",
          "add" in by_addr[0x63C311B] and "$0x1a8,%rsp" in by_addr[0x63C311B])
    check("tail path mov class to esi",
          "mov" in by_addr[0x63C3117] and "0x8(%rsp),%esi" in by_addr[0x63C3117])
    check("tail path mov r14 to rdx",
          "mov" in by_addr[0x63C3122] and "%r14,%rdx" in by_addr[0x63C3122])
    check("tail path mov rbp to rdi",
          "mov" in by_addr[0x63C3125] and "%rbp,%rdi" in by_addr[0x63C3125])
    eax_writes = [addr_of(l) for l in lines
                  if "%eax" in l and mnemonic_of(l) in
                  ("xor", "and", "mov", "movl", "add", "sub", "or", "lea")]
    check("eax writes exact list",
          eax_writes == [0x63C2F35, 0x63C2F65],
          str([hex(a) for a in eax_writes]))


    # .bss section check (own ELF parse): both referenced addresses inside.
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

    bss = None
    for s in secs:
        if secname(s[0]) == ".bss":
            bss = s
    check("bss section 0x64ffe40..0x6728924",
          bss is not None and bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924,
          str(bss))
    for _a in (0x6511A00, 0x67125F0, 0x6713601, 0x6713620, 0x6713D60,
               0x6717690, 0x67277C0):
        check("0x%x inside .bss" % _a,
              bss is not None and bss[3] <= _a < bss[3] + bss[5])

    # rela counts by direct ELF parse
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
    check("priors >= 50000", len(priors) >= 50000, str(len(priors)))
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
