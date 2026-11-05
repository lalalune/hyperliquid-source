#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-trylock.

Byte reads only; never executes the node binary. Checks, counted at the end:
base + binary identity, .eh_frame bounds, exhibit bytes, strict/call census,
site-block shape (lea 0x20 rsp, rsi/r10/rdi save/restore, table base in rdi),
single-walk extract (shl/sar 0x10, zero/flag/index paths, node tables read),
trylock-guarded update (pthread_mutex_trylock, lock-wait helper 0x63bf680,
fallback helper 0x63abd00, tail-jump unlock exit), single 8-slot scan
(reversed-operand compares tracked: slots 3, 6), one lu-miss site
(rsi 0x6511a00 .bss, rcx entry key), canary on both exits, jump closure with
exactly one outside target (the unlock tail jump), rel32 targets, rela counts,
raw-e8 tiers, disjointness over every exhibit range, slug uniqueness, MANIFEST.
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
                      "RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-trylock")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-1site-1walk-extract-trylock"
NAME = "bintableinit_caller_1walk_extract_trylock_1site"
START, END = 0x63BC730, 0x63BCB12

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
    check("target FDE size 994", END - START == 994)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x63bc490..0x63bc728",
          prev == (0x63BC490, 0x63BC728), str(prev))
    check("prev gap 8", START - prev[1] == 8)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 8, gap.hex())
    check("next FDE 0x63bcb20..0x63bcb77",
          nxt == (0x63BCB20, 0x63BCB77), str(nxt))
    check("next padding 14", nxt[0] - END == 14)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 14, pad.hex())
    check("no overlap with 0x63ed090 exclusion",
          END <= 0x63ED090 or START >= 0x63ED862)
    check("no overlap with 0x63ef8e0 exclusion",
          END <= 0x63EF8E0 or START >= 0x63EFBA2)

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 994", len(hexb) == 994, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 212", len(lines) == 212, str(len(lines)))
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 6", len(calls) == 6, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63bc83e", [addr_of(l) for l in rets] == [0x63BC83E],
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
          ct == [(0x63BC8B9, 0x63F17B0), (0x63BC943, 0x63BF680),
                 (0x63BC9EC, 0x63D9880), (0x63BCA0F, 0x63ABD00),
                 (0x63BCAFE, 0x63D9700), (0x63BCB0D, 0x63F0D70)],
          str(ct))
    bti = [a for a, t in ct if t == 0x63D9880]
    check("bti sites", bti == [0x63BC9EC], str(bti))
    miss = [a for a, t in ct if t == 0x63D9700]
    check("lu-miss sites", miss == [0x63BCAFE], str(miss))
    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str(len(bsr)))
    locks = [(mnemonic_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))

    by_addr = {addr_of(l): l for l in lines}
    # Entry register mapping + frame.
    check("entry rdx to r15",
          "mov" in by_addr[0x63BC736] and "%rdx,%r15" in by_addr[0x63BC736])
    check("entry r9 to r13",
          "mov" in by_addr[0x63BC73D] and "%r9,%r13" in by_addr[0x63BC73D])
    check("entry rcx to r12",
          "mov" in by_addr[0x63BC742] and "%rcx,%r12" in by_addr[0x63BC742])
    check("entry rdi to rbp",
          "mov" in by_addr[0x63BC746] and "%rdi,%rbp" in by_addr[0x63BC746])
    check("walk table add 0x1b0 rdi (overwrites rdi)",
          "add" in by_addr[0x63BC749] and "$0x1b0,%rdi" in by_addr[0x63BC749])
    check("entry r8 to rbx",
          "mov" in by_addr[0x63BC751] and "%r8,%rbx" in by_addr[0x63BC751])
    check("frame sub 0x1b8 rsp",
          "sub" in by_addr[0x63BC754] and "$0x1b8,%rsp" in by_addr[0x63BC754])
    check("canary at 0x1a8 rsp",
          "0x1a8(%rsp)" in by_addr[0x63BC764])
    check("entry xor eax",
          "xor" in by_addr[0x63BC76C] and "%eax,%eax" in by_addr[0x63BC76C])
    check("stack arg 0x1f0 rsp to r10",
          "mov" in by_addr[0x63BC76E] and "0x1f0(%rsp),%r10" in by_addr[0x63BC76E])
    check("stack arg 0x1f8 rsp to r14",
          "mov" in by_addr[0x63BC776] and "0x1f8(%rsp),%r14" in by_addr[0x63BC776])
    # Null-context site + bti block.
    check("null-context test rbp",
          "test" in by_addr[0x63BC77E] and "%rbp,%rbp" in by_addr[0x63BC77E])
    check("null-context je to site block",
          "je" in by_addr[0x63BC781] and "63bc9d8" in by_addr[0x63BC781])
    check("site lea 0x20 rsp in block",
          "lea" in by_addr[0x63BC9D8] and "0x20(%rsp),%rdi" in by_addr[0x63BC9D8])
    check("site saves r10 to 0x18 rsp",
          "mov" in by_addr[0x63BC9DD] and "%r10,0x18(%rsp)" in by_addr[0x63BC9DD])
    check("site saves rsi to 0x10 rsp",
          "mov" in by_addr[0x63BC9E2] and "%rsi,0x10(%rsp)" in by_addr[0x63BC9E2])
    check("site saves rdi to 0x8 rsp",
          "mov" in by_addr[0x63BC9E7] and "%rdi,0x8(%rsp)" in by_addr[0x63BC9E7])
    check("site restores rdi from 0x8 rsp",
          "mov" in by_addr[0x63BC9F1] and "0x8(%rsp),%rdi" in by_addr[0x63BC9F1])
    check("site restores r10 from 0x18 rsp",
          "mov" in by_addr[0x63BC9F6] and "0x18(%rsp),%r10" in by_addr[0x63BC9F6])
    check("site restores rsi from 0x10 rsp",
          "mov" in by_addr[0x63BC9FB] and "0x10(%rsp),%rsi" in by_addr[0x63BC9FB])
    check("site rejoin jmp 0x63bc787",
          "jmp" in by_addr[0x63BCA00] and "63bc787" in by_addr[0x63BCA00])
    check("site block preceded by nopl",
          "nopl" in by_addr[0x63BC9D1])
    check("bti table temp 0x20 rsp referenced once",
          sum(1 for l in lines if "0x20(%rsp)" in l) == 1,
          str([l for l in lines if "0x20(%rsp)" in l]))
    check("no rep stos in FDE",
          not any("rep" in l and "stos" in l for l in lines))

    # Jump closure: exactly one outside target, the unlock tail jump.
    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 27", len(jmps) == 27, str(len(jmps)))
    outside = [(a, t) for a, t in jmps
               if not (START <= t < END)]
    check("jump closure exactly one outside (unlock tail jump)",
          outside == [(0x63BC93B, 0x63F0B70)], str(outside))
    check("unlock tail jump is pthread_mutex_unlock",
          "pthread_mutex_unlock" in by_addr[0x63BC93B])
    tg = [a for a, t in jmps if t == 0x63BC9D8]
    check("block 0x63bc9d8 single je entry", tg == [0x63BC781], str(tg))

    # Walk (single).
    check("walk key mov rsi to rax",
          "mov" in by_addr[0x63BC787] and "%rsi,%rax" in by_addr[0x63BC787])
    check("walk key mov rsi to r8",
          "mov" in by_addr[0x63BC78A] and "%rsi,%r8" in by_addr[0x63BC78A])
    check("walk top shr 0x1a",
          "shr" in by_addr[0x63BC78D] and "$0x1a,%rax" in by_addr[0x63BC78D])
    check("walk high bits and",
          "and" in by_addr[0x63BC791] and "$0xffffffffc0000000,%r8" in by_addr[0x63BC791])
    check("walk top and 0xf0",
          "and" in by_addr[0x63BC798] and "$0xf0,%eax" in by_addr[0x63BC798])
    check("walk add table rdi",
          "add" in by_addr[0x63BC79D] and "%rdi,%rax" in by_addr[0x63BC79D])
    check("walk top compare",
          "cmp" in by_addr[0x63BC7A3] and "%rcx,%r8" in by_addr[0x63BC7A3])
    check("walk mismatch jne scan",
          "jne" in by_addr[0x63BC7A6] and "63bc960" in by_addr[0x63BC7A6])
    check("walk second level shr 0x9",
          "shr" in by_addr[0x63BC7AC] and "$0x9,%rsi" in by_addr[0x63BC7AC])
    check("walk second level and 0x1ffff8",
          "and" in by_addr[0x63BC7B0] and "$0x1ffff8,%esi" in by_addr[0x63BC7B0])
    check("walk second level add table entry",
          "add" in by_addr[0x63BC7B6] and "0x8(%rax),%rsi" in by_addr[0x63BC7B6])
    check("walk second level loaded into rdi",
          "mov" in by_addr[0x63BC7BD] and "(%rax),%rdi" in by_addr[0x63BC7BD])

    # Extract.
    check("extract shl 0x10 rdi",
          "shl" in by_addr[0x63BC7C0] and "$0x10,%rdi" in by_addr[0x63BC7C0])
    check("extract mov rdi to r8",
          "mov" in by_addr[0x63BC7C4] and "%rdi,%r8" in by_addr[0x63BC7C4])
    check("extract sar 0x10 r8",
          "sar" in by_addr[0x63BC7C7] and "$0x10,%r8" in by_addr[0x63BC7C7])
    check("extract and mask",
          "and" in by_addr[0x63BC7CB] and "$0xffffffffffffff80,%r8" in by_addr[0x63BC7CB])
    check("extract small value cmp",
          "cmp" in by_addr[0x63BC7CF] and "$0x7fffff,%rdi" in by_addr[0x63BC7CF])
    check("extract zero path jbe",
          "jbe" in by_addr[0x63BC7D6] and "63bc9a0" in by_addr[0x63BC7D6])
    check("extract page load node+0x10",
          "mov" in by_addr[0x63BC7DC] and "0x10(%r8),%rax" in by_addr[0x63BC7DC])
    check("extract page mask",
          "and" in by_addr[0x63BC7E0] and "$0xfffffffffffff000,%rax" in by_addr[0x63BC7E0])
    check("extract page store to rbx output",
          "mov" in by_addr[0x63BC7E6] and "%rax,(%rbx)" in by_addr[0x63BC7E6])
    check("extract descriptor load",
          "mov" in by_addr[0x63BC7E9] and "(%r8),%rbx" in by_addr[0x63BC7E9])
    check("extract flag test bit 12",
          "test" in by_addr[0x63BC7EC] and "$0x10,%bh" in by_addr[0x63BC7EC])
    check("extract flag path jne index",
          "jne" in by_addr[0x63BC7EF] and "63bc840" in by_addr[0x63BC7EF])
    check("extract zero path stores six zeros",
          all("movq" in by_addr[a] and "$0x0" in by_addr[a] for a in
              [0x63BC9A0, 0x63BC9A7, 0x63BC9AF, 0x63BC9B6, 0x63BC9BE, 0x63BC9C5]))
    check("extract zero path rejoins epilogue",
          "jmp" in by_addr[0x63BC9CC] and "63bc816" in by_addr[0x63BC9CC])
    check("extract flag path stores zero/one",
          "movq" in by_addr[0x63BC7F1] and "$0x0,(%r10)" in by_addr[0x63BC7F1]
          and "movq" in by_addr[0x63BC807] and "$0x1,(%r12)" in by_addr[0x63BC807])
    check("extract index shr 0x1c",
          "shr" in by_addr[0x63BC840] and "$0x1c,%rbx" in by_addr[0x63BC840])
    check("extract index and 0x3ff",
          "and" in by_addr[0x63BC850] and "$0x3ff,%ebx" in by_addr[0x63BC850])
    check("extract index store to r15 output",
          "mov" in by_addr[0x63BC856] and "%rbx,(%r15)" in by_addr[0x63BC856])
    check("extract table lea 0x6711b40",
          "lea" in by_addr[0x63BC849] and "6711b40" in by_addr[0x63BC849])
    check("extract byte index shr 0x14",
          "shr" in by_addr[0x63BC85C] and "$0x14,%r15" in by_addr[0x63BC85C])
    check("extract table field to r12 output",
          "mov" in by_addr[0x63BC870] and "%rcx,(%r12)" in by_addr[0x63BC870])
    # Node-resolution tables are read on the index path.
    check("node table 0x65096c0 lea",
          "lea" in by_addr[0x63BC877] and "65096c0" in by_addr[0x63BC877])
    check("node table 0x6511780 lea",
          "lea" in by_addr[0x63BC892] and "6511780" in by_addr[0x63BC892])
    check("node index shr 0x26",
          "shr" in by_addr[0x63BC881] and "$0x26,%rdi" in by_addr[0x63BC881])
    check("node index and 0xfff",
          "and" in by_addr[0x63BC885] and "$0xfff,%esi" in by_addr[0x63BC885])
    check("node mutex lea 0x40 rbx",
          "lea" in by_addr[0x63BC8B2] and "0x40(%rbx),%r15" in by_addr[0x63BC8B2])
    check("no size table 0x6727a00 read",
          not any("0x6727a00" in l for l in lines))
    check("no threshold table 0x67277c0 read",
          not any("0x67277c0" in l for l in lines))

    # Trylock-guarded update.
    check("trylock call is pthread_mutex_trylock",
          "pthread_mutex_trylock" in by_addr[0x63BC8B9])
    check("trylock result test eax",
          "test" in by_addr[0x63BC8C3] and "%eax,%eax" in by_addr[0x63BC8C3])
    check("trylock failure jne lock-wait block",
          "jne" in by_addr[0x63BC8C5] and "63bc940" in by_addr[0x63BC8C5])
    check("lock-wait call 0x63bf680",
          "call" in by_addr[0x63BC943] and "63bf680" in by_addr[0x63BC943])
    check("lock-wait sets flag byte 1",
          "movb" in by_addr[0x63BC948] and "$0x1,0x68(%rbx)" in by_addr[0x63BC948])
    check("lock-wait rejoins locked section",
          "jmp" in by_addr[0x63BC951] and "63bc8c7" in by_addr[0x63BC951])
    check("locked section addq 0x38 rbx",
          "addq" in by_addr[0x63BC8C7] and "$0x1,0x38(%rbx)" in by_addr[0x63BC8C7])
    check("locked section owner cmp",
          "cmp" in by_addr[0x63BC8CC] and "0x30(%rbx),%rbp" in by_addr[0x63BC8CC])
    check("locked section owner je skip",
          "je" in by_addr[0x63BC8D0] and "63bc8db" in by_addr[0x63BC8D0])
    check("locked section imul 0xb0",
          "imul" in by_addr[0x63BC8DF] and "0xb0(%rbx),%rbp" in by_addr[0x63BC8DF])
    check("locked section store imul to r10 output",
          "mov" in by_addr[0x63BC8EE] and "%rbp,(%r10)" in by_addr[0x63BC8EE])
    check("locked section sub 0x88 to r13 output",
          "mov" in by_addr[0x63BC8F8] and "%rbp,0x0(%r13)" in by_addr[0x63BC8F8])
    check("locked section chain test rax",
          "test" in by_addr[0x63BC8FC] and "%rax,%rax" in by_addr[0x63BC8FC])
    check("locked section chain je fallback",
          "je" in by_addr[0x63BC8FF] and "63bca08" in by_addr[0x63BC8FF])
    check("locked section chain mov 0x8 rax to r14 output",
          "mov" in by_addr[0x63BC909] and "%rax,(%r14)" in by_addr[0x63BC909])
    check("locked section clears flag byte",
          "movb" in by_addr[0x63BC90C] and "$0x0,0x68(%rbx)" in by_addr[0x63BC90C])
    check("unlock epilogue mov r15 to rdi",
          "mov" in by_addr[0x63BC92E] and "%r15,%rdi" in by_addr[0x63BC92E])
    # Fallback helper when 0xc0(%rbx) is null.
    check("fallback lea 0xc8 rbx",
          "lea" in by_addr[0x63BCA08] and "0xc8(%rbx),%rdi" in by_addr[0x63BCA08])
    check("fallback call 0x63abd00",
          "call" in by_addr[0x63BCA0F] and "63abd00" in by_addr[0x63BCA0F])
    check("fallback test rax",
          "test" in by_addr[0x63BCA14] and "%rax,%rax" in by_addr[0x63BCA14])
    check("fallback zero je chain store",
          "je" in by_addr[0x63BCA17] and "63bc909" in by_addr[0x63BCA17])
    check("fallback nonzero jmp chain deref",
          "jmp" in by_addr[0x63BCA1D] and "63bc905" in by_addr[0x63BCA1D])

    # Scan (single 8-slot MTF).
    slot = [0x63BC960, 0x63BCA2E, 0x63BCA7A, 0x63BCA89,
            0x63BCA98, 0x63BCAA7, 0x63BCAB6, 0x63BCAC3]
    check("scan all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slot),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slot
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan reversed-operand slots 3 and 6",
          [a for a in slot
           if operands_of(by_addr[a]).startswith("%r8,")] == [0x63BCA89, 0x63BCAB6],
          str([(hex(a), operands_of(by_addr[a])) for a in slot
               if operands_of(by_addr[a]).startswith("%r8,")]))
    check("scan slot 7 compares memory directly",
          "cmp" in by_addr[0x63BCAC3] and "0x170(%rdi),%r8" in by_addr[0x63BCAC3])
    check("scan slot 0 hit mov top entry",
          "mov" in by_addr[0x63BC96D] and "0x108(%rdi),%rdx" in by_addr[0x63BC96D])
    check("scan slot 0 hit swaps top entry",
          "mov" in by_addr[0x63BC974] and "%rcx,0x100(%rdi)" in by_addr[0x63BC974])
    check("scan slot 0 hit recomputes second level",
          "lea" in by_addr[0x63BC997] and "(%rdx,%rsi,1),%rax" in by_addr[0x63BC997])
    check("scan slot 0 hit rejoins second-level deref",
          "jmp" in by_addr[0x63BC99B] and "63bc7bd" in by_addr[0x63BC99B])
    check("scan slot 1 jne slots chain",
          "jne" in by_addr[0x63BCA35] and "63bca74" in by_addr[0x63BCA35])
    check("scan slot 2 je shared mtf",
          "je" in by_addr[0x63BCA81] and "63bca37" in by_addr[0x63BCA81])
    check("scan slot 7 jne lu-miss",
          "jne" in by_addr[0x63BCACA] and "63bcae0" in by_addr[0x63BCACA])
    check("scan slot 7 hit rejoins shared mtf",
          "jmp" in by_addr[0x63BCAD2] and "63bca37" in by_addr[0x63BCAD2])
    check("scan shared mtf rejoins slot 0 block",
          "jmp" in by_addr[0x63BCA6F] and "63bc974" in by_addr[0x63BCA6F])

    # Lu-miss site.
    check("lu-miss rcx entry key",
          "mov" in by_addr[0x63BCAE0] and "%rsi,%rcx" in by_addr[0x63BCAE0])
    check("lu-miss rsi 0x6511a00 bss",
          "lea" in by_addr[0x63BCAE3] and "6511a00" in by_addr[0x63BCAE3])
    check("lu-miss rdx scan table rdi",
          "mov" in by_addr[0x63BCAEA] and "%rdi,%rdx" in by_addr[0x63BCAEA])
    check("lu-miss r9d 0",
          "xor" in by_addr[0x63BCAED] and "%r9d,%r9d" in by_addr[0x63BCAED])
    check("lu-miss r8d 1",
          "mov" in by_addr[0x63BCAF0] and "$0x1,%r8d" in by_addr[0x63BCAF0])
    check("lu-miss rdi context rbp",
          "mov" in by_addr[0x63BCAF6] and "%rbp,%rdi" in by_addr[0x63BCAF6])
    check("lu-miss rejoin jmp 0x63bc7bd",
          "jmp" in by_addr[0x63BCB08] and "63bc7bd" in by_addr[0x63BCB08])

    # Exits: ret path + unlock tail-jump path; canary on both.
    check("ret path canary check sub fs",
          "sub" in by_addr[0x63BC81E] and "%fs:0x28" in by_addr[0x63BC81E])
    check("ret path canary fail jne to stack_chk_fail",
          "jne" in by_addr[0x63BC827] and "63bcb0d" in by_addr[0x63BC827])
    check("unlock path canary check sub fs",
          "sub" in by_addr[0x63BC918] and "%fs:0x28" in by_addr[0x63BC918])
    check("unlock path canary fail jne to stack_chk_fail",
          "jne" in by_addr[0x63BC921] and "63bcb0d" in by_addr[0x63BC921])
    check("ret path add rsp epilogue",
          "add" in by_addr[0x63BC82D] and "$0x1b8,%rsp" in by_addr[0x63BC82D])
    check("unlock path add rsp epilogue",
          "add" in by_addr[0x63BC927] and "$0x1b8,%rsp" in by_addr[0x63BC927])
    eax_writes = [addr_of(l) for l in lines
                  if "%eax" in l and mnemonic_of(l) in
                  ("xor", "and", "mov", "movl", "add", "sub", "or", "lea")]
    check("eax writes exact list",
          eax_writes == [0x63BC76C, 0x63BC798],
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
    check("0x6511a00 inside .bss",
          bss is not None and bss[3] <= 0x6511A00 < bss[3] + bss[5])
    check("0x6711b40 inside .bss",
          bss is not None and bss[3] <= 0x6711B40 < bss[3] + bss[5])

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
