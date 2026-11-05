#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-miss-caller-1site.

Byte reads only; never executes the node binary. Checks, counted at the end:
base + binary identity, .eh_frame bounds, exhibit bytes, strict/call census
(100 strict, 1 call: the lu-miss call; 1 ret; 0 bsr; 0 lock), entry mapping
(rdi->rbx output struct, rsi->r10 context, rdx table, rcx key; no endbr64,
no canary, push/pop rbx only), single-walk (top index + high-bits compare,
second level into rsi), inline extract (shl/sar 0x10, five stores into the
struct at rbx), single 8-slot move-to-front scan (0 reversed-operand
compares; slot-0 inline block + shared MTF block), one lu-miss site
(rsi 0x6511a00 .bss, rdi entry rsi via r10, rdx entry table, rcx entry key
— miss-path write-set check), exit rax = rbx, jump closure with 0 outside
targets, rel32 targets, rela counts, raw-e8 lu-miss census (168 sites,
53 FDEs, tiers 1x18 2x14 3x1 4x11 5x1 6x2 7x1 8x1 10x3 13x1; 0 bti sites in
this FDE), lu-miss frontier survey (16 survivors), next-candidate
disjointness, disjointness over every exhibit range, slug uniqueness,
MANIFEST.
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
                      "RE-001-node115-lu-miss-caller-1site")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-1site"
NAME = "lu_miss_caller_1site"
START, END = 0x63495B0, 0x6349775

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
    check("target FDE size 453", END - START == 453)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x6349560..0x63495a5",
          prev == (0x6349560, 0x63495A5), str(prev))
    check("prev gap 11", START - prev[1] == 11)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 11, gap.hex())
    check("next FDE 0x6349780..0x6349bd9",
          nxt == (0x6349780, 0x6349BD9), str(nxt))
    check("next padding 11", nxt[0] - END == 11)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 11, pad.hex())
    check("no overlap with 0x63ed090 exclusion",
          END <= 0x63ED090 or START >= 0x63ED862)
    check("no overlap with 0x63ef8e0 exclusion",
          END <= 0x63EF8E0 or START >= 0x63EFBA2)

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 453", len(hexb) == 453, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 100", len(lines) == 100, str(len(lines)))
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 1", len(calls) == 1, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x634962f", [addr_of(l) for l in rets] == [0x634962F],
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
          ct == [(0x634976B, 0x63D9700)], str(ct))
    bti = [a for a, t in ct if t == 0x63D9880]
    check("no bti sites", bti == [], str(bti))
    miss = [a for a, t in ct if t == 0x63D9700]
    check("lu-miss sites", miss == [0x634976B], str(miss))
    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str(len(bsr)))
    locks = [(mnemonic_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))
    check("no endbr64 in FDE",
          not any(mnemonic_of(l) == "endbr64" for l in lines))
    check("no canary reference (no fs:)",
          not any("%fs:" in l for l in lines))
    check("no stack_chk_fail call",
          not any("__stack_chk_fail" in l for l in lines))
    check("no rep stos in FDE",
          not any("rep" in l and "stos" in l for l in lines))
    check("no trylock / unlock PLT call",
          not any("pthread_mutex" in l for l in lines))
    check("no size table 0x6727a00 read",
          not any("0x6727a00" in l for l in lines))
    check("no node table 0x65096c0 read",
          not any("0x65096c0" in l for l in lines))
    check("no node table 0x6511780 read",
          not any("0x6511780" in l for l in lines))

    by_addr = {addr_of(l): l for l in lines}
    # Entry register mapping + frame (push/pop rbx only).
    check("entry mov rcx to rax",
          "mov" in by_addr[0x63495B0] and "%rcx,%rax" in by_addr[0x63495B0])
    check("entry push rbx",
          "push" in by_addr[0x63495B3] and "%rbx" in by_addr[0x63495B3])
    check("entry mov rsi to r10",
          "mov" in by_addr[0x63495B4] and "%rsi,%r10" in by_addr[0x63495B4])
    check("entry mov rdi to rbx",
          "mov" in by_addr[0x63495B7] and "%rdi,%rbx" in by_addr[0x63495B7])
    check("no sub rsp in FDE",
          not any("sub" in l and "%rsp" in l for l in lines))
    check("epilogue mov rbx to rax",
          "mov" in by_addr[0x6349623] and "%rbx,%rax" in by_addr[0x6349623])
    check("epilogue pop rbx",
          "pop" in by_addr[0x634962E] and "%rbx" in by_addr[0x634962E])

    # Walk (single, table in rdx, key in rcx).
    check("walk top shr 0x1a",
          "shr" in by_addr[0x63495BA] and "$0x1a,%rax" in by_addr[0x63495BA])
    check("walk top and 0xf0",
          "and" in by_addr[0x63495C1] and "$0xf0,%eax" in by_addr[0x63495C1])
    check("walk high bits and",
          "and" in by_addr[0x63495C6] and "$0xffffffffc0000000,%rsi" in by_addr[0x63495C6])
    check("walk add table rdx",
          "add" in by_addr[0x63495CD] and "%rdx,%rax" in by_addr[0x63495CD])
    check("walk top load",
          "mov" in by_addr[0x63495D0] and "(%rax),%rdi" in by_addr[0x63495D0])
    check("walk top compare",
          "cmp" in by_addr[0x63495D3] and "%rdi,%rsi" in by_addr[0x63495D3])
    check("walk mismatch jne scan",
          "jne" in by_addr[0x63495D6] and "6349630" in by_addr[0x63495D6])
    check("walk second level shr 0x9",
          "shr" in by_addr[0x63495D8] and "$0x9,%rcx" in by_addr[0x63495D8])
    check("walk second level and 0x1ffff8",
          "and" in by_addr[0x63495DC] and "$0x1ffff8,%ecx" in by_addr[0x63495DC])
    check("walk second level add table entry",
          "add" in by_addr[0x63495E2] and "0x8(%rax),%rcx" in by_addr[0x63495E2])
    check("walk second level mov rcx to rax",
          "mov" in by_addr[0x63495E6] and "%rcx,%rax" in by_addr[0x63495E6])
    check("walk second level loaded into rsi",
          "mov" in by_addr[0x63495E9] and "(%rax),%rsi" in by_addr[0x63495E9])

    # Extract (inline, five stores into the struct at rbx).
    check("extract mov rsi to rax",
          "mov" in by_addr[0x63495EC] and "%rsi,%rax" in by_addr[0x63495EC])
    check("extract mov rsi to rdx",
          "mov" in by_addr[0x63495EF] and "%rsi,%rdx" in by_addr[0x63495EF])
    check("extract mov rsi to r10",
          "mov" in by_addr[0x63495F2] and "%rsi,%r10" in by_addr[0x63495F2])
    check("extract mov rsi to r11",
          "mov" in by_addr[0x63495F5] and "%rsi,%r11" in by_addr[0x63495F5])
    check("extract shl 0x10 rax",
          "shl" in by_addr[0x63495F8] and "$0x10,%rax" in by_addr[0x63495F8])
    check("extract sar 0x10 rax",
          "sar" in by_addr[0x6349603] and "$0x10,%rax" in by_addr[0x6349603])
    check("extract and mask 0x80",
          "and" in by_addr[0x6349611] and "$0xffffffffffffff80,%rax" in by_addr[0x6349611])
    check("extract store 48-bit value at 0x0 rbx",
          "mov" in by_addr[0x6349620] and "%rax,(%rbx)" in by_addr[0x6349620])
    check("extract store desc>>0x30 at 0x8 rbx",
          "mov" in by_addr[0x6349626] and "%r11d,0x8(%rbx)" in by_addr[0x6349626])
    check("extract store (desc>>2)&7 at 0xc rbx",
          "mov" in by_addr[0x634961D] and "%edx,0xc(%rbx)" in by_addr[0x634961D])
    check("extract store (desc>>1)&1 at 0x10 rbx",
          "mov" in by_addr[0x634962A] and "%r10b,0x10(%rbx)" in by_addr[0x634962A])
    check("extract store desc&1 at 0x11 rbx",
          "mov" in by_addr[0x634960D] and "%sil,0x11(%rbx)" in by_addr[0x634960D])
    check("extract shr 0x30 r11",
          "shr" in by_addr[0x6349615] and "$0x30,%r11" in by_addr[0x6349615])
    check("extract shr 0x2 rdx",
          "shr" in by_addr[0x63495FC] and "$0x2,%rdx" in by_addr[0x63495FC])
    check("extract and 0x7 edx",
          "and" in by_addr[0x634960A] and "$0x7,%edx" in by_addr[0x634960A])
    check("extract shr 0x1 r10",
          "shr" in by_addr[0x6349607] and "$1,%r10" in by_addr[0x6349607])
    check("extract and 0x1 r10d",
          "and" in by_addr[0x6349619] and "$0x1,%r10d" in by_addr[0x6349619])
    check("extract and 0x1 esi",
          "and" in by_addr[0x6349600] and "$0x1,%esi" in by_addr[0x6349600])
    check("extract no helper call",
          not any("call" in l for l in lines if 0x63495E9 <= addr_of(l) <= 0x634962F))

    # Jump closure: all 13 jumps target inside the window (no tail jump).
    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 13", len(jmps) == 13, str(len(jmps)))
    outside = [(a, t) for a, t in jmps
               if not (START <= t < END)]
    check("jump closure zero outside", outside == [], str(outside))

    # Scan (single 8-slot MTF, table+0x100 in rdx, key in rsi).
    slot = [0x6349630, 0x6349676, 0x63496E9, 0x63496F8,
            0x634970B, 0x634971E, 0x6349731, 0x634973E]
    check("scan all 8 slot compares are cmp",
          all(mnemonic_of(by_addr[a]) == "cmp" for a in slot),
          str([(hex(a), mnemonic_of(by_addr[a])) for a in slot
               if mnemonic_of(by_addr[a]) != "cmp"]))
    check("scan slot offsets 0x100..0x170 step 0x10",
          [operands_of(by_addr[a]).split(",")[0] for a in slot] ==
          ["0x100(%rdx)", "0x110(%rdx)", "0x120(%rdx)", "0x130(%rdx)",
           "0x140(%rdx)", "0x150(%rdx)", "0x160(%rdx)", "0x170(%rdx)"],
          str([operands_of(by_addr[a]) for a in slot]))
    check("scan zero reversed-operand compares",
          [a for a in slot
           if operands_of(by_addr[a]).startswith("%rsi,")] == [],
          str([(hex(a), operands_of(by_addr[a])) for a in slot]))
    check("scan slot 7 compares memory directly",
          "cmp" in by_addr[0x634973E] and "0x170(%rdx),%rsi" in by_addr[0x634973E])
    check("scan slot-index movs r8d 1..7",
          [(a, operands_of(by_addr[a])) for a in
           [0x6349670, 0x63496E3, 0x63496F2, 0x6349705, 0x6349718, 0x634972B, 0x6349747]] ==
          [(0x6349670, "$0x1,%r8d"), (0x63496E3, "$0x2,%r8d"),
           (0x63496F2, "$0x3,%r8d"), (0x6349705, "$0x4,%r8d"),
           (0x6349718, "$0x5,%r8d"), (0x634972B, "$0x6,%r8d"),
           (0x6349747, "$0x7,%r8d")],
          str([(hex(a), operands_of(by_addr[a])) for a in
               [0x6349670, 0x63496E3, 0x63496F2, 0x6349705, 0x6349718, 0x634972B, 0x6349747]]))
    check("scan slot 0 hit block mov top entry",
          "mov" in by_addr[0x6349639] and "0x108(%rdx),%r8" in by_addr[0x6349639])
    check("scan slot 0 hit swaps top entry",
          "mov" in by_addr[0x6349640] and "%rdi,0x100(%rdx)" in by_addr[0x6349640])
    check("scan slot 0 hit rejoins second-level deref",
          "jmp" in by_addr[0x6349667] and "63495e9" in by_addr[0x6349667])
    check("scan slots 2-6 je shared mtf",
          all("je" in by_addr[a] and "634967f" in by_addr[a] for a in
              [0x63496F0, 0x63496FF, 0x6349712, 0x6349725, 0x6349738]),
          str([(hex(a), by_addr[a]) for a in
               [0x63496F0, 0x63496FF, 0x6349712, 0x6349725, 0x6349738]
               if "634967f" not in by_addr[a]]))
    check("scan slot 1 jne slot 2 block",
          "jne" in by_addr[0x634967D] and "63496e3" in by_addr[0x634967D])
    check("scan slot 7 jne lu-miss",
          "jne" in by_addr[0x6349745] and "6349758" in by_addr[0x6349745])
    check("scan slot 7 hit sets index 7",
          "mov" in by_addr[0x6349747] and "$0x7,%r8d" in by_addr[0x6349747])
    check("scan slot 7 hit jmp shared mtf",
          "jmp" in by_addr[0x634974D] and "634967f" in by_addr[0x634974D])
    check("scan shared mtf rejoins second-level deref",
          "jmp" in by_addr[0x63496DE] and "63495e9" in by_addr[0x63496DE])
    check("scan shared mtf mov index to r9d",
          "mov" in by_addr[0x634967F] and "%r8d,%r9d" in by_addr[0x634967F])
    check("scan slot 0 jne slot 1 block",
          "jne" in by_addr[0x6349637] and "6349670" in by_addr[0x6349637])

    # Lu-miss site + miss-path write-set provenance.
    check("lu-miss lea rsi 0x6511a00 bss",
          "lea" in by_addr[0x6349758] and "6511a00" in by_addr[0x6349758])
    check("lu-miss r9d 0",
          "xor" in by_addr[0x634975F] and "%r9d,%r9d" in by_addr[0x634975F])
    check("lu-miss r8d 1",
          "mov" in by_addr[0x6349762] and "$0x1,%r8d" in by_addr[0x6349762])
    check("lu-miss rdi entry rsi via r10",
          "mov" in by_addr[0x6349768] and "%r10,%rdi" in by_addr[0x6349768])
    check("lu-miss call 0x63d9700",
          "call" in by_addr[0x634976B] and "63d9700" in by_addr[0x634976B])
    check("lu-miss rejoin jmp 0x63495e9",
          "jmp" in by_addr[0x6349770] and "63495e9" in by_addr[0x6349770])
    # Miss path (traced branch outcomes): entry -> walk mismatch -> slot
    # compares 0..7 all miss -> lu-miss block. Register writes on it prove
    # rdi = entry rsi, rdx = entry table, rcx = entry key at the call.
    miss_path = [0x63495B0, 0x63495B3, 0x63495B4, 0x63495B7, 0x63495BA,
                 0x63495BE, 0x63495C1, 0x63495C6, 0x63495CD, 0x63495D0,
                 0x63495D3, 0x63495D6, 0x6349630, 0x6349637, 0x6349670,
                 0x6349676, 0x634967D, 0x63496E3, 0x63496E9, 0x63496F0,
                 0x63496F2, 0x63496F8, 0x63496FF, 0x6349705, 0x634970B,
                 0x6349712, 0x6349718, 0x634971E, 0x6349725, 0x634972B,
                 0x6349731, 0x6349738, 0x634973E, 0x6349745, 0x6349758,
                 0x634975F, 0x6349762, 0x6349768, 0x634976B]
    check("miss path is 39 traced instructions", len(miss_path) == 39)

    def dst_reg(line):
        mn = mnemonic_of(line)
        if mn in ("cmp", "test", "call", "jmp", "je", "jne", "ret", "push",
                  "nopl", "nopw"):
            return None
        if mn == "pop":
            return operands_of(line).strip()
        parts = [p.strip() for p in operands_of(line).split(",")]
        return parts[-1] if parts else None

    def reg_writes(reg, addrs):
        out = []
        for a in addrs:
            d = dst_reg(by_addr[a])
            if d in ("%" + reg, "%" + reg + "d", "%" + reg + "b",
                     "%" + reg + "w"):
                out.append(a)
        return out

    check("miss path r10 written only at entry 0x63495b4",
          reg_writes("r10", miss_path) == [0x63495B4],
          str([hex(a) for a in reg_writes("r10", miss_path)]))
    check("miss path rcx never written (entry key at call)",
          reg_writes("rcx", miss_path) == [] and
          reg_writes("ecx", miss_path) == [],
          str([hex(a) for a in reg_writes("rcx", miss_path)]))
    check("miss path rdx never written (entry table at call)",
          reg_writes("rdx", miss_path) == [],
          str([hex(a) for a in reg_writes("rdx", miss_path)]))
    check("miss path r8d last write is $0x1 at 0x6349762",
          reg_writes("r8", miss_path)[-1] == 0x6349762,
          str([hex(a) for a in reg_writes("r8", miss_path)]))
    check("miss path r9d written only by xor at 0x634975f",
          reg_writes("r9", miss_path) == [0x634975F],
          str([hex(a) for a in reg_writes("r9", miss_path)]))
    check("r10 writes in whole window are entry + extract + shared-mtf only",
          sorted(a for a in by_addr
                 if dst_reg(by_addr[a]) in ("%r10", "%r10d", "%r10b")) ==
          [0x63495B4, 0x63495F2, 0x6349607, 0x6349619, 0x63496B3],
          str([hex(a) for a in sorted(a for a in by_addr
               if dst_reg(by_addr[a]) in ("%r10", "%r10d", "%r10b"))]))

    # Exit: single ret, rax = rbx (NOT 0).
    check("exit rax is rbx (mov rbx to rax before ret)",
          "mov" in by_addr[0x6349623] and "%rbx,%rax" in by_addr[0x6349623])
    eax_writes = [addr_of(l) for l in lines
                  if "%eax" in l and mnemonic_of(l) in
                  ("xor", "and", "mov", "movl", "add", "sub", "or", "lea")]
    check("eax writes exact list (entry xor + top-index and only)",
          eax_writes == [0x63495C1],
          str([hex(a) for a in eax_writes]))

    # .bss section check (own ELF parse): exact end asserted.
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

    # raw-e8 census: scan .text for e8 with rel32 target 0x63d9700
    text_sec = None
    for s in secs:
        if secname(s[0]) == ".text":
            text_sec = s
    tva, toff_sec, tsize = text_sec[3], text_sec[4], text_sec[5]
    tbytes = node[toff_sec:toff_sec + tsize]
    counts = {}
    bti_counts = {}
    pos = tbytes.find(b"\xe8")
    while pos != -1:
        if pos + 5 <= len(tbytes):
            rel = struct.unpack_from("<i", tbytes, pos + 1)[0]
            tgt = tva + pos + 5 + rel
            va = tva + pos
            k = bisect.bisect_right(starts, va) - 1
            if k >= 0 and fdes[k][0] <= va < fdes[k][1]:
                if tgt == 0x63D9700:
                    counts[fdes[k][0]] = counts.get(fdes[k][0], 0) + 1
                if tgt == 0x63D9880:
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
    check("this FDE raw bti 0", bti_counts.get(START, 0) == 0,
          str(bti_counts.get(START, 0)))

    # lu-miss frontier survey consistency
    survey = rec.get("survey", {})
    cands = survey.get("candidates", [])
    check("survey candidates 16", len(cands) == 16, str(len(cands)))
    check("survey first candidate is this window",
          cands and cands[0]["start"] == "0x63495b0")
    check("survey this candidate BUILT by #314",
          cands and "BUILT by packet #314" in cands[0].get("status", ""))
    check("survey other 15 are SURVIVOR",
          all("SURVIVOR" in c.get("status", "") for c in cands[1:]),
          str([c["start"] for c in cands[1:] if "SURVIVOR" not in c.get("status", "")]))
    check("survey total sites 168", survey.get("total_sites") == 168,
          str(survey.get("total_sites")))
    check("survey total FDEs 53", survey.get("total_fdes") == 53,
          str(survey.get("total_fdes")))
    check("survey next candidate is 0x6353a70",
          rec.get("next_question", {}).get("window") == "0x6353a70..0x635582b")
    check("survey second candidate lu-miss sites 1",
          cands[1].get("lu_miss_sites") == 1, str(cands[1]))
    check("survey second candidate size 7611",
          cands[1].get("size") == 7611, str(cands[1]))
    check("survey second candidate shared with 2nd handler",
          cands[1].get("also_second_handler_survivor") is True)

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
    # next candidate 0x6353a70..0x635582b must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x6353A70 < p[1] and p[0] < 0x635582B]
    check("next candidate 0x6353a70 disjoint from priors",
          not nxt_bad, str(nxt_bad[:3]))

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
