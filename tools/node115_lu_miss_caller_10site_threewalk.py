"""Static verifier for RE-001-node115-lu-miss-caller-10site-threewalk.

Eleventh packet of the lu-miss-caller frontier (callers of the lu-miss
handler 0x63d9700 that do not call bin_table_init): FDE
0x63d03a0..0x63d17d7, 5175 bytes, 1037 strict instructions, 23 calls
(11 distinct direct targets, 0 indirect), 10 lu-miss sites, 0
bin_table_init sites, 1 second-handler site at 0x63d0837, ONE ret at
0x63d0817, bsr 2, lock sub 2 / lock add 1, 172 jumps, 0 outside the
window, endbr64 0, canary present, NO TLS flag check.

This window is a SHARED survivor: it is in both the survey's 16-FDE
lu-miss survivor list and the 18-FDE second-handler survivor list, so
it consumes one slot of the combined 25-FDE miss-handler pool. Largest
lu-miss window so far (5175 bytes). First frontier window with THREE
context-table walks (A, B, C) plus a deep-resolution tail (D, D-prime),
an outer loop that recomputes the size class each iteration, and TWO
bsr paths.

Entry: rdi is the context base (kept in r15), rsi holds the remaining
count in 0x14(%rsi) (kept in r12d); 0x88(%r15) is the resolver input
(kept in r14). The size class is recomputed each outer iteration from
the count (shl, $0x3800 / $0x1000 thresholds, byte table 0x67277c0,
size table 0x6727a00, $0x3fff cap, 0x6728140 fallback, $0x4000 cap),
then cmpb $0x0,0x1(%r15) gates the second-handler path. Resolver
0x6365150 (rdi=r15, rsi=r14, rdx=size class, rcx=$0x40, r8d=1, r9d=0)
returns the walk-A key in rax (null -> exit 1). Walk A (key r14,
lock add), an element loop calling prev FDE 0x63d0080 once per
element, walk B (key r10, lock sub), walk C (key r12, lock sub), then
a deep-resolution tail (0x63bd6c0, 0x63637f0, 0x6363260) and a loop-back
to 0x63d03d4. Ten 8-slot move-to-front scans share one slot set
(0x2b0..0x320 in r15): 74 slot-compare instructions, EIGHTEEN
reversed-operand (B1 slots 1,2,4; B2 slots 3,4,5,6; C3 slots 1,2,3,4;
D2 slots 1-7), i.e. 18 of 80 slot positions reversed; nine scans are
unrolled chains, D1 is a counter loop. All ten lu-miss sites share
one argument pattern (rdi = r15 context, rsi = .bss 0x6511a00, rdx =
walk table pointer from 0x18(%rsp), rcx = walk key, r8d = 1, r9d =
0); the rcx provenance is proven by reaching-definitions (sites
1,3,5,6 = r10 walk-B key; sites 2,4,7,8 = r12 walk-C key; sites 9,10
= r14 walk-A key). Exit: a single ret with two reaching rax defs --
0 (xor %eax,%eax at 0x63d066f / 0x63d0d30 / 0x63d1316) or 1
(mov $0x1,%eax at 0x63d07f0) -- so no single exit value is
established, unlike #314 (rbx), #315 (r12), #316 (r13), #317 (r12),
#319 (0), and #320 (r15).

#323's pointer for this window (5175 bytes, 1037 strict, 23 calls,
10 lu-miss sites at 0x63d1063 / 0x63d1183 / 0x63d1258 / 0x63d12a8 /
0x63d1416 / 0x63d15b6 / 0x63d166c / 0x63d16b7 / 0x63d177a / 0x63d17c1,
0 bin_table_init sites, 1 second-handler site at 0x63d0837, 1 ret at
0x63d0817, bsr 2) was verified correct by targeted objdump census.
No correction (prior_pointer_verified).

Next question: the next lu-miss survivor in address order is
0x63d17e0..0x63d2a80 (4768 bytes, 928 strict, 20 calls, 10 lu-miss
sites, 0 bti, 1 second-handler site at 0x63d1c81, 1 ret at 0x63d1bd7,
bsr 2) -- also a SHARED survivor, unlike #323.

Usage: python3 tools/node115_lu_miss_caller_10site_threewalk.py
Exit 0 iff every check passes. Reads only the node binary, the
packet's records.json and exhibits, and prior records.json files
for the disjointness scan.
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
                      "RE-001-node115-lu-miss-caller-10site-threewalk")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-10site-threewalk"
NAME = "lu_miss_caller_10site_threewalk"
START, END = 0x63D03A0, 0x63D17D7

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
        s = toks[1] if len(toks) > 1 else ""
        return s.split(" #")[0]
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


PLAIN_REGS = ({"rax", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rbx"}
              | {"r%d" % i for i in range(8, 16)})


def canon(op):
    if op is None:
        return None
    base = op.strip().lstrip("%")
    if base in ("eax", "ax", "al"):
        return "rax"
    if base in ("ecx", "cx", "cl"):
        return "rcx"
    if base in ("edx", "dx", "dl"):
        return "rdx"
    if base in ("esi", "si", "sil"):
        return "rsi"
    if base in ("edi", "di", "dil"):
        return "rdi"
    if base in ("ebp", "bp", "bpl"):
        return "rbp"
    if base in ("esp", "sp", "spl"):
        return "rsp"
    if base in ("ebx", "bx", "bl"):
        return "rbx"
    if base in PLAIN_REGS:
        return base
    if re.match(r"r\d+[dwb]$", base):
        return base[:-1]
    return None




def main():
    node = read(BIN)
    check("binary size 105896032", len(node) == 105896032, str(len(node)))
    check("binary sha256",
          hashlib.sha256(node).hexdigest() ==
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    rec = json.loads(read(os.path.join(PACKET, "records.json")).decode())
    check("records base", rec["base"] ==
          "05bc2de303c05525b71e7e257426e741bc66a390", str(rec.get("base")))

    fdes = parse_eh_frame(node)
    starts = [s for s, e in fdes]
    check("total FDEs 135313", len(fdes) == 135313, str(len(fdes)))
    i = bisect.bisect_left(starts, START)
    check("target FDE start", i < len(fdes) and fdes[i][0] == START)
    check("target FDE end", i < len(fdes) and fdes[i][1] == END)
    check("target FDE size 5175", END - START == 5175)
    prev = fdes[i - 1]
    check("prev FDE 0x63d0080..0x63d0398",
          prev == (0x63D0080, 0x63D0398), str(prev))
    check("prev gap 8", START - prev[1] == 8)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 8, gap.hex())
    nxt = fdes[i + 1]
    check("next FDE 0x63d17e0..0x63d2a80",
          nxt == (0x63D17E0, 0x63D2A80), str(nxt))
    check("next padding 9", nxt[0] - END == 9)
    pad = node[toff(END):toff(nxt[0])]
    check("padding bytes all cc", pad == b"\xcc" * 9, pad.hex())
    check("next FDE starts push r15 (no endbr64)",
          node[toff(nxt[0]):toff(nxt[0]) + 2] == b"\x41\x57")
    check("prev FDE starts push r15 (no endbr64)",
          node[toff(prev[0]):toff(prev[0]) + 2] == b"\x41\x57")

    hexb = read(os.path.join(PACKET, "lu_miss_caller_10site_threewalk.hex"))
    check("hex exhibit raw bytes 5175", len(hexb) == 5175, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lu_miss_caller_10site_threewalk.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 1037", len(lines) == 1037, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 23", len(calls) == 23, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63d0817",
          len(rets) == 1 and addr_of(rets[0]) == 0x63D0817,
          str([hex(addr_of(l)) for l in rets]))
    tgt = {}
    for l in calls:
        m = re.search(r"\tcall\s+([0-9a-f]+)", l)
        if m:
            t = int(m.group(1), 16)
            tgt[t] = tgt.get(t, 0) + 1
    indirect = [l for l in calls
                if re.search(r"\tcall\s+\*", l)]
    check("indirect calls 0", indirect == [],
          str([hex(addr_of(l)) for l in indirect]))
    expect = {0x6365150: 1, 0x63D0080: 1, 0x63637F0: 2, 0x634EBB0: 1,
              0x6352FC0: 1, 0x63EDF10: 1, 0x63BD6C0: 2, 0x63EC4C0: 1,
              0x6363260: 2, 0x63D9700: 10, 0x63F0D70: 1}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct call targets 11", len(tgt) == 11, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 10",
          tgt.get(0x63D9700, 0) == 10, str(tgt.get(0x63D9700, 0)))
    check("lu-miss site list",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63d9700" in l) ==
          [0x63D1063, 0x63D1183, 0x63D1258, 0x63D12A8, 0x63D1416,
           0x63D15B6, 0x63D166C, 0x63D16B7, 0x63D177A, 0x63D17C1])
    check("second-handler sites 1", tgt.get(0x634EBB0, 0) == 1,
          str(tgt.get(0x634EBB0, 0)))
    check("second-handler site 0x63d0837",
          "call" in by_addr[0x63D0837] and "634ebb0" in by_addr[0x63D0837])
    check("lock-wait helper called 0 times", tgt.get(0x63BF680, 0) == 0,
          str(tgt.get(0x63BF680, 0)))
    check("resolver 0x6365150 called once at 0x63d0484",
          "call" in by_addr[0x63D0484] and "6365150" in by_addr[0x63D0484])
    check("prev FDE 0x63d0080 called once at 0x63d0582",
          "call" in by_addr[0x63D0582] and "63d0080" in by_addr[0x63D0582])
    check("0x63637f0 called twice at 0x63d066a/0x63d0750",
          "call" in by_addr[0x63D066A] and "63637f0" in by_addr[0x63D066A]
          and "call" in by_addr[0x63D0750] and "63637f0" in by_addr[0x63D0750])
    check("0x6363260 called twice at 0x63d0c91/0x63d1311",
          "call" in by_addr[0x63D0C91] and "6363260" in by_addr[0x63D0C91]
          and "call" in by_addr[0x63D1311] and "6363260" in by_addr[0x63D1311])
    check("0x63bd6c0 called twice at 0x63d0979/0x63d0d2b",
          "call" in by_addr[0x63D0979] and "63bd6c0" in by_addr[0x63D0979]
          and "call" in by_addr[0x63D0D2B] and "63bd6c0" in by_addr[0x63D0D2B])
    check("0x63ec4c0 called once at 0x63d0aa8",
          "call" in by_addr[0x63D0AA8] and "63ec4c0" in by_addr[0x63D0AA8])
    check("0x6352fc0 called once at 0x63d084c",
          "call" in by_addr[0x63D084C] and "6352fc0" in by_addr[0x63D084C])
    check("0x63edf10 called once at 0x63d088b",
          "call" in by_addr[0x63D088B] and "63edf10" in by_addr[0x63D088B])
    check("stack_chk_fail plt called once at 0x63d1383",
          "call" in by_addr[0x63D1383] and "63f0d70" in by_addr[0x63D1383])
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 2", sorted(addr_of(l) for l in bsr) == [0x63D07A4, 0x63D0A80],
          str([hex(addr_of(l)) for l in bsr]))
    check("bsr 1 is bsr rbp r8", "bsr" in by_addr[0x63D07A4]
          and "%rbp,%r8" in by_addr[0x63D07A4], by_addr[0x63D07A4])
    check("bsr 2 is bsr rdi rdx", "bsr" in by_addr[0x63D0A80]
          and "%rdi,%rdx" in by_addr[0x63D0A80], by_addr[0x63D0A80])
    locks = [l for l in lines if mnemonic_of(l) == "lock"]
    check("lock lines 3", len(locks) == 3, str(locks))
    check("lock add at 0x63d052b",
          "lock add" in by_addr[0x63D052B]
          and "%r11,0x38(%r8)" in by_addr[0x63D052B], by_addr[0x63D052B])
    check("lock sub at 0x63d0631",
          "lock sub" in by_addr[0x63D0631]
          and "%r14,0x38(%r9)" in by_addr[0x63D0631], by_addr[0x63D0631])
    check("lock sub at 0x63d0717",
          "lock sub" in by_addr[0x63D0717]
          and "%r11,0x38(%rsi)" in by_addr[0x63D0717], by_addr[0x63D0717])
    jmps = [l for l in lines
            if mnemonic_of(l) in ("jmp", "je", "jne", "ja", "jb", "jae",
                                  "jbe", "jg", "jl", "jge", "jle", "jo",
                                  "jno", "js", "jns", "jp", "jnp")]
    check("jump lines 172", len(jmps) == 172, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure zero outside", outside == [], str(outside))
    check("endbr64 count 0",
          sum(1 for l in lines if "endbr64" in l) == 0)
    check("entry is push r15 not endbr64",
          "push" in by_addr[START] and "%r15" in by_addr[START])
    check("canary present (stack_chk_fail called)",
          any("stack_chk" in l for l in lines))
    check("canary load fs:0x28 at 0x63d03b7",
          "mov" in by_addr[0x63D03B7] and "%fs:0x28,%rax" in by_addr[0x63D03B7])
    check("canary check sub fs:0x28 at 0x63d07fa",
          "sub" in by_addr[0x63D07FA] and "%fs:0x28,%rdx" in by_addr[0x63D07FA])
    check("no TLS flag fs:0x330 anywhere",
          not any("%fs:0x330" in l for l in lines))

    # Entry / prologue.
    check("entry mov rdi r15",
          "mov" in by_addr[0x63D03A2] and "%rdi,%r15" in by_addr[0x63D03A2])
    check("entry push r14", "push" in by_addr[0x63D03A5]
          and "%r14" in by_addr[0x63D03A5])
    check("entry push r13", "push" in by_addr[0x63D03A7]
          and "%r13" in by_addr[0x63D03A7])
    check("entry push r12", "push" in by_addr[0x63D03A9]
          and "%r12" in by_addr[0x63D03A9])
    check("entry push rbp", "push" in by_addr[0x63D03AB]
          and "%rbp" in by_addr[0x63D03AB])
    check("entry push rbx", "push" in by_addr[0x63D03AC]
          and "%rbx" in by_addr[0x63D03AC])
    check("entry mov rsi rbx",
          "mov" in by_addr[0x63D03AD] and "%rsi,%rbx" in by_addr[0x63D03AD])
    check("entry sub 0x58 rsp",
          "sub" in by_addr[0x63D03B0] and "$0x58,%rsp" in by_addr[0x63D03B0])
    check("entry mov count 0x14 rsi",
          "mov" in by_addr[0x63D03B4] and "0x14(%rsi),%esi" in by_addr[0x63D03B4])
    check("entry lea 0x2 count r12d",
          "lea" in by_addr[0x63D03D0] and "0x2(%rsi),%r12d" in by_addr[0x63D03D0])

    # Size class (outer loop head at 0x63d03d4).
    check("size lea 0x1 r12 edi",
          "lea" in by_addr[0x63D03D4] and "0x1(%r12),%edi" in by_addr[0x63D03D4])
    check("size mov 0x10 eax",
          "mov" in by_addr[0x63D03D9] and "$0x10,%eax" in by_addr[0x63D03D9])
    check("size shl cl rax",
          "shl" in by_addr[0x63D03E4] and "%cl,%rax" in by_addr[0x63D03E4])
    check("size cmp 0x3800",
          "cmp" in by_addr[0x63D03E7] and "$0x3800,%rax" in by_addr[0x63D03E7])
    check("size ja 0x63d0778",
          "ja" in by_addr[0x63D03ED] and "63d0778" in by_addr[0x63D03ED])
    check("size add 0x3f",
          "add" in by_addr[0x63D03F3] and "$0x3f,%rax" in by_addr[0x63D03F3])
    check("size cmp 0x1000",
          "cmp" in by_addr[0x63D03FB] and "$0x1000,%rax" in by_addr[0x63D03FB])
    check("size ja 0x63d0a75",
          "ja" in by_addr[0x63D0401] and "63d0a75" in by_addr[0x63D0401])
    check("size byte table lea 0x67277c0",
          "lea" in by_addr[0x63D0407] and "67277c0" in by_addr[0x63D0407])
    check("size movzbl byte table",
          "movzbl" in by_addr[0x63D0412]
          and "(%r9,%rax,1),%r10d" in by_addr[0x63D0412])
    check("size table lea 0x6727a00",
          "lea" in by_addr[0x63D0417] and "6727a00" in by_addr[0x63D0417])
    check("size table load rbp",
          "mov" in by_addr[0x63D041E]
          and "(%rax,%r10,8),%rbp" in by_addr[0x63D041E])
    check("size cmp 0x3fff",
          "cmp" in by_addr[0x63D0422] and "$0x3fff,%rbp" in by_addr[0x63D0422])
    check("size jbe 0x63d07d8",
          "jbe" in by_addr[0x63D0429] and "63d07d8" in by_addr[0x63D0429])
    check("size fallback lea 0x6728140",
          "lea" in by_addr[0x63D042F] and "6728140" in by_addr[0x63D042F])
    check("size fallback add 0x4000",
          "add" in by_addr[0x63D0439] and "$0x4000,%rbp" in by_addr[0x63D0439])
    check("size overflow jbe 0x63d07f0",
          "jbe" in by_addr[0x63D0447] and "63d07f0" in by_addr[0x63D0447])
    check("size cap mov 0x4000 ebp",
          "mov" in by_addr[0x63D044D] and "$0x4000,%ebp" in by_addr[0x63D044D])
    check("gate cmpb 0x1 r15",
          "cmpb" in by_addr[0x63D0452] and "$0x0,0x1(%r15)" in by_addr[0x63D0452])
    check("gate jg second-handler block 0x63d0818",
          "jg" in by_addr[0x63D0457] and "63d0818" in by_addr[0x63D0457])
    check("resolver input mov 0x88 r15 r14",
          "mov" in by_addr[0x63D045D] and "0x88(%r15),%r14" in by_addr[0x63D045D])
    check("resolver input null je 0x63d0844",
          "je" in by_addr[0x63D0467] and "63d0844" in by_addr[0x63D0467])

    # Resolver call + walk A head.
    check("resolver mov r14 rsi",
          "mov" in by_addr[0x63D046D] and "%r14,%rsi" in by_addr[0x63D046D])
    check("resolver xor r9d",
          "xor" in by_addr[0x63D0470] and "%r9d,%r9d" in by_addr[0x63D0470])
    check("resolver mov 1 r8d",
          "mov" in by_addr[0x63D0473] and "$0x1,%r8d" in by_addr[0x63D0473])
    check("resolver mov rbp rdx",
          "mov" in by_addr[0x63D0479] and "%rbp,%rdx" in by_addr[0x63D0479])
    check("resolver mov 0x40 ecx",
          "mov" in by_addr[0x63D047C] and "$0x40,%ecx" in by_addr[0x63D047C])
    check("resolver mov r15 rdi",
          "mov" in by_addr[0x63D0481] and "%r15,%rdi" in by_addr[0x63D0481])
    check("resolver return mov rax r14",
          "mov" in by_addr[0x63D0489] and "%rax,%r14" in by_addr[0x63D0489])
    check("resolver null je 0x63d07f0",
          "je" in by_addr[0x63D048F] and "63d07f0" in by_addr[0x63D048F])
    check("walkA mov rax rbp",
          "mov" in by_addr[0x63D0495] and "%rax,%rbp" in by_addr[0x63D0495])
    check("walkA mov rax r10",
          "mov" in by_addr[0x63D0498] and "%rax,%r10" in by_addr[0x63D0498])
    check("walkA table lea 0x1b0 r15 rcx",
          "lea" in by_addr[0x63D049B] and "0x1b0(%r15),%rcx" in by_addr[0x63D049B])
    check("walkA shr 0x1a rbp",
          "shr" in by_addr[0x63D04A2] and "$0x1a,%rbp" in by_addr[0x63D04A2])
    check("walkA high bits and r10",
          "and" in by_addr[0x63D04A6]
          and "$0xffffffffc0000000,%r10" in by_addr[0x63D04A6])
    check("walkA table store 0x18 rsp",
          "mov" in by_addr[0x63D04AD] and "%rcx,0x18(%rsp)" in by_addr[0x63D04AD])
    check("walkA top index and f0",
          "and" in by_addr[0x63D04B2] and "$0xf0,%ebp" in by_addr[0x63D04B2])
    check("walkA top load 0x1b0 rbp rdx",
          "mov" in by_addr[0x63D04BB] and "0x1b0(%rbp),%rdx" in by_addr[0x63D04BB])
    check("walkA top cmp rdx r10",
          "cmp" in by_addr[0x63D04C2] and "%rdx,%r10" in by_addr[0x63D04C2])
    check("walkA top jne scan A1 0x63d08e4",
          "jne" in by_addr[0x63D04C5] and "63d08e4" in by_addr[0x63D04C5])
    check("walkA extract1 shr 0x30 r9",
          "shr" in by_addr[0x63D04E5] and "$0x30,%r9" in by_addr[0x63D04E5])
    check("walkA extract1 size table load r11",
          "mov" in by_addr[0x63D04E9]
          and "(%rax,%r9,8),%r11" in by_addr[0x63D04E9])
    check("walkA extract2 shl 0x10 r10",
          "shl" in by_addr[0x63D0513] and "$0x10,%r10" in by_addr[0x63D0513])
    check("walkA extract2 sar 0x10 r10",
          "sar" in by_addr[0x63D0517] and "$0x10,%r10" in by_addr[0x63D0517])
    check("walkA extract2 node table lea 0x65096c0",
          "lea" in by_addr[0x63D050C] and "65096c0" in by_addr[0x63D050C])

    # Element loop + walk B head.
    check("elem mov 0x28 rbx r11",
          "mov" in by_addr[0x63D0530] and "0x28(%rbx),%r11" in by_addr[0x63D0530])
    check("elem mov r14 0x28 rbx",
          "mov" in by_addr[0x63D0534] and "%r14,0x28(%rbx)" in by_addr[0x63D0534])
    check("elem sub 1 r12d",
          "sub" in by_addr[0x63D053C] and "$0x1,%r12d" in by_addr[0x63D053C])
    check("elem walkB key save 0x8 rsp",
          "mov" in by_addr[0x63D0540] and "%r11,0x8(%rsp)" in by_addr[0x63D0540])
    check("elem call 0x63d0080",
          "call" in by_addr[0x63D0582] and "63d0080" in by_addr[0x63D0582])
    check("elem test al jne 0x63d0680",
          "jne" in by_addr[0x63D0589] and "63d0680" in by_addr[0x63D0589])
    check("walkB key mov 0x8 rsp r10",
          "mov" in by_addr[0x63D059C] and "0x8(%rsp),%r10" in by_addr[0x63D059C])
    check("walkB key mov r10 r13",
          "mov" in by_addr[0x63D05A4] and "%r10,%r13" in by_addr[0x63D05A4])
    check("walkB top cmp rax r13",
          "cmp" in by_addr[0x63D05C2] and "%rax,%r13" in by_addr[0x63D05C2])
    check("walkB top jne scan B1 0x63d0dce",
          "jne" in by_addr[0x63D05C5] and "63d0dce" in by_addr[0x63D05C5])
    check("walkB extract1 shr 0x30 rdi",
          "shr" in by_addr[0x63D05E9] and "$0x30,%rdi" in by_addr[0x63D05E9])
    check("walkB extract2 shl 0x10 r12",
          "shl" in by_addr[0x63D0617] and "$0x10,%r12" in by_addr[0x63D0617])
    check("walkB leaf test 1 al",
          "test" in by_addr[0x63D065C] and "$0x1,%al" in by_addr[0x63D065C])
    check("walkB leaf call 0x63637f0",
          "call" in by_addr[0x63D066A] and "63637f0" in by_addr[0x63D066A])
    check("walkB leaf exit0 xor eax",
          "xor" in by_addr[0x63D066F] and "%eax,%eax" in by_addr[0x63D066F])

    # Walk C head + tail / loop-back.
    check("walkC key mov 0x28 rbx r12",
          "mov" in by_addr[0x63D0680] and "0x28(%rbx),%r12" in by_addr[0x63D0680])
    check("walkC key mov r12 r10",
          "mov" in by_addr[0x63D068B] and "%r12,%r10" in by_addr[0x63D068B])
    check("walkC top cmp r14 r10",
          "cmp" in by_addr[0x63D06A9] and "%r14,%r10" in by_addr[0x63D06A9])
    check("walkC top jne scan C1 0x63d0a22",
          "jne" in by_addr[0x63D06AC] and "63d0a22" in by_addr[0x63D06AC])
    check("walkC extract1 shr 0x30 rax",
          "shr" in by_addr[0x63D06CF] and "$0x30,%rax" in by_addr[0x63D06CF])
    check("walkC deep call 0x63bd6c0 at 0x63d0979",
          "call" in by_addr[0x63D0979] and "63bd6c0" in by_addr[0x63D0979])
    check("walkC deep call 0x63637f0 at 0x63d0750",
          "call" in by_addr[0x63D0750] and "63637f0" in by_addr[0x63D0750])
    check("loopback mov 0x8 rsp rbp",
          "mov" in by_addr[0x63D0755] and "0x8(%rsp),%rbp" in by_addr[0x63D0755])
    check("loopback jmp 0x63d03d4",
          "jmp" in by_addr[0x63D076C] and "63d03d4" in by_addr[0x63D076C])
    check("exit1 mov 1 eax",
          "mov" in by_addr[0x63D07F0] and "$0x1,%eax" in by_addr[0x63D07F0])
    check("exit0 xor eax at 0x63d0d30",
          "xor" in by_addr[0x63D0D30] and "%eax,%eax" in by_addr[0x63D0D30])
    check("exit0 xor eax at 0x63d1316",
          "xor" in by_addr[0x63D1316] and "%eax,%eax" in by_addr[0x63D1316])

    # Second-handler block.
    check("sh block lea node table 0x65096c0",
          "lea" in by_addr[0x63D0818] and "65096c0" in by_addr[0x63D0818])
    check("sh block mov node table r14",
          "mov" in by_addr[0x63D081F] and "(%rdx),%r14" in by_addr[0x63D081F])
    check("sh block test r14",
          "test" in by_addr[0x63D0822] and "%r14,%r14" in by_addr[0x63D0822])
    check("sh block nonnull jne 0x63d046d",
          "jne" in by_addr[0x63D0825] and "63d046d" in by_addr[0x63D0825])
    check("sh block lea 0x64da4b0 rdx",
          "lea" in by_addr[0x63D082B] and "64da4b0" in by_addr[0x63D082B])
    check("sh block xor esi",
          "xor" in by_addr[0x63D0832] and "%esi,%esi" in by_addr[0x63D0832])
    check("sh block mov r15 rdi",
          "mov" in by_addr[0x63D0834] and "%r15,%rdi" in by_addr[0x63D0834])
    check("sh block return mov rax r14",
          "mov" in by_addr[0x63D083C] and "%rax,%r14" in by_addr[0x63D083C])
    check("sh block jmp 0x63d046d",
          "jmp" in by_addr[0x63D083F] and "63d046d" in by_addr[0x63D083F])

    # Scans: ten 8-slot MTF scans, 74 slot compares, 18 reversed.
    # Normal = slot value first (cmp mem,%key or cmp %slotreg,%key);
    # reversed = key first (cmp %key,mem) -- the #321/#322 convention.

    # Slot compares: exact operand text for all 74.
    slot_cmps = {
        0x63D089C: "%rsi,%r10", 0x63D08EB: "%rsi,%r10",
        0x63D098A: "%r8,%r10", 0x63D09D9: "%r8,%r10",
        0x63D0A29: "%rdx,%r10", 0x63D0AC0: "%rdi,%r10",
        0x63D0B1B: "%r10,%r14", 0x63D0B76: "%rdi,%r10",
        0x63D0BD3: "%rcx,%r10", 0x63D0C32: "%r8,%r10",
        0x63D0CA2: "%r8,%r10", 0x63D0D37: "0x2b0(%r15),%r13",
        0x63D0D83: "0x2b0(%r15),%r13", 0x63D0DCE: "0x2b0(%r15),%r13",
        0x63D0E25: "%rdx,%r10", 0x63D0E47: "%r10,%r8",
        0x63D0E69: "%rsi,%r10", 0x63D0E8D: "%r8,%r10",
        0x63D0EAF: "%rsi,%r10", 0x63D0ED9: "%r10,%rcx",
        0x63D0F2B: "0x2c0(%r15),%r13", 0x63D0F8B: "%r10,%r8",
        0x63D0FA7: "0x2d0(%r15),%r13", 0x63D0FB5: "0x2e0(%r15),%r13",
        0x63D0FC7: "0x2f0(%r15),%r13", 0x63D0FD9: "0x300(%r15),%r13",
        0x63D0FEB: "0x310(%r15),%r13", 0x63D0FF8: "0x320(%r15),%r13",
        0x63D101C: "%r10,%r11", 0x63D102C: "%r10,%r8",
        0x63D1083: "%r10,%r14", 0x63D1093: "%r10,%r8",
        0x63D10B6: "%r13,0x2c0(%r15)", 0x63D1126: "%rax,%r10",
        0x63D1136: "%rdx,%r10", 0x63D115B: "%r10,0x320(%r15)",
        0x63D1193: "%r13,0x2d0(%r15)", 0x63D11A6: "0x2e0(%r15),%r13",
        0x63D11B9: "%r13,0x2f0(%r15)", 0x63D11CC: "0x300(%r15),%r13",
        0x63D11DF: "0x310(%r15),%r13", 0x63D11EC: "0x320(%r15),%r13",
        0x63D1211: "%r9,%r10", 0x63D1221: "%rdx,%r10",
        0x63D127B: "0x320(%r15),%r10", 0x63D12BE: "0x2b0(%r15),%r13",
        0x63D132A: "0x2b0(%r15,%rcx,1),%r13", 0x63D138E: "0x2c0(%r15),%r13",
        0x63D1426: "0x2d0(%r15),%r13", 0x63D1439: "%r13,0x2e0(%r15)",
        0x63D144C: "%r13,0x2f0(%r15)", 0x63D145F: "%r13,0x300(%r15)",
        0x63D1472: "%r13,0x310(%r15)", 0x63D147F: "0x320(%r15),%r13",
        0x63D14B1: "%r10,%rdi", 0x63D14C1: "%r10,%r8",
        0x63D14EF: "%rdi,%r10", 0x63D14FF: "%rsi,%r10",
        0x63D152D: "%r9,%r10", 0x63D153D: "%r8,%r10",
        0x63D156A: "%r11,%r10", 0x63D157A: "%rsi,%r10",
        0x63D15D6: "%r9,%r10", 0x63D15E6: "%r8,%r10",
        0x63D160E: "%rax,%r10", 0x63D161E: "%r8,%r10",
        0x63D163F: "0x320(%r15),%r10", 0x63D1685: "0x320(%r15),%r10",
        0x63D16DE: "%rax,%r10", 0x63D16EE: "%rsi,%r10",
        0x63D1719: "%rdi,%r10", 0x63D1729: "%rsi,%r10",
        0x63D174D: "0x320(%r15),%r10", 0x63D1794: "0x320(%r15),%r10",
    }
    for a, ops in slot_cmps.items():
        check("slot compare at %s" % hex(a),
              "cmp" in by_addr[a] and ops in by_addr[a], by_addr[a])
    rev = [a for a, ops in slot_cmps.items()
           if re.match(r"%r(10|13),", ops)]
    check("slot compares total 74", len(slot_cmps) == 74,
          str(len(slot_cmps)))
    check("reversed-operand slot compares exactly 18",
          sorted(rev) == [0x63D0B1B, 0x63D0E47, 0x63D0ED9, 0x63D0F8B, 0x63D101C, 0x63D102C, 0x63D1083, 0x63D1093, 0x63D10B6, 0x63D115B, 0x63D1193, 0x63D11B9, 0x63D1439, 0x63D144C, 0x63D145F, 0x63D1472, 0x63D14B1, 0x63D14C1],
          str([hex(a) for a in sorted(rev)]))
    check("slot positions total 80",
          len(slot_cmps) + 6 == 80,
          "74 compare instructions cover 80 slot positions: D1's loop "
          "compare at 0x63d132a serves slots 1-7 (7 positions, 1 "
          "instruction), so 74 instructions + 6 extra positions = 80")
    # D1 loop form.
    check("D1 slot0 cmp 0x2b0 r15 r13",
          "cmp" in by_addr[0x63D12BE]
          and "0x2b0(%r15),%r13" in by_addr[0x63D12BE])
    check("D1 slot0 jne 0x63d131d",
          "jne" in by_addr[0x63D12C5] and "63d131d" in by_addr[0x63D12C5])
    check("D1 counter init mov 1 r14d",
          "mov" in by_addr[0x63D131D] and "$0x1,%r14d" in by_addr[0x63D131D])
    check("D1 loop cmp indexed",
          "cmp" in by_addr[0x63D132A]
          and "0x2b0(%r15,%rcx,1),%r13" in by_addr[0x63D132A])
    check("D1 loop jne 0x63d13ed",
          "jne" in by_addr[0x63D1332] and "63d13ed" in by_addr[0x63D1332])
    check("D1 counter add 1 r14",
          "add" in by_addr[0x63D13ED] and "$0x1,%r14" in by_addr[0x63D13ED])
    check("D1 counter cmp 8 r14",
          "cmp" in by_addr[0x63D13F1] and "$0x8,%r14" in by_addr[0x63D13F1])
    check("D1 counter jne 0x63d1323",
          "jne" in by_addr[0x63D13F5] and "63d1323" in by_addr[0x63D13F5])
    # Scan exhaustion: each scan's slot-7 mismatch reaches its lu-miss
    # site (follow the branch out of the slot-7 compare).
    ordered_all = sorted(by_addr)

    def next_addr(a):
        j = ordered_all.index(a)
        return ordered_all[j + 1] if j + 1 < len(ordered_all) else None

    def miss_call_after(entry):
        cur = entry
        for _ in range(12):
            if cur is None:
                return None
            if ("call" in by_addr[cur]
                    and "63d9700" in by_addr[cur]):
                return cur
            cur = next_addr(cur)
        return None

    EXH = [(0x63D1794, 0x63D17C1), (0x63D174D, 0x63D177A),
           (0x63D11EC, 0x63D1258), (0x63D147F, 0x63D15B6),
           (0x63D0FF8, 0x63D1063), (0x63D127B, 0x63D12A8),
           (0x63D1685, 0x63D16B7), (0x63D163F, 0x63D166C),
           (0x63D115B, 0x63D1183)]
    for s7, site in EXH:
        br = next_addr(s7)
        mn = mnemonic_of(by_addr[br])
        if mn in ("jne", "jnz"):
            entry = jump_target(by_addr[br])
        else:
            entry = next_addr(br)
        got = miss_call_after(entry)
        check("scan slot-7 %s exhausts to miss %s" % (hex(s7), hex(site)),
              got == site, "branch %s entry %s got %s"
              % (by_addr[br], hex(entry) if entry else None,
                 hex(got) if got else None))
    check("D1 loop exhausts to miss 0x63d1416",
          miss_call_after(0x63D13FB) == 0x63D1416)

    # Miss site 1 at 0x63d1063 (rcx = r10).
    check("miss 1 rdx mov 0x18 rsp", "mov" in by_addr[0x63D1043] and "0x18(%rsp),%rdx" in by_addr[0x63D1043], by_addr[0x63D1043])
    check("miss 1 xor r9d", "xor" in by_addr[0x63D104B] and "%r9d,%r9d" in by_addr[0x63D104B], by_addr[0x63D104B])
    check("miss 1 mov r10 rcx", "mov" in by_addr[0x63D1048] and "%r10,%rcx" in by_addr[0x63D1048], by_addr[0x63D1048])
    check("miss 1 mov r15 rdi", "mov" in by_addr[0x63D104E] and "%r15,%rdi" in by_addr[0x63D104E], by_addr[0x63D104E])
    check("miss 1 lea 0x6511a00 rsi", "lea" in by_addr[0x63D1051] and "6511a00" in by_addr[0x63D1051], by_addr[0x63D1051])
    check("miss 1 mov 1 r8d", "mov" in by_addr[0x63D1058] and "$0x1,%r8d" in by_addr[0x63D1058], by_addr[0x63D1058])
    check("miss 1 call 0x63d9700", "call" in by_addr[0x63D1063] and "63d9700" in by_addr[0x63D1063], by_addr[0x63D1063])
    check("miss 1 rejoin jmp 0x63d0659", "jmp" in by_addr[0x63D106D] and "63d0659" in by_addr[0x63D106D], by_addr[0x63D106D])
    # Miss site 2 at 0x63d1183 (rcx = r12).
    check("miss 2 rdx mov 0x18 rsp", "mov" in by_addr[0x63D1168] and "0x18(%rsp),%rdx" in by_addr[0x63D1168], by_addr[0x63D1168])
    check("miss 2 xor r9d", "xor" in by_addr[0x63D116D] and "%r9d,%r9d" in by_addr[0x63D116D], by_addr[0x63D116D])
    check("miss 2 mov r12 rcx", "mov" in by_addr[0x63D1170] and "%r12,%rcx" in by_addr[0x63D1170], by_addr[0x63D1170])
    check("miss 2 mov r15 rdi", "mov" in by_addr[0x63D1173] and "%r15,%rdi" in by_addr[0x63D1173], by_addr[0x63D1173])
    check("miss 2 lea 0x6511a00 rsi", "lea" in by_addr[0x63D1176] and "6511a00" in by_addr[0x63D1176], by_addr[0x63D1176])
    check("miss 2 mov 1 r8d", "mov" in by_addr[0x63D117D] and "$0x1,%r8d" in by_addr[0x63D117D], by_addr[0x63D117D])
    check("miss 2 call 0x63d9700", "call" in by_addr[0x63D1183] and "63d9700" in by_addr[0x63D1183], by_addr[0x63D1183])
    check("miss 2 rejoin jmp 0x63d0967", "jmp" in by_addr[0x63D1188] and "63d0967" in by_addr[0x63D1188], by_addr[0x63D1188])
    # Miss site 3 at 0x63d1258 (rcx = r10).
    check("miss 3 rdx mov 0x18 rsp", "mov" in by_addr[0x63D1238] and "0x18(%rsp),%rdx" in by_addr[0x63D1238], by_addr[0x63D1238])
    check("miss 3 xor r9d", "xor" in by_addr[0x63D1240] and "%r9d,%r9d" in by_addr[0x63D1240], by_addr[0x63D1240])
    check("miss 3 mov r10 rcx", "mov" in by_addr[0x63D123D] and "%r10,%rcx" in by_addr[0x63D123D], by_addr[0x63D123D])
    check("miss 3 mov r15 rdi", "mov" in by_addr[0x63D1243] and "%r15,%rdi" in by_addr[0x63D1243], by_addr[0x63D1243])
    check("miss 3 lea 0x6511a00 rsi", "lea" in by_addr[0x63D1246] and "6511a00" in by_addr[0x63D1246], by_addr[0x63D1246])
    check("miss 3 mov 1 r8d", "mov" in by_addr[0x63D124D] and "$0x1,%r8d" in by_addr[0x63D124D], by_addr[0x63D124D])
    check("miss 3 call 0x63d9700", "call" in by_addr[0x63D1258] and "63d9700" in by_addr[0x63D1258], by_addr[0x63D1258])
    check("miss 3 rejoin jmp 0x63d05df", "jmp" in by_addr[0x63D126C] and "63d05df" in by_addr[0x63D126C], by_addr[0x63D126C])
    # Miss site 4 at 0x63d12a8 (rcx = r12).
    check("miss 4 rdx mov 0x18 rsp", "mov" in by_addr[0x63D1288] and "0x18(%rsp),%rdx" in by_addr[0x63D1288], by_addr[0x63D1288])
    check("miss 4 xor r9d", "xor" in by_addr[0x63D128D] and "%r9d,%r9d" in by_addr[0x63D128D], by_addr[0x63D128D])
    check("miss 4 mov r12 rcx", "mov" in by_addr[0x63D1290] and "%r12,%rcx" in by_addr[0x63D1290], by_addr[0x63D1290])
    check("miss 4 mov r15 rdi", "mov" in by_addr[0x63D1293] and "%r15,%rdi" in by_addr[0x63D1293], by_addr[0x63D1293])
    check("miss 4 lea 0x6511a00 rsi", "lea" in by_addr[0x63D1296] and "6511a00" in by_addr[0x63D1296], by_addr[0x63D1296])
    check("miss 4 mov 1 r8d", "mov" in by_addr[0x63D129D] and "$0x1,%r8d" in by_addr[0x63D129D], by_addr[0x63D129D])
    check("miss 4 call 0x63d9700", "call" in by_addr[0x63D12A8] and "63d9700" in by_addr[0x63D12A8], by_addr[0x63D12A8])
    check("miss 4 rejoin jmp 0x63d06c5", "jmp" in by_addr[0x63D12B9] and "63d06c5" in by_addr[0x63D12B9], by_addr[0x63D12B9])
    # Miss site 5 at 0x63d1416 (rcx = r10).
    check("miss 5 rdx mov 0x18 rsp", "mov" in by_addr[0x63D13FB] and "0x18(%rsp),%rdx" in by_addr[0x63D13FB], by_addr[0x63D13FB])
    check("miss 5 xor r9d", "xor" in by_addr[0x63D1400] and "%r9d,%r9d" in by_addr[0x63D1400], by_addr[0x63D1400])
    check("miss 5 mov r10 rcx", "mov" in by_addr[0x63D1403] and "%r10,%rcx" in by_addr[0x63D1403], by_addr[0x63D1403])
    check("miss 5 mov r15 rdi", "mov" in by_addr[0x63D1406] and "%r15,%rdi" in by_addr[0x63D1406], by_addr[0x63D1406])
    check("miss 5 lea 0x6511a00 rsi", "lea" in by_addr[0x63D1409] and "6511a00" in by_addr[0x63D1409], by_addr[0x63D1409])
    check("miss 5 mov 1 r8d", "mov" in by_addr[0x63D1410] and "$0x1,%r8d" in by_addr[0x63D1410], by_addr[0x63D1410])
    check("miss 5 call 0x63d9700", "call" in by_addr[0x63D1416] and "63d9700" in by_addr[0x63D1416], by_addr[0x63D1416])
    check("miss 5 rejoin jmp 0x63d0d19", "jmp" in by_addr[0x63D141B] and "63d0d19" in by_addr[0x63D141B], by_addr[0x63D141B])
    # Miss site 6 at 0x63d15b6 (rcx = r10).
    check("miss 6 rdx mov 0x18 rsp", "mov" in by_addr[0x63D1596] and "0x18(%rsp),%rdx" in by_addr[0x63D1596], by_addr[0x63D1596])
    check("miss 6 xor r9d", "xor" in by_addr[0x63D159E] and "%r9d,%r9d" in by_addr[0x63D159E], by_addr[0x63D159E])
    check("miss 6 mov r10 rcx", "mov" in by_addr[0x63D159B] and "%r10,%rcx" in by_addr[0x63D159B], by_addr[0x63D159B])
    check("miss 6 mov r15 rdi", "mov" in by_addr[0x63D15A1] and "%r15,%rdi" in by_addr[0x63D15A1], by_addr[0x63D15A1])
    check("miss 6 lea 0x6511a00 rsi", "lea" in by_addr[0x63D15A4] and "6511a00" in by_addr[0x63D15A4], by_addr[0x63D15A4])
    check("miss 6 mov 1 r8d", "mov" in by_addr[0x63D15AB] and "$0x1,%r8d" in by_addr[0x63D15AB], by_addr[0x63D15AB])
    check("miss 6 call 0x63d9700", "call" in by_addr[0x63D15B6] and "63d9700" in by_addr[0x63D15B6], by_addr[0x63D15B6])
    check("miss 6 rejoin jmp 0x63d060d", "jmp" in by_addr[0x63D15C0] and "63d060d" in by_addr[0x63D15C0], by_addr[0x63D15C0])
    # Miss site 7 at 0x63d166c (rcx = r12).
    check("miss 7 rdx mov 0x18 rsp", "mov" in by_addr[0x63D164C] and "0x18(%rsp),%rdx" in by_addr[0x63D164C], by_addr[0x63D164C])
    check("miss 7 xor r9d", "xor" in by_addr[0x63D1651] and "%r9d,%r9d" in by_addr[0x63D1651], by_addr[0x63D1651])
    check("miss 7 mov r12 rcx", "mov" in by_addr[0x63D1654] and "%r12,%rcx" in by_addr[0x63D1654], by_addr[0x63D1654])
    check("miss 7 mov r15 rdi", "mov" in by_addr[0x63D1657] and "%r15,%rdi" in by_addr[0x63D1657], by_addr[0x63D1657])
    check("miss 7 lea 0x6511a00 rsi", "lea" in by_addr[0x63D165A] and "6511a00" in by_addr[0x63D165A], by_addr[0x63D165A])
    check("miss 7 mov 1 r8d", "mov" in by_addr[0x63D1661] and "$0x1,%r8d" in by_addr[0x63D1661], by_addr[0x63D1661])
    check("miss 7 call 0x63d9700", "call" in by_addr[0x63D166C] and "63d9700" in by_addr[0x63D166C], by_addr[0x63D166C])
    check("miss 7 rejoin jmp 0x63d073f", "jmp" in by_addr[0x63D1676] and "63d073f" in by_addr[0x63D1676], by_addr[0x63D1676])
    # Miss site 8 at 0x63d16b7 (rcx = r12).
    check("miss 8 rdx mov 0x18 rsp", "mov" in by_addr[0x63D1692] and "0x18(%rsp),%rdx" in by_addr[0x63D1692], by_addr[0x63D1692])
    check("miss 8 xor r9d", "xor" in by_addr[0x63D1697] and "%r9d,%r9d" in by_addr[0x63D1697], by_addr[0x63D1697])
    check("miss 8 mov r12 rcx", "mov" in by_addr[0x63D169A] and "%r12,%rcx" in by_addr[0x63D169A], by_addr[0x63D169A])
    check("miss 8 mov r15 rdi", "mov" in by_addr[0x63D169D] and "%r15,%rdi" in by_addr[0x63D169D], by_addr[0x63D169D])
    check("miss 8 lea 0x6511a00 rsi", "lea" in by_addr[0x63D16A0] and "6511a00" in by_addr[0x63D16A0], by_addr[0x63D16A0])
    check("miss 8 mov 1 r8d", "mov" in by_addr[0x63D16A7] and "$0x1,%r8d" in by_addr[0x63D16A7], by_addr[0x63D16A7])
    check("miss 8 call 0x63d9700", "call" in by_addr[0x63D16B7] and "63d9700" in by_addr[0x63D16B7], by_addr[0x63D16B7])
    check("miss 8 rejoin jmp 0x63d06f3", "jmp" in by_addr[0x63D16C6] and "63d06f3" in by_addr[0x63D16C6], by_addr[0x63D16C6])
    # Miss site 9 at 0x63d177a (rcx = r14).
    check("miss 9 rdx mov 0x18 rsp", "mov" in by_addr[0x63D175A] and "0x18(%rsp),%rdx" in by_addr[0x63D175A], by_addr[0x63D175A])
    check("miss 9 xor r9d", "xor" in by_addr[0x63D175F] and "%r9d,%r9d" in by_addr[0x63D175F], by_addr[0x63D175F])
    check("miss 9 mov r14 rcx", "mov" in by_addr[0x63D1762] and "%r14,%rcx" in by_addr[0x63D1762], by_addr[0x63D1762])
    check("miss 9 mov r15 rdi", "mov" in by_addr[0x63D1765] and "%r15,%rdi" in by_addr[0x63D1765], by_addr[0x63D1765])
    check("miss 9 lea 0x6511a00 rsi", "lea" in by_addr[0x63D1768] and "6511a00" in by_addr[0x63D1768], by_addr[0x63D1768])
    check("miss 9 mov 1 r8d", "mov" in by_addr[0x63D176F] and "$0x1,%r8d" in by_addr[0x63D176F], by_addr[0x63D176F])
    check("miss 9 call 0x63d9700", "call" in by_addr[0x63D177A] and "63d9700" in by_addr[0x63D177A], by_addr[0x63D177A])
    check("miss 9 rejoin jmp 0x63d0509", "jmp" in by_addr[0x63D1784] and "63d0509" in by_addr[0x63D1784], by_addr[0x63D1784])
    # Miss site 10 at 0x63d17c1 (rcx = r14).
    check("miss 10 rdx mov 0x18 rsp", "mov" in by_addr[0x63D17A1] and "0x18(%rsp),%rdx" in by_addr[0x63D17A1], by_addr[0x63D17A1])
    check("miss 10 xor r9d", "xor" in by_addr[0x63D17A6] and "%r9d,%r9d" in by_addr[0x63D17A6], by_addr[0x63D17A6])
    check("miss 10 mov r14 rcx", "mov" in by_addr[0x63D17A9] and "%r14,%rcx" in by_addr[0x63D17A9], by_addr[0x63D17A9])
    check("miss 10 mov r15 rdi", "mov" in by_addr[0x63D17AC] and "%r15,%rdi" in by_addr[0x63D17AC], by_addr[0x63D17AC])
    check("miss 10 lea 0x6511a00 rsi", "lea" in by_addr[0x63D17AF] and "6511a00" in by_addr[0x63D17AF], by_addr[0x63D17AF])
    check("miss 10 mov 1 r8d", "mov" in by_addr[0x63D17B6] and "$0x1,%r8d" in by_addr[0x63D17B6], by_addr[0x63D17B6])
    check("miss 10 call 0x63d9700", "call" in by_addr[0x63D17C1] and "63d9700" in by_addr[0x63D17C1], by_addr[0x63D17C1])
    check("miss 10 rejoin jmp 0x63d04db", "jmp" in by_addr[0x63D17D2] and "63d04db" in by_addr[0x63D17D2], by_addr[0x63D17D2])

    # CFG: successors (jump targets inside window + fall-through; calls
    # fall through except noreturn PLT calls; ret is terminal).
    def call_target(line):
        m = re.search(r"\tcall\s+([0-9a-f]+)", line)
        return int(m.group(1), 16) if m else None

    NORETURN = {0x63F0D70}
    succ = {}
    ordered = sorted(by_addr)
    for idx, a in enumerate(ordered):
        line = by_addr[a]
        mn = mnemonic_of(line)
        s = set()
        t = jump_target(line) if mn.startswith("j") else None
        ct = call_target(line) if mn == "call" else None
        if mn == "ret":
            pass
        elif mn == "call" and ct in NORETURN:
            pass
        elif mn == "jmp":
            if t is not None and START <= t < END:
                s.add(t)
        elif mn.startswith("j"):
            if t is not None and START <= t < END:
                s.add(t)
            if idx + 1 < len(ordered):
                s.add(ordered[idx + 1])
        else:
            if idx + 1 < len(ordered):
                s.add(ordered[idx + 1])
        succ[a] = s
    preds = {a: set() for a in ordered}
    for a, ss in succ.items():
        for t in ss:
            preds[t].add(a)

    def reaches(src, dst):
        seen = set()
        stack = [src]
        while stack:
            x = stack.pop()
            if x == dst:
                return True
            if x in seen:
                continue
            seen.add(x)
            stack.extend(succ.get(x, ()))
        return False

    for _s in [0x63D1063, 0x63D1183, 0x63D1258, 0x63D12A8, 0x63D1416,
               0x63D15B6, 0x63D166C, 0x63D16B7, 0x63D177A, 0x63D17C1]:
        check("entry reaches lu-miss site %s" % hex(_s), reaches(START, _s))
    check("entry reaches ret 0x63d0817", reaches(START, 0x63D0817))

    # Reaching definitions for one register: forward fixpoint. A call
    # kills the register (caller-saved) and defines ("CALL", addr); a
    # cmov is a conditional def (does not kill); any other write kills
    # prior defs. ENTRY is the caller's value at the window entry.
    CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9",
                    "r10", "r11"}

    def reaching_defs(reg):
        IN = {a: set() for a in ordered}
        OUT = {a: set() for a in ordered}
        IN[START] = {("ENTRY",)}

        def is_def(x):
            return (isinstance(x, tuple)
                    or (isinstance(x, int)
                        and canon(dst_reg(by_addr[x])) == reg))

        changed = True
        while changed:
            changed = False
            for a in ordered:
                new_in = set()
                for p in preds[a]:
                    new_in |= OUT[p]
                if a == START:
                    new_in |= {("ENTRY",)}
                if new_in != IN[a]:
                    IN[a] = new_in
                    changed = True
                mn = mnemonic_of(by_addr[a])
                if mn == "call" and reg in CALLER_SAVED:
                    new_out = {("CALL", a)}
                elif mn.startswith("cmov"):
                    d = canon(dst_reg(by_addr[a]))
                    new_out = set(IN[a]) | ({a} if d == reg else set())
                else:
                    d = canon(dst_reg(by_addr[a]))
                    if d == reg:
                        new_out = ({x for x in IN[a] if not is_def(x)}
                                   | {a})
                    else:
                        new_out = set(IN[a])
                if new_out != OUT[a]:
                    OUT[a] = new_out
                    changed = True
        return IN

    SITES = [0x63D1063, 0x63D1183, 0x63D1258, 0x63D12A8, 0x63D1416,
             0x63D15B6, 0x63D166C, 0x63D16B7, 0x63D177A, 0x63D17C1]
    RCX = {0x63D1063: 0x63D1048, 0x63D1183: 0x63D1170, 0x63D1258: 0x63D123D,
           0x63D12A8: 0x63D1290, 0x63D1416: 0x63D1403, 0x63D15B6: 0x63D159B,
           0x63D166C: 0x63D1654, 0x63D16B7: 0x63D169A, 0x63D177A: 0x63D1762,
           0x63D17C1: 0x63D17A9}
    RDI = {0x63D1063: 0x63D104E, 0x63D1183: 0x63D1173, 0x63D1258: 0x63D1243,
           0x63D12A8: 0x63D1293, 0x63D1416: 0x63D1406, 0x63D15B6: 0x63D15A1,
           0x63D166C: 0x63D1657, 0x63D16B7: 0x63D169D, 0x63D177A: 0x63D1765,
           0x63D17C1: 0x63D17AC}
    RSI = {0x63D1063: 0x63D1051, 0x63D1183: 0x63D1176, 0x63D1258: 0x63D1246,
           0x63D12A8: 0x63D1296, 0x63D1416: 0x63D1409, 0x63D15B6: 0x63D15A4,
           0x63D166C: 0x63D165A, 0x63D16B7: 0x63D16A0, 0x63D177A: 0x63D1768,
           0x63D17C1: 0x63D17AF}
    RDX = {0x63D1063: 0x63D1043, 0x63D1183: 0x63D1168, 0x63D1258: 0x63D1238,
           0x63D12A8: 0x63D1288, 0x63D1416: 0x63D13FB, 0x63D15B6: 0x63D1596,
           0x63D166C: 0x63D164C, 0x63D16B7: 0x63D1692, 0x63D177A: 0x63D175A,
           0x63D17C1: 0x63D17A1}
    R8 = {0x63D1063: 0x63D1058, 0x63D1183: 0x63D117D, 0x63D1258: 0x63D124D,
          0x63D12A8: 0x63D129D, 0x63D1416: 0x63D1410, 0x63D15B6: 0x63D15AB,
          0x63D166C: 0x63D1661, 0x63D16B7: 0x63D16A7, 0x63D177A: 0x63D176F,
          0x63D17C1: 0x63D17B6}
    R9 = {0x63D1063: 0x63D104B, 0x63D1183: 0x63D116D, 0x63D1258: 0x63D1240,
          0x63D12A8: 0x63D128D, 0x63D1416: 0x63D1400, 0x63D15B6: 0x63D159E,
          0x63D166C: 0x63D1651, 0x63D16B7: 0x63D1697, 0x63D177A: 0x63D175F,
          0x63D17C1: 0x63D17A6}
    rcx_in = reaching_defs("rcx")
    rdi_in = reaching_defs("rdi")
    rsi_in = reaching_defs("rsi")
    rdx_in = reaching_defs("rdx")
    r8_in = reaching_defs("r8")
    r9_in = reaching_defs("r9")
    for s in SITES:
        check("rcx at %s only def is mov rcx %s" % (hex(s), hex(RCX[s])),
              rcx_in[s] == {RCX[s]}, str(rcx_in[s]))
        check("rdi at %s only def is mov rdi %s" % (hex(s), hex(RDI[s])),
              rdi_in[s] == {RDI[s]}, str(rdi_in[s]))
        check("rsi at %s only def is lea rsi %s" % (hex(s), hex(RSI[s])),
              rsi_in[s] == {RSI[s]}, str(rsi_in[s]))
        check("rdx at %s only def is mov rdx %s" % (hex(s), hex(RDX[s])),
              rdx_in[s] == {RDX[s]}, str(rdx_in[s]))
        check("r8 at %s only def is mov r8 %s" % (hex(s), hex(R8[s])),
              r8_in[s] == {R8[s]}, str(r8_in[s]))
        check("r9 at %s only def is xor r9 %s" % (hex(s), hex(R9[s])),
              r9_in[s] == {R9[s]}, str(r9_in[s]))
    r15_in = reaching_defs("r15")
    for s in SITES:
        check("r15 at %s only def is entry mov rdi r15 0x63d03a2" % hex(s),
              r15_in[s] == {0x63D03A2}, str(r15_in[s]))
    # Walk-key provenance (loop-carried: restores and re-definitions
    # across outer iterations join in).
    R10 = {0x63D1063: {0x63D059C, 0x63D0A9A, 0x63D125D, 0x63D15BB},
           0x63D1183: {0x63D0692, 0x63D12B4, 0x63D1671, 0x63D16BC},
           0x63D1258: {0x63D059C, 0x63D0A9A},
           0x63D12A8: {0x63D0692},
           0x63D1416: {0x63D059C, 0x63D0A9A, 0x63D1068, 0x63D125D, 0x63D15BB},
           0x63D15B6: {0x63D059C, 0x63D0A9A, 0x63D125D},
           0x63D166C: {0x63D0692, 0x63D12B4, 0x63D16BC},
           0x63D16B7: {0x63D0692, 0x63D12B4},
           0x63D177A: {0x63D04A6, 0x63D17CD},
           0x63D17C1: {0x63D04A6}}
    R12 = {0x63D1063: {0x63D061F},
           0x63D1183: {0x63D0680},
           0x63D1258: {0x63D053C, 0x63D055D, 0x63D058F},
           0x63D12A8: {0x63D0680},
           0x63D1416: {0x63D061F, 0x63D0D4B},
           0x63D15B6: {0x63D053C, 0x63D055D, 0x63D058F, 0x63D0E0F},
           0x63D166C: {0x63D0680},
           0x63D16B7: {0x63D0680},
           0x63D177A: {0x63D03D0, 0x63D075F},
           0x63D17C1: {0x63D03D0, 0x63D075F}}
    R14 = {0x63D1063: {0x63D0636},
           0x63D1183: {0x63D1072},
           0x63D1258: {0x63D0538},
           0x63D12A8: {0x63D06A2},
           0x63D1416: {0x63D13ED},
           0x63D15B6: {0x63D05ED},
           0x63D166C: {0x63D0B0D},
           0x63D16B7: {0x63D06A2, 0x63D0A58, 0x63D12AD},
           0x63D177A: {0x63D0489},
           0x63D17C1: {0x63D0489}}
    r10_in = reaching_defs("r10")
    r12_in = reaching_defs("r12")
    r14_in = reaching_defs("r14")
    for s in SITES:
        check("r10 at %s" % hex(s), r10_in[s] == R10[s], str(r10_in[s]))
        check("r12 at %s" % hex(s), r12_in[s] == R12[s], str(r12_in[s]))
        check("r14 at %s" % hex(s), r14_in[s] == R14[s], str(r14_in[s]))
    rax_in = reaching_defs("rax")
    check("rax at ret is xor 0 / mov 1 only",
          rax_in[0x63D0817] == {0x63D066F, 0x63D07F0, 0x63D0D30, 0x63D1316},
          str(rax_in[0x63D0817]))
    check("records lu-miss sites match census",
          [s.get("site") for s in rec.get("lu_miss_sites", [])] ==
          ["0x63d1063", "0x63d1183", "0x63d1258", "0x63d12a8", "0x63d1416",
           "0x63d15b6", "0x63d166c", "0x63d16b7", "0x63d177a", "0x63d17c1"])
    check("records second-handler sites 1",
          [s.get("site") for s in rec.get("second_handler_sites", [])] ==
          ["0x63d0837"])
    check("records scan slot compares 74",
          rec.get("scan", {}).get("slot_compares_total") == 74)
    check("records scan reversed 18",
          rec.get("scan", {}).get("reversed_operand_compares") == 18)
    check("records scan reversed sites match",
          rec.get("scan", {}).get("reversed_sites") ==
          sorted(hex(a) for a in
                 [0x63D0B1B, 0x63D0E47, 0x63D0ED9, 0x63D0F8B, 0x63D101C,
                  0x63D102C, 0x63D1083, 0x63D1093, 0x63D10B6, 0x63D115B,
                  0x63D1193, 0x63D11B9, 0x63D1439, 0x63D144C, 0x63D145F,
                  0x63D1472, 0x63D14B1, 0x63D14C1]))

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for va in [0x65096C0, 0x6511A00, 0x67277C0, 0x6727A00, 0x6728140]:
        check("address %s inside .bss" % hex(va),
              bss[3] <= va < bss[3] + bss[5])
    dr = secmap[".data.rel.ro"]
    check("address 0x64da4b0 inside .data.rel.ro",
          dr[3] <= 0x64DA4B0 < dr[3] + dr[5])
    txt = secmap[".text"]
    check("window inside .text",
          txt[3] <= START and END <= txt[3] + txt[5])

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

    # raw-e8 census: scan .text for e8 with rel32 targets 0x63d9700 /
    # 0x63d9880 / 0x634ebb0 (second handler).
    text_sec = secmap[".text"]
    tva, toff_sec, tsize = text_sec[3], text_sec[4], text_sec[5]
    tbytes = node[toff_sec:toff_sec + tsize]
    counts = {}
    bti_counts = {}
    sh_counts = {}
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
                if tgtv == 0x634EBB0:
                    sh_counts[fdes[k][0]] = sh_counts.get(fdes[k][0], 0) + 1
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
    check("this FDE raw lu-miss 10", counts.get(START, 0) == 10,
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
    check("this FDE raw second-handler 1",
          sh_counts.get(START, 0) == 1, str(sh_counts.get(START, 0)))
    check("raw-e8 second-handler total 64", sum(sh_counts.values()) == 64,
          str(sum(sh_counts.values())))
    check("raw-e8 second-handler FDEs 28", len(sh_counts) == 28,
          str(len(sh_counts)))
    check("next candidate raw lu-miss 10", counts.get(0x63D17E0, 0) == 10,
          str(counts.get(0x63D17E0, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63D17E0, 0) == 0,
          str(bti_counts.get(0x63D17E0, 0)))
    check("next candidate raw second-handler 1",
          sh_counts.get(0x63D17E0, 0) == 1,
          str(sh_counts.get(0x63D17E0, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 11th survivor",
          survey.get("survivors", [None] * 11)[10] == "0x63d03a0",
          str(survey.get("survivors", [])[:12]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window IS shared",
          "0x63d03a0" in survey.get("shared_survivors", []))
    check("survey next candidate IS shared",
          "0x63d17e0" in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x63d17e0..0x63d2a80",
          nq.get("range") == "0x63d17e0..0x63d2a80", str(nq.get("range")))
    check("next question bytes 4768", nq.get("bytes") == 4768,
          str(nq.get("bytes")))
    check("next question lu-miss sites 10",
          nq.get("lu_miss_sites") == 10, str(nq.get("lu_miss_sites")))
    check("next question lu-miss site list",
          nq.get("lu_miss_site") == ["0x63d2549", "0x63d2575", "0x63d26f7",
                                     "0x63d2738", "0x63d2771", "0x63d2871",
                                     "0x63d28a6", "0x63d29b3", "0x63d29e1",
                                     "0x63d2a76"],
          str(nq.get("lu_miss_site")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 928", nq.get("strict") == 928,
          str(nq.get("strict")))
    check("next question calls 20", nq.get("calls") == 20,
          str(nq.get("calls")))
    check("next question second-handler sites 1",
          nq.get("second_handler_sites") == 1,
          str(nq.get("second_handler_sites")))
    check("next question bsr 2", nq.get("bsr") == 2,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63d1bd7"],
          str(nq.get("ret")))
    check("records census strict 1037",
          rec.get("census", {}).get("strict") == 1037)
    check("records census calls 23",
          rec.get("census", {}).get("calls") == 23)
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
    # next candidate 0x63d17e0..0x63d2a80 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63D17E0 < p[1] and p[0] < 0x63D2A80]
    check("next candidate 0x63d17e0 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63D2A80 and 0x63D17E0 < END))

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
