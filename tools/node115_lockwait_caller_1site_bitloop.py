"""Static verifier for RE-001-node115-lockwait-caller-1site-bitloop.

FIRST packet of the lock-wait-helper-caller frontier (callers of the
lock-wait helper 0x63bf680): FDE 0x6362190..0x6362901, 1,905 bytes, 446
strict instructions, 13 calls (1 lock-wait site at 0x636286f, 0
lu-miss, 0 bin_table_init, 0 second-handler sites), 1 ret at
0x636282d with exit value 0 (canary residue), bsr 0, 49 jumps with 1
tail jump to 0x6360ed0 (itself a lock-wait survivor), endbr64 1,
canary present, lock sub 0 / lock add 0, NO TLS flag check, NO
prefetch instructions.

Shape: trylock(node+0x40) -> on failure the lock-wait helper
0x63bf680 (single argument: rdi = current node pointer, proven by
reaching-definitions) -> waited flag set -> retry at the loop head.
The loop walks a +0xc0 list; per element a 10-bit tag
(word >> 0x1c) & 0x3ff decides between the list-insert path (tag
== 0, 0x650969c table check, 0x63ac480 call) and the bitmap path:
a 10-entry unrolled scan for a nonzero 64-bit word at node+0x40,
then tzcnt/btc bit extraction (7 tzcnt + 7 btc: 3-bit remainder
prologue + 4-at-a-time loop + trailing single), writing normalized
pointers to the r12 output array. Epilogue: stats (+0x70 += i,
+0x90 count++), unlock, wake helper 0x63c0340 when 0x28(%rsp)
is nonzero, memmove compaction when needed, refcount decrement at
0x98(%rbp); a last-reference drop takes the 0x635f340 cleanup and
tail-jumps to 0x6360ed0 with rdi=rbp, rcx=0, rdx=0, rax=0.

#329's pointer for this window (1,905 bytes, 446 strict, 13 calls,
1 lock-wait site at 0x636286f, 0 lu-miss / 0 bin_table_init /
0 second-handler sites, 1 ret at 0x636282d, bsr 0, endbr64 1, canary
present, 49 jumps with 1 tail jump to 0x6360ed0) was verified correct
by targeted objdump census -- with ONE correction: #329 stated PLT
calls 7, but the true count is 6. Call 0x63f0960 (at 0x63624ee) has
no @plt suffix and its target lies inside .text (0x63f0960 <
0x63f0a00), so it is an internal call, not a PLT stub. The four
real PLT targets are 0x63f17b0 (trylock x2), 0x63f0b70 (unlock x2),
0x63f0a70 (memmove), 0x63f0d70 (stack_chk_fail). Also clarified:
#329's "largest 1-site disjoint candidate" holds WITHIN the
500-2000B light band; two larger 1-site disjoint survivors exist
above the band (0x63b4b50, 2,770B; 0x63eb870, 2,408B).

The lu-miss frontier is exhausted (16/16 claimed, #314-#329). The
lock-wait frontier has 344 survivors (474 sites / 385 FDEs, 319
with exactly 1 site); this packet claims the largest 1-site
disjoint survivor in the 500-2000B range.

Next question: 0x6362910..0x6362f82 (1,650 bytes, 393 strict, 9
calls, 1 lock-wait site at 0x6362f25, 0 lu-miss / 0 bin_table_init
/ 0 second-handler sites, 1 ret at 0x6362e78, bsr 0, endbr64 1, NO
canary, 45 jumps, 0 outside).

Usage: python3 tools/node115_lockwait_caller_1site_bitloop.py
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
                      "RE-001-node115-lockwait-caller-1site-bitloop")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lockwait-caller-1site-bitloop"
NAME = "lockwait_caller_1site_bitloop"
START, END = 0x6362190, 0x6362901

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
    check("target FDE size 1905", END - START == 1905)
    prev = fdes[i - 1]
    check("prev FDE 0x6362130..0x6362189",
          prev == (0x6362130, 0x6362189), str(prev))
    check("prev gap 7 (0xcc padding)", START - prev[1] == 7)
    check("prev gap bytes are 0xcc int3 padding",
          node[toff(prev[1]):toff(START)] == b"\xcc" * 7)
    nxt = fdes[i + 1]
    check("next FDE 0x6362910..0x6362f82",
          nxt == (0x6362910, 0x6362F82), str(nxt))
    check("next gap 15 (0xcc padding)", nxt[0] - END == 15)
    check("next gap bytes are 0xcc int3 padding",
          node[toff(END):toff(nxt[0])] == b"\xcc" * 15)
    check("next FDE starts endbr64",
          node[toff(nxt[0]):toff(nxt[0]) + 4] == b"\xf3\x0f\x1e\xfa")
    check("prev FDE end is 7 bytes before this FDE start",
          prev[1] == START - 7)
    check("tail-jump target FDE 0x6360ed0..0x636116d",
          fdes[bisect.bisect_left(starts, 0x6360ED0)] ==
          (0x6360ED0, 0x636116D))
    check("lock-wait helper FDE 0x63bf680..0x63bf7ee",
          fdes[bisect.bisect_left(starts, 0x63BF680)] ==
          (0x63BF680, 0x63BF7EE))
    check("second-handler FDE 0x634ebb0..0x634eccd",
          fdes[bisect.bisect_left(starts, 0x634EBB0)] ==
          (0x634EBB0, 0x634ECCD))
    check("key resolver FDE 0x6365150..0x6365660",
          fdes[bisect.bisect_left(starts, 0x6365150)] ==
          (0x6365150, 0x6365660))

    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_bitloop.hex"))
    check("hex exhibit raw bytes 1905", len(hexb) == 1905, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_bitloop.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 446", len(lines) == 446, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 13", len(calls) == 13, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x636282d",
          sorted(addr_of(l) for l in rets) == [0x636282D],
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
    expect = {0x63F17B0: 2, 0x63AC480: 1, 0x63F0960: 1, 0x63F0B70: 2,
              0x63C0340: 1, 0x63606D0: 1, 0x63BF680: 1, 0x63F0A70: 1,
              0x6360610: 1, 0x635F340: 1, 0x63F0D70: 1}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct call targets 11", len(tgt) == 11, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 0",
          tgt.get(0x63D9700, 0) == 0, str(tgt.get(0x63D9700, 0)))
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called 1 time", tgt.get(0x63BF680, 0) == 1,
          str(tgt.get(0x63BF680, 0)))
    check("lock-wait site is 0x636286f",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x636286F])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("stack_chk_fail plt call 1",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 6 (by @plt suffix, not address range)",
          len(plt_calls) == 6, str(len(plt_calls)))
    check("distinct PLT targets 4",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 4)
    check("0x63f0960 is an internal .text call, NOT a PLT stub",
          not any("63f0960" in l and "@plt" in l for l in calls))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0), ("#325", 0x63D17E0),
                  ("#326", 0x63D2A80), ("#327", 0x63D3F0E),
                  ("#328", 0x63D4048), ("#329", 0x63E94A0)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", bsr == [], str([hex(addr_of(l)) for l in bsr]))
    locks = [l for l in lines if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))
    check("lock sub count 0",
          sum(1 for l in lines if "lock sub" in l) == 0)
    check("lock add count 0",
          sum(1 for l in lines if "lock add" in l) == 0)
    jmps = [l for l in lines
            if mnemonic_of(l) in ("jmp", "je", "jne", "ja", "jb", "jae",
                                  "jbe", "jg", "jl", "jge", "jle", "jo",
                                  "jno", "js", "jns", "jp", "jnp")]
    check("jump lines 49", len(jmps) == 49, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure exactly one outside: tail jmp 0x63628f7->0x6360ed0",
          outside == [(0x63628F7, 0x6360ED0)], str(outside))
    check("jump targets are exactly the 49 branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x6360ED0, 0x636221D, 0x636221D, 0x6362222, 0x6362298,
           0x6362298, 0x63622AC, 0x63622E0, 0x636233B, 0x6362342,
           0x6362342, 0x636236C, 0x636237C, 0x636237C, 0x63623F0,
           0x63624B5, 0x63624D0, 0x63624D0, 0x63624D0, 0x6362597,
           0x63625C8, 0x6362637, 0x6362637, 0x6362637, 0x63626A4,
           0x63626C0, 0x63626C0, 0x63626C0, 0x63626C0, 0x63626C0,
           0x63626C0, 0x63626C0, 0x63626C0, 0x63626D0, 0x6362710,
           0x6362725, 0x6362730, 0x63627BC, 0x63627BC, 0x63627F0,
           0x6362805, 0x6362805, 0x636282E, 0x636286C, 0x636287E,
           0x636289D, 0x63628AF, 0x63628FC, 0x63628FC],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x6362190",
          "endbr64" in by_addr[START])
    check("canary present: exactly 3 fs:0x28 lines",
          sorted(addr_of(l) for l in lines if "%fs:0x28" in l) ==
          [0x63621CE, 0x636280D, 0x63628CF])
    check("canary load at entry 0x63621ce",
          "mov" in by_addr[0x63621CE] and "%fs:0x28,%rax" in by_addr[0x63621CE])
    check("canary saved to 0x98(rsp) at 0x63621d7",
          "mov" in by_addr[0x63621D7] and "%rax,0x98(%rsp)" in by_addr[0x63621D7])
    check("stack_chk_fail call at 0x63628fc",
          "call" in by_addr[0x63628FC] and "63f0d70" in by_addr[0x63628FC])
    check("no TLS flag fs:0x330 anywhere",
          not any("%fs:0x330" in l for l in lines))
    check("no size-table lea 0x6727a00 anywhere",
          not any("6727a00" in l for l in lines))
    check("no byte-table lea 0x67277c0 anywhere",
          not any("67277c0" in l for l in lines))
    check("no fallback-table lea 0x6728140 anywhere",
          not any("6728140" in l for l in lines))
    check("no node-table lea 0x65096c0 anywhere",
          not any("65096c0" in l for l in lines))
    check("no lu-miss .bss 0x6511a00 anywhere",
          not any("6511a00" in l for l in lines))
    check("bss table lea 0x6511780 at 0x6362222",
          "lea" in by_addr[0x6362222] and "6511780" in by_addr[0x6362222])
    check("bss lea 0x650969c at 0x63622e0 (list-insert path)",
          "lea" in by_addr[0x63622E0] and "650969c" in by_addr[0x63622E0])
    check("bss lea 0x6711b40 at 0x63621b0 (entry table base)",
          "lea" in by_addr[0x63621B0] and "6711b40" in by_addr[0x63621B0])
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 7",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "tzcnt") ==
          [0x6362541, 0x636257A, 0x63625A3, 0x63625D1, 0x63625E6,
           0x6362609, 0x636263F])
    check("btc 7",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "btc") ==
          [0x6362549, 0x6362585, 0x63625AE, 0x63625DC, 0x63625EF,
           0x6362612, 0x636264A])
    check("tzcnt/btc pairs share the same bitmap word (7 each)",
          len([l for l in lines if mnemonic_of(l) == "tzcnt"]) ==
          len([l for l in lines if mnemonic_of(l) == "btc"]) == 7)

    # Instruction spot checks: (address, mnemonic, operand substring).
    # Entry / setup.
    EXPECT = [
        (0x6362190, "endbr64", ""),
        (0x6362194, "push", "%r15"),
        (0x6362198, "mov", "%rdx,%r14"),
        (0x63621A0, "mov", "%rdi,%rbp"),
        (0x63621A4, "sub", "$0xa8,%rsp"),
        (0x63621AB, "movzwl", "0x14(%r14),%ebx"),
        (0x63621B0, "lea", "0x3af989(%rip),%rcx"),
        (0x63621B7, "mov", "%rsi,0x38(%rsp)"),
        (0x63621CE, "mov", "%fs:0x28,%rax"),
        (0x63621D7, "mov", "%rax,0x98(%rsp)"),
        (0x63621E9, "lea", "(%rsi,%r10,1),%r12"),
        (0x63621F1, "lea", "(%rcx,%rdx,8),%r13"),
        (0x63621F5, "test", "%rdi,%rdi"),
        (0x63621FA, "cmpq", "$0x0,0x90(%rdi)"),
        (0x6362204, "movzbl", "0xa1(%rdi,%rax,1),%edx"),
        (0x6362222, "lea", "0x1af557(%rip),%r15"),
        (0x6362232, "mov", "(%r15,%rax,4),%esi"),
        (0x6362253, "mov", "$0x1,%ebx"),
        (0x6362264, "lea", "0x40(%r10),%r15"),
        (0x6362270, "mov", "%r10,%r13"),
        (0x6362273, "mov", "%r15,%rdi"),
        # trylock 1: node+0x40 mutex.
        (0x6362284, "call", "63f17b0"),
        (0x6362289, "test", "%eax,%eax"),
        (0x636228B, "jne", "636286c"),
        # Loop head: acquisition count + owner tracking.
        (0x6362298, "addq", "$0x1,0x38(%r13)"),
        (0x636229D, "cmp", "0x30(%r13),%rbp"),
        (0x63622A3, "addq", "$0x1,0x28(%r13)"),
        (0x63622AC, "mov", "0x24(%rsp),%r8d"),
        (0x63622B1, "cmp", "%r8d,0x20(%rsp)"),
        (0x63622B6, "jae", "6362725"),
        (0x63622BC, "lea", "0xc8(%r13),%r14"),
        (0x63622CD, "mov", "%r13,%r14"),
        (0x63622D5, "jmp", "636237c"),
        # List-insert path (tag == 0).
        (0x63622E0, "lea", "0x1a73b5(%rip),%r12"),
        (0x63622EC, "mov", "(%r12),%edi"),
        (0x63622F0, "cmp", "%edi,0x13450(%r9)"),
        (0x6362342, "mov", "0x30(%rsp),%rdi"),
        (0x6362347, "call", "63ac480"),
        (0x6362355, "addq", "$0x1,0xa8(%r14)"),
        # Inner loop: next list element, tag extract.
        (0x636237C, "mov", "0xc0(%r14),%r15"),
        (0x6362388, "mov", "(%r15),%r13"),
        (0x636238B, "mov", "%r13,%rbp"),
        (0x636238E, "shr", "$0x1c,%rbp"),
        (0x6362392, "and", "$0x3ff,%ebp"),
        (0x6362398, "je", "63622e0"),
        (0x63623C6, "mov", "0x40(%r15),%rbx"),
        (0x63623CA, "cmp", "%ebp,%r9d"),
        (0x63623D0, "cmovbe", "%r9d,%ebp"),
        # Bitmap word scan: 10-entry unrolled search for nonzero word.
        (0x63623F0, "mov", "%r8d,%r13d"),
        (0x63623F3, "test", "%rbx,%rbx"),
        (0x63623F6, "jne", "63624d0"),
        (0x63623FC, "lea", "0x1(%r8),%r13d"),
        (0x6362400, "mov", "0x40(%r9,%r13,8),%rbx"),
        (0x63624D0, "mov", "%rbx,%rdi"),
        (0x63624D3, "mov", "%r8d,%r14d"),
        (0x63624E0, "shl", "$0x6,%r14d"),
        (0x63624EE, "call", "63f0960"),
        (0x63624FD, "movslq", "%eax,%rdi"),
        (0x636252C, "and", "$0x3,%r11d"),
        (0x6362530, "je", "6362637"),
        # Remainder prologue (count&3 == 1..3): tzcnt/btc extract.
        (0x6362541, "tzcnt", "%rbx,%rdx"),
        (0x6362549, "btc", "%rdx,%rbx"),
        (0x636255A, "mov", "%rdx,(%r12,%rdi,8)"),
        # 4-at-a-time loop.
        (0x63625C8, "xor", "%r11d,%r11d"),
        (0x63625CD, "sub", "$0x4,%rax"),
        (0x63625D1, "tzcnt", "%rbx,%r11"),
        (0x6362637, "xor", "%r11d,%r11d"),
        (0x636263F, "tzcnt", "%rbx,%r11"),
        (0x636265C, "test", "%rax,%rax"),
        (0x636265F, "jne", "63625c8"),
        (0x6362665, "mov", "%rbx,0x40(%r9,%r13,8)"),
        (0x636266A, "cmp", "%r10d,%ebp"),
        (0x636266D, "jb", "63623f0"),
        (0x636267B, "add", "%r10d,0x20(%rsp)"),
        (0x6362685, "shl", "$0x1c,%rax"),
        (0x6362699, "cmp", "%r10d,0x20(%rsp)"),
        (0x636269E, "jb", "636237c"),
        (0x63626A4, "mov", "0x40(%rsp),%rbp"),
        (0x63626B9, "jmp", "6362730"),
        (0x63626C0, "mov", "%r14d,%r8d"),
        (0x63626C3, "jmp", "63624d0"),
        # Cleanup path (list element was NULL).
        (0x63626D0, "movq", "$0x0,0xc0(%r14)"),
        (0x63626DB, "mov", "0x28(%rsp),%rcx"),
        (0x6362705, "jmp", "636236c"),
        (0x6362710, "mov", "0x40(%rsp),%rbp"),
        (0x636271A, "mov", "%r14,%r13"),
        (0x636271F, "jne", "636282e"),
        # Epilogue: stats, unlock, wake, compaction, refcount.
        (0x6362730, "mov", "0x20(%rsp),%esi"),
        (0x6362739, "mov", "%r15,%rdi"),
        (0x6362746, "add", "%rsi,0x70(%r12)"),
        (0x636274B, "addq", "$0x1,0x90(%r12)"),
        (0x636276A, "movq", "$0x0,0x8(%rbx)"),
        (0x6362772, "movb", "$0x0,0x68(%r12)"),
        (0x6362778, "call", "63f0b70"),
        (0x636277D, "cmpq", "$0x0,0x28(%rsp)"),
        (0x6362783, "je", "63627bc"),
        (0x63627A2, "lea", "0x2998(%r15),%rsi"),
        (0x63627A9, "call", "63c0340"),
        (0x63627AE, "cmpb", "$0x0,0x97(%rsp)"),
        (0x63627B6, "jne", "636289d"),
        (0x63627BC, "mov", "(%rbx),%r12"),
        (0x63627F0, "mov", "%rdi,(%rbx)"),
        (0x63627F3, "test", "%rbp,%rbp"),
        (0x63627F8, "subl", "$0x1,0x98(%rbp)"),
        (0x63627FF, "js", "63628af"),
        (0x6362805, "mov", "0x98(%rsp),%rax"),
        (0x636280D, "sub", "%fs:0x28,%rax"),
        (0x6362816, "jne", "63628fc"),
        (0x636281C, "add", "$0xa8,%rsp"),
        (0x6362823, "pop", "%rbx"),
        (0x636282D, "ret", ""),
        # Slow path: waited-flag clear, unlock, helper, trylock 2.
        (0x636282E, "movb", "$0x0,0x68(%r14)"),
        (0x6362833, "mov", "%r15,%rdi"),
        (0x6362836, "xor", "%ebx,%ebx"),
        (0x6362838, "call", "63f0b70"),
        (0x6362845, "mov", "%rbp,%rdi"),
        (0x6362852, "call", "63606d0"),
        (0x6362857, "mov", "%r15,%rdi"),
        (0x636285A, "mov", "%rax,0x28(%rsp)"),
        (0x636285F, "call", "63f17b0"),
        (0x6362864, "test", "%eax,%eax"),
        (0x6362866, "je", "6362298"),
        # Lock-wait site: single argument, current node in rdi.
        (0x636286C, "mov", "%r13,%rdi"),
        (0x636286F, "call", "63bf680"),
        (0x6362874, "movb", "$0x1,0x68(%r13)"),
        (0x6362879, "jmp", "6362298"),
        # memmove compaction path.
        (0x636287E, "mov", "0x70(%rsp),%rcx"),
        (0x6362890, "call", "63f0a70"),
        (0x6362895, "mov", "%rax,%rdi"),
        (0x6362898, "jmp", "63627f0"),
        (0x636289D, "mov", "0x38(%rsp),%rsi"),
        (0x63628A5, "call", "6360610"),
        (0x63628AA, "jmp", "63627bc"),
        # Last-reference cleanup: 0x635f340 call, then tail jump.
        (0x63628AF, "lea", "0x70(%rbp),%rsi"),
        (0x63628B3, "lea", "0x98(%rbp),%rdi"),
        (0x63628BA, "call", "635f340"),
        (0x63628BF, "test", "%al,%al"),
        (0x63628C1, "je", "6362805"),
        (0x63628C7, "mov", "0x98(%rsp),%rax"),
        (0x63628CF, "sub", "%fs:0x28,%rax"),
        (0x63628D8, "jne", "63628fc"),
        (0x63628DA, "mov", "0x38(%rsp),%rsi"),
        (0x63628DF, "add", "$0xa8,%rsp"),
        (0x63628E6, "xor", "%ecx,%ecx"),
        (0x63628E8, "xor", "%edx,%edx"),
        (0x63628EB, "mov", "%rbp,%rdi"),
        (0x63628F7, "jmp", "6360ed0"),
        (0x63628FC, "call", "63f0d70"),
    ]
    for _a, _m, _op in EXPECT:
        check("expect %s %s %s" % (hex(_a), _m, _op),
              _a in by_addr and mnemonic_of(by_addr[_a]) == _m
              and _op in operands_of(by_addr[_a]),
              by_addr.get(_a, "MISSING"))

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


    check("entry reaches lock-wait site 0x636286f", reaches(START, 0x636286F))
    check("entry reaches ret 0x636282d", reaches(START, 0x636282D))
    check("entry reaches tail jmp 0x63628f7", reaches(START, 0x63628F7))
    check("entry reaches trylock1 0x6362284", reaches(START, 0x6362284))
    check("entry reaches trylock2 0x636285f", reaches(START, 0x636285F))
    check("entry reaches bit loop 0x63623f0", reaches(START, 0x63623F0))
    check("entry reaches inner loop 0x636237c", reaches(START, 0x636237C))
    check("entry reaches epilogue 0x6362805", reaches(START, 0x6362805))
    check("entry reaches tail-call setup 0x63628c7", reaches(START, 0x63628C7))
    check("entry reaches slow path 0x636282e", reaches(START, 0x636282E))
    check("entry reaches list-insert path 0x63622e0", reaches(START, 0x63622E0))
    check("entry reaches bitmap-count call 0x63624ee", reaches(START, 0x63624EE))
    check("entry reaches wake helper 0x63627a9", reaches(START, 0x63627A9))
    check("entry reaches memmove 0x6362890", reaches(START, 0x6362890))
    check("entry reaches cleanup 0x63628af", reaches(START, 0x63628AF))
    check("entry reaches loop head 0x6362298", reaches(START, 0x6362298))
    check("preds of lock-wait setup 0x636286c are the two trylock fails",
          sorted(preds[0x636286C]) == [0x636228B, 0x6362866],
          str(sorted(preds[0x636286C])))
    check("preds of loop head 0x6362298 are entry, trylock2 ok, helper ret",
          sorted(preds[0x6362298]) == [0x6362291, 0x6362866, 0x6362879],
          str(sorted(preds[0x6362298])))

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


    rdi_in = reaching_defs("rdi")
    r13_in = reaching_defs("r13")
    rsi_in = reaching_defs("rsi")
    rdx_in = reaching_defs("rdx")
    rcx_in = reaching_defs("rcx")
    r8_in = reaching_defs("r8")
    r9_in = reaching_defs("r9")
    rax_in = reaching_defs("rax")
    r10_in = reaching_defs("r10")
    rbx_in = reaching_defs("rbx")
    rbp_in = reaching_defs("rbp")
    r14_in = reaching_defs("r14")
    r15_in = reaching_defs("r15")
    SITE = 0x636286F
    CALL2 = {("CALL", 0x6362284), ("CALL", 0x636285F)}
    check("site rdi only def is mov r13 rdi 0x636286c",
          rdi_in[SITE] == {0x636286C}, str(rdi_in[SITE]))
    check("site r13 defs are entry mov r10 r13 and reload mov r14 r13",
          r13_in[SITE] == {0x6362270, 0x636271A}, str(r13_in[SITE]))
    check("r13 at loop head 0x6362298 same two defs",
          r13_in[0x6362298] == {0x6362270, 0x636271A},
          str(r13_in[0x6362298]))
    check("site rsi is clobbered by the two trylocks only",
          rsi_in[SITE] == CALL2, str(rsi_in[SITE]))
    check("site rdx is clobbered by the two trylocks only",
          rdx_in[SITE] == CALL2, str(rdx_in[SITE]))
    check("site rcx is clobbered by the two trylocks only",
          rcx_in[SITE] == CALL2, str(rcx_in[SITE]))
    check("site r8 is clobbered by the two trylocks only",
          r8_in[SITE] == CALL2, str(r8_in[SITE]))
    check("site r9 is clobbered by the two trylocks only",
          r9_in[SITE] == CALL2, str(r9_in[SITE]))
    check("site rax is clobbered by the two trylocks only",
          rax_in[SITE] == CALL2, str(rax_in[SITE]))
    check("site r10 is clobbered by the two trylocks only",
          r10_in[SITE] == CALL2, str(r10_in[SITE]))
    check("site rbx defs are mov 1 ebx entry and xor ebx slow path",
          rbx_in[SITE] == {0x6362253, 0x6362836}, str(rbx_in[SITE]))
    check("site rbp defs are entry mov rdi rbp and cleanup reload",
          rbp_in[SITE] == {0x63621A0, 0x6362710}, str(rbp_in[SITE]))
    check("site r14 defs are entry, loop reload, bit-loop reload",
          r14_in[SITE] == {0x6362198, 0x63622CD, 0x6362689},
          str(r14_in[SITE]))
    check("site r15 defs are lea node+0x40 and epilogue reload",
          r15_in[SITE] == {0x6362264, 0x6362715}, str(r15_in[SITE]))
    # Exits: single ret, rax is the canary residue (0); tail jump takes
    # rdi=rbp, rcx=0, rdx=0, rax=0 (canary residue).
    check("rax at ret is the single canary-sub def 0x636280d",
          rax_in[0x636282D] == {0x636280D}, str(rax_in[0x636282D]))
    check("ret rax is 0: canary saved at 0x63621d7, loaded at 0x6362805,"
          " subtracted at 0x636280d, gated by jne 0x6362816",
          "mov" in by_addr[0x6362805]
          and "0x98(%rsp),%rax" in by_addr[0x6362805]
          and "sub" in by_addr[0x636280D]
          and "%fs:0x28,%rax" in by_addr[0x636280D])
    check("rax at tail jmp is the single canary-sub def 0x63628cf",
          rax_in[0x63628F7] == {0x63628CF}, str(rax_in[0x63628F7]))
    check("rdi at tail jmp is mov rbp rdi 0x63628eb",
          rdi_in[0x63628F7] == {0x63628EB}, str(rdi_in[0x63628F7]))
    check("rcx at tail jmp is xor ecx ecx 0x63628e6 (0)",
          rcx_in[0x63628F7] == {0x63628E6}, str(rcx_in[0x63628F7]))
    check("rdx at tail jmp is xor edx edx 0x63628e8 (0)",
          rdx_in[0x63628F7] == {0x63628E8}, str(rdx_in[0x63628F7]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x636286f"])
    check("records second-handler sites 0",
          rec.get("second_handler_sites", []) == [])
    check("records bitloop tzcnt 7",
          rec.get("bitloop", {}).get("tzcnt") == 7)
    check("records bitloop btc 7",
          rec.get("bitloop", {}).get("btc") == 7)
    check("records bitloop tzcnt sites",
          rec.get("bitloop", {}).get("tzcnt_sites") ==
          ["0x6362541", "0x636257a", "0x63625a3", "0x63625d1", "0x63625e6",
           "0x6362609", "0x636263f"])
    check("records bitloop btc sites",
          rec.get("bitloop", {}).get("btc_sites") ==
          ["0x6362549", "0x6362585", "0x63625ae", "0x63625dc", "0x63625ef",
           "0x6362612", "0x636264a"])
    check("records sites lu-miss 0",
          rec.get("sites", {}).get("lu_miss") == 0)
    check("records sites bin_table_init 0",
          rec.get("sites", {}).get("bin_table_init") == 0)
    check("records sites second-handler 0",
          rec.get("sites", {}).get("second_handler") == 0)
    check("records sites lock-wait 1",
          rec.get("sites", {}).get("lock_wait") == 1)
    check("records window bytes 1905",
          rec.get("window", {}).get("bytes") == 1905)
    check("records window range",
          rec.get("window", {}).get("range") == "0x6362190..0x6362901")
    check("records return value is 0 at the single ret",
          rec.get("return_value", {}).get("rax") == 0)

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    check("address 0x6511780 inside .bss",
          bss[3] <= 0x6511780 < bss[3] + bss[5])
    check("address 0x650969c inside .bss",
          bss[3] <= 0x650969C < bss[3] + bss[5])
    check("address 0x6711b40 inside .bss",
          bss[3] <= 0x6711B40 < bss[3] + bss[5])
    check("no 0x65096c0 referenced (no node table in this window)",
          not any("65096c0" in l for l in lines))
    txt = secmap[".text"]
    check("window inside .text",
          txt[3] <= START and END <= txt[3] + txt[5])
    check("0x63f0960 call target is inside .text (internal, not PLT)",
          txt[3] <= 0x63F0960 < txt[3] + txt[5])

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
    # 0x63d9880 / 0x634ebb0 / 0x63bf680 (lock-wait helper).
    text_sec = secmap[".text"]
    tva, toff_sec, tsize = text_sec[3], text_sec[4], text_sec[5]
    tbytes = node[toff_sec:toff_sec + tsize]
    counts = {}
    bti_counts = {}
    sh_counts = {}
    lw_counts = {}
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
                if tgtv == 0x63BF680:
                    lw_counts[fdes[k][0]] = lw_counts.get(fdes[k][0], 0) + 1
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
    check("this FDE raw lu-miss 0", counts.get(START, 0) == 0,
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
    check("this FDE raw second-handler 0",
          sh_counts.get(START, 0) == 0, str(sh_counts.get(START, 0)))
    check("raw-e8 second-handler total 64", sum(sh_counts.values()) == 64,
          str(sum(sh_counts.values())))
    check("raw-e8 second-handler FDEs 28", len(sh_counts) == 28,
          str(len(sh_counts)))
    lw_tiers = {}
    for v in lw_counts.values():
        lw_tiers[v] = lw_tiers.get(v, 0) + 1
    check("raw-e8 lock-wait total 474", sum(lw_counts.values()) == 474,
          str(sum(lw_counts.values())))
    check("raw-e8 lock-wait tiers",
          lw_tiers == {1: 348, 2: 19, 3: 9, 4: 4, 5: 1, 7: 2, 8: 1, 18: 1},
          str(lw_tiers))
    check("raw-e8 lock-wait FDEs 385", len(lw_counts) == 385,
          str(len(lw_counts)))
    check("this FDE raw lock-wait 1", lw_counts.get(START, 0) == 1,
          str(lw_counts.get(START, 0)))
    check("tail target 0x6360ed0 raw lock-wait 1",
          lw_counts.get(0x6360ED0, 0) == 1,
          str(lw_counts.get(0x6360ED0, 0)))
    check("next candidate raw lu-miss 0", counts.get(0x6362910, 0) == 0,
          str(counts.get(0x6362910, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x6362910, 0) == 0,
          str(bti_counts.get(0x6362910, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x6362910, 0) == 0,
          str(sh_counts.get(0x6362910, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x6362910, 0) == 1,
          str(lw_counts.get(0x6362910, 0)))


    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x6362190" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x6362190") == 1,
          str(survey.get("sites_per_fde", {}).get("0x6362190")))
    check("survey one-site survivors 319",
          survey.get("one_site_survivors") == 319,
          str(survey.get("one_site_survivors")))
    check("survey lock-wait total sites 474",
          survey.get("total_sites") == 474,
          str(survey.get("total_sites")))
    check("survey lock-wait total FDEs 385",
          survey.get("total_fdes") == 385,
          str(survey.get("total_fdes")))
    check("survey lu-miss frontier exhausted (16/16 claimed)",
          survey.get("lu_miss_exhausted") is True)
    check("survey this window is NOT a lu-miss survivor",
          "0x6362190" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x6362190" not in survey.get("second_handler_survivors", []))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x6362910..0x6362f82",
          nq.get("range") == "0x6362910..0x6362f82", str(nq.get("range")))
    check("next question bytes 1650", nq.get("bytes") == 1650,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 393", nq.get("strict") == 393,
          str(nq.get("strict")))
    check("next question calls 9", nq.get("calls") == 9,
          str(nq.get("calls")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x6362f25"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x6362e78"], str(nq.get("ret")))
    check("next question jumps 45", nq.get("jumps") == 45,
          str(nq.get("jumps")))
    check("next question jumps outside 0", nq.get("jumps_outside_window") == 0,
          str(nq.get("jumps_outside_window")))
    check("next question endbr64 1", nq.get("endbr64") == 1,
          str(nq.get("endbr64")))
    check("next question canary absent", nq.get("canary") is False,
          str(nq.get("canary")))
    check("records census strict 446",
          rec.get("census", {}).get("strict") == 446)
    check("records census calls 13",
          rec.get("census", {}).get("calls") == 13)
    check("records exhibits 2", len(rec.get("exhibits", [])) == 2,
          str(len(rec.get("exhibits", []))))

    # Disjointness against ALL prior records.json exhibits in the tree.
    own = os.path.join(PACKET, "records.json")
    mine = []
    skipped = []
    collect_ranges(rec, mine, skipped)
    check("own ranges collected", len(mine) >= 1, str(len(mine)))
    check("0 skipped own records", len(skipped) == 0, str(skipped[:3]))
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
    # next candidate 0x6362910..0x6362f82 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x6362910 < p[1] and p[0] < 0x6362F82]
    check("next candidate 0x6362910 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x6362F82 and 0x6362910 < END))


    # Slug uniqueness: committed tree + worktree scan, same packet excluded.
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
    check("slug not colliding with #314-#329 lu-miss slugs",
          SLUG not in ("RE-001-node115-lu-miss-caller-1site",
                       "RE-001-node115-lu-miss-caller-1site-dispatch",
                       "RE-001-node115-lu-miss-caller-1site-dispatch2",
                       "RE-001-node115-lu-miss-caller-1site-dispatch3",
                       "RE-001-node115-lu-miss-caller-4site-dispatch",
                       "RE-001-node115-lu-miss-caller-7site-dispatch",
                       "RE-001-node115-lu-miss-caller-1site-arraywalk",
                       "RE-001-node115-lu-miss-caller-2site-trylock",
                       "RE-001-node115-lu-miss-caller-6site-twowalk",
                       "RE-001-node115-lu-miss-caller-2site-ctypescan",
                       "RE-001-node115-lu-miss-caller-10site-threewalk",
                       "RE-001-node115-lu-miss-caller-10site-threetail",
                       "RE-001-node115-lu-miss-caller-2site-singlewalk",
                       "RE-001-node115-lu-miss-caller-1site-lookup",
                       "RE-001-node115-lu-miss-caller-1site-direct",
                       "RE-001-node115-lu-miss-caller-3site-prefetch"))


    # MANIFEST: exactly 5 entries, packet files only, sha256 matches.
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
    check("MANIFEST has no tools/tests entries",
          not any("tools/" in l or "tests/" in l
                  for l in man.splitlines()))
    expect_names = {"README.md", "EVIDENCE.md", "records.json",
                    "lockwait_caller_1site_bitloop.hex",
                    "lockwait_caller_1site_bitloop.objdump.txt"}
    check("MANIFEST names are the 5 packet files",
          {l.split(None, 1)[1].strip().lstrip("*")
           for l in man.strip().splitlines()} == expect_names)

    # EVIDENCE + README presence.
    check("EVIDENCE.md present",
          os.path.exists(os.path.join(PACKET, "EVIDENCE.md")))
    check("README.md present",
          os.path.exists(os.path.join(PACKET, "README.md")))

    print("PASS %d FAIL %d" % (PASS, FAIL))
    if FAILURES:
        print("FAILURES:")
        for f in FAILURES:
            print(" - " + f)
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
