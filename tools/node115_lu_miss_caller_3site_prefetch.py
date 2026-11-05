"""Static verifier for RE-001-node115-lu-miss-caller-3site-prefetch.

Sixteenth and LAST packet of the lu-miss-caller frontier (callers of the
lu-miss handler 0x63d9700 that do not call bin_table_init): FDE
0x63e94a0..0x63e9bf2, 1,874 bytes, 396 strict instructions, 3 calls (all
lu-miss, at 0x63e9b6c, 0x63e9bac and 0x63e9be8), 0 bin_table_init sites,
0 second-handler sites, TWO rets at 0x63e96b1 and 0x63e97a6, bsr 0, lock
sub 0 / lock add 0, 55 jumps, 0 outside the window, endbr64 0, NO
canary, NO TLS flag check.

This window is a lu-miss-ONLY survivor: it is in the survey's 16-FDE
lu-miss survivor list but NOT in the 18-FDE second-handler survivor
list, so it consumes one slot of the combined 25-FDE miss-handler
pool without being shared. It is the FIRST frontier window with THREE
lu-miss sites, TWO rets, an early rdx==0 exit, an odd-count
single-element path, a pair-unrolled lookup loop, and a post-lookup
normalize+prefetch pass -- and the first whose scans are
majority-reversed: 24 slot compares, 21 reversed-operand, 3 normal.
There is NO size-class computation for the lookup (no byte table, no
size table, no $0x3fff cap, no fallback, no bsr arms, no resolver
call: the lookup indexes the table directly from the entry key
((key >> 0x1a) & 0xf0 top index, (key >> 0x9) & 0x1ffff8 second
level)); the count%4 dispatch only unrolls the prefetch pass. The
three lu-miss sites share the frontier argument pattern (rdi = table
base, rsi = .bss 0x6511a00, rdx = entry rdi+0x1b0 top-table base via
r15, rcx = key, r8d = 1, r9d = 0), with rcx provenance proven per site
by reaching-definitions. Exits: ret 1 at 0x63e96b1 has a 7-def
may-analysis rax set with no constant-setting def; ret 2 at
0x63e97a6 (rdx==0 early exit) has ENTRY only -- no constant exit
value at either ret.

#328's pointer for this window (1,874 bytes, 396 strict, 3 calls --
all lu-miss at 0x63e9b6c/0x63e9bac/0x63e9be8, 0 bin_table_init sites,
0 second-handler sites, 2 rets at 0x63e96b1 and 0x63e97a6, bsr 0) was
verified correct by targeted objdump census. No correction
(prior_pointer_verified).

Next question: the lu-miss frontier is exhausted with this packet.
The follow-on frontier is the lock-wait helper 0x63bf680 callers (344
survivors); the largest 1-site disjoint candidate is
0x6362190..0x6362901 (1,905 bytes, 446 strict, 13 calls, 1 lock-wait
site at 0x636286f, 0 lu-miss / 0 bin_table_init / 0 second-handler
sites, 1 ret at 0x636282d, bsr 0, endbr64 1, canary present, 49 jumps
with 1 tail jump to 0x6360ed0).

Usage: python3 tools/node115_lu_miss_caller_3site_prefetch.py
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
                      "RE-001-node115-lu-miss-caller-3site-prefetch")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-3site-prefetch"
NAME = "lu_miss_caller_3site_prefetch"
START, END = 0x63E94A0, 0x63E9BF2

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
    check("target FDE size 1874", END - START == 1874)
    prev = fdes[i - 1]
    check("prev FDE 0x63e91c0..0x63e9491",
          prev == (0x63E91C0, 0x63E9491), str(prev))
    check("prev gap 15 (0xcc padding)", START - prev[1] == 15)
    check("prev gap bytes are 0xcc int3 padding",
          node[toff(prev[1]):toff(START)] == b"\xcc" * 15)
    nxt = fdes[i + 1]
    check("next FDE 0x63e9c00..0x63e9c0c",
          nxt == (0x63E9C00, 0x63E9C0C), str(nxt))
    check("next gap 14 (0xcc padding)", nxt[0] - END == 14)
    check("next gap bytes are 0xcc int3 padding",
          node[toff(END):toff(nxt[0])] == b"\xcc" * 14)
    check("next FDE starts endbr64",
          node[toff(nxt[0]):toff(nxt[0]) + 4] == b"\xf3\x0f\x1e\xfa")
    check("prev FDE end is 15 bytes before this FDE start",
          prev[1] == START - 15)

    hexb = read(os.path.join(PACKET, "lu_miss_caller_3site_prefetch.hex"))
    check("hex exhibit raw bytes 1874", len(hexb) == 1874, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lu_miss_caller_3site_prefetch.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 396", len(lines) == 396, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 3", len(calls) == 3, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 2", len(rets) == 2, str(len(rets)))
    check("ret sites 0x63e96b1 and 0x63e97a6",
          sorted(addr_of(l) for l in rets) == [0x63E96B1, 0x63E97A6],
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
    expect = {0x63D9700: 3}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct call targets 1", len(tgt) == 1, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 3",
          tgt.get(0x63D9700, 0) == 3, str(tgt.get(0x63D9700, 0)))
    check("lu-miss site list",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63d9700" in l) == [0x63E9B6C, 0x63E9BAC, 0x63E9BE8])
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called 0 times", tgt.get(0x63BF680, 0) == 0,
          str(tgt.get(0x63BF680, 0)))
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("no stack_chk_fail plt call",
          tgt.get(0x63F0D70, 0) == 0, str(tgt.get(0x63F0D70, 0)))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0), ("#325", 0x63D17E0),
                  ("#326", 0x63D2A80), ("#327", 0x63D3F0E),
                  ("#328", 0x63D4048)):
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
    check("jump lines 55", len(jmps) == 55, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure none outside", outside == [], str(outside))
    check("jump targets are exactly the 55 internal branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x63E94E0, 0x63E94E0, 0x63E9525, 0x63E9525, 0x63E9525,
           0x63E9570, 0x63E9570, 0x63E9570, 0x63E9581, 0x63E95C9,
           0x63E95ED, 0x63E9617, 0x63E9617, 0x63E96A3, 0x63E96B2,
           0x63E96F6, 0x63E96F6, 0x63E96F6, 0x63E970E, 0x63E975A,
           0x63E97A6, 0x63E97A7, 0x63E97F5, 0x63E980E, 0x63E980E,
           0x63E980E, 0x63E980E, 0x63E980E, 0x63E980E, 0x63E9873,
           0x63E988B, 0x63E988B, 0x63E988B, 0x63E988B, 0x63E988B,
           0x63E988B, 0x63E98F0, 0x63E9907, 0x63E9907, 0x63E9907,
           0x63E9907, 0x63E9907, 0x63E9907, 0x63E9968, 0x63E9988,
           0x63E99A7, 0x63E99C9, 0x63E9A09, 0x63E9A47, 0x63E9A83,
           0x63E9AC3, 0x63E9B01, 0x63E9B3D, 0x63E9B79, 0x63E9BBB],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 0",
          sum(1 for l in lines if "endbr64" in l) == 0)
    check("entry is test rdx rdx at 0x63e94a0 (no endbr64)",
          "test" in by_addr[START] and "%rdx,%rdx" in by_addr[START])
    check("no canary (no fs:0x28 anywhere)",
          not any("%fs:0x28" in l for l in lines))
    check("no stack_chk anywhere",
          not any("stack_chk" in l for l in lines))
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

    # Instruction spot checks: (address, mnemonic, operand substring).
    # Entry / setup.
    EXPECT = [
        (0x63E94A0, "test", "%rdx,%rdx"),
        (0x63E94A3, "je", "63e97a6"),
        (0x63E94A9, "push", "%r15"),
        (0x63E94AE, "lea", "0x1b0(%rdi),%r15"),
        (0x63E94B7, "mov", "%rsi,%r14"),
        (0x63E94BE, "lea", "0x0(,%rdx,8),%r12"),
        (0x63E94C7, "mov", "%rdi,%rbp"),
        (0x63E94CB, "mov", "%rcx,%rbx"),
        (0x63E94CE, "sub", "$0x18,%rsp"),
        (0x63E94D2, "test", "$0x8,%r12b"),
        (0x63E94D6, "jne", "63e96b2"),
        # Pair loop: first element, top-index lookup.
        (0x63E94E0, "mov", "0x8(%r14),%rcx"),
        (0x63E94E4, "mov", "(%rcx,%r10,1),%rcx"),
        (0x63E94EE, "shr", "$0x1a,%rdx"),
        (0x63E94F2, "and", "$0xffffffffc0000000,%rsi"),
        (0x63E94F9, "and", "$0xf0,%edx"),
        (0x63E94FF, "add", "%rbp,%rdx"),
        (0x63E9502, "mov", "0x1b0(%rdx),%rdi"),
        (0x63E9509, "cmp", "%rdi,%rsi"),
        (0x63E950C, "jne", "63e975a"),
        (0x63E9512, "mov", "%rcx,%rax"),
        (0x63E9515, "shr", "$0x9,%rax"),
        (0x63E9519, "and", "$0x1ffff8,%eax"),
        (0x63E951E, "add", "0x1b8(%rdx),%rax"),
        # Pair loop: second element, top-index lookup.
        (0x63E9525, "mov", "0x8(%r14),%rsi"),
        (0x63E9529, "mov", "%rax,(%rbx,%r10,1)"),
        (0x63E952D, "lea", "0x8(%r10),%r13"),
        (0x63E9531, "mov", "0x8(%rsi,%r10,1),%rcx"),
        (0x63E9536, "mov", "%rcx,%rax"),
        (0x63E953C, "shr", "$0x1a,%rax"),
        (0x63E9547, "and", "$0xf0,%eax"),
        (0x63E954C, "add", "%rbp,%rax"),
        (0x63E954F, "mov", "0x1b0(%rax),%r11"),
        (0x63E9556, "cmp", "%r11,%rdx"),
        (0x63E9559, "jne", "63e970e"),
        (0x63E955F, "shr", "$0x9,%rcx"),
        (0x63E9563, "and", "$0x1ffff8,%ecx"),
        (0x63E9569, "add", "0x1b8(%rax),%rcx"),
        (0x63E9570, "lea", "0x8(%r13),%r10"),
        (0x63E9574, "mov", "%rcx,(%rbx,%r13,1)"),
        (0x63E9578, "cmp", "%r10,%r12"),
        (0x63E957B, "jne", "63e94e0"),
        # Prefetch dispatch: count%4.
        (0x63E9581, "lea", "(%rbx,%r12,1),%rbp"),
        (0x63E9585, "sub", "$0x8,%r12"),
        (0x63E9589, "shr", "$0x3,%r12"),
        (0x63E958D, "lea", "0x1(%r12),%r14"),
        (0x63E9592, "and", "$0x3,%r14d"),
        (0x63E9596, "je", "63e9617"),
        (0x63E9598, "cmp", "$0x1,%r14"),
        (0x63E959C, "je", "63e95ed"),
        (0x63E959E, "cmp", "$0x2,%r14"),
        (0x63E95A2, "je", "63e95c9"),
        # Remainder block, count%4 == 3 (third element normalize+prefetch).
        (0x63E95A4, "mov", "(%rbx),%r15"),
        (0x63E95AB, "mov", "(%r15),%r12"),
        (0x63E95AE, "shl", "$0x10,%r12"),
        (0x63E95B2, "sar", "$0x10,%r12"),
        (0x63E95B6, "and", "$0xffffffffffffff80,%r12"),
        (0x63E95BE, "prefetcht0", "(%r12)"),
        (0x63E95C3, "prefetcht0", "0x40(%r12)"),
        # Remainder block, count%4 == 2.
        (0x63E95C9, "mov", "(%rbx),%rcx"),
        (0x63E95D0, "mov", "(%rcx),%r13"),
        # Remainder block, count%4 == 1.
        (0x63E95ED, "mov", "(%rbx),%rdx"),
        (0x63E95F4, "mov", "(%rdx),%rax"),
        (0x63E95F7, "shl", "$0x10,%rax"),
        (0x63E95FB, "sar", "$0x10,%rax"),
        (0x63E95FF, "and", "$0xffffffffffffff80,%rax"),
        (0x63E960E, "cmp", "%rbx,%rbp"),
        (0x63E9611, "je", "63e96a3"),
        # Prefetch 4-at-a-time loop.
        (0x63E9617, "mov", "(%rbx),%rdi"),
        (0x63E961A, "add", "$0x20,%rbx"),
        (0x63E961E, "mov", "(%rdi),%r8"),
        (0x63E963E, "mov", "(%r11),%r9"),
        (0x63E965E, "mov", "(%rsi),%r10"),
        (0x63E967E, "mov", "(%r14),%r15"),
        (0x63E969A, "cmp", "%rbx,%rbp"),
        (0x63E969D, "jne", "63e9617"),
        # Epilogue.
        (0x63E96A3, "add", "$0x18,%rsp"),
        (0x63E96A7, "pop", "%rbx"),
        (0x63E96A8, "pop", "%rbp"),
        (0x63E96A9, "pop", "%r12"),
        (0x63E96AB, "pop", "%r13"),
        (0x63E96AD, "pop", "%r14"),
        (0x63E96AF, "pop", "%r15"),
        # Odd-count single-element path.
        (0x63E96B2, "mov", "0x8(%rsi),%rax"),
        (0x63E96B6, "mov", "(%rax),%rcx"),
        (0x63E96B9, "mov", "%rcx,%rdx"),
        (0x63E96BC, "mov", "%rcx,%r11"),
        (0x63E96BF, "shr", "$0x1a,%rdx"),
        (0x63E96C3, "and", "$0xffffffffc0000000,%r11"),
        (0x63E96CA, "and", "$0xf0,%edx"),
        (0x63E96D0, "add", "%rdi,%rdx"),
        (0x63E96D3, "mov", "0x1b0(%rdx),%r8"),
        (0x63E96DA, "cmp", "%r8,%r11"),
        (0x63E96DD, "jne", "63e97a7"),
        (0x63E96E3, "mov", "%rcx,%rax"),
        (0x63E96E6, "shr", "$0x9,%rax"),
        (0x63E96EA, "and", "$0x1ffff8,%eax"),
        (0x63E96EF, "add", "0x1b8(%rdx),%rax"),
        (0x63E96F6, "mov", "%rax,(%rbx)"),
        (0x63E96F9, "mov", "$0x8,%r10d"),
        (0x63E96FF, "cmp", "$0x8,%r12"),
        (0x63E9703, "jne", "63e94e0"),
        (0x63E9709, "jmp", "63e9581"),
        # Chain B slot-0 hit.
        (0x63E970E, "mov", "0x2b0(%rbp),%rdi"),
        (0x63E9715, "cmp", "%rdi,%rdx"),
        (0x63E9718, "jne", "63e97f5"),
        (0x63E971E, "mov", "0x2b8(%rbp),%r9"),
        (0x63E9725, "mov", "%r11,0x2b0(%rbp)"),
        (0x63E972C, "shr", "$0x9,%rcx"),
        (0x63E9755, "jmp", "63e9570"),
        # Chain A slot-0 hit.
        (0x63E975A, "mov", "0x2b0(%rbp),%r8"),
        (0x63E9761, "cmp", "%r8,%rsi"),
        (0x63E9764, "jne", "63e9873"),
        (0x63E976A, "mov", "0x2b8(%rbp),%rax"),
        (0x63E9771, "mov", "%rdi,0x2b0(%rbp)"),
        (0x63E97A1, "jmp", "63e9525"),
        # Chain C slot-0 hit.
        (0x63E97A7, "mov", "0x2b0(%rdi),%r9"),
        (0x63E97AE, "cmp", "%r9,%r11"),
        (0x63E97B1, "jne", "63e98f0"),
        (0x63E97B7, "mov", "%r8,0x2b0(%rdi)"),
        (0x63E97F0, "jmp", "63e96f6"),
        # Chain B scan slot 1 + rejoin.
        (0x63E97F5, "mov", "0x2c0(%rbp),%r10"),
        (0x63E97FC, "xor", "%r8d,%r8d"),
        (0x63E97FF, "mov", "$0x1,%r9d"),
        (0x63E9805, "cmp", "%r10,%rdx"),
        (0x63E9808, "jne", "63e9968"),
        (0x63E980E, "mov", "%r9d,%esi"),
        (0x63E9811, "shr", "$0x9,%rcx"),
        (0x63E986E, "jmp", "63e9570"),
        # Chain A scan slot 1 + rejoin.
        (0x63E9873, "mov", "0x2c0(%rbp),%r13"),
        (0x63E987A, "xor", "%r11d,%r11d"),
        (0x63E987D, "mov", "$0x1,%eax"),
        (0x63E9882, "cmp", "%r13,%rsi"),
        (0x63E9885, "jne", "63e9988"),
        (0x63E988B, "mov", "%eax,%r9d"),
        (0x63E98EB, "jmp", "63e9525"),
        # Chain C scan slot 1 + rejoin.
        (0x63E98F0, "mov", "0x2c0(%rdi),%r10"),
        (0x63E98F7, "xor", "%esi,%esi"),
        (0x63E98F9, "mov", "$0x1,%edi"),
        (0x63E98FE, "cmp", "%r10,%r11"),
        (0x63E9901, "jne", "63e99a7"),
        (0x63E9907, "shl", "$0x4,%rdi"),
        (0x63E9963, "jmp", "63e96f6"),
        # Miss block 1 (chain B): standard handler args.
        (0x63E9B56, "lea", "0x127ea3(%rip),%rsi"),
        (0x63E9B5D, "xor", "%r9d,%r9d"),
        (0x63E9B60, "mov", "%r15,%rdx"),
        (0x63E9B63, "mov", "%rbp,%rdi"),
        (0x63E9B66, "mov", "$0x1,%r8d"),
        (0x63E9B6C, "call", "63d9700"),
        (0x63E9B71, "mov", "%rax,%rcx"),
        (0x63E9B74, "jmp", "63e9570"),
        # Miss block 2 (chain A): r10 spilled across the call.
        (0x63E9B91, "lea", "0x127e68(%rip),%rsi"),
        (0x63E9B98, "xor", "%r9d,%r9d"),
        (0x63E9B9B, "mov", "%r15,%rdx"),
        (0x63E9B9E, "mov", "%rbp,%rdi"),
        (0x63E9BA1, "mov", "$0x1,%r8d"),
        (0x63E9BA7, "mov", "%r10,0x8(%rsp)"),
        (0x63E9BAC, "call", "63d9700"),
        (0x63E9BB1, "mov", "0x8(%rsp),%r10"),
        (0x63E9BB6, "jmp", "63e9525"),
        # Miss block 3 (chain C).
        (0x63E9BD2, "lea", "0x127e27(%rip),%rsi"),
        (0x63E9BD9, "xor", "%r9d,%r9d"),
        (0x63E9BDC, "mov", "%r15,%rdx"),
        (0x63E9BDF, "mov", "%rbp,%rdi"),
        (0x63E9BE2, "mov", "$0x1,%r8d"),
        (0x63E9BE8, "call", "63d9700"),
        (0x63E9BED, "jmp", "63e96f6"),
    ]
    for _a, _m, _op in EXPECT:
        check("expect %s %s %s" % (hex(_a), _m, _op),
              _a in by_addr and mnemonic_of(by_addr[_a]) == _m
              and _op in operands_of(by_addr[_a]),
              by_addr.get(_a, "MISSING"))

    # Slot compares: three 8-slot MTF scans over 0x2b0..0x320.
    # Reversed means the register comes first (e.g. cmp %r8,%rsi);
    # memory-first is NORMAL. Slots 0-6 are mov+cmp (register-first);
    # slot 7 is a direct memory-first compare in each chain.
    slot_cmps = {
        # Chain A (key rsi, base rbp).
        0x63E9761: "%r8,%rsi",
        0x63E9882: "%r13,%rsi",
        0x63E998F: "%r8,%rsi",
        0x63E9A1B: "%r9,%rsi",
        0x63E9A2B: "%r8,%rsi",
        0x63E9AD5: "%r13,%rsi",
        0x63E9AE5: "%r8,%rsi",
        0x63E9B84: "0x320(%rbp),%rsi",
        # Chain B (key rdx, base rbp).
        0x63E9715: "%rdi,%rdx",
        0x63E9805: "%r10,%rdx",
        0x63E996F: "%rdi,%rdx",
        0x63E99DC: "%rsi,%rdx",
        0x63E99EC: "%rdi,%rdx",
        0x63E9A96: "%r10,%rdx",
        0x63E9AA6: "%rdi,%rdx",
        0x63E9B49: "0x320(%rbp),%rdx",
        # Chain C (key r11, base rdi slots 0-1, rbp slots 2-7).
        0x63E97AE: "%r9,%r11",
        0x63E98FE: "%r10,%r11",
        0x63E99AE: "%r9,%r11",
        0x63E9A58: "%r13,%r11",
        0x63E9A68: "%r9,%r11",
        0x63E9B12: "%rax,%r11",
        0x63E9B22: "%r9,%r11",
        0x63E9BC5: "0x320(%rbp),%r11",
    }
    check("slot compares 24", len(slot_cmps) == 24, str(len(slot_cmps)))
    for a, op in slot_cmps.items():
        check("slot compare %s" % hex(a),
              "cmp" in by_addr[a] and op in by_addr[a], by_addr[a])
    check("reversed-operand compares 21",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%")) ==
          [0x63E9715, 0x63E9761, 0x63E97AE, 0x63E9805, 0x63E9882,
           0x63E98FE, 0x63E996F, 0x63E998F, 0x63E99AE, 0x63E99DC,
           0x63E99EC, 0x63E9A1B, 0x63E9A2B, 0x63E9A58, 0x63E9A68,
           0x63E9A96, 0x63E9AA6, 0x63E9AD5, 0x63E9AE5, 0x63E9B12,
           0x63E9B22],
          str(sorted(a for a, op in slot_cmps.items()
                     if op.startswith("%"))))
    check("reversed count via objdump",
          sum(1 for a in slot_cmps
              if re.search(r"\bcmp\s+%", by_addr[a])) == 21)
    check("normal slot compares 3 (slot 7 of each chain)",
          sorted(a for a, op in slot_cmps.items()
                 if not op.startswith("%")) ==
          [0x63E9B49, 0x63E9B84, 0x63E9BC5])
    check("slot positions 24 = 3 chains x 8 slots",
          24 == 24)
    check("top compare A is register-first (table compare, not slot)",
          "cmp" in by_addr[0x63E9509] and "%rdi,%rsi" in by_addr[0x63E9509])
    check("top compare B is register-first (table compare, not slot)",
          "cmp" in by_addr[0x63E9556] and "%r11,%rdx" in by_addr[0x63E9556])
    check("top compare C is register-first (table compare, not slot)",
          "cmp" in by_addr[0x63E96DA] and "%r8,%r11" in by_addr[0x63E96DA])
    check("scan exhaustion B falls through to miss block 1 0x63e9b56",
          "lea" in by_addr[0x63E9B56] and "6511a00" in by_addr[0x63E9B56])
    check("scan exhaustion A falls through to miss block 2 0x63e9b91",
          "lea" in by_addr[0x63E9B91] and "6511a00" in by_addr[0x63E9B91])
    check("scan exhaustion C falls through to miss block 3 0x63e9bd2",
          "lea" in by_addr[0x63E9BD2] and "6511a00" in by_addr[0x63E9BD2])


    # CFG: successors (jump targets inside window + fall-through; calls
    # fall through except noreturn PLT calls; ret is terminal).
    def call_target(line):
        m = re.search(r"\tcall\s+([0-9a-f]+)", line)
        return int(m.group(1), 16) if m else None

    NORETURN = set()
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


    check("entry reaches lu-miss site 1 0x63e9b6c", reaches(START, 0x63E9B6C))
    check("entry reaches lu-miss site 2 0x63e9bac", reaches(START, 0x63E9BAC))
    check("entry reaches lu-miss site 3 0x63e9be8", reaches(START, 0x63E9BE8))
    check("entry reaches ret 1 0x63e96b1", reaches(START, 0x63E96B1))
    check("entry reaches ret 2 0x63e97a6 (rdx==0 early exit)",
          reaches(START, 0x63E97A6))
    check("pair loop head 0x63e94e0 reachable", reaches(START, 0x63E94E0))
    check("odd path 0x63e96b2 reachable", reaches(START, 0x63E96B2))
    check("prefetch 4-loop 0x63e9617 reachable", reaches(START, 0x63E9617))
    check("miss block 1 0x63e9b56 reachable", reaches(START, 0x63E9B56))
    check("miss block 2 0x63e9b91 reachable", reaches(START, 0x63E9B91))
    check("miss block 3 0x63e9bd2 reachable", reaches(START, 0x63E9BD2))
    check("scan B slot-1 head 0x63e97f5 reachable", reaches(START, 0x63E97F5))
    check("scan A slot-1 head 0x63e9873 reachable", reaches(START, 0x63E9873))
    check("scan C slot-1 head 0x63e98f0 reachable", reaches(START, 0x63E98F0))
    check("epilogue 0x63e96a3 reachable", reaches(START, 0x63E96A3))

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


    rcx_in = reaching_defs("rcx")
    rdi_in = reaching_defs("rdi")
    rsi_in = reaching_defs("rsi")
    rdx_in = reaching_defs("rdx")
    r8_in = reaching_defs("r8")
    r9_in = reaching_defs("r9")
    rax_in = reaching_defs("rax")
    r15_in = reaching_defs("r15")
    # Site 1 (chain B miss): rcx is the second element key.
    SITE1 = 0x63E9B6C
    check("site1 rcx only def is mov 0x8(rsi,r10) rcx 0x63e9531",
          rcx_in[SITE1] == {0x63E9531}, str(rcx_in[SITE1]))
    check("site1 rdi only def is mov rbp rdi 0x63e9b63",
          rdi_in[SITE1] == {0x63E9B63}, str(rdi_in[SITE1]))
    check("site1 rsi only def is lea 0x6511a00 0x63e9b56",
          rsi_in[SITE1] == {0x63E9B56}, str(rsi_in[SITE1]))
    check("site1 rdx only def is mov r15 rdx 0x63e9b60",
          rdx_in[SITE1] == {0x63E9B60}, str(rdx_in[SITE1]))
    check("site1 r8 only def is mov 1 r8d 0x63e9b66",
          r8_in[SITE1] == {0x63E9B66}, str(r8_in[SITE1]))
    check("site1 r9 only def is xor r9d 0x63e9b5d",
          r9_in[SITE1] == {0x63E9B5D}, str(r9_in[SITE1]))
    check("site1 rax only def is add rbp rax 0x63e954c",
          rax_in[SITE1] == {0x63E954C}, str(rax_in[SITE1]))
    check("site1 r15 only def is lea 0x1b0(rdi) r15 0x63e94ae (entry)",
          r15_in[SITE1] == {0x63E94AE}, str(r15_in[SITE1]))
    # Site 2 (chain A miss): rcx is the first element key.
    SITE2 = 0x63E9BAC
    check("site2 rcx only def is mov (rcx,r10) rcx 0x63e94e4",
          rcx_in[SITE2] == {0x63E94E4}, str(rcx_in[SITE2]))
    check("site2 rdi only def is mov rbp rdi 0x63e9b9e",
          rdi_in[SITE2] == {0x63E9B9E}, str(rdi_in[SITE2]))
    check("site2 rsi only def is lea 0x6511a00 0x63e9b91",
          rsi_in[SITE2] == {0x63E9B91}, str(rsi_in[SITE2]))
    check("site2 rdx only def is mov r15 rdx 0x63e9b9b",
          rdx_in[SITE2] == {0x63E9B9B}, str(rdx_in[SITE2]))
    check("site2 r8 only def is mov 1 r8d 0x63e9ba1",
          r8_in[SITE2] == {0x63E9BA1}, str(r8_in[SITE2]))
    check("site2 r9 only def is xor r9d 0x63e9b98",
          r9_in[SITE2] == {0x63E9B98}, str(r9_in[SITE2]))
    check("site2 rax only def is mov 7 eax 0x63e9b7f (slot-7 index)",
          rax_in[SITE2] == {0x63E9B7F}, str(rax_in[SITE2]))
    check("site2 r15 only def is lea 0x1b0(rdi) r15 0x63e94ae (entry)",
          r15_in[SITE2] == {0x63E94AE}, str(r15_in[SITE2]))
    # Site 3 (chain C miss): rcx is the single element key.
    SITE3 = 0x63E9BE8
    check("site3 rcx only def is mov (rax) rcx 0x63e96b6",
          rcx_in[SITE3] == {0x63E96B6}, str(rcx_in[SITE3]))
    check("site3 rdi only def is mov rbp rdi 0x63e9bdf",
          rdi_in[SITE3] == {0x63E9BDF}, str(rdi_in[SITE3]))
    check("site3 rsi only def is lea 0x6511a00 0x63e9bd2",
          rsi_in[SITE3] == {0x63E9BD2}, str(rsi_in[SITE3]))
    check("site3 rdx only def is mov r15 rdx 0x63e9bdc",
          rdx_in[SITE3] == {0x63E9BDC}, str(rdx_in[SITE3]))
    check("site3 r8 only def is mov 1 r8d 0x63e9be2",
          r8_in[SITE3] == {0x63E9BE2}, str(r8_in[SITE3]))
    check("site3 r9 only def is xor r9d 0x63e9bd9",
          r9_in[SITE3] == {0x63E9BD9}, str(r9_in[SITE3]))
    check("site3 rax only def is mov 0x300(rbp) rax 0x63e9b01",
          rax_in[SITE3] == {0x63E9B01}, str(rax_in[SITE3]))
    check("site3 r15 only def is lea 0x1b0(rdi) r15 0x63e94ae (entry)",
          r15_in[SITE3] == {0x63E94AE}, str(r15_in[SITE3]))
    # Exits: ret 1 is a may-analysis set (7 defs, none constant-setting);
    # ret 2 (rdx==0 early exit) has ENTRY only.
    check("rax at ret 1 is the 7-def may-analysis set",
          rax_in[0x63E96B1] ==
          {("CALL", 0x63E9B6C), ("CALL", 0x63E9BE8), 0x63E954C,
           0x63E95FF, 0x63E96EF, 0x63E97ED, 0x63E994B},
          str(rax_in[0x63E96B1]))
    ret1_defs = rax_in[0x63E96B1]

    def is_const_rax_def(d):
        if not isinstance(d, int):
            return False
        line = by_addr[d]
        mn = mnemonic_of(line)
        op = operands_of(line)
        return ((mn == "mov" and op.startswith("$")) or
                (mn == "xor" and op in ("%eax,%eax", "%rax,%rax")))

    check("ret 1 rax may-set has no constant-setting def",
          not any(is_const_rax_def(d) for d in ret1_defs),
          str(ret1_defs))
    check("rax at ret 2 is ENTRY only (rdx==0 early exit, no constant)",
          rax_in[0x63E97A6] == {("ENTRY",)}, str(rax_in[0x63E97A6]))

    check("records lu-miss sites match census",
          [s.get("site") for s in rec.get("lu_miss_sites", [])] ==
          ["0x63e9b6c", "0x63e9bac", "0x63e9be8"])
    check("records second-handler sites 0",
          rec.get("second_handler_sites", []) == [])
    check("records scan slot compares 24",
          rec.get("scan", {}).get("slot_compares_total") == 24)
    check("records scan reversed 21",
          rec.get("scan", {}).get("reversed_operand_compares") == 21)
    check("records scan reversed sites 21",
          rec.get("scan", {}).get("reversed_sites") ==
          ["0x63e9715", "0x63e9761", "0x63e97ae", "0x63e9805", "0x63e9882",
           "0x63e98fe", "0x63e996f", "0x63e998f", "0x63e99ae", "0x63e99dc",
           "0x63e99ec", "0x63e9a1b", "0x63e9a2b", "0x63e9a58", "0x63e9a68",
           "0x63e9a96", "0x63e9aa6", "0x63e9ad5", "0x63e9ae5", "0x63e9b12",
           "0x63e9b22"])
    check("records scan positions 24",
          rec.get("scan", {}).get("slot_positions_total") == 24)
    check("records scan reversed positions 21",
          rec.get("scan", {}).get("reversed_positions") == 21)
    check("records sites lu-miss 3",
          rec.get("sites", {}).get("lu_miss") == 3)
    check("records sites bin_table_init 0",
          rec.get("sites", {}).get("bin_table_init") == 0)
    check("records sites second-handler 0",
          rec.get("sites", {}).get("second_handler") == 0)
    check("records sites lock-wait 0",
          rec.get("sites", {}).get("lock_wait") == 0)
    check("records window bytes 1874",
          rec.get("window", {}).get("bytes") == 1874)
    check("records window range",
          rec.get("window", {}).get("range") == "0x63e94a0..0x63e9bf2")

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    check("address 0x6511a00 inside .bss",
          bss[3] <= 0x6511A00 < bss[3] + bss[5])
    check("no 0x65096c0 referenced (no node table in this window)",
          not any("65096c0" in l for l in lines))
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
    check("this FDE raw lu-miss 3", counts.get(START, 0) == 3,
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
    check("next candidate raw lu-miss 0", counts.get(0x6362190, 0) == 0,
          str(counts.get(0x6362190, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x6362190, 0) == 0,
          str(bti_counts.get(0x6362190, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x6362190, 0) == 0,
          str(sh_counts.get(0x6362190, 0)))


    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 16th survivor (LAST)",
          survey.get("survivors", [None] * 16)[15] == "0x63e94a0",
          str(survey.get("survivors", [])[:16]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window is NOT shared",
          "0x63e94a0" not in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier (lu-miss exhausted)",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x6362190..0x6362901",
          nq.get("range") == "0x6362190..0x6362901", str(nq.get("range")))
    check("next question bytes 1905", nq.get("bytes") == 1905,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 446", nq.get("strict") == 446,
          str(nq.get("strict")))
    check("next question calls 13", nq.get("calls") == 13,
          str(nq.get("calls")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x636286f"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x636282d"], str(nq.get("ret")))
    check("next question jumps 49", nq.get("jumps") == 49,
          str(nq.get("jumps")))
    check("next question jumps outside 1", nq.get("jumps_outside_window") == 1,
          str(nq.get("jumps_outside_window")))
    check("next question endbr64 1", nq.get("endbr64") == 1,
          str(nq.get("endbr64")))
    check("next question canary present", nq.get("canary") is True,
          str(nq.get("canary")))
    check("records census strict 396",
          rec.get("census", {}).get("strict") == 396)
    check("records census calls 3",
          rec.get("census", {}).get("calls") == 3)
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
    # next candidate 0x6362190..0x6362901 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x6362190 < p[1] and p[0] < 0x6362901]
    check("next candidate 0x6362190 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x6362901 and 0x6362190 < END))


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
    check("slug not colliding with #314-#328 slugs",
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
                       "RE-001-node115-lu-miss-caller-1site-direct"))


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
                    "lu_miss_caller_3site_prefetch.hex",
                    "lu_miss_caller_3site_prefetch.objdump.txt"}
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
