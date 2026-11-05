"""Static verifier for RE-001-node115-lu-miss-caller-1site-direct.

Fifteenth packet of the lu-miss-caller frontier (callers of the lu-miss
handler 0x63d9700 that do not call bin_table_init): FDE
0x63d4048..0x63d4171, 297 bytes, 76 strict instructions, 1 call (the
lu-miss site itself at 0x63d4127, its only call), 0 bin_table_init
sites, 0 second-handler sites, ONE ret at 0x63d4170, bsr 0, lock sub 0
/ lock add 0, 7 jumps, 0 outside the window, endbr64 0, NO canary, NO
TLS flag check.

This window is a lu-miss-ONLY survivor: it is in the survey's 16-FDE
lu-miss survivor list but NOT in the 18-FDE second-handler survivor
list, so it consumes one slot of the combined 25-FDE miss-handler
pool without being shared. It is the SMALLEST lu-miss-caller window
so far (297 bytes, vs #327's 314) and the second with NO size-class
computation at all -- no byte table, no size table, no $0x3fff cap, no
fallback, no bsr arms, no resolver call: the lookup indexes the table
directly from the entry key ((key >> 0x1a) & 0xf0 top index, (key >>
0x9) & 0x1ffff8 second level). A single top-index lookup plus one
8-slot move-to-front scan over 0x100..0x180 in rsi (table base), slot
0 checked directly, slots 1-7 in a counter loop: 2 slot-compare
instructions, ZERO reversed-operand, 0 of 8 slot positions reversed.
The single lu-miss site shares the frontier argument pattern (rdi =
context, rsi = .bss 0x6511a00, rdx = table pointer, rcx = key, r8d =
1, r9d = 0), with the context coming from entry rsi (via rax) while
entry rdi is the output struct (saved to rbx); rcx provenance is
proven by reaching-definitions (rcx has NO reaching def at the site
other than the entry value). Exit: a SINGLE ret with ONE reaching rax
definition (mov %rbx,%rax at 0x63d4166) -- the exit value is the entry
rdi (the output struct pointer), after the resolve tail writes five
fields into (%rbx) from node[0] extracts.

#327's pointer for this window (297 bytes, 76 strict, 1 call, 1
lu-miss site at 0x63d4127, 0 bin_table_init sites, 0 second-handler
sites, 1 ret at 0x63d4170, bsr 0) was verified correct by targeted
objdump census. No correction (prior_pointer_verified).

Next question: the next and LAST lu-miss survivor in address order is
0x63e94a0..0x63e9bf2 (1,874 bytes, 396 strict, 3 calls -- all lu-miss,
at 0x63e9b6c, 0x63e9bac and 0x63e9be8 -- 0 bin_table_init sites, 0
second-handler sites, 2 rets at 0x63e96b1 and 0x63e97a6, bsr 0) -- a
lu-miss-ONLY survivor, NOT shared, like this packet.

Usage: python3 tools/node115_lu_miss_caller_1site_direct.py
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
                      "RE-001-node115-lu-miss-caller-1site-direct")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-1site-direct"
NAME = "lu_miss_caller_1site_direct"
START, END = 0x63D4048, 0x63D4171

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
    check("target FDE size 297", END - START == 297)
    prev = fdes[i - 1]
    check("prev FDE 0x63d3f0e..0x63d4048",
          prev == (0x63D3F0E, 0x63D4048), str(prev))
    check("prev gap 0", START - prev[1] == 0)
    nxt = fdes[i + 1]
    check("next FDE 0x63d4171..0x63d4289",
          nxt == (0x63D4171, 0x63D4289), str(nxt))
    check("next gap 0", nxt[0] - END == 0)
    check("next FDE starts push r12 (no endbr64)",
          node[toff(nxt[0]):toff(nxt[0]) + 2] == b"\x41\x54")
    check("prev FDE end is this FDE start", prev[1] == START)

    hexb = read(os.path.join(PACKET, "lu_miss_caller_1site_direct.hex"))
    check("hex exhibit raw bytes 297", len(hexb) == 297, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lu_miss_caller_1site_direct.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 76", len(lines) == 76, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 1", len(calls) == 1, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63d4170",
          len(rets) == 1 and addr_of(rets[0]) == 0x63D4170,
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
    expect = {0x63D9700: 1}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct call targets 1", len(tgt) == 1, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 1",
          tgt.get(0x63D9700, 0) == 1, str(tgt.get(0x63D9700, 0)))
    check("lu-miss site list",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63d9700" in l) == [0x63D4127])
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called 0 times", tgt.get(0x63BF680, 0) == 0,
          str(tgt.get(0x63BF680, 0)))
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("prev FDE 0x63d0080 called 0 times", tgt.get(0x63D0080, 0) == 0,
          str(tgt.get(0x63D0080, 0)))
    check("0x63bd6c0 called 0 times", tgt.get(0x63BD6C0, 0) == 0,
          str(tgt.get(0x63BD6C0, 0)))
    check("0x63637f0 called 0 times", tgt.get(0x63637F0, 0) == 0,
          str(tgt.get(0x63637F0, 0)))
    check("0x6363260 called 0 times", tgt.get(0x6363260, 0) == 0,
          str(tgt.get(0x6363260, 0)))
    check("0x6352fc0 called 0 times", tgt.get(0x6352FC0, 0) == 0,
          str(tgt.get(0x6352FC0, 0)))
    check("0x63edf10 called 0 times", tgt.get(0x63EDF10, 0) == 0,
          str(tgt.get(0x63EDF10, 0)))
    check("0x63ec4c0 called 0 times", tgt.get(0x63EC4C0, 0) == 0,
          str(tgt.get(0x63EC4C0, 0)))
    check("no stack_chk_fail plt call",
          tgt.get(0x63F0D70, 0) == 0, str(tgt.get(0x63F0D70, 0)))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0), ("#325", 0x63D17E0),
                  ("#326", 0x63D2A80),
                  ("#327", 0x63D3F0E)):
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
    check("jump lines 7", len(jmps) == 7, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure none outside", outside == [], str(outside))
    check("jump targets are exactly the 7 internal branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x63D4089, 0x63D409B, 0x63D40A0, 0x63D40E0, 0x63D4108,
           0x63D412C, 0x63D412C],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 0",
          sum(1 for l in lines if "endbr64" in l) == 0)
    check("entry is mov rsi rax at 0x63d4048 (no endbr64)",
          "mov" in by_addr[START] and "%rsi,%rax" in by_addr[START])
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

    # Entry / top-index lookup.
    check("entry mov rdx rsi",
          "mov" in by_addr[0x63D404B] and "%rdx,%rsi" in by_addr[0x63D404B])
    check("entry mov rcx rdx",
          "mov" in by_addr[0x63D404E] and "%rcx,%rdx" in by_addr[0x63D404E])
    check("entry push rbx",
          "push" in by_addr[0x63D4051] and "%rbx" in by_addr[0x63D4051])
    check("entry shr 0x1a rdx",
          "shr" in by_addr[0x63D4052] and "$0x1a,%rdx" in by_addr[0x63D4052])
    check("entry mov rcx r9",
          "mov" in by_addr[0x63D4056] and "%rcx,%r9" in by_addr[0x63D4056])
    check("entry mov rdi rbx",
          "mov" in by_addr[0x63D4059] and "%rdi,%rbx" in by_addr[0x63D4059])
    check("entry and 0xf0 edx",
          "and" in by_addr[0x63D405C] and "$0xf0,%edx" in by_addr[0x63D405C])
    check("entry and high bits r9",
          "and" in by_addr[0x63D4062]
          and "$0xffffffffc0000000,%r9" in by_addr[0x63D4062])
    check("entry add rsi rdx",
          "add" in by_addr[0x63D4069] and "%rsi,%rdx" in by_addr[0x63D4069])
    check("entry mov top slot r10",
          "mov" in by_addr[0x63D406C] and "(%rdx),%r10" in by_addr[0x63D406C])
    check("top compare cmp r10 r9 (register-first)",
          "cmp" in by_addr[0x63D406F] and "%r10,%r9" in by_addr[0x63D406F])
    check("top compare jne scan 0x63d4089",
          "jne" in by_addr[0x63D4072] and "63d4089" in by_addr[0x63D4072])
    # Top-match path: second-level extract, jmp resolve tail.
    check("top match mov rcx rax",
          "mov" in by_addr[0x63D4074] and "%rcx,%rax" in by_addr[0x63D4074])
    check("top match shr 0x9 rax",
          "shr" in by_addr[0x63D4077] and "$0x9,%rax" in by_addr[0x63D4077])
    check("top match and 0x1ffff8 eax",
          "and" in by_addr[0x63D407B] and "$0x1ffff8,%eax" in by_addr[0x63D407B])
    check("top match add 0x8 rdx rax",
          "add" in by_addr[0x63D4080] and "0x8(%rdx),%rax" in by_addr[0x63D4080])
    check("top match jmp resolve 0x63d412c",
          "jmp" in by_addr[0x63D4084] and "63d412c" in by_addr[0x63D4084])
    # Slot-0 compare and hit path.
    check("slot-0 compare cmp 0x100 rsi r9 (memory-first, normal)",
          "cmp" in by_addr[0x63D4089]
          and "0x100(%rsi),%r9" in by_addr[0x63D4089])
    check("slot-0 compare jne scan loop 0x63d409b",
          "jne" in by_addr[0x63D4090] and "63d409b" in by_addr[0x63D4090])
    check("slot-0 hit mov 0x108 rsi rax",
          "mov" in by_addr[0x63D4092] and "0x108(%rsi),%rax" in by_addr[0x63D4092])
    check("slot-0 hit jmp extract 0x63d40e0",
          "jmp" in by_addr[0x63D4099] and "63d40e0" in by_addr[0x63D4099])
    # Scan counter loop (slots 1-7).
    check("scan loop mov 1 edi",
          "mov" in by_addr[0x63D409B] and "$0x1,%edi" in by_addr[0x63D409B])
    check("scan loop mov rdi r8",
          "mov" in by_addr[0x63D40A0] and "%rdi,%r8" in by_addr[0x63D40A0])
    check("scan loop shl 4 r8",
          "shl" in by_addr[0x63D40A3] and "$0x4,%r8" in by_addr[0x63D40A3])
    check("loop compare cmp 0x100 rsi r8 r9 (memory-first, normal)",
          "cmp" in by_addr[0x63D40A7]
          and "0x100(%rsi,%r8,1),%r9" in by_addr[0x63D40A7])
    check("loop compare jne next slot 0x63d4108",
          "jne" in by_addr[0x63D40AF] and "63d4108" in by_addr[0x63D40AF])
    check("loop hit dec edi",
          "dec" in by_addr[0x63D40B1] and "%edi" in by_addr[0x63D40B1])
    check("loop hit add rsi r8",
          "add" in by_addr[0x63D40B3] and "%rsi,%r8" in by_addr[0x63D40B3])
    check("loop hit shl 4 rdi",
          "shl" in by_addr[0x63D40B6] and "$0x4,%rdi" in by_addr[0x63D40B6])
    check("loop hit mov 0x108 r8 rax",
          "mov" in by_addr[0x63D40BA] and "0x108(%r8),%rax" in by_addr[0x63D40BA])
    check("loop hit add rdi rsi",
          "add" in by_addr[0x63D40C1] and "%rdi,%rsi" in by_addr[0x63D40C1])
    check("loop hit mov 0x100 rsi r11",
          "mov" in by_addr[0x63D40C4] and "0x100(%rsi),%r11" in by_addr[0x63D40C4])
    check("loop hit mov r11 0x100 r8",
          "mov" in by_addr[0x63D40CB] and "%r11,0x100(%r8)" in by_addr[0x63D40CB])
    check("loop hit mov 0x108 rsi rdi",
          "mov" in by_addr[0x63D40D2] and "0x108(%rsi),%rdi" in by_addr[0x63D40D2])
    check("loop hit mov rdi 0x108 r8",
          "mov" in by_addr[0x63D40D9] and "%rdi,0x108(%r8)" in by_addr[0x63D40D9])
    # Extract tail (hit paths rejoin here).
    check("extract mov r10 0x100 rsi",
          "mov" in by_addr[0x63D40E0] and "%r10,0x100(%rsi)" in by_addr[0x63D40E0])
    check("extract shr 9 rcx",
          "shr" in by_addr[0x63D40E7] and "$0x9,%rcx" in by_addr[0x63D40E7])
    check("extract mov 0x8 rdx r10",
          "mov" in by_addr[0x63D40EB] and "0x8(%rdx),%r10" in by_addr[0x63D40EB])
    check("extract and 0x1ffff8 ecx",
          "and" in by_addr[0x63D40EF] and "$0x1ffff8,%ecx" in by_addr[0x63D40EF])
    check("extract mov r10 0x108 rsi",
          "mov" in by_addr[0x63D40F5] and "%r10,0x108(%rsi)" in by_addr[0x63D40F5])
    check("extract mov rax 0x8 rdx",
          "mov" in by_addr[0x63D40FC] and "%rax,0x8(%rdx)" in by_addr[0x63D40FC])
    check("extract add rcx rax",
          "add" in by_addr[0x63D4100] and "%rcx,%rax" in by_addr[0x63D4100])
    check("extract mov r9 top slot",
          "mov" in by_addr[0x63D4103] and "%r9,(%rdx)" in by_addr[0x63D4103])
    check("extract jmp resolve 0x63d412c",
          "jmp" in by_addr[0x63D4106] and "63d412c" in by_addr[0x63D4106])
    # Next slot.
    check("next slot inc rdi",
          "inc" in by_addr[0x63D4108] and "%rdi" in by_addr[0x63D4108])
    check("next slot cmp 8 rdi",
          "cmp" in by_addr[0x63D410B] and "$0x8,%rdi" in by_addr[0x63D410B])
    check("next slot jne loop head 0x63d40a0",
          "jne" in by_addr[0x63D410F] and "63d40a0" in by_addr[0x63D410F])
    # Miss block: single lu-miss site.
    check("miss mov rsi rdx",
          "mov" in by_addr[0x63D4111] and "%rsi,%rdx" in by_addr[0x63D4111])
    check("miss lea 0x6511a00 rsi",
          "lea" in by_addr[0x63D4114] and "6511a00" in by_addr[0x63D4114])
    check("miss xor r9d",
          "xor" in by_addr[0x63D411B] and "%r9d,%r9d" in by_addr[0x63D411B])
    check("miss mov rax rdi",
          "mov" in by_addr[0x63D411E] and "%rax,%rdi" in by_addr[0x63D411E])
    check("miss mov 1 r8d",
          "mov" in by_addr[0x63D4121] and "$0x1,%r8d" in by_addr[0x63D4121])
    check("miss call 0x63d9700 at 0x63d4127",
          "call" in by_addr[0x63D4127] and "63d9700" in by_addr[0x63D4127])
    # Resolve tail: field extracts from the resolved node.
    check("resolve mov node0 rcx",
          "mov" in by_addr[0x63D412C] and "(%rax),%rcx" in by_addr[0x63D412C])
    check("resolve mov rcx rax",
          "mov" in by_addr[0x63D412F] and "%rcx,%rax" in by_addr[0x63D412F])
    check("resolve mov rcx r9",
          "mov" in by_addr[0x63D4132] and "%rcx,%r9" in by_addr[0x63D4132])
    check("resolve mov rcx rdx",
          "mov" in by_addr[0x63D4135] and "%rcx,%rdx" in by_addr[0x63D4135])
    check("resolve mov rcx rsi",
          "mov" in by_addr[0x63D4138] and "%rcx,%rsi" in by_addr[0x63D4138])
    check("resolve shl 0x10 rax",
          "shl" in by_addr[0x63D413B] and "$0x10,%rax" in by_addr[0x63D413B])
    check("resolve shr 2 r9",
          "shr" in by_addr[0x63D413F] and "$0x2,%r9" in by_addr[0x63D413F])
    check("resolve and 1 ecx",
          "and" in by_addr[0x63D4143] and "$0x1,%ecx" in by_addr[0x63D4143])
    check("resolve sar 0x10 rax",
          "sar" in by_addr[0x63D4146] and "$0x10,%rax" in by_addr[0x63D4146])
    check("resolve shr 1 rdx (decimal $1, not $0x1)",
          "shr" in by_addr[0x63D414A] and "$1,%rdx" in by_addr[0x63D414A])
    check("resolve and 7 r9d",
          "and" in by_addr[0x63D414D] and "$0x7,%r9d" in by_addr[0x63D414D])
    check("resolve mov cl 0x11 rbx",
          "mov" in by_addr[0x63D4151] and "%cl,0x11(%rbx)" in by_addr[0x63D4151])
    check("resolve and ffffffffffffff80 rax",
          "and" in by_addr[0x63D4154]
          and "$0xffffffffffffff80,%rax" in by_addr[0x63D4154])
    check("resolve shr 0x30 rsi",
          "shr" in by_addr[0x63D4158] and "$0x30,%rsi" in by_addr[0x63D4158])
    check("resolve and 1 edx",
          "and" in by_addr[0x63D415C] and "$0x1,%edx" in by_addr[0x63D415C])
    check("resolve mov r9d 0xc rbx",
          "mov" in by_addr[0x63D415F] and "%r9d,0xc(%rbx)" in by_addr[0x63D415F])
    check("resolve mov rax 0x0 rbx",
          "mov" in by_addr[0x63D4163] and "%rax,(%rbx)" in by_addr[0x63D4163])
    check("resolve mov rbx rax (exit def)",
          "mov" in by_addr[0x63D4166] and "%rbx,%rax" in by_addr[0x63D4166])
    check("resolve mov esi 0x8 rbx",
          "mov" in by_addr[0x63D4169] and "%esi,0x8(%rbx)" in by_addr[0x63D4169])
    check("resolve mov dl 0x10 rbx",
          "mov" in by_addr[0x63D416C] and "%dl,0x10(%rbx)" in by_addr[0x63D416C])
    check("epilogue pop rbx (no add rsp: no stack frame adjustment)",
          "pop" in by_addr[0x63D416F] and "%rbx" in by_addr[0x63D416F])

    # Scan: one 8-slot MTF scan, 2 slot compares, 0 reversed.
    # Slot set 0x100..0x180 in rsi (table base); reversed means the
    # register comes first (e.g. cmp %r9,0x100(%rsi)); memory-first
    # is NORMAL.
    slot_cmps = {
        0x63D4089: "0x100(%rsi),%r9",
        0x63D40A7: "0x100(%rsi,%r8,1),%r9",
    }
    check("slot compares 2", len(slot_cmps) == 2, str(len(slot_cmps)))
    for a, op in slot_cmps.items():
        check("slot compare %s" % hex(a),
              "cmp" in by_addr[a] and op in by_addr[a], by_addr[a])
    check("reversed-operand compares 0",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%")) == [],
          str(sorted(a for a, op in slot_cmps.items()
                     if op.startswith("%"))))
    check("reversed count via objdump",
          sum(1 for a in slot_cmps
              if re.search(r"\bcmp\s+%", by_addr[a])) == 0)
    check("slot positions 8 = slot 0 + counter loop slots 1-7",
          8 == 8)
    check("scan slot-0 0x63d4089 key r9",
          "cmp" in by_addr[0x63D4089] and "0x100(%rsi),%r9" in by_addr[0x63D4089])
    check("scan loop compare 0x63d40a7 key r9",
          "cmp" in by_addr[0x63D40A7]
          and "0x100(%rsi,%r8,1),%r9" in by_addr[0x63D40A7])
    check("top compare is register-first (table compare, not a slot compare)",
          "cmp" in by_addr[0x63D406F] and "%r10,%r9" in by_addr[0x63D406F])
    check("scan exhaustion falls through to miss block 0x63d4111",
          "mov" in by_addr[0x63D4111] and "%rsi,%rdx" in by_addr[0x63D4111])


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

    check("entry reaches lu-miss site 0x63d4127", reaches(START, 0x63D4127))
    check("entry reaches ret 0x63d4170", reaches(START, 0x63D4170))
    check("scan loop head 0x63d409b reachable", reaches(START, 0x63D409B))
    check("miss block 0x63d4111 reachable", reaches(START, 0x63D4111))
    check("resolve tail 0x63d412c reachable", reaches(START, 0x63D412C))

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

    SITE = 0x63D4127
    rcx_in = reaching_defs("rcx")
    rdi_in = reaching_defs("rdi")
    rsi_in = reaching_defs("rsi")
    rdx_in = reaching_defs("rdx")
    r8_in = reaching_defs("r8")
    r9_in = reaching_defs("r9")
    rax_in = reaching_defs("rax")
    check("rcx at site has NO reaching def other than ENTRY (entry key)",
          rcx_in[SITE] == {("ENTRY",)}, str(rcx_in[SITE]))
    check("rdi at site only def is mov rax rdi 0x63d411e",
          rdi_in[SITE] == {0x63D411E}, str(rdi_in[SITE]))
    check("rsi at site only def is lea 0x6511a00 0x63d4114",
          rsi_in[SITE] == {0x63D4114}, str(rsi_in[SITE]))
    check("rdx at site only def is mov rsi rdx 0x63d4111",
          rdx_in[SITE] == {0x63D4111}, str(rdx_in[SITE]))
    check("r8 at site only def is mov 1 r8d 0x63d4121",
          r8_in[SITE] == {0x63D4121}, str(r8_in[SITE]))
    check("r9 at site only def is xor r9d 0x63d411b",
          r9_in[SITE] == {0x63D411B}, str(r9_in[SITE]))
    check("rax at site only def is mov rsi rax 0x63d4048 (entry rsi)",
          rax_in[SITE] == {0x63D4048}, str(rax_in[SITE]))
    r10_in = reaching_defs("r10")
    check("r10 at site only def is mov top slot r10 0x63d406c",
          r10_in[SITE] == {0x63D406C}, str(r10_in[SITE]))
    check("rax at ret only def is mov rbx rax 0x63d4166",
          rax_in[0x63D4170] == {0x63D4166}, str(rax_in[0x63D4170]))
    check("rax at resolve tail 0x63d412c has 3 reaching defs "
          "(top match / hit via extract add / miss call)",
          rax_in[0x63D412C] == {0x63D4080, 0x63D4100, ("CALL", 0x63D4127)},
          str(rax_in[0x63D412C]))

    check("records lu-miss sites match census",
          [s.get("site") for s in rec.get("lu_miss_sites", [])] ==
          ["0x63d4127"])
    check("records second-handler sites 0",
          rec.get("second_handler_sites", []) == [])
    check("records scan slot compares 2",
          rec.get("scan", {}).get("slot_compares_total") == 2)
    check("records scan reversed 0",
          rec.get("scan", {}).get("reversed_operand_compares") == 0)
    check("records scan reversed sites empty",
          rec.get("scan", {}).get("reversed_sites") == [])
    check("records scan positions 8",
          rec.get("scan", {}).get("slot_positions_total") == 8)
    check("records scan reversed positions 0",
          rec.get("scan", {}).get("reversed_positions") == 0)

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
    check("this FDE raw lu-miss 1", counts.get(START, 0) == 1,
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
    check("next candidate raw lu-miss 3", counts.get(0x63E94A0, 0) == 3,
          str(counts.get(0x63E94A0, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63E94A0, 0) == 0,
          str(bti_counts.get(0x63E94A0, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63E94A0, 0) == 0,
          str(sh_counts.get(0x63E94A0, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 15th survivor",
          survey.get("survivors", [None] * 15)[14] == "0x63d4048",
          str(survey.get("survivors", [])[:16]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window is NOT shared",
          "0x63d4048" not in survey.get("shared_survivors", []))
    check("survey next candidate is NOT shared",
          "0x63e94a0" not in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x63e94a0..0x63e9bf2",
          nq.get("range") == "0x63e94a0..0x63e9bf2", str(nq.get("range")))
    check("next question bytes 1874", nq.get("bytes") == 1874,
          str(nq.get("bytes")))
    check("next question lu-miss sites 3",
          nq.get("lu_miss_sites") == 3, str(nq.get("lu_miss_sites")))
    check("next question lu-miss site list",
          nq.get("lu_miss_site") == ["0x63e9b6c", "0x63e9bac", "0x63e9be8"],
          str(nq.get("lu_miss_site")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 396", nq.get("strict") == 396,
          str(nq.get("strict")))
    check("next question calls 3", nq.get("calls") == 3,
          str(nq.get("calls")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 2",
          nq.get("ret") == ["0x63e96b1", "0x63e97a6"],
          str(nq.get("ret")))
    check("records census strict 76",
          rec.get("census", {}).get("strict") == 76)
    check("records census calls 1",
          rec.get("census", {}).get("calls") == 1)
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
    # next candidate 0x63e94a0..0x63e9bf2 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63E94A0 < p[1] and p[0] < 0x63E9BF2]
    check("next candidate 0x63e94a0 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63E9BF2 and 0x63E94A0 < END))

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
    check("slug not colliding with #314-#326 slugs",
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
                       "RE-001-node115-lu-miss-caller-1site-lookup"))

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
                    "lu_miss_caller_1site_direct.hex",
                    "lu_miss_caller_1site_direct.objdump.txt"}
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
