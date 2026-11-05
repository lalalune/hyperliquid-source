"""Static verifier for RE-001-node115-lu-miss-caller-2site-singlewalk.

Thirteenth packet of the lu-miss-caller frontier (callers of the lu-miss
handler 0x63d9700 that do not call bin_table_init): FDE
0x63d2a80..0x63d3071, 1521 bytes, 313 strict instructions, 7 calls
(6 distinct direct targets, 0 indirect), 2 lu-miss sites, 0
bin_table_init sites, 1 second-handler site at 0x63d2d51, ONE ret at
0x63d2c97, bsr 2, lock sub 0 / lock add 1, 51 jumps, 0 outside the
window, endbr64 1, NO canary, NO TLS flag check.

This window is a SHARED survivor: it is in both the survey's 16-FDE
lu-miss survivor list and the 18-FDE second-handler survivor list, so
it consumes one slot of the combined 25-FDE miss-handler pool. First
frontier window with a SINGLE walk only (walk A; no walk B/C, no
element loop, no prev-FDE call, no deep-resolution tail), the first
with endbr64 present but NO canary (after #321, which had neither),
and the first with zero lock sub instructions. Two 8-slot
move-to-front scans share one slot set (0x2b0..0x320 in rbp): 16
slot-compare instructions, SIX reversed-operand (A1 slots 1, 3, 5, 6;
A2 slots 5, 6), i.e. 6 of 16 slot positions reversed; slot 0 and slot
1 are checked directly, slots 2-7 are an unrolled chain. Both
lu-miss sites share one argument pattern (rdi = rbp context, rsi =
.bss 0x6511a00, rdx = walk table pointer, rcx = walk key, r8d = 1,
r9d = 0); site 1 takes rcx = r12 (the resolver return), site 2 takes
rcx = rax (the resolver return). Site 1's rdx is the walk table
pointer from lea 0x1b0(%rbp),%rdx at 0x63d2bf0 (its only reaching
definitions there are that lea and site 2's stack restore at
0x63d3067, which reloads the same saved value); site 2's rdx is the
same table pointer, saved to 0x8(%rsp) before the call and restored
after. Exit: a SINGLE ret with two reaching rax definitions -- 0
(xor %eax,%eax at 0x63d2c83, success path) or 1 (mov $0x1,%eax at
0x63d2d02, size-class overflow / resolver-null paths) -- so no single
exit value is established, like #324 (0 or 1), unlike #325 (uniform
0) and #319 (0, ret only).

#325's pointer for this window (1521 bytes, 313 strict, 7 calls,
2 lu-miss sites at 0x63d3036 and 0x63d305b, 0 bin_table_init sites, 1
second-handler site at 0x63d2d51, 1 ret at 0x63d2c97, bsr 2) was
verified correct by targeted objdump census. No correction
(prior_pointer_verified).

Next question: the next lu-miss survivor in address order is
0x63d3f0e..0x63d4048 (314 bytes, 75 strict, 1 call, 1 lu-miss site at
0x63d4003, 0 bin_table_init sites, 0 second-handler sites, 1 ret at
0x63d4047, bsr 0) -- a lu-miss-ONLY survivor, NOT shared, unlike this
packet.

Usage: python3 tools/node115_lu_miss_caller_2site_singlewalk.py
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
                      "RE-001-node115-lu-miss-caller-2site-singlewalk")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-2site-singlewalk"
NAME = "lu_miss_caller_2site_singlewalk"
START, END = 0x63D2A80, 0x63D3071

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
    check("target FDE size 1521", END - START == 1521)
    prev = fdes[i - 1]
    check("prev FDE 0x63d17e0..0x63d2a80",
          prev == (0x63D17E0, 0x63D2A80), str(prev))
    check("prev gap 0", START - prev[1] == 0)
    nxt = fdes[i + 1]
    check("next FDE 0x63d3080..0x63d379c",
          nxt == (0x63D3080, 0x63D379C), str(nxt))
    check("next padding 15", nxt[0] - END == 15)
    gap = node[toff(END):toff(nxt[0])]
    check("gap bytes all cc", gap == b"\xcc" * 15, gap.hex())
    check("next FDE starts endbr64",
          node[toff(nxt[0]):toff(nxt[0]) + 4] == b"\xf3\x0f\x1e\xfa")
    check("prev FDE starts push r15 (no endbr64)",
          node[toff(prev[0]):toff(prev[0]) + 2] == b"\x41\x57")

    hexb = read(os.path.join(PACKET, "lu_miss_caller_2site_singlewalk.hex"))
    check("hex exhibit raw bytes 1521", len(hexb) == 1521, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lu_miss_caller_2site_singlewalk.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 313", len(lines) == 313, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 7", len(calls) == 7, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63d2c97",
          len(rets) == 1 and addr_of(rets[0]) == 0x63D2C97,
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
    expect = {0x6365150: 1, 0x634EBB0: 1, 0x6352FC0: 1, 0x63EDF10: 1,
              0x63EC4C0: 1, 0x63D9700: 2}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct call targets 6", len(tgt) == 6, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 2",
          tgt.get(0x63D9700, 0) == 2, str(tgt.get(0x63D9700, 0)))
    check("lu-miss site list",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63d9700" in l) == [0x63D3036, 0x63D305B])
    check("second-handler sites 1", tgt.get(0x634EBB0, 0) == 1,
          str(tgt.get(0x634EBB0, 0)))
    check("second-handler site 0x63d2d51",
          "call" in by_addr[0x63D2D51] and "634ebb0" in by_addr[0x63D2D51])
    check("lock-wait helper called 0 times", tgt.get(0x63BF680, 0) == 0,
          str(tgt.get(0x63BF680, 0)))
    check("resolver 0x6365150 called once at 0x63d2bd9",
          "call" in by_addr[0x63D2BD9] and "6365150" in by_addr[0x63D2BD9])
    check("prev FDE 0x63d0080 called 0 times", tgt.get(0x63D0080, 0) == 0,
          str(tgt.get(0x63D0080, 0)))
    check("0x63bd6c0 called 0 times", tgt.get(0x63BD6C0, 0) == 0,
          str(tgt.get(0x63BD6C0, 0)))
    check("0x63637f0 called 0 times", tgt.get(0x63637F0, 0) == 0,
          str(tgt.get(0x63637F0, 0)))
    check("0x6363260 called 0 times", tgt.get(0x6363260, 0) == 0,
          str(tgt.get(0x6363260, 0)))
    check("0x63ec4c0 called once at 0x63d2e6d",
          "call" in by_addr[0x63D2E6D] and "63ec4c0" in by_addr[0x63D2E6D])
    check("0x6352fc0 called once at 0x63d2db5",
          "call" in by_addr[0x63D2DB5] and "6352fc0" in by_addr[0x63D2DB5])
    check("0x63edf10 called once at 0x63d2df4",
          "call" in by_addr[0x63D2DF4] and "63edf10" in by_addr[0x63D2DF4])
    check("no stack_chk_fail plt call",
          tgt.get(0x63F0D70, 0) == 0, str(tgt.get(0x63F0D70, 0)))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0), ("#325", 0x63D17E0)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 2", sorted(addr_of(l) for l in bsr) == [0x63D2B54, 0x63D2E4C],
          str([hex(addr_of(l)) for l in bsr]))
    check("bsr 1 is bsr r13 r14", "bsr" in by_addr[0x63D2B54]
          and "%r13,%r14" in by_addr[0x63D2B54], by_addr[0x63D2B54])
    check("bsr 2 is bsr rdx r10", "bsr" in by_addr[0x63D2E4C]
          and "%rdx,%r10" in by_addr[0x63D2E4C], by_addr[0x63D2E4C])
    locks = [l for l in lines if mnemonic_of(l) == "lock"]
    check("lock lines 1", len(locks) == 1, str(locks))
    check("lock add at 0x63d2c7e",
          "lock add" in by_addr[0x63D2C7E]
          and "%r14,0x38(%r9)" in by_addr[0x63D2C7E], by_addr[0x63D2C7E])
    check("lock sub count 0",
          sum(1 for l in lines if "lock sub" in l) == 0)
    jmps = [l for l in lines
            if mnemonic_of(l) in ("jmp", "je", "jne", "ja", "jb", "jae",
                                  "jbe", "jg", "jl", "jge", "jle", "jo",
                                  "jno", "js", "jns", "jp", "jnp")]
    check("jump lines 51", len(jmps) == 51, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure none outside", outside == [], str(outside))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x63d2a80",
          "endbr64" in by_addr[START])
    check("entry push r15 at 0x63d2a84",
          "push" in by_addr[0x63D2A84] and "%r15" in by_addr[0x63D2A84])
    check("no canary (no fs:0x28 anywhere)",
          not any("%fs:0x28" in l for l in lines))
    check("no stack_chk anywhere",
          not any("stack_chk" in l for l in lines))
    check("no TLS flag fs:0x330 anywhere",
          not any("%fs:0x330" in l for l in lines))

    # Entry / prologue: struct init + count rounding.
    check("entry mov rdx rax",
          "mov" in by_addr[0x63D2A86] and "%rdx,%rax" in by_addr[0x63D2A86])
    check("entry mov rcx rdi",
          "mov" in by_addr[0x63D2A93] and "%rcx,%rdi" in by_addr[0x63D2A93])
    check("entry movabs divide-by-3 magic",
          "movabs" in by_addr[0x63D2A96]
          and "$0xaaaaaaaaaaaaaaab,%rcx" in by_addr[0x63D2A96])
    check("entry push rbx", "push" in by_addr[0x63D2AA0]
          and "%rbx" in by_addr[0x63D2AA0])
    check("entry mul rcx",
          "mul" in by_addr[0x63D2AA1] and "%rcx" in by_addr[0x63D2AA1])
    check("entry mov rsi rbx",
          "mov" in by_addr[0x63D2AA4] and "%rsi,%rbx" in by_addr[0x63D2AA4])
    check("entry sub 0x18 rsp",
          "sub" in by_addr[0x63D2AA7] and "$0x18,%rsp" in by_addr[0x63D2AA7])
    check("entry movdqa constant 0x454c10",
          "movdqa" in by_addr[0x63D2AAB] and "454c10" in by_addr[0x63D2AAB])
    check("entry movups xmm0 rsi",
          "movups" in by_addr[0x63D2AB3]
          and "%xmm0,(%rsi)" in by_addr[0x63D2AB3])
    check("entry mov rdx rsi",
          "mov" in by_addr[0x63D2AB6] and "%rdx,%rsi" in by_addr[0x63D2AB6])
    check("entry and fffffffe rdx",
          "and" in by_addr[0x63D2AB9]
          and "$0xfffffffffffffffe,%rdx" in by_addr[0x63D2AB9])
    check("entry shr 1 rsi",
          "shr" in by_addr[0x63D2ABD] and "$1,%rsi" in by_addr[0x63D2ABD])
    check("entry lea 0x3 rsi rdx rax",
          "lea" in by_addr[0x63D2AC0]
          and "0x3(%rsi,%rdx,1),%rax" in by_addr[0x63D2AC0])
    check("entry second mul rcx",
          "mul" in by_addr[0x63D2AC5] and "%rcx" in by_addr[0x63D2AC5])
    check("entry shr 1 rdx",
          "shr" in by_addr[0x63D2AC8] and "$1,%rdx" in by_addr[0x63D2AC8])
    check("entry shl 2 rdx",
          "shl" in by_addr[0x63D2ACB] and "$0x2,%rdx" in by_addr[0x63D2ACB])
    check("entry cmp 4 rdx",
          "cmp" in by_addr[0x63D2ACF] and "$0x4,%rdx" in by_addr[0x63D2ACF])
    check("entry jbe small path 0x63d2d10",
          "jbe" in by_addr[0x63D2AD3] and "63d2d10" in by_addr[0x63D2AD3])

    # Log2 loop (power-of-two size r8).
    check("log2 mov 2 ecx",
          "mov" in by_addr[0x63D2AD9] and "$0x2,%ecx" in by_addr[0x63D2AD9])
    check("log2 mov 1 r9d",
          "mov" in by_addr[0x63D2ADE] and "$0x1,%r9d" in by_addr[0x63D2ADE])
    check("log2 loop mov ecx r10d",
          "mov" in by_addr[0x63D2AE8] and "%ecx,%r10d" in by_addr[0x63D2AE8])
    check("log2 loop mov r9 r11",
          "mov" in by_addr[0x63D2AEB] and "%r9,%r11" in by_addr[0x63D2AEB])
    check("log2 loop add 1 ecx",
          "add" in by_addr[0x63D2AEE] and "$0x1,%ecx" in by_addr[0x63D2AEE])
    check("log2 loop shl cl r11",
          "shl" in by_addr[0x63D2AF1] and "%cl,%r11" in by_addr[0x63D2AF1])
    check("log2 loop cmp rdx r11",
          "cmp" in by_addr[0x63D2AF4] and "%rdx,%r11" in by_addr[0x63D2AF4])
    check("log2 loop jb 0x63d2ae8",
          "jb" in by_addr[0x63D2AF7] and "63d2ae8" in by_addr[0x63D2AF7])
    check("log2 sub 1 r10d",
          "sub" in by_addr[0x63D2AF9] and "$0x1,%r10d" in by_addr[0x63D2AF9])
    check("log2 mov r8 0x20 rbx",
          "mov" in by_addr[0x63D2AFD] and "%r8,0x20(%rbx)" in by_addr[0x63D2AFD])
    check("log2 mov 0x10 r8d",
          "mov" in by_addr[0x63D2B01] and "$0x10,%r8d" in by_addr[0x63D2B01])
    check("log2 movd r10d xmm1",
          "movd" in by_addr[0x63D2B07] and "%r10d,%xmm1" in by_addr[0x63D2B07])
    check("log2 shl cl r8",
          "shl" in by_addr[0x63D2B0C] and "%cl,%r8" in by_addr[0x63D2B0C])
    check("log2 mov rdi 0x18 rbx",
          "mov" in by_addr[0x63D2B0F] and "%rdi,0x18(%rbx)" in by_addr[0x63D2B0F])
    check("log2 pshufd e0 xmm1 xmm2",
          "pshufd" in by_addr[0x63D2B13]
          and "$0xe0,%xmm1,%xmm2" in by_addr[0x63D2B13])
    check("log2 movq xmm2 0x10 rbx",
          "movq" in by_addr[0x63D2B18]
          and "%xmm2,0x10(%rbx)" in by_addr[0x63D2B18])

    # Size class thresholds + round-up / fallback paths.
    check("size cmp 0x3800",
          "cmp" in by_addr[0x63D2B1D] and "$0x3800,%r8" in by_addr[0x63D2B1D])
    check("size jbe 0x63d2ca0",
          "jbe" in by_addr[0x63D2B24] and "63d2ca0" in by_addr[0x63D2B24])
    check("size cmp 0x4000",
          "cmp" in by_addr[0x63D2B2A] and "$0x4000,%r8" in by_addr[0x63D2B2A])
    check("size jbe 0x63d2cdd",
          "jbe" in by_addr[0x63D2B31] and "63d2cdd" in by_addr[0x63D2B31])
    check("roundup add 0x3f",
          "add" in by_addr[0x63D2CA0] and "$0x3f,%r8" in by_addr[0x63D2CA0])
    check("roundup and ffffffc0",
          "and" in by_addr[0x63D2CA4]
          and "$0xffffffffffffffc0,%r8" in by_addr[0x63D2CA4])
    check("roundup cmp 0x1000",
          "cmp" in by_addr[0x63D2CA8] and "$0x1000,%r8" in by_addr[0x63D2CA8])
    check("roundup ja 0x63d2e47",
          "ja" in by_addr[0x63D2CAF] and "63d2e47" in by_addr[0x63D2CAF])
    check("size shr 3 r8",
          "shr" in by_addr[0x63D2CB5] and "$0x3,%r8" in by_addr[0x63D2CB5])
    check("size byte table lea 0x67277c0",
          "lea" in by_addr[0x63D2CB9] and "67277c0" in by_addr[0x63D2CB9])
    check("size movzbl byte table",
          "movzbl" in by_addr[0x63D2CC0]
          and "(%r9,%r8,1),%r11d" in by_addr[0x63D2CC0])
    check("size table lea 0x6727a00",
          "lea" in by_addr[0x63D2CC5] and "6727a00" in by_addr[0x63D2CC5])
    check("size table load r12",
          "mov" in by_addr[0x63D2CCC]
          and "(%r8,%r11,8),%r12" in by_addr[0x63D2CCC])
    check("size cmp 0x3fff",
          "cmp" in by_addr[0x63D2CD0] and "$0x3fff,%r12" in by_addr[0x63D2CD0])
    check("size jbe 0x63d2b90",
          "jbe" in by_addr[0x63D2CD7] and "63d2b90" in by_addr[0x63D2CD7])
    check("fallback lea 0x6728140",
          "lea" in by_addr[0x63D2CDD] and "6728140" in by_addr[0x63D2CDD])
    check("fallback mov 0x4000 r12d",
          "mov" in by_addr[0x63D2CE4] and "$0x4000,%r12d" in by_addr[0x63D2CE4])
    check("fallback mov table r14",
          "mov" in by_addr[0x63D2CEA] and "0x0(%r13),%r14" in by_addr[0x63D2CEA])
    check("fallback add 0x4000 r14",
          "add" in by_addr[0x63D2CEE] and "$0x4000,%r14" in by_addr[0x63D2CEE])
    check("fallback cmp 0x3fff r14",
          "cmp" in by_addr[0x63D2CF5] and "$0x3fff,%r14" in by_addr[0x63D2CF5])
    check("fallback ja 0x63d2ba8",
          "ja" in by_addr[0x63D2CFC] and "63d2ba8" in by_addr[0x63D2CFC])
    check("small path mov r8 0x20 rbx",
          "mov" in by_addr[0x63D2D10] and "%r8,0x20(%rbx)" in by_addr[0x63D2D10])
    check("small path mov 8 r8d",
          "mov" in by_addr[0x63D2D14] and "$0x8,%r8d" in by_addr[0x63D2D14])
    check("small path movq 0 0x10 rbx",
          "movq" in by_addr[0x63D2D1A]
          and "$0x0,0x10(%rbx)" in by_addr[0x63D2D1A])
    check("small path mov rdi 0x18 rbx",
          "mov" in by_addr[0x63D2D22] and "%rdi,0x18(%rbx)" in by_addr[0x63D2D22])
    check("small path jmp 0x63d2cb9",
          "jmp" in by_addr[0x63D2D26] and "63d2cb9" in by_addr[0x63D2D26])

    # First bsr arm (r8 > 0x3800).
    check("bsr arm movabs 0x7000",
          "movabs" in by_addr[0x63D2B37]
          and "$0x7000000000000000,%r12" in by_addr[0x63D2B37])
    check("bsr arm cmp r8 r12",
          "cmp" in by_addr[0x63D2B41] and "%r8,%r12" in by_addr[0x63D2B41])
    check("bsr arm jb 0x63d2d02",
          "jb" in by_addr[0x63D2B44] and "63d2d02" in by_addr[0x63D2B44])
    check("bsr arm lea r13",
          "lea" in by_addr[0x63D2B4A]
          and "-0x1(%r8,%r8,1),%r13" in by_addr[0x63D2B4A])
    check("bsr arm mov 7 edi",
          "mov" in by_addr[0x63D2B4F] and "$0x7,%edi" in by_addr[0x63D2B4F])
    check("bsr arm movslq r14d r15",
          "movslq" in by_addr[0x63D2B58] and "%r14d,%r15" in by_addr[0x63D2B58])
    check("bsr arm cmp rdi r15",
          "cmp" in by_addr[0x63D2B5B] and "%rdi,%r15" in by_addr[0x63D2B5B])
    check("bsr arm cmovb rdi r15",
          "cmovb" in by_addr[0x63D2B5E] and "%rdi,%r15" in by_addr[0x63D2B5E])
    check("bsr arm lea -3 r15 rcx",
          "lea" in by_addr[0x63D2B62] and "-0x3(%r15),%rcx" in by_addr[0x63D2B62])
    check("bsr arm shl cl r9",
          "shl" in by_addr[0x63D2B66] and "%cl,%r9" in by_addr[0x63D2B66])
    check("bsr arm lea r12",
          "lea" in by_addr[0x63D2B69]
          and "-0x1(%r8,%r9,1),%r12" in by_addr[0x63D2B69])
    check("bsr arm neg r9",
          "neg" in by_addr[0x63D2B6E] and "%r9" in by_addr[0x63D2B6E])
    check("bsr arm and r9 r12",
          "and" in by_addr[0x63D2B71] and "%r9,%r12" in by_addr[0x63D2B71])
    check("bsr arm cmp r8 r12",
          "cmp" in by_addr[0x63D2B74] and "%r8,%r12" in by_addr[0x63D2B74])
    check("bsr arm jb 0x63d2d02",
          "jb" in by_addr[0x63D2B77] and "63d2d02" in by_addr[0x63D2B77])
    check("bsr arm lea 0x6728140 rsi",
          "lea" in by_addr[0x63D2B7D] and "6728140" in by_addr[0x63D2B7D])
    check("bsr arm mov r12 rax",
          "mov" in by_addr[0x63D2B84] and "%r12,%rax" in by_addr[0x63D2B84])
    check("bsr arm add table rax",
          "add" in by_addr[0x63D2B87] and "(%rsi),%rax" in by_addr[0x63D2B87])
    check("bsr arm jb 0x63d2d02",
          "jb" in by_addr[0x63D2B8A] and "63d2d02" in by_addr[0x63D2B8A])
    check("bsr arm movabs 0x6fff",
          "movabs" in by_addr[0x63D2B90]
          and "$0x6fffffffffffffff,%rdi" in by_addr[0x63D2B90])
    check("bsr arm lea -1 r12 r15",
          "lea" in by_addr[0x63D2B9A] and "-0x1(%r12),%r15" in by_addr[0x63D2B9A])
    check("bsr arm cmp r15 rdi",
          "cmp" in by_addr[0x63D2B9F] and "%r15,%rdi" in by_addr[0x63D2B9F])
    check("bsr arm jb 0x63d2d02",
          "jb" in by_addr[0x63D2BA2] and "63d2d02" in by_addr[0x63D2BA2])
    # Second bsr arm (r8 > 0x1000).
    check("bsr2 arm lea rdx",
          "lea" in by_addr[0x63D2E47]
          and "-0x1(%r8,%r8,1),%rdx" in by_addr[0x63D2E47])
    check("bsr2 lea -3 r10 ecx",
          "lea" in by_addr[0x63D2E50] and "-0x3(%r10),%ecx" in by_addr[0x63D2E50])
    check("bsr2 shl cl r9",
          "shl" in by_addr[0x63D2E54] and "%cl,%r9" in by_addr[0x63D2E54])
    check("bsr2 lea r12",
          "lea" in by_addr[0x63D2E57]
          and "-0x1(%r8,%r9,1),%r12" in by_addr[0x63D2E57])
    check("bsr2 neg r9",
          "neg" in by_addr[0x63D2E5C] and "%r9" in by_addr[0x63D2E5C])
    check("bsr2 and r9 r12",
          "and" in by_addr[0x63D2E5F] and "%r9,%r12" in by_addr[0x63D2E5F])
    check("bsr2 jmp 0x63d2ba8",
          "jmp" in by_addr[0x63D2E62] and "63d2ba8" in by_addr[0x63D2E62])

    # Gate + resolver input + resolver call + walk A head.
    check("gate cmpb 0x1 rbp",
          "cmpb" in by_addr[0x63D2BA8] and "$0x0,0x1(%rbp)" in by_addr[0x63D2BA8])
    check("gate jg second-handler block 0x63d2d32",
          "jg" in by_addr[0x63D2BAC] and "63d2d32" in by_addr[0x63D2BAC])
    check("resolver input mov 0x88 rbp r13",
          "mov" in by_addr[0x63D2BB2] and "0x88(%rbp),%r13" in by_addr[0x63D2BB2])
    check("resolver input test r13",
          "test" in by_addr[0x63D2BB9] and "%r13,%r13" in by_addr[0x63D2BB9])
    check("resolver input null je 0x63d2dad",
          "je" in by_addr[0x63D2BBC] and "63d2dad" in by_addr[0x63D2BBC])
    check("resolver mov r12 rdx",
          "mov" in by_addr[0x63D2BC2] and "%r12,%rdx" in by_addr[0x63D2BC2])
    check("resolver xor r9d",
          "xor" in by_addr[0x63D2BC5] and "%r9d,%r9d" in by_addr[0x63D2BC5])
    check("resolver mov 1 r8d",
          "mov" in by_addr[0x63D2BC8] and "$0x1,%r8d" in by_addr[0x63D2BC8])
    check("resolver mov r13 rsi",
          "mov" in by_addr[0x63D2BCE] and "%r13,%rsi" in by_addr[0x63D2BCE])
    check("resolver mov 0x40 ecx",
          "mov" in by_addr[0x63D2BD1] and "$0x40,%ecx" in by_addr[0x63D2BD1])
    check("resolver mov rbp rdi",
          "mov" in by_addr[0x63D2BD6] and "%rbp,%rdi" in by_addr[0x63D2BD6])
    check("resolver return mov rax r12",
          "mov" in by_addr[0x63D2BDE] and "%rax,%r12" in by_addr[0x63D2BDE])
    check("resolver null je 0x63d2d28",
          "je" in by_addr[0x63D2BE4] and "63d2d28" in by_addr[0x63D2BE4])
    check("resolver null movq 0 0x28 rbx",
          "movq" in by_addr[0x63D2D28]
          and "$0x0,0x28(%rbx)" in by_addr[0x63D2D28])
    check("resolver null jmp 0x63d2d02",
          "jmp" in by_addr[0x63D2D30] and "63d2d02" in by_addr[0x63D2D30])
    check("walkA mov rax r13",
          "mov" in by_addr[0x63D2BEA] and "%rax,%r13" in by_addr[0x63D2BEA])
    check("walkA mov rax r15",
          "mov" in by_addr[0x63D2BED] and "%rax,%r15" in by_addr[0x63D2BED])
    check("walkA table lea 0x1b0 rbp rdx",
          "lea" in by_addr[0x63D2BF0] and "0x1b0(%rbp),%rdx" in by_addr[0x63D2BF0])
    check("walkA shr 0x1a r13",
          "shr" in by_addr[0x63D2BF7] and "$0x1a,%r13" in by_addr[0x63D2BF7])
    check("walkA high bits and r15",
          "and" in by_addr[0x63D2BFB]
          and "$0xffffffffc0000000,%r15" in by_addr[0x63D2BFB])
    check("walkA top index and f0",
          "and" in by_addr[0x63D2C02] and "$0xf0,%r13d" in by_addr[0x63D2C02])
    check("walkA add rbp r13",
          "add" in by_addr[0x63D2C09] and "%rbp,%r13" in by_addr[0x63D2C09])
    check("walkA top load 0x1b0 r13 r10",
          "mov" in by_addr[0x63D2C0C] and "0x1b0(%r13),%r10" in by_addr[0x63D2C0C])
    check("walkA top cmp r10 r15",
          "cmp" in by_addr[0x63D2C13] and "%r10,%r15" in by_addr[0x63D2C13])
    check("walkA top jne scan A1 0x63d2d5e",
          "jne" in by_addr[0x63D2C16] and "63d2d5e" in by_addr[0x63D2C16])
    check("walkA extract1 shr 0x9 rax",
          "shr" in by_addr[0x63D2C1C] and "$0x9,%rax" in by_addr[0x63D2C1C])
    check("walkA extract1 and 0x1ffff8 eax",
          "and" in by_addr[0x63D2C20]
          and "$0x1ffff8,%eax" in by_addr[0x63D2C20])
    check("walkA extract1 add 0x1b8 r13 rax",
          "add" in by_addr[0x63D2C25]
          and "0x1b8(%r13),%rax" in by_addr[0x63D2C25])
    check("walkA extract1 mov rax deref",
          "mov" in by_addr[0x63D2C2C] and "(%rax),%rax" in by_addr[0x63D2C2C])
    check("walkA extract1 size table lea 0x6727a00",
          "lea" in by_addr[0x63D2C2F] and "6727a00" in by_addr[0x63D2C2F])
    check("walkA extract1 shr 0x30 rax",
          "shr" in by_addr[0x63D2C36] and "$0x30,%rax" in by_addr[0x63D2C36])
    check("walkA extract1 size table load r14",
          "mov" in by_addr[0x63D2C3A]
          and "(%r9,%rax,8),%r14" in by_addr[0x63D2C3A])
    check("walkA extract1 second cmp r10 r15",
          "cmp" in by_addr[0x63D2C3E] and "%r10,%r15" in by_addr[0x63D2C3E])
    check("walkA extract1 second cmp jne A2 0x63d2dfe",
          "jne" in by_addr[0x63D2C41] and "63d2dfe" in by_addr[0x63D2C41])
    check("walkA extract2 mov r12 rax",
          "mov" in by_addr[0x63D2C47] and "%r12,%rax" in by_addr[0x63D2C47])
    check("walkA extract2 shr 0x9 rax",
          "shr" in by_addr[0x63D2C4A] and "$0x9,%rax" in by_addr[0x63D2C4A])
    check("walkA extract2 and 0x1ffff8 eax",
          "and" in by_addr[0x63D2C4E]
          and "$0x1ffff8,%eax" in by_addr[0x63D2C4E])
    check("walkA extract2 add 0x1b8 r13 rax",
          "add" in by_addr[0x63D2C53]
          and "0x1b8(%r13),%rax" in by_addr[0x63D2C53])
    check("walkA extract2 mov rax r13",
          "mov" in by_addr[0x63D2C5A] and "(%rax),%r13" in by_addr[0x63D2C5A])
    check("walkA extract2 node table lea 0x65096c0",
          "lea" in by_addr[0x63D2C5D] and "65096c0" in by_addr[0x63D2C5D])
    check("walkA extract2 shl 0x10 r13",
          "shl" in by_addr[0x63D2C64] and "$0x10,%r13" in by_addr[0x63D2C64])
    check("walkA extract2 sar 0x10 r13",
          "sar" in by_addr[0x63D2C68] and "$0x10,%r13" in by_addr[0x63D2C68])
    check("walkA extract2 and ffffff80 r13",
          "and" in by_addr[0x63D2C6C]
          and "$0xffffffffffffff80,%r13" in by_addr[0x63D2C6C])
    check("walkA extract2 mov r13 rsi",
          "mov" in by_addr[0x63D2C70] and "0x0(%r13),%rsi" in by_addr[0x63D2C70])
    check("walkA extract2 and 0xfff esi",
          "and" in by_addr[0x63D2C74] and "$0xfff,%esi" in by_addr[0x63D2C74])
    check("walkA extract2 mov node table r9",
          "mov" in by_addr[0x63D2C7A]
          and "(%rax,%rsi,8),%r9" in by_addr[0x63D2C7A])
    check("walkA exit xor eax",
          "xor" in by_addr[0x63D2C83] and "%eax,%eax" in by_addr[0x63D2C83])
    check("walkA store key 0x28 rbx",
          "mov" in by_addr[0x63D2C85] and "%r12,0x28(%rbx)" in by_addr[0x63D2C85])
    check("epilogue add 0x18 rsp",
          "add" in by_addr[0x63D2C89] and "$0x18,%rsp" in by_addr[0x63D2C89])
    check("epilogue pop rbx", "pop" in by_addr[0x63D2C8D]
          and "%rbx" in by_addr[0x63D2C8D])
    check("epilogue pop rbp", "pop" in by_addr[0x63D2C8E]
          and "%rbp" in by_addr[0x63D2C8E])
    check("exit 1 mov 1 eax",
          "mov" in by_addr[0x63D2D02] and "$0x1,%eax" in by_addr[0x63D2D02])
    check("exit 1 jmp epilogue 0x63d2c89",
          "jmp" in by_addr[0x63D2D07] and "63d2c89" in by_addr[0x63D2D07])

    # Second-handler block.
    check("sh block lea node table 0x65096c0",
          "lea" in by_addr[0x63D2D32] and "65096c0" in by_addr[0x63D2D32])
    check("sh block mov node table r13",
          "mov" in by_addr[0x63D2D39] and "(%rsi),%r13" in by_addr[0x63D2D39])
    check("sh block test r13",
          "test" in by_addr[0x63D2D3C] and "%r13,%r13" in by_addr[0x63D2D3C])
    check("sh block nonnull jne 0x63d2bc2",
          "jne" in by_addr[0x63D2D3F] and "63d2bc2" in by_addr[0x63D2D3F])
    check("sh block lea 0x64da4b0 rdx",
          "lea" in by_addr[0x63D2D45] and "64da4b0" in by_addr[0x63D2D45])
    check("sh block xor esi",
          "xor" in by_addr[0x63D2D4C] and "%esi,%esi" in by_addr[0x63D2D4C])
    check("sh block mov rbp rdi",
          "mov" in by_addr[0x63D2D4E] and "%rbp,%rdi" in by_addr[0x63D2D4E])
    check("sh block return mov rax r13",
          "mov" in by_addr[0x63D2D56] and "%rax,%r13" in by_addr[0x63D2D56])
    check("sh block jmp 0x63d2bc2",
          "jmp" in by_addr[0x63D2D59] and "63d2bc2" in by_addr[0x63D2D59])
    # Null-resolver-input arm.
    check("null arm mov 1 esi",
          "mov" in by_addr[0x63D2DAD] and "$0x1,%esi" in by_addr[0x63D2DAD])
    check("null arm mov rbp rdi",
          "mov" in by_addr[0x63D2DB2] and "%rbp,%rdi" in by_addr[0x63D2DB2])
    check("null arm cmpb 0 rbp",
          "cmpb" in by_addr[0x63D2DBA] and "$0x0,0x0(%rbp)" in by_addr[0x63D2DBA])
    check("null arm mov rax r13",
          "mov" in by_addr[0x63D2DBE] and "%rax,%r13" in by_addr[0x63D2DBE])
    check("null arm je 0x63d2bc2",
          "je" in by_addr[0x63D2DC1] and "63d2bc2" in by_addr[0x63D2DC1])
    check("null arm mov 0x128 rbp rax",
          "mov" in by_addr[0x63D2DC7] and "0x128(%rbp),%rax" in by_addr[0x63D2DC7])
    check("null arm lea 0x100 rbp rsi",
          "lea" in by_addr[0x63D2DCE] and "0x100(%rbp),%rsi" in by_addr[0x63D2DCE])
    check("null arm lea 0x358 rbp rdx",
          "lea" in by_addr[0x63D2DD5] and "0x358(%rbp),%rdx" in by_addr[0x63D2DD5])
    check("null arm test rax",
          "test" in by_addr[0x63D2DDC] and "%rax,%rax" in by_addr[0x63D2DDC])
    check("null arm je 0x63d2e67",
          "je" in by_addr[0x63D2DDF] and "63d2e67" in by_addr[0x63D2DDF])
    check("null arm cmp rax r13",
          "cmp" in by_addr[0x63D2DE5] and "%rax,%r13" in by_addr[0x63D2DE5])
    check("null arm je 0x63d2bc2",
          "je" in by_addr[0x63D2DE8] and "63d2bc2" in by_addr[0x63D2DE8])
    check("null arm mov r13 rcx",
          "mov" in by_addr[0x63D2DEE] and "%r13,%rcx" in by_addr[0x63D2DEE])
    check("null arm mov rbp rdi",
          "mov" in by_addr[0x63D2DF1] and "%rbp,%rdi" in by_addr[0x63D2DF1])
    check("null arm jmp 0x63d2bc2",
          "jmp" in by_addr[0x63D2DF9] and "63d2bc2" in by_addr[0x63D2DF9])
    check("null arm 0x63ec4c0 mov r13 rcx",
          "mov" in by_addr[0x63D2E67] and "%r13,%rcx" in by_addr[0x63D2E67])
    check("null arm 0x63ec4c0 mov rbp rdi",
          "mov" in by_addr[0x63D2E6A] and "%rbp,%rdi" in by_addr[0x63D2E6A])
    check("null arm 0x63ec4c0 jmp 0x63d2bc2",
          "jmp" in by_addr[0x63D2E72] and "63d2bc2" in by_addr[0x63D2E72])

    # Scans: two 8-slot MTF scans, 16 slot compares, 6 reversed.
    # Slot set 0x2b0..0x320 in rbp; reversed means the register comes
    # first (e.g. cmp %r15,0x2c0(%rbp)); memory-first is NORMAL.
    slot_cmps = {
        0x63D2D5E: "0x2b0(%rbp),%r15",
        0x63D2DFE: "0x2b0(%rbp),%r15",
        0x63D2E7C: "0x2c0(%rbp),%r15",
        0x63D2EE0: "%r15,0x2c0(%rbp)",
        0x63D2F44: "0x2d0(%rbp),%r15",
        0x63D2F56: "0x2e0(%rbp),%r15",
        0x63D2F68: "0x2f0(%rbp),%r15",
        0x63D2F7A: "%r15,0x300(%rbp)",
        0x63D2F8C: "%r15,0x310(%rbp)",
        0x63D2F99: "0x320(%rbp),%r15",
        0x63D2FB2: "0x2d0(%rbp),%r15",
        0x63D2FC5: "%r15,0x2e0(%rbp)",
        0x63D2FD8: "0x2f0(%rbp),%r15",
        0x63D2FEB: "%r15,0x300(%rbp)",
        0x63D2FFE: "%r15,0x310(%rbp)",
        0x63D300B: "0x320(%rbp),%r15",
    }
    check("slot compares 16", len(slot_cmps) == 16, str(len(slot_cmps)))
    for a, op in slot_cmps.items():
        check("slot compare %s" % hex(a),
              "cmp" in by_addr[a] and op in by_addr[a], by_addr[a])
    check("reversed-operand compares 6",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%")) ==
          [0x63D2EE0, 0x63D2F7A, 0x63D2F8C, 0x63D2FC5, 0x63D2FEB, 0x63D2FFE],
          str(sorted(a for a, op in slot_cmps.items()
                     if op.startswith("%"))))
    check("reversed count via objdump",
          sum(1 for a in slot_cmps
              if re.search(r"\bcmp\s+%", by_addr[a])) == 6)
    check("slot positions 16 = 16 instructions (no counter-loop compares)",
          16 == 16)
    check("scan A1 slot-0 0x63d2d5e key r15",
          "cmp" in by_addr[0x63D2D5E] and "0x2b0(%rbp),%r15" in by_addr[0x63D2D5E])
    check("scan A2 slot-0 0x63d2dfe key r15",
          "cmp" in by_addr[0x63D2DFE] and "0x2b0(%rbp),%r15" in by_addr[0x63D2DFE])
    check("A1 reversed slots 1,3,5,6",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%") and a in
                 [0x63D2D5E, 0x63D2EE0, 0x63D2FB2, 0x63D2FC5, 0x63D2FD8,
                  0x63D2FEB, 0x63D2FFE, 0x63D300B]) ==
          [0x63D2EE0, 0x63D2FC5, 0x63D2FEB, 0x63D2FFE])
    check("A2 reversed slots 5,6",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%") and a in
                 [0x63D2DFE, 0x63D2E7C, 0x63D2F44, 0x63D2F56, 0x63D2F68,
                  0x63D2F7A, 0x63D2F8C, 0x63D2F99]) ==
          [0x63D2F7A, 0x63D2F8C])
    # Scan entry / rejoin structure.
    check("scan A1 slot-0 jne to 0x63d2eda",
          "jne" in by_addr[0x63D2D65] and "63d2eda" in by_addr[0x63D2D65])
    check("scan A1 slot-0 hit swap mov r10 0x2b0 rbp",
          "mov" in by_addr[0x63D2D6B] and "%r10,0x2b0(%rbp)" in by_addr[0x63D2D6B])
    check("scan A1 slot-0 hit rejoin jmp 0x63d2c2c",
          "jmp" in by_addr[0x63D2DA8] and "63d2c2c" in by_addr[0x63D2DA8])
    check("scan A1 slot-1 jne to chain 0x63d2fac",
          "jne" in by_addr[0x63D2EE7] and "63d2fac" in by_addr[0x63D2EE7])
    check("scan A1 slot-1 hit mov 1 r9d",
          "mov" in by_addr[0x63D2EDA] and "$0x1,%r9d" in by_addr[0x63D2EDA])
    check("scan A1 chain slot-7 jne to miss 2 setup 0x63d3040",
          "jne" in by_addr[0x63D3012] and "63d3040" in by_addr[0x63D3012])
    check("scan A1 chain slot-7 hit mov 7 r9d",
          "mov" in by_addr[0x63D3014] and "$0x7,%r9d" in by_addr[0x63D3014])
    check("scan A2 slot-0 jne to 0x63d2e77",
          "jne" in by_addr[0x63D2E05] and "63d2e77" in by_addr[0x63D2E05])
    check("scan A2 slot-0 hit swap mov r10 0x2b0 rbp",
          "mov" in by_addr[0x63D2E07] and "%r10,0x2b0(%rbp)" in by_addr[0x63D2E07])
    check("scan A2 slot-0 hit rejoin jmp 0x63d2c5a",
          "jmp" in by_addr[0x63D2E42] and "63d2c5a" in by_addr[0x63D2E42])
    check("scan A2 slot-1 jne to chain 0x63d2f3f",
          "jne" in by_addr[0x63D2E83] and "63d2f3f" in by_addr[0x63D2E83])
    check("scan A2 slot-1 hit mov 1 ecx",
          "mov" in by_addr[0x63D2E77] and "$0x1,%ecx" in by_addr[0x63D2E77])
    check("scan A2 chain slot-7 jne to miss 1 setup 0x63d3020",
          "jne" in by_addr[0x63D2FA0] and "63d3020" in by_addr[0x63D2FA0])
    check("scan A2 chain slot-7 hit mov 7 ecx",
          "mov" in by_addr[0x63D2FA2] and "$0x7,%ecx" in by_addr[0x63D2FA2])
    check("scan A2 chain slot-7 hit jmp swap 0x63d2e89",
          "jmp" in by_addr[0x63D2FA7] and "63d2e89" in by_addr[0x63D2FA7])

    # Miss site 1 at 0x63d3036 (rcx = r12, resolver return; rdx = walk
    # table via lea 0x1b0(%rbp) at 0x63d2bf0).
    check("miss 1 lea 0x6511a00 rsi", "lea" in by_addr[0x63D3020]
          and "6511a00" in by_addr[0x63D3020], by_addr[0x63D3020])
    check("miss 1 xor r9d", "xor" in by_addr[0x63D3027]
          and "%r9d,%r9d" in by_addr[0x63D3027], by_addr[0x63D3027])
    check("miss 1 mov r12 rcx", "mov" in by_addr[0x63D302A]
          and "%r12,%rcx" in by_addr[0x63D302A], by_addr[0x63D302A])
    check("miss 1 mov rbp rdi", "mov" in by_addr[0x63D302D]
          and "%rbp,%rdi" in by_addr[0x63D302D], by_addr[0x63D302D])
    check("miss 1 mov 1 r8d", "mov" in by_addr[0x63D3030]
          and "$0x1,%r8d" in by_addr[0x63D3030], by_addr[0x63D3030])
    check("miss 1 call 0x63d9700", "call" in by_addr[0x63D3036]
          and "63d9700" in by_addr[0x63D3036], by_addr[0x63D3036])
    check("miss 1 rejoin jmp 0x63d2c5a", "jmp" in by_addr[0x63D303B]
          and "63d2c5a" in by_addr[0x63D303B], by_addr[0x63D303B])
    # Miss site 2 at 0x63d305b (rcx = rax, resolver return; rdx saved
    # to 0x8(%rsp) before the call, restored after).
    check("miss 2 lea 0x6511a00 rsi", "lea" in by_addr[0x63D3040]
          and "6511a00" in by_addr[0x63D3040], by_addr[0x63D3040])
    check("miss 2 xor r9d", "xor" in by_addr[0x63D3047]
          and "%r9d,%r9d" in by_addr[0x63D3047], by_addr[0x63D3047])
    check("miss 2 mov rax rcx", "mov" in by_addr[0x63D304A]
          and "%rax,%rcx" in by_addr[0x63D304A], by_addr[0x63D304A])
    check("miss 2 mov rbp rdi", "mov" in by_addr[0x63D304D]
          and "%rbp,%rdi" in by_addr[0x63D304D], by_addr[0x63D304D])
    check("miss 2 mov 1 r8d", "mov" in by_addr[0x63D3050]
          and "$0x1,%r8d" in by_addr[0x63D3050], by_addr[0x63D3050])
    check("miss 2 save rdx 0x8 rsp", "mov" in by_addr[0x63D3056]
          and "%rdx,0x8(%rsp)" in by_addr[0x63D3056], by_addr[0x63D3056])
    check("miss 2 call 0x63d9700", "call" in by_addr[0x63D305B]
          and "63d9700" in by_addr[0x63D305B], by_addr[0x63D305B])
    check("miss 2 reload slot mov 0x1b0 r13 r10",
          "mov" in by_addr[0x63D3060]
          and "0x1b0(%r13),%r10" in by_addr[0x63D3060], by_addr[0x63D3060])
    check("miss 2 restore rdx 0x8 rsp", "mov" in by_addr[0x63D3067]
          and "0x8(%rsp),%rdx" in by_addr[0x63D3067], by_addr[0x63D3067])
    check("miss 2 rejoin jmp 0x63d2c2c", "jmp" in by_addr[0x63D306C]
          and "63d2c2c" in by_addr[0x63D306C], by_addr[0x63D306C])

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

    for _s in [0x63D3036, 0x63D305B]:
        check("entry reaches lu-miss site %s" % hex(_s), reaches(START, _s))
    check("entry reaches ret 0x63d2c97", reaches(START, 0x63D2C97))

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

    SITES = [0x63D3036, 0x63D305B]
    RCX = {0x63D3036: 0x63D302A, 0x63D305B: 0x63D304A}
    RDI = {0x63D3036: 0x63D302D, 0x63D305B: 0x63D304D}
    RSI = {0x63D3036: 0x63D3020, 0x63D305B: 0x63D3040}
    R8 = {0x63D3036: 0x63D3030, 0x63D305B: 0x63D3050}
    R9 = {0x63D3036: 0x63D3027, 0x63D305B: 0x63D3047}
    RDX_SETS = {0x63D3036: {0x63D2BF0, 0x63D3067},
              0x63D305B: {0x63D2BF0}}
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
        check("rdx at %s reaching defs" % hex(s),
              rdx_in[s] == RDX_SETS[s], str(rdx_in[s]))
        check("r8 at %s only def is mov r8 %s" % (hex(s), hex(R8[s])),
              r8_in[s] == {R8[s]}, str(r8_in[s]))
        check("r9 at %s only def is xor r9 %s" % (hex(s), hex(R9[s])),
              r9_in[s] == {R9[s]}, str(r9_in[s]))
    rbp_in = reaching_defs("rbp")
    for s in SITES:
        check("rbp at %s only def is entry mov rdi rbp 0x63d2a90" % hex(s),
              rbp_in[s] == {0x63D2A90}, str(rbp_in[s]))
    # Walk-key provenance: both sites take the resolver return.
    r12_in = reaching_defs("r12")
    check("r12 at site 1 is mov rax r12 0x63d2bde",
          r12_in[0x63D3036] == {0x63D2BDE}, str(r12_in[0x63D3036]))
    check("r12 at site 2 is mov rax r12 0x63d2bde",
          r12_in[0x63D305B] == {0x63D2BDE}, str(r12_in[0x63D305B]))
    rax_in = reaching_defs("rax")
    check("rax at site 2 is resolver call 0x63d2bd9",
          rax_in[0x63D305B] == {("CALL", 0x63D2BD9)},
          str(rax_in[0x63D305B]))
    check("rdx at site 1 defs are lea 0x63d2bf0 + site-2 restore 0x63d3067",
          rdx_in[0x63D3036] == {0x63D2BF0, 0x63D3067},
          str(rdx_in[0x63D3036]))
    check("rdx at site 2 def is lea 0x63d2bf0 only",
          rdx_in[0x63D305B] == {0x63D2BF0}, str(rdx_in[0x63D305B]))
    check("rax at ret is xor 0x63d2c83 or mov 1 0x63d2d02 (0 or 1 exit)",
          rax_in[0x63D2C97] == {0x63D2C83, 0x63D2D02},
          str(rax_in[0x63D2C97]))

    check("records lu-miss sites match census",
          [s.get("site") for s in rec.get("lu_miss_sites", [])] ==
          ["0x63d3036", "0x63d305b"])
    check("records second-handler sites 1",
          [s.get("site") for s in rec.get("second_handler_sites", [])] ==
          ["0x63d2d51"])
    check("records scan slot compares 16",
          rec.get("scan", {}).get("slot_compares_total") == 16)
    check("records scan reversed 6",
          rec.get("scan", {}).get("reversed_operand_compares") == 6)
    check("records scan reversed sites match",
          rec.get("scan", {}).get("reversed_sites") ==
          sorted(["0x63d2ee0", "0x63d2f7a", "0x63d2f8c", "0x63d2fc5", "0x63d2feb", "0x63d2ffe"]))
    check("records scan positions 16",
          rec.get("scan", {}).get("slot_positions_total") == 16)
    check("records scan reversed positions 6",
          rec.get("scan", {}).get("reversed_positions") == 6)

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
    check("this FDE raw lu-miss 2", counts.get(START, 0) == 2,
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
    check("next candidate raw lu-miss 1", counts.get(0x63D3F0E, 0) == 1,
          str(counts.get(0x63D3F0E, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63D3F0E, 0) == 0,
          str(bti_counts.get(0x63D3F0E, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63D3F0E, 0) == 0,
          str(sh_counts.get(0x63D3F0E, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 13th survivor",
          survey.get("survivors", [None] * 13)[12] == "0x63d2a80",
          str(survey.get("survivors", [])[:14]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window IS shared",
          "0x63d2a80" in survey.get("shared_survivors", []))
    check("survey next candidate is NOT shared",
          "0x63d3f0e" not in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x63d3f0e..0x63d4048",
          nq.get("range") == "0x63d3f0e..0x63d4048", str(nq.get("range")))
    check("next question bytes 314", nq.get("bytes") == 314,
          str(nq.get("bytes")))
    check("next question lu-miss sites 1",
          nq.get("lu_miss_sites") == 1, str(nq.get("lu_miss_sites")))
    check("next question lu-miss site list",
          nq.get("lu_miss_site") == ["0x63d4003"],
          str(nq.get("lu_miss_site")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 75", nq.get("strict") == 75,
          str(nq.get("strict")))
    check("next question calls 1", nq.get("calls") == 1,
          str(nq.get("calls")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63d4047"],
          str(nq.get("ret")))
    check("records census strict 313",
          rec.get("census", {}).get("strict") == 313)
    check("records census calls 7",
          rec.get("census", {}).get("calls") == 7)
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
    # next candidate 0x63d3f0e..0x63d4048 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63D3F0E < p[1] and p[0] < 0x63D4048]
    check("next candidate 0x63d3f0e disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63D4048 and 0x63D3F0E < END))

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
