"""Static verifier for RE-001-node115-lu-miss-caller-10site-threetail.

Twelfth packet of the lu-miss-caller frontier (callers of the lu-miss
handler 0x63d9700 that do not call bin_table_init): FDE
0x63d17e0..0x63d2a80, 4768 bytes, 928 strict instructions, 20 calls
(11 distinct direct targets, 0 indirect), 10 lu-miss sites, 0
bin_table_init sites, 1 second-handler site at 0x63d1c81, ONE ret at
0x63d1bd7, bsr 2, lock sub 2 / lock add 1, 156 jumps, 3 outside the
window (all three are tail jumps), endbr64 0, canary present, NO TLS
flag check.

This window is a SHARED survivor: it is in both the survey's 16-FDE
lu-miss survivor list and the 18-FDE second-handler survivor list, so
it consumes one slot of the combined 25-FDE miss-handler pool. First
frontier window with THREE tail jumps (0x63d1abe to 0x63637f0,
0x63d212c to 0x63bd6c0, 0x63d2450 to 0x6363260) and the first with a
uniform 0 exit across the single ret and all three tail jumps (each
exit passes its own canary check, which zeroes rax). Three
context-table walks (A, B, C) plus a deep-resolution tail with two
counter-loop scans (D1, D2); NO outer loop -- the walks run once,
straight-line. Ten 8-slot move-to-front scans share one slot set
(0x2b0..0x320 in r14): 68 slot-compare instructions, SEVENTEEN
reversed-operand (A1 slots 3, 6; B2 slots 3, 4, 5, 6; B3 slots 1, 2;
C1 slots 1, 2; C2 slots 1, 2, 4, 5; C3 slots 1, 2, 5), i.e. 17 of 80
slot positions reversed; eight scans are unrolled chains, D1 and D2
are counter loops. All ten lu-miss sites share one argument pattern
(rdi = r14 context, rsi = .bss 0x6511a00, rdx = walk table pointer,
rcx = walk key, r8d = 1, r9d = 0); site 1 takes the table from r12
(lea 0x1b0(%r14),%r12 at 0x63d18c1, its only reaching definition
there), sites 2-10 load it with mov 0x18(%rsp),%rdx. The rcx
provenance is proven by reaching-definitions (sites 1, 2 = walk-A
key from the resolver return; sites 3, 4, 5, 10 = r10 walk-C key;
sites 6, 7, 8, 9 = walk-B key from the stack slot 0x8(%rsp)).
Exit: rax = 0 uniformly (single reaching def at the ret: the canary
sub at 0x63d1bba), unlike #324 (0 or 1) and #319 (0, ret only).

#324's pointer for this window (4768 bytes, 928 strict, 20 calls,
10 lu-miss sites at 0x63d2549 / 0x63d2575 / 0x63d26f7 / 0x63d2738 /
0x63d2771 / 0x63d2871 / 0x63d28a6 / 0x63d29b3 / 0x63d29e1 / 0x63d2a76,
0 bin_table_init sites, 1 second-handler site at 0x63d1c81, 1 ret at
0x63d1bd7, bsr 2) was verified correct by targeted objdump census.
No correction (prior_pointer_verified). Two corrections to the
pre-build handoff draft, both caught by byte-level verification:
the scan->miss-site mapping is A1->1, A2->2, C1->3, C2->4, C3->5,
B3->6, D1->7, B1->8, B2->9, D2->10 (the draft had B1->9, B3->10,
D2->8); and the rcx groups are sites 3, 4, 5, 10 = r10 walk-C key
and sites 6, 7, 8, 9 = 0x8(%rsp) walk-B key (the draft had sites
8 and 10 swapped).

Next question: the next lu-miss survivor in address order is
0x63d2a80..0x63d3071 (1521 bytes, 313 strict, 7 calls, 2 lu-miss
sites, 0 bti, 1 second-handler site at 0x63d2d51, 1 ret at 0x63d2c97,
bsr 2) -- also a SHARED survivor, unlike #323.

Usage: python3 tools/node115_lu_miss_caller_10site_threetail.py
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
                      "RE-001-node115-lu-miss-caller-10site-threetail")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-10site-threetail"
NAME = "lu_miss_caller_10site_threetail"
START, END = 0x63D17E0, 0x63D2A80

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
    check("target FDE size 4768", END - START == 4768)
    prev = fdes[i - 1]
    check("prev FDE 0x63d03a0..0x63d17d7",
          prev == (0x63D03A0, 0x63D17D7), str(prev))
    check("prev gap 9", START - prev[1] == 9)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 9, gap.hex())
    nxt = fdes[i + 1]
    check("next FDE 0x63d2a80..0x63d3071",
          nxt == (0x63D2A80, 0x63D3071), str(nxt))
    check("next padding 0", nxt[0] - END == 0)
    check("next FDE starts endbr64",
          node[toff(nxt[0]):toff(nxt[0]) + 4] == b"\xf3\x0f\x1e\xfa")
    check("prev FDE starts push r15 (no endbr64)",
          node[toff(prev[0]):toff(prev[0]) + 2] == b"\x41\x57")

    hexb = read(os.path.join(PACKET, "lu_miss_caller_10site_threetail.hex"))
    check("hex exhibit raw bytes 4768", len(hexb) == 4768, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lu_miss_caller_10site_threetail.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 928", len(lines) == 928, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 20", len(calls) == 20, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63d1bd7",
          len(rets) == 1 and addr_of(rets[0]) == 0x63D1BD7,
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
    expect = {0x6365150: 1, 0x63D0080: 1, 0x63637F0: 1, 0x634EBB0: 1,
              0x6352FC0: 1, 0x63EDF10: 1, 0x63BD6C0: 1, 0x63EC4C0: 1,
              0x6363260: 1, 0x63D9700: 10, 0x63F0D70: 1}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct call targets 11", len(tgt) == 11, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 10",
          tgt.get(0x63D9700, 0) == 10, str(tgt.get(0x63D9700, 0)))
    check("lu-miss site list",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63d9700" in l) ==
          [0x63D2549, 0x63D2575, 0x63D26F7, 0x63D2738, 0x63D2771,
           0x63D2871, 0x63D28A6, 0x63D29B3, 0x63D29E1, 0x63D2A76])
    check("second-handler sites 1", tgt.get(0x634EBB0, 0) == 1,
          str(tgt.get(0x634EBB0, 0)))
    check("second-handler site 0x63d1c81",
          "call" in by_addr[0x63D1C81] and "634ebb0" in by_addr[0x63D1C81])
    check("lock-wait helper called 0 times", tgt.get(0x63BF680, 0) == 0,
          str(tgt.get(0x63BF680, 0)))
    check("resolver 0x6365150 called once at 0x63d18aa",
          "call" in by_addr[0x63D18AA] and "6365150" in by_addr[0x63D18AA])
    check("prev FDE 0x63d0080 called once at 0x63d19b1",
          "call" in by_addr[0x63D19B1] and "63d0080" in by_addr[0x63D19B1])
    check("0x63637f0 called once at 0x63d1b9e",
          "call" in by_addr[0x63D1B9E] and "63637f0" in by_addr[0x63D1B9E])
    check("0x6363260 called once at 0x63d1eef",
          "call" in by_addr[0x63D1EEF] and "6363260" in by_addr[0x63D1EEF])
    check("0x63bd6c0 called once at 0x63d1dc1",
          "call" in by_addr[0x63D1DC1] and "63bd6c0" in by_addr[0x63D1DC1])
    check("0x63ec4c0 called once at 0x63d2186",
          "call" in by_addr[0x63D2186] and "63ec4c0" in by_addr[0x63D2186])
    check("0x6352fc0 called once at 0x63d1c96",
          "call" in by_addr[0x63D1C96] and "6352fc0" in by_addr[0x63D1C96])
    check("0x63edf10 called once at 0x63d1cd5",
          "call" in by_addr[0x63D1CD5] and "63edf10" in by_addr[0x63D1CD5])
    check("stack_chk_fail plt called once at 0x63d2a4c",
          "call" in by_addr[0x63D2A4C] and "63f0d70" in by_addr[0x63D2A4C])
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 2", sorted(addr_of(l) for l in bsr) == [0x63D1C0D, 0x63D1EC8],
          str([hex(addr_of(l)) for l in bsr]))
    check("bsr 1 is bsr rdi rbp", "bsr" in by_addr[0x63D1C0D]
          and "%rdi,%rbp" in by_addr[0x63D1C0D], by_addr[0x63D1C0D])
    check("bsr 2 is bsr r15 rax", "bsr" in by_addr[0x63D1EC8]
          and "%r15,%rax" in by_addr[0x63D1EC8], by_addr[0x63D1EC8])
    locks = [l for l in lines if mnemonic_of(l) == "lock"]
    check("lock lines 3", len(locks) == 3, str(locks))
    check("lock add at 0x63d1954",
          "lock add" in by_addr[0x63D1954]
          and "%r12,0x38(%rax)" in by_addr[0x63D1954], by_addr[0x63D1954])
    check("lock sub at 0x63d1a5d",
          "lock sub" in by_addr[0x63D1A5D]
          and "%r13,0x38(%rdi)" in by_addr[0x63D1A5D], by_addr[0x63D1A5D])
    check("lock sub at 0x63d1b63",
          "lock sub" in by_addr[0x63D1B63]
          and "%rbp,0x38(%r13)" in by_addr[0x63D1B63], by_addr[0x63D1B63])
    jmps = [l for l in lines
            if mnemonic_of(l) in ("jmp", "je", "jne", "ja", "jb", "jae",
                                  "jbe", "jg", "jl", "jge", "jle", "jo",
                                  "jno", "js", "jns", "jp", "jnp")]
    check("jump lines 156", len(jmps) == 156, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure exactly the 3 tail jumps",
          sorted(outside) == [(0x63D1ABE, 0x63637F0), (0x63D212C, 0x63BD6C0),
                              (0x63D2450, 0x6363260)], str(outside))
    check("tail jump 1 to 0x63637f0",
          "jmp" in by_addr[0x63D1ABE] and "63637f0" in by_addr[0x63D1ABE])
    check("tail jump 2 to 0x63bd6c0",
          "jmp" in by_addr[0x63D212C] and "63bd6c0" in by_addr[0x63D212C])
    check("tail jump 3 to 0x6363260",
          "jmp" in by_addr[0x63D2450] and "6363260" in by_addr[0x63D2450])
    check("endbr64 count 0",
          sum(1 for l in lines if "endbr64" in l) == 0)
    check("entry is push r15 not endbr64",
          "push" in by_addr[START] and "%r15" in by_addr[START])
    check("canary present (stack_chk_fail called)",
          any("stack_chk" in l for l in lines))
    check("canary load fs:0x28 at 0x63d17f4",
          "mov" in by_addr[0x63D17F4] and "%fs:0x28,%rax" in by_addr[0x63D17F4])
    check("canary store 0x48 rsp at 0x63d17fd",
          "mov" in by_addr[0x63D17FD] and "0x48(%rsp)" in by_addr[0x63D17FD])
    check("canary check sub fs:0x28 at 0x63d1bba",
          "sub" in by_addr[0x63D1BBA] and "%fs:0x28,%rax" in by_addr[0x63D1BBA])
    check("no TLS flag fs:0x330 anywhere",
          not any("%fs:0x330" in l for l in lines))

    # Entry / prologue.
    check("entry mov rdi r14",
          "mov" in by_addr[0x63D17E4] and "%rdi,%r14" in by_addr[0x63D17E4])
    check("entry push r13", "push" in by_addr[0x63D17E7]
          and "%r13" in by_addr[0x63D17E7])
    check("entry push r12", "push" in by_addr[0x63D17E9]
          and "%r12" in by_addr[0x63D17E9])
    check("entry push rbp", "push" in by_addr[0x63D17EB]
          and "%rbp" in by_addr[0x63D17EB])
    check("entry push rbx", "push" in by_addr[0x63D17EC]
          and "%rbx" in by_addr[0x63D17EC])
    check("entry mov rsi rbx",
          "mov" in by_addr[0x63D17ED] and "%rsi,%rbx" in by_addr[0x63D17ED])
    check("entry sub 0x58 rsp",
          "sub" in by_addr[0x63D17F0] and "$0x58,%rsp" in by_addr[0x63D17F0])
    check("entry mov count 0x14 rsi",
          "mov" in by_addr[0x63D1802] and "0x14(%rsi),%eax" in by_addr[0x63D1802])
    check("entry mov 0x10 esi",
          "mov" in by_addr[0x63D1805] and "$0x10,%esi" in by_addr[0x63D1805])
    check("entry lea 0x1 rax ecx",
          "lea" in by_addr[0x63D180A] and "0x1(%rax),%ecx" in by_addr[0x63D180A])

    # Size class (computed once at entry; two bsr overflow arms).
    check("size shl cl rsi",
          "shl" in by_addr[0x63D1811] and "%cl,%rsi" in by_addr[0x63D1811])
    check("size cmp 0x3800",
          "cmp" in by_addr[0x63D1814] and "$0x3800,%rsi" in by_addr[0x63D1814])
    check("size ja 0x63d1be0",
          "ja" in by_addr[0x63D181B] and "63d1be0" in by_addr[0x63D181B])
    check("size add 0x3f",
          "add" in by_addr[0x63D1821] and "$0x3f,%rsi" in by_addr[0x63D1821])
    check("size and ffffffc0",
          "and" in by_addr[0x63D1825]
          and "$0xffffffffffffffc0,%rsi" in by_addr[0x63D1825])
    check("size cmp 0x1000",
          "cmp" in by_addr[0x63D1829] and "$0x1000,%rsi" in by_addr[0x63D1829])
    check("size ja 0x63d1ebe",
          "ja" in by_addr[0x63D1830] and "63d1ebe" in by_addr[0x63D1830])
    check("size byte table lea 0x67277c0",
          "lea" in by_addr[0x63D1836] and "67277c0" in by_addr[0x63D1836])
    check("size shr 3 rsi",
          "shr" in by_addr[0x63D183D] and "$0x3,%rsi" in by_addr[0x63D183D])
    check("size table lea 0x6727a00",
          "lea" in by_addr[0x63D1841] and "6727a00" in by_addr[0x63D1841])
    check("size movzbl byte table",
          "movzbl" in by_addr[0x63D1848]
          and "(%rdi,%rsi,1),%esi" in by_addr[0x63D1848])
    check("size table load r12",
          "mov" in by_addr[0x63D184C]
          and "0x0(%rbp,%rsi,8),%r12" in by_addr[0x63D184C])
    check("size cmp 0x3fff",
          "cmp" in by_addr[0x63D1851] and "$0x3fff,%r12" in by_addr[0x63D1851])
    check("size jbe 0x63d1c45",
          "jbe" in by_addr[0x63D1858] and "63d1c45" in by_addr[0x63D1858])
    check("size fallback lea 0x6728140",
          "lea" in by_addr[0x63D185E] and "6728140" in by_addr[0x63D185E])
    check("size fallback mov 0x4000 r12d",
          "mov" in by_addr[0x63D1865] and "$0x4000,%r12d" in by_addr[0x63D1865])
    check("size fallback cmpq c000",
          "cmpq" in by_addr[0x63D186B]
          and "$0xffffffffffffc000,(%r8)" in by_addr[0x63D186B])
    check("size fallback jae 0x63d1bb5",
          "jae" in by_addr[0x63D1872] and "63d1bb5" in by_addr[0x63D1872])
    check("gate cmpb 0x1 r14",
          "cmpb" in by_addr[0x63D1878] and "$0x0,0x1(%r14)" in by_addr[0x63D1878])
    check("gate jg second-handler block 0x63d1c62",
          "jg" in by_addr[0x63D187D] and "63d1c62" in by_addr[0x63D187D])
    check("resolver input mov 0x88 r14 r13",
          "mov" in by_addr[0x63D1883] and "0x88(%r14),%r13" in by_addr[0x63D1883])
    check("resolver input null je 0x63d1c8e",
          "je" in by_addr[0x63D188D] and "63d1c8e" in by_addr[0x63D188D])
    # First bsr arm (rsi > 0x3800).
    check("bsr arm cmp 0x4000",
          "cmp" in by_addr[0x63D1BE0] and "$0x4000,%rsi" in by_addr[0x63D1BE0])
    check("bsr arm jbe 0x63d185e",
          "jbe" in by_addr[0x63D1BE7] and "63d185e" in by_addr[0x63D1BE7])
    check("bsr arm movabs 0x7000",
          "movabs" in by_addr[0x63D1BED]
          and "$0x7000000000000000,%rdx" in by_addr[0x63D1BED])
    check("bsr arm cmp rsi rdx",
          "cmp" in by_addr[0x63D1BF7] and "%rsi,%rdx" in by_addr[0x63D1BF7])
    check("bsr arm jb 0x63d1bb5",
          "jb" in by_addr[0x63D1BFA] and "63d1bb5" in by_addr[0x63D1BFA])
    check("bsr arm lea rdi",
          "lea" in by_addr[0x63D1BFC]
          and "-0x1(%rsi,%rsi,1),%rdi" in by_addr[0x63D1BFC])
    check("bsr arm mov 7 r9d",
          "mov" in by_addr[0x63D1C01] and "$0x7,%r9d" in by_addr[0x63D1C01])
    check("bsr arm mov 1 r10d",
          "mov" in by_addr[0x63D1C07] and "$0x1,%r10d" in by_addr[0x63D1C07])
    check("bsr arm lea r12",
          "lea" in by_addr[0x63D1C22]
          and "-0x1(%rsi,%r10,1),%r12" in by_addr[0x63D1C22])
    check("bsr arm neg r10",
          "neg" in by_addr[0x63D1C27] and "%r10" in by_addr[0x63D1C27])
    check("bsr arm and r10 r12",
          "and" in by_addr[0x63D1C2A] and "%r10,%r12" in by_addr[0x63D1C2A])
    check("bsr arm cmp rsi r12",
          "cmp" in by_addr[0x63D1C2D] and "%rsi,%r12" in by_addr[0x63D1C2D])
    check("bsr arm jb 0x63d1bb5",
          "jb" in by_addr[0x63D1C30] and "63d1bb5" in by_addr[0x63D1C30])
    check("bsr arm lea 0x6728140 r11",
          "lea" in by_addr[0x63D1C32] and "6728140" in by_addr[0x63D1C32])
    check("bsr arm mov r12 r13",
          "mov" in by_addr[0x63D1C39] and "%r12,%r13" in by_addr[0x63D1C39])
    check("bsr arm add table r13",
          "add" in by_addr[0x63D1C3C] and "(%r11),%r13" in by_addr[0x63D1C3C])
    check("bsr arm jb 0x63d1bb5",
          "jb" in by_addr[0x63D1C3F] and "63d1bb5" in by_addr[0x63D1C3F])
    check("gate rejoin movabs 0x6fff",
          "movabs" in by_addr[0x63D1C45]
          and "$0x6fffffffffffffff,%r10" in by_addr[0x63D1C45])
    check("gate rejoin lea -1 r12 r9",
          "lea" in by_addr[0x63D1C4F] and "-0x1(%r12),%r9" in by_addr[0x63D1C4F])
    check("gate rejoin cmp r9 r10",
          "cmp" in by_addr[0x63D1C54] and "%r9,%r10" in by_addr[0x63D1C54])
    check("gate rejoin jae 0x63d1878",
          "jae" in by_addr[0x63D1C57] and "63d1878" in by_addr[0x63D1C57])
    check("gate rejoin jmp 0x63d1bb5",
          "jmp" in by_addr[0x63D1C5D] and "63d1bb5" in by_addr[0x63D1C5D])
    # Second bsr arm (rsi > 0x1000).
    check("bsr2 arm lea r15",
          "lea" in by_addr[0x63D1EBE]
          and "-0x1(%rsi,%rsi,1),%r15" in by_addr[0x63D1EBE])
    check("bsr2 mov 1 edx",
          "mov" in by_addr[0x63D1EC3] and "$0x1,%edx" in by_addr[0x63D1EC3])
    check("bsr2 lea -3 rax ecx",
          "lea" in by_addr[0x63D1ECC] and "-0x3(%rax),%ecx" in by_addr[0x63D1ECC])
    check("bsr2 shl cl rdx",
          "shl" in by_addr[0x63D1ECF] and "%cl,%rdx" in by_addr[0x63D1ECF])
    check("bsr2 lea r12",
          "lea" in by_addr[0x63D1ED2]
          and "-0x1(%rsi,%rdx,1),%r12" in by_addr[0x63D1ED2])
    check("bsr2 jmp 0x63d1878",
          "jmp" in by_addr[0x63D1EDD] and "63d1878" in by_addr[0x63D1EDD])

    # Resolver call + walk A head.
    check("resolver xor r9d",
          "xor" in by_addr[0x63D1893] and "%r9d,%r9d" in by_addr[0x63D1893])
    check("resolver mov 1 r8d",
          "mov" in by_addr[0x63D1896] and "$0x1,%r8d" in by_addr[0x63D1896])
    check("resolver mov r12 rdx",
          "mov" in by_addr[0x63D189C] and "%r12,%rdx" in by_addr[0x63D189C])
    check("resolver mov r13 rsi",
          "mov" in by_addr[0x63D189F] and "%r13,%rsi" in by_addr[0x63D189F])
    check("resolver mov 0x40 ecx",
          "mov" in by_addr[0x63D18A2] and "$0x40,%ecx" in by_addr[0x63D18A2])
    check("resolver mov r14 rdi",
          "mov" in by_addr[0x63D18A7] and "%r14,%rdi" in by_addr[0x63D18A7])
    check("resolver return mov rax rbp",
          "mov" in by_addr[0x63D18AF] and "%rax,%rbp" in by_addr[0x63D18AF])
    check("resolver null je 0x63d1bb5",
          "je" in by_addr[0x63D18B5] and "63d1bb5" in by_addr[0x63D18B5])
    check("walkA mov rax r15",
          "mov" in by_addr[0x63D18BB] and "%rax,%r15" in by_addr[0x63D18BB])
    check("walkA mov rax r13",
          "mov" in by_addr[0x63D18BE] and "%rax,%r13" in by_addr[0x63D18BE])
    check("walkA table lea 0x1b0 r14 r12",
          "lea" in by_addr[0x63D18C1] and "0x1b0(%r14),%r12" in by_addr[0x63D18C1])
    check("walkA shr 0x1a r15",
          "shr" in by_addr[0x63D18C8] and "$0x1a,%r15" in by_addr[0x63D18C8])
    check("walkA high bits and r13",
          "and" in by_addr[0x63D18CC]
          and "$0xffffffffc0000000,%r13" in by_addr[0x63D18CC])
    check("walkA table store 0x18 rsp",
          "mov" in by_addr[0x63D18D3] and "%r12,0x18(%rsp)" in by_addr[0x63D18D3])
    check("walkA top index and f0",
          "and" in by_addr[0x63D18D8] and "$0xf0,%r15d" in by_addr[0x63D18D8])
    check("walkA top load 0x1b0 r15 rdx",
          "mov" in by_addr[0x63D18E2] and "0x1b0(%r15),%rdx" in by_addr[0x63D18E2])
    check("walkA top cmp rdx r13",
          "cmp" in by_addr[0x63D18E9] and "%rdx,%r13" in by_addr[0x63D18E9])
    check("walkA top jne scan A1 0x63d1d2c",
          "jne" in by_addr[0x63D18EC] and "63d1d2c" in by_addr[0x63D18EC])
    check("walkA extract1 shr 0x9 rax",
          "shr" in by_addr[0x63D18F2] and "$0x9,%rax" in by_addr[0x63D18F2])
    check("walkA extract1 size table load r12",
          "mov" in by_addr[0x63D1910]
          and "(%r12,%rax,8),%r12" in by_addr[0x63D1910])
    check("walkA extract1 second cmp jne A2",
          "jne" in by_addr[0x63D1917] and "63d1cdf" in by_addr[0x63D1917])
    check("walkA extract2 mov rbp rax",
          "mov" in by_addr[0x63D191D] and "%rbp,%rax" in by_addr[0x63D191D])
    check("walkA extract2 node table lea 0x65096c0",
          "lea" in by_addr[0x63D1933] and "65096c0" in by_addr[0x63D1933])
    check("walkA extract2 shl 0x10 r15",
          "shl" in by_addr[0x63D193A] and "$0x10,%r15" in by_addr[0x63D193A])
    check("walkA extract2 sar 0x10 r15",
          "sar" in by_addr[0x63D193E] and "$0x10,%r15" in by_addr[0x63D193E])

    # Element loop + walk B head.
    check("elem mov 0x28 rbx r15",
          "mov" in by_addr[0x63D1959] and "0x28(%rbx),%r15" in by_addr[0x63D1959])
    check("elem mov 0x8 rbx r13",
          "mov" in by_addr[0x63D195D] and "0x8(%rbx),%r13" in by_addr[0x63D195D])
    check("elem mov rbp 0x28 rbx",
          "mov" in by_addr[0x63D1961] and "%rbp,0x28(%rbx)" in by_addr[0x63D1961])
    check("elem walkB key save 0x8 rsp",
          "mov" in by_addr[0x63D1969] and "%r15,0x8(%rsp)" in by_addr[0x63D1969])
    check("elem sub 1 ebp",
          "sub" in by_addr[0x63D196E] and "$0x1,%ebp" in by_addr[0x63D196E])
    check("elem movq 0 0x8 rbx",
          "movq" in by_addr[0x63D1971] and "$0x0,0x8(%rbx)" in by_addr[0x63D1971])
    check("elem test r13",
          "test" in by_addr[0x63D197C] and "%r13,%r13" in by_addr[0x63D197C])
    check("elem je 0x63d19cb",
          "je" in by_addr[0x63D197F] and "63d19cb" in by_addr[0x63D197F])
    check("elem call 0x63d0080",
          "call" in by_addr[0x63D19B1] and "63d0080" in by_addr[0x63D19B1])
    check("elem test al jne 0x63d1ac8",
          "jne" in by_addr[0x63D19B8] and "63d1ac8" in by_addr[0x63D19B8])
    check("walkB key mov 0x8 rsp rax",
          "mov" in by_addr[0x63D19CB] and "0x8(%rsp),%rax" in by_addr[0x63D19CB])
    check("walkB key mov rax rbx",
          "mov" in by_addr[0x63D19D0] and "%rax,%rbx" in by_addr[0x63D19D0])
    check("walkB key mov rax r15",
          "mov" in by_addr[0x63D19D3] and "%rax,%r15" in by_addr[0x63D19D3])
    check("walkB top cmp rdx r15",
          "cmp" in by_addr[0x63D19F1] and "%rdx,%r15" in by_addr[0x63D19F1])
    check("walkB top jne scan B1 0x63d2025",
          "jne" in by_addr[0x63D19F4] and "63d2025" in by_addr[0x63D19F4])
    check("walkB extract1 second cmp jne B3",
          "jne" in by_addr[0x63D1A1F] and "63d2076" in by_addr[0x63D1A1F])
    check("walkB extract2 shl 0x10 rbp",
          "shl" in by_addr[0x63D1A44] and "$0x10,%rbp" in by_addr[0x63D1A44])
    check("walkB leaf mov 0x1b0 rbx r13",
          "mov" in by_addr[0x63D1A62] and "0x1b0(%rbx),%r13" in by_addr[0x63D1A62])
    check("walkB leaf cmp r13 r15",
          "cmp" in by_addr[0x63D1A69] and "%r13,%r15" in by_addr[0x63D1A69])
    check("walkB leaf jne scan B2 0x63d2131",
          "jne" in by_addr[0x63D1A6C] and "63d2131" in by_addr[0x63D1A6C])
    check("walkB leaf test 1 bpl",
          "test" in by_addr[0x63D1A8A] and "$0x1,%bpl" in by_addr[0x63D1A8A])
    check("walkB leaf je 0x63d20c5",
          "je" in by_addr[0x63D1A8E] and "63d20c5" in by_addr[0x63D1A8E])
    check("tail1 canary check sub fs:0x28",
          "sub" in by_addr[0x63D1A99] and "%fs:0x28,%rax" in by_addr[0x63D1A99])
    check("tail1 rsi mov 0x8 rsp",
          "mov" in by_addr[0x63D1AA8] and "0x8(%rsp),%rsi" in by_addr[0x63D1AA8])
    check("tail1 rdi mov r14",
          "mov" in by_addr[0x63D1AB1] and "%r14,%rdi" in by_addr[0x63D1AB1])

    # Walk C head + tail / exit.
    check("walkC key mov 0x28 rbx r10",
          "mov" in by_addr[0x63D1AC8] and "0x28(%rbx),%r10" in by_addr[0x63D1AC8])
    check("walkC key mov r10 r12",
          "mov" in by_addr[0x63D1AD0] and "%r10,%r12" in by_addr[0x63D1AD0])
    check("walkC key mov r10 r11",
          "mov" in by_addr[0x63D1AD3] and "%r10,%r11" in by_addr[0x63D1AD3])
    check("walkC top cmp rdx r11",
          "cmp" in by_addr[0x63D1AF3] and "%rdx,%r11" in by_addr[0x63D1AF3])
    check("walkC top jne scan C1 0x63d1e6b",
          "jne" in by_addr[0x63D1AF6] and "63d1e6b" in by_addr[0x63D1AF6])
    check("walkC extract1 second cmp jne C2",
          "jne" in by_addr[0x63D1B25] and "63d1e1b" in by_addr[0x63D1B25])
    check("walkC extract2 node table lea 0x65096c0",
          "lea" in by_addr[0x63D1B42] and "65096c0" in by_addr[0x63D1B42])
    check("walkC leaf mov 0x1b0 r12 rbp",
          "mov" in by_addr[0x63D1B68] and "0x1b0(%r12),%rbp" in by_addr[0x63D1B68])
    check("walkC leaf cmp rbp r11",
          "cmp" in by_addr[0x63D1B70] and "%rbp,%r11" in by_addr[0x63D1B70])
    check("walkC leaf jne scan C3 0x63d1dcb",
          "jne" in by_addr[0x63D1B73] and "63d1dcb" in by_addr[0x63D1B73])
    check("walkC leaf test 1 al",
          "test" in by_addr[0x63D1B90] and "$0x1,%al" in by_addr[0x63D1B90])
    check("walkC leaf je 0x63d1d7c",
          "je" in by_addr[0x63D1B92] and "63d1d7c" in by_addr[0x63D1B92])
    check("walkC leaf call 0x63637f0 at 0x63d1b9e",
          "call" in by_addr[0x63D1B9E] and "63637f0" in by_addr[0x63D1B9E])
    check("walkC tail mov 0x8 rsp r14",
          "mov" in by_addr[0x63D1BA3] and "0x8(%rsp),%r14" in by_addr[0x63D1BA3])
    check("walkC tail mov 0x14 rsp r12d",
          "mov" in by_addr[0x63D1BA8] and "0x14(%rsp),%r12d" in by_addr[0x63D1BA8])
    check("exit canary jne stack_chk_fail",
          "jne" in by_addr[0x63D1BC3] and "63d2a4c" in by_addr[0x63D1BC3])
    check("exit add 0x58 rsp",
          "add" in by_addr[0x63D1BC9] and "$0x58,%rsp" in by_addr[0x63D1BC9])
    # Walk-B deep arm + tail jump 2.
    check("deepB shr 0x30 rbp",
          "shr" in by_addr[0x63D20C5] and "$0x30,%rbp" in by_addr[0x63D20C5])
    check("deepB cmp 0x23 rbp",
          "cmp" in by_addr[0x63D20C9] and "$0x23,%rbp" in by_addr[0x63D20C9])
    check("deepB jbe 0x63d241f",
          "jbe" in by_addr[0x63D20CD] and "63d241f" in by_addr[0x63D20CD])
    check("deepB extract mov 0x8 rsp rax",
          "mov" in by_addr[0x63D20E3] and "0x8(%rsp),%rax" in by_addr[0x63D20E3])
    check("deepB rsi mov rax deref",
          "mov" in by_addr[0x63D20F8] and "(%rax),%rsi" in by_addr[0x63D20F8])
    check("tail2 canary check sub fs:0x28",
          "sub" in by_addr[0x63D2100] and "%fs:0x28,%rax" in by_addr[0x63D2100])
    check("tail2 rdi mov r14",
          "mov" in by_addr[0x63D2117] and "%r14,%rdi" in by_addr[0x63D2117])
    check("tail2 rsi shl 0x10",
          "shl" in by_addr[0x63D210F] and "$0x10,%rsi" in by_addr[0x63D210F])
    check("tail2 rsi sar 0x10",
          "sar" in by_addr[0x63D211A] and "$0x10,%rsi" in by_addr[0x63D211A])
    # Walk-C deep arm + call 0x63bd6c0 / call 0x6363260.
    check("deepC shr 0x30 rax",
          "shr" in by_addr[0x63D1D7C] and "$0x30,%rax" in by_addr[0x63D1D7C])
    check("deepC cmp 0x23 rax",
          "cmp" in by_addr[0x63D1D80] and "$0x23,%rax" in by_addr[0x63D1D80])
    check("deepC jbe 0x63d1ee2",
          "jbe" in by_addr[0x63D1D84] and "63d1ee2" in by_addr[0x63D1D84])
    check("deepC extract mov r10 rax",
          "mov" in by_addr[0x63D1D9B] and "%r10,%rax" in by_addr[0x63D1D9B])
    check("deepC rsi mov rax deref",
          "mov" in by_addr[0x63D1DAF] and "(%rax),%rsi" in by_addr[0x63D1DAF])
    check("deepC call 0x63bd6c0",
          "call" in by_addr[0x63D1DC1] and "63bd6c0" in by_addr[0x63D1DC1])
    check("deepC jmp 0x63d1ba3",
          "jmp" in by_addr[0x63D1DC6] and "63d1ba3" in by_addr[0x63D1DC6])
    check("deepC arm mov 1 ecx",
          "mov" in by_addr[0x63D1EE2] and "$0x1,%ecx" in by_addr[0x63D1EE2])
    check("deepC arm xor edx",
          "xor" in by_addr[0x63D1EE7] and "%edx,%edx" in by_addr[0x63D1EE7])
    check("deepC arm mov r10 rsi",
          "mov" in by_addr[0x63D1EE9] and "%r10,%rsi" in by_addr[0x63D1EE9])
    check("deepC arm mov r14 rdi",
          "mov" in by_addr[0x63D1EEC] and "%r14,%rdi" in by_addr[0x63D1EEC])
    check("deepC arm jmp 0x63d1ba3",
          "jmp" in by_addr[0x63D1EF4] and "63d1ba3" in by_addr[0x63D1EF4])
    # Tail jump 3 arm (jbe from deepB).
    check("tail3 canary check sub fs:0x28",
          "sub" in by_addr[0x63D2424] and "%fs:0x28,%rax" in by_addr[0x63D2424])
    check("tail3 rsi mov 0x8 rsp",
          "mov" in by_addr[0x63D2433] and "0x8(%rsp),%rsi" in by_addr[0x63D2433])
    check("tail3 rdi mov r14",
          "mov" in by_addr[0x63D243C] and "%r14,%rdi" in by_addr[0x63D243C])
    check("tail3 xor edx",
          "xor" in by_addr[0x63D243F] and "%edx,%edx" in by_addr[0x63D243F])
    check("tail3 mov 1 ecx",
          "mov" in by_addr[0x63D2442] and "$0x1,%ecx" in by_addr[0x63D2442])

    # Second-handler block.
    check("sh block lea node table 0x65096c0",
          "lea" in by_addr[0x63D1C62] and "65096c0" in by_addr[0x63D1C62])
    check("sh block mov node table r13",
          "mov" in by_addr[0x63D1C69] and "(%r15),%r13" in by_addr[0x63D1C69])
    check("sh block test r13",
          "test" in by_addr[0x63D1C6C] and "%r13,%r13" in by_addr[0x63D1C6C])
    check("sh block nonnull jne 0x63d1893",
          "jne" in by_addr[0x63D1C6F] and "63d1893" in by_addr[0x63D1C6F])
    check("sh block lea 0x64da4b0 rdx",
          "lea" in by_addr[0x63D1C75] and "64da4b0" in by_addr[0x63D1C75])
    check("sh block xor esi",
          "xor" in by_addr[0x63D1C7C] and "%esi,%esi" in by_addr[0x63D1C7C])
    check("sh block mov r14 rdi",
          "mov" in by_addr[0x63D1C7E] and "%r14,%rdi" in by_addr[0x63D1C7E])
    check("sh block return mov rax r13",
          "mov" in by_addr[0x63D1C86] and "%rax,%r13" in by_addr[0x63D1C86])
    check("sh block jmp 0x63d1893",
          "jmp" in by_addr[0x63D1C89] and "63d1893" in by_addr[0x63D1C89])
    # Null-resolver-input arm.
    check("null arm mov 1 esi",
          "mov" in by_addr[0x63D1C8E] and "$0x1,%esi" in by_addr[0x63D1C8E])
    check("null arm mov r14 rdi",
          "mov" in by_addr[0x63D1C93] and "%r14,%rdi" in by_addr[0x63D1C93])
    check("null arm cmpb 0 r14",
          "cmpb" in by_addr[0x63D1C9B] and "$0x0,(%r14)" in by_addr[0x63D1C9B])
    check("null arm mov rax r13",
          "mov" in by_addr[0x63D1C9F] and "%rax,%r13" in by_addr[0x63D1C9F])
    check("null arm je 0x63d1893",
          "je" in by_addr[0x63D1CA2] and "63d1893" in by_addr[0x63D1CA2])
    check("null arm mov 0x128 r14 r11",
          "mov" in by_addr[0x63D1CA8] and "0x128(%r14),%r11" in by_addr[0x63D1CA8])
    check("null arm lea 0x100 r14 rsi",
          "lea" in by_addr[0x63D1CAF] and "0x100(%r14),%rsi" in by_addr[0x63D1CAF])
    check("null arm lea 0x358 r14 rdx",
          "lea" in by_addr[0x63D1CB6] and "0x358(%r14),%rdx" in by_addr[0x63D1CB6])
    check("null arm test r11",
          "test" in by_addr[0x63D1CBD] and "%r11,%r11" in by_addr[0x63D1CBD])
    check("null arm je 0x63d2180",
          "je" in by_addr[0x63D1CC0] and "63d2180" in by_addr[0x63D1CC0])
    check("null arm mov rax rcx",
          "mov" in by_addr[0x63D2180] and "%rax,%rcx" in by_addr[0x63D2180])
    check("null arm jmp 0x63d1893",
          "jmp" in by_addr[0x63D218B] and "63d1893" in by_addr[0x63D218B])

    # Scans: ten 8-slot MTF scans, 68 slot compares, 17 reversed.
    # Slot set 0x2b0..0x320 in r14; reversed means the register comes
    # first (e.g. cmp %r11,0x2b0(%r14)); memory-first is NORMAL.
    slot_cmps = {
        0x63D1CDF: "0x2b0(%r14),%r13",
        0x63D1D2C: "0x2b0(%r14),%r13",
        0x63D1DCB: "0x2b0(%r14),%r11",
        0x63D1E1B: "0x2b0(%r14),%r11",
        0x63D1E6B: "0x2b0(%r14),%r11",
        0x63D1EFE: "%r11,0x2c0(%r14)",
        0x63D1F62: "%r11,0x2c0(%r14)",
        0x63D1FC7: "%r11,0x2c0(%r14)",
        0x63D2025: "0x2b0(%r14),%r15",
        0x63D2076: "0x2b0(%r14),%r15",
        0x63D2131: "0x2b0(%r14),%r15",
        0x63D2195: "0x2c0(%r14),%r13",
        0x63D21F7: "0x2c0(%r14),%r13",
        0x63D2254: "0x2b0(%r14),%r11",
        0x63D22A7: "0x2c0(%r14),%r15",
        0x63D230C: "0x2c0(%r14),%r15",
        0x63D2371: "%r15,0x2c0(%r14)",
        0x63D23D0: "0x2b0(%r14),%r15",
        0x63D245A: "0x2d0(%r14),%r13",
        0x63D246C: "%r13,0x2e0(%r14)",
        0x63D247E: "0x2f0(%r14),%r13",
        0x63D2490: "0x300(%r14),%r13",
        0x63D24A2: "%r13,0x310(%r14)",
        0x63D24AF: "0x320(%r14),%r13",
        0x63D24C7: "0x2d0(%r14),%r13",
        0x63D24D9: "0x2e0(%r14),%r13",
        0x63D24EB: "0x2f0(%r14),%r13",
        0x63D24FD: "0x300(%r14),%r13",
        0x63D250F: "0x310(%r14),%r13",
        0x63D251C: "0x320(%r14),%r13",
        0x63D2584: "%r11,0x2d0(%r14)",
        0x63D2596: "0x2e0(%r14),%r11",
        0x63D25A8: "0x2f0(%r14),%r11",
        0x63D25BA: "0x300(%r14),%r11",
        0x63D25CC: "0x310(%r14),%r11",
        0x63D25D9: "0x320(%r14),%r11",
        0x63D25F5: "%r11,0x2d0(%r14)",
        0x63D2607: "0x2e0(%r14),%r11",
        0x63D2619: "%r11,0x2f0(%r14)",
        0x63D262B: "%r11,0x300(%r14)",
        0x63D263D: "0x310(%r14),%r11",
        0x63D264A: "0x320(%r14),%r11",
        0x63D2666: "%r11,0x2d0(%r14)",
        0x63D2678: "0x2e0(%r14),%r11",
        0x63D268A: "0x2f0(%r14),%r11",
        0x63D269C: "%r11,0x300(%r14)",
        0x63D26AE: "0x310(%r14),%r11",
        0x63D26BB: "0x320(%r14),%r11",
        0x63D278A: "%r15,0x2d0(%r14)",
        0x63D279C: "0x2e0(%r14),%r15",
        0x63D27AE: "0x2f0(%r14),%r15",
        0x63D27C0: "0x300(%r14),%r15",
        0x63D27D2: "0x310(%r14),%r15",
        0x63D27DF: "0x320(%r14),%r15",
        0x63D27FF: "0x2b0(%r14,%rcx,1),%r15",
        0x63D28B6: "0x2d0(%r14),%r15",
        0x63D28C9: "0x2e0(%r14),%r15",
        0x63D28DC: "0x2f0(%r14),%r15",
        0x63D28EF: "0x300(%r14),%r15",
        0x63D2902: "0x310(%r14),%r15",
        0x63D290F: "0x320(%r14),%r15",
        0x63D2929: "0x2d0(%r14),%r15",
        0x63D293C: "%r15,0x2e0(%r14)",
        0x63D294F: "%r15,0x2f0(%r14)",
        0x63D2962: "%r15,0x300(%r14)",
        0x63D2975: "%r15,0x310(%r14)",
        0x63D2982: "0x320(%r14),%r15",
        0x63D29F7: "0x2b0(%r14,%r9,1),%r11",
    }
    check("slot compares 68", len(slot_cmps) == 68, str(len(slot_cmps)))
    for a, op in slot_cmps.items():
        check("slot compare %s" % hex(a),
              "cmp" in by_addr[a] and op in by_addr[a], by_addr[a])
    check("reversed-operand compares 17",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%")) ==
          [0x63D1EFE, 0x63D1F62, 0x63D1FC7, 0x63D2371, 0x63D246C, 0x63D24A2, 0x63D2584, 0x63D25F5, 0x63D2619, 0x63D262B, 0x63D2666, 0x63D269C, 0x63D278A, 0x63D293C, 0x63D294F, 0x63D2962, 0x63D2975],
          str(sorted(a for a, op in slot_cmps.items()
                     if op.startswith("%"))))
    check("reversed count via objdump",
          sum(1 for a in slot_cmps
              if re.search(r"\bcmp\s+%", by_addr[a])) == 17)
    check("slot positions 80 = 68 instr + 6 D1 loop + 6 D2 loop",
          68 + 6 + 6 == 80)
    check("scan A1 slot-0 0x63d1d2c key r13",
          "cmp" in by_addr[0x63D1D2C] and "0x2b0(%r14),%r13" in by_addr[0x63D1D2C])
    check("scan A2 slot-0 0x63d1cdf key r13",
          "cmp" in by_addr[0x63D1CDF] and "0x2b0(%r14),%r13" in by_addr[0x63D1CDF])
    check("scan B1 slot-0 0x63d2025 key r15",
          "cmp" in by_addr[0x63D2025] and "0x2b0(%r14),%r15" in by_addr[0x63D2025])
    check("scan B2 slot-0 0x63d2131 key r15",
          "cmp" in by_addr[0x63D2131] and "0x2b0(%r14),%r15" in by_addr[0x63D2131])
    check("scan B3 slot-0 0x63d2076 key r15",
          "cmp" in by_addr[0x63D2076] and "0x2b0(%r14),%r15" in by_addr[0x63D2076])
    check("scan C1 slot-0 0x63d1e6b key r11",
          "cmp" in by_addr[0x63D1E6B] and "0x2b0(%r14),%r11" in by_addr[0x63D1E6B])
    check("scan C2 slot-0 0x63d1e1b key r11",
          "cmp" in by_addr[0x63D1E1B] and "0x2b0(%r14),%r11" in by_addr[0x63D1E1B])
    check("scan C3 slot-0 0x63d1dcb key r11",
          "cmp" in by_addr[0x63D1DCB] and "0x2b0(%r14),%r11" in by_addr[0x63D1DCB])
    check("scan D1 slot-0 0x63d23d0 key r15",
          "cmp" in by_addr[0x63D23D0] and "0x2b0(%r14),%r15" in by_addr[0x63D23D0])
    check("scan D2 slot-0 0x63d2254 key r11",
          "cmp" in by_addr[0x63D2254] and "0x2b0(%r14),%r11" in by_addr[0x63D2254])
    # Slot-7 exhaustion branches land on the miss-site setup blocks.
    check("scan A1 slot-7 jne to miss 1 setup 0x63d2530",
          "jne" in by_addr[0x63D24B6] and "63d2530" in by_addr[0x63D24B6])
    check("scan A2 slot-7 jne to miss 2 setup 0x63d255a",
          "jne" in by_addr[0x63D2523] and "63d255a" in by_addr[0x63D2523])
    check("scan C1 slot-7 jne to miss 3 setup 0x63d26d2",
          "jne" in by_addr[0x63D25E0] and "63d26d2" in by_addr[0x63D25E0])
    check("scan C2 slot-7 jne to miss 4 setup 0x63d2713",
          "jne" in by_addr[0x63D2651] and "63d2713" in by_addr[0x63D2651])
    check("scan C3 slot-7 jne to miss 5 setup 0x63d274c",
          "jne" in by_addr[0x63D26C2] and "63d274c" in by_addr[0x63D26C2])
    check("scan B3 slot-7 jne to miss 6 setup 0x63d2854",
          "jne" in by_addr[0x63D27E6] and "63d2854" in by_addr[0x63D27E6])
    check("scan B1 slot-7 jne to miss 8 setup 0x63d2996",
          "jne" in by_addr[0x63D2916] and "63d2996" in by_addr[0x63D2916])
    check("scan B2 slot-7 jne to miss 9 setup 0x63d29c4",
          "jne" in by_addr[0x63D2989] and "63d29c4" in by_addr[0x63D2989])
    # Counter-loop scans D1 (r13d) and D2 (rcx).
    check("D1 counter init mov 1 r13d",
          "mov" in by_addr[0x63D27F2] and "$0x1,%r13d" in by_addr[0x63D27F2])
    check("D1 loop cmp 0x63d27ff",
          "cmp" in by_addr[0x63D27FF]
          and "0x2b0(%r14,%rcx,1),%r15" in by_addr[0x63D27FF])
    check("D1 loop mismatch jne 0x63d287b",
          "jne" in by_addr[0x63D2807] and "63d287b" in by_addr[0x63D2807])
    check("D1 exhaustion falls to miss 7 setup 0x63d2889",
          "mov" in by_addr[0x63D2889]
          and "0x8(%rsp),%rcx" in by_addr[0x63D2889])
    check("D2 counter init mov 1 ecx",
          "mov" in by_addr[0x63D29EB] and "$0x1,%ecx" in by_addr[0x63D29EB])
    check("D2 loop cmp 0x63d29f7",
          "cmp" in by_addr[0x63D29F7]
          and "0x2b0(%r14,%r9,1),%r11" in by_addr[0x63D29F7])
    check("D2 loop mismatch jne 0x63d2a51",
          "jne" in by_addr[0x63D29FF] and "63d2a51" in by_addr[0x63D29FF])
    check("D2 exhaustion falls to miss 10 setup 0x63d2a5b",
          "mov" in by_addr[0x63D2A5B]
          and "0x18(%rsp),%rdx" in by_addr[0x63D2A5B])
    # Reversed slots per scan (register-first).
    check("A1 reversed slots 3,6",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%") and a in
                 [0x63D1D2C, 0x63D21F7, 0x63D245A, 0x63D246C, 0x63D247E,
                  0x63D2490, 0x63D24A2, 0x63D24AF]) == [0x63D246C, 0x63D24A2])
    check("B2 reversed slots 3,4,5,6",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%") and a in
                 [0x63D2131, 0x63D22A7, 0x63D2929, 0x63D293C, 0x63D294F,
                  0x63D2962, 0x63D2975, 0x63D2982]) ==
          [0x63D293C, 0x63D294F, 0x63D2962, 0x63D2975])
    check("B3 reversed slots 1,2",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%") and a in
                 [0x63D2076, 0x63D2371, 0x63D278A, 0x63D279C, 0x63D27AE,
                  0x63D27C0, 0x63D27D2, 0x63D27DF]) == [0x63D2371, 0x63D278A])
    check("C1 reversed slots 1,2",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%") and a in
                 [0x63D1E6B, 0x63D1FC7, 0x63D2584, 0x63D2596, 0x63D25A8,
                  0x63D25BA, 0x63D25CC, 0x63D25D9]) == [0x63D1FC7, 0x63D2584])
    check("C2 reversed slots 1,2,4,5",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%") and a in
                 [0x63D1E1B, 0x63D1EFE, 0x63D25F5, 0x63D2607, 0x63D2619,
                  0x63D262B, 0x63D263D, 0x63D264A]) ==
          [0x63D1EFE, 0x63D25F5, 0x63D2619, 0x63D262B])
    check("C3 reversed slots 1,2,5",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%") and a in
                 [0x63D1DCB, 0x63D1F62, 0x63D2666, 0x63D2678, 0x63D268A,
                  0x63D269C, 0x63D26AE, 0x63D26BB]) ==
          [0x63D1F62, 0x63D2666, 0x63D269C])
    check("A2/B1/D1/D2 reversed none",
          sorted(a for a, op in slot_cmps.items()
                 if op.startswith("%") and a in
                 [0x63D1CDF, 0x63D2195, 0x63D24C7, 0x63D24D9, 0x63D24EB,
                  0x63D24FD, 0x63D250F, 0x63D251C, 0x63D2025, 0x63D230C,
                  0x63D28B6, 0x63D28C9, 0x63D28DC, 0x63D28EF, 0x63D2902,
                  0x63D290F, 0x63D23D0, 0x63D27FF, 0x63D2254,
                  0x63D29F7]) == [])

    # Miss site 1 at 0x63d2549 (rcx = rax, resolver return;
    # rdx = walk table via r12, lea 0x1b0(%r14) at 0x63d18c1).
    check("miss 1 lea 0x6511a00 rsi", "lea" in by_addr[0x63D2530]
          and "6511a00" in by_addr[0x63D2530], by_addr[0x63D2530])
    check("miss 1 mov r12 rdx", "mov" in by_addr[0x63D2537]
          and "%r12,%rdx" in by_addr[0x63D2537], by_addr[0x63D2537])
    check("miss 1 xor r9d", "xor" in by_addr[0x63D253A]
          and "%r9d,%r9d" in by_addr[0x63D253A], by_addr[0x63D253A])
    check("miss 1 mov rax rcx", "mov" in by_addr[0x63D253D]
          and "%rax,%rcx" in by_addr[0x63D253D], by_addr[0x63D253D])
    check("miss 1 mov 1 r8d", "mov" in by_addr[0x63D2540]
          and "$0x1,%r8d" in by_addr[0x63D2540], by_addr[0x63D2540])
    check("miss 1 mov r14 rdi", "mov" in by_addr[0x63D2546]
          and "%r14,%rdi" in by_addr[0x63D2546], by_addr[0x63D2546])
    check("miss 1 call 0x63d9700", "call" in by_addr[0x63D2549]
          and "63d9700" in by_addr[0x63D2549], by_addr[0x63D2549])
    check("miss 1 post-call rdx reload", "mov" in by_addr[0x63D254E]
          and "0x1b0(%r15),%rdx" in by_addr[0x63D254E], by_addr[0x63D254E])
    check("miss 1 rejoin jmp 0x63d1902", "jmp" in by_addr[0x63D2555]
          and "63d1902" in by_addr[0x63D2555], by_addr[0x63D2555])
    # Miss site 2 at 0x63d2575 (rcx = rbp).
    check("miss 2 rdx mov 0x18 rsp", "mov" in by_addr[0x63D255A]
          and "0x18(%rsp),%rdx" in by_addr[0x63D255A], by_addr[0x63D255A])
    check("miss 2 xor r9d", "xor" in by_addr[0x63D255F]
          and "%r9d,%r9d" in by_addr[0x63D255F], by_addr[0x63D255F])
    check("miss 2 mov rbp rcx", "mov" in by_addr[0x63D2562]
          and "%rbp,%rcx" in by_addr[0x63D2562], by_addr[0x63D2562])
    check("miss 2 mov r14 rdi", "mov" in by_addr[0x63D2565]
          and "%r14,%rdi" in by_addr[0x63D2565], by_addr[0x63D2565])
    check("miss 2 lea 0x6511a00 rsi", "lea" in by_addr[0x63D2568]
          and "6511a00" in by_addr[0x63D2568], by_addr[0x63D2568])
    check("miss 2 mov 1 r8d", "mov" in by_addr[0x63D256F]
          and "$0x1,%r8d" in by_addr[0x63D256F], by_addr[0x63D256F])
    check("miss 2 call 0x63d9700", "call" in by_addr[0x63D2575]
          and "63d9700" in by_addr[0x63D2575], by_addr[0x63D2575])
    check("miss 2 rejoin jmp 0x63d1930", "jmp" in by_addr[0x63D257A]
          and "63d1930" in by_addr[0x63D257A], by_addr[0x63D257A])
    # Miss site 3 at 0x63d26f7 (rcx = r10; saves r11/r10 on stack).
    check("miss 3 rdx mov 0x18 rsp", "mov" in by_addr[0x63D26D2]
          and "0x18(%rsp),%rdx" in by_addr[0x63D26D2], by_addr[0x63D26D2])
    check("miss 3 mov r10 rcx", "mov" in by_addr[0x63D26D7]
          and "%r10,%rcx" in by_addr[0x63D26D7], by_addr[0x63D26D7])
    check("miss 3 xor r9d", "xor" in by_addr[0x63D26DA]
          and "%r9d,%r9d" in by_addr[0x63D26DA], by_addr[0x63D26DA])
    check("miss 3 mov r14 rdi", "mov" in by_addr[0x63D26DD]
          and "%r14,%rdi" in by_addr[0x63D26DD], by_addr[0x63D26DD])
    check("miss 3 lea 0x6511a00 rsi", "lea" in by_addr[0x63D26E0]
          and "6511a00" in by_addr[0x63D26E0], by_addr[0x63D26E0])
    check("miss 3 mov 1 r8d", "mov" in by_addr[0x63D26E7]
          and "$0x1,%r8d" in by_addr[0x63D26E7], by_addr[0x63D26E7])
    check("miss 3 save r11 0x28 rsp", "mov" in by_addr[0x63D26ED]
          and "%r11,0x28(%rsp)" in by_addr[0x63D26ED], by_addr[0x63D26ED])
    check("miss 3 save r10 0x20 rsp", "mov" in by_addr[0x63D26F2]
          and "%r10,0x20(%rsp)" in by_addr[0x63D26F2], by_addr[0x63D26F2])
    check("miss 3 call 0x63d9700", "call" in by_addr[0x63D26F7]
          and "63d9700" in by_addr[0x63D26F7], by_addr[0x63D26F7])
    check("miss 3 restore r11", "mov" in by_addr[0x63D26FC]
          and "0x28(%rsp),%r11" in by_addr[0x63D26FC], by_addr[0x63D26FC])
    check("miss 3 restore r10", "mov" in by_addr[0x63D2701]
          and "0x20(%rsp),%r10" in by_addr[0x63D2701], by_addr[0x63D2701])
    check("miss 3 rejoin mov 0x1b0 r12 rdx", "mov" in by_addr[0x63D2706]
          and "0x1b0(%r12),%rdx" in by_addr[0x63D2706], by_addr[0x63D2706])
    check("miss 3 rejoin jmp 0x63d1b10", "jmp" in by_addr[0x63D270E]
          and "63d1b10" in by_addr[0x63D270E], by_addr[0x63D270E])
    # Miss site 4 at 0x63d2738 (rcx = r10; saves r11/r10 on stack).
    check("miss 4 rdx mov 0x18 rsp", "mov" in by_addr[0x63D2713]
          and "0x18(%rsp),%rdx" in by_addr[0x63D2713], by_addr[0x63D2713])
    check("miss 4 mov r10 rcx", "mov" in by_addr[0x63D2718]
          and "%r10,%rcx" in by_addr[0x63D2718], by_addr[0x63D2718])
    check("miss 4 xor r9d", "xor" in by_addr[0x63D271B]
          and "%r9d,%r9d" in by_addr[0x63D271B], by_addr[0x63D271B])
    check("miss 4 mov r14 rdi", "mov" in by_addr[0x63D271E]
          and "%r14,%rdi" in by_addr[0x63D271E], by_addr[0x63D271E])
    check("miss 4 lea 0x6511a00 rsi", "lea" in by_addr[0x63D2721]
          and "6511a00" in by_addr[0x63D2721], by_addr[0x63D2721])
    check("miss 4 mov 1 r8d", "mov" in by_addr[0x63D2728]
          and "$0x1,%r8d" in by_addr[0x63D2728], by_addr[0x63D2728])
    check("miss 4 save r11 0x28 rsp", "mov" in by_addr[0x63D272E]
          and "%r11,0x28(%rsp)" in by_addr[0x63D272E], by_addr[0x63D272E])
    check("miss 4 save r10 0x20 rsp", "mov" in by_addr[0x63D2733]
          and "%r10,0x20(%rsp)" in by_addr[0x63D2733], by_addr[0x63D2733])
    check("miss 4 call 0x63d9700", "call" in by_addr[0x63D2738]
          and "63d9700" in by_addr[0x63D2738], by_addr[0x63D2738])
    check("miss 4 restore r11", "mov" in by_addr[0x63D273D]
          and "0x28(%rsp),%r11" in by_addr[0x63D273D], by_addr[0x63D273D])
    check("miss 4 restore r10", "mov" in by_addr[0x63D2742]
          and "0x20(%rsp),%r10" in by_addr[0x63D2742], by_addr[0x63D2742])
    check("miss 4 rejoin jmp 0x63d1b3f", "jmp" in by_addr[0x63D2747]
          and "63d1b3f" in by_addr[0x63D2747], by_addr[0x63D2747])
    # Miss site 5 at 0x63d2771 (rcx = r10; saves r11/r10 on stack).
    check("miss 5 rdx mov 0x18 rsp", "mov" in by_addr[0x63D274C]
          and "0x18(%rsp),%rdx" in by_addr[0x63D274C], by_addr[0x63D274C])
    check("miss 5 mov r10 rcx", "mov" in by_addr[0x63D2751]
          and "%r10,%rcx" in by_addr[0x63D2751], by_addr[0x63D2751])
    check("miss 5 xor r9d", "xor" in by_addr[0x63D2754]
          and "%r9d,%r9d" in by_addr[0x63D2754], by_addr[0x63D2754])
    check("miss 5 mov r14 rdi", "mov" in by_addr[0x63D2757]
          and "%r14,%rdi" in by_addr[0x63D2757], by_addr[0x63D2757])
    check("miss 5 lea 0x6511a00 rsi", "lea" in by_addr[0x63D275A]
          and "6511a00" in by_addr[0x63D275A], by_addr[0x63D275A])
    check("miss 5 mov 1 r8d", "mov" in by_addr[0x63D2761]
          and "$0x1,%r8d" in by_addr[0x63D2761], by_addr[0x63D2761])
    check("miss 5 save r11 0x28 rsp", "mov" in by_addr[0x63D2767]
          and "%r11,0x28(%rsp)" in by_addr[0x63D2767], by_addr[0x63D2767])
    check("miss 5 save r10 0x20 rsp", "mov" in by_addr[0x63D276C]
          and "%r10,0x20(%rsp)" in by_addr[0x63D276C], by_addr[0x63D276C])
    check("miss 5 call 0x63d9700", "call" in by_addr[0x63D2771]
          and "63d9700" in by_addr[0x63D2771], by_addr[0x63D2771])
    check("miss 5 restore r11", "mov" in by_addr[0x63D2776]
          and "0x28(%rsp),%r11" in by_addr[0x63D2776], by_addr[0x63D2776])
    check("miss 5 restore r10", "mov" in by_addr[0x63D277B]
          and "0x20(%rsp),%r10" in by_addr[0x63D277B], by_addr[0x63D277B])
    check("miss 5 rejoin jmp 0x63d1b8d", "jmp" in by_addr[0x63D2780]
          and "63d1b8d" in by_addr[0x63D2780], by_addr[0x63D2780])
    # Miss site 6 at 0x63d2871 (rcx = 0x8(%rsp), walk-B key).
    check("miss 6 rcx mov 0x8 rsp", "mov" in by_addr[0x63D2854]
          and "0x8(%rsp),%rcx" in by_addr[0x63D2854], by_addr[0x63D2854])
    check("miss 6 rdx mov 0x18 rsp", "mov" in by_addr[0x63D2859]
          and "0x18(%rsp),%rdx" in by_addr[0x63D2859], by_addr[0x63D2859])
    check("miss 6 xor r9d", "xor" in by_addr[0x63D285E]
          and "%r9d,%r9d" in by_addr[0x63D285E], by_addr[0x63D285E])
    check("miss 6 mov r14 rdi", "mov" in by_addr[0x63D2861]
          and "%r14,%rdi" in by_addr[0x63D2861], by_addr[0x63D2861])
    check("miss 6 lea 0x6511a00 rsi", "lea" in by_addr[0x63D2864]
          and "6511a00" in by_addr[0x63D2864], by_addr[0x63D2864])
    check("miss 6 mov 1 r8d", "mov" in by_addr[0x63D286B]
          and "$0x1,%r8d" in by_addr[0x63D286B], by_addr[0x63D286B])
    check("miss 6 call 0x63d9700", "call" in by_addr[0x63D2871]
          and "63d9700" in by_addr[0x63D2871], by_addr[0x63D2871])
    check("miss 6 rejoin jmp 0x63d1a3a", "jmp" in by_addr[0x63D2876]
          and "63d1a3a" in by_addr[0x63D2876], by_addr[0x63D2876])
    # Miss site 7 at 0x63d28a6 (rcx = 0x8(%rsp), walk-B key).
    check("miss 7 rcx mov 0x8 rsp", "mov" in by_addr[0x63D2889]
          and "0x8(%rsp),%rcx" in by_addr[0x63D2889], by_addr[0x63D2889])
    check("miss 7 rdx mov 0x18 rsp", "mov" in by_addr[0x63D288E]
          and "0x18(%rsp),%rdx" in by_addr[0x63D288E], by_addr[0x63D288E])
    check("miss 7 xor r9d", "xor" in by_addr[0x63D2893]
          and "%r9d,%r9d" in by_addr[0x63D2893], by_addr[0x63D2893])
    check("miss 7 mov r14 rdi", "mov" in by_addr[0x63D2896]
          and "%r14,%rdi" in by_addr[0x63D2896], by_addr[0x63D2896])
    check("miss 7 lea 0x6511a00 rsi", "lea" in by_addr[0x63D2899]
          and "6511a00" in by_addr[0x63D2899], by_addr[0x63D2899])
    check("miss 7 mov 1 r8d", "mov" in by_addr[0x63D28A0]
          and "$0x1,%r8d" in by_addr[0x63D28A0], by_addr[0x63D28A0])
    check("miss 7 call 0x63d9700", "call" in by_addr[0x63D28A6]
          and "63d9700" in by_addr[0x63D28A6], by_addr[0x63D28A6])
    check("miss 7 rejoin jmp 0x63d20f8", "jmp" in by_addr[0x63D28AB]
          and "63d20f8" in by_addr[0x63D28AB], by_addr[0x63D28AB])
    # Miss site 8 at 0x63d29b3 (rcx = 0x8(%rsp), walk-B key).
    check("miss 8 rdx mov 0x18 rsp", "mov" in by_addr[0x63D2996]
          and "0x18(%rsp),%rdx" in by_addr[0x63D2996], by_addr[0x63D2996])
    check("miss 8 rcx mov 0x8 rsp", "mov" in by_addr[0x63D299B]
          and "0x8(%rsp),%rcx" in by_addr[0x63D299B], by_addr[0x63D299B])
    check("miss 8 xor r9d", "xor" in by_addr[0x63D29A0]
          and "%r9d,%r9d" in by_addr[0x63D29A0], by_addr[0x63D29A0])
    check("miss 8 mov r14 rdi", "mov" in by_addr[0x63D29A3]
          and "%r14,%rdi" in by_addr[0x63D29A3], by_addr[0x63D29A3])
    check("miss 8 lea 0x6511a00 rsi", "lea" in by_addr[0x63D29A6]
          and "6511a00" in by_addr[0x63D29A6], by_addr[0x63D29A6])
    check("miss 8 mov 1 r8d", "mov" in by_addr[0x63D29AD]
          and "$0x1,%r8d" in by_addr[0x63D29AD], by_addr[0x63D29AD])
    check("miss 8 call 0x63d9700", "call" in by_addr[0x63D29B3]
          and "63d9700" in by_addr[0x63D29B3], by_addr[0x63D29B3])
    check("miss 8 rejoin mov 0x1b0 rbx rdx", "mov" in by_addr[0x63D29B8]
          and "0x1b0(%rbx),%rdx" in by_addr[0x63D29B8], by_addr[0x63D29B8])
    check("miss 8 rejoin jmp 0x63d1a0a", "jmp" in by_addr[0x63D29BF]
          and "63d1a0a" in by_addr[0x63D29BF], by_addr[0x63D29BF])
    # Miss site 9 at 0x63d29e1 (rcx = 0x8(%rsp), walk-B key).
    check("miss 9 rcx mov 0x8 rsp", "mov" in by_addr[0x63D29C4]
          and "0x8(%rsp),%rcx" in by_addr[0x63D29C4], by_addr[0x63D29C4])
    check("miss 9 rdx mov 0x18 rsp", "mov" in by_addr[0x63D29C9]
          and "0x18(%rsp),%rdx" in by_addr[0x63D29C9], by_addr[0x63D29C9])
    check("miss 9 xor r9d", "xor" in by_addr[0x63D29CE]
          and "%r9d,%r9d" in by_addr[0x63D29CE], by_addr[0x63D29CE])
    check("miss 9 mov r14 rdi", "mov" in by_addr[0x63D29D1]
          and "%r14,%rdi" in by_addr[0x63D29D1], by_addr[0x63D29D1])
    check("miss 9 lea 0x6511a00 rsi", "lea" in by_addr[0x63D29D4]
          and "6511a00" in by_addr[0x63D29D4], by_addr[0x63D29D4])
    check("miss 9 mov 1 r8d", "mov" in by_addr[0x63D29DB]
          and "$0x1,%r8d" in by_addr[0x63D29DB], by_addr[0x63D29DB])
    check("miss 9 call 0x63d9700", "call" in by_addr[0x63D29E1]
          and "63d9700" in by_addr[0x63D29E1], by_addr[0x63D29E1])
    check("miss 9 rejoin jmp 0x63d1a87", "jmp" in by_addr[0x63D29E6]
          and "63d1a87" in by_addr[0x63D29E6], by_addr[0x63D29E6])
    # Miss site 10 at 0x63d2a76 (rcx = r10).
    check("miss 10 rdx mov 0x18 rsp", "mov" in by_addr[0x63D2A5B]
          and "0x18(%rsp),%rdx" in by_addr[0x63D2A5B], by_addr[0x63D2A5B])
    check("miss 10 xor r9d", "xor" in by_addr[0x63D2A60]
          and "%r9d,%r9d" in by_addr[0x63D2A60], by_addr[0x63D2A60])
    check("miss 10 mov r10 rcx", "mov" in by_addr[0x63D2A63]
          and "%r10,%rcx" in by_addr[0x63D2A63], by_addr[0x63D2A63])
    check("miss 10 mov r14 rdi", "mov" in by_addr[0x63D2A66]
          and "%r14,%rdi" in by_addr[0x63D2A66], by_addr[0x63D2A66])
    check("miss 10 lea 0x6511a00 rsi", "lea" in by_addr[0x63D2A69]
          and "6511a00" in by_addr[0x63D2A69], by_addr[0x63D2A69])
    check("miss 10 mov 1 r8d", "mov" in by_addr[0x63D2A70]
          and "$0x1,%r8d" in by_addr[0x63D2A70], by_addr[0x63D2A70])
    check("miss 10 call 0x63d9700", "call" in by_addr[0x63D2A76]
          and "63d9700" in by_addr[0x63D2A76], by_addr[0x63D2A76])
    check("miss 10 rejoin jmp 0x63d1daf", "jmp" in by_addr[0x63D2A7B]
          and "63d1daf" in by_addr[0x63D2A7B], by_addr[0x63D2A7B])

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

    for _s in [0x63D2549, 0x63D2575, 0x63D26F7, 0x63D2738, 0x63D2771,
               0x63D2871, 0x63D28A6, 0x63D29B3, 0x63D29E1, 0x63D2A76]:
        check("entry reaches lu-miss site %s" % hex(_s), reaches(START, _s))
    check("entry reaches ret 0x63d1bd7", reaches(START, 0x63D1BD7))

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

    SITES = [0x63D2549, 0x63D2575, 0x63D26F7, 0x63D2738, 0x63D2771,
             0x63D2871, 0x63D28A6, 0x63D29B3, 0x63D29E1, 0x63D2A76]
    RCX = {0x63D2549: 0x63D253D, 0x63D2575: 0x63D2562, 0x63D26F7: 0x63D26D7,
           0x63D2738: 0x63D2718, 0x63D2771: 0x63D2751, 0x63D2871: 0x63D2854,
           0x63D28A6: 0x63D2889, 0x63D29B3: 0x63D299B, 0x63D29E1: 0x63D29C4,
           0x63D2A76: 0x63D2A63}
    RDI = {0x63D2549: 0x63D2546, 0x63D2575: 0x63D2565, 0x63D26F7: 0x63D26DD,
           0x63D2738: 0x63D271E, 0x63D2771: 0x63D2757, 0x63D2871: 0x63D2861,
           0x63D28A6: 0x63D2896, 0x63D29B3: 0x63D29A3, 0x63D29E1: 0x63D29D1,
           0x63D2A76: 0x63D2A66}
    RSI = {0x63D2549: 0x63D2530, 0x63D2575: 0x63D2568, 0x63D26F7: 0x63D26E0,
           0x63D2738: 0x63D2721, 0x63D2771: 0x63D275A, 0x63D2871: 0x63D2864,
           0x63D28A6: 0x63D2899, 0x63D29B3: 0x63D29A6, 0x63D29E1: 0x63D29D4,
           0x63D2A76: 0x63D2A69}
    RDX = {0x63D2549: 0x63D2537, 0x63D2575: 0x63D255A, 0x63D26F7: 0x63D26D2,
           0x63D2738: 0x63D2713, 0x63D2771: 0x63D274C, 0x63D2871: 0x63D2859,
           0x63D28A6: 0x63D288E, 0x63D29B3: 0x63D2996, 0x63D29E1: 0x63D29C9,
           0x63D2A76: 0x63D2A5B}
    R8 = {0x63D2549: 0x63D2540, 0x63D2575: 0x63D256F, 0x63D26F7: 0x63D26E7,
          0x63D2738: 0x63D2728, 0x63D2771: 0x63D2761, 0x63D2871: 0x63D286B,
          0x63D28A6: 0x63D28A0, 0x63D29B3: 0x63D29AD, 0x63D29E1: 0x63D29DB,
          0x63D2A76: 0x63D2A70}
    R9 = {0x63D2549: 0x63D253A, 0x63D2575: 0x63D255F, 0x63D26F7: 0x63D26DA,
          0x63D2738: 0x63D271B, 0x63D2771: 0x63D2754, 0x63D2871: 0x63D285E,
          0x63D28A6: 0x63D2893, 0x63D29B3: 0x63D29A0, 0x63D29E1: 0x63D29CE,
          0x63D2A76: 0x63D2A60}
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
    r14_in = reaching_defs("r14")
    for s in SITES:
        check("r14 at %s only def is entry mov rdi r14 0x63d17e4" % hex(s),
              r14_in[s] == {0x63D17E4}, str(r14_in[s]))
    # Walk-key provenance: sites 1, 2 = walk-A key (resolver return);
    # sites 3, 4, 5, 10 = r10 walk-C key (restores from 0x20(%rsp) in
    # sites 3/4/5 join in at later sites); sites 6, 7, 8, 9 take the
    # walk-B key from the stack slot 0x8(%rsp), stored once at
    # 0x63d1969 from the element loop's mov 0x28(%rbx),%r15.
    R10 = {0x63D26F7: {0x63D1AC8},
           0x63D2738: {0x63D1AC8, 0x63D2701},
           0x63D2771: {0x63D1AC8, 0x63D2701, 0x63D2742},
           0x63D2A76: {0x63D1AC8, 0x63D2701, 0x63D2742, 0x63D277B}}
    r10_in = reaching_defs("r10")
    for s, want in R10.items():
        check("r10 at %s" % hex(s), r10_in[s] == want, str(r10_in[s]))
    r12_in = reaching_defs("r12")
    check("r12 at site 1 is walk-table lea 0x63d18c1",
          r12_in[0x63D2549] == {0x63D18C1}, str(r12_in[0x63D2549]))
    rax_in = reaching_defs("rax")
    check("rax at site 1 is resolver call 0x63d18aa",
          rax_in[0x63D2549] == {("CALL", 0x63D18AA)},
          str(rax_in[0x63D2549]))
    rbp_in = reaching_defs("rbp")
    check("rbp at site 2 is mov rax rbp 0x63d18af",
          rbp_in[0x63D2575] == {0x63D18AF}, str(rbp_in[0x63D2575]))
    r15_in = reaching_defs("r15")
    check("r15 at walk-B key store 0x63d1969 is mov 0x28 rbx 0x63d1959",
          r15_in[0x63D1969] == {0x63D1959}, str(r15_in[0x63D1969]))
    check("rax at ret is canary sub 0x63d1bba only (uniform 0 exit)",
          rax_in[0x63D1BD7] == {0x63D1BBA}, str(rax_in[0x63D1BD7]))
    check("rax at tail jump 1 is canary sub 0x63d1a99",
          rax_in[0x63D1ABE] == {0x63D1A99}, str(rax_in[0x63D1ABE]))
    check("rax at tail jump 2 is canary sub 0x63d2100",
          rax_in[0x63D212C] == {0x63D2100}, str(rax_in[0x63D212C]))
    check("rax at tail jump 3 is canary sub 0x63d2424",
          rax_in[0x63D2450] == {0x63D2424}, str(rax_in[0x63D2450]))
    rcx3 = reaching_defs("rcx")
    check("rcx at tail jump 3 is mov 1 ecx 0x63d2442",
          rcx3[0x63D2450] == {0x63D2442}, str(rcx3[0x63D2450]))
    rdx3 = reaching_defs("rdx")
    check("rdx at tail jump 3 is xor edx 0x63d243f",
          rdx3[0x63D2450] == {0x63D243F}, str(rdx3[0x63D2450]))

    check("records lu-miss sites match census",
          [s.get("site") for s in rec.get("lu_miss_sites", [])] ==
          ["0x63d2549", "0x63d2575", "0x63d26f7", "0x63d2738", "0x63d2771",
           "0x63d2871", "0x63d28a6", "0x63d29b3", "0x63d29e1", "0x63d2a76"])
    check("records second-handler sites 1",
          [s.get("site") for s in rec.get("second_handler_sites", [])] ==
          ["0x63d1c81"])
    check("records scan slot compares 68",
          rec.get("scan", {}).get("slot_compares_total") == 68)
    check("records scan reversed 17",
          rec.get("scan", {}).get("reversed_operand_compares") == 17)
    check("records scan reversed sites match",
          rec.get("scan", {}).get("reversed_sites") ==
          sorted(["0x63d1efe", "0x63d1f62", "0x63d1fc7", "0x63d2371", "0x63d246c", "0x63d24a2", "0x63d2584", "0x63d25f5", "0x63d2619", "0x63d262b", "0x63d2666", "0x63d269c", "0x63d278a", "0x63d293c", "0x63d294f", "0x63d2962", "0x63d2975"]))
    check("records scan positions 80",
          rec.get("scan", {}).get("slot_positions_total") == 80)
    check("records scan reversed positions 17",
          rec.get("scan", {}).get("reversed_positions") == 17)

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
    check("next candidate raw lu-miss 2", counts.get(0x63D2A80, 0) == 2,
          str(counts.get(0x63D2A80, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63D2A80, 0) == 0,
          str(bti_counts.get(0x63D2A80, 0)))
    check("next candidate raw second-handler 1",
          sh_counts.get(0x63D2A80, 0) == 1,
          str(sh_counts.get(0x63D2A80, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 12th survivor",
          survey.get("survivors", [None] * 12)[11] == "0x63d17e0",
          str(survey.get("survivors", [])[:13]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window IS shared",
          "0x63d17e0" in survey.get("shared_survivors", []))
    check("survey next candidate IS shared",
          "0x63d2a80" in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x63d2a80..0x63d3071",
          nq.get("range") == "0x63d2a80..0x63d3071", str(nq.get("range")))
    check("next question bytes 1521", nq.get("bytes") == 1521,
          str(nq.get("bytes")))
    check("next question lu-miss sites 2",
          nq.get("lu_miss_sites") == 2, str(nq.get("lu_miss_sites")))
    check("next question lu-miss site list",
          nq.get("lu_miss_site") == ["0x63d3036", "0x63d305b"],
          str(nq.get("lu_miss_site")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 313", nq.get("strict") == 313,
          str(nq.get("strict")))
    check("next question calls 7", nq.get("calls") == 7,
          str(nq.get("calls")))
    check("next question second-handler sites 1",
          nq.get("second_handler_sites") == 1,
          str(nq.get("second_handler_sites")))
    check("next question bsr 2", nq.get("bsr") == 2,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63d2c97"],
          str(nq.get("ret")))
    check("records census strict 928",
          rec.get("census", {}).get("strict") == 928)
    check("records census calls 20",
          rec.get("census", {}).get("calls") == 20)
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
    # next candidate 0x63d2a80..0x63d3071 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63D2A80 < p[1] and p[0] < 0x63D3071]
    check("next candidate 0x63d2a80 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63D3071 and 0x63D2A80 < END))

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
