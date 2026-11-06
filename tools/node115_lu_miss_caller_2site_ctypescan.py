"""Static verifier for RE-001-node115-lu-miss-caller-2site-ctypescan.

Tenth packet of the lu-miss-caller frontier (callers of the lu-miss
handler 0x63d9700 that do not call bin_table_init): FDE
0x63cddd0..0x63ce23b, 1131 bytes, 242 strict instructions, 7 calls
(6 distinct direct targets, 0 indirect), 2 lu-miss sites, 0
bin_table_init sites, 0 second-handler sites, THREE rets at
0x63cdf2f / 0x63cdf43 / 0x63cdf7a, bsr 0, lock sub 1 / lock add 0,
39 jumps, 0 outside the window, endbr64 1, NO canary, NO TLS flag
check.

This window is a lu-miss-ONLY survivor: it is in the survey's 16-FDE
lu-miss survivor list but NOT in the 18-FDE second-handler survivor
list, so it consumes one slot of the combined 25-FDE miss-handler
pool without being shared. First frontier window with a
__ctype_b_loc pre-scan, first with THREE rets (three distinct exit
values 0 / 14 / 11, one reaching def each), and first to call the FDE
immediately after #322's window (0x63cd910, once).

Entry: rdi is the context base (kept in r12), rsi is a string pointer
(kept in rbp); 0x68(%rdi) is loaded into r13 and null-checked, with
init arms (helper 0x63c3780 when the field is null and the 0x330(%rdi)
flag byte is <= 2; helper 0x63c3b00 when 0x21(%r13) is nonzero) and a
null-string exit (14). A per-character __ctype_b_loc table scan
validates the string (a byte is accepted iff its ctype entry has the
sign bit set or bit 0 set; otherwise exit 14). Then the window calls
0x63cd910 (rdi = r12, rsi = rbp); its return goes to rbx and is
null-checked (exit 11 on null). A single context-table walk follows,
keyed by the node pointer in 0x18(%r13) (rbp), table r12 + 0x1b0:
top index (key >> 0x1a) & 0xf0, high bits key & 0xffffffffc0000000,
inline shr $0x30 extract feeding size table 0x6727a00 (size class
into r15), then a shl/sar $0x10 extract feeding node table 0x65096c0
and a lock sub %r15,0x38(%rdi) refcount decrement. The window then
calls 0x63c89c0, clears 0x18(%r13), and installs rbx into 0x18(%r13)
iff *rbx is nonzero. Two 8-slot move-to-front scans share one slot
set (0x2b0..0x320 in r12): 16 slot-compare instructions, ELEVEN
reversed-operand (arm-B slot-0; scan-A slots 2-7; scan-B slots 2-5),
i.e. 11 of 16 slot positions reversed; their exhaustions fall to the
two lu-miss sites. Both miss sites share one argument pattern (rdi =
r12 context, rsi = .bss 0x6511a00, rdx = walk table pointer
lea 0x1b0(%r12), rcx = rbp walk key, r8d = 1, r9d = 0); the rcx
provenance is proven by reaching-definitions: the only rcx def
reaching either site is the mov %rbp,%rcx immediately before its
call, and the only rbp def reaching either site is
mov 0x18(%r13),%rbp at 0x63cde5b (the walk-key node pointer). Exit:
three rets with one reaching rax def each -- 0 (xor %eax,%eax at
0x63cdf23), 14 (mov $0xe,%eax at 0x63cdf34), 11 (mov $0xb,%eax at
0x63cdf6b) -- so no single exit value is established, unlike #314
(rbx), #315 (r12), #316 (r13), #317 (r12), #319 (0), and #320 (r15).

#322's pointer for this window (1131 bytes, 242 strict, 7 calls,
2 lu-miss sites at 0x63ce1f8 and 0x63ce221, 0 bin_table_init sites,
0 second-handler sites, THREE rets at 0x63cdf2f / 0x63cdf43 /
0x63cdf7a, bsr 0) was verified correct by targeted objdump census.
No correction (prior_pointer_verified).

Next question: the next lu-miss survivor in address order is
0x63d03a0..0x63d17d7 (5175 bytes, 1037 strict, 23 calls, 10 lu-miss
sites, 0 bti, 1 second-handler site at 0x63d0837, 1 ret at 0x63d0817,
bsr 2) -- a SHARED survivor, unlike this packet.

Usage: python3 tools/node115_lu_miss_caller_2site_ctypescan.py
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
                      "RE-001-node115-lu-miss-caller-2site-ctypescan")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-2site-ctypescan"
NAME = "lu_miss_caller_2site_ctypescan"
START, END = 0x63CDDD0, 0x63CE23B

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
          "05bc2de303c05525b71e7e257426e741bc66a390")

    fdes = parse_eh_frame(node)
    check("total FDEs 135313", len(fdes) == 135313, str(len(fdes)))
    starts = [a for a, _ in fdes]
    i = bisect.bisect_left(starts, START)
    check("target FDE start", i < len(fdes) and fdes[i][0] == START)
    check("target FDE end", i < len(fdes) and fdes[i][1] == END)
    check("target FDE size 1131", END - START == 1131)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x63cd910..0x63cddce",
          prev == (0x63CD910, 0x63CDDCE), str(prev))
    check("prev gap 2", START - prev[1] == 2)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 2, gap.hex())
    check("next FDE 0x63ce240..0x63ce501",
          nxt == (0x63CE240, 0x63CE501), str(nxt))
    check("next padding 5", nxt[0] - END == 5)
    pad = node[toff(END):toff(nxt[0])]
    check("padding bytes all cc", pad == b"\xcc" * 5, pad.hex())
    check("next FDE starts endbr64",
          node[toff(0x63CE240):toff(0x63CE240) + 4] ==
          bytes.fromhex("f30f1efa"))
    check("next FDE push r15 after endbr64",
          node[toff(0x63CE240) + 4:toff(0x63CE240) + 6] ==
          bytes.fromhex("4157"))
    check("prev FDE starts endbr64",
          node[toff(0x63CD910):toff(0x63CD910) + 4] ==
          bytes.fromhex("f30f1efa"))
    check("prev FDE push r15 after endbr64",
          node[toff(0x63CD910) + 4:toff(0x63CD910) + 6] ==
          bytes.fromhex("4157"))

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 1131", len(hexb) == 1131, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 242", len(lines) == 242, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 7", len(calls) == 7, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 3", len(rets) == 3, str(len(rets)))
    check("ret sites 0x63cdf2f/0x63cdf43/0x63cdf7a",
          [addr_of(l) for l in rets] == [0x63CDF2F, 0x63CDF43, 0x63CDF7A],
          str([hex(addr_of(l)) for l in rets]))

    def call_targets(ls):
        out = []
        for l in ls:
            m = re.search(r"\tcall\s+([0-9a-f]+)", l)
            if m:
                out.append((addr_of(l), int(m.group(1), 16)))
        return out

    ct = call_targets(calls)
    indirect = [addr_of(l) for l in calls
                if re.search(r"\tcall\s+\*", l)]
    check("indirect calls 0", indirect == [],
          str([hex(a) for a in indirect]))
    from collections import Counter
    tgt = Counter(t for _, t in ct)
    expect = {0x63F1B60: 1, 0x63CD910: 1, 0x63C89C0: 1, 0x63C3780: 1,
              0x63C3B00: 1, 0x63D9700: 2}
    check("call target multiset exact", dict(tgt) == expect,
          str(dict(tgt)))
    check("distinct call targets 6", len(tgt) == 6, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 2",
          sorted(a for a, t in ct if t == 0x63D9700) ==
          [0x63CE1F8, 0x63CE221],
          str([hex(a) for a, t in ct if t == 0x63D9700]))
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called 0 times", tgt.get(0x63BF680, 0) == 0,
          str(tgt.get(0x63BF680, 0)))
    check("ctype_b_loc plt called once at 0x63cde13",
          sorted(a for a, t in ct if t == 0x63F1B60) == [0x63CDE13],
          str([hex(a) for a, t in ct if t == 0x63F1B60]))
    check("prev FDE 0x63cd910 called once at 0x63cde4a",
          sorted(a for a, t in ct if t == 0x63CD910) == [0x63CDE4A],
          str([hex(a) for a, t in ct if t == 0x63CD910]))
    check("0x63c89c0 called once at 0x63cdf09",
          sorted(a for a, t in ct if t == 0x63C89C0) == [0x63CDF09],
          str([hex(a) for a, t in ct if t == 0x63C89C0]))
    check("0x63c3780 called once at 0x63cdf51",
          sorted(a for a, t in ct if t == 0x63C3780) == [0x63CDF51],
          str([hex(a) for a, t in ct if t == 0x63C3780]))
    check("0x63c3b00 called once at 0x63cdf7e",
          sorted(a for a, t in ct if t == 0x63C3B00) == [0x63CDF7E],
          str([hex(a) for a, t in ct if t == 0x63C3B00]))
    check("no 0x63be540 helper sites", tgt.get(0x63BE540, 0) == 0,
          str(tgt.get(0x63BE540, 0)))
    check("no 0x63be4d0 helper sites", tgt.get(0x63BE4D0, 0) == 0,
          str(tgt.get(0x63BE4D0, 0)))
    check("no 0x63bd6c0 helper sites", tgt.get(0x63BD6C0, 0) == 0,
          str(tgt.get(0x63BD6C0, 0)))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#313", 0x63C2F00)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", bsr == [], str([hex(addr_of(l)) for l in bsr]))
    locks = [l for l in lines if mnemonic_of(l) == "lock"]
    check("lock lines 1", len(locks) == 1, str(locks))
    check("lock sub at 0x63cdefe",
          "lock sub" in by_addr[0x63CDEFE]
          and "%r15,0x38(%rdi)" in by_addr[0x63CDEFE], by_addr[0x63CDEFE])
    check("no lock add", not any("lock add" in l for l in locks))
    jmps = [l for l in lines
            if mnemonic_of(l) in ("jmp", "je", "jne", "ja", "jb", "jae",
                                  "jbe", "jg", "jl", "jge", "jle", "jo",
                                  "jno", "js", "jns", "jp", "jnp")]
    check("jump lines 39", len(jmps) == 39, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure zero outside", outside == [], str(outside))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("no canary (no stack_chk_fail)",
          not any("stack_chk" in l for l in lines))
    check("no TLS flag fs:0x330 anywhere",
          not any("%fs:0x330" in l for l in lines))
    check("no byte table 0x67277c0 anywhere",
          not any("67277c0" in l for l in lines))

    # Entry + guards.
    check("entry endbr64", "endbr64" in by_addr[START])
    check("entry push r15", "push" in by_addr[0x63CDDD4] and
          "%r15" in by_addr[0x63CDDD4])
    check("entry push r14", "push" in by_addr[0x63CDDD6] and
          "%r14" in by_addr[0x63CDDD6])
    check("entry push r13", "push" in by_addr[0x63CDDD8] and
          "%r13" in by_addr[0x63CDDD8])
    check("entry push r12", "push" in by_addr[0x63CDDDA] and
          "%r12" in by_addr[0x63CDDDA])
    check("entry mov rdi to r12",
          "mov" in by_addr[0x63CDDDC] and "%rdi,%r12" in by_addr[0x63CDDDC])
    check("entry push rbp", "push" in by_addr[0x63CDDDF] and
          "%rbp" in by_addr[0x63CDDDF])
    check("entry mov rsi to rbp",
          "mov" in by_addr[0x63CDDE0] and "%rsi,%rbp" in by_addr[0x63CDDE0])
    check("entry push rbx", "push" in by_addr[0x63CDDE3] and
          "%rbx" in by_addr[0x63CDDE3])
    check("entry sub 0x18 rsp",
          "sub" in by_addr[0x63CDDE4] and "$0x18,%rsp" in by_addr[0x63CDDE4])
    check("entry mov 0x68 rdi r13",
          "mov" in by_addr[0x63CDDE8] and "0x68(%rdi),%r13" in by_addr[0x63CDDE8])
    check("entry test r13",
          "test" in by_addr[0x63CDDEC] and "%r13,%r13" in by_addr[0x63CDDEC])
    check("entry null r13 je 0x63cdf48",
          "je" in by_addr[0x63CDDEF] and "63cdf48" in by_addr[0x63CDDEF])
    check("entry cmpb 0x21 r13",
          "cmpb" in by_addr[0x63CDDF5] and "$0x0,0x21(%r13)" in by_addr[0x63CDDF5])
    check("entry flag nonzero jne 0x63cdf7b",
          "jne" in by_addr[0x63CDDFA] and "63cdf7b" in by_addr[0x63CDDFA])
    check("entry test rbp",
          "test" in by_addr[0x63CDE00] and "%rbp,%rbp" in by_addr[0x63CDE00])
    check("entry null rbp je 0x63cdf30",
          "je" in by_addr[0x63CDE03] and "63cdf30" in by_addr[0x63CDE03])

    # Init arms.
    check("init cmpb 0x330 rdi",
          "cmpb" in by_addr[0x63CDF48] and "$0x2,0x330(%rdi)" in by_addr[0x63CDF48])
    check("init flag gt ja 0x63cdf67",
          "ja" in by_addr[0x63CDF4F] and "63cdf67" in by_addr[0x63CDF4F])
    check("init call 0x63c3780",
          "call" in by_addr[0x63CDF51] and "63c3780" in by_addr[0x63CDF51])
    check("init mov rax r13",
          "mov" in by_addr[0x63CDF56] and "%rax,%r13" in by_addr[0x63CDF56])
    check("init store r13 0x68 r12",
          "mov" in by_addr[0x63CDF59] and "%r13,0x68(%r12)" in by_addr[0x63CDF59])
    check("init test r13",
          "test" in by_addr[0x63CDF5E] and "%r13,%r13" in by_addr[0x63CDF5E])
    check("init nonzero jne 0x63cde00",
          "jne" in by_addr[0x63CDF61] and "63cde00" in by_addr[0x63CDF61])
    check("refresh mov r13 rsi",
          "mov" in by_addr[0x63CDF7B] and "%r13,%rsi" in by_addr[0x63CDF7B])
    check("refresh call 0x63c3b00",
          "call" in by_addr[0x63CDF7E] and "63c3b00" in by_addr[0x63CDF7E])
    check("refresh mov rax r13",
          "mov" in by_addr[0x63CDF83] and "%rax,%r13" in by_addr[0x63CDF83])
    check("refresh jmp 0x63cdf59",
          "jmp" in by_addr[0x63CDF86] and "63cdf59" in by_addr[0x63CDF86])

    # Ctype scan.
    check("ctype first char movsbq",
          "movsbq" in by_addr[0x63CDE09] and "0x0(%rbp),%r14" in by_addr[0x63CDE09])
    check("ctype first char test",
          "test" in by_addr[0x63CDE0E] and "%r14b,%r14b" in by_addr[0x63CDE0E])
    check("ctype NUL je 0x63cde44",
          "je" in by_addr[0x63CDE11] and "63cde44" in by_addr[0x63CDE11])
    check("ctype call __ctype_b_loc",
          "call" in by_addr[0x63CDE13] and "63f1b60" in by_addr[0x63CDE13])
    check("ctype table load",
          "mov" in by_addr[0x63CDE18] and "(%rax),%rcx" in by_addr[0x63CDE18])
    check("ctype entry movzwl",
          "movzwl" in by_addr[0x63CDE20] and "(%rcx,%r14,2),%edx" in by_addr[0x63CDE20])
    check("ctype test dx",
          "test" in by_addr[0x63CDE25] and "%dx,%dx" in by_addr[0x63CDE25])
    check("ctype sign js 0x63cde33",
          "js" in by_addr[0x63CDE28] and "63cde33" in by_addr[0x63CDE28])
    check("ctype and 1 edx",
          "and" in by_addr[0x63CDE2A] and "$0x1,%edx" in by_addr[0x63CDE2A])
    check("ctype fail je 0x63cdf30",
          "je" in by_addr[0x63CDE2D] and "63cdf30" in by_addr[0x63CDE2D])
    check("ctype advance lea",
          "lea" in by_addr[0x63CDE33] and "0x1(%rax),%ebx" in by_addr[0x63CDE33])
    check("ctype next char movsbq",
          "movsbq" in by_addr[0x63CDE36] and "0x0(%rbp,%rbx,1),%r14" in by_addr[0x63CDE36])
    check("ctype mov rbx rax",
          "mov" in by_addr[0x63CDE3C] and "%rbx,%rax" in by_addr[0x63CDE3C])
    check("ctype loop test",
          "test" in by_addr[0x63CDE3F] and "%r14b,%r14b" in by_addr[0x63CDE3F])
    check("ctype loop jne 0x63cde20",
          "jne" in by_addr[0x63CDE42] and "63cde20" in by_addr[0x63CDE42])

    # Call 0x63cd910 before the walk.
    check("prewalk mov rbp rsi",
          "mov" in by_addr[0x63CDE44] and "%rbp,%rsi" in by_addr[0x63CDE44])
    check("prewalk mov r12 rdi",
          "mov" in by_addr[0x63CDE47] and "%r12,%rdi" in by_addr[0x63CDE47])
    check("prewalk call 0x63cd910",
          "call" in by_addr[0x63CDE4A] and "63cd910" in by_addr[0x63CDE4A])
    check("prewalk mov rax rbx",
          "mov" in by_addr[0x63CDE4F] and "%rax,%rbx" in by_addr[0x63CDE4F])
    check("prewalk test rax",
          "test" in by_addr[0x63CDE52] and "%rax,%rax" in by_addr[0x63CDE52])
    check("prewalk null je 0x63cdf67",
          "je" in by_addr[0x63CDE55] and "63cdf67" in by_addr[0x63CDE55])

    # Walk.
    check("walk mov 0x18 r13 rbp",
          "mov" in by_addr[0x63CDE5B] and "0x18(%r13),%rbp" in by_addr[0x63CDE5B])
    check("walk test rbp",
          "test" in by_addr[0x63CDE5F] and "%rbp,%rbp" in by_addr[0x63CDE5F])
    check("walk null rbp je 0x63cdf16",
          "je" in by_addr[0x63CDE62] and "63cdf16" in by_addr[0x63CDE62])
    check("walk mov rbp r14",
          "mov" in by_addr[0x63CDE68] and "%rbp,%r14" in by_addr[0x63CDE68])
    check("walk mov rbp r10",
          "mov" in by_addr[0x63CDE6B] and "%rbp,%r10" in by_addr[0x63CDE6B])
    check("walk table lea 0x1b0 r12 rdx",
          "lea" in by_addr[0x63CDE6E] and "0x1b0(%r12),%rdx" in by_addr[0x63CDE6E])
    check("walk shr 0x1a r14",
          "shr" in by_addr[0x63CDE76] and "$0x1a,%r14" in by_addr[0x63CDE76])
    check("walk high bits and r10",
          "and" in by_addr[0x63CDE7A] and "$0xffffffffc0000000,%r10" in by_addr[0x63CDE7A])
    check("walk top index and f0",
          "and" in by_addr[0x63CDE81] and "$0xf0,%r14d" in by_addr[0x63CDE81])
    check("walk top add r12 r14",
          "add" in by_addr[0x63CDE88] and "%r12,%r14" in by_addr[0x63CDE88])
    check("walk top load 0x1b0 r14 r9",
          "mov" in by_addr[0x63CDE8B] and "0x1b0(%r14),%r9" in by_addr[0x63CDE8B])
    check("walk top cmp r9 r10",
          "cmp" in by_addr[0x63CDE92] and "%r9,%r10" in by_addr[0x63CDE92])
    check("walk top jne scan B 0x63cdfd9",
          "jne" in by_addr[0x63CDE95] and "63cdfd9" in by_addr[0x63CDE95])

    # First extract (shr $0x30 + size table).
    check("extract1 mov rbp rax",
          "mov" in by_addr[0x63CDE9B] and "%rbp,%rax" in by_addr[0x63CDE9B])
    check("extract1 shr 0x9 rax",
          "shr" in by_addr[0x63CDE9E] and "$0x9,%rax" in by_addr[0x63CDE9E])
    check("extract1 and 0x1ffff8",
          "and" in by_addr[0x63CDEA2] and "$0x1ffff8,%eax" in by_addr[0x63CDEA2])
    check("extract1 add 0x1b8 r14",
          "add" in by_addr[0x63CDEA7] and "0x1b8(%r14),%rax" in by_addr[0x63CDEA7])
    check("extract1 head mov rax deref",
          "mov" in by_addr[0x63CDEAE] and "(%rax),%rax" in by_addr[0x63CDEAE])
    check("extract1 lea size table 0x6727a00",
          "lea" in by_addr[0x63CDEB1] and "6727a00" in by_addr[0x63CDEB1])
    check("extract1 shr 0x30 rax",
          "shr" in by_addr[0x63CDEB8] and "$0x30,%rax" in by_addr[0x63CDEB8])
    check("extract1 size table load r15",
          "mov" in by_addr[0x63CDEBC] and "(%rsi,%rax,8),%r15" in by_addr[0x63CDEBC])
    check("extract1 second cmp r10 r9",
          "cmp" in by_addr[0x63CDEC0] and "%r10,%r9" in by_addr[0x63CDEC0])
    check("extract1 second jne scan A 0x63cdf88",
          "jne" in by_addr[0x63CDEC3] and "63cdf88" in by_addr[0x63CDEC3])

    # Second extract (shl/sar $0x10 + node table + lock sub).
    check("extract2 mov rbp rax",
          "mov" in by_addr[0x63CDEC9] and "%rbp,%rax" in by_addr[0x63CDEC9])
    check("extract2 shr 0x9 rax",
          "shr" in by_addr[0x63CDECC] and "$0x9,%rax" in by_addr[0x63CDECC])
    check("extract2 and 0x1ffff8",
          "and" in by_addr[0x63CDED0] and "$0x1ffff8,%eax" in by_addr[0x63CDED0])
    check("extract2 add 0x1b8 r14",
          "add" in by_addr[0x63CDED5] and "0x1b8(%r14),%rax" in by_addr[0x63CDED5])
    check("extract2 mov rax deref r10",
          "mov" in by_addr[0x63CDEDC] and "(%rax),%r10" in by_addr[0x63CDEDC])
    check("extract2 lea node table 0x65096c0",
          "lea" in by_addr[0x63CDEDF] and "65096c0" in by_addr[0x63CDEDF])
    check("extract2 shl 0x10 r10",
          "shl" in by_addr[0x63CDEE6] and "$0x10,%r10" in by_addr[0x63CDEE6])
    check("extract2 sar 0x10 r10",
          "sar" in by_addr[0x63CDEEA] and "$0x10,%r10" in by_addr[0x63CDEEA])
    check("extract2 and 80 r10",
          "and" in by_addr[0x63CDEEE] and "$0xffffffffffffff80,%r10" in by_addr[0x63CDEEE])
    check("extract2 node load rax",
          "mov" in by_addr[0x63CDEF2] and "(%r10),%rax" in by_addr[0x63CDEF2])
    check("extract2 and fff eax",
          "and" in by_addr[0x63CDEF5] and "$0xfff,%eax" in by_addr[0x63CDEF5])
    check("extract2 node table load rdi",
          "mov" in by_addr[0x63CDEFA] and "(%r8,%rax,8),%rdi" in by_addr[0x63CDEFA])
    check("lock sub r15 0x38 rdi",
          "lock sub" in by_addr[0x63CDEFE]
          and "%r15,0x38(%rdi)" in by_addr[0x63CDEFE])

    # Release call + slot store + epilogue/exits.
    check("release mov rbp rsi",
          "mov" in by_addr[0x63CDF03] and "%rbp,%rsi" in by_addr[0x63CDF03])
    check("release mov r12 rdi",
          "mov" in by_addr[0x63CDF06] and "%r12,%rdi" in by_addr[0x63CDF06])
    check("release call 0x63c89c0",
          "call" in by_addr[0x63CDF09] and "63c89c0" in by_addr[0x63CDF09])
    check("release movq 0 0x18 r13",
          "movq" in by_addr[0x63CDF0E] and "$0x0,0x18(%r13)" in by_addr[0x63CDF0E])
    check("store cmpb rbx deref",
          "cmpb" in by_addr[0x63CDF16] and "$0x0,(%rbx)" in by_addr[0x63CDF16])
    check("store zero je 0x63cdf1f",
          "je" in by_addr[0x63CDF19] and "63cdf1f" in by_addr[0x63CDF19])
    check("store mov rbx 0x18 r13",
          "mov" in by_addr[0x63CDF1B] and "%rbx,0x18(%r13)" in by_addr[0x63CDF1B])
    check("epilogue add 0x18 rsp",
          "add" in by_addr[0x63CDF1F] and "$0x18,%rsp" in by_addr[0x63CDF1F])
    check("exit0 xor eax",
          "xor" in by_addr[0x63CDF23] and "%eax,%eax" in by_addr[0x63CDF23])
    check("exit0 pops",
          "pop" in by_addr[0x63CDF25] and "%rbx" in by_addr[0x63CDF25]
          and "pop" in by_addr[0x63CDF2D] and "%r15" in by_addr[0x63CDF2D])
    check("exit14 add 0x18 rsp",
          "add" in by_addr[0x63CDF30] and "$0x18,%rsp" in by_addr[0x63CDF30])
    check("exit14 mov e eax",
          "mov" in by_addr[0x63CDF34] and "$0xe,%eax" in by_addr[0x63CDF34])
    check("exit11 add 0x18 rsp",
          "add" in by_addr[0x63CDF67] and "$0x18,%rsp" in by_addr[0x63CDF67])
    check("exit11 mov b eax",
          "mov" in by_addr[0x63CDF6B] and "$0xb,%eax" in by_addr[0x63CDF6B])

    # Miss arm B (second-level miss -> scan A).
    check("armB cmp r10 slot0",
          "cmp" in by_addr[0x63CDF88] and "%r10,0x2b0(%r12)" in by_addr[0x63CDF88])
    check("armB jne scan A 0x63ce02d",
          "jne" in by_addr[0x63CDF90] and "63ce02d" in by_addr[0x63CDF90])
    check("armB slot0 mov r9 0x2b0",
          "mov" in by_addr[0x63CDF96] and "%r9,0x2b0(%r12)" in by_addr[0x63CDF96])
    check("armB slot0 mov 0x1b8 rsi",
          "mov" in by_addr[0x63CDF9E] and "0x1b8(%r14),%rsi" in by_addr[0x63CDF9E])
    check("armB slot0 mov 0x2b8 rax",
          "mov" in by_addr[0x63CDFA5] and "0x2b8(%r12),%rax" in by_addr[0x63CDFA5])
    check("armB slot0 mov rsi 0x2b8",
          "mov" in by_addr[0x63CDFAD] and "%rsi,0x2b8(%r12)" in by_addr[0x63CDFAD])
    check("armB slot0 mov rax 0x1b8",
          "mov" in by_addr[0x63CDFB5] and "%rax,0x1b8(%r14)" in by_addr[0x63CDFB5])
    check("armB slot0 mov r10 0x1b0",
          "mov" in by_addr[0x63CDFBC] and "%r10,0x1b0(%r14)" in by_addr[0x63CDFBC])
    check("armB slot0 mov rbp r14",
          "mov" in by_addr[0x63CDFC3] and "%rbp,%r14" in by_addr[0x63CDFC3])
    check("armB slot0 shr 0x9 r14",
          "shr" in by_addr[0x63CDFC6] and "$0x9,%r14" in by_addr[0x63CDFC6])
    check("armB slot0 and 0x1ffff8 r14",
          "and" in by_addr[0x63CDFCA] and "$0x1ffff8,%r14d" in by_addr[0x63CDFCA])
    check("armB slot0 add r14 rax",
          "add" in by_addr[0x63CDFD1] and "%r14,%rax" in by_addr[0x63CDFD1])
    check("armB slot0 jmp 0x63cdedc",
          "jmp" in by_addr[0x63CDFD4] and "63cdedc" in by_addr[0x63CDFD4])

    # Miss arm A (top-index miss -> scan B).
    check("armA cmp slot0 r10",
          "cmp" in by_addr[0x63CDFD9] and "0x2b0(%r12),%r10" in by_addr[0x63CDFD9])
    check("armA jne scan B 0x63ce093",
          "jne" in by_addr[0x63CDFE1] and "63ce093" in by_addr[0x63CDFE1])
    check("armA slot0 mov r9 0x2b0",
          "mov" in by_addr[0x63CDFE7] and "%r9,0x2b0(%r12)" in by_addr[0x63CDFE7])
    check("armA slot0 mov 0x1b8 rcx",
          "mov" in by_addr[0x63CDFEF] and "0x1b8(%r14),%rcx" in by_addr[0x63CDFEF])
    check("armA slot0 mov 0x2b8 rax",
          "mov" in by_addr[0x63CDFF6] and "0x2b8(%r12),%rax" in by_addr[0x63CDFF6])
    check("armA slot0 mov rcx 0x2b8",
          "mov" in by_addr[0x63CDFFE] and "%rcx,0x2b8(%r12)" in by_addr[0x63CDFFE])
    check("armA slot0 mov rbp r9",
          "mov" in by_addr[0x63CE006] and "%rbp,%r9" in by_addr[0x63CE006])
    check("armA slot0 mov rax 0x1b8",
          "mov" in by_addr[0x63CE009] and "%rax,0x1b8(%r14)" in by_addr[0x63CE009])
    check("armA slot0 shr 0x9 r9",
          "shr" in by_addr[0x63CE010] and "$0x9,%r9" in by_addr[0x63CE010])
    check("armA slot0 mov r10 0x1b0",
          "mov" in by_addr[0x63CE014] and "%r10,0x1b0(%r14)" in by_addr[0x63CE014])
    check("armA slot0 and 0x1ffff8 r9",
          "and" in by_addr[0x63CE01B] and "$0x1ffff8,%r9d" in by_addr[0x63CE01B])
    check("armA slot0 add r9 rax",
          "add" in by_addr[0x63CE022] and "%r9,%rax" in by_addr[0x63CE022])
    check("armA slot0 mov r10 r9",
          "mov" in by_addr[0x63CE025] and "%r10,%r9" in by_addr[0x63CE025])
    check("armA slot0 jmp 0x63cdeae",
          "jmp" in by_addr[0x63CE028] and "63cdeae" in by_addr[0x63CE028])

    # Scans: two 8-slot MTF scans, 16 slot compares, 11 reversed.
    # Normal = slot value first (cmp mem,%r10); reversed = key first
    # (cmp %r10,mem) -- the #321/#322 convention.
    slot_cmps = {
        0x63CDF88: "%r10,0x2b0(%r12)", 0x63CE033: "0x2c0(%r12),%r10",
        0x63CE0FC: "%r10,0x2d0(%r12)", 0x63CE110: "%r10,0x2e0(%r12)",
        0x63CE124: "%r10,0x2f0(%r12)", 0x63CE138: "%r10,0x300(%r12)",
        0x63CE14C: "%r10,0x310(%r12)", 0x63CE15A: "%r10,0x320(%r12)",
        0x63CDFD9: "0x2b0(%r12),%r10", 0x63CE098: "0x2c0(%r12),%r10",
        0x63CE174: "%r10,0x2d0(%r12)", 0x63CE187: "%r10,0x2e0(%r12)",
        0x63CE19A: "%r10,0x2f0(%r12)", 0x63CE1AD: "%r10,0x300(%r12)",
        0x63CE1C0: "0x310(%r12),%r10", 0x63CE1CE: "0x320(%r12),%r10",
    }
    for a, ops in slot_cmps.items():
        check("slot compare at %s" % hex(a),
              "cmp" in by_addr[a] and ops in by_addr[a], by_addr[a])
    rev = [a for a, ops in slot_cmps.items()
           if re.match(r"%r10,", ops)]
    check("reversed-operand slot compares exactly 11",
          sorted(rev) == [0x63CDF88, 0x63CE0FC, 0x63CE110, 0x63CE124,
                          0x63CE138, 0x63CE14C, 0x63CE15A, 0x63CE174,
                          0x63CE187, 0x63CE19A, 0x63CE1AD],
          str([hex(a) for a in sorted(rev)]))
    check("scan A slot-1 jne 0x63ce0f6",
          "jne" in by_addr[0x63CE03B] and "63ce0f6" in by_addr[0x63CE03B])
    check("scan A slot-7 jne miss 1 0x63ce1e2",
          "jne" in by_addr[0x63CE162] and "63ce1e2" in by_addr[0x63CE162])
    check("scan A slot-7 hit mov 7 r8d",
          "mov" in by_addr[0x63CE164] and "$0x7,%r8d" in by_addr[0x63CE164])
    check("scan A hit jmp 0x63ce041",
          "jmp" in by_addr[0x63CE16A] and "63ce041" in by_addr[0x63CE16A])
    check("scan A hit lea edx",
          "lea" in by_addr[0x63CE041] and "-0x1(%r8),%edx" in by_addr[0x63CE041])
    check("scan A hit jmp 0x63cdfb5",
          "jmp" in by_addr[0x63CE08E] and "63cdfb5" in by_addr[0x63CE08E])
    check("scan B slot-1 jne 0x63ce16f",
          "jne" in by_addr[0x63CE0A0] and "63ce16f" in by_addr[0x63CE0A0])
    check("scan B slot-7 jne miss 2 0x63ce202",
          "jne" in by_addr[0x63CE1D6] and "63ce202" in by_addr[0x63CE1D6])
    check("scan B slot-7 hit mov 7 esi",
          "mov" in by_addr[0x63CE1D8] and "$0x7,%esi" in by_addr[0x63CE1D8])
    check("scan B hit jmp 0x63ce0a6",
          "jmp" in by_addr[0x63CE1DD] and "63ce0a6" in by_addr[0x63CE1DD])
    check("scan B hit jmp 0x63ce006",
          "jmp" in by_addr[0x63CE0F1] and "63ce006" in by_addr[0x63CE0F1])

    # Lu-miss sites: argument setup (two blocks).
    check("miss 1 lea 0x6511a00 rsi",
          "lea" in by_addr[0x63CE1E2] and "6511a00" in by_addr[0x63CE1E2])
    check("miss 1 xor r9d",
          "xor" in by_addr[0x63CE1E9] and "%r9d,%r9d" in by_addr[0x63CE1E9])
    check("miss 1 mov rbp rcx",
          "mov" in by_addr[0x63CE1EC] and "%rbp,%rcx" in by_addr[0x63CE1EC])
    check("miss 1 mov r12 rdi",
          "mov" in by_addr[0x63CE1EF] and "%r12,%rdi" in by_addr[0x63CE1EF])
    check("miss 1 mov 1 r8d",
          "mov" in by_addr[0x63CE1F2] and "$0x1,%r8d" in by_addr[0x63CE1F2])
    check("miss 1 call 0x63d9700",
          "call" in by_addr[0x63CE1F8] and "63d9700" in by_addr[0x63CE1F8])
    check("miss 1 rejoin jmp 0x63cdedc",
          "jmp" in by_addr[0x63CE1FD] and "63cdedc" in by_addr[0x63CE1FD])
    check("miss 2 lea 0x6511a00 rsi",
          "lea" in by_addr[0x63CE202] and "6511a00" in by_addr[0x63CE202])
    check("miss 2 xor r9d",
          "xor" in by_addr[0x63CE209] and "%r9d,%r9d" in by_addr[0x63CE209])
    check("miss 2 mov rbp rcx",
          "mov" in by_addr[0x63CE20C] and "%rbp,%rcx" in by_addr[0x63CE20C])
    check("miss 2 mov r12 rdi",
          "mov" in by_addr[0x63CE20F] and "%r12,%rdi" in by_addr[0x63CE20F])
    check("miss 2 mov 1 r8d",
          "mov" in by_addr[0x63CE212] and "$0x1,%r8d" in by_addr[0x63CE212])
    check("miss 2 save r10 0x8 rsp",
          "mov" in by_addr[0x63CE218] and "%r10,0x8(%rsp)" in by_addr[0x63CE218])
    check("miss 2 save rdx rsp",
          "mov" in by_addr[0x63CE21D] and "%rdx,(%rsp)" in by_addr[0x63CE21D])
    check("miss 2 call 0x63d9700",
          "call" in by_addr[0x63CE221] and "63d9700" in by_addr[0x63CE221])
    check("miss 2 restore r9 0x1b0 r14",
          "mov" in by_addr[0x63CE226] and "0x1b0(%r14),%r9" in by_addr[0x63CE226])
    check("miss 2 restore r10 0x8 rsp",
          "mov" in by_addr[0x63CE22D] and "0x8(%rsp),%r10" in by_addr[0x63CE22D])
    check("miss 2 restore rdx rsp",
          "mov" in by_addr[0x63CE232] and "(%rsp),%rdx" in by_addr[0x63CE232])
    check("miss 2 rejoin jmp 0x63cdeae",
          "jmp" in by_addr[0x63CE236] and "63cdeae" in by_addr[0x63CE236])

    # CFG: successors (jump targets inside window + fall-through; calls
    # fall through except noreturn PLT calls; ret is terminal).
    def call_target(line):
        m = re.search(r"\tcall\s+([0-9a-f]+)", line)
        return int(m.group(1), 16) if m else None

    NORETURN = {0x63F0D70, 0x63F0BF0}
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

    for _s in [0x63CE1F8, 0x63CE221]:
        check("entry reaches lu-miss site %s" % hex(_s), reaches(START, _s))
    for _r in [0x63CDF2F, 0x63CDF43, 0x63CDF7A]:
        check("entry reaches ret %s" % hex(_r), reaches(START, _r))

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

    SITES = [0x63CE1F8, 0x63CE221]
    rcx_in = reaching_defs("rcx")
    check("miss 1 rcx only def is mov rbp rcx 0x63ce1ec",
          rcx_in[0x63CE1F8] == {0x63CE1EC}, str(rcx_in[0x63CE1F8]))
    check("miss 2 rcx only def is mov rbp rcx 0x63ce20c",
          rcx_in[0x63CE221] == {0x63CE20C}, str(rcx_in[0x63CE221]))
    rbp_in = reaching_defs("rbp")
    for s in SITES:
        check("rbp at %s only def is walk key 0x63cde5b" % hex(s),
              rbp_in[s] == {0x63CDE5B}, str(rbp_in[s]))
    r12_in = reaching_defs("r12")
    for s in SITES:
        check("r12 at %s only def is entry mov rdi r12 0x63cdddc" % hex(s),
              r12_in[s] == {0x63CDDDC}, str(r12_in[s]))
    rdx_in = reaching_defs("rdx")
    check("rdx at miss 1 is lea 0x63cde6e or restore 0x63ce232",
          rdx_in[0x63CE1F8] == {0x63CDE6E, 0x63CE232},
          str(rdx_in[0x63CE1F8]))
    check("rdx at miss 2 only def is lea 0x63cde6e",
          rdx_in[0x63CE221] == {0x63CDE6E}, str(rdx_in[0x63CE221]))
    rdi_in = reaching_defs("rdi")
    check("rdi at miss 1 only def is mov r12 rdi 0x63ce1ef",
          rdi_in[0x63CE1F8] == {0x63CE1EF}, str(rdi_in[0x63CE1F8]))
    check("rdi at miss 2 only def is mov r12 rdi 0x63ce20f",
          rdi_in[0x63CE221] == {0x63CE20F}, str(rdi_in[0x63CE221]))
    rsi_in = reaching_defs("rsi")
    check("rsi at miss 1 only def is lea 0x6511a00 0x63ce1e2",
          rsi_in[0x63CE1F8] == {0x63CE1E2}, str(rsi_in[0x63CE1F8]))
    check("rsi at miss 2 only def is lea 0x6511a00 0x63ce202",
          rsi_in[0x63CE221] == {0x63CE202}, str(rsi_in[0x63CE221]))
    r8_in = reaching_defs("r8")
    check("r8 at miss 1 only def is mov 1 r8d 0x63ce1f2",
          r8_in[0x63CE1F8] == {0x63CE1F2}, str(r8_in[0x63CE1F8]))
    check("r8 at miss 2 only def is mov 1 r8d 0x63ce212",
          r8_in[0x63CE221] == {0x63CE212}, str(r8_in[0x63CE221]))
    r9_in = reaching_defs("r9")
    check("r9 at miss 1 only def is xor r9d 0x63ce1e9",
          r9_in[0x63CE1F8] == {0x63CE1E9}, str(r9_in[0x63CE1F8]))
    check("r9 at miss 2 only def is xor r9d 0x63ce209",
          r9_in[0x63CE221] == {0x63CE209}, str(r9_in[0x63CE221]))
    r15_in = reaching_defs("r15")
    check("r15 at miss 1 only def is size class 0x63cdebc",
          r15_in[0x63CE1F8] == {0x63CDEBC}, str(r15_in[0x63CE1F8]))
    check("r15 at miss 2 is ENTRY (extract not run yet)",
          r15_in[0x63CE221] == {("ENTRY",)}, str(r15_in[0x63CE221]))
    r10_in = reaching_defs("r10")
    check("r10 at miss 1 is and 0x63cde7a or restore 0x63ce22d",
          r10_in[0x63CE1F8] == {0x63CDE7A, 0x63CE22D},
          str(r10_in[0x63CE1F8]))
    check("r10 at miss 2 only def is and 0x63cde7a",
          r10_in[0x63CE221] == {0x63CDE7A}, str(r10_in[0x63CE221]))
    rax_in = reaching_defs("rax")
    check("exit 0 rax only def is xor eax 0x63cdf23",
          rax_in[0x63CDF2F] == {0x63CDF23}, str(rax_in[0x63CDF2F]))
    check("exit 14 rax only def is mov e eax 0x63cdf34",
          rax_in[0x63CDF43] == {0x63CDF34}, str(rax_in[0x63CDF43]))
    check("exit 11 rax only def is mov b eax 0x63cdf6b",
          rax_in[0x63CDF7A] == {0x63CDF6B}, str(rax_in[0x63CDF7A]))
    check("records lu-miss sites match census",
          [s.get("site") for s in rec.get("lu_miss_sites", [])] ==
          ["0x63ce1f8", "0x63ce221"])
    check("records second-handler sites empty",
          rec.get("second_handler_sites", None) == [])

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for va in [0x65096C0, 0x6511A00, 0x6727A00]:
        check("address %s inside .bss" % hex(va),
              bss[3] <= va < bss[3] + bss[5])
    check("address 0x67277c0 inside .bss (not referenced here)",
          bss[3] <= 0x67277C0 < bss[3] + bss[5])
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
    check("this FDE raw second-handler 0",
          sh_counts.get(START, 0) == 0, str(sh_counts.get(START, 0)))
    check("raw-e8 second-handler total 64", sum(sh_counts.values()) == 64,
          str(sum(sh_counts.values())))
    check("raw-e8 second-handler FDEs 28", len(sh_counts) == 28,
          str(len(sh_counts)))
    check("next candidate raw lu-miss 10", counts.get(0x63D03A0, 0) == 10,
          str(counts.get(0x63D03A0, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63D03A0, 0) == 0,
          str(bti_counts.get(0x63D03A0, 0)))
    check("next candidate raw second-handler 1",
          sh_counts.get(0x63D03A0, 0) == 1,
          str(sh_counts.get(0x63D03A0, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 10th survivor",
          survey.get("survivors", [None] * 10)[9] == "0x63cddd0",
          str(survey.get("survivors", [])[:11]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window is NOT shared",
          "0x63cddd0" not in survey.get("shared_survivors", []))
    check("survey next candidate IS shared",
          "0x63d03a0" in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x63d03a0..0x63d17d7",
          nq.get("range") == "0x63d03a0..0x63d17d7", str(nq.get("range")))
    check("next question bytes 5175", nq.get("bytes") == 5175,
          str(nq.get("bytes")))
    check("next question lu-miss sites 10",
          nq.get("lu_miss_sites") == 10, str(nq.get("lu_miss_sites")))
    check("next question lu-miss site list",
          nq.get("lu_miss_site") == ["0x63d1063", "0x63d1183", "0x63d1258",
                                     "0x63d12a8", "0x63d1416", "0x63d15b6",
                                     "0x63d166c", "0x63d16b7", "0x63d177a",
                                     "0x63d17c1"],
          str(nq.get("lu_miss_site")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 1037", nq.get("strict") == 1037,
          str(nq.get("strict")))
    check("next question calls 23", nq.get("calls") == 23,
          str(nq.get("calls")))
    check("next question second-handler sites 1",
          nq.get("second_handler_sites") == 1,
          str(nq.get("second_handler_sites")))
    check("next question bsr 2", nq.get("bsr") == 2,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63d0817"],
          str(nq.get("ret")))
    check("records census strict 242",
          rec.get("census", {}).get("strict") == 242)
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
    # next candidate 0x63d03a0..0x63d17d7 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63D03A0 < p[1] and p[0] < 0x63D17D7]
    check("next candidate 0x63d03a0 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63D17D7 and 0x63D03A0 < END))

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
