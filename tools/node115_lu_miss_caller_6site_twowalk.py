"""Static verifier for RE-001-node115-lu-miss-caller-6site-twowalk.

Ninth packet of the lu-miss-caller frontier (callers of the lu-miss
handler 0x63d9700 that do not call bin_table_init): FDE
0x63ccd60..0x63cd907, 2983 bytes, 613 strict instructions, 31 calls
(31 direct, 0 indirect, 18 distinct targets), 6 lu-miss sites, 0
bin_table_init sites, 1 second-handler site, 1 ret at 0x63cd044,
bsr 0, lock sub 1 / lock add 1, 87 jumps, 0 outside the window.

This window is a SHARED survivor: it is in both the survey's 16-FDE
lu-miss survivor list and its 18-FDE second-handler survivor list, so
it consumes one slot of the combined 25-FDE miss-handler pool. Unlike
#321 it HAS endbr64, a canary, and a size class (byte table 0x67277c0
feeding the key-resolver helper 0x6364880): a trylock-guarded install
of a fresh node (0x63d3aa0 probe, 0x63cba10 allocator, 16-byte zero-init
plus node-field init, three lock-wait-helper retry arms), then TWO
context-table walks over rbx + 0x1b0 tables -- walk A keyed by the
0x6364880 return value, walk B keyed by the saved node pointer in
0x20(%rsp) -- each with inline shr $0x30 and shl/sar $0x10 extracts
(size table 0x6727a00, node table 0x65096c0), a lock add (walk A) and a
lock sub (walk B) refcount step, and six 8-slot move-to-front scans
(24 slot-compare instructions, 8 reversed-operand, 14 of 48 slot
positions reversed) whose exhaustion blocks are the six lu-miss sites.
All six sites share one argument pattern (rdi = rbx context,
rsi = .bss 0x6511a00, rdx = r15 table pointer rbx + 0x1b0, rcx = walk
key, r8d = 1, r9d = 0); the rcx provenance is proven by
reaching-definitions (noreturn-aware): sites 1-2 take the walk-A key
(mov %rax,%rcx at 0x63cce42, restored from (%rsp) at site 2), sites
3-6 take r13 set immediately before the call, and the only r13 def
reaching sites 3-6 is mov 0x20(%rsp),%r13 at 0x63cd06b (the walk-B
key). The one second-handler site (0x63cd27f) is gated on the node
table 0x65096c0 being null and takes rsi = 0, rdx = .data.rel.ro
0x64da4b0. Exit: rax is path-dependent (saved node pointer at
0x63cd01d, or 0 on the four xor paths), so no single exit value is
established.

Next question: the next lu-miss survivor in address order is
0x63cddd0..0x63ce23b (1131 bytes, 242 strict, 7 calls, 2 lu-miss
sites, 0 bti, 0 second-handler sites, THREE rets at 0x63cdf2f /
0x63cdf43 / 0x63cdf7a, bsr 0) -- a lu-miss-ONLY survivor, unlike this
packet.

Usage: python3 tools/node115_lu_miss_caller_6site_twowalk.py
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
                      "RE-001-node115-lu-miss-caller-6site-twowalk")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-6site-twowalk"
NAME = "lu_miss_caller_6site_twowalk"
START, END = 0x63CCD60, 0x63CD907

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
    check("target FDE size 2983", END - START == 2983)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x63ccd30..0x63ccd5e",
          prev == (0x63CCD30, 0x63CCD5E), str(prev))
    check("prev gap 2", START - prev[1] == 2)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 2, gap.hex())
    check("next FDE 0x63cd910..0x63cddce",
          nxt == (0x63CD910, 0x63CDDCE), str(nxt))
    check("next padding 9", nxt[0] - END == 9)
    pad = node[toff(END):toff(nxt[0])]
    check("padding bytes all cc", pad == b"\xcc" * 9, pad.hex())
    check("next FDE starts endbr64",
          node[toff(0x63CD910):toff(0x63CD910) + 4] ==
          bytes.fromhex("f30f1efa"))
    check("next FDE push r15 after endbr64",
          node[toff(0x63CD910) + 4:toff(0x63CD910) + 6] ==
          bytes.fromhex("4157"))

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 2983", len(hexb) == 2983, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 613", len(lines) == 613, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 31", len(calls) == 31, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63cd044", [addr_of(l) for l in rets] == [0x63CD044],
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
    expect = {0x634EBB0: 1, 0x6352FC0: 1, 0x6363260: 1, 0x63637F0: 1,
              0x6364880: 1, 0x63BD6C0: 1, 0x63BF680: 3, 0x63C66D0: 1,
              0x63C9500: 2, 0x63CBA10: 1, 0x63D39A0: 1, 0x63D3AA0: 1,
              0x63D9700: 6, 0x63EC4C0: 1, 0x63EDF10: 1, 0x63F0B70: 4,
              0x63F0D70: 1, 0x63F17B0: 3}
    check("call target multiset exact", dict(tgt) == expect,
          str(dict(tgt)))
    check("distinct call targets 18", len(tgt) == 18, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 6",
          sorted(a for a, t in ct if t == 0x63D9700) ==
          [0x63CD70D, 0x63CD7B3, 0x63CD7F1, 0x63CD831, 0x63CD86A, 0x63CD8FD],
          str([hex(a) for a, t in ct if t == 0x63D9700]))
    check("second-handler sites 1",
          sorted(a for a, t in ct if t == 0x634EBB0) == [0x63CD27F],
          str([hex(a) for a, t in ct if t == 0x634EBB0]))
    check("lock-wait helper called 3 times", tgt.get(0x63BF680, 0) == 3,
          str(tgt.get(0x63BF680, 0)))
    check("trylock plt called 3 times", tgt.get(0x63F17B0, 0) == 3,
          str(tgt.get(0x63F17B0, 0)))
    check("unlock plt called 4 times", tgt.get(0x63F0B70, 0) == 4,
          str(tgt.get(0x63F0B70, 0)))
    check("stack_chk_fail plt called once", tgt.get(0x63F0D70, 0) == 1,
          str(tgt.get(0x63F0D70, 0)))
    check("no 0x63be540 helper sites", tgt.get(0x63BE540, 0) == 0,
          str(tgt.get(0x63BE540, 0)))
    check("no 0x63be4d0 helper sites", tgt.get(0x63BE4D0, 0) == 0,
          str(tgt.get(0x63BE4D0, 0)))
    check("0x63bd6c0 helper called once at 0x63cd320",
          sorted(a for a, t in ct if t == 0x63BD6C0) == [0x63CD320],
          str([hex(a) for a, t in ct if t == 0x63BD6C0]))
    check("prev FDE 0x63c9500 called twice",
          sorted(a for a, t in ct if t == 0x63C9500) ==
          [0x63CD20B, 0x63CD24F],
          str([hex(a) for a, t in ct if t == 0x63C9500]))
    check("#298 window called once at 0x63cd4f5",
          sorted(a for a, t in ct if t == 0x6363260) == [0x63CD4F5],
          str([hex(a) for a, t in ct if t == 0x6363260]))
    check("#300 window called once at 0x63cd130",
          sorted(a for a, t in ct if t == 0x63637F0) == [0x63CD130],
          str([hex(a) for a, t in ct if t == 0x63637F0]))
    check("#314 window not called", tgt.get(0x63495B0, 0) == 0,
          str(tgt.get(0x63495B0, 0)))
    check("#315 window not called", tgt.get(0x6353A70, 0) == 0,
          str(tgt.get(0x6353A70, 0)))
    check("#316 window not called", tgt.get(0x6355900, 0) == 0,
          str(tgt.get(0x6355900, 0)))
    check("#317 window not called", tgt.get(0x63577F0, 0) == 0,
          str(tgt.get(0x63577F0, 0)))
    check("#318 window not called", tgt.get(0x635A7A0, 0) == 0,
          str(tgt.get(0x635A7A0, 0)))
    check("#319 window not called", tgt.get(0x635C6D0, 0) == 0,
          str(tgt.get(0x635C6D0, 0)))
    check("#320 window not called", tgt.get(0x635E2E0, 0) == 0,
          str(tgt.get(0x635E2E0, 0)))
    check("#321 window not called", tgt.get(0x63C9650, 0) == 0,
          str(tgt.get(0x63C9650, 0)))
    check("#313 window not called", tgt.get(0x63C2F00, 0) == 0,
          str(tgt.get(0x63C2F00, 0)))
    bsr = [addr_of(l) for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", bsr == [], str([hex(a) for a in bsr]))
    locks = [(addr_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 2", len(locks) == 2, str(locks))
    check("lock add at 0x63ccee0",
          locks[0][0] == 0x63CCEE0 and "add" in locks[0][1], str(locks))
    check("lock sub at 0x63cd0f7",
          locks[1][0] == 0x63CD0F7 and "sub" in locks[1][1], str(locks))
    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 87", len(jmps) == 87, str(len(jmps)))
    outside = [(a, t) for a, t in jmps if not (START <= t < END)]
    check("jump closure zero outside", outside == [], str(outside))

    # Entry + frame: endbr64, canary, trylock-guarded prologue.
    check("entry endbr64", "endbr64" in by_addr[START])
    check("entry push r15", "push" in by_addr[0x63CCD64] and
          "%r15" in by_addr[0x63CCD64])
    check("entry push r14", "push" in by_addr[0x63CCD66] and
          "%r14" in by_addr[0x63CCD66])
    check("entry push r13", "push" in by_addr[0x63CCD68] and
          "%r13" in by_addr[0x63CCD68])
    check("entry mov rsi to r13",
          "mov" in by_addr[0x63CCD6A] and "%rsi,%r13" in by_addr[0x63CCD6A])
    check("entry push r12", "push" in by_addr[0x63CCD6D] and
          "%r12" in by_addr[0x63CCD6D])
    check("entry push rbp", "push" in by_addr[0x63CCD6F] and
          "%rbp" in by_addr[0x63CCD6F])
    check("entry push rbx", "push" in by_addr[0x63CCD70] and
          "%rbx" in by_addr[0x63CCD70])
    check("entry mov rdi to rbx",
          "mov" in by_addr[0x63CCD71] and "%rdi,%rbx" in by_addr[0x63CCD71])
    check("entry sub 0x48 rsp",
          "sub" in by_addr[0x63CCD74] and "$0x48,%rsp" in by_addr[0x63CCD74])
    check("entry mov 0x68 rdi r12",
          "mov" in by_addr[0x63CCD78] and "0x68(%rdi),%r12" in by_addr[0x63CCD78])
    check("canary load fs:0x28",
          "mov" in by_addr[0x63CCD7C] and "%fs:0x28,%rax" in by_addr[0x63CCD7C])
    check("canary save 0x38 rsp",
          "mov" in by_addr[0x63CCD85] and "%rax,0x38(%rsp)" in by_addr[0x63CCD85])
    check("prologue mov r12 deref rbp",
          "mov" in by_addr[0x63CCD8C] and "(%r12),%rbp" in by_addr[0x63CCD8C])
    check("prologue lea 0x40 rbp rdi",
          "lea" in by_addr[0x63CCD90] and "0x40(%rbp),%rdi" in by_addr[0x63CCD90])
    check("prologue trylock call",
          "call" in by_addr[0x63CCD94] and "63f17b0" in by_addr[0x63CCD94])
    check("prologue trylock test eax",
          "test" in by_addr[0x63CCD99] and "%eax,%eax" in by_addr[0x63CCD99])
    check("prologue trylock fail jne 0x63cd048",
          "jne" in by_addr[0x63CCD9B] and "63cd048" in by_addr[0x63CCD9B])
    check("lock-wait 1 mov rbp rdi",
          "mov" in by_addr[0x63CD048] and "%rbp,%rdi" in by_addr[0x63CD048])
    check("lock-wait 1 call 0x63bf680",
          "call" in by_addr[0x63CD04B] and "63bf680" in by_addr[0x63CD04B])
    check("lock-wait 1 set byte 0x68 rbp",
          "movb" in by_addr[0x63CD050] and "$0x1,0x68(%rbp)" in by_addr[0x63CD050])
    check("lock-wait 1 jmp retry 0x63ccda1",
          "jmp" in by_addr[0x63CD054] and "63ccda1" in by_addr[0x63CD054])
    check("refcount addq 0x38 rbp",
          "addq" in by_addr[0x63CCDA1] and "$0x1,0x38(%rbp)" in by_addr[0x63CCDA1])
    check("owner cmp 0x30 rbp rbx",
          "cmp" in by_addr[0x63CCDA6] and "0x30(%rbp),%rbx" in by_addr[0x63CCDA6])
    check("owner je 0x63ccdb5",
          "je" in by_addr[0x63CCDAA] and "63ccdb5" in by_addr[0x63CCDAA])
    check("owner update addq 0x28 rbp",
          "addq" in by_addr[0x63CCDAC] and "$0x1,0x28(%rbp)" in by_addr[0x63CCDAC])
    check("owner update mov rbx 0x30 rbp",
          "mov" in by_addr[0x63CCDB1] and "%rbx,0x30(%rbp)" in by_addr[0x63CCDB1])
    check("no TLS flag fs:0x330 anywhere",
          not any("%fs:0x330" in l for l in lines))

    # Install: 0x63d3aa0 probe, 0x63cba10 allocator, zero-init + node init.
    check("probe lea 0x40 r12 rbp",
          "lea" in by_addr[0x63CCDB5] and "0x40(%r12),%rbp" in by_addr[0x63CCDB5])
    check("probe lea 0x20 rsp rcx",
          "lea" in by_addr[0x63CCDBC] and "0x20(%rsp),%rcx" in by_addr[0x63CCDBC])
    check("probe mov r13 rsi",
          "mov" in by_addr[0x63CCDC1] and "%r13,%rsi" in by_addr[0x63CCDC1])
    check("probe mov rbp rdi",
          "mov" in by_addr[0x63CCDC4] and "%rbp,%rdi" in by_addr[0x63CCDC4])
    check("probe call 0x63d3aa0",
          "call" in by_addr[0x63CCDC7] and "63d3aa0" in by_addr[0x63CCDC7])
    check("probe test al",
          "test" in by_addr[0x63CCDCC] and "%al,%al" in by_addr[0x63CCDCC])
    check("probe zero je 0x63cd000",
          "je" in by_addr[0x63CCDCE] and "63cd000" in by_addr[0x63CCDCE])
    check("probe unlock call",
          "call" in by_addr[0x63CCDE0] and "63f0b70" in by_addr[0x63CCDE0])
    check("alloc lea 0x28 rsp rcx",
          "lea" in by_addr[0x63CCDE5] and "0x28(%rsp),%rcx" in by_addr[0x63CCDE5])
    check("alloc mov r12 rdx",
          "mov" in by_addr[0x63CCDEA] and "%r12,%rdx" in by_addr[0x63CCDEA])
    check("alloc mov r13 rsi",
          "mov" in by_addr[0x63CCDED] and "%r13,%rsi" in by_addr[0x63CCDED])
    check("alloc lea 0x1f rsp r9",
          "lea" in by_addr[0x63CCDF0] and "0x1f(%rsp),%r9" in by_addr[0x63CCDF0])
    check("alloc lea 0x30 rsp r8",
          "lea" in by_addr[0x63CCDF5] and "0x30(%rsp),%r8" in by_addr[0x63CCDF5])
    check("alloc mov rbx rdi",
          "mov" in by_addr[0x63CCDFA] and "%rbx,%rdi" in by_addr[0x63CCDFA])
    check("alloc call 0x63cba10",
          "call" in by_addr[0x63CCDFD] and "63cba10" in by_addr[0x63CCDFD])
    check("alloc test al",
          "test" in by_addr[0x63CCE02] and "%al,%al" in by_addr[0x63CCE02])
    check("alloc nonzero jne 0x63cd135",
          "jne" in by_addr[0x63CCE04] and "63cd135" in by_addr[0x63CCE04])
    check("install gate cmpb 0x1 rbx",
          "cmpb" in by_addr[0x63CCE0A] and "$0x0,0x1(%rbx)" in by_addr[0x63CCE0A])
    check("install gate jg 0x63cd260",
          "jg" in by_addr[0x63CCE0E] and "63cd260" in by_addr[0x63CCE0E])
    check("install mov 0x88 rbx r14",
          "mov" in by_addr[0x63CCE14] and "0x88(%rbx),%r14" in by_addr[0x63CCE14])
    check("install test r14",
          "test" in by_addr[0x63CCE1B] and "%r14,%r14" in by_addr[0x63CCE1B])
    check("install null je 0x63cd1b0",
          "je" in by_addr[0x63CCE1E] and "63cd1b0" in by_addr[0x63CCE1E])
    check("install call 0x6352fc0",
          "call" in by_addr[0x63CD1B8] and "6352fc0" in by_addr[0x63CD1B8])
    check("install call 0x63edf10",
          "call" in by_addr[0x63CD1F6] and "63edf10" in by_addr[0x63CD1F6])

    # Second-handler path (0x63cd260).
    check("second lea 0x65096c0 rdx",
          "lea" in by_addr[0x63CD260] and "65096c0" in by_addr[0x63CD260])
    check("second mov rdx deref r14",
          "mov" in by_addr[0x63CD267] and "(%rdx),%r14" in by_addr[0x63CD267])
    check("second test r14",
          "test" in by_addr[0x63CD26A] and "%r14,%r14" in by_addr[0x63CD26A])
    check("second nonzero jne 0x63cce24",
          "jne" in by_addr[0x63CD26D] and "63cce24" in by_addr[0x63CD26D])
    check("second lea 0x64da4b0 rdx",
          "lea" in by_addr[0x63CD273] and "64da4b0" in by_addr[0x63CD273])
    check("second xor esi",
          "xor" in by_addr[0x63CD27A] and "%esi,%esi" in by_addr[0x63CD27A])
    check("second mov rbx rdi",
          "mov" in by_addr[0x63CD27C] and "%rbx,%rdi" in by_addr[0x63CD27C])
    check("second call 0x634ebb0",
          "call" in by_addr[0x63CD27F] and "634ebb0" in by_addr[0x63CD27F])
    check("second mov rax r14",
          "mov" in by_addr[0x63CD284] and "%rax,%r14" in by_addr[0x63CD284])
    check("second jmp 0x63cce24",
          "jmp" in by_addr[0x63CD287] and "63cce24" in by_addr[0x63CD287])

    # Size class + walk A (key = 0x6364880 return).
    check("size lea 0x67277c0 rcx",
          "lea" in by_addr[0x63CCE24] and "67277c0" in by_addr[0x63CCE24])
    check("size xor r8d",
          "xor" in by_addr[0x63CCE2B] and "%r8d,%r8d" in by_addr[0x63CCE2B])
    check("size mov r14 rsi",
          "mov" in by_addr[0x63CCE2E] and "%r14,%rsi" in by_addr[0x63CCE2E])
    check("size mov rbx rdi",
          "mov" in by_addr[0x63CCE31] and "%rbx,%rdi" in by_addr[0x63CCE31])
    check("size mov c8 edx",
          "mov" in by_addr[0x63CCE34] and "$0xc8,%edx" in by_addr[0x63CCE34])
    check("size movzbl 0x19 rcx",
          "movzbl" in by_addr[0x63CCE39] and "0x19(%rcx),%ecx" in by_addr[0x63CCE39])
    check("resolver call 0x6364880",
          "call" in by_addr[0x63CCE3D] and "6364880" in by_addr[0x63CCE3D])
    check("walk A key mov rax rcx",
          "mov" in by_addr[0x63CCE42] and "%rax,%rcx" in by_addr[0x63CCE42])
    check("walk A key test rax",
          "test" in by_addr[0x63CCE45] and "%rax,%rax" in by_addr[0x63CCE45])
    check("walk A key zero je 0x63cd230",
          "je" in by_addr[0x63CCE48] and "63cd230" in by_addr[0x63CCE48])
    check("walk A mov rax r13",
          "mov" in by_addr[0x63CCE4E] and "%rax,%r13" in by_addr[0x63CCE4E])
    check("walk A mov rax r11",
          "mov" in by_addr[0x63CCE51] and "%rax,%r11" in by_addr[0x63CCE51])
    check("walk A table lea 0x1b0 rbx r15",
          "lea" in by_addr[0x63CCE54] and "0x1b0(%rbx),%r15" in by_addr[0x63CCE54])
    check("walk A shr 0x1a r13",
          "shr" in by_addr[0x63CCE5B] and "$0x1a,%r13" in by_addr[0x63CCE5B])
    check("walk A high bits and r11",
          "and" in by_addr[0x63CCE5F] and
          "$0xffffffffc0000000,%r11" in by_addr[0x63CCE5F])
    check("walk A top index and f0",
          "and" in by_addr[0x63CCE66] and "$0xf0,%r13d" in by_addr[0x63CCE66])
    check("walk A top add rbx r13",
          "add" in by_addr[0x63CCE6D] and "%rbx,%r13" in by_addr[0x63CCE6D])
    check("walk A top load 0x1b0 r13 r9",
          "mov" in by_addr[0x63CCE70] and "0x1b0(%r13),%r9" in by_addr[0x63CCE70])
    check("walk A top cmp r9 r11",
          "cmp" in by_addr[0x63CCE77] and "%r9,%r11" in by_addr[0x63CCE77])
    check("walk A top jne scan A1 0x63cd158",
          "jne" in by_addr[0x63CCE7A] and "63cd158" in by_addr[0x63CCE7A])
    check("walk A second shr 0x9 rax",
          "shr" in by_addr[0x63CCE80] and "$0x9,%rax" in by_addr[0x63CCE80])
    check("walk A second and 0x1ffff8",
          "and" in by_addr[0x63CCE84] and "$0x1ffff8,%eax" in by_addr[0x63CCE84])
    check("walk A second add 0x1b8 r13",
          "add" in by_addr[0x63CCE89] and "0x1b8(%r13),%rax" in by_addr[0x63CCE89])
    check("walk A head mov rax deref",
          "mov" in by_addr[0x63CCE90] and "(%rax),%rax" in by_addr[0x63CCE90])
    check("extract A lea size table 0x6727a00",
          "lea" in by_addr[0x63CCE93] and "6727a00" in by_addr[0x63CCE93])
    check("extract A shr 0x30 rax",
          "shr" in by_addr[0x63CCE9A] and "$0x30,%rax" in by_addr[0x63CCE9A])
    check("extract A size table load r10",
          "mov" in by_addr[0x63CCE9E] and "(%r14,%rax,8),%r10" in by_addr[0x63CCE9E])
    check("walk A second cmp r11 r9",
          "cmp" in by_addr[0x63CCEA2] and "%r11,%r9" in by_addr[0x63CCEA2])
    check("walk A second jne scan A2 0x63cd290",
          "jne" in by_addr[0x63CCEA5] and "63cd290" in by_addr[0x63CCEA5])
    check("walk A mov rcx rax",
          "mov" in by_addr[0x63CCEAB] and "%rcx,%rax" in by_addr[0x63CCEAB])
    check("walk A shr 0x9 rax 2",
          "shr" in by_addr[0x63CCEAE] and "$0x9,%rax" in by_addr[0x63CCEAE])
    check("walk A and 0x1ffff8 2",
          "and" in by_addr[0x63CCEB2] and "$0x1ffff8,%eax" in by_addr[0x63CCEB2])
    check("walk A add 0x1b8 r13 2",
          "add" in by_addr[0x63CCEB7] and "0x1b8(%r13),%rax" in by_addr[0x63CCEB7])
    check("walk A mov rax deref r11",
          "mov" in by_addr[0x63CCEBE] and "(%rax),%r11" in by_addr[0x63CCEBE])
    check("extract A lea node table 0x65096c0",
          "lea" in by_addr[0x63CCEC1] and "65096c0" in by_addr[0x63CCEC1])
    check("extract A shl 0x10 r11",
          "shl" in by_addr[0x63CCEC8] and "$0x10,%r11" in by_addr[0x63CCEC8])
    check("extract A sar 0x10 r11",
          "sar" in by_addr[0x63CCECC] and "$0x10,%r11" in by_addr[0x63CCECC])
    check("extract A and 80 r11",
          "and" in by_addr[0x63CCED0] and
          "$0xffffffffffffff80,%r11" in by_addr[0x63CCED0])
    check("extract A node load rax",
          "mov" in by_addr[0x63CCED4] and "(%r11),%rax" in by_addr[0x63CCED4])
    check("extract A and fff eax",
          "and" in by_addr[0x63CCED7] and "$0xfff,%eax" in by_addr[0x63CCED7])
    check("extract A node table load r8",
          "mov" in by_addr[0x63CCEDC] and "(%rdi,%rax,8),%r8" in by_addr[0x63CCEDC])
    check("lock add r10 0x38 r8",
          "lock" in by_addr[0x63CCEE0] and "add" in by_addr[0x63CCEE0] and
          "%r10,0x38(%r8)" in by_addr[0x63CCEE0])
    check("zero-init pxor xmm0",
          "pxor" in by_addr[0x63CCEE5] and "%xmm0,%xmm0" in by_addr[0x63CCEE5])
    check("zero-init movdqu 0x8 r12 xmm1",
          "movdqu" in by_addr[0x63CCEE9] and "0x8(%r12),%xmm1" in by_addr[0x63CCEE9])
    check("zero-init movups 0x20 rcx",
          "movups" in by_addr[0x63CCEF5] and "%xmm0,0x20(%rcx)" in by_addr[0x63CCEF5])
    check("zero-init movups 0x50 rcx",
          "movups" in by_addr[0x63CCF01] and "%xmm0,0x50(%rcx)" in by_addr[0x63CCF01])
    check("zero-init movups xmm1 0x8 rcx",
          "movups" in by_addr[0x63CCF09] and "%xmm1,0x8(%rcx)" in by_addr[0x63CCF09])
    check("node init save rcx 0x20 rsp",
          "mov" in by_addr[0x63CCF12] and "%rcx,0x20(%rsp)" in by_addr[0x63CCF12])
    check("node init mov r12 deref rcx",
          "mov" in by_addr[0x63CCF1F] and "%r12,(%rcx)" in by_addr[0x63CCF1F])
    check("node init movq 0 0x18 rcx",
          "movq" in by_addr[0x63CCF22] and "$0x0,0x18(%rcx)" in by_addr[0x63CCF22])
    check("node init mov r10 0x60 rcx",
          "mov" in by_addr[0x63CCF2A] and "%r10,0x60(%rcx)" in by_addr[0x63CCF2A])
    check("node init mov r9 0x68 rcx",
          "mov" in by_addr[0x63CCF33] and "%r9,0x68(%rcx)" in by_addr[0x63CCF33])
    check("node init movb 1 0x80 rcx",
          "movb" in by_addr[0x63CCF37] and "$0x1,0x80(%rcx)" in by_addr[0x63CCF37])
    check("node init movl 0 0x84 rcx",
          "movl" in by_addr[0x63CCF3E] and "$0x0,0x84(%rcx)" in by_addr[0x63CCF3E])
    check("node trylock call",
          "call" in by_addr[0x63CCF48] and "63f17b0" in by_addr[0x63CCF48])
    check("node trylock fail jne 0x63cd140",
          "jne" in by_addr[0x63CCF4F] and "63cd140" in by_addr[0x63CCF4F])
    check("lock-wait 2 mov r13 rdi",
          "mov" in by_addr[0x63CD140] and "%r13,%rdi" in by_addr[0x63CD140])
    check("lock-wait 2 call 0x63bf680",
          "call" in by_addr[0x63CD143] and "63bf680" in by_addr[0x63CD143])
    check("lock-wait 2 set byte 0x68 r13",
          "movb" in by_addr[0x63CD148] and "$0x1,0x68(%r13)" in by_addr[0x63CD148])
    check("lock-wait 2 jmp retry 0x63ccf55",
          "jmp" in by_addr[0x63CD14D] and "63ccf55" in by_addr[0x63CD14D])
    check("node refcount addq 0x38 r13",
          "addq" in by_addr[0x63CCF55] and "$0x1,0x38(%r13)" in by_addr[0x63CCF55])
    check("node owner cmp 0x30 r13 rbx",
          "cmp" in by_addr[0x63CCF5A] and "0x30(%r13),%rbx" in by_addr[0x63CCF5A])
    check("node owner update addq 0x28 r13",
          "addq" in by_addr[0x63CCF60] and "$0x1,0x28(%r13)" in by_addr[0x63CCF60])
    check("node restore rcx 0x20 rsp",
          "mov" in by_addr[0x63CCF69] and "0x20(%rsp),%rcx" in by_addr[0x63CCF69])
    check("node restore rdx 0x28 rsp",
          "mov" in by_addr[0x63CCF6E] and "0x28(%rsp),%rdx" in by_addr[0x63CCF6E])
    check("node call 0x63d39a0",
          "call" in by_addr[0x63CCF79] and "63d39a0" in by_addr[0x63CCF79])
    check("node mov r12 deref rdi",
          "mov" in by_addr[0x63CCF7E] and "(%r12),%rdi" in by_addr[0x63CCF7E])
    check("node mov eax ebp",
          "mov" in by_addr[0x63CCF82] and "%eax,%ebp" in by_addr[0x63CCF82])
    check("node unlock call",
          "call" in by_addr[0x63CCF8C] and "63f0b70" in by_addr[0x63CCF8C])
    check("node test bpl",
          "test" in by_addr[0x63CCF91] and "%bpl,%bpl" in by_addr[0x63CCF91])
    check("node nonzero jne walk B 0x63cd060",
          "jne" in by_addr[0x63CCF94] and "63cd060" in by_addr[0x63CCF94])
    check("second node mov r12 r15 deref",
          "mov" in by_addr[0x63CCF9F] and "(%r12),%r15" in by_addr[0x63CCF9F])
    check("second node trylock call",
          "call" in by_addr[0x63CCFA7] and "63f17b0" in by_addr[0x63CCFA7])
    check("second node trylock fail jne 0x63cd218",
          "jne" in by_addr[0x63CCFAE] and "63cd218" in by_addr[0x63CCFAE])
    check("lock-wait 3 mov r15 rdi",
          "mov" in by_addr[0x63CD218] and "%r15,%rdi" in by_addr[0x63CD218])
    check("lock-wait 3 call 0x63bf680",
          "call" in by_addr[0x63CD21B] and "63bf680" in by_addr[0x63CD21B])
    check("lock-wait 3 jmp retry 0x63ccfb4",
          "jmp" in by_addr[0x63CD225] and "63ccfb4" in by_addr[0x63CD225])
    check("second node mov 0x20 rsp rsi",
          "mov" in by_addr[0x63CCFC8] and "0x20(%rsp),%rsi" in by_addr[0x63CCFC8])
    check("second node movl 1 0x84 rsi",
          "movl" in by_addr[0x63CCFD2] and "$0x1,0x84(%rsi)" in by_addr[0x63CCFD2])
    check("second node call 0x63c66d0",
          "call" in by_addr[0x63CCFDC] and "63c66d0" in by_addr[0x63CCFDC])
    check("second node unlock call",
          "call" in by_addr[0x63CCFF3] and "63f0b70" in by_addr[0x63CCFF3])
    check("second node jmp epilogue 0x63cd01d",
          "jmp" in by_addr[0x63CCFF8] and "63cd01d" in by_addr[0x63CCFF8])

    # Walk B (key = saved node pointer in 0x20(%rsp)).
    check("walk B cmpb 0x1f rsp",
          "cmpb" in by_addr[0x63CD060] and "$0x0,0x1f(%rsp)" in by_addr[0x63CD060])
    check("walk B jne 0x63cd200",
          "jne" in by_addr[0x63CD065] and "63cd200" in by_addr[0x63CD065])
    check("walk B call 0x63c9500",
          "call" in by_addr[0x63CD20B] and "63c9500" in by_addr[0x63CD20B])
    check("walk B jmp 0x63cd06b",
          "jmp" in by_addr[0x63CD210] and "63cd06b" in by_addr[0x63CD210])
    check("walk B key mov 0x20 rsp r13",
          "mov" in by_addr[0x63CD06B] and "0x20(%rsp),%r13" in by_addr[0x63CD06B])
    check("walk B mov r13 rbp",
          "mov" in by_addr[0x63CD070] and "%r13,%rbp" in by_addr[0x63CD070])
    check("walk B mov r13 r10",
          "mov" in by_addr[0x63CD073] and "%r13,%r10" in by_addr[0x63CD073])
    check("walk B shr 0x1a rbp",
          "shr" in by_addr[0x63CD076] and "$0x1a,%rbp" in by_addr[0x63CD076])
    check("walk B high bits and r10",
          "and" in by_addr[0x63CD07A] and
          "$0xffffffffc0000000,%r10" in by_addr[0x63CD07A])
    check("walk B top index and f0",
          "and" in by_addr[0x63CD081] and "$0xf0,%ebp" in by_addr[0x63CD081])
    check("walk B top add rbx rbp",
          "add" in by_addr[0x63CD087] and "%rbx,%rbp" in by_addr[0x63CD087])
    check("walk B top load 0x1b0 rbp r11",
          "mov" in by_addr[0x63CD08A] and "0x1b0(%rbp),%r11" in by_addr[0x63CD08A])
    check("walk B top cmp r11 r10",
          "cmp" in by_addr[0x63CD091] and "%r11,%r10" in by_addr[0x63CD091])
    check("walk B top jne scan B1 0x63cd3c4",
          "jne" in by_addr[0x63CD094] and "63cd3c4" in by_addr[0x63CD094])
    check("walk B second shr 0x9 rax",
          "shr" in by_addr[0x63CD09D] and "$0x9,%rax" in by_addr[0x63CD09D])
    check("walk B second and 0x1ffff8",
          "and" in by_addr[0x63CD0A1] and "$0x1ffff8,%eax" in by_addr[0x63CD0A1])
    check("walk B second add 0x1b8 rbp",
          "add" in by_addr[0x63CD0A6] and "0x1b8(%rbp),%rax" in by_addr[0x63CD0A6])
    check("walk B mov rax deref",
          "mov" in by_addr[0x63CD0AD] and "(%rax),%rax" in by_addr[0x63CD0AD])
    check("extract B shr 0x30 rax",
          "shr" in by_addr[0x63CD0B0] and "$0x30,%rax" in by_addr[0x63CD0B0])
    check("extract B size table load r14",
          "mov" in by_addr[0x63CD0B4] and "(%r14,%rax,8),%r14" in by_addr[0x63CD0B4])
    check("walk B second cmp r10 r11",
          "cmp" in by_addr[0x63CD0B8] and "%r10,%r11" in by_addr[0x63CD0B8])
    check("walk B second jne scan B2 0x63cd378",
          "jne" in by_addr[0x63CD0BB] and "63cd378" in by_addr[0x63CD0BB])
    check("walk B resolve shr 0x9 rax",
          "shr" in by_addr[0x63CD0C4] and "$0x9,%rax" in by_addr[0x63CD0C4])
    check("walk B resolve mov rax deref r12",
          "mov" in by_addr[0x63CD0D4] and "(%rax),%r12" in by_addr[0x63CD0D4])
    check("extract B lea node table 0x65096c0",
          "lea" in by_addr[0x63CD0D7] and "65096c0" in by_addr[0x63CD0D7])
    check("extract B shl 0x10 r12",
          "shl" in by_addr[0x63CD0DE] and "$0x10,%r12" in by_addr[0x63CD0DE])
    check("extract B sar 0x10 r12",
          "sar" in by_addr[0x63CD0E2] and "$0x10,%r12" in by_addr[0x63CD0E2])
    check("extract B and 80 r12",
          "and" in by_addr[0x63CD0E6] and
          "$0xffffffffffffff80,%r12" in by_addr[0x63CD0E6])
    check("extract B node load rax",
          "mov" in by_addr[0x63CD0EA] and "(%r12),%rax" in by_addr[0x63CD0EA])
    check("extract B and fff eax",
          "and" in by_addr[0x63CD0EE] and "$0xfff,%eax" in by_addr[0x63CD0EE])
    check("extract B node table load rsi",
          "mov" in by_addr[0x63CD0F3] and "(%rcx,%rax,8),%rsi" in by_addr[0x63CD0F3])
    check("lock sub r14 0x38 rsi",
          "lock" in by_addr[0x63CD0F7] and "sub" in by_addr[0x63CD0F7] and
          "%r14,0x38(%rsi)" in by_addr[0x63CD0F7])
    check("walk B mov 0x1b0 rbp r14",
          "mov" in by_addr[0x63CD0FC] and "0x1b0(%rbp),%r14" in by_addr[0x63CD0FC])
    check("walk B cmp r14 r10",
          "cmp" in by_addr[0x63CD103] and "%r14,%r10" in by_addr[0x63CD103])
    check("walk B jne scan B3 0x63cd32c",
          "jne" in by_addr[0x63CD106] and "63cd32c" in by_addr[0x63CD106])
    check("walk B leaf mov rax deref",
          "mov" in by_addr[0x63CD11F] and "(%rax),%rax" in by_addr[0x63CD11F])
    check("walk B leaf test 1 al",
          "test" in by_addr[0x63CD122] and "$0x1,%al" in by_addr[0x63CD122])
    check("walk B leaf je 0x63cd2dd",
          "je" in by_addr[0x63CD124] and "63cd2dd" in by_addr[0x63CD124])
    check("walk B leaf call 0x63637f0",
          "call" in by_addr[0x63CD130] and "63637f0" in by_addr[0x63CD130])
    check("walk B leaf xor eax",
          "xor" in by_addr[0x63CD135] and "%eax,%eax" in by_addr[0x63CD135])
    check("walk B leaf jmp 0x63cd022",
          "jmp" in by_addr[0x63CD137] and "63cd022" in by_addr[0x63CD137])
    check("walk B leaf shr 0x30 rax",
          "shr" in by_addr[0x63CD2DD] and "$0x30,%rax" in by_addr[0x63CD2DD])
    check("walk B leaf cmp 0x23 rax",
          "cmp" in by_addr[0x63CD2E1] and "$0x23,%rax" in by_addr[0x63CD2E1])
    check("walk B leaf jbe 0x63cd4e8",
          "jbe" in by_addr[0x63CD2E5] and "63cd4e8" in by_addr[0x63CD2E5])
    check("walk B leaf jne scan B4 0x63cd62f",
          "jne" in by_addr[0x63CD2F5] and "63cd62f" in by_addr[0x63CD2F5])
    check("walk B leaf shl 0x10 rsi",
          "shl" in by_addr[0x63CD314] and "$0x10,%rsi" in by_addr[0x63CD314])
    check("walk B leaf sar 0x10 rsi",
          "sar" in by_addr[0x63CD318] and "$0x10,%rsi" in by_addr[0x63CD318])
    check("walk B leaf call 0x63bd6c0",
          "call" in by_addr[0x63CD320] and "63bd6c0" in by_addr[0x63CD320])
    check("walk B leaf xor eax 2",
          "xor" in by_addr[0x63CD325] and "%eax,%eax" in by_addr[0x63CD325])
    check("walk B leaf call 0x6363260",
          "call" in by_addr[0x63CD4F5] and "6363260" in by_addr[0x63CD4F5])
    check("walk B leaf xor eax 3",
          "xor" in by_addr[0x63CD4FA] and "%eax,%eax" in by_addr[0x63CD4FA])

    # Scans: six 8-slot MTF scans, 24 slot compares, 8 reversed.
    slot_cmps = {
        0x63CD158: "0x2b0(%rbx),%r11", 0x63CD48B: "%r11,0x2c0(%rbx)",
        0x63CD686: "0x2d0(%rbx),%r11", 0x63CD698: "0x2e0(%rbx),%r11",
        0x63CD6AA: "0x2f0(%rbx),%r11", 0x63CD6BC: "0x300(%rbx),%r11",
        0x63CD6CE: "0x310(%rbx),%r11", 0x63CD6DB: "0x320(%rbx),%r11",
        0x63CD290: "%r11,0x2b0(%rbx)", 0x63CD429: "0x2c0(%rbx),%r11",
        0x63CD72C: "0x2d0(%rbx),%r11", 0x63CD73E: "0x2e0(%rbx),%r11",
        0x63CD750: "%r11,0x2f0(%rbx)", 0x63CD762: "%r11,0x300(%rbx)",
        0x63CD774: "%r11,0x310(%rbx)", 0x63CD781: "%r11,0x320(%rbx)",
        0x63CD3C4: "0x2b0(%rbx),%r10", 0x63CD5D7: "0x2b0(%rbx,%rsi,1),%r10",
        0x63CD378: "%r10,0x2b0(%rbx)", 0x63CD573: "%r10,0x2b0(%rbx,%rsi,1)",
        0x63CD32C: "0x2b0(%rbx),%r10", 0x63CD50E: "0x2b0(%rbx,%r11,1),%r10",
        0x63CD62F: "0x2b0(%rbx),%r10", 0x63CD885: "0x2b0(%rbx,%rsi,1),%r10",
    }
    for a, ops in slot_cmps.items():
        check("slot compare at %s" % hex(a),
              "cmp" in by_addr[a] and ops in by_addr[a], by_addr[a])
    rev = [a for a, ops in slot_cmps.items()
           if re.match(r"%r1[01],", ops)]
    check("reversed-operand slot compares exactly 8",
          sorted(rev) == [0x63CD290, 0x63CD378, 0x63CD48B, 0x63CD573,
                          0x63CD750, 0x63CD762, 0x63CD774, 0x63CD781],
          str([hex(a) for a in sorted(rev)]))
    check("scan A1 slot-0 jne 0x63cd486",
          "jne" in by_addr[0x63CD15F] and "63cd486" in by_addr[0x63CD15F])
    check("scan A1 slot-7 jne miss 1 0x63cd6ee",
          "jne" in by_addr[0x63CD6E2] and "63cd6ee" in by_addr[0x63CD6E2])
    check("scan A1 slot-7 hit mov 7 esi",
          "mov" in by_addr[0x63CD6E4] and "$0x7,%esi" in by_addr[0x63CD6E4])
    check("scan A2 slot-0 jne 0x63cd424",
          "jne" in by_addr[0x63CD297] and "63cd424" in by_addr[0x63CD297])
    check("scan A2 slot-7 jne miss 2 0x63cd794",
          "jne" in by_addr[0x63CD788] and "63cd794" in by_addr[0x63CD788])
    check("scan B1 slot-0 jne 0x63cd5cb",
          "jne" in by_addr[0x63CD3CB] and "63cd5cb" in by_addr[0x63CD3CB])
    check("scan B1 loop jne 0x63cd7c6",
          "jne" in by_addr[0x63CD5DF] and "63cd7c6" in by_addr[0x63CD5DF])
    check("scan B1 loop add 1 rcx",
          "add" in by_addr[0x63CD7C6] and "$0x1,%rcx" in by_addr[0x63CD7C6])
    check("scan B1 loop cmp 8 rcx",
          "cmp" in by_addr[0x63CD7CA] and "$0x8,%rcx" in by_addr[0x63CD7CA])
    check("scan B1 loop jne 0x63cd5d0",
          "jne" in by_addr[0x63CD7CE] and "63cd5d0" in by_addr[0x63CD7CE])
    check("scan B2 slot-0 jne 0x63cd567",
          "jne" in by_addr[0x63CD37F] and "63cd567" in by_addr[0x63CD37F])
    check("scan B2 loop jne 0x63cd806",
          "jne" in by_addr[0x63CD57B] and "63cd806" in by_addr[0x63CD57B])
    check("scan B2 loop add 1 rcx",
          "add" in by_addr[0x63CD806] and "$0x1,%rcx" in by_addr[0x63CD806])
    check("scan B3 slot-0 jne 0x63cd501",
          "jne" in by_addr[0x63CD333] and "63cd501" in by_addr[0x63CD333])
    check("scan B3 loop jne 0x63cd83f",
          "jne" in by_addr[0x63CD516] and "63cd83f" in by_addr[0x63CD516])
    check("scan B3 loop add 1 r8",
          "add" in by_addr[0x63CD83F] and "$0x1,%r8" in by_addr[0x63CD83F])
    check("scan B4 slot-0 jne 0x63cd878",
          "jne" in by_addr[0x63CD636] and "63cd878" in by_addr[0x63CD636])
    check("scan B4 loop jne 0x63cd8da",
          "jne" in by_addr[0x63CD88D] and "63cd8da" in by_addr[0x63CD88D])
    check("scan B4 loop add 1 r8",
          "add" in by_addr[0x63CD8DA] and "$0x1,%r8" in by_addr[0x63CD8DA])

    # Lu-miss sites: argument setup (six blocks).
    miss_blocks = [
        (0x63CD6EE, 0x63CD6F5, 0x63CD6F8, 0x63CD6FB, 0x63CD6FE, None,
         0x63CD70D, 0x63CD722, 0x63CCE90),
        (0x63CD794, 0x63CD79B, 0x63CD79E, 0x63CD7A1, 0x63CD7A4, None,
         0x63CD7B3, 0x63CD7C1, 0x63CCEBE),
        (0x63CD7D4, 0x63CD7DB, 0x63CD7E1, 0x63CD7EA, 0x63CD7E4, 0x63CD7DE,
         0x63CD7F1, 0x63CD801, 0x63CD0AD),
        (0x63CD814, 0x63CD81B, 0x63CD821, 0x63CD82A, 0x63CD824, 0x63CD81E,
         0x63CD831, 0x63CD83A, 0x63CD0D4),
        (0x63CD84D, 0x63CD854, 0x63CD85A, 0x63CD863, 0x63CD85D, 0x63CD857,
         0x63CD86A, 0x63CD873, 0x63CD11F),
        (0x63CD8E4, 0x63CD8EB, 0x63CD8F1, 0x63CD8FA, 0x63CD8F4, 0x63CD8EE,
         0x63CD8FD, 0x63CD902, 0x63CD30E),
    ]
    for n, (blk, r9a, rdxa, rdia, r8a, rcxa, site, jmpa, rejoin) in             enumerate(miss_blocks, 1):
        check("miss %d lea 0x6511a00 rsi" % n,
              "lea" in by_addr[blk] and "6511a00" in by_addr[blk])
        check("miss %d xor r9d" % n,
              "xor" in by_addr[r9a] and "%r9d,%r9d" in by_addr[r9a])
        check("miss %d mov r15 rdx" % n,
              "mov" in by_addr[rdxa] and "%r15,%rdx" in by_addr[rdxa])
        check("miss %d mov rbx rdi" % n,
              "mov" in by_addr[rdia] and "%rbx,%rdi" in by_addr[rdia])
        check("miss %d mov 1 r8d" % n,
              "mov" in by_addr[r8a] and "$0x1,%r8d" in by_addr[r8a])
        if rcxa is not None:
            check("miss %d mov r13 rcx" % n,
                  "mov" in by_addr[rcxa] and "%r13,%rcx" in by_addr[rcxa])
        check("miss %d call 0x63d9700" % n,
              "call" in by_addr[site] and "63d9700" in by_addr[site])
        check("miss %d rejoin jmp %s" % (n, hex(rejoin)),
              "jmp" in by_addr[jmpa] and hex(rejoin)[2:] in by_addr[jmpa])
    check("miss 1 save r11 0x8 rsp",
          "mov" in by_addr[0x63CD704] and "%r11,0x8(%rsp)" in by_addr[0x63CD704])
    check("miss 1 save rax rsp",
          "mov" in by_addr[0x63CD709] and "%rax,(%rsp)" in by_addr[0x63CD709])
    check("miss 1 restore r11 0x8 rsp",
          "mov" in by_addr[0x63CD719] and "0x8(%rsp),%r11" in by_addr[0x63CD719])
    check("miss 1 restore rcx rsp",
          "mov" in by_addr[0x63CD71E] and "(%rsp),%rcx" in by_addr[0x63CD71E])
    check("miss 2 save r10 0x8 rsp",
          "mov" in by_addr[0x63CD7AA] and "%r10,0x8(%rsp)" in by_addr[0x63CD7AA])
    check("miss 2 save rcx rsp",
          "mov" in by_addr[0x63CD7AF] and "%rcx,(%rsp)" in by_addr[0x63CD7AF])
    check("miss 2 restore r10 0x8 rsp",
          "mov" in by_addr[0x63CD7B8] and "0x8(%rsp),%r10" in by_addr[0x63CD7B8])
    check("miss 2 restore rcx rsp",
          "mov" in by_addr[0x63CD7BD] and "(%rsp),%rcx" in by_addr[0x63CD7BD])
    check("miss 3 save r10 rsp",
          "mov" in by_addr[0x63CD7ED] and "%r10,(%rsp)" in by_addr[0x63CD7ED])
    check("miss 3 restore r11 0x1b0 rbp",
          "mov" in by_addr[0x63CD7F6] and "0x1b0(%rbp),%r11" in by_addr[0x63CD7F6])
    check("miss 3 restore r10 rsp",
          "mov" in by_addr[0x63CD7FD] and "(%rsp),%r10" in by_addr[0x63CD7FD])

    # Epilogue + alternate exits.
    check("alt exit mov 0x20 rsp rbx",
          "mov" in by_addr[0x63CD000] and "0x20(%rsp),%rbx" in by_addr[0x63CD000])
    check("alt exit movb 1 0x80 rbx",
          "movb" in by_addr[0x63CD009] and "$0x1,0x80(%rbx)" in by_addr[0x63CD009])
    check("alt exit unlock call",
          "call" in by_addr[0x63CD018] and "63f0b70" in by_addr[0x63CD018])
    check("epilogue mov 0x20 rsp rax",
          "mov" in by_addr[0x63CD01D] and "0x20(%rsp),%rax" in by_addr[0x63CD01D])
    check("epilogue mov 0x38 rsp rdx",
          "mov" in by_addr[0x63CD022] and "0x38(%rsp),%rdx" in by_addr[0x63CD022])
    check("epilogue canary sub fs:0x28 rdx",
          "sub" in by_addr[0x63CD027] and "%fs:0x28,%rdx" in by_addr[0x63CD027])
    check("epilogue canary jne 0x63cd67c",
          "jne" in by_addr[0x63CD030] and "63cd67c" in by_addr[0x63CD030])
    check("epilogue add 0x48 rsp",
          "add" in by_addr[0x63CD036] and "$0x48,%rsp" in by_addr[0x63CD036])
    check("epilogue pop rbx",
          "pop" in by_addr[0x63CD03A] and "%rbx" in by_addr[0x63CD03A])
    check("epilogue pop r15",
          "pop" in by_addr[0x63CD042] and "%r15" in by_addr[0x63CD042])
    check("canary fail call stack_chk_fail",
          "call" in by_addr[0x63CD67C] and "63f0d70" in by_addr[0x63CD67C])
    check("zero node movq 0 0x20 rsp",
          "movq" in by_addr[0x63CD230] and "$0x0,0x20(%rsp)" in by_addr[0x63CD230])
    check("zero node cmpb 0x1f rsp",
          "cmpb" in by_addr[0x63CD239] and "$0x0,0x1f(%rsp)" in by_addr[0x63CD239])
    check("zero node je 0x63cd135",
          "je" in by_addr[0x63CD23E] and "63cd135" in by_addr[0x63CD23E])
    check("zero node call 0x63c9500",
          "call" in by_addr[0x63CD24F] and "63c9500" in by_addr[0x63CD24F])
    check("zero node xor eax",
          "xor" in by_addr[0x63CD254] and "%eax,%eax" in by_addr[0x63CD254])

    # CFG: successors (jump targets inside window + fall-through; calls
    # fall through except noreturn PLT calls; ret is terminal).
    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    def call_target(line):
        m = re.search(r"	call\s+([0-9a-f]+)", line)
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

    for _s in [0x63CD70D, 0x63CD7B3, 0x63CD7F1, 0x63CD831, 0x63CD86A,
               0x63CD8FD]:
        check("entry reaches lu-miss site %s" % hex(_s), reaches(START, _s))
    check("entry reaches ret", reaches(START, 0x63CD044))


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

    SITES = [0x63CD70D, 0x63CD7B3, 0x63CD7F1, 0x63CD831, 0x63CD86A, 0x63CD8FD]
    rcx_in = reaching_defs("rcx")
    check("miss 1 rcx only def is mov rax rcx 0x63cce42",
          rcx_in[0x63CD70D] == {0x63CCE42}, str(rcx_in[0x63CD70D]))
    check("miss 2 rcx defs are 0x63cce42 and restore 0x63cd71e",
          rcx_in[0x63CD7B3] == {0x63CCE42, 0x63CD71E},
          str(rcx_in[0x63CD7B3]))
    check("miss 3 rcx only def is mov r13 rcx 0x63cd7de",
          rcx_in[0x63CD7F1] == {0x63CD7DE}, str(rcx_in[0x63CD7F1]))
    check("miss 4 rcx only def is mov r13 rcx 0x63cd81e",
          rcx_in[0x63CD831] == {0x63CD81E}, str(rcx_in[0x63CD831]))
    check("miss 5 rcx only def is mov r13 rcx 0x63cd857",
          rcx_in[0x63CD86A] == {0x63CD857}, str(rcx_in[0x63CD86A]))
    check("miss 6 rcx only def is mov r13 rcx 0x63cd8ee",
          rcx_in[0x63CD8FD] == {0x63CD8EE}, str(rcx_in[0x63CD8FD]))
    r13_in = reaching_defs("r13")
    for s in SITES[2:]:
        check("r13 at %s only def is walk-B key 0x63cd06b" % hex(s),
              r13_in[s] == {0x63CD06B}, str(r13_in[s]))
    r15_in = reaching_defs("r15")
    for s in SITES:
        check("r15 at %s only def is lea 0x1b0 rbx 0x63cce54" % hex(s),
              r15_in[s] == {0x63CCE54}, str(r15_in[s]))
    rbx_in = reaching_defs("rbx")
    for s in SITES:
        check("rbx at %s only def is entry mov rdi rbx 0x63ccd71" % hex(s),
              rbx_in[s] == {0x63CCD71}, str(rbx_in[s]))
    rdx_in = reaching_defs("rdx")
    rdx_expect = {0x63CD70D: 0x63CD6F8, 0x63CD7B3: 0x63CD79E,
                  0x63CD7F1: 0x63CD7E1, 0x63CD831: 0x63CD821,
                  0x63CD86A: 0x63CD85A, 0x63CD8FD: 0x63CD8F1}
    for s in SITES:
        check("rdx at %s only def is mov r15 rdx %s" % (hex(s), hex(rdx_expect[s])),
              rdx_in[s] == {rdx_expect[s]}, str(rdx_in[s]))
    rdi_in = reaching_defs("rdi")
    rdi_expect = {0x63CD70D: 0x63CD6FB, 0x63CD7B3: 0x63CD7A1,
                  0x63CD7F1: 0x63CD7EA, 0x63CD831: 0x63CD82A,
                  0x63CD86A: 0x63CD863, 0x63CD8FD: 0x63CD8FA}
    for s in SITES:
        check("rdi at %s only def is mov rbx rdi %s" % (hex(s), hex(rdi_expect[s])),
              rdi_in[s] == {rdi_expect[s]}, str(rdi_in[s]))
    rsi_in = reaching_defs("rsi")
    rsi_expect = {0x63CD70D: 0x63CD6EE, 0x63CD7B3: 0x63CD794,
                  0x63CD7F1: 0x63CD7D4, 0x63CD831: 0x63CD814,
                  0x63CD86A: 0x63CD84D, 0x63CD8FD: 0x63CD8E4}
    for s in SITES:
        check("rsi at %s only def is lea 0x6511a00 %s" % (hex(s), hex(rsi_expect[s])),
              rsi_in[s] == {rsi_expect[s]}, str(rsi_in[s]))
    r8_in = reaching_defs("r8")
    r8_expect = {0x63CD70D: 0x63CD6FE, 0x63CD7B3: 0x63CD7A4,
                 0x63CD7F1: 0x63CD7E4, 0x63CD831: 0x63CD824,
                 0x63CD86A: 0x63CD85D, 0x63CD8FD: 0x63CD8F4}
    for s in SITES:
        check("r8 at %s only def is mov 1 r8d %s" % (hex(s), hex(r8_expect[s])),
              r8_in[s] == {r8_expect[s]}, str(r8_in[s]))
    r9_in = reaching_defs("r9")
    r9_expect = {0x63CD70D: 0x63CD6F5, 0x63CD7B3: 0x63CD79B,
                 0x63CD7F1: 0x63CD7DB, 0x63CD831: 0x63CD81B,
                 0x63CD86A: 0x63CD854, 0x63CD8FD: 0x63CD8EB}
    for s in SITES:
        check("r9 at %s only def is xor r9d %s" % (hex(s), hex(r9_expect[s])),
              r9_in[s] == {r9_expect[s]}, str(r9_in[s]))
    rax_in = reaching_defs("rax")
    check("exit rax path-dependent (5 defs reach ret)",
          rax_in[0x63CD044] == {0x63CD01D, 0x63CD135, 0x63CD254, 0x63CD325,
                                0x63CD4FA},
          str(rax_in[0x63CD044]))
    check("records lu-miss sites match census",
          [s.get("site") for s in rec.get("lu_miss_sites", [])] ==
          ["0x63cd70d", "0x63cd7b3", "0x63cd7f1", "0x63cd831", "0x63cd86a",
           "0x63cd8fd"])
    check("records second-handler sites match census",
          [s.get("site") for s in rec.get("second_handler_sites", [])] ==
          ["0x63cd27f"])

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for va in [0x65096C0, 0x6511A00, 0x67277C0, 0x6727A00]:
        check("address %s inside .bss" % hex(va),
              bss[3] <= va < bss[3] + bss[5])
    check("address 0x64da4b0 inside .data.rel.ro",
          secmap[".data.rel.ro"][3] <= 0x64DA4B0 <
          secmap[".data.rel.ro"][3] + secmap[".data.rel.ro"][5])
    txt = secmap[".text"]
    check("0x63c4c40 inside .text",
          txt[3] <= 0x63C4C40 < txt[3] + txt[5])

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
    check("this FDE raw lu-miss 6", counts.get(START, 0) == 6,
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
    check("next candidate raw lu-miss 2", counts.get(0x63CDDD0, 0) == 2,
          str(counts.get(0x63CDDD0, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63CDDD0, 0) == 0,
          str(bti_counts.get(0x63CDDD0, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63CDDD0, 0) == 0,
          str(sh_counts.get(0x63CDDD0, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 9th survivor",
          survey.get("survivors", [None] * 9)[8] == "0x63ccd60",
          str(survey.get("survivors", [])[:10]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window IS shared",
          "0x63ccd60" in survey.get("shared_survivors", []))
    check("survey next candidate NOT shared",
          "0x63cddd0" not in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x63cddd0..0x63ce23b",
          nq.get("range") == "0x63cddd0..0x63ce23b", str(nq.get("range")))
    check("next question bytes 1131", nq.get("bytes") == 1131,
          str(nq.get("bytes")))
    check("next question lu-miss sites 2",
          nq.get("lu_miss_sites") == 2, str(nq.get("lu_miss_sites")))
    check("next question lu-miss site list",
          nq.get("lu_miss_site") == ["0x63ce1f8", "0x63ce221"],
          str(nq.get("lu_miss_site")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 242", nq.get("strict") == 242,
          str(nq.get("strict")))
    check("next question calls 7", nq.get("calls") == 7,
          str(nq.get("calls")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 3",
          nq.get("ret") == ["0x63cdf2f", "0x63cdf43", "0x63cdf7a"],
          str(nq.get("ret")))
    check("records census strict 613",
          rec.get("census", {}).get("strict") == 613)
    check("records census calls 31",
          rec.get("census", {}).get("calls") == 31)
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
    # next candidate 0x63cddd0..0x63ce23b must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63CDDD0 < p[1] and p[0] < 0x63CE23B]
    check("next candidate 0x63cddd0 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63CE23B and 0x63CDDD0 < END))

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
