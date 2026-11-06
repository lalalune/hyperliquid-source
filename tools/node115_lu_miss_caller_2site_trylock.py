"""Static verifier for RE-001-node115-lu-miss-caller-2site-trylock.

Eighth packet of the lu-miss-caller frontier (callers of the lu-miss
handler 0x63d9700 that do not call bin_table_init): FDE
0x63c9650..0x63c9c80, 1584 bytes, 363 strict instructions, 12 calls
(12 direct, 0 indirect, 10 distinct targets), 2 lu-miss sites, 0
bin_table_init sites, 0 second-handler sites, 1 ret at 0x63c9868,
bsr 0, lock sub 1 / lock add 0, 58 jumps, 0 outside the window.

This window is a lu-miss-ONLY survivor: it is in the survey's 16-FDE
lu-miss survivor list but NOT in the 18-FDE second-handler survivor
list, so it consumes one slot of the combined 25-FDE miss-handler pool
without being shared. Unlike #314-#320 it has NO endbr64, NO canary,
NO TLS flag check and NO size class: it is a linked-list traversal
(outer 0x18-next walk) with a pthread_mutex_trylock guard, a
lock-wait-helper retry arm, a three-field ordered-insert key compare,
and one context-table walk keyed by the current node pointer in r12.
The walk re-checks its top compare with flipped operands, the two
8-slot move-to-front scans share one slot set with exactly ONE
reversed-operand compare (the second scan's slot-0 at 0x63c998f), and
the two lu-miss sites share one argument pattern (rdi = r14 context,
rsi = .bss 0x6511a00, rdx = saved walk table, rcx = r12 walk key,
r8d = 1, r9d = 0) with the rcx provenance proven by
reaching-definitions (only mov %rbp,%r12 at 0x63c9713 and
mov %rax,%r12 at 0x63c97fd reach either miss site). Exit: rax is
path-dependent (entry 0x68(%rdi), the unlock return, or the 0x63c9500
return), so no single exit value is established.

Next question: the next lu-miss survivor in address order is
0x63ccd60..0x63cd907 (2983 bytes, 613 strict, 31 calls, 6 lu-miss
sites, 0 bti, 1 second-handler site, 1 ret at 0x63cd044, bsr 0) -- a
SHARED survivor, unlike this packet.

Usage: python3 tools/node115_lu_miss_caller_2site_trylock.py
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
                      "RE-001-node115-lu-miss-caller-2site-trylock")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-2site-trylock"
NAME = "lu_miss_caller_2site_trylock"
START, END = 0x63C9650, 0x63C9C80

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
    check("target FDE size 1584", END - START == 1584)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x63c9500..0x63c964d",
          prev == (0x63C9500, 0x63C964D), str(prev))
    check("prev gap 3", START - prev[1] == 3)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 3, gap.hex())
    check("next FDE 0x63c9c80..0x63cb146",
          nxt == (0x63C9C80, 0x63CB146), str(nxt))
    check("next padding 0", nxt[0] - END == 0)
    check("next FDE starts push r15",
          node[toff(0x63C9C80):toff(0x63C9C80) + 2] == bytes.fromhex("4157"))
    check("next FDE no endbr64",
          node[toff(0x63C9C80):toff(0x63C9C80) + 4] !=
          bytes.fromhex("f30f1efa"))

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 1584", len(hexb) == 1584, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 363", len(lines) == 363, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 12", len(calls) == 12, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63c9868", [addr_of(l) for l in rets] == [0x63C9868],
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
    expect = {0x63C58B0: 1, 0x63F17B0: 1, 0x63C7620: 1, 0x63C50E0: 1,
              0x63C89C0: 1, 0x63C7EF0: 1, 0x63F0B70: 2, 0x63BF680: 1,
              0x63C9500: 1, 0x63D9700: 2}
    check("call target multiset exact", dict(tgt) == expect,
          str(dict(tgt)))
    check("distinct call targets 10", len(tgt) == 10, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 2",
          sorted(a for a, t in ct if t == 0x63D9700) ==
          [0x63C9C29, 0x63C9C76],
          str([hex(a) for a, t in ct if t == 0x63D9700]))
    check("no second-handler sites", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called once", tgt.get(0x63BF680, 0) == 1,
          str(tgt.get(0x63BF680, 0)))
    check("trylock plt called once", tgt.get(0x63F17B0, 0) == 1,
          str(tgt.get(0x63F17B0, 0)))
    check("unlock plt called twice", tgt.get(0x63F0B70, 0) == 2,
          str(tgt.get(0x63F0B70, 0)))
    check("no 0x63be540 helper sites", tgt.get(0x63BE540, 0) == 0,
          str(tgt.get(0x63BE540, 0)))
    check("no 0x63be4d0 helper sites", tgt.get(0x63BE4D0, 0) == 0,
          str(tgt.get(0x63BE4D0, 0)))
    check("no 0x63bd6c0 helper sites", tgt.get(0x63BD6C0, 0) == 0,
          str(tgt.get(0x63BD6C0, 0)))
    check("prev FDE 0x63c9500 called once at 0x63c9a09",
          sorted(a for a, t in ct if t == 0x63C9500) == [0x63C9A09],
          str([hex(a) for a, t in ct if t == 0x63C9500]))
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
    check("#313 window not called", tgt.get(0x63C2F00, 0) == 0,
          str(tgt.get(0x63C2F00, 0)))
    check("#298 window not called", tgt.get(0x6362F90, 0) == 0,
          str(tgt.get(0x6362F90, 0)))
    bsr = [addr_of(l) for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", bsr == [], str([hex(a) for a in bsr]))
    locks = [(addr_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 1", len(locks) == 1, str(locks))
    check("lock is sub", locks[0][0] == 0x63C97D6 and
          "sub" in locks[0][1], str(locks))
    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 58", len(jmps) == 58, str(len(jmps)))
    outside = [(a, t) for a, t in jmps if not (START <= t < END)]
    check("jump closure zero outside", outside == [], str(outside))

    # Entry + frame: NO endbr64, NO canary, entry null guard on (%rsi).
    check("entry no endbr64", "endbr64" not in by_addr[START])
    check("entry push r15", "push" in by_addr[0x63C9650] and
          "%r15" in by_addr[0x63C9650])
    check("entry push r14", "push" in by_addr[0x63C9652] and
          "%r14" in by_addr[0x63C9652])
    check("entry push r13", "push" in by_addr[0x63C9654] and
          "%r13" in by_addr[0x63C9654])
    check("entry push r12", "push" in by_addr[0x63C9656] and
          "%r12" in by_addr[0x63C9656])
    check("entry push rbp", "push" in by_addr[0x63C9658] and
          "%rbp" in by_addr[0x63C9658])
    check("entry push rbx", "push" in by_addr[0x63C9659] and
          "%rbx" in by_addr[0x63C9659])
    check("entry sub 0x38 rsp",
          "sub" in by_addr[0x63C965A] and "$0x38,%rsp" in by_addr[0x63C965A])
    check("entry mov 0x68 rdi rax",
          "mov" in by_addr[0x63C965E] and "0x68(%rdi),%rax" in by_addr[0x63C965E])
    check("entry mov rdi rax to 0x18 rsp",
          "mov" in by_addr[0x63C9665] and "%rax,0x18(%rsp)" in by_addr[0x63C9665])
    check("entry mov rsi head to rdx",
          "mov" in by_addr[0x63C9662] and "(%rsi),%rdx" in by_addr[0x63C9662])
    check("entry null test rdx",
          "test" in by_addr[0x63C966A] and "%rdx,%rdx" in by_addr[0x63C966A])
    check("entry null je epilogue 0x63c985a",
          "je" in by_addr[0x63C966D] and "63c985a" in by_addr[0x63C966D])
    check("entry mov rdi to r14",
          "mov" in by_addr[0x63C9673] and "%rdi,%r14" in by_addr[0x63C9673])
    check("entry mov rsi to r12",
          "mov" in by_addr[0x63C9676] and "%rsi,%r12" in by_addr[0x63C9676])
    check("no canary fs:0x28 anywhere",
          not any("%fs:0x28" in l for l in lines))
    check("no TLS flag fs:0x330 anywhere",
          not any("%fs:0x330" in l for l in lines))
    check("no byte table 0x67277c0 anywhere",
          not any("67277c0" in l for l in lines))
    check("no $0xe7 gate anywhere",
          not any("$0xe7" in l for l in lines))

    # Outer linked-list walk + trylock + lock-wait retry.
    check("list loop mov rdx to r15",
          "mov" in by_addr[0x63C9680] and "%rdx,%r15" in by_addr[0x63C9680])
    check("list loop next 0x18 rdx",
          "mov" in by_addr[0x63C9683] and "0x18(%rdx),%rdx" in by_addr[0x63C9683])
    check("list loop jne 0x63c9680",
          "jne" in by_addr[0x63C968A] and "63c9680" in by_addr[0x63C968A])
    check("helper 0x63c58b0 call args",
          "mov" in by_addr[0x63C968C] and "%r12,%rdi" in by_addr[0x63C968C] and
          "mov" in by_addr[0x63C968F] and "%r15,%rsi" in by_addr[0x63C968F])
    check("helper 0x63c58b0 call",
          "call" in by_addr[0x63C9692] and "63c58b0" in by_addr[0x63C9692])
    check("node head mov r15 rbx",
          "mov" in by_addr[0x63C9697] and "(%r15),%rbx" in by_addr[0x63C9697])
    check("trylock lea 0x40 rbx",
          "lea" in by_addr[0x63C969A] and "0x40(%rbx),%rdi" in by_addr[0x63C969A])
    check("trylock call",
          "call" in by_addr[0x63C969E] and "63f17b0" in by_addr[0x63C969E])
    check("trylock test eax",
          "test" in by_addr[0x63C96A3] and "%eax,%eax" in by_addr[0x63C96A3])
    check("trylock fail jne 0x63c99d8",
          "jne" in by_addr[0x63C96A5] and "63c99d8" in by_addr[0x63C96A5])
    check("lock-wait mov rbx rdi",
          "mov" in by_addr[0x63C99D8] and "%rbx,%rdi" in by_addr[0x63C99D8])
    check("lock-wait call 0x63bf680",
          "call" in by_addr[0x63C99DB] and "63bf680" in by_addr[0x63C99DB])
    check("lock-wait set byte 0x68 rbx",
          "movb" in by_addr[0x63C99E0] and "$0x1,0x68(%rbx)" in by_addr[0x63C99E0])
    check("lock-wait jmp retry 0x63c96ab",
          "jmp" in by_addr[0x63C99E4] and "63c96ab" in by_addr[0x63C99E4])
    check("refcount addq 0x38 rbx",
          "addq" in by_addr[0x63C96AB] and "$0x1,0x38(%rbx)" in by_addr[0x63C96AB])
    check("owner cmp 0x30 rbx r14",
          "cmp" in by_addr[0x63C96B0] and "0x30(%rbx),%r14" in by_addr[0x63C96B0])
    check("owner update addq 0x28 rbx",
          "addq" in by_addr[0x63C96B6] and "$0x1,0x28(%rbx)" in by_addr[0x63C96B6])
    check("node key mov 0x10 r15 rbp",
          "mov" in by_addr[0x63C96BF] and "0x10(%r15),%rbp" in by_addr[0x63C96BF])
    check("node key lea 0x10 r15 r13",
          "lea" in by_addr[0x63C96C3] and "0x10(%r15),%r13" in by_addr[0x63C96C3])
    check("node key null je 0x63c980e",
          "je" in by_addr[0x63C96CA] and "63c980e" in by_addr[0x63C96CA])

    # Field dispatch via 0x63c7620 + 0x84 field.
    check("field helper rsi 0x70 rbp",
          "mov" in by_addr[0x63C96D0] and "0x70(%rbp),%rsi" in by_addr[0x63C96D0])
    check("field helper rcx r14",
          "mov" in by_addr[0x63C96D4] and "%r14,%rcx" in by_addr[0x63C96D4])
    check("field helper rdx callback 0x63c4c40",
          "lea" in by_addr[0x63C96D7] and "63c4c40" in by_addr[0x63C96D7])
    check("field helper rdi r13",
          "mov" in by_addr[0x63C96DE] and "%r13,%rdi" in by_addr[0x63C96DE])
    check("field helper call 0x63c7620",
          "call" in by_addr[0x63C96E1] and "63c7620" in by_addr[0x63C96E1])
    check("field helper test rax",
          "test" in by_addr[0x63C96E6] and "%rax,%rax" in by_addr[0x63C96E6])
    check("field helper nonzero jne 0x63c9920",
          "jne" in by_addr[0x63C96E9] and "63c9920" in by_addr[0x63C96E9])
    check("field 0x84 mov ecx",
          "mov" in by_addr[0x63C96EF] and "0x84(%rbp),%ecx" in by_addr[0x63C96EF])
    check("field cmp 2",
          "cmp" in by_addr[0x63C96F5] and "$0x2,%ecx" in by_addr[0x63C96F5])
    check("field cmp 2 je 0x63c9870",
          "je" in by_addr[0x63C96F8] and "63c9870" in by_addr[0x63C96F8])
    check("field set 1 at 0x63c9870",
          "movl" in by_addr[0x63C9870] and "$0x1,0x84(%rbp)" in by_addr[0x63C9870])
    check("field cmp 3",
          "cmp" in by_addr[0x63C96FE] and "$0x3,%ecx" in by_addr[0x63C96FE])
    check("field cmp 3 jne 0x63c987a",
          "jne" in by_addr[0x63C9701] and "63c987a" in by_addr[0x63C9701])
    check("chain advance mov 0x78 rbp rsi",
          "mov" in by_addr[0x63C987A] and "0x78(%rbp),%rsi" in by_addr[0x63C987A])
    check("chain advance and fe rbp",
          "and" in by_addr[0x63C9881] and "$0xfffffffffffffffe,%rbp" in by_addr[0x63C9881])
    check("chain advance ja 0x63c96d0",
          "ja" in by_addr[0x63C9889] and "63c96d0" in by_addr[0x63C9889])
    check("chain end jmp 0x63c980e",
          "jmp" in by_addr[0x63C988F] and "63c980e" in by_addr[0x63C988F])

    # Walk entry: table pointer + key load.
    check("walk lea 0x1b0 r14 rdi",
          "lea" in by_addr[0x63C9707] and "0x1b0(%r14),%rdi" in by_addr[0x63C9707])
    check("walk save r12 to 0x8 rsp",
          "mov" in by_addr[0x63C970E] and "%r12,0x8(%rsp)" in by_addr[0x63C970E])
    check("walk key mov rbp to r12",
          "mov" in by_addr[0x63C9713] and "%rbp,%r12" in by_addr[0x63C9713])
    check("walk save table to 0x10 rsp",
          "mov" in by_addr[0x63C9716] and "%rdi,0x10(%rsp)" in by_addr[0x63C9716])
    check("walk 0x78 mov r12 rdi",
          "mov" in by_addr[0x63C971B] and "0x78(%r12),%rdi" in by_addr[0x63C971B])
    check("walk 0x78 cmp 1",
          "cmp" in by_addr[0x63C9720] and "$0x1,%rdi" in by_addr[0x63C9720])
    check("walk 0x78 jbe 0x63c9898",
          "jbe" in by_addr[0x63C9724] and "63c9898" in by_addr[0x63C9724])
    check("walk chain mov rdi rbx",
          "mov" in by_addr[0x63C9730] and "%rdi,%rbx" in by_addr[0x63C9730])
    check("walk chain mov 0x70 rdi",
          "mov" in by_addr[0x63C9733] and "0x70(%rdi),%rdi" in by_addr[0x63C9733])
    check("walk helper call 0x63c50e0",
          "call" in by_addr[0x63C9742] and "63c50e0" in by_addr[0x63C9742])
    check("walk top shr 0x1a r10",
          "shr" in by_addr[0x63C974D] and "$0x1a,%r10" in by_addr[0x63C974D])
    check("walk high bits and r11",
          "and" in by_addr[0x63C9751] and
          "$0xffffffffc0000000,%r11" in by_addr[0x63C9751])
    check("walk top index and f0",
          "and" in by_addr[0x63C9758] and "$0xf0,%r10d" in by_addr[0x63C9758])
    check("walk top add r14 r10",
          "add" in by_addr[0x63C975F] and "%r14,%r10" in by_addr[0x63C975F])
    check("walk top load 0x1b0 r10 rdx",
          "mov" in by_addr[0x63C9762] and "0x1b0(%r10),%rdx" in by_addr[0x63C9762])
    check("walk top cmp rdx r11",
          "cmp" in by_addr[0x63C9769] and "%rdx,%r11" in by_addr[0x63C9769])
    check("walk top jne scan A 0x63c9930",
          "jne" in by_addr[0x63C976C] and "63c9930" in by_addr[0x63C976C])
    check("walk second shr 0x9 rax",
          "shr" in by_addr[0x63C9775] and "$0x9,%rax" in by_addr[0x63C9775])
    check("walk second and 0x1ffff8",
          "and" in by_addr[0x63C9779] and "$0x1ffff8,%eax" in by_addr[0x63C9779])
    check("walk second add 0x1b8 r10",
          "add" in by_addr[0x63C977E] and "0x1b8(%r10),%rax" in by_addr[0x63C977E])
    check("walk second deref rbp",
          "mov" in by_addr[0x63C9785] and "(%rax),%rbp" in by_addr[0x63C9785])
    check("extract lea size table 0x6727a00",
          "lea" in by_addr[0x63C9788] and "6727a00" in by_addr[0x63C9788])
    check("extract shr 0x30 rbp",
          "shr" in by_addr[0x63C978F] and "$0x30,%rbp" in by_addr[0x63C978F])
    check("extract size table load",
          "mov" in by_addr[0x63C9793] and "(%rax,%rbp,8),%rbp" in by_addr[0x63C9793])
    check("walk second cmp r11 rdx flipped",
          "cmp" in by_addr[0x63C9797] and "%r11,%rdx" in by_addr[0x63C9797])
    check("walk second jne scan B 0x63c9988",
          "jne" in by_addr[0x63C979A] and "63c9988" in by_addr[0x63C979A])
    check("extract lea node table 0x65096c0",
          "lea" in by_addr[0x63C97B6] and "65096c0" in by_addr[0x63C97B6])
    check("extract shl 0x10 r11",
          "shl" in by_addr[0x63C97BD] and "$0x10,%r11" in by_addr[0x63C97BD])
    check("extract sar 0x10 r11",
          "sar" in by_addr[0x63C97C1] and "$0x10,%r11" in by_addr[0x63C97C1])
    check("extract and 80 r11",
          "and" in by_addr[0x63C97C5] and
          "$0xffffffffffffff80,%r11" in by_addr[0x63C97C5])
    check("extract node load rdi",
          "mov" in by_addr[0x63C97C9] and "(%r11),%rdi" in by_addr[0x63C97C9])
    check("extract and fff edi",
          "and" in by_addr[0x63C97CC] and "$0xfff,%edi" in by_addr[0x63C97CC])
    check("extract node table load r8",
          "mov" in by_addr[0x63C97D2] and "(%rax,%rdi,8),%r8" in by_addr[0x63C97D2])
    check("lock sub rbp 0x38 r8",
          "lock" in by_addr[0x63C97D6] and "sub" in by_addr[0x63C97D6] and
          "%rbp,0x38(%r8)" in by_addr[0x63C97D6])
    check("helper 0x63c89c0 call",
          "call" in by_addr[0x63C97E1] and "63c89c0" in by_addr[0x63C97E1])
    check("rbx null je 0x63c9809",
          "je" in by_addr[0x63C97E9] and "63c9809" in by_addr[0x63C97E9])
    check("helper 0x63c7ef0 call",
          "call" in by_addr[0x63C97F8] and "63c7ef0" in by_addr[0x63C97F8])
    check("next key mov rax to r12",
          "mov" in by_addr[0x63C97FD] and "%rax,%r12" in by_addr[0x63C97FD])
    check("next key nonzero jne 0x63c971b",
          "jne" in by_addr[0x63C9803] and "63c971b" in by_addr[0x63C9803])

    # Scan: slot-0 compares (A normal, B reversed), loops, swaps.
    check("scan A slot-0 mov 0x2b0",
          "mov" in by_addr[0x63C9930] and "0x2b0(%r14),%rsi" in by_addr[0x63C9930])
    check("scan A slot-0 cmp normal",
          "cmp" in by_addr[0x63C9937] and "%rsi,%r11" in by_addr[0x63C9937])
    check("scan A slot-0 jne loop 0x63c9a13",
          "jne" in by_addr[0x63C993A] and "63c9a13" in by_addr[0x63C993A])
    check("scan A swap mov rdx 0x2b0",
          "mov" in by_addr[0x63C9940] and "%rdx,0x2b0(%r14)" in by_addr[0x63C9940])
    check("scan A swap jmp rejoin 0x63c9785",
          "jmp" in by_addr[0x63C997D] and "63c9785" in by_addr[0x63C997D])
    check("scan B slot-0 mov 0x2b0",
          "mov" in by_addr[0x63C9988] and "0x2b0(%r14),%rsi" in by_addr[0x63C9988])
    check("scan B slot-0 cmp REVERSED",
          "cmp" in by_addr[0x63C998F] and "%r11,%rsi" in by_addr[0x63C998F])
    check("scan B slot-0 jne loop 0x63c9a74",
          "jne" in by_addr[0x63C9992] and "63c9a74" in by_addr[0x63C9992])
    check("scan B swap jmp rejoin 0x63c97b3",
          "jmp" in by_addr[0x63C99D3] and "63c97b3" in by_addr[0x63C99D3])
    loop_a = [0x63C9A21, 0x63C9AD8, 0x63C9B1E, 0x63C9B2E, 0x63C9B8E,
              0x63C9B9E, 0x63C9BF7]
    loop_b = [0x63C9A82, 0x63C9AF6, 0x63C9B56, 0x63C9B66, 0x63C9BC6,
              0x63C9BD6, 0x63C9C4E]
    slot_offs = ["0x2c0", "0x2d0", "0x2e0", "0x2f0", "0x300", "0x310", "0x320"]
    # Slots 1-6 load the slot value into a register first, then compare
    # it (slot-value-first, normal order) against the key in %r11;
    # slot 7 compares the memory operand directly.
    slot_regs = ["%r8", "%rsi", "%r9", "%rsi", "%rcx", "%rsi"]
    slot_loads_a = [0x63C9A13, 0x63C9AD1, 0x63C9B0D, 0x63C9B27, 0x63C9B7D,
                    0x63C9B97]
    slot_loads_b = [0x63C9A74, 0x63C9AEF, 0x63C9B45, 0x63C9B5F, 0x63C9BB5,
                    0x63C9BCF]
    for k in range(6):
        for tag, loads, cmps in (("A", slot_loads_a, loop_a),
                                 ("B", slot_loads_b, loop_b)):
            check("scan %s slot %d load %s" % (tag, k + 1, slot_offs[k]),
                  "mov" in by_addr[loads[k]]
                  and (slot_offs[k] + "(%r14)," + slot_regs[k])
                  in by_addr[loads[k]],
                  by_addr[loads[k]])
            check("scan %s slot %d cmp normal at %s"
                  % (tag, k + 1, hex(cmps[k])),
                  "cmp" in by_addr[cmps[k]]
                  and (slot_regs[k] + ",%r11") in by_addr[cmps[k]],
                  by_addr[cmps[k]])
    for tag, cmps in (("A", loop_a), ("B", loop_b)):
        check("scan %s slot 7 cmp direct 0x320" % tag,
              "cmp" in by_addr[cmps[6]]
              and "0x320(%r14),%r11" in by_addr[cmps[6]],
              by_addr[cmps[6]])
    scan_cmps = []
    for l in lines:
        a = addr_of(l)
        if 0x63C9930 <= a < 0x63C9C80 and re.search(r"\tcmp\s", l):
            scan_cmps.append(l)
    check("scan-region cmp count 16", len(scan_cmps) == 16,
          str(len(scan_cmps)))
    rev = [l for l in scan_cmps
           if re.search(r"\tcmp\s+%r11,", l)]
    check("reversed-operand scan compares exactly 1",
          [addr_of(l) for l in rev] == [0x63C998F],
          str([hex(addr_of(l)) for l in rev]))
    check("scan A slot-7 fallthrough to miss 1",
          "cmp" in by_addr[0x63C9BF7] and "0x320(%r14),%r11" in by_addr[0x63C9BF7])
    check("scan B slot-7 fallthrough to miss 2",
          "cmp" in by_addr[0x63C9C4E] and "0x320(%r14),%r11" in by_addr[0x63C9C4E])

    # Lu-miss sites: argument setup.
    check("miss 1 rdx mov 0x10 rsp",
          "mov" in by_addr[0x63C9C04] and "0x10(%rsp),%rdx" in by_addr[0x63C9C04])
    check("miss 1 xor r9d",
          "xor" in by_addr[0x63C9C09] and "%r9d,%r9d" in by_addr[0x63C9C09])
    check("miss 1 mov r12 rcx",
          "mov" in by_addr[0x63C9C0C] and "%r12,%rcx" in by_addr[0x63C9C0C])
    check("miss 1 mov r14 rdi",
          "mov" in by_addr[0x63C9C0F] and "%r14,%rdi" in by_addr[0x63C9C0F])
    check("miss 1 lea 0x6511a00 rsi",
          "lea" in by_addr[0x63C9C12] and "6511a00" in by_addr[0x63C9C12])
    check("miss 1 mov 1 r8d",
          "mov" in by_addr[0x63C9C19] and "$0x1,%r8d" in by_addr[0x63C9C19])
    check("miss 1 call 0x63d9700",
          "call" in by_addr[0x63C9C29] and "63d9700" in by_addr[0x63C9C29])
    check("miss 1 restore r10",
          "mov" in by_addr[0x63C9C2E] and "0x28(%rsp),%r10" in by_addr[0x63C9C2E])
    check("miss 1 restore r11",
          "mov" in by_addr[0x63C9C33] and "0x20(%rsp),%r11" in by_addr[0x63C9C33])
    check("miss 1 rejoin jmp 0x63c9785",
          "jmp" in by_addr[0x63C9C3F] and "63c9785" in by_addr[0x63C9C3F])
    check("miss 2 rdx mov 0x10 rsp",
          "mov" in by_addr[0x63C9C5B] and "0x10(%rsp),%rdx" in by_addr[0x63C9C5B])
    check("miss 2 xor r9d",
          "xor" in by_addr[0x63C9C60] and "%r9d,%r9d" in by_addr[0x63C9C60])
    check("miss 2 mov r12 rcx",
          "mov" in by_addr[0x63C9C63] and "%r12,%rcx" in by_addr[0x63C9C63])
    check("miss 2 mov r14 rdi",
          "mov" in by_addr[0x63C9C66] and "%r14,%rdi" in by_addr[0x63C9C66])
    check("miss 2 lea 0x6511a00 rsi",
          "lea" in by_addr[0x63C9C69] and "6511a00" in by_addr[0x63C9C69])
    check("miss 2 mov 1 r8d",
          "mov" in by_addr[0x63C9C70] and "$0x1,%r8d" in by_addr[0x63C9C70])
    check("miss 2 call 0x63d9700",
          "call" in by_addr[0x63C9C76] and "63d9700" in by_addr[0x63C9C76])
    check("miss 2 rejoin jmp 0x63c97b3",
          "jmp" in by_addr[0x63C9C7B] and "63c97b3" in by_addr[0x63C9C7B])

    # CFG: successors (jump targets inside window + fall-through; calls
    # fall through except noreturn PLT calls; ret is terminal).
    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

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

    check("entry reaches lu-miss site 1", reaches(START, 0x63C9C29))
    check("entry reaches lu-miss site 2", reaches(START, 0x63C9C76))
    check("entry reaches ret", reaches(START, 0x63C9868))

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

    r12_in = reaching_defs("r12")
    check("miss 1 rcx key defs are 0x63c9713 and 0x63c97fd",
          r12_in[0x63C9C29] == {0x63C9713, 0x63C97FD},
          str(r12_in[0x63C9C29]))
    check("miss 2 rcx key defs are 0x63c9713 and 0x63C97FD",
          r12_in[0x63C9C76] == {0x63C9713, 0x63C97FD},
          str(r12_in[0x63C9C76]))
    check("entry r12 def 0x63c9676 does not reach miss 1",
          0x63C9676 not in r12_in[0x63C9C29],
          str(r12_in[0x63C9C29]))
    check("tail r12 restore 0x63c9809 does not reach miss 1",
          0x63C9809 not in r12_in[0x63C9C29],
          str(r12_in[0x63C9C29]))
    rcx_in = reaching_defs("rcx")
    check("miss 1 rcx only def is mov r12 rcx 0x63c9c0c",
          rcx_in[0x63C9C29] == {0x63C9C0C}, str(rcx_in[0x63C9C29]))
    check("miss 2 rcx only def is mov r12 rcx 0x63c9c63",
          rcx_in[0x63C9C76] == {0x63C9C63}, str(rcx_in[0x63C9C76]))
    rdx_in = reaching_defs("rdx")
    check("miss 1 rdx only def is mov 0x10 rsp 0x63c9c04",
          rdx_in[0x63C9C29] == {0x63C9C04}, str(rdx_in[0x63C9C29]))
    check("miss 2 rdx only def is mov 0x10 rsp 0x63c9c5b",
          rdx_in[0x63C9C76] == {0x63C9C5B}, str(rdx_in[0x63C9C76]))
    rdi_in = reaching_defs("rdi")
    check("miss 1 rdi only def is mov r14 rdi 0x63c9c0f",
          rdi_in[0x63C9C29] == {0x63C9C0F}, str(rdi_in[0x63C9C29]))
    check("miss 2 rdi only def is mov r14 rdi 0x63c9c66",
          rdi_in[0x63C9C76] == {0x63C9C66}, str(rdi_in[0x63C9C76]))
    rsi_in = reaching_defs("rsi")
    check("miss 1 rsi only def is lea 0x6511a00 0x63c9c12",
          rsi_in[0x63C9C29] == {0x63C9C12}, str(rsi_in[0x63C9C29]))
    check("miss 2 rsi only def is lea 0x6511a00 0x63c9c69",
          rsi_in[0x63C9C76] == {0x63C9C69}, str(rsi_in[0x63C9C76]))
    r8_in = reaching_defs("r8")
    check("miss 1 r8 only def is mov 1 r8d 0x63c9c19",
          r8_in[0x63C9C29] == {0x63C9C19}, str(r8_in[0x63C9C29]))
    check("miss 2 r8 only def is mov 1 r8d 0x63c9c70",
          r8_in[0x63C9C76] == {0x63C9C70}, str(r8_in[0x63C9C76]))
    r9_in = reaching_defs("r9")
    check("miss 1 r9 only def is xor r9d 0x63c9c09",
          r9_in[0x63C9C29] == {0x63C9C09}, str(r9_in[0x63C9C29]))
    check("miss 2 r9 only def is xor r9d 0x63c9c60",
          r9_in[0x63C9C76] == {0x63C9C60}, str(r9_in[0x63C9C76]))
    rax_in = reaching_defs("rax")
    check("exit rax path-dependent (3 defs reach ret)",
          rax_in[0x63C9868] == {0x63C965E, ("CALL", 0x63C9848),
                                ("CALL", 0x63C9A09)},
          str(rax_in[0x63C9868]))
    check("records lu-miss sites match census",
          [s.get("site") for s in rec.get("lu_miss_sites", [])] ==
          ["0x63c9c29", "0x63c9c76"])
    check("records second-handler sites empty",
          rec.get("second_handler_sites", None) == [])

    # Tail / epilogue.
    check("tail restore r12 from 0x8 rsp",
          "mov" in by_addr[0x63C9809] and "0x8(%rsp),%r12" in by_addr[0x63C9809])
    check("tail count mov 0x8 r15 r13d",
          "mov" in by_addr[0x63C980E] and "0x8(%r15),%r13d" in by_addr[0x63C980E])
    check("tail flag lea 0x6713601",
          "lea" in by_addr[0x63C9812] and "6713601" in by_addr[0x63C9812])
    check("tail flag cmpb 0",
          "cmpb" in by_addr[0x63C9820] and "$0x0,(%rbx)" in by_addr[0x63C9820])
    check("tail last-ref je 0x63c99e9",
          "je" in by_addr[0x63C9833] and "63c99e9" in by_addr[0x63C9833])
    check("tail clear byte 0x68 rdi",
          "movb" in by_addr[0x63C9840] and "$0x0,0x68(%rdi)" in by_addr[0x63C9840])
    check("tail unlock call 0x63f0b70",
          "call" in by_addr[0x63C9848] and "63f0b70" in by_addr[0x63C9848])
    check("tail next head mov r12 rdx",
          "mov" in by_addr[0x63C984D] and "(%r12),%rdx" in by_addr[0x63C984D])
    check("tail next head jne 0x63c9680",
          "jne" in by_addr[0x63C9854] and "63c9680" in by_addr[0x63C9854])
    check("last-ref set count 1",
          "movl" in by_addr[0x63C99E9] and "$0x1,0x8(%r15)" in by_addr[0x63C99E9])
    check("last-ref unlock call 0x63f0b70",
          "call" in by_addr[0x63C99F9] and "63f0b70" in by_addr[0x63C99F9])
    check("last-ref helper call 0x63c9500",
          "call" in by_addr[0x63C9A09] and "63c9500" in by_addr[0x63C9A09])
    check("epilogue add 0x38 rsp",
          "add" in by_addr[0x63C985A] and "$0x38,%rsp" in by_addr[0x63C985A])
    check("epilogue pop rbx",
          "pop" in by_addr[0x63C985E] and "%rbx" in by_addr[0x63C985E])
    check("epilogue pop r15",
          "pop" in by_addr[0x63C9866] and "%r15" in by_addr[0x63C9866])
    check("no rax write in epilogue 0x63c985a..0x63c9868",
          not any(dst_reg(by_addr[a]) in ("%rax", "%eax")
                  for a in by_addr if 0x63C985A <= a <= 0x63C9868),
          str([(hex(a), by_addr[a]) for a in by_addr
               if 0x63C985A <= a <= 0x63C9868
               and dst_reg(by_addr[a]) in ("%rax", "%eax")]))

    # Ordered-insert three-field compare.
    check("insert cmp field 0x8",
          "mov" in by_addr[0x63C98B0] and "0x8(%rax),%r11" in by_addr[0x63C98B0])
    check("insert cmp field 0x10",
          "mov" in by_addr[0x63C98C6] and "0x10(%rax),%rcx" in by_addr[0x63C98C6])
    check("insert cmp field 0x68",
          "mov" in by_addr[0x63C98DC] and "0x68(%rax),%rsi" in by_addr[0x63C98DC])
    check("insert chain mov 0x78 rax",
          "mov" in by_addr[0x63C9900] and "0x78(%rax),%rax" in by_addr[0x63C9900])
    check("insert take node mov rax rbx",
          "mov" in by_addr[0x63C9915] and "%rax,%rbx" in by_addr[0x63C9915])

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for va in [0x65096C0, 0x6511A00, 0x6713601, 0x6727A00]:
        check("address %s inside .bss" % hex(va),
              bss[3] <= va < bss[3] + bss[5])
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
    check("next candidate raw lu-miss 6", counts.get(0x63CCD60, 0) == 6,
          str(counts.get(0x63CCD60, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63CCD60, 0) == 0,
          str(bti_counts.get(0x63CCD60, 0)))
    check("next candidate raw second-handler 1",
          sh_counts.get(0x63CCD60, 0) == 1,
          str(sh_counts.get(0x63CCD60, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 8th survivor",
          survey.get("survivors", [None] * 8)[7] == "0x63c9650",
          str(survey.get("survivors", [])[:9]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window NOT shared",
          "0x63c9650" not in survey.get("shared_survivors", []))
    check("survey next candidate IS shared",
          "0x63ccd60" in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x63ccd60..0x63cd907",
          nq.get("range") == "0x63ccd60..0x63cd907", str(nq.get("range")))
    check("next question bytes 2983", nq.get("bytes") == 2983,
          str(nq.get("bytes")))
    check("next question lu-miss sites 6",
          nq.get("lu_miss_sites") == 6, str(nq.get("lu_miss_sites")))
    check("next question lu-miss site list",
          nq.get("lu_miss_site") == ["0x63cd70d", "0x63cd7b3", "0x63cd7f1",
                                     "0x63cd831", "0x63cd86a", "0x63cd8fd"],
          str(nq.get("lu_miss_site")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 613", nq.get("strict") == 613,
          str(nq.get("strict")))
    check("next question calls 31", nq.get("calls") == 31,
          str(nq.get("calls")))
    check("next question second-handler sites 1",
          nq.get("second_handler_sites") == 1,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question ret 0x63cd044", nq.get("ret") == "0x63cd044",
          str(nq.get("ret")))
    check("records census strict 363",
          rec.get("census", {}).get("strict") == 363)
    check("records census calls 12",
          rec.get("census", {}).get("calls") == 12)
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
    # next candidate 0x63ccd60..0x63cd907 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63CCD60 < p[1] and p[0] < 0x63CD907]
    check("next candidate 0x63ccd60 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63CD907 and 0x63CCD60 < END))

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
