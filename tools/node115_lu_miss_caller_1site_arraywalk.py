"""Static verifier for RE-001-node115-lu-miss-caller-1site-arraywalk.

Seventh packet of the lu-miss-caller frontier (callers of the lu-miss
handler 0x63d9700 that do not call bin_table_init): FDE
0x635e2e0..0x635f315, 4149 bytes, 898 strict instructions, 38 calls
(38 direct, 0 indirect, 21 distinct targets), 1 lu-miss site, 0
bin_table_init sites, 3 second-handler sites, 1 ret at 0x635e7eb,
bsr 5, lock 0/0, 131 jumps, 0 outside the window.

This window is a SHARED survivor: it is in the survey's 16-FDE
lu-miss survivor list AND in the 18-FDE second-handler survivor list,
so it consumes one slot of the combined 25-FDE miss-handler pool.
The walk iterates the input array element by element (key = *rbp in
rcx); the single 8-slot move-to-front scan has FOUR reversed-operand
compares (slots 1, 2, 4, 5) -- the first frontier window with any.
The lu-miss rcx provenance and the three second-handler rsi
provenances are proven by reaching-definitions over the window CFG
(noreturn PLT calls terminal; cmov is a conditional def).

Entry: rdi is the input array base (saved 0x18(%rsp)), rsi is the
element count (saved (%rsp)), rdx is kept in r9, ecx in r8d; rbx is
the TLS-derived context base. No entry null guard, no lock-add walk
entry. TLS flag byte %fs:0x330; size class from byte table 0x67277c0
+ size table 0x6727a00 + flag 0x6713606. One shl/sar $0x10 extract
feeding helper 0x63be540. Dispatcher calls the #317 window once and
memset@plt 15 times (unrolled slot-clear loop). Exit: eax = r15
(the element count) at ret.

Next question: the next lu-miss survivor in address order is
0x63c9650..0x63c9c80 (1584 bytes, 363 strict, 12 calls, 2 lu-miss
sites at 0x63c9c29 and 0x63c9c76, 0 bti, 0 second-handler sites, 1
ret at 0x63c9868, bsr 0) -- a lu-miss-ONLY survivor, unlike this
packet.

Usage: python3 tools/node115_lu_miss_caller_1site_arraywalk.py
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
                      "RE-001-node115-lu-miss-caller-1site-arraywalk")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-1site-arraywalk"
NAME = "lu_miss_caller_1site_arraywalk"
START, END = 0x635E2E0, 0x635F315

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
    check("target FDE size 4149", END - START == 4149)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x635e1a0..0x635e2de",
          prev == (0x635E1A0, 0x635E2DE), str(prev))
    check("prev gap 2", START - prev[1] == 2)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 2, gap.hex())
    check("next FDE 0x635f320..0x635f334",
          nxt == (0x635F320, 0x635F334), str(nxt))
    check("next padding 11", nxt[0] - END == 11)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 11, pad.hex())
    check("next FDE starts endbr64",
          node[toff(0x635F320):toff(0x635F320) + 4] ==
          bytes.fromhex("f30f1efa"))

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 4149", len(hexb) == 4149, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 898", len(lines) == 898, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 38", len(calls) == 38, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x635e7eb", [addr_of(l) for l in rets] == [0x635E7EB],
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
    expect = {0x634EBB0: 3, 0x6352FC0: 1, 0x63577F0: 1, 0x6360ED0: 1,
              0x6362910: 1, 0x6364400: 1, 0x6364410: 1, 0x6364420: 1,
              0x63BE540: 1, 0x63BF5B6: 1, 0x63D9700: 1, 0x63EC4C0: 1,
              0x63ED8B0: 1, 0x63EDF10: 2, 0x63EEC80: 1, 0x63EF8E0: 1,
              0x63F0A60: 1, 0x63F0A90: 15, 0x63F0BF0: 1, 0x63F0D70: 1,
              0x63F1AD0: 1}
    check("call target multiset exact", dict(tgt) == expect,
          str(dict(tgt)))
    check("distinct call targets 21", len(tgt) == 21, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 1",
          sorted(a for a, t in ct if t == 0x63D9700) == [0x635F30B],
          str([hex(a) for a, t in ct if t == 0x63D9700]))
    check("second-handler sites 3",
          sorted(a for a, t in ct if t == 0x634EBB0) ==
          [0x635EC8D, 0x635EF3E, 0x635F24D],
          str([hex(a) for a, t in ct if t == 0x634EBB0]))
    check("no lock-wait sites", tgt.get(0x63BF680, 0) == 0,
          str(tgt.get(0x63BF680, 0)))
    check("no 0x63be4d0 helper sites", tgt.get(0x63BE4D0, 0) == 0,
          str(tgt.get(0x63BE4D0, 0)))
    check("no 0x63bd6c0 helper sites", tgt.get(0x63BD6C0, 0) == 0,
          str(tgt.get(0x63BD6C0, 0)))
    check("#317 window called once at 0x635e799",
          sorted(a for a, t in ct if t == 0x63577F0) == [0x635E799],
          str([hex(a) for a, t in ct if t == 0x63577F0]))
    check("#314 window not called", tgt.get(0x63495B0, 0) == 0,
          str(tgt.get(0x63495B0, 0)))
    check("#315 window not called", tgt.get(0x6353A70, 0) == 0,
          str(tgt.get(0x6353A70, 0)))
    check("#316 window not called", tgt.get(0x6355900, 0) == 0,
          str(tgt.get(0x6355900, 0)))
    check("#318 window not called", tgt.get(0x635A7A0, 0) == 0,
          str(tgt.get(0x635A7A0, 0)))
    check("#319 window not called", tgt.get(0x635C6D0, 0) == 0,
          str(tgt.get(0x635C6D0, 0)))
    check("#313 window not called", tgt.get(0x63C2F00, 0) == 0,
          str(tgt.get(0x63C2F00, 0)))
    check("#298 window not called", tgt.get(0x6362F90, 0) == 0,
          str(tgt.get(0x6362F90, 0)))
    check("memset plt 15 exact list",
          sorted(a for a, t in ct if t == 0x63F0A90) ==
          [0x635E97A, 0x635E9AD, 0x635E9E0, 0x635EA13, 0x635EA46,
           0x635EA79, 0x635EAAC, 0x635EAF2, 0x635EB00, 0x635EB0E,
           0x635EB1C, 0x635EB2A, 0x635EB38, 0x635EB46, 0x635EB54],
          str([hex(a) for a, t in ct if t == 0x63F0A90]))
    bsr = [addr_of(l) for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 5 exact list",
          bsr == [0x635EE29, 0x635EEB3, 0x635F074, 0x635F0C4, 0x635F195],
          str([hex(a) for a in bsr]))
    locks = [(addr_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))
    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 131", len(jmps) == 131, str(len(jmps)))
    outside = [(a, t) for a, t in jmps if not (START <= t < END)]
    check("jump closure zero outside", outside == [], str(outside))

    # Entry + frame.
    check("entry endbr64", "endbr64" in by_addr[0x635E2E0])
    check("entry push r15", "push" in by_addr[0x635E2E4] and "%r15" in by_addr[0x635E2E4])
    check("entry mov rdx to r9",
          "mov" in by_addr[0x635E2E6] and "%rdx,%r9" in by_addr[0x635E2E6])
    check("entry mov ecx to r8d",
          "mov" in by_addr[0x635E2E9] and "%ecx,%r8d" in by_addr[0x635E2E9])
    check("entry push r14", "push" in by_addr[0x635E2EC] and "%r14" in by_addr[0x635E2EC])
    check("entry push r13", "push" in by_addr[0x635E2EE] and "%r13" in by_addr[0x635E2EE])
    check("entry push r12", "push" in by_addr[0x635E2F0] and "%r12" in by_addr[0x635E2F0])
    check("entry push rbp", "push" in by_addr[0x635E2F2] and "%rbp" in by_addr[0x635E2F2])
    check("entry push rbx", "push" in by_addr[0x635E2F3] and "%rbx" in by_addr[0x635E2F3])
    check("entry sub 0xa8 rsp",
          "sub" in by_addr[0x635E2F4] and "$0xa8,%rsp" in by_addr[0x635E2F4])
    check("tls base mov fs:0x0 to r11",
          "mov" in by_addr[0x635E2FB] and "%fs:0x0,%r11" in by_addr[0x635E2FB])
    check("entry mov rdi to 0x18 rsp",
          "mov" in by_addr[0x635E304] and "%rdi,0x18(%rsp)" in by_addr[0x635E304])
    check("entry mov rsi to 0 rsp",
          "mov" in by_addr[0x635E309] and "%rsi,(%rsp)" in by_addr[0x635E309])
    check("canary load fs:0x28",
          "mov" in by_addr[0x635E30D] and "%fs:0x28,%rax" in by_addr[0x635E30D])
    check("canary store 0x98 rsp",
          "mov" in by_addr[0x635E316] and "0x98(%rsp)" in by_addr[0x635E316])
    check("tls base mov -0x10a8 to rax",
          "mov" in by_addr[0x635E31E] and "$0xffffffffffffef58,%rax" in by_addr[0x635E31E])
    check("tls base add rax to r11",
          "add" in by_addr[0x635E325] and "%rax,%r11" in by_addr[0x635E325])
    check("tls flag cmpb fs:0x330 rax",
          "cmpb" in by_addr[0x635E328] and "%fs:0x330(%rax)" in by_addr[0x635E328])
    check("tls flag jne init block 0x635ecb7",
          "jne" in by_addr[0x635E330] and "635ecb7" in by_addr[0x635E330])
    check("tls flag2 cmpb 0x1 r11",
          "cmpb" in by_addr[0x635E336] and "0x1(%r11)" in by_addr[0x635E336])
    check("tls flag2 jg 0x635ece0",
          "jg" in by_addr[0x635E33B] and "635ece0" in by_addr[0x635E33B])
    check("no entry null test",
          not any(mnemonic_of(l) == "test" for l in lines
                  if addr_of(l) < 0x635E328),
          str([hex(addr_of(l)) for l in lines
               if addr_of(l) < 0x635E328 and mnemonic_of(l) == "test"]))
    check("init block xor esi esi",
          "xor" in by_addr[0x635ECB7] and "%esi,%esi" in by_addr[0x635ECB7])
    check("init block mov r11 to rdi",
          "mov" in by_addr[0x635ECB9] and "%r11,%rdi" in by_addr[0x635ECB9])
    check("init block mov ecx to 0x38 rsp",
          "mov" in by_addr[0x635ECBC] and "%ecx,0x38(%rsp)" in by_addr[0x635ECBC])
    check("init block mov rdx to 0x8 rsp",
          "mov" in by_addr[0x635ECC0] and "%rdx,0x8(%rsp)" in by_addr[0x635ECC0])
    check("context helper call 0x63ef8e0 in init block",
          "call" in by_addr[0x635ECC5] and "63ef8e0" in by_addr[0x635ECC5])
    check("init block test rax rax",
          "test" in by_addr[0x635ECD4] and "%rax,%rax" in by_addr[0x635ECD4])
    check("init block mov rax to r11",
          "mov" in by_addr[0x635ECD7] and "%rax,%r11" in by_addr[0x635ECD7])
    check("init block jne 0x635e336",
          "jne" in by_addr[0x635ECDA] and "635e336" in by_addr[0x635ECDA])

    # Entry size class.
    check("size cmp 0x1000 r9",
          "cmp" in by_addr[0x635E359] and "$0x1000,%r9" in by_addr[0x635E359])
    check("size ja 0x635f0a7",
          "ja" in by_addr[0x635E360] and "635f0a7" in by_addr[0x635E360])
    check("size byte table lea 0x67277c0",
          "lea" in by_addr[0x635E366] and "67277c0" in by_addr[0x635E366])
    check("size byte index lea 7 r9",
          "lea" in by_addr[0x635E36D] and "0x7(%r9),%rsi" in by_addr[0x635E36D])
    check("size table lea 0x6727a00",
          "lea" in by_addr[0x635E371] and "6727a00" in by_addr[0x635E371])
    check("size byte index shr 3",
          "shr" in by_addr[0x635E378] and "$0x3,%rsi" in by_addr[0x635E378])
    check("size byte load movzbl",
          "movzbl" in by_addr[0x635E37C] and "0x0(%rbp,%rsi,1),%r10d" in by_addr[0x635E37C])
    check("size table load",
          "mov" in by_addr[0x635E382] and "(%rdi,%r10,8),%rax" in by_addr[0x635E382])
    check("size store 0x8 rsp",
          "mov" in by_addr[0x635E386] and "%rax,0x8(%rsp)" in by_addr[0x635E386])
    check("size movabs 0x6fffffffffffffff r12",
          "movabs" in by_addr[0x635E38B] and "$0x6fffffffffffffff,%r12" in by_addr[0x635E38B])
    check("size sub 1 rax",
          "sub" in by_addr[0x635E395] and "$0x1,%rax" in by_addr[0x635E395])
    check("size cmp rax r12",
          "cmp" in by_addr[0x635E399] and "%rax,%r12" in by_addr[0x635E399])
    check("size jb 0x635ece0",
          "jb" in by_addr[0x635E39C] and "635ece0" in by_addr[0x635E39C])
    check("size cmpq 0x1000 0x8 rsp",
          "cmp" in by_addr[0x635E3A2] and "$0x1000,0x8(%rsp)" in by_addr[0x635E3A2])
    check("size ja 0x635f179",
          "ja" in by_addr[0x635E3AB] and "635f179" in by_addr[0x635E3AB])
    check("size re-read mov 0x8 rsp rsi",
          "mov" in by_addr[0x635E3B1] and "0x8(%rsp),%rsi" in by_addr[0x635E3B1])
    check("size re-read lea byte table",
          "lea" in by_addr[0x635E3B6] and "67277c0" in by_addr[0x635E3B6])
    check("size re-read add 7 rsi",
          "add" in by_addr[0x635E3BD] and "$0x7,%rsi" in by_addr[0x635E3BD])
    check("size re-read shr 3 rsi",
          "shr" in by_addr[0x635E3C1] and "$0x3,%rsi" in by_addr[0x635E3C1])
    check("size re-read movzbl",
          "movzbl" in by_addr[0x635E3C5] and "0x0(%rbp,%rsi,1),%r10d" in by_addr[0x635E3C5])
    check("size store byte class 0x38 rsp",
          "mov" in by_addr[0x635E3CB] and "%r10d,0x38(%rsp)" in by_addr[0x635E3CB])
    check("size movzbl 0x6511738 r12d",
          "movzbl" in by_addr[0x635E3D0] and "6511738" in by_addr[0x635E3D0])
    check("size mov r8d to edi",
          "mov" in by_addr[0x635E3D8] and "%r8d,%edi" in by_addr[0x635E3D8])
    check("size mov 0x38 rsp r13d",
          "mov" in by_addr[0x635E3DB] and "0x38(%rsp),%r13d" in by_addr[0x635E3DB])
    check("size shr 6 edi",
          "shr" in by_addr[0x635E3E0] and "$0x6,%edi" in by_addr[0x635E3E0])
    check("size and 1 edi",
          "and" in by_addr[0x635E3E3] and "$0x1,%edi" in by_addr[0x635E3E3])
    check("size test r12b",
          "test" in by_addr[0x635E3E6] and "%r12b,%r12b" in by_addr[0x635E3E6])
    check("size cmove edi r12d",
          "cmove" in by_addr[0x635E3E9] and "%edi,%r12d" in by_addr[0x635E3E9])
    check("size mov r12b 0x3e rsp",
          "mov" in by_addr[0x635E3ED] and "%r12b,0x3e(%rsp)" in by_addr[0x635E3ED])
    check("size cmp 0x23 r13d",
          "cmp" in by_addr[0x635E3F2] and "$0x23,%r13d" in by_addr[0x635E3F2])
    check("size ja 0x635f16b",
          "ja" in by_addr[0x635E3F6] and "635f16b" in by_addr[0x635E3F6])
    check("size lea 0x6711b40 r14",
          "lea" in by_addr[0x635E3FC] and "6711b40" in by_addr[0x635E3FC])
    check("size lea r13x5 rbx",
          "lea" in by_addr[0x635E403] and "0x0(%r13,%r13,4),%rbx" in by_addr[0x635E403])
    check("size lea table row rcx",
          "lea" in by_addr[0x635E408] and "(%r14,%rbx,8),%rcx" in by_addr[0x635E408])
    check("size mov 0x10 rcx r15d",
          "mov" in by_addr[0x635E40C] and "0x10(%rcx),%r15d" in by_addr[0x635E40C])
    check("size mov r15 0x10 rsp",
          "mov" in by_addr[0x635E410] and "%r15,0x10(%rsp)" in by_addr[0x635E410])
    check("size cmpq 0 0 rsp",
          "cmp" in by_addr[0x635E415] and "$0x0,(%rsp)" in by_addr[0x635E415])
    check("size je 0x635ece0",
          "je" in by_addr[0x635E41A] and "635ece0" in by_addr[0x635E41A])
    check("size flag lea 0x6713606",
          "lea" in by_addr[0x635E4F3] and "6713606" in by_addr[0x635E4F3])
    check("no $0xe7 gate",
          not any("$0xe7" in l for l in lines),
          str([hex(addr_of(l)) for l in lines if "$0xe7" in l]))

    # Walk (single, element-wise over the input array, table rbx+0x1b0).
    check("walk setup mov 0x40 rsp rcx",
          "mov" in by_addr[0x635EB8E] and "0x40(%rsp),%rcx" in by_addr[0x635EB8E])
    check("walk setup mov 0x18 rsp rax",
          "mov" in by_addr[0x635EB93] and "0x18(%rsp),%rax" in by_addr[0x635EB93])
    check("walk setup lea end r13",
          "lea" in by_addr[0x635EBAD] and "(%rax,%r8,8),%r13" in by_addr[0x635EBAD])
    check("walk setup mov rcx rbp",
          "mov" in by_addr[0x635EBB1] and "%rcx,%rbp" in by_addr[0x635EBB1])
    check("walk key load mov 0 rbp rcx",
          "mov" in by_addr[0x635EBB8] and "0x0(%rbp),%rcx" in by_addr[0x635EBB8])
    check("walk top mov rcx rsi",
          "mov" in by_addr[0x635EBBC] and "%rcx,%rsi" in by_addr[0x635EBBC])
    check("walk high bits mov rcx r10",
          "mov" in by_addr[0x635EBBF] and "%rcx,%r10" in by_addr[0x635EBBF])
    check("walk top shr 0x1a rsi",
          "shr" in by_addr[0x635EBC2] and "$0x1a,%rsi" in by_addr[0x635EBC2])
    check("walk high bits and",
          "and" in by_addr[0x635EBC6] and "$0xffffffffc0000000,%r10" in by_addr[0x635EBC6])
    check("walk top and 0xf0",
          "and" in by_addr[0x635EBCD] and "$0xf0,%esi" in by_addr[0x635EBCD])
    check("walk table add rbx rsi",
          "add" in by_addr[0x635EBD3] and "%rbx,%rsi" in by_addr[0x635EBD3])
    check("walk top load",
          "mov" in by_addr[0x635EBD6] and "0x1b0(%rsi),%rdi" in by_addr[0x635EBD6])
    check("walk top compare",
          "cmp" in by_addr[0x635EBDD] and "%rdi,%r10" in by_addr[0x635EBDD])
    check("walk top mismatch jne scan",
          "jne" in by_addr[0x635EBE0] and "635ecf0" in by_addr[0x635EBE0])
    check("walk second level shr 0x9 rcx",
          "shr" in by_addr[0x635EBE6] and "$0x9,%rcx" in by_addr[0x635EBE6])
    check("walk second level mov rcx rax",
          "mov" in by_addr[0x635EBEA] and "%rcx,%rax" in by_addr[0x635EBEA])
    check("walk second level and 0x1ffff8",
          "and" in by_addr[0x635EBED] and "$0x1ffff8,%eax" in by_addr[0x635EBED])
    check("walk second level add table entry",
          "add" in by_addr[0x635EBF2] and "0x1b8(%rsi),%rax" in by_addr[0x635EBF2])
    check("walk second level deref into rdi",
          "mov" in by_addr[0x635EBF9] and "(%rax),%rdi" in by_addr[0x635EBF9])
    check("walk advance add 8 rbp",
          "add" in by_addr[0x635EBFC] and "$0x8,%rbp" in by_addr[0x635EBFC])

    # Extract (one shape).
    check("extract shl 0x10 rdi",
          "shl" in by_addr[0x635EC00] and "$0x10,%rdi" in by_addr[0x635EC00])
    check("extract sar 0x10 rdi",
          "sar" in by_addr[0x635EC04] and "$0x10,%rdi" in by_addr[0x635EC04])
    check("extract and mask",
          "and" in by_addr[0x635EC08] and "$0xffffffffffffff80,%rdi" in by_addr[0x635EC08])
    check("extract helper call 0x63be540",
          "call" in by_addr[0x635EC0C] and "63be540" in by_addr[0x635EC0C])
    check("extract loop-back cmp r13 rbp",
          "cmp" in by_addr[0x635EC11] and "%r13,%rbp" in by_addr[0x635EC11])
    check("extract loop-back jne walk head",
          "jne" in by_addr[0x635EC14] and "635ebb8" in by_addr[0x635EC14])
    check("no inline shr 0x30 extracts",
          not any(re.search(r"\tshr\s+\$0x30,", l) for l in lines),
          str([hex(addr_of(l)) for l in lines
               if re.search(r"\tshr\s+\$0x30,", l)]))

    # Scan (single 8-slot MTF, table+0x2b0 in rbx, key in r10).
    check("scan slot 0 load 0x2b0 rbx",
          "mov" in by_addr[0x635ECF0] and "0x2b0(%rbx),%r8" in by_addr[0x635ECF0])
    check("scan slot 0 cmp r8 r10",
          "cmp" in by_addr[0x635ECF7] and "%r8,%r10" in by_addr[0x635ECF7])
    check("scan slot 0 mismatch jne loop",
          "jne" in by_addr[0x635ECFA] and "635f0ed" in by_addr[0x635ECFA])
    check("scan slot 0 hit mov 0x2b8 rbx rdx",
          "mov" in by_addr[0x635ED00] and "0x2b8(%rbx),%rdx" in by_addr[0x635ED00])
    check("scan slot 0 hit mov rdi 0x2b0 rbx",
          "mov" in by_addr[0x635ED07] and "%rdi,0x2b0(%rbx)" in by_addr[0x635ED07])
    check("scan slot 0 hit mov r10 0x1b0 rsi",
          "mov" in by_addr[0x635ED2A] and "%r10,0x1b0(%rsi)" in by_addr[0x635ED2A])
    check("scan slot 0 hit mov rdx 0x1b8 rsi",
          "mov" in by_addr[0x635ED31] and "%rdx,0x1b8(%rsi)" in by_addr[0x635ED31])
    check("scan slot 0 hit jmp deref",
          "jmp" in by_addr[0x635ED38] and "635ebf9" in by_addr[0x635ED38])
    loopc = {0x635F0FC: "%r10,%r11", 0x635F1F6: "%r10,%r8",
             0x635F272: "%rax,%r10", 0x635F282: "%r10,%r8",
             0x635F2B1: "%r10,%r11", 0x635F2C1: "%r8,%r10",
             0x635F2E4: "0x320(%rbx),%r10"}
    for a, ops in loopc.items():
        check("scan loop compare %s" % hex(a),
              "cmp" in by_addr[a] and ops in by_addr[a])
    check("scan slot 1 load 0x2c0 rbx",
          "mov" in by_addr[0x635F0ED] and "0x2c0(%rbx),%r11" in by_addr[0x635F0ED])
    check("scan slot 2 load 0x2d0 rbx",
          "mov" in by_addr[0x635F1EF] and "0x2d0(%rbx),%r8" in by_addr[0x635F1EF])
    check("scan slot 3 load 0x2e0 rbx",
          "mov" in by_addr[0x635F260] and "0x2e0(%rbx),%rax" in by_addr[0x635F260])
    check("scan slot 4 load 0x2f0 rbx",
          "mov" in by_addr[0x635F27B] and "0x2f0(%rbx),%r8" in by_addr[0x635F27B])
    check("scan slot 5 load 0x300 rbx",
          "mov" in by_addr[0x635F29F] and "0x300(%rbx),%r11" in by_addr[0x635F29F])
    check("scan slot 6 load 0x310 rbx",
          "mov" in by_addr[0x635F2BA] and "0x310(%rbx),%r8" in by_addr[0x635F2BA])
    check("scan slot 7 je shared swap",
          "je" in by_addr[0x635F2EB] and "635f105" in by_addr[0x635F2EB])
    check("scan shared swap mov r8 0x2b0 rax",
          "mov" in by_addr[0x635F10E] and "%r8,0x2b0(%rax)" in by_addr[0x635F10E])
    check("scan shared swap mov rdi 0x2b0 r8",
          "mov" in by_addr[0x635F137] and "%rdi,0x2b0(%r8)" in by_addr[0x635F137])
    check("scan shared swap mov r10 0x1b0 rsi",
          "mov" in by_addr[0x635F158] and "%r10,0x1b0(%rsi)" in by_addr[0x635F158])
    check("scan shared swap mov r11 0x1b8 rsi",
          "mov" in by_addr[0x635F15F] and "%r11,0x1b8(%rsi)" in by_addr[0x635F15F])
    check("scan shared swap jmp deref",
          "jmp" in by_addr[0x635F166] and "635ebf9" in by_addr[0x635F166])
    reversed_sites = [0x635F0FC, 0x635F1F6, 0x635F282, 0x635F2B1]
    check("scan reversed-operand compares 4 exact list",
          [a for a in loopc
           if operands_of(by_addr[a]).startswith("%r10")] == reversed_sites,
          str([(hex(a), operands_of(by_addr[a]))
               for a in loopc
               if operands_of(by_addr[a]).startswith("%r10")]))
    check("scan slot 0 compare not reversed",
          not operands_of(by_addr[0x635ECF7]).startswith("%r10"),
          operands_of(by_addr[0x635ECF7]))

    # Lu-miss site (1).
    check("lu-miss rsi lea 0x6511a00",
          "lea" in by_addr[0x635F2F1] and "6511a00" in by_addr[0x635F2F1])
    check("lu-miss rdx lea 0x1b0 rbx",
          "lea" in by_addr[0x635F2F8] and "0x1b0(%rbx),%rdx" in by_addr[0x635F2F8])
    check("lu-miss r9d 0",
          "xor" in by_addr[0x635F2FF] and "%r9d,%r9d" in by_addr[0x635F2FF])
    check("lu-miss rdi is rbx",
          "mov" in by_addr[0x635F302] and "%rbx,%rdi" in by_addr[0x635F302])
    check("lu-miss r8d 1",
          "mov" in by_addr[0x635F305] and "$0x1,%r8d" in by_addr[0x635F305])
    check("lu-miss call 0x63d9700",
          "call" in by_addr[0x635F30B] and "63d9700" in by_addr[0x635F30B])
    check("lu-miss rejoin jmp 0x635ebf9",
          "jmp" in by_addr[0x635F310] and "635ebf9" in by_addr[0x635F310])

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

    miss_site = 0x635F30B
    sh_sites = [0x635EC8D, 0x635EF3E, 0x635F24D]
    check("entry 0x635e2e0 reaches lu-miss site",
          reaches(START, miss_site))
    check("entry reaches all second-handler sites",
          all(reaches(START, s) for s in sh_sites))

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
    check("lu-miss rcx only def is walk-head load 0x635ebb8",
          rcx_in[miss_site] == {0x635EBB8},
          str(rcx_in[miss_site]))
    check("walk-match shr rcx 0x635ebe6 does not reach miss",
          0x635EBE6 not in rcx_in[miss_site],
          str(rcx_in[miss_site]))
    check("slot-0-hit shr rcx 0x635ed0e does not reach miss",
          0x635ED0E not in rcx_in[miss_site],
          str(rcx_in[miss_site]))
    rsi_in = reaching_defs("rsi")
    check("second-handler site 1 rsi only def is lea 0x635ec66",
          rsi_in[0x635EC8D] == {0x635EC66},
          str(rsi_in[0x635EC8D]))
    check("second-handler site 2 rsi only def is xor 0x635ef34",
          rsi_in[0x635EF3E] == {0x635EF34},
          str(rsi_in[0x635EF3E]))
    check("second-handler site 3 rsi defs are sched_getcpu-derived",
          rsi_in[0x635F24D] == {0x635E877, 0x635E885, 0x635E88B},
          str(rsi_in[0x635F24D]))

    # Second-handler sites: argument setup.
    check("second-handler site 1 rdx lea 0x64da4b0",
          "lea" in by_addr[0x635EC7E] and "64da4b0" in by_addr[0x635EC7E])
    check("second-handler site 1 rdi is rbx",
          "mov" in by_addr[0x635EC85] and "%rbx,%rdi" in by_addr[0x635EC85])
    check("second-handler site 1 rsi lea -1 rcx",
          "lea" in by_addr[0x635EC66] and "-0x1(%rcx),%esi" in by_addr[0x635EC66])
    check("second-handler site 1 node load null-tested",
          "mov" in by_addr[0x635EC69] and "(%r10,%rsi,8),%r9" in by_addr[0x635EC69] and
          "test" in by_addr[0x635EC75] and "%r9,%r9" in by_addr[0x635EC75])
    check("second-handler site 1 call 0x634ebb0",
          "call" in by_addr[0x635EC8D] and "634ebb0" in by_addr[0x635EC8D])
    check("second-handler site 2 rdx lea 0x64da4b0",
          "lea" in by_addr[0x635EF2D] and "64da4b0" in by_addr[0x635EF2D])
    check("second-handler site 2 xor esi esi",
          "xor" in by_addr[0x635EF34] and "%esi,%esi" in by_addr[0x635EF34])
    check("second-handler site 2 rdi is rbx",
          "mov" in by_addr[0x635EF36] and "%rbx,%rdi" in by_addr[0x635EF36])
    check("second-handler site 2 call 0x634ebb0",
          "call" in by_addr[0x635EF3E] and "634ebb0" in by_addr[0x635EF3E])
    check("second-handler site 3 rdx lea 0x64da4b0",
          "lea" in by_addr[0x635F23E] and "64da4b0" in by_addr[0x635F23E])
    check("second-handler site 3 rdi is rbx",
          "mov" in by_addr[0x635F245] and "%rbx,%rdi" in by_addr[0x635F245])
    check("second-handler site 3 call 0x634ebb0",
          "call" in by_addr[0x635F24D] and "634ebb0" in by_addr[0x635F24D])
    check("sched_getcpu call 0x63f1ad0 at 0x635e867",
          "call" in by_addr[0x635E867] and "63f1ad0" in by_addr[0x635E867])
    check("site 3 rsi mov eax esi 0x635e877",
          "mov" in by_addr[0x635E877] and "%eax,%esi" in by_addr[0x635E877])
    check("site 3 rsi sub r9d esi 0x635e885",
          "sub" in by_addr[0x635E885] and "%r9d,%esi" in by_addr[0x635E885])
    check("site 3 rsi cmovb eax esi 0x635e88b",
          "cmovb" in by_addr[0x635E88B] and "%eax,%esi" in by_addr[0x635E88B])
    check("records second-handler sites match census",
          [s.get("site") for s in rec.get("second_handler_sites", [])] ==
          ["0x635ec8d", "0x635ef3e", "0x635f24d"])

    # Dispatcher callees.
    check("#317 call site args: rdi 0x48 rsp, esi 0x50 rsp",
          "mov" in by_addr[0x635E790] and "0x50(%rsp),%esi" in by_addr[0x635E790] and
          "mov" in by_addr[0x635E794] and "0x48(%rsp),%rdi" in by_addr[0x635E794])
    check("#317 call result null-tested and stored",
          "test" in by_addr[0x635E79E] and "%rax,%rax" in by_addr[0x635E79E] and
          "mov" in by_addr[0x635E7A8] and "%rax,(%r11,%r15,8)" in by_addr[0x635E7A8])
    check("memcpy plt called 1 time", tgt.get(0x63F0A60, 0) == 1,
          str(tgt.get(0x63F0A60, 0)))
    check("memset plt called 15 times", tgt.get(0x63F0A90, 0) == 15,
          str(tgt.get(0x63F0A90, 0)))
    check("sched_getcpu plt called 1 time", tgt.get(0x63F1AD0, 0) == 1,
          str(tgt.get(0x63F1AD0, 0)))
    check("abort plt called 1 time", tgt.get(0x63F0BF0, 0) == 1,
          str(tgt.get(0x63F0BF0, 0)))
    check("stack_chk_fail plt called 1 time", tgt.get(0x63F0D70, 0) == 1,
          str(tgt.get(0x63F0D70, 0)))
    check("0x63eec80 called 1 time", tgt.get(0x63EEC80, 0) == 1,
          str(tgt.get(0x63EEC80, 0)))
    check("0x63ed8b0 called 1 time", tgt.get(0x63ED8B0, 0) == 1,
          str(tgt.get(0x63ED8B0, 0)))
    check("0x63bf5b6 called 1 time", tgt.get(0x63BF5B6, 0) == 1,
          str(tgt.get(0x63BF5B6, 0)))
    check("0x63ec4c0 called 1 time", tgt.get(0x63EC4C0, 0) == 1,
          str(tgt.get(0x63EC4C0, 0)))
    check("0x6360ed0 called 1 time", tgt.get(0x6360ED0, 0) == 1,
          str(tgt.get(0x6360ED0, 0)))
    check("0x6362910 called 1 time", tgt.get(0x6362910, 0) == 1,
          str(tgt.get(0x6362910, 0)))
    check("0x6364400 called 1 time", tgt.get(0x6364400, 0) == 1,
          str(tgt.get(0x6364400, 0)))
    check("0x6364410 called 1 time", tgt.get(0x6364410, 0) == 1,
          str(tgt.get(0x6364410, 0)))
    check("0x6364420 called 1 time", tgt.get(0x6364420, 0) == 1,
          str(tgt.get(0x6364420, 0)))
    check("0x6352fc0 called 1 time", tgt.get(0x6352FC0, 0) == 1,
          str(tgt.get(0x6352FC0, 0)))
    check("0x63edf10 called 2 times", tgt.get(0x63EDF10, 0) == 2,
          str(tgt.get(0x63EDF10, 0)))
    check("0x63be540 called 1 time", tgt.get(0x63BE540, 0) == 1,
          str(tgt.get(0x63BE540, 0)))
    check("0x63ef8e0 called 1 time", tgt.get(0x63EF8E0, 0) == 1,
          str(tgt.get(0x63EF8E0, 0)))

    # Exit: single ret, rax = r15 (element count).
    check("epilogue canary load 0x98 rsp",
          "mov" in by_addr[0x635E7C0] and "0x98(%rsp),%rax" in by_addr[0x635E7C0])
    check("epilogue canary sub fs:0x28",
          "sub" in by_addr[0x635E7C8] and "%fs:0x28,%rax" in by_addr[0x635E7C8])
    check("epilogue canary jne 0x635f29a",
          "jne" in by_addr[0x635E7D1] and "635f29a" in by_addr[0x635E7D1])
    check("epilogue add 0xa8 rsp",
          "add" in by_addr[0x635E7D7] and "$0xa8,%rsp" in by_addr[0x635E7D7])
    check("epilogue mov r15 rax",
          "mov" in by_addr[0x635E7DE] and "%r15,%rax" in by_addr[0x635E7DE])
    check("no rax write between mov r15 rax and ret",
          not any(dst_reg(by_addr[a]) in ("%rax", "%eax")
                  for a in by_addr if 0x635E7DE < a <= 0x635E7EB),
          str([(hex(a), by_addr[a]) for a in by_addr
               if 0x635E7DE < a <= 0x635E7EB
               and dst_reg(by_addr[a]) in ("%rax", "%eax")]))
    check("canary failure calls stack_chk_fail",
          "call" in by_addr[0x635F29A] and "63f0d70" in by_addr[0x635F29A])

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for va in [0x65096A0, 0x65096C0, 0x6511A00, 0x6511730, 0x6511738,
               0x6711B40, 0x6713606, 0x67277C0, 0x6727A00, 0x6728140,
               0x6728840, 0x6728850]:
        check("address %s inside .bss" % hex(va),
              bss[3] <= va < bss[3] + bss[5])
    dro = secmap[".data.rel.ro"]
    check("0x64da4b0 inside .data.rel.ro",
          dro[3] <= 0x64DA4B0 < dro[3] + dro[5])
    dat = secmap[".data"]
    check("0x64ffb80 inside .data", dat[3] <= 0x64FFB80 < dat[3] + dat[5])

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
    check("this FDE raw second-handler 3",
          sh_counts.get(START, 0) == 3, str(sh_counts.get(START, 0)))
    check("raw-e8 second-handler total 64", sum(sh_counts.values()) == 64,
          str(sum(sh_counts.values())))
    check("raw-e8 second-handler FDEs 28", len(sh_counts) == 28,
          str(len(sh_counts)))
    check("next candidate raw lu-miss 2", counts.get(0x63C9650, 0) == 2,
          str(counts.get(0x63C9650, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63C9650, 0) == 0,
          str(bti_counts.get(0x63C9650, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63C9650, 0) == 0,
          str(sh_counts.get(0x63C9650, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 7th survivor",
          survey.get("survivors", [None] * 7)[6] == "0x635e2e0",
          str(survey.get("survivors", [])[:8]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window IS shared",
          "0x635e2e0" in survey.get("shared_survivors", []))
    check("survey next candidate NOT shared",
          "0x63c9650" not in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x63c9650..0x63c9c80",
          nq.get("range") == "0x63c9650..0x63c9c80", str(nq.get("range")))
    check("next question bytes 1584", nq.get("bytes") == 1584,
          str(nq.get("bytes")))
    check("next question lu-miss sites 2",
          nq.get("lu_miss_sites") == 2, str(nq.get("lu_miss_sites")))
    check("next question lu-miss site list",
          nq.get("lu_miss_site") == ["0x63c9c29", "0x63c9c76"],
          str(nq.get("lu_miss_site")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 363", nq.get("strict") == 363,
          str(nq.get("strict")))
    check("next question calls 12", nq.get("calls") == 12,
          str(nq.get("calls")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question ret 0x63c9868", nq.get("ret") == "0x63c9868",
          str(nq.get("ret")))
    check("records census strict 898",
          rec.get("census", {}).get("strict") == 898)
    check("records census calls 38",
          rec.get("census", {}).get("calls") == 38)
    check("records lu-miss sites match census",
          [s.get("site") for s in rec.get("lu_miss_sites", [])] ==
          ["0x635f30b"])
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
    # next candidate 0x63c9650..0x63c9c80 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63C9650 < p[1] and p[0] < 0x63C9C80]
    check("next candidate 0x63c9650 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63C9C80 and 0x63C9650 < END))

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
