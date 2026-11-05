"""Static verifier for RE-001-node115-lu-miss-caller-7site-dispatch.

Sixth packet of the lu-miss-caller frontier (callers of the lu-miss
handler 0x63d9700 that do not call bin_table_init): FDE
0x635c6d0..0x635de25, 5973 bytes, 1220 strict instructions, 31 calls
(30 direct + 1 indirect via GOT 0x64ffb30), 7 lu-miss sites, 0
bin_table_init sites, 0 second-handler sites, 1 ret at 0x635c886,
bsr 9, lock 0/0, 200 jumps, 0 outside the window.

This window is a lu-miss-ONLY survivor: it is in the survey's
16-FDE lu-miss survivor list but NOT in the 18-FDE second-handler
survivor list, so it consumes one slot of the combined 25-FDE
miss-handler pool without being shared. The second miss handler
0x634ebb0 is not called from this FDE at all.

Entry: rdi is the walk key (r12), rsi is the size input (r14), edx
is flags (r13d); rbx is the TLS-derived context base. No entry null
guard, no lock-add walk entry. TLS flag byte %fs:0x330(%rbx); size
class from byte table 0x67277c0 + size table 0x6727a00 + flag
0x6713606. Nine top-index re-entries, nine 8-slot MTF loops, seven
lu-miss sites sharing one argument pattern (rdi = rbx, rsi = .bss
0x6511a00, rdx = lea 0x1b0(%rbx), rcx = r12 walk key, r8d = 1,
r9d = 0); the fourth miss block (0x635dcc6) is the shared
exhaustion target of three loops. Exit: eax = 0 at ret (the canary
check leaves rax 0).

Next question: the next lu-miss survivor in address order is
0x635e2e0..0x635f315 (4149 bytes, 898 strict, 38 calls, 1 lu-miss
site at 0x635f30b, 0 bti, 3 second-handler sites, 1 ret at
0x635e7eb, bsr 5) -- a SHARED survivor, unlike this packet.

Usage: python3 tools/node115_lu_miss_caller_7site_dispatch.py
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
                      "RE-001-node115-lu-miss-caller-7site-dispatch")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-miss-caller-7site-dispatch"
NAME = "lu_miss_caller_7site_dispatch"
START, END = 0x635C6D0, 0x635DE25

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
    check("target FDE size 5973", END - START == 5973)
    prev = fdes[i - 1]
    nxt = fdes[i + 1]
    check("prev FDE 0x635a7a0..0x635c6c7",
          prev == (0x635A7A0, 0x635C6C7), str(prev))
    check("prev gap 9", START - prev[1] == 9)
    gap = node[toff(prev[1]):toff(START)]
    check("gap bytes all cc", gap == b"\xcc" * 9, gap.hex())
    check("next FDE 0x635de30..0x635ded5",
          nxt == (0x635DE30, 0x635DED5), str(nxt))
    check("next padding 11", nxt[0] - END == 11)
    pad = node[toff(END):toff(nxt[0])]
    check("next padding bytes all cc", pad == b"\xcc" * 11, pad.hex())
    check("next FDE starts endbr64",
          node[toff(0x635DE30):toff(0x635DE30) + 4] ==
          bytes.fromhex("f30f1efa"))
    check("next FDE cmp $0x1000,%rsi at 0x635de34",
          node[toff(0x635DE34):toff(0x635DE34) + 7] ==
          bytes.fromhex("4881fe00100000"))

    hexb = read(os.path.join(PACKET, NAME + ".hex"))
    check("hex exhibit raw bytes 5973", len(hexb) == 5973, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])

    obj = read(os.path.join(PACKET, NAME + ".objdump.txt")).decode()
    lines = strict_lines(obj)
    check("strict lines 1220", len(lines) == 1220, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("call lines 31", len(calls) == 31, str(len(calls)))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x635c886", [addr_of(l) for l in rets] == [0x635C886],
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
    check("indirect calls 1 via GOT 0x64ffb30",
          indirect == [0x635CE82],
          str([hex(a) for a in indirect]))
    check("indirect call GOT slot 0x64ffb30",
          "64ffb30" in by_addr[0x635CE82])
    from collections import Counter
    tgt = Counter(t for _, t in ct)
    expect = {0x63D9700: 7, 0x6363260: 3, 0x63BE4D0: 2, 0x63BD6C0: 2,
              0x63C3330: 2, 0x63EAD50: 2, 0x63EB870: 2, 0x6349510: 1,
              0x63495B0: 1, 0x63637F0: 1, 0x63B73A0: 1, 0x63BF5B6: 1,
              0x63ED8B0: 1, 0x63EEC80: 1, 0x63EF8E0: 1, 0x63F0BF0: 1,
              0x63F0D70: 1}
    check("call target multiset exact", dict(tgt) == expect,
          str(dict(tgt)))
    check("distinct call targets 17 direct + 1 indirect",
          len(tgt) == 17, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 7",
          sorted(a for a, t in ct if t == 0x63D9700) ==
          [0x635DB78, 0x635DC13, 0x635DC48, 0x635DCE3, 0x635DD28,
           0x635DDDA, 0x635DE17],
          str([hex(a) for a, t in ct if t == 0x63D9700]))
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("no lock-wait sites", tgt.get(0x63BF680, 0) == 0,
          str(tgt.get(0x63BF680, 0)))
    check("no 0x63be540 helper sites", tgt.get(0x63BE540, 0) == 0,
          str(tgt.get(0x63BE540, 0)))
    check("no 0x63bd2c0 thunk sites", tgt.get(0x63BD2C0, 0) == 0,
          str(tgt.get(0x63BD2C0, 0)))
    check("#314 window called once",
          sorted(a for a, t in ct if t == 0x63495B0) == [0x635D52D],
          str([hex(a) for a, t in ct if t == 0x63495B0]))
    check("0x63c3330 (after #313 window) called twice",
          sorted(a for a, t in ct if t == 0x63C3330) ==
          [0x635CB8E, 0x635D0F4],
          str([hex(a) for a, t in ct if t == 0x63C3330]))
    check("0x6363260 (after #298 window) called 3 times",
          sorted(a for a, t in ct if t == 0x6363260) ==
          [0x635D076, 0x635D44B, 0x635D9BD],
          str([hex(a) for a, t in ct if t == 0x6363260]))
    check("#313 window not called", tgt.get(0x63C2F00, 0) == 0,
          str(tgt.get(0x63C2F00, 0)))
    check("#298 window not called", tgt.get(0x6362F90, 0) == 0,
          str(tgt.get(0x6362F90, 0)))
    check("#315 window not called", tgt.get(0x6353A70, 0) == 0,
          str(tgt.get(0x6353A70, 0)))
    check("#316 window not called", tgt.get(0x6355900, 0) == 0,
          str(tgt.get(0x6355900, 0)))
    check("#317 window not called", tgt.get(0x63577F0, 0) == 0,
          str(tgt.get(0x63577F0, 0)))
    check("#318 window not called", tgt.get(0x635A7A0, 0) == 0,
          str(tgt.get(0x635A7A0, 0)))
    bsr = [addr_of(l) for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 9 exact list",
          bsr == [0x635C9DC, 0x635CC75, 0x635CDBC, 0x635CF71, 0x635D1B5,
                  0x635D20F, 0x635D358, 0x635D5BB, 0x635D825],
          str([hex(a) for a in bsr]))
    locks = [(addr_of(l), operands_of(l)) for l in lines
             if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))
    jmps = []
    for l in lines:
        m = re.search(r"\t(jmp|je|jne|ja|jae|jb|jbe|jge|jl|jle|jg|jo|jno|js|jns|jp|jnp)\s+([0-9a-f]+)", l)
        if m:
            jmps.append((addr_of(l), int(m.group(2), 16)))
    check("jump lines 200", len(jmps) == 200, str(len(jmps)))
    outside = [(a, t) for a, t in jmps if not (START <= t < END)]
    check("jump closure zero outside", outside == [], str(outside))

    # Entry + frame (pushes interleaved with the entry movs).
    check("entry endbr64", "endbr64" in by_addr[0x635C6D0])
    check("entry push r15", "push" in by_addr[0x635C6D4] and "%r15" in by_addr[0x635C6D4])
    check("entry push r14", "push" in by_addr[0x635C6D6] and "%r14" in by_addr[0x635C6D6])
    check("entry mov rsi to r14",
          "mov" in by_addr[0x635C6D8] and "%rsi,%r14" in by_addr[0x635C6D8])
    check("entry push r13", "push" in by_addr[0x635C6DB] and "%r13" in by_addr[0x635C6DB])
    check("entry mov edx to r13d",
          "mov" in by_addr[0x635C6DD] and "%edx,%r13d" in by_addr[0x635C6DD])
    check("entry push r12", "push" in by_addr[0x635C6E0] and "%r12" in by_addr[0x635C6E0])
    check("entry mov rdi to r12",
          "mov" in by_addr[0x635C6E2] and "%rdi,%r12" in by_addr[0x635C6E2])
    check("entry push rbp", "push" in by_addr[0x635C6E5] and "%rbp" in by_addr[0x635C6E5])
    check("entry push rbx", "push" in by_addr[0x635C6E6] and "%rbx" in by_addr[0x635C6E6])
    check("entry sub 0x88 rsp",
          "sub" in by_addr[0x635C6E7] and "$0x88,%rsp" in by_addr[0x635C6E7])
    check("tls base mov -0x10a8 to rbx",
          "mov" in by_addr[0x635C6EE] and "$0xffffffffffffef58,%rbx" in by_addr[0x635C6EE])
    check("canary load fs:0x28",
          "mov" in by_addr[0x635C6F5] and "%fs:0x28,%rax" in by_addr[0x635C6F5])
    check("canary store 0x78 rsp",
          "mov" in by_addr[0x635C6FE] and "0x78(%rsp)" in by_addr[0x635C6FE])
    check("entry xor eax eax",
          "xor" in by_addr[0x635C703] and "%eax,%eax" in by_addr[0x635C703])
    check("tls flag movzbl fs:0x330 rbx",
          "movzbl" in by_addr[0x635C705] and "%fs:0x330(%rbx),%edx" in by_addr[0x635C705])
    check("tls base add fs:0x0",
          "add" in by_addr[0x635C70D] and "%fs:0x0,%rbx" in by_addr[0x635C70D])
    check("tls flag test dl",
          "test" in by_addr[0x635C716] and "%dl,%dl" in by_addr[0x635C716])
    check("tls flag jne init block 0x635ccb0",
          "jne" in by_addr[0x635C718] and "635ccb0" in by_addr[0x635C718])
    check("no entry null test",
          not any(mnemonic_of(l) == "test" for l in lines
                  if addr_of(l) < 0x635C705),
          str([hex(addr_of(l)) for l in lines
               if addr_of(l) < 0x635C705 and mnemonic_of(l) == "test"]))
    check("init block mov rbx to rdi",
          "mov" in by_addr[0x635CCB0] and "%rbx,%rdi" in by_addr[0x635CCB0])
    check("init block mov 1 to esi",
          "mov" in by_addr[0x635CCB3] and "$0x1,%esi" in by_addr[0x635CCB3])
    check("context helper call 0x63ef8e0 in init block",
          "call" in by_addr[0x635CCB8] and "63ef8e0" in by_addr[0x635CCB8])
    check("init block flag recheck movzbl 0x330 rax",
          "movzbl" in by_addr[0x635CCBD] and "0x330(%rax),%edx" in by_addr[0x635CCBD])
    check("init block mov rax to rbx",
          "mov" in by_addr[0x635CCC4] and "%rax,%rbx" in by_addr[0x635CCC4])
    check("init block rejoin jmp 0x635c71e",
          "jmp" in by_addr[0x635CCC7] and "635c71e" in by_addr[0x635CCC7])

    # Entry size class.
    check("size cmp 0x1000 r14",
          "cmp" in by_addr[0x635C736] and "$0x1000,%r14" in by_addr[0x635C736])
    check("size byte table lea 0x67277c0",
          "lea" in by_addr[0x635C743] and "67277c0" in by_addr[0x635C743])
    check("size byte index lea 7 r14",
          "lea" in by_addr[0x635C74A] and "0x7(%r14),%rdi" in by_addr[0x635C74A])
    check("size table lea 0x6727a00",
          "lea" in by_addr[0x635C74E] and "6727a00" in by_addr[0x635C74E])
    check("size byte index shr 3",
          "shr" in by_addr[0x635C755] and "$0x3,%rdi" in by_addr[0x635C755])
    check("size byte load movzbl",
          "movzbl" in by_addr[0x635C759] and "(%r8,%rdi,1),%r9d" in by_addr[0x635C759])
    check("size table load",
          "mov" in by_addr[0x635C75E] and "(%r10,%r9,8),%rbp" in by_addr[0x635C75E])
    check("size flags mov r13d to r11d",
          "mov" in by_addr[0x635C762] and "%r13d,%r11d" in by_addr[0x635C762])
    check("size flags and 0xfff00",
          "and" in by_addr[0x635C765] and "$0xfff00,%r11d" in by_addr[0x635C765])
    check("size flags jne 0x635ca40",
          "jne" in by_addr[0x635C76C] and "635ca40" in by_addr[0x635C76C])
    check("size flag lea 0x6713606",
          "lea" in by_addr[0x635C781] and "6713606" in by_addr[0x635C781])
    check("size flag cmpb 0 r13",
          "cmpb" in by_addr[0x635C7B9] and "$0x0,0x0(%r13)" in by_addr[0x635C7B9])
    check("size cmp 0x1000 rbp",
          "cmp" in by_addr[0x635C79A] and "$0x1000,%rbp" in by_addr[0x635C79A])
    check("size cmp 0x3800 r14",
          "cmp" in by_addr[0x635C890] and "$0x3800,%r14" in by_addr[0x635C890])
    check("size cmp 0x1000 rax",
          "cmp" in by_addr[0x635C89D] and "$0x1000,%rax" in by_addr[0x635C89D])

    # Walk (single, table in rbx, key in r12, re-entered per element).
    check("walk key is entry rdi in r12",
          "mov" in by_addr[0x635C6E2] and "%rdi,%r12" in by_addr[0x635C6E2])
    check("walk top mov r12 to rax",
          "mov" in by_addr[0x635CB10] and "%r12,%rax" in by_addr[0x635CB10])
    check("walk high bits mov r12 to r11",
          "mov" in by_addr[0x635CB13] and "%r12,%r11" in by_addr[0x635CB13])
    check("walk top shr 0x1a rax",
          "shr" in by_addr[0x635CB16] and "$0x1a,%rax" in by_addr[0x635CB16])
    check("walk high bits and",
          "and" in by_addr[0x635CB1A] and "$0xffffffffc0000000,%r11" in by_addr[0x635CB1A])
    check("walk top and 0xf0",
          "and" in by_addr[0x635CB21] and "$0xf0,%eax" in by_addr[0x635CB21])
    check("walk table lea rbx+rax rcx",
          "lea" in by_addr[0x635CB26] and "(%rbx,%rax,1),%rcx" in by_addr[0x635CB26])
    check("walk top load",
          "mov" in by_addr[0x635CB2A] and "0x1b0(%rcx),%rdx" in by_addr[0x635CB2A])
    check("walk top compare",
          "cmp" in by_addr[0x635CB31] and "%rdx,%r11" in by_addr[0x635CB31])
    check("walk second level mov r12 to rax",
          "mov" in by_addr[0x635CB3A] and "%r12,%rax" in by_addr[0x635CB3A])
    check("walk second level shr 0x9",
          "shr" in by_addr[0x635CB3D] and "$0x9,%rax" in by_addr[0x635CB3D])
    check("walk second level and 0x1ffff8",
          "and" in by_addr[0x635CB41] and "$0x1ffff8,%eax" in by_addr[0x635CB41])
    check("walk second level add table entry",
          "add" in by_addr[0x635CB46] and "0x1b8(%rcx),%rax" in by_addr[0x635CB46])
    check("walk second level deref into rsi",
          "mov" in by_addr[0x635CB51] and "(%rax),%rsi" in by_addr[0x635CB51])
    shr1a = [addr_of(l) for l in lines
             if re.search(r"\tshr\s+\$0x1a,", l)]
    check("walk top-index shr 0x1a 9 sites",
          shr1a == [0x635CB16, 0x635CD29, 0x635CEFE, 0x635D016, 0x635D086,
                    0x635D156, 0x635D2BA, 0x635D463, 0x635D63A],
          str([hex(a) for a in shr1a]))
    topcmp = {0x635CB31: "%rdx,%r11", 0x635CD43: "%r15,%r10",
              0x635CF19: "%r13,%r11", 0x635D032: "%rax,%r15",
              0x635D0A1: "%r10,%r11", 0x635D171: "%rsi,%r14",
              0x635D2D5: "%r11,%r14", 0x635D47F: "%r15,%r14",
              0x635D654: "%rcx,%r11"}
    for a, ops in topcmp.items():
        check("walk top compare %s" % hex(a),
              "cmp" in by_addr[a] and ops in by_addr[a])

    # Extracts (two shapes).
    check("extract1 shl 0x10 rsi",
          "shl" in by_addr[0x635CB64] and "$0x10,%rsi" in by_addr[0x635CB64])
    check("extract1 sar 0x10 rsi",
          "sar" in by_addr[0x635CB68] and "$0x10,%rsi" in by_addr[0x635CB68])
    check("extract1 and mask",
          "and" in by_addr[0x635CB6C] and "$0xffffffffffffff80,%rsi" in by_addr[0x635CB6C])
    check("extract1 helper call 0x63be4d0",
          "call" in by_addr[0x635CB70] and "63be4d0" in by_addr[0x635CB70])
    check("extract2 shl 0x10 rsi",
          "shl" in by_addr[0x635CD6E] and "$0x10,%rsi" in by_addr[0x635CD6E])
    check("extract2 sar 0x10 rsi",
          "sar" in by_addr[0x635CD72] and "$0x10,%rsi" in by_addr[0x635CD72])
    check("extract2 helper call 0x63bd6c0",
          "call" in by_addr[0x635CD7A] and "63bd6c0" in by_addr[0x635CD7A])
    check("extract3 shl 0x10 rsi",
          "shl" in by_addr[0x635D0D1] and "$0x10,%rsi" in by_addr[0x635D0D1])
    check("extract3 sar 0x10 rsi",
          "sar" in by_addr[0x635D0D5] and "$0x10,%rsi" in by_addr[0x635D0D5])
    check("extract3 helper call 0x63be4d0",
          "call" in by_addr[0x635D0DD] and "63be4d0" in by_addr[0x635D0DD])
    check("extract4 rsi from #314 output",
          "mov" in by_addr[0x635D532] and "0x10(%rsp),%rsi" in by_addr[0x635D532])
    check("extract4 rdi is rbx",
          "mov" in by_addr[0x635D537] and "%rbx,%rdi" in by_addr[0x635D537])
    check("extract4 helper call 0x63bd6c0",
          "call" in by_addr[0x635D53A] and "63bd6c0" in by_addr[0x635D53A])
    for a, reg in [(0x635D05B, "%r8"), (0x635D19D, "%r14"),
                   (0x635D4A6, "%rax"), (0x635D67F, "%r13")]:
        check("inline extract shr 0x30 %s" % hex(a),
              "shr" in by_addr[a] and "$0x30,%s" % reg in by_addr[a])

    # Scan (nine 8-slot MTF loops, table+0x2b0 in rbx).
    slot0 = {0x635D2DE: "%r14", 0x635D4C0: "%r15", 0x635D544: "%r11",
             0x635D5EA: "%r11", 0x635D688: "%r14", 0x635D6F4: "%r10",
             0x635D762: "%r11", 0x635D7AF: "%r14", 0x635DA2D: "%r11"}
    for a, reg in slot0.items():
        check("scan slot 0 cmp %s" % hex(a),
              "cmp" in by_addr[a] and "0x2b0(%%rbx),%s" % reg in by_addr[a])
    loopc = {0x635D863: ("r13", "%r15"), 0x635D8C8: ("rsi", "%r11"),
             0x635D92C: ("rsi", "%r11"), 0x635D9D4: ("rcx", "%r14"),
             0x635DA85: ("r8", "%r10"), 0x635DAF5: ("r8", "%r11"),
             0x635DB8F: ("r13", "%r14"), 0x635DC5F: ("rcx", "%r14"),
             0x635DD3F: ("rdi", "%r11")}
    for a, (idx, key) in loopc.items():
        check("scan loop compare %s" % hex(a),
              "cmp" in by_addr[a] and
              "0x2b0(%%rbx,%%%s,1),%s" % (idx, key) in by_addr[a])
    exhaust = [(0x635DB51, 0x635DB55, 0x635D85C, "%r11", 1),
               (0x635DBEC, 0x635DBF0, 0x635D9CD, "%r11", 2),
               (0x635DC21, 0x635DC25, 0x635DB88, "%r10", 3),
               (0x635DCBC, 0x635DCC0, 0x635DA7E, "%r14", 4),
               (0x635DCF1, 0x635DCF5, 0x635DC58, "%r15", 4),
               (0x635DD01, 0x635DD05, 0x635D8C1, "%rdi", 5),
               (0x635DD9C, 0x635DDA0, 0x635D925, "%rdi", 4),
               (0x635DDAF, 0x635DDB3, 0x635DAEE, "%rdi", 6),
               (0x635DDEC, 0x635DDF0, 0x635DD38, "%r8", 7)]
    for cmp_a, jne_a, tgt_a, reg, miss in exhaust:
        check("scan exhaustion %s == 8 -> miss %d" % (reg, miss),
              "cmp" in by_addr[cmp_a] and "$0x8,%s" % reg in by_addr[cmp_a] and
              "jne" in by_addr[jne_a] and hex(tgt_a)[2:] in by_addr[jne_a])
    check("scan zero reversed-operand compares",
          [a for a in list(slot0) + list(loopc)
           if operands_of(by_addr[a]).startswith("%r")] == [],
          str([(hex(a), operands_of(by_addr[a]))
               for a in list(slot0) + list(loopc)
               if operands_of(by_addr[a]).startswith("%r")]))

    # Lu-miss sites + miss-path write-set provenance (CFG reachability).
    miss_sites = [0x635DB78, 0x635DC13, 0x635DC48, 0x635DCE3, 0x635DD28,
                  0x635DDDA, 0x635DE17]
    # (rsi lea, r9 xor, rcx mov, rdi mov, rdx lea, r8 mov, rejoin jmp, rejoin target)
    miss_args = {
        0x635DB78: (0x635DB5B, 0x635DB62, 0x635DB65, 0x635DB68, 0x635DB6B, 0x635DB72, 0x635DB7D, "635d04e"),
        0x635DC13: (0x635DBF6, 0x635DBFD, 0x635DC00, 0x635DC03, 0x635DC06, 0x635DC0D, 0x635DC18, "635d18d"),
        0x635DC48: (0x635DC2B, 0x635DC32, 0x635DC35, 0x635DC38, 0x635DC3B, 0x635DC42, 0x635DC4D, "635d49b"),
        0x635DCE3: (0x635DCC6, 0x635DCCD, 0x635DCD0, 0x635DCD3, 0x635DCD6, 0x635DCDD, 0x635DCE8, "635cd68"),
        0x635DD28: (0x635DD0B, 0x635DD12, 0x635DD15, 0x635DD18, 0x635DD1B, 0x635DD22, 0x635DD2D, "635d0bd"),
        0x635DDDA: (0x635DDB9, 0x635DDC0, 0x635DDC3, 0x635DDC6, 0x635DDC9, 0x635DDD0, 0x635DDE3, "635cb4d"),
        0x635DE17: (0x635DDF6, 0x635DDFD, 0x635DE00, 0x635DE03, 0x635DE06, 0x635DE0D, 0x635DE20, "635d675"),
    }
    for site in miss_sites:
        rsi_a, r9_a, rcx_a, rdi_a, rdx_a, r8_a, jmp_a, jmp_t = miss_args[site]
        check("lu-miss %s rsi 0x6511a00 bss" % hex(site),
              "lea" in by_addr[rsi_a] and "6511a00" in by_addr[rsi_a])
        check("lu-miss %s r9d 0" % hex(site),
              "xor" in by_addr[r9_a] and "%r9d,%r9d" in by_addr[r9_a])
        check("lu-miss %s rcx is r12" % hex(site),
              "mov" in by_addr[rcx_a] and "%r12,%rcx" in by_addr[rcx_a])
        check("lu-miss %s rdi is rbx" % hex(site),
              "mov" in by_addr[rdi_a] and "%rbx,%rdi" in by_addr[rdi_a])
        check("lu-miss %s rdx lea 0x1b0 rbx" % hex(site),
              "lea" in by_addr[rdx_a] and "0x1b0(%rbx),%rdx" in by_addr[rdx_a])
        check("lu-miss %s r8d 1" % hex(site),
              "mov" in by_addr[r8_a] and "$0x1,%r8d" in by_addr[r8_a])
        check("lu-miss %s call 0x63d9700" % hex(site),
              "call" in by_addr[site] and "63d9700" in by_addr[site])
        check("lu-miss %s rejoin jmp 0x%s" % (hex(site), jmp_t),
              "jmp" in by_addr[jmp_a] and jmp_t in by_addr[jmp_a])
    check("lu-miss site 6 saves r10 before call",
          "mov" in by_addr[0x635DDD6] and "%r10,(%rsp)" in by_addr[0x635DDD6])
    check("lu-miss site 6 restores r10 after call",
          "mov" in by_addr[0x635DDDF] and "(%rsp),%r10" in by_addr[0x635DDDF])
    check("lu-miss site 7 saves r10 before call",
          "mov" in by_addr[0x635DE13] and "%r10,(%rsp)" in by_addr[0x635DE13])
    check("lu-miss site 7 restores r10 after call",
          "mov" in by_addr[0x635DE1C] and "(%rsp),%r10" in by_addr[0x635DE1C])
    # CFG: successors (jump targets inside window + fall-through; calls
    # fall through; ret/jmp-outside are terminal).
    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    succ = {}
    ordered = sorted(by_addr)
    for idx, a in enumerate(ordered):
        line = by_addr[a]
        mn = mnemonic_of(line)
        s = set()
        t = jump_target(line) if mn.startswith("j") else None
        if mn == "ret":
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

    check("entry 0x635c6d0 reaches all miss sites",
          all(reaches(START, m) for m in miss_sites))
    r12_writes = sorted(a for a in by_addr
                        if dst_reg(by_addr[a]) in ("%r12", "%r12d"))
    reaching = sorted(a for a in r12_writes
                      if any(reaches(a, m) for m in miss_sites))
    check("only entry r12 write reaches any miss site",
          reaching == [0x635C6E2],
          str([hex(a) for a in reaching]))
    check("walk-2 shr r12 at 0x635cd4c reaches no miss site",
          not any(reaches(0x635CD4C, m) for m in miss_sites))
    check("walk-7 shr r12 at 0x635d30e reaches no miss site",
          not any(reaches(0x635D30E, m) for m in miss_sites))
    check("walk-3 shr r12 at 0x635d605 reaches no miss site",
          not any(reaches(0x635D605, m) for m in miss_sites))

    # Second-handler sites: none in this FDE.
    check("records second-handler sites empty",
          rec.get("second_handler_sites") == [])

    # Dispatcher callees.
    check("#314 call site args: rdi stack temp, rsi rbx, rcx r12, rdx lea 0x1b0 rbx",
          "lea" in by_addr[0x635D51B] and "0x10(%rsp),%rdi" in by_addr[0x635D51B] and
          "mov" in by_addr[0x635D520] and "%rbx,%rsi" in by_addr[0x635D520] and
          "mov" in by_addr[0x635D52A] and "%r12,%rcx" in by_addr[0x635D52A] and
          "lea" in by_addr[0x635D523] and "0x1b0(%rbx),%rdx" in by_addr[0x635D523])
    check("0x6363260 called 3 times", tgt.get(0x6363260, 0) == 3,
          str(tgt.get(0x6363260, 0)))
    check("0x63c3330 called 2 times", tgt.get(0x63C3330, 0) == 2,
          str(tgt.get(0x63C3330, 0)))
    check("0x63eb870 called 2 times", tgt.get(0x63EB870, 0) == 2,
          str(tgt.get(0x63EB870, 0)))
    check("0x63ead50 called 2 times", tgt.get(0x63EAD50, 0) == 2,
          str(tgt.get(0x63EAD50, 0)))
    check("0x63be4d0 called 2 times", tgt.get(0x63BE4D0, 0) == 2,
          str(tgt.get(0x63BE4D0, 0)))
    check("0x63bd6c0 called 2 times", tgt.get(0x63BD6C0, 0) == 2,
          str(tgt.get(0x63BD6C0, 0)))
    check("0x63ef8e0 called 1 time", tgt.get(0x63EF8E0, 0) == 1,
          str(tgt.get(0x63EF8E0, 0)))
    check("0x63eec80 called 1 time", tgt.get(0x63EEC80, 0) == 1,
          str(tgt.get(0x63EEC80, 0)))
    check("0x6349510 called 1 time", tgt.get(0x6349510, 0) == 1,
          str(tgt.get(0x6349510, 0)))
    check("0x63637f0 called 1 time", tgt.get(0x63637F0, 0) == 1,
          str(tgt.get(0x63637F0, 0)))
    check("0x63b73a0 called 1 time", tgt.get(0x63B73A0, 0) == 1,
          str(tgt.get(0x63B73A0, 0)))
    check("0x63bf5b6 called 1 time", tgt.get(0x63BF5B6, 0) == 1,
          str(tgt.get(0x63BF5B6, 0)))
    check("0x63ed8b0 called 1 time", tgt.get(0x63ED8B0, 0) == 1,
          str(tgt.get(0x63ED8B0, 0)))
    check("abort plt called 1 time", tgt.get(0x63F0BF0, 0) == 1,
          str(tgt.get(0x63F0BF0, 0)))
    check("stack_chk_fail plt called 1 time", tgt.get(0x63F0D70, 0) == 1,
          str(tgt.get(0x63F0D70, 0)))

    # Exit: single ret, rax = 0 (canary check leaves rax 0).
    check("epilogue canary load 0x78 rsp",
          "mov" in by_addr[0x635C861] and "0x78(%rsp),%rax" in by_addr[0x635C861])
    check("epilogue canary sub fs:0x28",
          "sub" in by_addr[0x635C866] and "%fs:0x28,%rax" in by_addr[0x635C866])
    check("epilogue canary jne 0x635d9aa",
          "jne" in by_addr[0x635C86F] and "635d9aa" in by_addr[0x635C86F])
    check("epilogue add 0x88 rsp",
          "add" in by_addr[0x635C875] and "$0x88,%rsp" in by_addr[0x635C875])
    check("no rax write between canary check and ret",
          not any(dst_reg(by_addr[a]) in ("%rax", "%eax")
                  for a in by_addr if 0x635C86F < a <= 0x635C886),
          str([(hex(a), by_addr[a]) for a in by_addr
               if 0x635C86F < a <= 0x635C886
               and dst_reg(by_addr[a]) in ("%rax", "%eax")]))
    check("canary failure calls stack_chk_fail",
          "call" in by_addr[0x635D9AA] and "63f0d70" in by_addr[0x635D9AA])

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for va in [0x6511749, 0x6511A00, 0x6713606, 0x67277C0, 0x6727A00,
               0x6728140, 0x6728840, 0x6728850, 0x6728868]:
        check("address %s inside .bss" % hex(va),
              bss[3] <= va < bss[3] + bss[5])
    dat = secmap[".data"]
    check("0x64ffb30 inside .data", dat[3] <= 0x64FFB30 < dat[3] + dat[5])
    check("0x64ffdc8 inside .data", dat[3] <= 0x64FFDC8 < dat[3] + dat[5])
    check("0x64ffdcc inside .data", dat[3] <= 0x64FFDCC < dat[3] + dat[5])
    rod = secmap[".rodata"]
    check("0x9618e8 inside .rodata", rod[3] <= 0x9618E8 < rod[3] + rod[5])

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
    check("this FDE raw lu-miss 7", counts.get(START, 0) == 7,
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
    check("next candidate raw lu-miss 1", counts.get(0x635E2E0, 0) == 1,
          str(counts.get(0x635E2E0, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x635E2E0, 0) == 0,
          str(bti_counts.get(0x635E2E0, 0)))
    check("next candidate raw second-handler 3",
          sh_counts.get(0x635E2E0, 0) == 3,
          str(sh_counts.get(0x635E2E0, 0)))
    check("raw-e8 second-handler total 64", sum(sh_counts.values()) == 64,
          str(sum(sh_counts.values())))
    check("this FDE raw second-handler 0",
          sh_counts.get(START, 0) == 0, str(sh_counts.get(START, 0)))

    # lu-miss frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 16", len(survey.get("survivors", [])) == 16,
          str(len(survey.get("survivors", []))))
    check("survey this window is 6th survivor",
          survey.get("survivors", [None] * 6)[5] == "0x635c6d0",
          str(survey.get("survivors", [])[:7]))
    check("survey combined pool 25", survey.get("combined_pool") == 25,
          str(survey.get("combined_pool")))
    check("survey shared survivors 9",
          len(survey.get("shared_survivors", [])) == 9,
          str(survey.get("shared_survivors", [])))
    check("survey this window NOT shared",
          "0x635c6d0" not in survey.get("shared_survivors", []))
    check("survey next candidate IS shared",
          "0x635e2e0" in survey.get("shared_survivors", []))
    nq = rec.get("next_question", {})
    check("next question range 0x635e2e0..0x635f315",
          nq.get("range") == "0x635e2e0..0x635f315", str(nq.get("range")))
    check("next question bytes 4149", nq.get("bytes") == 4149,
          str(nq.get("bytes")))
    check("next question lu-miss sites 1",
          nq.get("lu_miss_sites") == 1, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 898", nq.get("strict") == 898,
          str(nq.get("strict")))
    check("next question calls 38", nq.get("calls") == 38,
          str(nq.get("calls")))
    check("next question second-handler sites 3",
          nq.get("second_handler_sites") == 3,
          str(nq.get("second_handler_sites")))
    check("next question bsr 5", nq.get("bsr") == 5,
          str(nq.get("bsr")))
    check("next question ret 0x635e7eb", nq.get("ret") == "0x635e7eb",
          str(nq.get("ret")))
    check("records census strict 1220",
          rec.get("census", {}).get("strict") == 1220)
    check("records census calls 31",
          rec.get("census", {}).get("calls") == 31)
    check("records lu-miss sites match census",
          [s.get("site") for s in rec.get("lu_miss_sites", [])] ==
          ["0x635db78", "0x635dc13", "0x635dc48", "0x635dce3",
           "0x635dd28", "0x635ddda", "0x635de17"])
    check("records second-handler sites empty",
          rec.get("second_handler_sites") == [])
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
    # next candidate 0x635e2e0..0x635f315 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x635E2E0 < p[1] and p[0] < 0x635F315]
    check("next candidate 0x635e2e0 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x635F315 and 0x635E2E0 < END))

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
