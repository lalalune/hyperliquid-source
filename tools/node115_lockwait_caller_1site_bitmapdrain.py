"""Static verifier for RE-001-node115-lockwait-caller-1site-bitmapdrain.

SECOND packet of the lock-wait-helper-caller frontier (callers of the
lock-wait helper 0x63bf680): FDE 0x6362910..0x6362f82, 1,650 bytes, 393
strict instructions, 9 calls (1 lock-wait site at 0x6362f25, 0
lu-miss, 0 bin_table_init, 0 second-handler sites), 1 ret at
0x6362e78 with exit value r15 (the drained element count), bsr 0, 45
jumps with 0 outside, endbr64 1, NO canary, lock sub 0 / lock add 0,
NO TLS flag check, NO prefetch instructions.

Shape: bitmap drain. The outer loop fetches nodes with helper
0x63606d0; per node a 10-entry unrolled scan finds a nonzero 64-bit
bitmap word at node+0x40, then tzcnt/btc bit extraction (7 tzcnt +
7 btc: 3-bit remainder prologue + 4-at-a-time loop + trailing
single) writes normalized pointers to the output array; the head
word is decremented by (count << 28). Then trylock(node+0x40) at
0x6362d77; on failure the lock-wait helper 0x63bf680 is called at
0x6362f25 with a single argument (rdi = current node pointer,
proven by reaching-definitions) -> waited flag set -> retry at
0x6362d89. Epilogue: stats, waited-flag clear, unlock, refcount
decrement at 0x98(%rdi); a last-reference drop calls 0x6360ed0
(itself a lock-wait survivor).

#330's pointer for this window (1,650 bytes, 393 strict, 9 calls,
1 lock-wait site at 0x6362f25, 0 lu-miss / 0 bin_table_init /
0 second-handler sites, 1 ret at 0x6362e78, bsr 0, endbr64 1, NO
canary, 45 jumps, 0 outside) was verified correct by targeted
objdump census -- NO correction (prior_pointer_verified).

The lu-miss frontier is exhausted (16/16 claimed, #314-#329). The
lock-wait frontier has 344 survivors (474 sites / 385 FDEs, 319
with exactly 1 site); this packet claims the second-largest 1-site
disjoint survivor in the 500-2000B range.

Next question: 0x636a140..0x636a675 (1,333 bytes, 315 strict, 17
calls -- 15 direct + 2 indirect call *(%r15) -- 1 lock-wait site
at 0x636a61e, 0 lu-miss / 0 bin_table_init / 0 second-handler
sites, 1 ret at 0x636a38c, bsr 2, endbr64 0, canary present, 42
jumps, 0 outside). The stated 15-call figure handed down with the
task was corrected: targeted census shows 17.

Usage: python3 tools/node115_lockwait_caller_1site_bitmapdrain.py
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
                      "RE-001-node115-lockwait-caller-1site-bitmapdrain")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lockwait-caller-1site-bitmapdrain"
NAME = "lockwait_caller_1site_bitmapdrain"
START, END = 0x6362910, 0x6362F82

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
    check("target FDE size 1650", END - START == 1650)
    prev = fdes[i - 1]
    check("prev FDE 0x6362190..0x6362901 (#330 window)",
          prev == (0x6362190, 0x6362901), str(prev))
    check("prev gap 15 (0xcc padding)", START - prev[1] == 15)
    check("prev gap bytes are 0xcc int3 padding",
          node[toff(prev[1]):toff(START)] == b"\xcc" * 15)
    nxt = fdes[i + 1]
    check("next FDE 0x6362f90..0x6363258",
          nxt == (0x6362F90, 0x6363258), str(nxt))
    check("next gap 14 (0xcc padding)", nxt[0] - END == 14)
    check("next gap bytes are 0xcc int3 padding",
          node[toff(END):toff(nxt[0])] == b"\xcc" * 14)
    check("next FDE starts endbr64",
          node[toff(nxt[0]):toff(nxt[0]) + 4] == b"\xf3\x0f\x1e\xfa")
    check("prev FDE end is 15 bytes before this FDE start",
          prev[1] == START - 15)
    check("call-target FDE 0x6360ed0..0x636116d",
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
    check("next-question FDE 0x636a140..0x636a675",
          fdes[bisect.bisect_left(starts, 0x636A140)] ==
          (0x636A140, 0x636A675))

    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_bitmapdrain.hex"))
    check("hex exhibit raw bytes 1650", len(hexb) == 1650, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_bitmapdrain.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 393", len(lines) == 393, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 9", len(calls) == 9, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x6362e78",
          sorted(addr_of(l) for l in rets) == [0x6362E78],
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
    expect = {0x63606D0: 1, 0x63F0960: 1, 0x63F17B0: 1, 0x635F3A0: 1,
              0x63F0B70: 1, 0x63F0A90: 1, 0x63BF680: 1, 0x635F340: 1,
              0x6360ED0: 1}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct call targets 9", len(tgt) == 9, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 0",
          tgt.get(0x63D9700, 0) == 0, str(tgt.get(0x63D9700, 0)))
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called 1 time", tgt.get(0x63BF680, 0) == 1,
          str(tgt.get(0x63BF680, 0)))
    check("lock-wait site is 0x6362f25",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x6362F25])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("stack_chk_fail plt call 0",
          tgt.get(0x63F0D70, 0) == 0, str(tgt.get(0x63F0D70, 0)))
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 3 (by @plt suffix, not address range)",
          len(plt_calls) == 3, str(len(plt_calls)))
    check("distinct PLT targets 3",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 3)
    check("0x63f0960 is an internal .text call, NOT a PLT stub",
          not any("63f0960" in l and "@plt" in l for l in calls))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0), ("#325", 0x63D17E0),
                  ("#326", 0x63D2A80), ("#327", 0x63D3F0E),
                  ("#328", 0x63D4048), ("#329", 0x63E94A0),
                  ("#330", 0x6362190)):
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
    check("jump lines 45", len(jmps) == 45, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure: 0 outside the window", outside == [], str(outside))
    check("jump targets are exactly the 45 branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x63629B3, 0x63629B3, 0x63629B9, 0x6362A20, 0x6362AA8,
           0x6362B6D, 0x6362B80, 0x6362B80, 0x6362B80, 0x6362C2D,
           0x6362C58, 0x6362CC0, 0x6362CC0, 0x6362CC0, 0x6362D14,
           0x6362D2C, 0x6362D3D, 0x6362D4B, 0x6362D5E, 0x6362D89,
           0x6362D9D, 0x6362DBC, 0x6362E11, 0x6362E11, 0x6362E11,
           0x6362E64, 0x6362E64, 0x6362E64, 0x6362E80, 0x6362E80,
           0x6362E80, 0x6362E80, 0x6362E80, 0x6362E80, 0x6362E80,
           0x6362E80, 0x6362E88, 0x6362EE3, 0x6362EE3, 0x6362EEB,
           0x6362F18, 0x6362F22, 0x6362F38, 0x6362F4C, 0x6362F54],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x6362910",
          "endbr64" in by_addr[START])
    check("canary absent: 0 fs:0x28 lines",
          [l for l in lines if "%fs:0x28" in l] == [])
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
    check("no shr $0x1c anywhere (no 10-bit tag extract)",
          not any("shr" in l and "$0x1c" in l for l in lines))
    check("bss table lea 0x6711b40 at 0x636292b",
          "lea" in by_addr[0x636292B] and "6711b40" in by_addr[0x636292B])
    check("bss lea 0x650969c at 0x6362948",
          "lea" in by_addr[0x6362948] and "650969c" in by_addr[0x6362948])
    check("bss lea 0x6511780 at 0x63629c2",
          "lea" in by_addr[0x63629C2] and "6511780" in by_addr[0x63629C2])
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 7",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "tzcnt") ==
          [0x6362BDD, 0x6362C13, 0x6362C38, 0x6362C63, 0x6362C75,
           0x6362C9D, 0x6362CC8])
    check("btc 7",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "btc") ==
          [0x6362BE2, 0x6362C18, 0x6362C40, 0x6362C6E, 0x6362C7E,
           0x6362CAD, 0x6362CD0])
    check("tzcnt/btc pairs share the same bitmap word (7 each)",
          len([l for l in lines if mnemonic_of(l) == "tzcnt"]) ==
          len([l for l in lines if mnemonic_of(l) == "btc"]) == 7)
    check("head-word decrement: shl $0x1c at 0x6362d17",
          "shl" in by_addr[0x6362D17] and "$0x1c,%rbx" in by_addr[0x6362D17])
    check("head-word decrement: sub at 0x6362d1b",
          "sub" in by_addr[0x6362D1B] and "(%r11)" in by_addr[0x6362D1B])
    check("bitmap writeback at 0x6362cf1",
          "mov" in by_addr[0x6362CF1]
          and "0x40(%r15,%r14,8)" in by_addr[0x6362CF1])
    check("memset call at 0x6362f05",
          "call" in by_addr[0x6362F05] and "63f0a90" in by_addr[0x6362F05])
    check("node-fetcher call at 0x6362a3a",
          "call" in by_addr[0x6362A3A] and "63606d0" in by_addr[0x6362A3A])
    check("last-ref drop call at 0x6362f78",
          "call" in by_addr[0x6362F78] and "6360ed0" in by_addr[0x6362F78])
    check("cleanup call at 0x6362f5f",
          "call" in by_addr[0x6362F5F] and "635f340" in by_addr[0x6362F5F])
    check("output index init xor r13d at 0x63629e0",
          "xor" in by_addr[0x63629E0] and "%r13d,%r13d" in by_addr[0x63629E0])
    check("exit value mov r15 rax at 0x6362e6b",
          "mov" in by_addr[0x6362E6B] and "%r15,%rax" in by_addr[0x6362E6B])

    # Instruction spot checks: (address, mnemonic, operand substring).
    # Exhaustive: every strict line of the exhibit.
    EXPECT = [
        (0x6362910, 'endbr64', ''),
        (0x6362914, 'push', '%r15'),
        (0x6362916, 'mov', '%rdi,%r11'),
        (0x6362919, 'push', '%r14'),
        (0x636291b, 'push', '%r13'),
        (0x636291d, 'push', '%r12'),
        (0x636291f, 'push', '%rbp'),
        (0x6362920, 'push', '%rbx'),
        (0x6362921, 'mov', '%rsi,%rbx'),
        (0x6362924, 'sub', '$0xb8,%rsp'),
        (0x636292b, 'lea', '0x3af20e(%rip),%rdi       '),
        (0x6362932, 'mov', '0x13450(%rbx),%ebp'),
        (0x6362938, 'mov', '%rsi,0x50(%rsp)'),
        (0x636293d, 'mov', '%edx,%esi'),
        (0x636293f, 'mov', '%r8,0x28(%rsp)'),
        (0x6362944, 'lea', '(%rsi,%rsi,4),%rax'),
        (0x6362948, 'lea', '0x1a6d4d(%rip),%r8       '),
        (0x636294f, 'lea', '(%rdi,%rax,8),%r10'),
        (0x6362953, 'mov', '%edx,0x6c(%rsp)'),
        (0x6362957, 'mov', '%rcx,0x78(%rsp)'),
        (0x636295c, 'mov', '0x10(%r10),%edx'),
        (0x6362960, 'mov', '%r9b,0x87(%rsp)'),
        (0x6362968, 'mov', '(%r10),%rcx'),
        (0x636296b, 'mov', '(%r8),%r9d'),
        (0x636296e, 'mov', '%rdx,0x30(%rsp)'),
        (0x6362973, 'mov', '%rcx,0xa0(%rsp)'),
        (0x636297b, 'mov', '%ebp,0x98(%rsp)'),
        (0x6362982, 'mov', '%r9d,0x9c(%rsp)'),
        (0x636298a, 'test', '%r11,%r11'),
        (0x636298d, 'je', '63629b3 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a583>'),
        (0x636298f, 'cmpq', '$0x0,0x90(%r11)'),
        (0x6362997, 'je', '63629b3 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a583>'),
        (0x6362999, 'movzbl', '0xa1(%r11,%rsi,1),%r14d'),
        (0x63629a2, 'lea', '0x0(,%r14,8),%r13'),
        (0x63629aa, 'sub', '%r14,%r13'),
        (0x63629ad, 'shl', '$0x5,%r13'),
        (0x63629b1, 'jmp', '63629b9 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a589>'),
        (0x63629b3, 'xor', '%r13d,%r13d'),
        (0x63629b6, 'xor', '%r14d,%r14d'),
        (0x63629b9, 'movq', '$0x0,0x60(%rsp)'),
        (0x63629c2, 'lea', '0x1aedb7(%rip),%r15       '),
        (0x63629c9, 'movq', '$0x0,0x90(%rsp)'),
        (0x63629d5, 'mov', '(%r15,%rsi,4),%eax'),
        (0x63629d9, 'add', '%rbx,%rax'),
        (0x63629dc, 'lea', '(%rax,%r13,1),%rbx'),
        (0x63629e0, 'xor', '%r13d,%r13d'),
        (0x63629e3, 'cmpq', '$0x0,0x28(%rsp)'),
        (0x63629e9, 'mov', '%r13,%r15'),
        (0x63629ec, 'je', '6362f4c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61ab1c>'),
        (0x63629f2, 'lea', '(%rsi,%rsi,4),%rsi'),
        (0x63629f6, 'mov', '%r10,0x70(%rsp)'),
        (0x63629fb, 'lea', '(%rdi,%rsi,8),%rdi'),
        (0x63629ff, 'mov', '%r14d,0x80(%rsp)'),
        (0x6362a07, 'mov', '%rdi,0x88(%rsp)'),
        (0x6362a0f, 'mov', '%rbx,0xa8(%rsp)'),
        (0x6362a17, 'mov', '%r11,0x58(%rsp)'),
        (0x6362a1c, 'nopl', '0x0(%rax)'),
        (0x6362a20, 'mov', '0x70(%rsp),%r8'),
        (0x6362a25, 'mov', '0x80(%rsp),%ecx'),
        (0x6362a2c, 'mov', '0x6c(%rsp),%edx'),
        (0x6362a30, 'mov', '0x50(%rsp),%rsi'),
        (0x6362a35, 'mov', '0x58(%rsp),%rdi'),
        (0x6362a3a, 'call', '63606d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6182a0>'),
        (0x6362a3f, 'mov', '%rax,%r11'),
        (0x6362a42, 'test', '%rax,%rax'),
        (0x6362a45, 'je', '6362d4b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a91b>'),
        (0x6362a4b, 'mov', '0x28(%rsp),%r8'),
        (0x6362a50, 'mov', '0x30(%rsp),%r14'),
        (0x6362a55, 'addq', '$0x1,0x60(%rsp)'),
        (0x6362a5b, 'mov', '0x78(%rsp),%rdx'),
        (0x6362a60, 'sub', '%r13,%r8'),
        (0x6362a63, 'mov', '0x40(%r11),%rbx'),
        (0x6362a67, 'cmp', '%r8,%r14'),
        (0x6362a6a, 'lea', '(%rdx,%r13,8),%r15'),
        (0x6362a6e, 'cmova', '%r8,%r14'),
        (0x6362a72, 'test', '%r14,%r14'),
        (0x6362a75, 'je', '6362d14 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a8e4>'),
        (0x6362a7b, 'mov', '0x88(%rsp),%rbp'),
        (0x6362a83, 'mov', '%r14d,(%rsp)'),
        (0x6362a87, 'xor', '%esi,%esi'),
        (0x6362a89, 'mov', '%r8,0x38(%rsp)'),
        (0x6362a8e, 'mov', '%r14,0x40(%rsp)'),
        (0x6362a93, 'mov', '0x0(%rbp),%r9'),
        (0x6362a97, 'xor', '%ebp,%ebp'),
        (0x6362a99, 'mov', '%r13,0x48(%rsp)'),
        (0x6362a9e, 'mov', '%r15,%r13'),
        (0x6362aa1, 'mov', '%r11,%r15'),
        (0x6362aa4, 'nopl', '0x0(%rax)'),
        (0x6362aa8, 'mov', '%esi,%r14d'),
        (0x6362aab, 'test', '%rbx,%rbx'),
        (0x6362aae, 'jne', '6362b80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a750>'),
        (0x6362ab4, 'lea', '0x1(%rsi),%r14d'),
        (0x6362ab8, 'mov', '0x40(%r15,%r14,8),%rbx'),
        (0x6362abd, 'mov', '%r14,%r10'),
        (0x6362ac0, 'test', '%rbx,%rbx'),
        (0x6362ac3, 'jne', '6362e80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa50>'),
        (0x6362ac9, 'lea', '0x2(%rsi),%r14d'),
        (0x6362acd, 'mov', '0x40(%r15,%r14,8),%rbx'),
        (0x6362ad2, 'mov', '%r14,%r10'),
        (0x6362ad5, 'test', '%rbx,%rbx'),
        (0x6362ad8, 'jne', '6362e80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa50>'),
        (0x6362ade, 'lea', '0x3(%rsi),%r14d'),
        (0x6362ae2, 'mov', '0x40(%r15,%r14,8),%rbx'),
        (0x6362ae7, 'mov', '%r14,%r10'),
        (0x6362aea, 'test', '%rbx,%rbx'),
        (0x6362aed, 'jne', '6362e80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa50>'),
        (0x6362af3, 'lea', '0x4(%rsi),%r14d'),
        (0x6362af7, 'mov', '0x40(%r15,%r14,8),%rbx'),
        (0x6362afc, 'mov', '%r14,%r10'),
        (0x6362aff, 'test', '%rbx,%rbx'),
        (0x6362b02, 'jne', '6362e80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa50>'),
        (0x6362b08, 'lea', '0x5(%rsi),%r14d'),
        (0x6362b0c, 'mov', '0x40(%r15,%r14,8),%rbx'),
        (0x6362b11, 'mov', '%r14,%r10'),
        (0x6362b14, 'test', '%rbx,%rbx'),
        (0x6362b17, 'jne', '6362e80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa50>'),
        (0x6362b1d, 'lea', '0x6(%rsi),%r14d'),
        (0x6362b21, 'mov', '0x40(%r15,%r14,8),%rbx'),
        (0x6362b26, 'mov', '%r14,%r10'),
        (0x6362b29, 'test', '%rbx,%rbx'),
        (0x6362b2c, 'jne', '6362e80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa50>'),
        (0x6362b32, 'lea', '0x7(%rsi),%r14d'),
        (0x6362b36, 'mov', '0x40(%r15,%r14,8),%rbx'),
        (0x6362b3b, 'mov', '%r14,%r10'),
        (0x6362b3e, 'test', '%rbx,%rbx'),
        (0x6362b41, 'jne', '6362e80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa50>'),
        (0x6362b47, 'lea', '0x8(%rsi),%r14d'),
        (0x6362b4b, 'mov', '0x40(%r15,%r14,8),%rbx'),
        (0x6362b50, 'mov', '%r14,%r10'),
        (0x6362b53, 'test', '%rbx,%rbx'),
        (0x6362b56, 'jne', '6362e80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa50>'),
        (0x6362b5c, 'lea', '0x9(%rsi),%r14d'),
        (0x6362b60, 'mov', '0x40(%r15,%r14,8),%rbx'),
        (0x6362b65, 'mov', '%r14,%rsi'),
        (0x6362b68, 'test', '%rbx,%rbx'),
        (0x6362b6b, 'jne', '6362b80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a750>'),
        (0x6362b6d, 'lea', '0x1(%rsi),%r14d'),
        (0x6362b71, 'mov', '0x40(%r15,%r14,8),%rbx'),
        (0x6362b76, 'mov', '%r14,%rsi'),
        (0x6362b79, 'test', '%rbx,%rbx'),
        (0x6362b7c, 'je', '6362b6d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a73d>'),
        (0x6362b7e, 'xchg', '%ax,%ax'),
        (0x6362b80, 'mov', '%rbx,%rdi'),
        (0x6362b83, 'mov', '%esi,%r12d'),
        (0x6362b86, 'mov', '%r9,0x20(%rsp)'),
        (0x6362b8b, 'mov', '%esi,0x18(%rsp)'),
        (0x6362b8f, 'shl', '$0x6,%r12d'),
        (0x6362b93, 'call', '63f0960 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6a8530>'),
        (0x6362b98, 'mov', '(%rsp),%r8d'),
        (0x6362b9c, 'mov', '0x8(%r15),%rdx'),
        (0x6362ba0, 'movslq', '%eax,%rsi'),
        (0x6362ba3, 'mov', '0x20(%rsp),%r9'),
        (0x6362ba8, 'sub', '%ebp,%r8d'),
        (0x6362bab, 'sub', '$0x1,%rsi'),
        (0x6362baf, 'mov', '%r8d,%edi'),
        (0x6362bb2, 'sub', '$0x1,%rdi'),
        (0x6362bb6, 'cmp', '%eax,%r8d'),
        (0x6362bb9, 'cmovae', '%rsi,%rdi'),
        (0x6362bbd, 'mov', '0x18(%rsp),%esi'),
        (0x6362bc1, 'mov', '%rdi,%rcx'),
        (0x6362bc4, 'lea', '-0x1(%rdi),%r8'),
        (0x6362bc8, 'and', '$0x3,%ecx'),
        (0x6362bcb, 'je', '6362cc0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a890>'),
        (0x6362bd1, 'xor', '%eax,%eax'),
        (0x6362bd3, 'mov', '%ebp,%r11d'),
        (0x6362bd6, 'lea', '-0x2(%rdi),%r8'),
        (0x6362bda, 'add', '$0x1,%ebp'),
        (0x6362bdd, 'tzcnt', '%rbx,%rax'),
        (0x6362be2, 'btc', '%rax,%rbx'),
        (0x6362be6, 'cltq', ''),
        (0x6362be8, 'add', '%r12,%rax'),
        (0x6362beb, 'imul', '%r9,%rax'),
        (0x6362bef, 'add', '%rdx,%rax'),
        (0x6362bf2, 'mov', '%rax,0x0(%r13,%r11,8)'),
        (0x6362bf7, 'cmp', '$0x1,%rcx'),
        (0x6362bfb, 'je', '6362cc0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a890>'),
        (0x6362c01, 'cmp', '$0x2,%rcx'),
        (0x6362c05, 'je', '6362c2d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a7fd>'),
        (0x6362c07, 'xor', '%eax,%eax'),
        (0x6362c09, 'mov', '%ebp,%r10d'),
        (0x6362c0c, 'lea', '-0x3(%rdi),%r8'),
        (0x6362c10, 'add', '$0x1,%ebp'),
        (0x6362c13, 'tzcnt', '%rbx,%rax'),
        (0x6362c18, 'btc', '%rax,%rbx'),
        (0x6362c1c, 'cltq', ''),
        (0x6362c1e, 'add', '%r12,%rax'),
        (0x6362c21, 'imul', '%r9,%rax'),
        (0x6362c25, 'add', '%rdx,%rax'),
        (0x6362c28, 'mov', '%rax,0x0(%r13,%r10,8)'),
        (0x6362c2d, 'xor', '%edi,%edi'),
        (0x6362c2f, 'mov', '%ebp,%ecx'),
        (0x6362c31, 'sub', '$0x1,%r8'),
        (0x6362c35, 'add', '$0x1,%ebp'),
        (0x6362c38, 'tzcnt', '%rbx,%rdi'),
        (0x6362c3d, 'movslq', '%edi,%r11'),
        (0x6362c40, 'btc', '%rdi,%rbx'),
        (0x6362c44, 'add', '%r12,%r11'),
        (0x6362c47, 'imul', '%r9,%r11'),
        (0x6362c4b, 'add', '%rdx,%r11'),
        (0x6362c4e, 'mov', '%r11,0x0(%r13,%rcx,8)'),
        (0x6362c53, 'jmp', '6362cc0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a890>'),
        (0x6362c55, 'nopl', '(%rax)'),
        (0x6362c58, 'xor', '%ecx,%ecx'),
        (0x6362c5a, 'xor', '%r11d,%r11d'),
        (0x6362c5d, 'mov', '%ebp,%eax'),
        (0x6362c5f, 'sub', '$0x4,%r8'),
        (0x6362c63, 'tzcnt', '%rbx,%rcx'),
        (0x6362c68, 'lea', '0x1(%rbp),%edi'),
        (0x6362c6b, 'movslq', '%ecx,%r10'),
        (0x6362c6e, 'btc', '%rcx,%rbx'),
        (0x6362c72, 'add', '%r12,%r10'),
        (0x6362c75, 'tzcnt', '%rbx,%r11'),
        (0x6362c7a, 'imul', '%r9,%r10'),
        (0x6362c7e, 'btc', '%r11,%rbx'),
        (0x6362c82, 'movslq', '%r11d,%rcx'),
        (0x6362c85, 'add', '%r12,%rcx'),
        (0x6362c88, 'imul', '%r9,%rcx'),
        (0x6362c8c, 'add', '%rdx,%r10'),
        (0x6362c8f, 'mov', '%r10,0x0(%r13,%rax,8)'),
        (0x6362c94, 'xor', '%eax,%eax'),
        (0x6362c96, 'lea', '0x2(%rbp),%r10d'),
        (0x6362c9a, 'add', '$0x3,%ebp'),
        (0x6362c9d, 'tzcnt', '%rbx,%rax'),
        (0x6362ca2, 'add', '%rdx,%rcx'),
        (0x6362ca5, 'movslq', '%eax,%r11'),
        (0x6362ca8, 'mov', '%rcx,0x0(%r13,%rdi,8)'),
        (0x6362cad, 'btc', '%rax,%rbx'),
        (0x6362cb1, 'add', '%r12,%r11'),
        (0x6362cb4, 'imul', '%r9,%r11'),
        (0x6362cb8, 'add', '%rdx,%r11'),
        (0x6362cbb, 'mov', '%r11,0x0(%r13,%r10,8)'),
        (0x6362cc0, 'xor', '%eax,%eax'),
        (0x6362cc2, 'mov', '%ebp,%r10d'),
        (0x6362cc5, 'add', '$0x1,%ebp'),
        (0x6362cc8, 'tzcnt', '%rbx,%rax'),
        (0x6362ccd, 'movslq', '%eax,%rdi'),
        (0x6362cd0, 'btc', '%rax,%rbx'),
        (0x6362cd4, 'add', '%r12,%rdi'),
        (0x6362cd7, 'imul', '%r9,%rdi'),
        (0x6362cdb, 'add', '%rdx,%rdi'),
        (0x6362cde, 'mov', '%rdi,0x0(%r13,%r10,8)'),
        (0x6362ce3, 'cmp', '$0xffffffffffffffff,%r8'),
        (0x6362ce7, 'jne', '6362c58 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a828>'),
        (0x6362ced, 'mov', '(%rsp),%r12d'),
        (0x6362cf1, 'mov', '%rbx,0x40(%r15,%r14,8)'),
        (0x6362cf6, 'cmp', '%r12d,%ebp'),
        (0x6362cf9, 'jb', '6362aa8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a678>'),
        (0x6362cff, 'mov', '%r15,%r11'),
        (0x6362d02, 'mov', '0x38(%rsp),%r8'),
        (0x6362d07, 'mov', '%r13,%r15'),
        (0x6362d0a, 'mov', '0x40(%rsp),%r14'),
        (0x6362d0f, 'mov', '0x48(%rsp),%r13'),
        (0x6362d14, 'mov', '%r14,%rbx'),
        (0x6362d17, 'shl', '$0x1c,%rbx'),
        (0x6362d1b, 'sub', '%rbx,(%r11)'),
        (0x6362d1e, 'cmpb', '$0x0,0x87(%rsp)'),
        (0x6362d26, 'jne', '6362eeb <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aabb>'),
        (0x6362d2c, 'mov', '0x30(%rsp),%rdx'),
        (0x6362d31, 'add', '%r14,%r13'),
        (0x6362d34, 'cmp', '%rdx,%r8'),
        (0x6362d37, 'jae', '6362e88 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa58>'),
        (0x6362d3d, 'mov', '0x28(%rsp),%r12'),
        (0x6362d42, 'cmp', '%r12,%r13'),
        (0x6362d45, 'jb', '6362a20 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a5f0>'),
        (0x6362d4b, 'mov', '%r11,%r14'),
        (0x6362d4e, 'mov', '0xa8(%rsp),%rbx'),
        (0x6362d56, 'mov', '0x58(%rsp),%r11'),
        (0x6362d5b, 'mov', '%r13,%r15'),
        (0x6362d5e, 'movq', '%r15,%xmm1'),
        (0x6362d63, 'lea', '0x40(%rbx),%r13'),
        (0x6362d67, 'mov', '%r11,0x18(%rsp)'),
        (0x6362d6c, 'punpcklqdq', '%xmm1,%xmm1'),
        (0x6362d70, 'mov', '%r13,%rdi'),
        (0x6362d73, 'movaps', '%xmm1,(%rsp)'),
        (0x6362d77, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),
        (0x6362d7c, 'mov', '0x18(%rsp),%r8'),
        (0x6362d81, 'test', '%eax,%eax'),
        (0x6362d83, 'jne', '6362f22 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aaf2>'),
        (0x6362d89, 'addq', '$0x1,0x38(%rbx)'),
        (0x6362d8e, 'cmp', '0x30(%rbx),%r8'),
        (0x6362d92, 'je', '6362d9d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a96d>'),
        (0x6362d94, 'addq', '$0x1,0x28(%rbx)'),
        (0x6362d99, 'mov', '%r8,0x30(%rbx)'),
        (0x6362d9d, 'test', '%r14,%r14'),
        (0x6362da0, 'je', '6362dbc <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a98c>'),
        (0x6362da2, 'mov', '0x50(%rsp),%rdi'),
        (0x6362da7, 'mov', '%rbx,%rdx'),
        (0x6362daa, 'mov', '%r14,%rsi'),
        (0x6362dad, 'mov', '%r8,0x18(%rsp)'),
        (0x6362db2, 'call', '635f3a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x616f70>'),
        (0x6362db7, 'mov', '0x18(%rsp),%r8'),
        (0x6362dbc, 'mov', '0x9c(%rsp),%edx'),
        (0x6362dc3, 'cmp', '%edx,0x98(%rsp)'),
        (0x6362dca, 'jb', '6362e11 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a9e1>'),
        (0x6362dcc, 'mov', '0xd8(%rbx),%rbp'),
        (0x6362dd3, 'test', '%rbp,%rbp'),
        (0x6362dd6, 'je', '6362f38 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61ab08>'),
        (0x6362ddc, 'mov', '0x90(%rsp),%r9'),
        (0x6362de4, 'test', '%r9,%r9'),
        (0x6362de7, 'je', '6362e11 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a9e1>'),
        (0x6362de9, 'mov', '0x30(%r9),%rsi'),
        (0x6362ded, 'mov', '0x30(%rbp),%rcx'),
        (0x6362df1, 'mov', '%rcx,0x28(%rsi)'),
        (0x6362df5, 'mov', '%rsi,0x30(%rbp)'),
        (0x6362df9, 'mov', '0x30(%r9),%rax'),
        (0x6362dfd, 'mov', '0x28(%rax),%r10'),
        (0x6362e01, 'mov', '%r10,0x30(%r9)'),
        (0x6362e05, 'mov', '0x30(%rbp),%rdi'),
        (0x6362e09, 'mov', '%rbp,0x28(%rdi)'),
        (0x6362e0d, 'mov', '%r9,0x28(%r10)'),
        (0x6362e11, 'movdqu', '0x80(%rbx),%xmm2'),
        (0x6362e19, 'paddq', '(%rsp),%xmm2'),
        (0x6362e1e, 'mov', '%r8,0x18(%rsp)'),
        (0x6362e23, 'mov', '%r13,%rdi'),
        (0x6362e26, 'mov', '0x60(%rsp),%r14'),
        (0x6362e2b, 'add', '%r15,0x70(%rbx)'),
        (0x6362e2f, 'add', '%r14,0xa0(%rbx)'),
        (0x6362e36, 'add', '%r14,0xb0(%rbx)'),
        (0x6362e3d, 'movups', '%xmm2,0x80(%rbx)'),
        (0x6362e44, 'movb', '$0x0,0x68(%rbx)'),
        (0x6362e48, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
        (0x6362e4d, 'mov', '0x18(%rsp),%rbx'),
        (0x6362e52, 'test', '%rbx,%rbx'),
        (0x6362e55, 'je', '6362e64 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa34>'),
        (0x6362e57, 'subl', '$0x1,0x98(%rbx)'),
        (0x6362e5e, 'js', '6362f54 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61ab24>'),
        (0x6362e64, 'add', '$0xb8,%rsp'),
        (0x6362e6b, 'mov', '%r15,%rax'),
        (0x6362e6e, 'pop', '%rbx'),
        (0x6362e6f, 'pop', '%rbp'),
        (0x6362e70, 'pop', '%r12'),
        (0x6362e72, 'pop', '%r13'),
        (0x6362e74, 'pop', '%r14'),
        (0x6362e76, 'pop', '%r15'),
        (0x6362e78, 'ret', ''),
        (0x6362e79, 'nopl', '0x0(%rax)'),
        (0x6362e80, 'mov', '%r10d,%esi'),
        (0x6362e83, 'jmp', '6362b80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a750>'),
        (0x6362e88, 'mov', '0x9c(%rsp),%ebp'),
        (0x6362e8f, 'cmp', '%ebp,0x98(%rsp)'),
        (0x6362e96, 'jb', '6362ee3 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aab3>'),
        (0x6362e98, 'movq', '%r11,%xmm0'),
        (0x6362e9d, 'mov', '0x90(%rsp),%r9'),
        (0x6362ea5, 'punpcklqdq', '%xmm0,%xmm0'),
        (0x6362ea9, 'movups', '%xmm0,0x28(%r11)'),
        (0x6362eae, 'test', '%r9,%r9'),
        (0x6362eb1, 'je', '6362f18 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aae8>'),
        (0x6362eb3, 'mov', '0x30(%r9),%rcx'),
        (0x6362eb7, 'mov', '%rcx,0x28(%r11)'),
        (0x6362ebb, 'mov', '%r11,0x30(%r9)'),
        (0x6362ebf, 'mov', '0x30(%r11),%rax'),
        (0x6362ec3, 'mov', '0x28(%rax),%r10'),
        (0x6362ec7, 'mov', '%r10,0x30(%r11)'),
        (0x6362ecb, 'mov', '0x30(%r9),%rdi'),
        (0x6362ecf, 'mov', '%r9,0x28(%rdi)'),
        (0x6362ed3, 'mov', '%r11,0x28(%r10)'),
        (0x6362ed7, 'mov', '0x28(%r11),%r11'),
        (0x6362edb, 'mov', '%r11,0x90(%rsp)'),
        (0x6362ee3, 'xor', '%r11d,%r11d'),
        (0x6362ee6, 'jmp', '6362d3d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a90d>'),
        (0x6362eeb, 'mov', '0xa0(%rsp),%rdx'),
        (0x6362ef3, 'mov', '(%r15),%rdi'),
        (0x6362ef6, 'xor', '%esi,%esi'),
        (0x6362ef8, 'mov', '%r11,0x18(%rsp)'),
        (0x6362efd, 'mov', '%r8,(%rsp)'),
        (0x6362f01, 'imul', '%r14,%rdx'),
        (0x6362f05, 'call', '63f0a90 <memset@plt>'),
        (0x6362f0a, 'mov', '0x18(%rsp),%r11'),
        (0x6362f0f, 'mov', '(%rsp),%r8'),
        (0x6362f13, 'jmp', '6362d2c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a8fc>'),
        (0x6362f18, 'mov', '%r11,0x90(%rsp)'),
        (0x6362f20, 'jmp', '6362ee3 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aab3>'),
        (0x6362f22, 'mov', '%rbx,%rdi'),
        (0x6362f25, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),
        (0x6362f2a, 'movb', '$0x1,0x68(%rbx)'),
        (0x6362f2e, 'mov', '0x18(%rsp),%r8'),
        (0x6362f33, 'jmp', '6362d89 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a959>'),
        (0x6362f38, 'mov', '0x90(%rsp),%r12'),
        (0x6362f40, 'mov', '%r12,0xd8(%rbx)'),
        (0x6362f47, 'jmp', '6362e11 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a9e1>'),
        (0x6362f4c, 'xor', '%r14d,%r14d'),
        (0x6362f4f, 'jmp', '6362d5e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61a92e>'),
        (0x6362f54, 'lea', '0x70(%rbx),%rsi'),
        (0x6362f58, 'lea', '0x98(%rbx),%rdi'),
        (0x6362f5f, 'call', '635f340 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x616f10>'),
        (0x6362f64, 'test', '%al,%al'),
        (0x6362f66, 'je', '6362e64 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa34>'),
        (0x6362f6c, 'mov', '0x50(%rsp),%rsi'),
        (0x6362f71, 'xor', '%ecx,%ecx'),
        (0x6362f73, 'xor', '%edx,%edx'),
        (0x6362f75, 'mov', '%rbx,%rdi'),
        (0x6362f78, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),
        (0x6362f7d, 'jmp', '6362e64 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61aa34>'),
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

    check("entry reaches lock-wait site 0x6362f25", reaches(START, 0x6362F25))
    check("entry reaches ret 0x6362e78", reaches(START, 0x6362E78))
    check("entry reaches trylock 0x6362d77", reaches(START, 0x6362D77))
    check("entry reaches outer loop head 0x6362a20", reaches(START, 0x6362A20))
    check("entry reaches inner loop 0x6362aa8", reaches(START, 0x6362AA8))
    check("entry reaches bit extract 0x6362b80", reaches(START, 0x6362B80))
    check("entry reaches epilogue 0x6362e64", reaches(START, 0x6362E64))
    check("entry reaches cleanup 0x6362f54", reaches(START, 0x6362F54))
    check("entry reaches memset 0x6362f05", reaches(START, 0x6362F05))
    check("entry reaches list-insert 0x6362e88", reaches(START, 0x6362E88))
    check("entry reaches bitmap-count call 0x6362b93", reaches(START, 0x6362B93))
    check("entry reaches node fetcher 0x6362a3a", reaches(START, 0x6362A3A))
    check("entry reaches last-ref drop 0x6362f78", reaches(START, 0x6362F78))
    check("entry reaches head-word decrement 0x6362d14", reaches(START, 0x6362D14))
    check("entry reaches r8==0 path 0x6362f4c", reaches(START, 0x6362F4C))
    check("preds of lock-wait setup 0x6362f22 is the trylock fail only",
          sorted(preds[0x6362F22]) == [0x6362D83],
          str(sorted(preds[0x6362F22])))
    check("preds of trylock block 0x6362d5e are NULL path and r8==0 path",
          sorted(preds[0x6362D5E]) == [0x6362D5B, 0x6362F4F],
          str(sorted(preds[0x6362D5E])))
    check("preds of outer loop head 0x6362a20 are prologue and back-edge",
          sorted(preds[0x6362A20]) == [0x6362A1C, 0x6362D45],
          str(sorted(preds[0x6362A20])))
    check("preds of inner loop 0x6362aa8 are setup and back-edge",
          sorted(preds[0x6362AA8]) == [0x6362AA4, 0x6362CF9],
          str(sorted(preds[0x6362AA8])))
    check("preds of bit extract 0x6362b80 are slot hits and rejoin",
          sorted(preds[0x6362B80]) ==
          [0x6362AAE, 0x6362B6B, 0x6362B7E, 0x6362E83],
          str(sorted(preds[0x6362B80])))
    check("preds of epilogue 0x6362e64 are four exits",
          sorted(preds[0x6362E64]) ==
          [0x6362E55, 0x6362E5E, 0x6362F66, 0x6362F7D],
          str(sorted(preds[0x6362E64])))

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
    r11_in = reaching_defs("r11")
    rbx_in = reaching_defs("rbx")
    rbp_in = reaching_defs("rbp")
    r14_in = reaching_defs("r14")
    r15_in = reaching_defs("r15")
    r12_in = reaching_defs("r12")
    SITE = 0x6362F25
    CALL1 = {("CALL", 0x6362D77)}
    check("site rdi only def is mov rbx rdi 0x6362f22",
          rdi_in[SITE] == {0x6362F22}, str(rdi_in[SITE]))
    check("site rbx defs are prologue lea and NULL-path reload",
          rbx_in[SITE] == {0x63629DC, 0x6362D4E}, str(rbx_in[SITE]))
    check("site rsi is clobbered by the trylock only",
          rsi_in[SITE] == CALL1, str(rsi_in[SITE]))
    check("site rdx is clobbered by the trylock only",
          rdx_in[SITE] == CALL1, str(rdx_in[SITE]))
    check("site rcx is clobbered by the trylock only",
          rcx_in[SITE] == CALL1, str(rcx_in[SITE]))
    check("site r9 is clobbered by the trylock only",
          r9_in[SITE] == CALL1, str(r9_in[SITE]))
    check("site rax is clobbered by the trylock only",
          rax_in[SITE] == CALL1, str(rax_in[SITE]))
    check("site r10 is clobbered by the trylock only",
          r10_in[SITE] == CALL1, str(r10_in[SITE]))
    check("site r11 is clobbered by the trylock only",
          r11_in[SITE] == CALL1, str(r11_in[SITE]))
    check("site r8 is reloaded from 0x18(rsp) at 0x6362d7c",
          r8_in[SITE] == {0x6362D7C}, str(r8_in[SITE]))
    check("site r13 def is the mutex lea 0x6362d63",
          r13_in[SITE] == {0x6362D63}, str(r13_in[SITE]))
    check("site r14 defs are NULL path and r8==0 path (both 0)",
          r14_in[SITE] == {0x6362D4B, 0x6362F4C}, str(r14_in[SITE]))
    check("site r15 defs are prologue mov and NULL-path mov",
          r15_in[SITE] == {0x63629E9, 0x6362D5B}, str(r15_in[SITE]))
    check("site rbp defs are prologue, bit loop, list-insert",
          rbp_in[SITE] == {0x6362932, 0x6362CC5, 0x6362E88},
          str(rbp_in[SITE]))
    check("site r12 defs are reload 0x6362d3d and ENTRY (r8==0 path)",
          r12_in[SITE] == {0x6362D3D, ("ENTRY",)}, str(r12_in[SITE]))
    # Exit: single ret, rax is the output index (r15).
    check("rax at ret is the single mov r15 rax def 0x6362e6b",
          rax_in[0x6362E78] == {0x6362E6B}, str(rax_in[0x6362E78]))
    check("r15 at mov-to-rax 0x6362e6b is the output index (prologue 0 "
          "and NULL-path mov)",
          r15_in[0x6362E6B] == {0x63629E9, 0x6362D5B},
          str(r15_in[0x6362E6B]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x6362f25"])
    check("records second-handler sites 0",
          rec.get("second_handler_sites", []) == [])
    check("records bitmapdrain tzcnt 7",
          rec.get("bitmapdrain", {}).get("tzcnt") == 7)
    check("records bitmapdrain btc 7",
          rec.get("bitmapdrain", {}).get("btc") == 7)
    check("records bitmapdrain tzcnt sites",
          rec.get("bitmapdrain", {}).get("tzcnt_sites") ==
          ["0x6362bdd", "0x6362c13", "0x6362c38", "0x6362c63", "0x6362c75",
           "0x6362c9d", "0x6362cc8"])
    check("records bitmapdrain btc sites",
          rec.get("bitmapdrain", {}).get("btc_sites") ==
          ["0x6362be2", "0x6362c18", "0x6362c40", "0x6362c6e", "0x6362c7e",
           "0x6362cad", "0x6362cd0"])
    check("records sites lu-miss 0",
          rec.get("sites", {}).get("lu_miss") == 0)
    check("records sites bin_table_init 0",
          rec.get("sites", {}).get("bin_table_init") == 0)
    check("records sites second-handler 0",
          rec.get("sites", {}).get("second_handler") == 0)
    check("records sites lock-wait 1",
          rec.get("sites", {}).get("lock_wait") == 1)
    check("records window bytes 1650",
          rec.get("window", {}).get("bytes") == 1650)
    check("records window range",
          rec.get("window", {}).get("range") == "0x6362910..0x6362f82")
    check("records return value is r15 (output index)",
          rec.get("return_value", {}).get("rax") ==
          "r15 (output index = drained element count)")

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
    check("call target 0x6360ed0 raw lock-wait 1",
          lw_counts.get(0x6360ED0, 0) == 1,
          str(lw_counts.get(0x6360ED0, 0)))
    check("next candidate raw lu-miss 0", counts.get(0x636A140, 0) == 0,
          str(counts.get(0x636A140, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x636A140, 0) == 0,
          str(bti_counts.get(0x636A140, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x636A140, 0) == 0, str(sh_counts.get(0x636A140, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x636A140, 0) == 1,
          str(lw_counts.get(0x636A140, 0)))

    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x6362910" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x6362910") == 1,
          str(survey.get("sites_per_fde", {}).get("0x6362910")))
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
          "0x6362910" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x6362910" not in survey.get("second_handler_survivors", []))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x636a140..0x636a675",
          nq.get("range") == "0x636a140..0x636a675", str(nq.get("range")))
    check("next question bytes 1333", nq.get("bytes") == 1333,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 315", nq.get("strict") == 315,
          str(nq.get("strict")))
    check("next question calls 17 (15 direct + 2 indirect)",
          nq.get("calls") == 17, str(nq.get("calls")))
    check("next question indirect calls 2",
          nq.get("indirect_calls") == 2, str(nq.get("indirect_calls")))
    check("next question indirect sites",
          nq.get("indirect_sites") == ["0x636a27d", "0x636a474"],
          str(nq.get("indirect_sites")))
    check("next question calls by target",
          nq.get("calls_by_target") ==
          {"0x63ad870": 1, "0x63b6050": 1, "0x63bf680": 1, "0x63c27b0": 3,
           "0x63c27f0": 1, "0x63ef5e0": 3, "0x63ef8e0": 2, "0x63f0b70": 1,
           "0x63f0d70": 1, "0x63f17b0": 1},
          str(nq.get("calls_by_target")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x636a61e"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 2", nq.get("bsr") == 2,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x636a38c"], str(nq.get("ret")))
    check("next question jumps 42", nq.get("jumps") == 42,
          str(nq.get("jumps")))
    check("next question jumps outside 0", nq.get("jumps_outside_window") == 0,
          str(nq.get("jumps_outside_window")))
    check("next question endbr64 0", nq.get("endbr64") == 0,
          str(nq.get("endbr64")))
    check("next question canary present", nq.get("canary") is True,
          str(nq.get("canary")))
    check("next question plt calls 3", nq.get("plt_calls") == 3,
          str(nq.get("plt_calls")))
    check("records census strict 393",
          rec.get("census", {}).get("strict") == 393)
    check("records census calls 9",
          rec.get("census", {}).get("calls") == 9)
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
    # next candidate 0x636a140..0x636a675 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x636A140 < p[1] and p[0] < 0x636A675]
    check("next candidate 0x636a140 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x636A675 and 0x636A140 < END))

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
    check("slug not colliding with #314-#329 lu-miss slugs or #330",
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
                       "RE-001-node115-lu-miss-caller-3site-prefetch",
                       "RE-001-node115-lockwait-caller-1site-bitloop"))

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
                    "lockwait_caller_1site_bitmapdrain.hex",
                    "lockwait_caller_1site_bitmapdrain.objdump.txt"}
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
