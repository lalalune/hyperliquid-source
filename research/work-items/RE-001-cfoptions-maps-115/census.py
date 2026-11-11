#!/usr/bin/env python3
"""Census of node #115's ColumnFamilyOptions OptionTypeInfo map family (RE-001).

Parses the verbatim objdump of the static initializer
``__static_initialization_and_destruction_0v`` (0x6089b50..0x6091e5c) and
resolves, for every pair-ctor block, helper call and range-ctor/
__cxa_atexit call, the actual argument values by backward register
resolution (register-width aliases unified: %esi == %rsi, %ecx == %rcx,
%edx == %rdx, %r8d == %r8, %r9d == %r9; rip-relative loads accept
positive and negative displacements).

Value builders (decoded from the helper bodies, not assumed):
- inline: offset at value+0x00 (movq $imm), type/verif qword at
  value+0xa8 (mov %reg), flags dword at value+0xb0 (movl $imm).
- 0x607ea10 (factory entries): (rdi=value, esi=offset, edx=type,
  ecx=verification, r8d=flags, r9=parse-function capture).
- 0x6083a90 (type-22): (rdi=value, esi=offset, edx=verification,
  ecx=flags); hardcodes type 22 at +0xa8.
- 0x5e32c70 (type-19 nested): (rdi=value, rsi=key temp, rdx=sub-map,
  ecx=offset, r8d=verification, r9d=flags); hardcodes type 19.
- 0x607f1b0 (nested wrap): builds a type-19 value via 0x5e32c70
  (rdi=template, rsi=section-name global, rdx=sub-map, rcx=offset,
  r8d=verification, r9d=flags); 0x60842a0 moves the built pair into
  the array (rdi=dest pair, rsi=key source, rdx=template).
- 0x6083570 / 0x6083d80 (vector entries): (rdi=value, esi=offset,
  edx=verification, ecx=flags, r8=capture, r9d=element tag 0x3a);
  hardcodes type 20 at +0xa8.
- 0x6083c90 (enum entries): (rdi=value, esi=offset, ecx=flags,
  rdx=parse-function global); hardcodes type 18, verification 0
  (movq $0x12, +0xa8).

Special pairs (helper-built values installed by 0x5e32b10/0x5e332c0
moves) are decoded by following the move chain TIME-AWARELY: at each
step the latest move/builder/writes BEFORE the consuming call are
used, because the template scratch -0x3550(%rbp) is reused for many
entries.  A move counts as a final install only when its value dest
lies inside the pair array being built for the current map; its key
is the string-ctor call whose %rdi is the pair key slot (dest-0x20).

Usage: python3 census.py  (run from the repo root)
Writes blocks.tsv, ranges.tsv, atexit.tsv, helpers.tsv, specials.tsv,
sections.tsv next to this file.
"""

import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"
DUMP = HERE / "static-initializer-6089b50.objdump.txt"

INSN = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$")
LEA_RIP = re.compile(
    r"lea\s+(-?0x[0-9a-f]+)\(%rip\),(%\w+)\s+# ([0-9a-f]+)")
LEA_RBP = re.compile(r"lea\s+(-0x[0-9a-f]+)\(%rbp\),(%\w+)")
MOV_IMM = re.compile(r"mov[qbl]?\s+\$(-?0x[0-9a-f]+),(%\w+)")
MOV_REG = re.compile(r"mov\s+(%\w+),(%\w+)")
XOR_ZERO = re.compile(r"xor\s+(%\w+),(%\w+)")
MOV_LOAD_RIP = re.compile(
    r"mov\s+(-?0x[0-9a-f]+)\(%rip\),(%\w+)\s+# ([0-9a-f]+)")
MOV_LOAD_RBP = re.compile(r"mov\s+(-0x[0-9a-f]+)\(%rbp\),(%\w+)")
CALL = re.compile(r"call\s+([0-9a-f]+)")
LEA_STR = re.compile(r"lea\s+-?0x[0-9a-f]+\(%rip\),%rsi\s+# ([0-9a-f]+)")
MOVQ_IMM_RBP = re.compile(
    r"movq\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")
MOVL_IMM_RBP = re.compile(
    r"movl\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")
MOV_REG_RBP = re.compile(r"mov\s+(%\w+),(-0x[0-9a-f]+)\(%rbp\)")

PAIR_CTOR = 0x5D400F0
RANGE_CTOR = 0x5D405B0
ATEXIT = 0x63F0F80
STR_CTOR = 0x607D9F0
HELPER_TYPE22 = 0x6083A90
HELPER_TYPE19 = 0x5E32C70
HELPER_NESTED_WRAP = 0x607F1B0
HELPER_PAIR_MOVE = 0x60842A0
HELPER_FACTORY = 0x607EA10
HELPER_VECTOR_A = 0x6083570
HELPER_VECTOR_B = 0x6083D80
HELPER_ENUM18 = 0x6083C90
MOVE_VALS = {0x5E32B10, 0x5E332C0}
CALLER_SAVED = {"%rax", "%rcx", "%rdx", "%rsi", "%rdi",
                "%r8", "%r9", "%r10", "%r11"}

ALIAS = {}
for _b in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"):
    ALIAS["%" + _b] = "%" + _b
    ALIAS["%e" + _b[1:]] = "%" + _b
for _n in range(8, 16):
    ALIAS[f"%r{_n}"] = f"%r{_n}"
    ALIAS[f"%r{_n}d"] = f"%r{_n}"


def canon(reg):
    return ALIAS.get(reg, reg)


def read_cstr(data, vaddr):
    if vaddr >= len(data):
        return None
    try:
        end = data.index(b"\x00", vaddr)
    except ValueError:
        return None
    s = data[vaddr:end].decode("utf-8", "replace")
    if not s or not all(32 <= ord(c) < 127 for c in s):
        return None
    return s


def qword(data, vaddr):
    return struct.unpack("<Q", data[vaddr:vaddr + 8])[0]


class Resolver:
    def __init__(self, insns, data):
        self.insns = insns
        self.data = data

    def resolve(self, idx, reg, depth=0):
        if depth > 4:
            return None
        want = canon(reg)
        for j in range(idx - 1, max(-1, idx - 6000), -1):
            _, t = self.insns[j]
            m = LEA_RBP.match(t)
            if m and canon(m.group(2)) == want:
                return ("stack", int(m.group(1), 16))
            m = LEA_RIP.match(t)
            if m and canon(m.group(2)) == want:
                return ("global", int(m.group(3), 16))
            m = MOV_IMM.match(t)
            if m and canon(m.group(2)) == want:
                return ("imm", int(m.group(1), 16))
            m = XOR_ZERO.match(t)
            if (m and canon(m.group(1)) == want
                    and canon(m.group(2)) == want):
                return ("imm", 0)
            m = MOV_REG.match(t)
            if m and canon(m.group(2)) == want:
                return self.resolve(j + 1, m.group(1), depth + 1)
            m = MOV_LOAD_RIP.match(t)
            if m and canon(m.group(2)) == want:
                return ("qword@", int(m.group(3), 16))
            m = MOV_LOAD_RBP.match(t)
            if m and canon(m.group(2)) == want:
                return self.resolve_slot(j, m.group(1), depth)
            if t.startswith("call") and want in CALLER_SAVED:
                return None
        return None

    def resolve_slot(self, idx, disp, depth=0):
        for j in range(idx - 1, max(-1, idx - 6000), -1):
            _, t = self.insns[j]
            m = re.match(r"mov\s+(%\w+),(-0x[0-9a-f]+)\(%rbp\)", t)
            if m and m.group(2) == disp:
                return self.resolve(j + 1, m.group(1), depth + 1)
            m = re.match(
                r"lea\s+(-0x[0-9a-f]+)\(%rbp\),(-0x[0-9a-f]+)\(%rbp\)",
                t)
            if m and m.group(2) == disp:
                return ("stack", int(m.group(1), 16))
        return None


def fmt(v, data=None):
    if v is None:
        return "?"
    if v[0] == "stack":
        return f"-0x{-v[1]:x}(%rbp)"
    if v[0] == "global":
        return f"0x{v[1]:x}"
    if v[0] == "imm":
        return f"{v[1]:#x}"
    if v[0] == "qword@":
        val = qword(data, v[1]) if data is not None else None
        return (f"qword@0x{v[1]:x}={val:#x}"
                if val is not None else f"qword@0x{v[1]:x}")
    return str(v)


def split_typeverif(tv):
    """Split a type/verif value into (type, verification).

    Accepts an int, a qword@ string, or a fmt() string.  The qword
    packs type in the low 32 bits and verification in the high 32 bits.
    """
    if tv is None:
        return None, None
    if isinstance(tv, int):
        return tv & 0xFFFFFFFF, (tv >> 32) & 0xFFFFFFFF
    if isinstance(tv, str):
        m = re.search(r"=0x([0-9a-f]+)$", tv)
        if m:
            v = int(m.group(1), 16)
            return v & 0xFFFFFFFF, (v >> 32) & 0xFFFFFFFF
        if tv.startswith("0x"):
            v = int(tv, 16)
            return v & 0xFFFFFFFF, (v >> 32) & 0xFFFFFFFF
    return None, None


def imm_arg(R, idx, reg):
    v = R.resolve(idx, reg)
    return v[1] if v and v[0] == "imm" else None


def main():
    data = BIN.read_bytes()
    insns = []
    for line in DUMP.read_text().splitlines():
        m = INSN.match(line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2).strip()))
    R = Resolver(insns, data)

    def value_fields_from_writes(temp, upto_idx):
        """(offset, typeverif, flags) written to value temp `temp`
        before instruction `upto_idx`, from direct writes:
        offset = movq $imm to temp+0x00, typeverif = mov %reg to
        temp+0xa8 (resolved), flags = movl $imm to temp+0xb0.
        Returns dict with raw values (int / fmt string / None) plus
        the instruction index of each field's last write (`*_idx`).
        Stack slots are reused across the function, so a caller must
        check the write indices are newer than the temp's last move
        or helper build before trusting them."""
        off = tv = fl = None
        off_i = tv_i = fl_i = -1
        for j in range(upto_idx - 1, max(-1, upto_idx - 6000), -1):
            _, t = insns[j]
            m = MOVQ_IMM_RBP.match(t)
            if m and int(m.group(2), 16) == temp and off is None:
                off = int(m.group(1), 16)
                off_i = j
            m = MOVL_IMM_RBP.match(t)
            if m and int(m.group(2), 16) == temp + 0xB0 and fl is None:
                fl = int(m.group(1), 16)
                fl_i = j
            m = MOVQ_IMM_RBP.match(t)
            if m and int(m.group(2), 16) == temp + 0xA8 and tv is None:
                tv = int(m.group(1), 16)
                tv_i = j
            m = MOV_REG_RBP.match(t)
            if m and int(m.group(2), 16) == temp + 0xA8 and tv is None:
                v = R.resolve(j, m.group(1))
                tv = fmt(v, data) if v else "?"
                tv_i = j
            if off is not None and tv is not None and fl is not None:
                break
        return {"offset": off, "typeverif": tv, "flags": fl,
                "off_idx": off_i, "tv_idx": tv_i, "fl_idx": fl_i}

    # --- pair blocks: split by pair-ctor calls -------------------------
    blocks = []
    cur = []
    for i, (a, t) in enumerate(insns):
        cur.append((i, a, t))
        m = CALL.search(t)
        if m and int(m.group(1), 16) == PAIR_CTOR:
            blocks.append((i, cur))
            cur = []
    print(f"pair-ctor blocks: {len(blocks)}")

    out_blocks = []
    for bi, (call_idx, binstrs) in enumerate(blocks):
        name = None
        for (gi, a, t) in binstrs:
            m = LEA_STR.search(t)
            if m:
                s = read_cstr(data, int(m.group(1), 16))
                if s is not None:
                    name = s
        dest = R.resolve(call_idx, "%rdi")
        keyt = R.resolve(call_idx, "%rsi")
        valt = R.resolve(call_idx, "%rdx")
        temp = valt[1] if (valt and valt[0] == "stack") else None
        offset = flags = typeverif = None
        builder = "inline"
        for (gi, a, t) in binstrs:
            m = CALL.search(t)
            if m and int(m.group(1), 16) == HELPER_FACTORY:
                builder = "factory-607ea10"
                offset = imm_arg(R, gi, "%esi")
                typ = imm_arg(R, gi, "%edx")
                ver = imm_arg(R, gi, "%ecx")
                flags = imm_arg(R, gi, "%r8d")
                typeverif = ((typ if typ is not None else 0)
                             | ((ver if ver is not None else 0) << 32))
                break
        if builder == "inline" and temp is not None:
            got = value_fields_from_writes(temp, call_idx)
            offset, typeverif, flags = (got["offset"], got["typeverif"],
                                        got["flags"])
        typ, ver = split_typeverif(typeverif)
        out_blocks.append({
            "block": bi, "call": f"0x{insns[call_idx][0]:x}",
            "name": name, "offset": offset, "type": typ,
            "verification": ver, "flags": flags, "typeverif": typeverif,
            "builder": builder, "temp": temp,
            "pair_dest": fmt(dest), "key_temp": fmt(keyt),
            "value_temp": fmt(valt),
        })
    with open(HERE / "blocks.tsv", "w") as f:
        f.write("block\tcall\tname\toffset\ttype\tverification\tflags\t"
                "builder\tpair_dest\tkey_temp\tvalue_temp\n")
        for b in out_blocks:
            f.write(f"{b['block']}\t{b['call']}\t{b['name']}\t"
                    f"{b['offset'] if b['offset'] is not None else ''}\t"
                    f"{b['type'] if b['type'] is not None else ''}\t"
                    f"{b['verification'] if b['verification'] is not None else ''}\t"
                    f"{b['flags'] if b['flags'] is not None else ''}\t"
                    f"{b['builder']}\t{b['pair_dest']}\t{b['key_temp']}\t"
                    f"{b['value_temp']}\n")

    # --- range constructors, helpers, __cxa_atexit ---------------------
    ranges, helpers, atexits = [], [], []
    # string-ctor calls keyed by destination slot (for special keys)
    str_ctor_dest = {}  # stack slot (int, negative) -> literal
    for i, (a, t) in enumerate(insns):
        m = CALL.search(t)
        if not m:
            continue
        tgt = int(m.group(1), 16)
        if tgt == STR_CTOR:
            rdi = R.resolve(i, "%rdi")
            rsi = R.resolve(i, "%rsi")
            if (rdi and rdi[0] == "stack" and rsi and rsi[0] == "global"):
                lit = read_cstr(data, rsi[1])
                if lit is not None:
                    str_ctor_dest[rdi[1]] = lit
        if tgt == RANGE_CTOR:
            ranges.append({
                "call": f"0x{a:x}", "idx": i,
                "map": fmt(R.resolve(i, "%rdi")),
                "first": fmt(R.resolve(i, "%rsi")),
                "last": fmt(R.resolve(i, "%rdx")),
            })
        elif tgt == HELPER_TYPE22:
            helpers.append({
                "call": f"0x{a:x}", "helper": "type22-6083a90",
                "dest": fmt(R.resolve(i, "%rdi")),
                "offset": fmt(R.resolve(i, "%esi")),
                "verification": fmt(R.resolve(i, "%edx")),
                "flags": fmt(R.resolve(i, "%ecx")),
                "type": "22",
            })
        elif tgt == HELPER_TYPE19:
            helpers.append({
                "call": f"0x{a:x}", "helper": "type19-5e32c70",
                "dest": fmt(R.resolve(i, "%rdi")),
                "key_temp": fmt(R.resolve(i, "%rsi")),
                "sub_map": fmt(R.resolve(i, "%rdx")),
                "offset": fmt(R.resolve(i, "%ecx")),
                "verification": fmt(R.resolve(i, "%r8d")),
                "flags": fmt(R.resolve(i, "%r9d")),
                "type": "19",
            })
        elif tgt == HELPER_NESTED_WRAP:
            helpers.append({
                "call": f"0x{a:x}", "helper": "nested-wrap-607f1b0",
                "dest": fmt(R.resolve(i, "%rdi")),
                "section": fmt(R.resolve(i, "%rsi")),
                "sub_map": fmt(R.resolve(i, "%rdx")),
                "offset": fmt(R.resolve(i, "%ecx")),
                "verification": fmt(R.resolve(i, "%r8d")),
                "flags": fmt(R.resolve(i, "%r9d")),
                "type": "19",
            })
        elif tgt == HELPER_PAIR_MOVE:
            helpers.append({
                "call": f"0x{a:x}", "helper": "pair-move-60842a0",
                "dest": fmt(R.resolve(i, "%rdi")),
                "key_src": fmt(R.resolve(i, "%rsi")),
                "template": fmt(R.resolve(i, "%rdx")),
            })
        elif tgt == HELPER_FACTORY:
            helpers.append({
                "call": f"0x{a:x}", "helper": "factory-607ea10",
                "dest": fmt(R.resolve(i, "%rdi")),
                "offset": fmt(R.resolve(i, "%esi")),
                "type": fmt(R.resolve(i, "%edx")),
                "verification": fmt(R.resolve(i, "%ecx")),
                "flags": fmt(R.resolve(i, "%r8d")),
            })
        elif tgt in (HELPER_VECTOR_A, HELPER_VECTOR_B):
            helpers.append({
                "call": f"0x{a:x}",
                "helper": ("vector-6083570" if tgt == HELPER_VECTOR_A
                           else "vector-6083d80"),
                "dest": fmt(R.resolve(i, "%rdi")),
                "offset": fmt(R.resolve(i, "%esi")),
                "verification": fmt(R.resolve(i, "%edx")),
                "flags": fmt(R.resolve(i, "%ecx")),
                "elem_tag": fmt(R.resolve(i, "%r9d")),
                "type": "20",
            })
        elif tgt == HELPER_ENUM18:
            helpers.append({
                "call": f"0x{a:x}", "helper": "enum18-6083c90",
                "dest": fmt(R.resolve(i, "%rdi")),
                "offset": fmt(R.resolve(i, "%esi")),
                "flags": fmt(R.resolve(i, "%ecx")),
                "parse_global": fmt(R.resolve(i, "%rdx")),
                "type": "18", "verification": "0",
            })
        elif tgt == ATEXIT:
            atexits.append({
                "call": f"0x{a:x}",
                "func": fmt(R.resolve(i, "%rdi"), data),
                "obj": fmt(R.resolve(i, "%rsi")),
                "dso": fmt(R.resolve(i, "%rdx")),
            })
    with open(HERE / "ranges.tsv", "w") as f:
        f.write("call\tmap\tfirst\tlast\n")
        for r in ranges:
            f.write(f"{r['call']}\t{r['map']}\t{r['first']}\t{r['last']}\n")
    with open(HERE / "helpers.tsv", "w") as f:
        f.write("call\thelper\tdest\tkey_temp\tsection\tsub_map\t"
                "key_src\ttemplate\toffset\ttype\tverification\tflags\t"
                "elem_tag\tparse_global\n")
        for h in helpers:
            f.write(f"{h['call']}\t{h['helper']}\t"
                    f"{h.get('dest', '')}\t{h.get('key_temp', '')}\t"
                    f"{h.get('section', '')}\t{h.get('sub_map', '')}\t"
                    f"{h.get('key_src', '')}\t{h.get('template', '')}\t"
                    f"{h.get('offset', '')}\t{h.get('type', '')}\t"
                    f"{h.get('verification', '')}\t{h.get('flags', '')}\t"
                    f"{h.get('elem_tag', '')}\t{h.get('parse_global', '')}\n")
    with open(HERE / "atexit.tsv", "w") as f:
        f.write("call\tfunc\tobj\tdso\n")
        for r in atexits:
            f.write(f"{r['call']}\t{r['func']}\t{r['obj']}\t{r['dso']}\n")
    print("ranges:")
    for r in ranges:
        print(" ", r["call"], r["map"], r["first"], r["last"])
    print("helpers:")
    for h in helpers:
        print(" ", h)
    print("atexit:")
    for r in atexits:
        print(" ", r)

    # --- special pairs: time-aware move-chain decoding -----------------
    # moves: (idx, dest_temp, src_temp); builders: (idx, temp, kind)
    moves = []
    builders = []  # (idx, dest_temp, kind, args-dict)
    for i, (a, t) in enumerate(insns):
        m = CALL.search(t)
        if not m:
            continue
        tgt = int(m.group(1), 16)
        if tgt in MOVE_VALS:
            d = R.resolve(i, "%rdi")
            s = R.resolve(i, "%rsi")
            dt = d[1] if d and d[0] == "stack" else None
            st = s[1] if s and s[0] == "stack" else None
            moves.append((i, dt, st))
        elif tgt == HELPER_TYPE22:
            d = R.resolve(i, "%rdi")
            if d and d[0] == "stack":
                builders.append((i, d[1], "type22", {
                    "offset": imm_arg(R, i, "%esi"),
                    "type": 22,
                    "verification": imm_arg(R, i, "%edx"),
                    "flags": imm_arg(R, i, "%ecx")}))
        elif tgt == HELPER_TYPE19:
            d = R.resolve(i, "%rdi")
            if d and d[0] == "stack":
                builders.append((i, d[1], "type19", {
                    "offset": imm_arg(R, i, "%ecx"),
                    "type": 19,
                    "verification": imm_arg(R, i, "%r8d"),
                    "flags": imm_arg(R, i, "%r9d")}))
        elif tgt == HELPER_FACTORY:
            d = R.resolve(i, "%rdi")
            if d and d[0] == "stack":
                builders.append((i, d[1], "factory", {
                    "offset": imm_arg(R, i, "%esi"),
                    "type": imm_arg(R, i, "%edx"),
                    "verification": imm_arg(R, i, "%ecx"),
                    "flags": imm_arg(R, i, "%r8d")}))
        elif tgt in (HELPER_VECTOR_A, HELPER_VECTOR_B):
            d = R.resolve(i, "%rdi")
            if d and d[0] == "stack":
                builders.append((i, d[1], "vector", {
                    "offset": imm_arg(R, i, "%esi"),
                    "type": 20,
                    "verification": imm_arg(R, i, "%edx"),
                    "flags": imm_arg(R, i, "%ecx")}))
        elif tgt == HELPER_ENUM18:
            d = R.resolve(i, "%rdi")
            if d and d[0] == "stack":
                builders.append((i, d[1], "enum18", {
                    "offset": imm_arg(R, i, "%esi"),
                    "type": 18,
                    "verification": 0,
                    "flags": imm_arg(R, i, "%ecx")}))

    def latest_before(items, temp, cutoff):
        """Latest (idx, ...) in `items` with dest==temp and idx<cutoff."""
        best = None
        for it in items:
            if it[1] == temp and it[0] < cutoff:
                if best is None or it[0] > best[0]:
                    best = it
        return best

    def decode_temp(temp, cutoff):
        """Decode the value in stack temp `temp` as of `cutoff` (an
        instruction index).  Returns (how, offset, type, verification,
        flags).  At each step the LATEST event that produced the
        temp's contents wins: direct writes count only when ALL THREE
        field writes are newer than the temp's latest move-in and
        latest helper build (stack slots are reused, so older writes
        are stale); otherwise the latest helper build wins over the
        latest move-in, and a move-in is followed to its source."""
        seen = set()
        cur, cut = temp, cutoff
        while cur is not None and cur not in seen:
            seen.add(cur)
            got = value_fields_from_writes(cur, cut)
            b = latest_before(builders, cur, cut)
            mv = latest_before(moves, cur, cut)
            b_idx = b[0] if b else -1
            mv_idx = mv[0] if mv else -1
            if (got["offset"] is not None and got["typeverif"] is not None
                    and got["flags"] is not None
                    and min(got["off_idx"], got["tv_idx"], got["fl_idx"])
                    > max(b_idx, mv_idx)):
                typ, ver = split_typeverif(got["typeverif"])
                return ("writes", got["offset"], typ, ver, got["flags"])
            if b is not None and b_idx >= mv_idx:
                a = b[3]
                return (b[2], a["offset"], a["type"], a["verification"],
                        a["flags"])
            if mv is None:
                return ("unknown", None, None, None, None)
            cur, cut = mv[2], mv[0]
        return ("unknown", None, None, None, None)

    # map-4 range ctor at 0x608ec56 separates the two arrays
    map4_cut = next(r["idx"] for r in ranges
                    if r["map"] == "0x6506b20")
    specials = []
    for (i, dt, st) in moves:
        if dt is None or st is None:
            continue
        # final install iff the value dest lies in the pair array
        # being built: map 4 array [-0x3490, -0x40] before its range
        # ctor, map 5 array [-0x3490, -0x1a68] after it.
        if i < map4_cut:
            in_array = -0x3490 <= dt <= -0x40
        else:
            in_array = -0x3490 <= dt <= -0x1A68
        if not in_array:
            continue
        key_slot = dt - 0x20
        key = str_ctor_dest.get(key_slot)
        how, off, typ, ver, fl = decode_temp(st, i)
        specials.append({
            "call": f"0x{insns[i][0]:x}", "key": key,
            "pair_key_temp": key_slot, "value_dest": dt,
            "src": st, "how": how,
            "offset": off, "type": typ, "verification": ver, "flags": fl,
        })
    with open(HERE / "specials.tsv", "w") as f:
        f.write("call\tkey\tpair_key_temp\tvalue_dest\tsrc\thow\t"
                "offset\ttype\tverification\tflags\n")
        for s in specials:
            f.write(f"{s['call']}\t{s['key']}\t"
                    f"-0x{-s['pair_key_temp']:x}(%rbp)\t"
                    f"-0x{-s['value_dest']:x}(%rbp)\t"
                    f"-0x{-s['src']:x}(%rbp)\t{s['how']}\t"
                    f"{s['offset'] if s['offset'] is not None else ''}\t"
                    f"{s['type'] if s['type'] is not None else ''}\t"
                    f"{s['verification'] if s['verification'] is not None else ''}\t"
                    f"{s['flags'] if s['flags'] is not None else ''}\n")
    print("specials (final installs):")
    for s in specials:
        print(" ", s)

    # --- section-name strings: string-ctor calls to a .bss global ------
    sections = []
    for i, (a, t) in enumerate(insns):
        m = CALL.search(t)
        if not m or int(m.group(1), 16) != STR_CTOR:
            continue
        rdi = R.resolve(i, "%rdi")
        rsi = R.resolve(i, "%rsi")
        lit = None
        if rsi and rsi[0] == "global":
            lit = read_cstr(data, rsi[1])
        if rdi and rdi[0] == "global" and lit is not None:
            sections.append({
                "call": f"0x{a:x}",
                "dest": fmt(rdi),
                "literal": lit,
            })
    with open(HERE / "sections.tsv", "w") as f:
        f.write("call\tdest\tliteral\n")
        for s in sections:
            f.write(f"{s['call']}\t{s['dest']}\t{s['literal']}\n")
    print("sections:")
    for s in sections:
        print(" ", s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
