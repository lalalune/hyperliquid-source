#!/usr/bin/env python3
"""Census of node #115's OptionTypeInfo map construction (RE-001).

Parses the verbatim objdump of the static initializer
``__static_initialization_and_destruction_0v`` (0x60aa2b0..0x60b1d78,
re-shipped byte-identical from #4233) and resolves, for every pair-ctor
block and every helper/range-ctor/__cxa_atexit call, the actual argument
values by backward register resolution:

- pair blocks: (name, offset, flags, type/verif qword at temp+0xa8,
  pair destination, key-string temp, value temp).
- range constructors (0x5d405b0 and the four enum-map range ctors
  0x60a76c0/0x60a7c90/0x60a8260/0x60a8830): (map global, first, last)
  -> which pair range goes to which global map.
- mid helpers (0x60a64d0/0x60a65c0/0x60a66b0/0x60a67a0): the enum-typed
  OptionTypeInfo values they build (offset %esi, enum map %rdx,
  flags %ecx; type is hardcoded 0x12).
- __cxa_atexit calls: (func, object, dso) -> which dtor guards which
  global.
- the five section-name strings built in the prologue.

Method: backward scan from each call site for the last write to each
argument register (lea/mov/movq/movl/xor, with one level of
register-to-register and stack-slot forwarding).  String literals are
read from .rodata at file offset == vaddr (LOAD1 identity mapping).
Qwords loaded from .rodata/.data.rel.ro are read from the binary.

Usage: python3 census.py  (run from the repo root)
Writes blocks.tsv, ranges.tsv, atexit.tsv, midhelpers.tsv,
sections.tsv next to this file.
"""

import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"
DUMP = ROOT / "research" / "work-items" / \
    "RE-001-optiontypeinfo-mismatches-115" / \
    "static-initializer-60aa2b0.objdump.txt"

INSN = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$")
LEA_RIP = re.compile(
    r"lea\s+(-?0x[0-9a-f]+)\(%rip\),(%\w+)\s+# ([0-9a-f]+)")
LEA_RBP = re.compile(r"lea\s+(-0x[0-9a-f]+)\(%rbp\),(%\w+)")
MOV_IMM = re.compile(r"mov[qbl]?\s+\$(-?0x[0-9a-f]+),(%\w+)")
MOV_REG = re.compile(r"mov\s+(%\w+),(%\w+)")
XOR_ZERO = re.compile(r"xor\s+(%\w+),(%\w+)")
MOV_LOAD_RIP = re.compile(
    r"mov\s+(-0x[0-9a-f]+)\(%rip\),(%\w+)\s+# ([0-9a-f]+)")
MOV_LOAD_RBP = re.compile(r"mov\s+(-0x[0-9a-f]+)\(%rbp\),(%\w+)")
CALL = re.compile(r"call\s+([0-9a-f]+)")
LEA_STR = re.compile(r"lea\s+-?0x[0-9a-f]+\(%rip\),%rsi\s+# ([0-9a-f]+)")
MOVUPS = re.compile(r"movups\s+(%xmm\d+),(-0x[0-9a-f]+)\(%rbp\)")
MOVQ_IMM_RBP = re.compile(
    r"movq\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")
MOVL_IMM_RBP = re.compile(
    r"movl\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")
MOV_REG_RBP = re.compile(r"mov\s+(%\w+),(-0x[0-9a-f]+)\(%rbp\)")
MOVB_IMM_RBP = re.compile(
    r"movb\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")

PAIR_CTOR = 0x5D400F0
RANGE_CTOR = 0x5D405B0
ATEXIT = 0x63F0F80
ENUM_CTORS = {0x60A76C0, 0x60A7C90, 0x60A8260, 0x60A8830}
MID_HELPERS = {0x60A64D0, 0x60A65C0, 0x60A66B0, 0x60A67A0}
CALLER_SAVED = {"%rax", "%rcx", "%rdx", "%rsi", "%rdi",
                "%r8", "%r9", "%r10", "%r11"}


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
    """Backward register resolver over one instruction list."""

    def __init__(self, insns, data):
        self.insns = insns  # list of (addr, text)
        self.data = data

    def resolve(self, idx, reg, depth=0):
        """Value of `reg` just before instruction idx.

        Returns ('stack', disp) | ('global', addr) | ('imm', v) |
        ('qword@', addr) | None.  disp is the negative %rbp offset.
        """
        if depth > 4:
            return None
        for j in range(idx - 1, max(-1, idx - 6000), -1):
            _, t = self.insns[j]
            m = LEA_RBP.match(t)
            if m and m.group(2) == reg:
                return ("stack", int(m.group(1), 16))
            m = LEA_RIP.match(t)
            if m and m.group(2) == reg:
                return ("global", int(m.group(3), 16))
            m = MOV_IMM.match(t)
            if m and m.group(2) == reg:
                return ("imm", int(m.group(1), 16))
            m = XOR_ZERO.match(t)
            if m and m.group(1) == reg and m.group(2) == reg:
                return ("imm", 0)
            m = MOV_REG.match(t)
            if m and m.group(2) == reg:
                return self.resolve(j + 1, m.group(1), depth + 1)
            m = MOV_LOAD_RIP.match(t)
            if m and m.group(2) == reg:
                return ("qword@", int(m.group(3), 16))
            m = MOV_LOAD_RBP.match(t)
            if m and m.group(2) == reg:
                return self.resolve_slot(j, m.group(1), depth)
            if t.startswith("call") and reg in CALLER_SAVED:
                return None
        return None

    def resolve_slot(self, idx, disp, depth=0):
        """Value last stored to stack slot `disp` before instruction idx."""
        for j in range(idx - 1, max(-1, idx - 6000), -1):
            _, t = self.insns[j]
            m = re.match(
                r"lea\s+(-0x[0-9a-f]+)\(%rbp\),"
                r"(-0x[0-9a-f]+)\(%rbp\)", t)
            if m and m.group(2) == disp:
                return ("stack", int(m.group(1), 16))
            m = re.match(r"mov\s+(%\w+),(-0x[0-9a-f]+)\(%rbp\)", t)
            if m and m.group(2) == disp:
                return self.resolve(j + 1, m.group(1), depth + 1)
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


def main():
    data = BIN.read_bytes()
    insns = []
    for line in DUMP.read_text().splitlines():
        m = INSN.match(line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2).strip()))
    R = Resolver(insns, data)

    # --- pair blocks: split by pair-ctor calls -------------------------
    blocks = []  # (call_global_idx, [(global_idx, addr, text), ...])
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
        # Value temp from the resolved %rdx at the pair-ctor call: the
        # first-movups heuristic fails for blocks with an interlude
        # (e.g. block 27, whose range also builds the wal_filter pair).
        dest = R.resolve(call_idx, "%rdi")
        keyt = R.resolve(call_idx, "%rsi")
        valt = R.resolve(call_idx, "%rdx")
        temp = valt[1] if (valt and valt[0] == "stack") else None
        offset = flags = typeverif = None
        if temp is not None:
            for (gi, a, t) in binstrs:
                m = MOVQ_IMM_RBP.match(t)
                if m and int(m.group(2), 16) == temp:
                    offset = int(m.group(1), 16)
                m = MOVL_IMM_RBP.match(t)
                if m and int(m.group(2), 16) == temp:
                    offset = int(m.group(1), 16)
                m = MOVL_IMM_RBP.match(t)
                if m and int(m.group(2), 16) == temp + 0xB0:
                    flags = int(m.group(1), 16)
                m = MOVQ_IMM_RBP.match(t)
                if m and int(m.group(2), 16) == temp + 0xA8:
                    typeverif = int(m.group(1), 16)
                m = MOV_REG_RBP.match(t)
                if m and int(m.group(2), 16) == temp + 0xA8:
                    v = R.resolve(gi, m.group(1))
                    typeverif = fmt(v, data) if v else "?"
        out_blocks.append({
            "block": bi, "call": f"0x{insns[call_idx][0]:x}",
            "name": name, "offset": offset,
            "flags": flags, "typeverif": typeverif, "temp": temp,
            "pair_dest": fmt(dest), "key_temp": fmt(keyt),
            "value_temp": fmt(valt),
        })
    with open(HERE / "blocks.tsv", "w") as f:
        f.write("block\tcall\tname\toffset\tflags\ttypeverif\ttemp\t"
                "pair_dest\tkey_temp\tvalue_temp\n")
        for b in out_blocks:
            f.write(f"{b['block']}\t{b['call']}\t{b['name']}\t"
                    f"{b['offset'] if b['offset'] is not None else ''}\t"
                    f"{b['flags'] if b['flags'] is not None else ''}\t"
                    f"{b['typeverif'] if b['typeverif'] is not None else ''}\t"
                    f"{b['temp'] if b['temp'] is not None else ''}\t"
                    f"{b['pair_dest']}\t{b['key_temp']}\t"
                    f"{b['value_temp']}\n")

    # --- range constructors, mid helpers, __cxa_atexit -----------------
    ranges, mids, atexits = [], [], []
    for i, (a, t) in enumerate(insns):
        m = CALL.search(t)
        if not m:
            continue
        tgt = int(m.group(1), 16)
        if tgt == RANGE_CTOR:
            ranges.append({
                "call": f"0x{a:x}",
                "map": fmt(R.resolve(i, "%rdi")),
                "first": fmt(R.resolve(i, "%rsi")),
                "last": fmt(R.resolve(i, "%rdx")),
            })
        elif tgt in ENUM_CTORS:
            ranges.append({
                "call": f"0x{a:x}",
                "helper": f"0x{tgt:x}",
                "map": fmt(R.resolve(i, "%rdi")),
                "first": fmt(R.resolve(i, "%rsi")),
                "last": fmt(R.resolve(i, "%rdx")),
            })
        elif tgt in MID_HELPERS:
            mids.append({
                "call": f"0x{a:x}",
                "helper": f"0x{tgt:x}",
                "dest": fmt(R.resolve(i, "%rdi")),
                "offset": fmt(R.resolve(i, "%esi")),
                "arg_rdx": fmt(R.resolve(i, "%rdx")),
                "flags": fmt(R.resolve(i, "%ecx")),
            })
        elif tgt == ATEXIT:
            atexits.append({
                "call": f"0x{a:x}",
                "func": fmt(R.resolve(i, "%rdi")),
                "obj": fmt(R.resolve(i, "%rsi")),
                "dso": fmt(R.resolve(i, "%rdx")),
            })
    with open(HERE / "ranges.tsv", "w") as f:
        f.write("call\thelper\tmap\tfirst\tlast\n")
        for r in ranges:
            f.write(f"{r['call']}\t{r.get('helper', '0x5d405b0')}\t"
                    f"{r['map']}\t{r['first']}\t{r['last']}\n")
    with open(HERE / "midhelpers.tsv", "w") as f:
        f.write("call\thelper\tdest\toffset\targ_rdx\tflags\n")
        for r in mids:
            f.write(f"{r['call']}\t{r['helper']}\t{r['dest']}\t"
                    f"{r['offset']}\t{r['arg_rdx']}\t{r['flags']}\n")
    with open(HERE / "atexit.tsv", "w") as f:
        f.write("call\tfunc\tobj\tdso\n")
        for r in atexits:
            f.write(f"{r['call']}\t{r['func']}\t{r['obj']}\t{r['dso']}\n")
    print("ranges:")
    for r in ranges:
        print(" ", r)
    print("mid helpers:")
    for r in mids:
        print(" ", r)
    print("atexit:")
    for r in atexits:
        print(" ", r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
