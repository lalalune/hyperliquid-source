#!/usr/bin/env python3
"""Reconstruct node #115 rate limiter peer counter 0x4fabf60 and the btree iterator step 0x5135900 from the ELF bytes.

0x4fabf60 takes a shared lock on the limiter record, walks its collection of 24 byte entries (a VecDeque of entries, or a
BTreeMap with 4 byte keys) and counts the entries whose leading 4 byte address is NOT a member of a BTreeSet of 4 byte
addresses (the lookup compares big endian words after a bswap). It releases the lock and wakes a waiter when the reader
count drops to one with waiters flagged. The real bytes of both functions run in a small x86-64 evaluator, a separately
written rule list predicts every result, every lock word and every wake request, and a battery of edited bytes and edited
rule lists must all disagree. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/transport_peer_count_115.py --out <dir>
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
COUNT_FN = (0x4FABF60, 0x4FAC30F)
NEXT_FN = (0x5135900, 0x5135B24)
GOT_SLOW_LOCK, GOT_WAKE, GOT_PANIC_A, GOT_PANIC_B = 0x64E0FD8, 0x64E0FE8, 0x64DF4C0, 0x64DF830
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF, 16: (1 << 128) - 1}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
RETURN_SENTINEL = 0xDEAD0000
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x4000
STEP_LIMIT = 2000000
NICHE = 0x8000000000000000
LEAF_CAP = 11


class EvidenceError(Exception):
    pass


class Fault(Exception):
    pass


class Image:
    def __init__(self, blob):
        self.blob = blob
        self.mapped = sorted((s for s in sections(blob) if s["type"] != 8 and s["address"] and s["size"]),
                             key=lambda s: s["address"])

    def offset(self, va):
        for s in self.mapped:
            if s["address"] <= va < s["address"] + s["size"]:
                return va - s["address"] + s["offset"]
        raise EvidenceError("address outside file-backed sections: %#x" % va)

    def code(self, start, end):
        base = self.offset(start)
        return bytes(self.blob[base:base + (end - start)])

    def u64(self, va):
        return struct.unpack_from("<Q", self.blob, self.offset(va))[0]


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


# ---------------------------------------------------------------- decoder

class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "lock", "raw")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, lock=False):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target, self.lock = width, cc, target, lock
        self.next = va + size
        self.raw = b""


ALU = {0: "add", 1: "or", 2: "adc", 3: "sbb", 4: "and", 5: "sub", 6: "xor", 7: "cmp"}
CC = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"]


def decode(code, base, va):
    """Decode one instruction of the subset used by the two bodies; anything else is an EvidenceError."""
    window = code[va - base:va - base + 16]
    pos, rex, opsize, lock = 0, 0, False, False
    while window[pos] in (0x66, 0xF0, 0x2E):
        opsize |= window[pos] == 0x66
        lock |= window[pos] == 0xF0
        pos += 1
    if 0x40 <= window[pos] <= 0x4F:
        rex = window[pos]
        pos += 1
    width = 8 if rex & 8 else (2 if opsize else 4)
    opcode = window[pos]
    pos += 1

    def modrm(byte_reg=False):
        nonlocal pos
        m = window[pos]
        pos += 1
        mod, reg, rm = m >> 6, ((m >> 3) & 7) | ((rex & 4) << 1), m & 7
        if mod == 3:
            return reg, ("r", rm | ((rex & 1) << 3))
        base_reg, index, scale = None, None, 1
        if rm == 4:
            sib = window[pos]
            pos += 1
            scale = 1 << (sib >> 6)
            index = ((sib >> 3) & 7) | ((rex & 2) << 2)
            index = None if index == 4 else index
            base_reg = (sib & 7) | ((rex & 1) << 3)
            if (sib & 7) == 5 and mod == 0:
                raise EvidenceError("absolute sib not in subset")
        elif rm == 5 and mod == 0:
            disp = struct.unpack_from("<i", window, pos)[0]
            pos += 4
            return reg, ("m", "rip", None, 1, disp)
        else:
            base_reg = rm | ((rex & 1) << 3)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from("<b", window, pos)[0]
            pos += 1
        elif mod == 2:
            disp = struct.unpack_from("<i", window, pos)[0]
            pos += 4
        return reg, ("m", base_reg, index, scale, disp)

    def imm(n):
        nonlocal pos
        v = int.from_bytes(window[pos:pos + n], "little", signed=True)
        pos += n
        return v

    def done(op, **kw):
        row = Insn(va, pos, op, lock=lock, **kw)
        row.raw = bytes(window[:pos])
        return row

    def byte_reg_check(operand):
        if operand[0] == "r" and 4 <= operand[1] < 8 and not rex:
            raise EvidenceError("legacy high byte register not in subset")

    if opcode in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57):
        return done("push", a=("r", (opcode & 7) | ((rex & 1) << 3)))
    if 0x58 <= opcode <= 0x5F:
        return done("pop", a=("r", (opcode & 7) | ((rex & 1) << 3)))
    if opcode < 0x40 and (opcode & 7) < 4:
        op = ALU[opcode >> 3]
        reg, rm = modrm()
        w = 1 if (opcode & 1) == 0 else width
        if w == 1:
            byte_reg_check(rm)
        if opcode & 2:
            return done(op, a=("r", reg), b=rm, width=w)
        return done(op, a=rm, b=("r", reg), width=w)
    if opcode < 0x40 and (opcode & 7) == 5:
        value = imm(2 if width == 2 else 4)
        return done(ALU[opcode >> 3], a=("r", 0), b=("i", value & MASK[width] if width < 8 else value), width=width)
    if opcode in (0x80, 0x81, 0x83):
        reg, rm = modrm()
        w = 1 if opcode == 0x80 else width
        value = imm(4 if opcode == 0x81 and w != 2 else (2 if opcode == 0x81 else 1))
        return done(ALU[reg & 7], a=rm, b=("i", value & MASK[w] if w < 8 else value), width=w)
    if opcode in (0x84, 0x85):
        reg, rm = modrm()
        w = 1 if opcode == 0x84 else width
        return done("test", a=rm, b=("r", reg), width=w)
    if opcode in (0x88, 0x89, 0x8A, 0x8B):
        reg, rm = modrm()
        w = 1 if opcode in (0x88, 0x8A) else width
        if w == 1:
            byte_reg_check(rm)
        return done("mov", a=rm, b=("r", reg), width=w) if opcode in (0x88, 0x89) else done("mov", a=("r", reg), b=rm, width=w)
    if opcode == 0x8D:
        reg, rm = modrm()
        return done("lea", a=("r", reg), b=rm, width=width)
    if opcode == 0xC7:
        reg, rm = modrm()
        return done("mov", a=rm, b=("i", imm(2 if width == 2 else 4)), width=width)
    if 0xB8 <= opcode <= 0xBF:
        value = int.from_bytes(window[pos:pos + (8 if width == 8 else 4)], "little")
        pos += 8 if width == 8 else 4
        return done("mov", a=("r", (opcode & 7) | ((rex & 1) << 3)), b=("i", value), width=width)
    if opcode == 0xB0 or opcode == 0xB1:
        return done("mov", a=("r", (opcode & 7) | ((rex & 1) << 3)), b=("i", imm(1) & 0xFF), width=1)
    if opcode == 0xC1:
        reg, rm = modrm()
        return done({4: "shl", 5: "shr"}[reg & 7], a=rm, b=("i", imm(1) & 0xFF), width=width)
    if opcode == 0xF7:
        reg, rm = modrm()
        if reg & 7 != 3:
            raise EvidenceError("f7 form not in subset")
        return done("neg", a=rm, width=width)
    if opcode == 0xFF:
        reg, rm = modrm()
        sub = reg & 7
        if sub in (0, 1):
            return done("inc" if sub == 0 else "dec", a=rm, width=width)
        if sub == 2:
            return done("call", a=rm)
        raise EvidenceError("ff form not in subset")
    if opcode == 0xE8:
        rel = imm(4)
        return done("call", target=va + pos + rel)
    if opcode == 0xE9:
        rel = imm(4)
        return done("jmp", target=va + pos + rel)
    if opcode == 0xEB:
        rel = imm(1)
        return done("jmp", target=va + pos + rel)
    if 0x70 <= opcode <= 0x7F:
        rel = imm(1)
        return done("jcc", cc=CC[opcode & 15], target=va + pos + rel)
    if opcode == 0xC3:
        return done("ret")
    if opcode == 0x90:
        return done("nop")
    if opcode == 0xCC:
        return done("int3")
    if opcode == 0x0F:
        second = window[pos]
        pos += 1
        if second == 0x0B:
            return done("ud2")
        if second == 0x1F:
            modrm()
            return done("nop")
        if second in (0x10, 0x11, 0x28, 0x29):
            reg, rm = modrm()
            xmm = ("x", reg)
            xrm = ("x", rm[1]) if rm[0] == "r" else rm
            return done("movups", a=xmm, b=xrm) if second in (0x10, 0x28) else done("movups", a=xrm, b=xmm)
        if second == 0x57:
            reg, rm = modrm()
            return done("xorps", a=("x", reg), b=("x", rm[1]))
        if 0x40 <= second <= 0x4F:
            reg, rm = modrm()
            return done("cmov", a=("r", reg), b=rm, width=width, cc=CC[second & 15])
        if 0x80 <= second <= 0x8F:
            rel = imm(4)
            return done("jcc", cc=CC[second & 15], target=va + pos + rel)
        if 0x90 <= second <= 0x9F:
            reg, rm = modrm()
            byte_reg_check(rm)
            return done("set", a=rm, cc=CC[second & 15], width=1)
        if second in (0xB6, 0xB7, 0xBE, 0xBF):
            reg, rm = modrm()
            src = 1 if second in (0xB6, 0xBE) else 2
            if src == 1:
                byte_reg_check(rm)
            return done("movzx" if second < 0xB8 else "movsx", a=("r", reg), b=rm, width=width, cc=src)
        if second == 0xB1:
            reg, rm = modrm()
            return done("cmpxchg", a=rm, b=("r", reg), width=width)
        if second == 0xC1:
            reg, rm = modrm()
            return done("xadd", a=rm, b=("r", reg), width=width)
        if 0xC8 <= second <= 0xCF:
            return done("bswap", a=("r", (second & 7) | ((rex & 1) << 3)), width=width)
        raise EvidenceError("0f %#x not in subset at %#x" % (second, va))
    raise EvidenceError("opcode %#x not in subset at %#x" % (opcode, va))


def decode_range(image, start, end, patches=None):
    code = bytearray(image.code(start, end + 16))
    for at, value in (patches or {}).items():
        if start <= at < end:
            code[at - start] = value
    code = bytes(code)
    rows, va = {}, start
    while va < end:
        row = decode(code, start, va)
        rows[va] = row
        va = row.next
    if va != end:
        raise EvidenceError("decoder overran range end at %#x" % end)
    return rows


# ---------------------------------------------------------------- machine

class Memory:
    def __init__(self):
        self.pages = {}

    def _page(self, addr, create=False):
        key = addr >> 12
        page = self.pages.get(key)
        if page is None:
            if not create:
                raise Fault("unmapped %#x" % addr)
            page = self.pages[key] = bytearray(4096)
        return page

    def map(self, addr, size):
        for key in range(addr >> 12, (addr + size - 1 >> 12) + 1):
            self._page(key << 12, True)

    def read(self, addr, size):
        out = bytearray()
        for at in range(addr, addr + size):
            out.append(self._page(at)[at & 4095])
        return bytes(out)

    def write(self, addr, data):
        for i, byte in enumerate(data):
            self._page(addr + i)[(addr + i) & 4095] = byte

    def u(self, addr, size):
        return int.from_bytes(self.read(addr, size), "little")

    def put(self, addr, value, size):
        self.write(addr, (value & MASK[size]).to_bytes(size, "little"))


class Outcome:
    """What one run produced: the return value or the boundary it stopped at, plus recorded effects."""

    def __init__(self, kind, value=0, events=(), steps=0):
        self.kind, self.value, self.events, self.steps = kind, value, tuple(events), steps

    def key(self):
        return (self.kind, self.value, self.events)


class Machine:
    def __init__(self, image, tables, patches=None):
        self.image = image
        self.tables = tables
        self.patches = patches or {}
        self.step_limit = STEP_LIMIT

    def fresh(self):
        self.regs = [0] * 16
        self.xmm = [0] * 16
        self.f = dict(c=0, z=0, s=0, o=0)
        self.mem = Memory()
        self.mem.map(STACK_TOP - STACK_SIZE, STACK_SIZE)
        self.regs[4] = STACK_TOP - 64
        self.events = []
        self.steps = 0

    # operand access -------------------------------------------------
    def addr(self, op, insn):
        _, base, index, scale, disp = op
        if base == "rip":
            return (insn.next + disp) & MASK[8]
        total = disp + (self.regs[base] if base is not None else 0) + (self.regs[index] * scale if index is not None else 0)
        return total & MASK[8]

    def get(self, op, w, insn):
        kind = op[0]
        if kind == "i":
            return op[1] & MASK[w]
        if kind == "r":
            return self.regs[op[1]] & MASK[w]
        if kind == "x":
            return self.xmm[op[1]]
        return self.mem.u(self.addr(op, insn), w)

    def put(self, op, value, w, insn):
        kind = op[0]
        if kind == "r":
            if w == 4:
                self.regs[op[1]] = value & MASK[4]
            elif w == 8:
                self.regs[op[1]] = value & MASK[8]
            else:
                self.regs[op[1]] = (self.regs[op[1]] & ~MASK[w] & MASK[8]) | (value & MASK[w])
        elif kind == "x":
            self.xmm[op[1]] = value
        else:
            self.mem.put(self.addr(op, insn), value, w)

    # flags ----------------------------------------------------------
    def alu(self, op, a, b, w):
        m, s = MASK[w], SIGN[w]
        carry = self.f["c"]
        if op in ("add", "adc"):
            c = carry if op == "adc" else 0
            r = (a + b + c) & m
            self.f["c"] = int(a + b + c > m)
            self.f["o"] = int(bool(~(a ^ b) & (a ^ r) & s))
        elif op in ("sub", "cmp", "sbb"):
            c = carry if op == "sbb" else 0
            r = (a - b - c) & m
            self.f["c"] = int(a < b + c)
            self.f["o"] = int(bool((a ^ b) & (a ^ r) & s))
        else:
            r = {"and": a & b, "or": a | b, "xor": a ^ b, "test": a & b}[op] & m
            self.f["c"] = self.f["o"] = 0
        self.f["z"], self.f["s"] = int(r == 0), int(bool(r & s))
        return r

    def cond(self, cc):
        f = self.f
        return {"o": f["o"], "no": not f["o"], "b": f["c"], "ae": not f["c"], "e": f["z"], "ne": not f["z"],
                "be": f["c"] or f["z"], "a": not (f["c"] or f["z"]), "s": f["s"], "ns": not f["s"],
                "l": f["s"] != f["o"], "ge": f["s"] == f["o"], "le": f["z"] or f["s"] != f["o"],
                "g": not f["z"] and f["s"] == f["o"]}[cc]

    # execution ------------------------------------------------------
    def push(self, value):
        self.regs[4] -= 8
        self.mem.put(self.regs[4], value, 8)

    def pop(self):
        value = self.mem.u(self.regs[4], 8)
        self.regs[4] += 8
        return value

    def run(self, entry, args, ranges):
        """Run from entry until it returns; stub calls (lock slow path, wake, panics) are recorded."""
        for i, value in enumerate(args):
            self.regs[(7, 6, 2, 1, 8, 9)[i]] = value
        self.push(RETURN_SENTINEL)
        pc = entry
        while True:
            self.steps += 1
            if self.steps > self.step_limit:
                return Outcome("limit", 0, self.events, self.steps)
            if pc == RETURN_SENTINEL:
                return Outcome("return", self.regs[0], self.events, self.steps)
            insn = None
            for table in ranges:
                insn = table.get(pc)
                if insn:
                    break
            if insn is None:
                raise Fault("pc outside decoded ranges: %#x" % pc)
            nxt = self.step(insn)
            if isinstance(nxt, Outcome):
                return nxt
            pc = insn.next if nxt is None else nxt

    def step_import(self, slot):
        """The out of line callees are recorded, not run: the lock slow path, the waiter wake and the two panics."""
        if slot == GOT_SLOW_LOCK:
            return Outcome("slow-lock", 0, self.events + [("slow", self.regs[7], self.regs[6], self.regs[1])], self.steps)
        if slot == GOT_WAKE:
            self.events.append(("wake", self.regs[7]))
        elif slot in (GOT_PANIC_A, GOT_PANIC_B):
            return Outcome("panic", slot, self.events, self.steps)
        else:
            raise Fault("unknown import slot %#x" % slot)
        return None

    def step(self, i):
        op, w = i.op, i.width
        if op == "push":
            self.push(self.regs[i.a[1]])
        elif op == "pop":
            self.regs[i.a[1]] = self.pop()
        elif op in ("add", "sub", "and", "or", "xor", "adc", "sbb", "cmp", "test"):
            if i.lock:
                raise Fault("lock on alu")
            a, b = self.get(i.a, w, i), self.get(i.b, w, i)
            if i.b[0] == "i" and w == 8:
                b = i.b[1] & MASK[8]
            r = self.alu(op, a, b, w)
            if op not in ("cmp", "test"):
                self.put(i.a, r, w, i)
        elif op == "mov":
            self.put(i.a, self.get(i.b, w, i) if i.b[0] != "i" else i.b[1] & MASK[w], w, i)
        elif op == "lea":
            self.put(i.a, self.addr(i.b, i), w, i)
        elif op in ("movzx", "movsx"):
            v = self.get(i.b, i.cc, i)
            if op == "movsx" and v & SIGN[i.cc]:
                v |= MASK[8] & ~MASK[i.cc]
            self.put(i.a, v, w, i)
        elif op == "shl" or op == "shr":
            v, n = self.get(i.a, w, i), i.b[1] & (63 if w == 8 else 31)
            r = (v << n if op == "shl" else v >> n) & MASK[w]
            if n:
                self.f["z"], self.f["s"] = int(r == 0), int(bool(r & SIGN[w]))
            self.put(i.a, r, w, i)
        elif op == "neg":
            v = self.get(i.a, w, i)
            r = self.alu("sub", 0, v, w)
            self.put(i.a, r, w, i)
        elif op in ("inc", "dec"):
            carry = self.f["c"]
            v = self.get(i.a, w, i)
            r = self.alu("add" if op == "inc" else "sub", v, 1, w)
            self.f["c"] = carry
            self.put(i.a, r, w, i)
        elif op == "bswap":
            self.put(i.a, int.from_bytes(self.get(i.a, w, i).to_bytes(w, "little"), "big"), w, i)
        elif op == "set":
            self.put(i.a, int(bool(self.cond(i.cc))), 1, i)
        elif op == "cmov":
            v = self.get(i.b, w, i)
            if self.cond(i.cc):
                self.put(i.a, v, w, i)
            elif w == 4:
                self.put(i.a, self.get(i.a, 4, i), 4, i)
        elif op == "cmpxchg":
            expected, current = self.regs[0] & MASK[w], self.get(i.a, w, i)
            self.alu("cmp", expected, current, w)
            if expected == current:
                self.put(i.a, self.get(i.b, w, i), w, i)
            else:
                self.put(("r", 0), current, w, i)
        elif op == "xadd":
            old, add = self.get(i.a, w, i), self.get(i.b, w, i)
            r = self.alu("add", old, add, w)
            self.put(i.b, old, w, i)
            self.put(i.a, r, w, i)
        elif op == "movups":
            if i.a[0] == "x":
                self.xmm[i.a[1]] = self.xmm[i.b[1]] if i.b[0] == "x" else self.mem.u(self.addr(i.b, i), 16)
            else:
                self.mem.put(self.addr(i.a, i), self.xmm[i.b[1]], 16)
        elif op == "xorps":
            self.xmm[i.a[1]] ^= self.xmm[i.b[1]]
        elif op == "jmp":
            return i.target
        elif op == "jcc":
            return i.target if self.cond(i.cc) else None
        elif op == "call":
            if i.target is not None:
                self.push(i.next)
                return i.target
            return self.step_import(self.addr(i.a, i))
        elif op == "ret":
            return self.pop()
        elif op == "nop":
            pass
        elif op in ("ud2", "int3"):
            return Outcome("trap", 0, self.events, self.steps)
        else:
            raise Fault("unimplemented " + op)
        return None


# ---------------------------------------------------------------- memory builders

ARC = 0x600000000
ARG_PTR = 0x600100000
SET_ARG = 0x600100100
DEQUE_BUF = 0x610000000
NODE_BASE = 0x620000000
SET_NODE_SIZE = 0x38 + 12 * 8
MAP_NODE_SIZE = 0xE8 + 12 * 8


class Node:
    def __init__(self, keys, children=()):
        self.keys, self.children = keys, list(children)


def size_range(height):
    """Fewest and most keys a tree of this height may hold when every node is non empty."""
    return (1 << (height + 1)) - 1, 12 ** (height + 1) - 1


def build_tree(keys, height, rng):
    """Split sorted keys into a valid tree of the given height; every node holds 1..11 keys."""
    if height == 0:
        return Node(list(keys))
    lo, hi = size_range(height - 1)
    count = len(keys)
    choices = [k for k in range(1, LEAF_CAP + 1) if (k + 1) * lo + k <= count <= (k + 1) * hi + k]
    k = choices[rng() % len(choices)]
    rest = count - k - lo * (k + 1)
    sizes = [lo] * (k + 1)
    while rest:
        j = rng() % (k + 1)
        if sizes[j] < hi:
            sizes[j] += 1
            rest -= 1
    children, seps, at = [], [], 0
    for j in range(k + 1):
        children.append(build_tree(keys[at:at + sizes[j]], height - 1, rng))
        at += sizes[j]
        if j < k:
            seps.append(keys[at])
            at += 1
    return Node(seps, children)


def pick_height(count):
    height = 0
    while count > size_range(height)[1]:
        height += 1
    return height


def lay_out(mem, root, kind, cursor):
    """Write a tree into memory; returns (root address, height)."""
    order = [(root, None, 0)]
    for node, parent, idx in order:
        for j, child in enumerate(node.children):
            order.append((child, node, j))
    size = SET_NODE_SIZE if kind == "set" else MAP_NODE_SIZE
    where = {}
    for node, _, _ in order:
        where[id(node)] = cursor
        mem.map(cursor, size)
        cursor += (size + 15) & ~15
    for node, parent, idx in order:
        at = where[id(node)]
        if kind == "set":
            keys_at, pidx_at, len_at, edge_at, parent_at = at + 8, at + 0x34, at + 0x36, at + 0x38, at
        else:
            keys_at, pidx_at, len_at, edge_at, parent_at = at + 0xB8, at + 0xE4, at + 0xE6, at + 0xE8, at + 0xB0
            for j in range(len(node.keys)):
                mem.write(at + 16 * j, bytes([0xC0 | j]) * 16)
        for j, key in enumerate(node.keys):
            mem.write(keys_at + 4 * j, key)
        mem.put(len_at, len(node.keys), 2)
        mem.put(parent_at, where[id(parent)] if parent else 0, 8)
        mem.put(pidx_at, idx, 2)
        for j, child in enumerate(node.children):
            mem.put(edge_at + 8 * j, where[id(child)], 8)
    height, probe = 0, root
    while probe.children:
        probe = probe.children[0]
        height += 1
    return where[id(root)], height


class Case:
    __slots__ = ("variant", "entries", "members", "state", "cap", "head", "map_keys", "tall")

    def __init__(self, variant, entries, members, state, cap=0, head=0, map_keys=(), tall=0):
        self.variant, self.entries, self.members, self.state = variant, entries, members, state
        self.cap, self.head, self.map_keys, self.tall = cap, head, map_keys, tall


def lcg(seed):
    state = [seed & 0xFFFFFFFF]

    def step():
        state[0] = (state[0] * 1664525 + 1013904223) & 0xFFFFFFFF
        return state[0] >> 8
    return step


def instantiate(machine, case, seed):
    """Build the lock record, the collection and the member set for a case; returns the call arguments."""
    machine.fresh()
    mem = machine.mem
    rng = lcg(seed)
    mem.map(ARC, 0x40)
    mem.map(ARG_PTR, 0x200)
    mem.put(ARC + 0x10, case.state, 8)
    mem.put(ARG_PTR, ARC, 8)
    if case.variant == "deque":
        mem.put(ARC + 0x18, case.cap, 8)
        mem.map(DEQUE_BUF, 24 * max(case.cap, 1) + 64)
        for slot in range(case.cap):
            mem.write(DEQUE_BUF + 24 * slot, bytes([0x5A]) * 24)
        phys = case.head - case.cap if case.head >= case.cap else case.head
        for j, key in enumerate(case.entries):
            mem.write(DEQUE_BUF + 24 * ((phys + j) % case.cap), key + bytes([j & 255]) * 20)
        mem.put(ARC + 0x20, DEQUE_BUF, 8)
        mem.put(ARC + 0x28, case.head, 8)
        mem.put(ARC + 0x30, len(case.entries), 8)
    else:
        mem.put(ARC + 0x18, NICHE, 8)
        keys = sorted(case.map_keys)
        if keys:
            addr, height = lay_out(mem, build_tree(keys, case.tall or pick_height(len(keys)), rng), "map", NODE_BASE + 0x100000)
            mem.put(ARC + 0x20, addr, 8)
            mem.put(ARC + 0x28, height, 8)
        mem.put(ARC + 0x30, len(keys), 8)
    members = sorted(case.members)
    mem.map(SET_ARG, 16)
    if members:
        addr, height = lay_out(mem, build_tree(members, pick_height(len(members)), rng), "set", NODE_BASE)
        mem.put(SET_ARG, addr, 8)
        mem.put(SET_ARG + 8, height, 8)
    return ARG_PTR, SET_ARG


# ---------------------------------------------------------------- rule list

SPEC_FLAWS = ("count-members", "ignore-set", "first-only", "little-endian-members", "prefix-three", "off-by-one",
              "stop-at-first-member", "skip-last", "distinct-keys", "wake-mask", "always-wake", "no-wake",
              "slow-ignored", "deque-skip-first")


def spec(case, flaw=None):
    """The written rule list: what the counter returns, which wake it requests, and where it stops."""
    state = case.state
    if ((state & 8) or state >= 0xFFFFFFFFFFFFFFF0) and flaw != "slow-ignored":
        return ("slow-lock", 0, (("slow", ARC + 0x10, 0, 0x3B9ACA00),))
    if case.variant == "deque":
        seen = list(case.entries)
        if flaw == "deque-skip-first":
            seen = seen[1:]
    else:
        seen = sorted(case.map_keys)
    members = set(case.members)
    if flaw == "count-members":
        count = sum(1 for key in seen if key in members)
    elif flaw == "ignore-set":
        count = len(seen)
    elif flaw == "first-only":
        count = int(bool(seen) and seen[0] not in members)
    elif flaw == "little-endian-members":
        flipped = {key[::-1] for key in members}
        count = sum(1 for key in seen if key not in flipped)
    elif flaw == "prefix-three":
        prefixes = {key[:3] for key in members}
        count = sum(1 for key in seen if key[:3] not in prefixes)
    elif flaw == "off-by-one":
        count = sum(1 for key in seen if key not in members) + 1
    elif flaw == "stop-at-first-member":
        count = 0
        for key in seen:
            if key in members:
                break
            count += 1
    elif flaw == "skip-last":
        count = sum(1 for key in seen[:-1] if key not in members)
    elif flaw == "distinct-keys":
        count = len({key for key in seen if key not in members})
    else:
        count = sum(1 for key in seen if key not in members)
    old = (state + 0x10) & MASK[8]
    mask = 0xFFFFFFFFFFFFFFF0 if flaw == "wake-mask" else 0xFFFFFFFFFFFFFFF2
    wake = (old & mask) == 0x12
    if flaw == "always-wake":
        wake = True
    if flaw == "no-wake":
        wake = False
    return ("return", count, (("wake", ARC + 0x10),) if wake else ())


# ---------------------------------------------------------------- cases

POOL_BYTES = (0x00, 0x01, 0x7F, 0x80, 0xC0, 0xFE, 0xFF, 0x0A)
STATES = (0, 0x10, 0x20, 0x30, 0x02, 0x12, 0x22, 0x04, 0x14, 0x01, 0x11, 0x08, 0x18, 0x1C, 0xFFFFFFFFFFFFFFF0,
          0xFFFFFFFFFFFFFFE0, 0xFFFFFFFFFFFFFFE2, 0x0C, 0x13, 0x16)


def make_key(rng, narrow):
    if narrow:
        return bytes(POOL_BYTES[rng() % len(POOL_BYTES)] for _ in range(4))
    return bytes(rng() & 255 for _ in range(4))


def case_stream(count, seed=0x7E11, limit_entries=26):
    """Yield deterministic cases; the first four are fixed boundary shapes."""
    rng = lcg(seed)
    yield Case("deque", [], [], 0, cap=1)
    yield Case("deque", [b"\x01\x02\x03\x04"], [], 0x10, cap=2, head=1)
    yield Case("map", [], [], 0, map_keys=[])
    yield Case("map", [], [b"\x00\x00\x00\x01"], 0x12, map_keys=[b"\x00\x00\x00\x01"])
    for tall in (3, 7, 8, 8):
        keys = [(7 * j + 1).to_bytes(4, "big") for j in range(size_range(tall)[0] + tall)]
        yield Case("map", [], keys[::3], 0x10, map_keys=keys, tall=tall)
    for _ in range(8, count):
        narrow = rng() % 3 != 0
        pool = sorted({make_key(rng, narrow) for _ in range(1 + rng() % 30)})
        members = [key for key in pool if rng() % 3 == 0]
        if rng() % 9 == 0:
            members = list(pool)
        elif rng() % 6 == 0:
            members = []
        state = STATES[rng() % len(STATES)]
        if rng() % 2:
            length = rng() % (limit_entries + 1)
            cap = max(length, 1) + rng() % 5
            head = rng() % (2 * cap) if rng() % 7 == 0 else rng() % cap
            entries = [pool[rng() % len(pool)] if rng() % 5 else make_key(rng, narrow) for _ in range(length)]
            yield Case("deque", entries, members, state, cap=cap, head=head)
        else:
            keys = [key for key in pool if rng() % 4]
            if rng() % 11 == 0:
                keys = pool[:]
            yield Case("map", [], members, state, map_keys=keys)


class Subject:
    """The decoded bytes of the two bodies, optionally with edited bytes."""

    def __init__(self, image, patches=None, step_limit=STEP_LIMIT):
        self.count = decode_range(image, COUNT_FN[0], COUNT_FN[1], patches)
        self.step = decode_range(image, NEXT_FN[0], NEXT_FN[1], patches)
        self.machine = Machine(image, None, patches)
        self.machine.step_limit = step_limit
        self.ranges = (self.count, self.step)


def run_case(subject, case, index):
    args = instantiate(subject.machine, case, 0x5EED + index)
    try:
        return subject.machine.run(COUNT_FN[0], args, subject.ranges)
    except Fault as exc:
        return Outcome("fault", 0, (("fault", str(exc)[:24]),), subject.machine.steps)


def verify_stream(subject, cases, flaw=None, stop_first=False, budgets=None):
    """Run cases through the bytes against the rule list; budgets caps each case at twice a reference step count."""
    out = dict(checked=0, mismatches=0, first=None, steps=0, kinds={}, wakes=0, per_case=[])
    for index, case in enumerate(cases):
        if budgets is not None:
            subject.machine.step_limit = 2 * budgets[index] + 2000
        got = run_case(subject, case, index)
        out["per_case"].append(got.steps)
        want = spec(case, flaw)
        out["checked"] += 1
        out["steps"] += got.steps
        out["kinds"][got.kind] = out["kinds"].get(got.kind, 0) + 1
        out["wakes"] += len(got.events) if got.kind == "return" else 0
        if got.key() != want:
            out["mismatches"] += 1
            if out["first"] is None:
                out["first"] = index
            if stop_first:
                break
    return out


# ---------------------------------------------------------------- controls and evidence

CASE_COUNT = 10500
SAMPLE_EVERY = 50
MUTANT_CASES = 3000
LANDING_PAD = 0x4FAC2DB
# Tag two with a btree walk cannot happen (the tag only becomes two on the deque path), so these four
# conditions of the empty-set btree loop are never decided by any input; they are listed, not claimed.
NEVER_DECIDED = (0x4FAC24D, 0x4FAC26E, 0x4FAC27C, 0x4FAC2A6)


def flip_patches(subject):
    """Every conditional jump of both bodies, with its condition inverted (one byte each)."""
    for table in (subject.count, subject.step):
        for va in sorted(table):
            row = table[va]
            if row.op == "jcc" and not LANDING_PAD <= va < COUNT_FN[1] and va not in NEVER_DECIDED:
                at = va + (1 if row.raw[0] == 0x0F else 0)
                yield "flip-jcc-%x" % va, {at: row.raw[at - va] ^ 1}


def erase_patches(subject):
    """Remove each byte swap so the member lookup compares words in the wrong order."""
    for table in (subject.count, subject.step):
        for va in sorted(table):
            row = table[va]
            if row.op == "bswap":
                yield "erase-bswap-%x" % va, {va + k: 0x90 for k in range(row.size)}


def boundary_controls(image):
    """Corrupted hash, address outside the file, bad decode ranges and a misaligned entry; each must be refused."""
    refusals = []

    def refused(label, action):
        try:
            action()
        except (EvidenceError, Fault, IndexError, KeyError, ValueError):
            refusals.append((label, True))
        else:
            refusals.append((label, False))

    refused("wrong-sha256", lambda: load_image(BINARY, "0" * 64))
    refused("address-outside-sections", lambda: image.offset(0x10))
    refused("range-ends-mid-instruction", lambda: decode_range(image, COUNT_FN[0], COUNT_FN[1] - 1))
    refused("opcode-outside-subset", lambda: decode(b"\x06" + bytes(15), 0, 0))
    refused("legacy-high-byte-register", lambda: decode(b"\x88\xc4" + bytes(14), 0, 0))
    subject = Subject(image)

    def misaligned():
        machine = subject.machine
        machine.fresh()
        machine.run(COUNT_FN[0] + 1, (0, 0), subject.ranges)

    refused("entry-inside-instruction", misaligned)

    def unknown_import():
        machine = subject.machine
        machine.fresh()
        machine.mem.map(ARC, 64)
        machine.step_import(0x64E0000)

    refused("unknown-import-slot", unknown_import)
    return refusals


def code_digest(image, start, end):
    return hashlib.sha256(image.code(start, end)).hexdigest()


def analyse(image):
    subject = Subject(image)
    cases = list(case_stream(CASE_COUNT))
    flaw_mismatch = {flaw: 0 for flaw in SPEC_FLAWS}
    flaw_first = {}
    sample_rows, total, steps, wakes, kinds, shapes = [], 0, 0, 0, {}, {}
    budgets = []
    for index, case in enumerate(cases):
        got = run_case(subject, case, index)
        want = spec(case)
        if got.key() != want:
            raise EvidenceError("case %d disagrees with the rule list: %r vs %r" % (index, got.key(), want))
        for flaw in SPEC_FLAWS:
            if spec(case, flaw) != got.key():
                flaw_mismatch[flaw] += 1
                flaw_first.setdefault(flaw, index)
        budgets.append(got.steps)
        total += 1
        steps += got.steps
        wakes += len(got.events) if got.kind == "return" else 0
        kinds[got.kind] = kinds.get(got.kind, 0) + 1
        shape = case.variant + ("-wrapped" if case.variant == "deque" and case.entries and case.head % max(case.cap, 1) + len(case.entries) > case.cap else "")
        shapes[shape] = shapes.get(shape, 0) + 1
        if index % SAMPLE_EVERY == 0:
            sample_rows.append((index, case.variant, case.state, len(case.entries) or len(case.map_keys),
                                len(case.members), got.kind, got.value, len(got.events), got.steps))
    controls = []
    for label, flaw in (("spec-" + f, f) for f in SPEC_FLAWS):
        controls.append((label, flaw_mismatch[flaw] > 0, flaw_first.get(flaw, -1)))
    patch_sets = list(flip_patches(subject)) + list(erase_patches(subject))
    for label, patch in patch_sets:
        mutant = Subject(image, patch)
        result = verify_stream(mutant, cases[:MUTANT_CASES], stop_first=True, budgets=budgets)
        controls.append((label, result["mismatches"] > 0, -1 if result["first"] is None else result["first"]))
    for label, ok in boundary_controls(image):
        controls.append((label, ok, -1))
    return dict(subject=subject, cases=total, steps=steps, wakes=wakes, kinds=kinds, shapes=shapes,
                sample=sample_rows, controls=controls, max_steps=max(budgets))


def instruction_rows(subject):
    for name, table in (("count", subject.count), ("step", subject.step)):
        for va in sorted(table):
            row = table[va]
            yield name, va, row.size, row.op, row.raw.hex()


def render(image, result):
    subject = result["subject"]
    files = {}
    rows = ["body\tva\tsize\top\tbytes"]
    rows += ["%s\t%#x\t%d\t%s\t%s" % r for r in instruction_rows(subject)]
    files["instructions.tsv"] = "\n".join(rows) + "\n"
    rows = ["index\tvariant\tlock_word\tentries\tmembers\toutcome\tcount\tevents\tsteps"]
    rows += ["%d\t%s\t%#x\t%d\t%d\t%s\t%d\t%d\t%d" % r for r in result["sample"]]
    files["cases.tsv"] = "\n".join(rows) + "\n"
    rows = ["control\tdetected\tfirst_case"]
    rows += ["%s\t%d\t%d" % (label, int(ok), first) for label, ok, first in result["controls"]]
    files["controls.tsv"] = "\n".join(rows) + "\n"
    detected = sum(1 for _, ok, _ in result["controls"] if ok)
    summary = dict(
        binary_sha256=SHA256,
        bodies={"count": {"start": COUNT_FN[0], "end": COUNT_FN[1], "instructions": len(subject.count),
                          "code_sha256": code_digest(image, *COUNT_FN)},
                "step": {"start": NEXT_FN[0], "end": NEXT_FN[1], "instructions": len(subject.step),
                         "code_sha256": code_digest(image, *NEXT_FN)}},
        import_slots={"lock_slow_path": GOT_SLOW_LOCK, "wake_one": GOT_WAKE, "panic_a": GOT_PANIC_A,
                      "panic_b": GOT_PANIC_B},
        case_count=result["cases"], executed_steps=result["steps"], max_case_steps=result["max_steps"],
        outcomes=dict(sorted(result["kinds"].items())), shapes=dict(sorted(result["shapes"].items())),
        wake_requests=result["wakes"], sample_every=SAMPLE_EVERY, mutant_cases=MUTANT_CASES,
        never_decided_conditions=list(NEVER_DECIDED), landing_pad_start=LANDING_PAD,
        negative_controls=len(result["controls"]), negative_detected=detected)
    files["summary.json"] = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps(dict(cases=result["cases"], negative_controls=len(result["controls"]),
                                            negative_detected=detected), indent=2, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(image, analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
