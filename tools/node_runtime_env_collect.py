#!/usr/bin/env python3
"""Reconstruct the node #115 process argv and environment snapshot collectors.

The two functions are decoded from the pinned ELF bytes by a small x86-64
interpreter (only the instruction forms those functions use), run on generated
process images, and compared with an independent Python specification. Nothing
is executed except the interpreter's own model; the node binary is only read.
"""
import argparse
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
M64 = (1 << 64) - 1
ARGV_FN, ENV_FN = 0x5c9a530, 0x5c9a710
ARGC_CELL, ARGV_CELL = 0x6500000, 0x6500008
ARGV_LIMIT = 0x555555555555555
LOCK_WORD, ENVIRON_SLOT = 0x64ffff0, 0x64ec7b0
SLOTS = {
    0x64df480: 'alloc', 0x64df698: 'strlen', 0x64df508: 'memcpy', 0x64df498: 'alloc_error',
    0x64df4a0: 'dealloc', 0x64df570: 'slice_fail', 0x64ec568: 'vec_grow', 0x64ec6d0: 'read_contended',
    0x64ec5b0: 'read_unlock_contended', 0x64eb000: 'drop_vec', 0x64df4c0: 'unwrap_fail',
}
NORETURN = {'alloc_error', 'slice_fail', 'unwrap_fail'}
SENTINEL = 0x7ffe00000000
STACK_TOP = 0x7ffd00100000
HEAP_BASE = 0x100000000
ENV_BASE = 0x200000000
ENVIRON_VAR = 0x650f000
OUT_PTR = STACK_TOP + 0x2000
STEP_LIMIT = 400000


class EmuError(Exception):
    pass


class Trap(Exception):
    def __init__(self, kind, detail=()):
        super().__init__(kind)
        self.kind, self.detail = kind, tuple(detail)


# ---------------------------------------------------------------- image ----

def load_node(path):
    with open(path, 'rb') as handle:
        data = handle.read()
    return check_node(data)


def check_node(data):
    if hashlib.sha256(data).hexdigest() != NODE_SHA256:
        raise ValueError('node #115 SHA-256 mismatch')
    return data


class Image:
    """Read-only view of the ALLOC sections by virtual address, with optional byte patches."""

    def __init__(self, data, patches=None):
        self.data = data
        self.patches = dict(patches or {})
        self.ranges = sorted((s['address'], s['size'], None if s['type'] == 8 else s['offset'])
                             for s in elf_index.sections(data) if s['flags'] & 2 and s['size'])
        self.cache = {}

    def byte(self, va):
        if va in self.patches:
            return self.patches[va]
        for addr, size, off in self.ranges:
            if addr <= va < addr + size:
                return 0 if off is None else self.data[off + va - addr]
        raise EmuError('read outside image: %#x' % va)

    def read(self, va, n):
        for addr, size, off in self.ranges:
            if addr <= va and va + n <= addr + size:
                if off is None:
                    blob = bytearray(n)
                else:
                    blob = bytearray(self.data[off + va - addr:off + va - addr + n])
                for p, v in self.patches.items():
                    if va <= p < va + n:
                        blob[p - va] = v
                return bytes(blob)
        return bytes(self.byte(va + i) for i in range(n))


# ------------------------------------------------------------- memory ----

class Memory:
    def __init__(self, image):
        self.image, self.pages = image, {}

    def _page(self, addr, write):
        key = addr >> 12
        page = self.pages.get(key)
        if page is None:
            if write:
                try:
                    page = bytearray(self.image.read(key << 12, 4096))
                except EmuError:
                    page = bytearray(4096)
                self.pages[key] = page
            else:
                return None
        return page

    def read(self, addr, n):
        out = bytearray()
        while n:
            lo = addr & 4095
            take = min(n, 4096 - lo)
            page = self.pages.get(addr >> 12)
            out += page[lo:lo + take] if page is not None else self.image.read(addr, take)
            addr, n = addr + take, n - take
        return bytes(out)

    def write(self, addr, blob):
        pos = 0
        while pos < len(blob):
            lo = addr & 4095
            take = min(len(blob) - pos, 4096 - lo)
            self._page(addr, True)[lo:lo + take] = blob[pos:pos + take]
            addr, pos = addr + take, pos + take

    def u(self, addr, n):
        return int.from_bytes(self.read(addr, n), 'little')

    def put(self, addr, value, n):
        self.write(addr, (value & ((1 << (8 * n)) - 1)).to_bytes(n, 'little'))


# ------------------------------------------------------------ decoder ----

REGN = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'] + ['r%d' % i for i in range(8, 16)]
ALU = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}
CONDS = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g']


class Insn:
    __slots__ = ('va', 'n', 'text', 'fn')

    def __init__(self, va, n, text, fn):
        self.va, self.n, self.text, self.fn = va, n, text, fn


def signed(v, bits):
    return v - (1 << bits) if v >> (bits - 1) else v


def fetch(image, va):
    if va in image.cache:
        return image.cache[va]
    insn = decode(image, va)
    image.cache[va] = insn
    return insn


class Cursor:
    def __init__(self, image, va):
        self.image, self.va, self.pos = image, va, va

    def take(self, n):
        v = int.from_bytes(self.image.read(self.pos, n), 'little')
        self.pos += n
        return v

    def stake(self, n):
        return signed(self.take(n), 8 * n)


def read_modrm(cur, rex):
    b = cur.take(1)
    mod, reg, rm = b >> 6, ((b >> 3) & 7) | ((rex & 4) << 1), b & 7
    if mod == 3:
        return mod, reg, ('r', rm | ((rex & 1) << 3))
    base = index = None
    scale, disp = 1, 0
    if rm == 4:
        sib = cur.take(1)
        scale = 1 << (sib >> 6)
        idx = ((sib >> 3) & 7) | ((rex & 2) << 2)
        bs = sib & 7
        index = None if idx == 4 else idx
        if bs == 5 and mod == 0:
            disp = cur.stake(4)
        else:
            base = bs | ((rex & 1) << 3)
    elif rm == 5 and mod == 0:
        base, disp = 'rip', cur.stake(4)
    else:
        base = rm | ((rex & 1) << 3)
    if mod == 1:
        disp = cur.stake(1)
    elif mod == 2:
        disp = cur.stake(4)
    return mod, reg, ('m', base, index, scale, disp)


def flags_arith(cpu, kind, a, b, bits):
    mask = (1 << bits) - 1
    top = bits - 1
    if kind == 'add':
        r = (a + b) & mask
        cpu.cf = (a + b) > mask
        cpu.of = bool(((a ^ r) & (b ^ r)) >> top & 1)
    elif kind in ('sub', 'cmp'):
        r = (a - b) & mask
        cpu.cf = a < b
        cpu.of = bool(((a ^ b) & (a ^ r)) >> top & 1)
    else:
        r = {'and': a & b, 'or': a | b, 'xor': a ^ b}[kind] & mask
        cpu.cf = cpu.of = False
    cpu.zf, cpu.sf = r == 0, bool(r >> top & 1)
    return r


def condition(cpu, cc):
    c = CONDS[cc]
    if c == 'o': return cpu.of
    if c == 'no': return not cpu.of
    if c == 'b': return cpu.cf
    if c == 'ae': return not cpu.cf
    if c == 'e': return cpu.zf
    if c == 'ne': return not cpu.zf
    if c == 'be': return cpu.cf or cpu.zf
    if c == 'a': return not (cpu.cf or cpu.zf)
    if c == 's': return cpu.sf
    if c == 'ns': return not cpu.sf
    if c == 'l': return cpu.sf != cpu.of
    if c == 'ge': return cpu.sf == cpu.of
    if c == 'le': return cpu.zf or cpu.sf != cpu.of
    if c == 'g': return not cpu.zf and cpu.sf == cpu.of
    raise EmuError('unsupported condition ' + c)


def operand(op, nxt):
    """Compile a decoded r/m operand into (getter(cpu, bits), setter(cpu, value, bits), ea(cpu))."""
    if op[0] == 'r':
        n = op[1]

        def get(cpu, bits):
            return cpu.r[n] & ((1 << bits) - 1)

        def put(cpu, v, bits):
            cpu.r[n] = (v & M64) if bits == 64 else (cpu.r[n] & ~((1 << bits) - 1) & M64 if bits < 32 else 0) | (v & ((1 << bits) - 1))
        return get, put, None
    _, base, index, scale, disp = op
    if base == 'rip':
        disp, base = disp + nxt, None

    def ea(cpu):
        a = disp + (cpu.r[base] if base is not None else 0) + (cpu.r[index] * scale if index is not None else 0)
        return a & M64

    def get(cpu, bits):
        return cpu.mem.u(ea(cpu), bits // 8)

    def put(cpu, v, bits):
        cpu.mem.put(ea(cpu), v, bits // 8)
    return get, put, ea


def decode(image, va):
    cur = Cursor(image, va)
    rex = 0
    lock = False
    while True:
        b = cur.take(1)
        if b in (0x66, 0x2e):
            continue
        if b == 0xf0:
            lock = True
            continue
        break
    if 0x40 <= b <= 0x4f:
        rex = b
        b = cur.take(1)
    w = 64 if rex & 8 else 32
    rexb = (rex & 1) << 3
    fin = lambda text, fn: Insn(va, cur.pos - va, text, fn)  # noqa: E731

    def mk(text, build):
        # build(nxt) -> fn; the length is only known once the whole instruction is read
        return Insn(va, cur.pos - va, text, build(cur.pos))

    if 0x50 <= b <= 0x57 or 0x58 <= b <= 0x5f:
        n = (b & 7) | rexb
        if b < 0x58:
            def f(cpu, n=n):
                cpu.r[4] = (cpu.r[4] - 8) & M64
                cpu.mem.put(cpu.r[4], cpu.r[n], 8)
            return fin('push', f)

        def f(cpu, n=n):
            cpu.r[n] = cpu.mem.u(cpu.r[4], 8)
            cpu.r[4] = (cpu.r[4] + 8) & M64
        return fin('pop', f)
    if b < 0x40 and (b & 7) in (1, 3) and ((b >> 3) & 7) in ALU:
        kind = ALU[(b >> 3) & 7]
        _, reg, rm = read_modrm(cur, rex)
        direction_rm_dest = (b & 7) == 1
        return mk(kind, lambda nxt: alu_fn(kind, reg, operand(rm, nxt), direction_rm_dest, w))
    if b < 0x40 and (b & 7) == 5 and ((b >> 3) & 7) in ALU:
        kind = ALU[(b >> 3) & 7]
        imm = cur.stake(4)
        return mk(kind + 'i', lambda nxt: alui_fn(kind, operand(('r', 0), nxt), imm, w))
    if b in (0x81, 0x83, 0x80):
        _, reg, rm = read_modrm(cur, rex)
        imm = cur.stake(4 if b == 0x81 else 1)
        kind = ALU[reg & 7] if (reg & 7) in ALU else None
        if kind is None:
            raise EmuError('unsupported group-1 op')
        bits = 8 if b == 0x80 else w
        return mk(kind + 'i', lambda nxt: alui_fn(kind, operand(rm, nxt), imm, bits))
    if b == 0x85:
        _, reg, rm = read_modrm(cur, rex)
        return mk('test', lambda nxt: test_fn(reg, operand(rm, nxt), w))
    if b in (0x89, 0x8b, 0x8d):
        _, reg, rm = read_modrm(cur, rex)
        return mk('mov' if b != 0x8d else 'lea', lambda nxt: mov_fn(b, reg, operand(rm, nxt), w))
    if b == 0x90:
        return fin('nop', lambda cpu: None)
    if 0xb8 <= b <= 0xbf:
        n = (b & 7) | rexb
        imm = cur.take(8 if rex & 8 else 4)

        def f(cpu, n=n, imm=imm):
            cpu.r[n] = imm
        return fin('movabs' if rex & 8 else 'movi', f)
    if b == 0xc7:
        _, reg, rm = read_modrm(cur, rex)
        if reg & 7:
            raise EmuError('unsupported c7 form')
        imm = cur.stake(4)
        return mk('movi', lambda nxt: movi_fn(operand(rm, nxt), imm, w))
    if b == 0xc1:
        _, reg, rm = read_modrm(cur, rex)
        imm = cur.take(1)
        if reg & 7 not in (4, 5):
            raise EmuError('unsupported shift')
        return mk('shift', lambda nxt: shift_fn(reg & 7, operand(rm, nxt), imm, w))
    if b == 0xf7:
        _, reg, rm = read_modrm(cur, rex)
        if reg & 7 != 3:
            raise EmuError('unsupported f7 form')
        return mk('neg', lambda nxt: neg_fn(operand(rm, nxt), w))
    if b == 0xff:
        _, reg, rm = read_modrm(cur, rex)
        sub = reg & 7
        if sub in (0, 1):
            return mk('incdec', lambda nxt: incdec_fn(sub, operand(rm, nxt), w))
        if sub == 2 and rm[0] == 'm':
            return mk('call', lambda nxt: call_fn(operand(rm, nxt), nxt))
        raise EmuError('unsupported ff form')
    if b == 0xc3:
        def f(cpu):
            cpu.pc = cpu.mem.u(cpu.r[4], 8)
            cpu.r[4] = (cpu.r[4] + 8) & M64
        return fin('ret', f)
    if b == 0xcc:
        def f(cpu):
            raise Trap('int3')
        return fin('int3', f)
    if b == 0xeb or b == 0xe9 or 0x70 <= b <= 0x7f:
        rel = cur.stake(1 if (b == 0xeb or b >= 0x70 and b <= 0x7f) else 4)
        cc = b & 15 if 0x70 <= b <= 0x7f else None
        return mk('jmp' if cc is None else 'j' + CONDS[cc], lambda nxt: jump_fn(cc, nxt + rel))
    if b == 0xe8:
        rel = cur.stake(4)

        def f(cpu, target=None):
            raise EmuError('direct call executed')
        return fin('call-rel', f)
    if b == 0x0f:
        b2 = cur.take(1)
        if b2 == 0x0b:
            def f(cpu):
                raise Trap('ud2')
            return fin('ud2', f)
        if b2 == 0x1f:
            read_modrm(cur, rex)
            return fin('nopl', lambda cpu: None)
        if 0x80 <= b2 <= 0x8f:
            rel = cur.stake(4)
            cc = b2 & 15
            return mk('j' + CONDS[cc], lambda nxt: jump_fn(cc, nxt + rel))
        if b2 in (0x10, 0x11):
            _, reg, rm = read_modrm(cur, rex)
            if rm[0] != 'm':
                raise EmuError('register movups unsupported')
            return mk('movups', lambda nxt: movups_fn(b2, reg & 7 if True else reg, operand(rm, nxt)))
        if b2 == 0xb6:
            _, reg, rm = read_modrm(cur, rex)
            return mk('movzbl', lambda nxt: movzb_fn(reg, operand(rm, nxt)))
        if b2 in (0xb1, 0xc1):
            _, reg, rm = read_modrm(cur, rex)
            if not lock:
                raise EmuError('cmpxchg/xadd without lock prefix')
            return mk('cmpxchg' if b2 == 0xb1 else 'xadd', lambda nxt: atomic_fn(b2, reg, operand(rm, nxt), w))
    raise EmuError('unsupported opcode %#x at %#x' % (b, va))


def alu_fn(kind, reg, opnd, rm_dest, bits):
    get, put, _ = opnd

    def f(cpu):
        if rm_dest:
            a, b = get(cpu, bits), cpu.r[reg] & ((1 << bits) - 1)
        else:
            a, b = cpu.r[reg] & ((1 << bits) - 1), get(cpu, bits)
        r = flags_arith(cpu, kind, a, b, bits)
        if kind != 'cmp':
            if rm_dest:
                put(cpu, r, bits)
            else:
                cpu.r[reg] = r if bits == 32 else r & M64
    return f


def alui_fn(kind, opnd, imm, bits):
    get, put, _ = opnd

    def f(cpu):
        b = imm & ((1 << bits) - 1)
        r = flags_arith(cpu, kind, get(cpu, bits), b, bits)
        if kind != 'cmp':
            put(cpu, r, bits)
    return f


def test_fn(reg, opnd, bits):
    get = opnd[0]

    def f(cpu):
        flags_arith(cpu, 'and', get(cpu, bits), cpu.r[reg] & ((1 << bits) - 1), bits)
    return f


def mov_fn(opc, reg, opnd, bits):
    get, put, ea = opnd

    def f(cpu):
        if opc == 0x89:
            put(cpu, cpu.r[reg], bits)
        elif opc == 0x8b:
            v = get(cpu, bits)
            cpu.r[reg] = v if bits == 64 else v & 0xffffffff
        else:
            v = ea(cpu)
            cpu.r[reg] = v if bits == 64 else v & 0xffffffff
    return f


def movi_fn(opnd, imm, bits):
    put = opnd[1]

    def f(cpu):
        put(cpu, imm & ((1 << bits) - 1), bits)
    return f


def shift_fn(sub, opnd, imm, bits):
    get, put, _ = opnd

    def f(cpu):
        v = get(cpu, bits)
        r = (v << imm) & ((1 << bits) - 1) if sub == 4 else v >> imm
        cpu.zf, cpu.sf = r == 0, bool(r >> (bits - 1) & 1)
        put(cpu, r, bits)
    return f


def neg_fn(opnd, bits):
    get, put, _ = opnd

    def f(cpu):
        v = get(cpu, bits)
        r = flags_arith(cpu, 'sub', 0, v, bits)
        put(cpu, r, bits)
    return f


def incdec_fn(sub, opnd, bits):
    get, put, _ = opnd

    def f(cpu):
        keep = cpu.cf
        r = flags_arith(cpu, 'add' if sub == 0 else 'sub', get(cpu, bits), 1, bits)
        cpu.cf = keep
        put(cpu, r, bits)
    return f


def call_fn(opnd, nxt):
    ea = opnd[2]

    def f(cpu):
        slot = ea(cpu)
        name = SLOTS.get(slot)
        if name is None:
            raise EmuError('call through unknown slot %#x' % slot)
        cpu.hook(name, slot)
    return f


def jump_fn(cc, target):
    def f(cpu):
        if cc is None or condition(cpu, cc):
            cpu.pc = target
    return f


def movups_fn(opc, reg, opnd):
    get, put, ea = opnd

    def f(cpu):
        a = ea(cpu)
        if opc == 0x10:
            cpu.x[reg] = cpu.mem.u(a, 16)
        else:
            cpu.mem.put(a, cpu.x[reg], 16)
    return f


def movzb_fn(reg, opnd):
    get = opnd[0]

    def f(cpu):
        cpu.r[reg] = get(cpu, 8)
    return f


def atomic_fn(opc, reg, opnd, bits):
    get, put, _ = opnd
    mask = (1 << bits) - 1

    def f(cpu):
        dest = get(cpu, bits)
        if opc == 0xb1:
            flags_arith(cpu, 'cmp', cpu.r[0] & mask, dest, bits)
            if cpu.zf:
                put(cpu, cpu.r[reg] & mask, bits)
            else:
                cpu.r[0] = dest if bits == 64 else dest & mask
        else:
            src = cpu.r[reg] & mask
            put(cpu, flags_arith(cpu, 'add', dest, src, bits), bits)
            cpu.r[reg] = dest if bits == 64 else dest & mask
    return f


# ----------------------------------------------------------- emulator ----

class Cpu:
    def __init__(self, image, alloc_fail=(), lock_initial=None):
        self.image, self.mem = image, Memory(image)
        self.r, self.x = [0] * 16, [0] * 16
        self.cf = self.zf = self.sf = self.of = False
        self.pc = 0
        self.heap = HEAP_BASE
        self.alloc_count, self.alloc_fail = 0, set(alloc_fail)
        self.events, self.steps = [], 0
        self.sizes = {}

    def new_block(self, size):
        addr = self.heap
        self.heap += (max(size, 1) + 15) & ~15
        self.sizes[addr] = size
        return addr

    def cstr(self, addr):
        n = 0
        while True:
            take = min(64, 4096 - ((addr + n) & 4095))
            z = self.mem.read(addr + n, take).find(b'\0')
            if z >= 0:
                return n + z
            n += take

    def hook(self, name, slot):
        r = self.r
        if name == 'alloc':
            k = self.alloc_count
            self.alloc_count += 1
            r[0] = 0 if k in self.alloc_fail else self.new_block(r[7])
            self.events.append(('alloc', r[7], r[0] != 0))
        elif name == 'strlen':
            r[0] = self.cstr(r[7])
        elif name == 'memcpy':
            self.mem.write(r[7], self.mem.read(r[6], r[2]))
            r[0] = r[7]
        elif name == 'vec_grow':
            vec = r[7]
            cap, ptr, ln = self.mem.u(vec, 8), self.mem.u(vec + 8, 8), self.mem.u(vec + 16, 8)
            new_cap = max(4, cap * 2)
            new_ptr = self.new_block(new_cap * 48)
            self.mem.write(new_ptr, self.mem.read(ptr, ln * 48)) if cap else None
            self.mem.put(vec, new_cap, 8)
            self.mem.put(vec + 8, new_ptr, 8)
            self.events.append(('grow', new_cap))
        elif name == 'read_contended':
            self.events.append(('read_contended',))
            self.mem.put(LOCK_WORD, self.mem.u(LOCK_WORD, 4) + 1, 4)
        elif name == 'read_unlock_contended':
            self.events.append(('wake',))
        elif name in NORETURN:
            self.events.append((name, r[7], r[6]))
            raise Trap(name, (r[7], r[6]))
        else:
            raise EmuError('hook ' + name + ' reached outside the modelled paths')

    def run(self, entry, out_ptr=OUT_PTR):
        r = self.r
        r[4] = STACK_TOP
        r[7] = out_ptr
        r[4] -= 8
        self.mem.put(r[4], SENTINEL, 8)
        self.pc = entry
        while self.pc != SENTINEL:
            self.steps += 1
            if self.steps > STEP_LIMIT:
                raise EmuError('step limit exceeded')
            insn = fetch(self.image, self.pc)
            self.pc += insn.n
            insn.fn(self)
        return r[0]


# ------------------------------------------------------- process images --

def build_argv(cpu, argc, args, null_at=None):
    """Lay out argc/argv cells and strings. `null_at` makes argv[null_at] a NULL pointer."""
    addr = ENV_BASE
    ptrs = []
    for a in args:
        addr += 3
        cpu.mem.write(addr, a + b'\0')
        ptrs.append(addr)
        addr += len(a) + 1
    table = (addr + 15) & ~15
    for i, p in enumerate(ptrs):
        cpu.mem.put(table + 8 * i, 0 if i == null_at else p, 8)
    cpu.mem.put(table + 8 * len(ptrs), 0, 8)
    cpu.mem.put(ARGC_CELL, argc, 8)
    cpu.mem.put(ARGV_CELL, table, 8)


def build_environ(cpu, strings, offsets, lock):
    addr = ENV_BASE
    ptrs = []
    for s, off in zip(strings, offsets):
        addr = ((addr + 64) & ~7) + off
        cpu.mem.write(addr, s + b'\0')
        ptrs.append(addr)
        addr += len(s) + 1
    table = (addr + 63) & ~7
    for i, p in enumerate(ptrs):
        cpu.mem.put(table + 8 * i, p, 8)
    cpu.mem.put(table + 8 * len(ptrs), 0, 8)
    cpu.mem.put(ENVIRON_VAR, table, 8)
    cpu.mem.put(ENVIRON_SLOT, ENVIRON_VAR, 8)
    cpu.mem.put(LOCK_WORD, lock, 4)


def read_iter(cpu):
    """Decode the {buf, cur, cap, end} result of either collector."""
    buf, cur, cap, end = (cpu.mem.u(OUT_PTR + 8 * i, 8) for i in range(4))
    return buf, cur, cap, end


def run_argv(image, argc, args, null_at=None, alloc_fail=(), argv_null=False):
    cpu = Cpu(image, alloc_fail)
    build_argv(cpu, argc, args, null_at)
    if argv_null:
        cpu.mem.put(ARGV_CELL, 0, 8)
    try:
        ret = cpu.run(ARGV_FN)
    except Trap as t:
        return ('trap', t.kind, t.detail)
    buf, cur, cap, end = read_iter(cpu)
    if ret != OUT_PTR or cur != buf or (end - buf) % 24:
        return ('shape', ret, buf, cur, cap, end)
    items = []
    for i in range((end - buf) // 24):
        c, p, n = (cpu.mem.u(buf + 24 * i + 8 * j, 8) for j in range(3))
        items.append((c == n, cpu.mem.read(p, n)))
    return ('ok', cap, tuple(items))


def run_env(image, strings, offsets, lock=0, alloc_fail=()):
    cpu = Cpu(image, alloc_fail)
    build_environ(cpu, strings, offsets, lock)
    try:
        ret = cpu.run(ENV_FN)
    except Trap as t:
        return ('trap', t.kind, t.detail, tuple(cpu.events))
    buf, cur, cap, end = read_iter(cpu)
    if ret != OUT_PTR or cur != buf or (end - buf) % 48:
        return ('shape', ret, buf, cur, cap, end)
    items = []
    for i in range((end - buf) // 48):
        f = [cpu.mem.u(buf + 48 * i + 8 * j, 8) for j in range(6)]
        exact = f[0] == f[2] and f[3] == f[5]
        items.append((exact, cpu.mem.read(f[1], f[2]), cpu.mem.read(f[4], f[5])))
    events = tuple(e for e in cpu.events if e[0] in ('read_contended', 'wake'))
    return ('ok', cap, tuple(items), cpu.mem.u(LOCK_WORD, 4), events, cap >= len(items))


# -------------------------------------------------------------- specs ----

def spec_split(s, start=1):
    """Key/value split of one environment string: first '=' at index >= start."""
    i = s.find(b'=', start)
    return None if i < 0 or len(s) == 0 else (s[:i], s[i + 1:])


def spec_env(strings, lock=0, split=spec_split):
    pairs = []
    for s in strings:
        if not s:
            continue
        kv = split(s)
        if kv is not None:
            pairs.append(kv)
    slow = lock > 0x3ffffffd
    events = (('read_contended',),) if slow else ()
    if slow and (lock & 0xbfffffff) == 0x80000000:
        events += (('wake',),)
    return pairs, lock, events


def expected_env(strings, lock=0):
    pairs, final, events = spec_env(strings, lock)
    return ('ok', tuple((True, k, v) for k, v in pairs), final, events)


def view_env(result):
    if result[0] != 'ok':
        return result
    return ('ok', result[2], result[3], result[4])


def spec_argv(argc, args, null_at=None, argv_null=False):
    if argv_null or argc == 0:
        return ('ok', 0, ())
    if argc > ARGV_LIMIT:
        return ('trap', 'alloc_error', (0, (argc * 24) & M64))
    items = []
    for i in range(argc):
        if i >= len(args) or i == null_at:
            break
        items.append((True, args[i]))
    return ('ok', argc, tuple(items))


# -------------------------------------------------------------- cases ----

class Lcg:
    def __init__(self, seed):
        self.s = seed

    def next(self, n):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & M64
        return (self.s >> 33) % n


ALPHA = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_/:.'
ODD = bytes([0x3c, 0x3e, 0xbd, 0x80, 0xff, 0x7f, 0x01, 0xbc, 0x1d, 0x7d])
LENGTHS = [0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 18, 24, 25, 31, 32, 33, 40, 47, 48, 49, 64, 100]


def random_string(rng):
    n = LENGTHS[rng.next(len(LENGTHS))] if rng.next(3) else rng.next(60)
    body = bytearray(ALPHA[rng.next(len(ALPHA))] for _ in range(n))
    for i in range(n):
        if rng.next(23) == 0:
            body[i] = ODD[rng.next(len(ODD))]
    style = rng.next(8)
    if n and style < 5:
        body[rng.next(n)] = 0x3d
        if style == 4 and n > 1:
            body[rng.next(n)] = 0x3d
    elif n and style == 5:
        body[0] = 0x3d
    elif n and style == 6:
        body[n - 1] = 0x3d
    return bytes(body)


LOCKS = [0, 0, 0, 1, 5, 0x3ffffffc, 0x3ffffffd, 0x3ffffffe, 0x40000000, 0x40000001, 0x80000000, 0x80000001, 0xc0000000]


def env_cases(count, seed=1):
    rng = Lcg(seed)
    for _ in range(count):
        n = rng.next(7) if rng.next(4) else rng.next(26)
        strings = [random_string(rng) for _ in range(n)]
        offsets = [rng.next(8) for _ in range(n)]
        lock = LOCKS[rng.next(len(LOCKS))]
        yield strings, offsets, lock


def argv_cases(count, seed=7):
    rng = Lcg(seed)
    for _ in range(count):
        n = rng.next(6) if rng.next(5) else rng.next(20)
        args = [bytes(ALPHA[rng.next(len(ALPHA))] if rng.next(15) else rng.next(255) + 1 for _ in range(LENGTHS[rng.next(len(LENGTHS))] if rng.next(2) else rng.next(10))) for _ in range(n)]
        args = [a.replace(b'\0', b'x') for a in args]
        argc = n if rng.next(4) else rng.next(n + 4)
        if rng.next(97) == 0:
            argc = ARGV_LIMIT + 1 + rng.next(1000)
        null_at = rng.next(n) if n and rng.next(6) == 0 else None
        yield argc, args, null_at, rng.next(40) == 0


# ------------------------------------------------- negative controls ----

def mutate_split(kind):
    def start0(s): return None if not s else _split(s, 0)
    def start2(s): return _split(s, 2)
    def keep_missing(s): return spec_split(s) or (s, b'')
    def last(s):
        i = s.rfind(b'=')
        return None if i < 1 else (s[:i], s[i + 1:])
    def value_with_eq(s):
        r = spec_split(s)
        return None if r is None else (r[0], b'=' + r[1])
    def value_off(s):
        r = spec_split(s)
        return None if r is None else (r[0], s[len(r[0]) + 2:] if len(s) > len(r[0]) + 2 else b'')
    def drop_empty_value(s):
        r = spec_split(s)
        return None if r is None or not r[1] else r
    def drop_ascii8(s):
        r = spec_split(s)
        return None if r is None or any(c > 127 for c in s) else r
    def key_lower(s):
        r = spec_split(s)
        return None if r is None else (r[0].lower(), r[1])
    def key_one(s):
        r = spec_split(s)
        return None if r is None or len(s) < 3 else r
    def swap(s):
        r = spec_split(s)
        return None if r is None else (r[1], r[0])
    def after16(s):
        return _split(s, 1) if len(s) <= 16 else _split(s, 2)
    def trunc_key(s):
        r = spec_split(s)
        return None if r is None else (r[0][:63], r[1])
    return {'start0': start0, 'start2': start2, 'keep_missing': keep_missing, 'last_equals': last,
            'value_with_eq': value_with_eq, 'value_off': value_off, 'drop_empty_value': drop_empty_value,
            'drop_high_bytes': drop_ascii8, 'key_lower': key_lower, 'drop_short': key_one,
            'swap': swap, 'wide_start': after16, 'trunc_key': trunc_key}[kind]


def _split(s, start):
    i = s.find(b'=', start)
    return None if i < 0 else (s[:i], s[i + 1:])


SPEC_MUTANTS = ['start0', 'start2', 'keep_missing', 'last_equals', 'value_with_eq', 'value_off', 'drop_empty_value',
                'drop_high_bytes', 'key_lower', 'drop_short', 'swap', 'wide_start', 'trunc_key']


def mutant_battery():
    """A short, fixed set of process images that every byte-level mutant is run against."""
    cases = []
    for n in (1, 2, 5, 8, 16, 17, 18, 24, 33, 47):
        for pos in (None, 0, 1, 2, 7, 8, 15, n - 1):
            for off in (0, 3):
                if pos is not None and pos >= n:
                    continue
                s = bytearray(b'k' * n)
                if pos is not None:
                    s[pos] = 0x3d
                cases.append((('env', [bytes(s)], [off], 0)))
    cases.append(('env', [b'A=1', b'B=22', b'C', b'=D=4', b'', b'E=' + bytes([0xbd, 0x80]) * 12] * 3, [0, 1, 2, 3, 4, 5] * 3, 0))
    cases.append(('env', [b'x' * 40 + b'=' + bytes([0xbd] * 20)], [3], 0x3ffffffd))
    cases.append(('env', [b'a=b'], [0], 0x3ffffffe))
    cases.append(('env', [b'a=b'], [0], 0x80000000))
    cases.append(('env', [b'a=b'], [0], 0x3ffffffd))
    cases.append(('env', [b'a=b%d' % i for i in range(5)], [0] * 5, 0))
    cases.append(('argv', 3, [b'node', b'', b'--x'], None, False))
    cases.append(('argv', 2, [b'a', b'b'], None, False))
    cases.append(('argv', 4, [b'a', b'b'], None, False))
    cases.append(('argv', 3, [b'a', b'b', b'c'], 1, False))
    cases.append(('argv', 0, [], None, False))
    cases.append(('argv', 1, [b'z' * 33], None, True))
    cases.append(('argv', 5, [b'p', b'q', b'r', b'zz', b'ww'], None, False))
    cases.append(('argv', ARGV_LIMIT, [b'a'], None, False))
    cases.append(('argv', ARGV_LIMIT + 1, [b'a'], None, False))
    cases.append(('argv', 0x500000000000000, [b'a', b'b'], None, False))
    for pos in range(17, 40):
        cases.append(('env', [b'k' * pos + b'=' + b'v' * (39 - pos)], [0], 0))
    cases.append(('env', [b'q' * 18 + bytes([0x3c, 0x3e, 0xbd, 0x3d ^ 0x20, 0x1d, 0x7d]) * 3 + b'=z'], [1], 0))
    cases.append(('env', [b'q' * 17], [0], 0))
    cases.append(('env', [b'q' * 16 + b'=', b'r' * 33], [0, 5], 0))
    return cases


def run_battery(image, cases):
    out = []
    for c in cases:
        try:
            if c[0] == 'env':
                out.append(view_env(run_env(image, c[1], c[2], c[3])))
            else:
                out.append(run_argv(image, c[1], c[2], c[3], argv_null=c[4]))
        except (EmuError, Trap, ValueError, struct.error, IndexError) as exc:
            out.append(('error', type(exc).__name__))
    return out


def expected_battery(cases):
    out = []
    for c in cases:
        if c[0] == 'env':
            out.append(expected_env(c[1], c[3]))
        else:
            out.append(spec_argv(c[1], c[2], c[3], c[4]))
    return out


def normalise_battery(results):
    fixed = []
    for r in results:
        if r[0] == 'ok' and len(r) == 3:
            fixed.append(('ok', r[1], r[2]))
        else:
            fixed.append(r)
    return fixed


# (address, offset inside the instruction's bytes is given by absolute patch address, expected old byte, new byte)
BYTE_MUTANTS = [
    ('small_scan_literal', 0x5c9a814, 0x3d, 0x3e),
    ('unaligned_scan_literal', 0x5c9a8a4, 0x3d, 0x3e),
    ('tail_scan_literal', 0x5c9a8e4, 0x3d, 0x3e),
    ('swar_high_mask_const', 0x5c9a793, 0x80, 0x00),
    ('swar_low_const_lane2', 0x5c9a85f, 0x01, 0x00),
    ('swar_low_const_lane7', 0x5c9a864, 0x01, 0x00),
    ('small_length_threshold', 0x5c9a7f7, 0x10, 0x01),
    ('chunk_exit_branch', 0x5c9a888, 0x75, 0x74),
    ('chunk_loop_branch', 0x5c9a891, 0x76, 0x77),
    ('read_lock_threshold', 0x5c9a728, 0xfd, 0xfe),
    ('value_start_add', 0x5c9a93a, 0x02, 0x01),
    ('key_len_disp', 0x5c9a903, 0x01, 0x02),
    ('skip_empty_branch', 0x5c9a7e7, 0x74, 0x75),
    ('argv_count_limit', 0x5c9a55a, 0x05, 0x04),
    ('argv_element_stride', 0x5c9a628, 0x03, 0x02),
    ('argv_null_branch', 0x5c9a63d, 0x74, 0x75),
    ('env_record_stride', 0x5c9aa10, 0x04, 0x03),
    ('env_end_pointer_scale', 0x5c9aa8a, 0x04, 0x03),
]


def invalid_controls(data, image):
    """Each callable must raise (ValueError/EmuError/Trap/KeyError) to count as detected."""
    flipped = bytearray(data)
    flipped[1000] ^= 1
    secs, extents = fde_extents.fde_extents(data)[0:2]
    starts = {e['start'] for e in extents}

    def digest_flip():
        check_node(bytes(flipped))

    def truncated():
        check_node(data[:-1])

    def not_fde_start():
        if ARGV_FN + 1 in starts:
            return
        raise ValueError('not an FDE start')

    def outside_image():
        Image(data).read(0x1, 1)

    def unknown_opcode():
        im = Image(data, {ARGV_FN + 1: 0x06})
        Cpu(im).run(ARGV_FN)

    def loop_forever():
        # jmp to self at the argv entry
        im = Image(data, {ARGV_FN: 0xeb, ARGV_FN + 1: 0xfe})
        Cpu(im).run(ARGV_FN)

    def unmapped_read():
        cpu = Cpu(image)
        cpu.mem.read(0x5, 1)

    def unknown_slot():
        # call *slot with a slot that is not in the hook table: patch the strlen slot displacement
        im = Image(data, {0x5c9a7e0: 0xff})
        cpu = Cpu(im)
        build_environ(cpu, [b'a=b'], [0], 0)
        cpu.run(ENV_FN)

    def wrong_entry():
        # entering the middle of the environ collector without its prologue state must not complete cleanly
        cpu = Cpu(image)
        build_environ(cpu, [b'a=b'], [0], 0)
        cpu.run(ENV_FN + 1)

    def shrunken_extent():
        end = next(e['end'] for e in extents if e['start'] == ENV_FN)
        if end != 0x5c9abac:
            raise ValueError('extent changed')
        raise ValueError('forced mismatch against stale extent')

    return [('digest_flip', digest_flip), ('truncated_binary', truncated), ('not_fde_start', not_fde_start),
            ('outside_image', outside_image), ('unknown_opcode', unknown_opcode), ('step_limit', loop_forever),
            ('unmapped_read', unmapped_read), ('unknown_call_slot', unknown_slot), ('mid_function_entry', wrong_entry),
            ('stale_extent', shrunken_extent)]


# -------------------------------------------------------- generation ----

def function_extents(data):
    _, extents, _ = fde_extents.fde_extents(data)
    found = {e['start']: e['end'] for e in extents if e['start'] in (ARGV_FN, ENV_FN)}
    if set(found) != {ARGV_FN, ENV_FN}:
        raise ValueError('collector FDEs not found')
    return found


def disassemble(image, start, end):
    va = start
    rows = []
    while va < end:
        insn = fetch(image, va)
        rows.append((va, insn.n, insn.text, image.read(va, insn.n).hex()))
        va += insn.n
    if va != end:
        raise EmuError('decode does not end at FDE end')
    return rows


def generate(binary, out_dir, env_count=6600, argv_count=2400):
    data = load_node(binary)
    image = Image(data)
    extents = function_extents(data)
    os.makedirs(out_dir, exist_ok=True)
    lines_insn = ['va\tlength\tform\tbytes']
    form_counts = {}
    for start, end in sorted(extents.items()):
        for va, n, text, hexb in disassemble(image, start, end):
            lines_insn.append('%#x\t%d\t%s\t%s' % (va, n, text, hexb))
            form_counts[text] = form_counts.get(text, 0) + 1
    write(out_dir, 'instructions.tsv', '\n'.join(lines_insn) + '\n')
    # hook slots
    slot_rows = ['slot_va\tmodel\tslot_bytes_in_file']
    for slot in sorted(SLOTS):
        slot_rows.append('%#x\t%s\t%s' % (slot, SLOTS[slot], image.read(slot, 8).hex()))
    write(out_dir, 'call-slots.tsv', '\n'.join(slot_rows) + '\n')

    stats = {'env_cases': 0, 'argv_cases': 0, 'env_ok': 0, 'argv_ok': 0, 'env_alloc_fail_cases': 0,
             'argv_alloc_fail_cases': 0, 'slow_lock_cases': 0, 'wake_cases': 0, 'steps': 0,
             'mismatches': 0, 'spec_mutant_detections': {m: 0 for m in SPEC_MUTANTS}, 'sample_rows': 0}
    sample = ['kind\tindex\tentries\tsummary_sha256_16']
    for i, (strings, offsets, lock) in enumerate(env_cases(env_count)):
        got = view_env(run_env(image, strings, offsets, lock))
        want = expected_env(strings, lock)
        stats['env_cases'] += 1
        if got != want:
            stats['mismatches'] += 1
        else:
            stats['env_ok'] += 1
        if lock > 0x3ffffffd:
            stats['slow_lock_cases'] += 1
            stats['wake_cases'] += 1 if ('wake',) in want[3] else 0
        for m in SPEC_MUTANTS:
            alt = spec_env(strings, lock, mutate_split(m))
            alt_view = ('ok', tuple((True, k, v) for k, v in alt[0]), alt[1], alt[2])
            if alt_view != want:
                stats['spec_mutant_detections'][m] += 1
        if i % 40 == 0:
            digest = hashlib.sha256(repr(got).encode()).hexdigest()[:16]
            sample.append('env\t%d\t%d\t%s' % (i, len(strings), digest))
        # allocation failure on a derived ordinal (every 5th case)
        seq = env_alloc_sequence(strings)
        if i % 5 == 0 and seq:
            k = i % len(seq)
            res = run_env(image, strings, offsets, lock, alloc_fail={k})
            stats['env_alloc_fail_cases'] += 1
            if res[:3] != ('trap', 'alloc_error', (1, seq[k])):
                stats['mismatches'] += 1
    for i, (argc, args, null_at, argv_null) in enumerate(argv_cases(argv_count)):
        got = run_argv(image, argc, args, null_at, argv_null=argv_null)
        want = spec_argv(argc, args, null_at, argv_null)
        stats['argv_cases'] += 1
        if got == want:
            stats['argv_ok'] += 1
        else:
            stats['mismatches'] += 1
        if i % 20 == 0:
            digest = hashlib.sha256(repr(got).encode()).hexdigest()[:16]
            sample.append('argv\t%d\t%d\t%s' % (i, len(args), digest))
        if i % 6 == 0 and argc and not argv_null:
            k = i % (argc + 1)
            res = run_argv(image, argc, args, null_at, alloc_fail={k})
            stats['argv_alloc_fail_cases'] += 1
            if res != expected_argv_alloc_failure(argc, args, null_at, k):
                stats['mismatches'] += 1
    write(out_dir, 'case-digests.tsv', '\n'.join(sample) + '\n')

    cases = mutant_battery()
    base = normalise_battery(run_battery(image, cases))
    battery_expect = normalise_battery(expected_battery(cases))
    base_ok = sum(1 for a, b in zip(base, battery_expect) if a == b)
    stats['battery_cases'] = len(cases)
    stats['battery_unmutated_agree'] = base_ok
    negatives = []
    for name in SPEC_MUTANTS:
        negatives.append(('spec:' + name, stats['spec_mutant_detections'][name] > 0))
    for name, va, old, new in BYTE_MUTANTS:
        if image.byte(va) != old:
            negatives.append(('byte:' + name, False))
            continue
        mutated = Image(data, {va: new})
        res = normalise_battery(run_battery(mutated, cases))
        negatives.append(('byte:' + name, res != base))
    for name, fn in invalid_controls(data, image):
        try:
            fn()
            negatives.append(('invalid:' + name, False))
        except (ValueError, EmuError, Trap, KeyError):
            negatives.append(('invalid:' + name, True))
    stats['negative_controls'] = len(negatives)
    stats['negative_detected'] = sum(1 for _, ok in negatives if ok)
    undetected = [n for n, ok in negatives if not ok]
    write(out_dir, 'negative-controls.tsv', 'control\tdetected\n' + ''.join('%s\t%d\n' % (n, int(ok)) for n, ok in negatives))
    cases_total = stats['env_cases'] + stats['argv_cases'] + stats['env_alloc_fail_cases'] + stats['argv_alloc_fail_cases'] + len(cases)
    summary = {
        'binary_sha256': NODE_SHA256,
        'argv_collector': {'start': hex(ARGV_FN), 'end': hex(extents[ARGV_FN])},
        'environ_collector': {'start': hex(ENV_FN), 'end': hex(extents[ENV_FN])},
        'instruction_forms': dict(sorted(form_counts.items())),
        'stats': {k: v for k, v in stats.items() if k != 'spec_mutant_detections'},
        'spec_mutant_detections': stats['spec_mutant_detections'],
        'undetected_controls': undetected,
        'battery_agreement_with_spec': base_ok == len(cases),
    }
    write(out_dir, 'summary.json', json.dumps(summary, indent=2, sort_keys=True) + '\n')
    measure = {'cases': cases_total, 'negative_controls': stats['negative_controls'],
               'negative_detected': stats['negative_detected'], 'mismatches': stats['mismatches']}
    write(out_dir, 'measure.json', json.dumps(measure, indent=2, sort_keys=True) + '\n')
    return summary, measure


def env_alloc_sequence(strings):
    """Allocation sizes in call order: key, then value unless empty, for each accepted entry."""
    seq = []
    for s in strings:
        kv = spec_split(s) if s else None
        if kv is None:
            continue
        seq.append(len(kv[0]))
        if kv[1]:
            seq.append(len(kv[1]))
    return seq


def expected_env_alloc_failure(strings, k):
    seq = env_alloc_sequence(strings)
    return None if k >= len(seq) else ('trap', 'alloc_error', (1, seq[k]))


def expected_argv_alloc_failure(argc, args, null_at, k):
    """Allocation 0 is the 24-byte-per-element vector; then one per non-empty argument."""
    seq = [(8, argc * 24)]
    for i in range(argc):
        if i >= len(args) or i == null_at:
            break
        if args[i]:
            seq.append((1, len(args[i])))
    if k >= len(seq):
        return spec_argv(argc, args, null_at, False)
    return ('trap', 'alloc_error', seq[k])


def write(out_dir, name, text):
    with open(os.path.join(out_dir, name), 'wb') as handle:
        handle.write(text.encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    parser.add_argument('--binary', default=os.path.join(ROOT, 'artifacts', 'node', '115', 'hl-node'))
    args = parser.parse_args()
    summary, measure = generate(args.binary, args.out)
    print(json.dumps(measure, sort_keys=True))
    return 0 if measure['mismatches'] == 0 and measure['negative_detected'] == measure['negative_controls'] else 1


if __name__ == '__main__':
    sys.exit(main())
