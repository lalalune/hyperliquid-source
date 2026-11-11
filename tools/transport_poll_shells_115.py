#!/usr/bin/env python3
"""Static, digest-bound model of two node #115 transport poll shells.

New independently authored tooling.  It never runs the target: the function
bytes are decoded and interpreted by a small x86-64 subset interpreter, and the
result is compared with a plain Python reconstruction on generated inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
WRITE_ALL = 0x5ab3a50          # tcp_stream.rs write-all poll shell
WRITE_ALL_LEN = 320
GATE = 0x5ab6ce0               # tcp write.rs compression-gate poll shell
GATE_LEN = 272
FUNCTIONS = {WRITE_ALL: WRITE_ALL_LEN, GATE: GATE_LEN}
M64 = (1 << 64) - 1
STACK_TOP = 0x70000000
SENTINEL = 0x7ffff000

CALLEE_WRITE = 0x5cdfa50       # cursor writer called by WRITE_ALL
CALLEE_ERR = 0x4ece740         # io::Error conversion called by WRITE_ALL
CALLEE_GATE = 0x5ab5be0        # inner poll called by GATE
CALLEE_DROP = 0x5a59590        # inner drop called by GATE
UNWIND_RESUME = 0x63f0a50
SLOT_CONST_ERR = 0x64e0750     # GOT slot: io::Error constructor (kind, msg, len)
SLOT_PANICS = (0x64df848, 0x64e1360, 0x64e1368, 0x64df4c0)

CF, ZF = 1, 2


class Fault(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ValueError(message)


def authenticate(data):
    require(len(data) == SIZE, 'target size')
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'target digest')


class Image:
    """File-backed view of the binary; NOBITS sections are excluded."""

    def __init__(self, data):
        self.data = data
        self.secs = [s for s in elf_index.sections(data)
                     if s['type'] != 8 and s['address'] and s['size']]
        self.patch = {}

    def offset(self, va, size=1):
        for s in self.secs:
            if s['address'] <= va and va + size <= s['address'] + s['size']:
                return s['offset'] + va - s['address']
        raise ValueError('VA is not file backed: %#x' % va)

    def read(self, va, size):
        o = self.offset(va, size)
        raw = bytearray(self.data[o:o + size])
        for i in range(size):
            if va + i in self.patch:
                raw[i] = self.patch[va + i]
        return bytes(raw)


def function_extents(data):
    """Return {start: end} for the FDEs named in FUNCTIONS, from .eh_frame."""
    result = fde_extents.fde_extents(data)
    fdes = result[1] if isinstance(result, tuple) else result
    if isinstance(fdes, dict):
        fdes = fdes.get('fdes', fdes.get('records', []))
    out = {}
    for f in fdes:
        if f['start'] in FUNCTIONS:
            out[f['start']] = f['end']
    return out


# ---------------------------------------------------------------- decoding

def sx(value, bits):
    return value - (1 << bits) if value >> (bits - 1) else value


class Insn:
    __slots__ = ('va', 'raw', 'length', 'op', 'a', 'b', 'c', 'size', 'text')

    def __init__(self, va, raw, op, size=8, a=None, b=None, c=None):
        self.va, self.raw, self.length = va, raw, len(raw)
        self.op, self.size, self.a, self.b, self.c = op, size, a, b, c


def decode(code, va):
    """Decode one instruction of the subset that the two functions use."""
    p = 0
    pfx66 = pf2 = lock = False
    while code[p] in (0x66, 0xf2, 0xf3, 0xf0):
        pfx66 |= code[p] == 0x66
        pf2 |= code[p] == 0xf2
        lock |= code[p] == 0xf0
        p += 1
    rex = 0
    if 0x40 <= code[p] <= 0x4f:
        rex = code[p]
        p += 1
    w, r, x, b = (rex >> 3) & 1, (rex >> 2) & 1, (rex >> 1) & 1, rex & 1
    op = code[p]
    p += 1
    osz = 8 if w else (2 if pfx66 else 4)

    def modrm():
        nonlocal p
        m = code[p]
        p += 1
        mod, reg, rm = m >> 6, ((m >> 3) & 7) | (r << 3), m & 7
        if mod == 3:
            return ('r', rm | (b << 3)), reg
        base = index = None
        scale = 1
        disp = 0
        if rm == 4:
            sib = code[p]
            p += 1
            scale = 1 << (sib >> 6)
            idx = ((sib >> 3) & 7) | (x << 3)
            index = None if idx == 4 else idx
            sb = sib & 7
            if sb == 5 and mod == 0:
                raise ValueError('absolute SIB base is outside the subset')
            base = sb | (b << 3)
        elif rm == 5 and mod == 0:
            disp = sx(struct.unpack_from('<I', code, p)[0], 32)
            p += 4
            return ('m', 'rip', None, 1, disp), reg
        else:
            base = rm | (b << 3)
        if mod == 1:
            disp = sx(code[p], 8)
            p += 1
        elif mod == 2:
            disp = sx(struct.unpack_from('<I', code, p)[0], 32)
            p += 4
        return ('m', base, index, scale, disp), reg

    def imm(n):
        nonlocal p
        v = int.from_bytes(code[p:p + n], 'little')
        p += n
        return v

    def done(*args, **kw):
        return Insn(va, bytes(code[:p]), *args, **kw)

    if 0x50 <= op <= 0x57:
        return done('push', 8, ('r', (op - 0x50) | (b << 3)))
    if 0x58 <= op <= 0x5f:
        return done('pop', 8, ('r', (op - 0x58) | (b << 3)))
    if op in (0x01, 0x03, 0x29, 0x31, 0x39, 0x85, 0x89, 0x8b, 0x20, 0x88, 0x63, 0x8d):
        rm, reg = modrm()
        names = {0x01: 'add', 0x03: 'add', 0x29: 'sub', 0x31: 'xor', 0x39: 'cmp',
                 0x85: 'test', 0x89: 'mov', 0x8b: 'mov', 0x20: 'and', 0x88: 'mov',
                 0x63: 'movslq', 0x8d: 'lea'}
        size = 1 if op in (0x20, 0x88) else osz
        if op in (0x03, 0x8b, 0x63, 0x8d):
            dst, src = ('r', reg), rm
        else:
            dst, src = rm, ('r', reg)
        if op == 0x63:
            size = 8
        if op == 0x8d:
            size = 8
        return done(names[op], size, dst, src, lock)
    if op in (0xc6, 0xc7):
        rm, reg = modrm()
        require(reg & 7 == 0, 'C6/C7 extension')
        size = 1 if op == 0xc6 else osz
        v = imm(1 if op == 0xc6 else (2 if size == 2 else 4))
        if size == 8:
            v = sx(v, 32) & M64
        return done('mov', size, rm, ('i', v))
    if op == 0xf6:
        rm, reg = modrm()
        require(reg & 7 == 0, 'F6 extension')
        return done('test', 1, rm, ('i', imm(1)))
    if op == 0x83:
        rm, reg = modrm()
        v = sx(imm(1), 8) & ((1 << (8 * osz)) - 1)
        name = {0: 'add', 7: 'cmp'}[reg & 7]
        return done(name, osz, rm, ('i', v), lock)
    if op == 0x3d:
        v = imm(4)
        return done('cmp', osz, ('r', 0), ('i', sx(v, 32) & ((1 << (8 * osz)) - 1)))
    if op == 0xa8:
        return done('test', 1, ('r', 0), ('i', imm(1)))
    if 0xb8 <= op <= 0xbf:
        return done('mov', 4, ('r', (op - 0xb8) | (b << 3)), ('i', imm(4)))
    if op == 0xe8:
        d = sx(imm(4), 32)
        return done('call', 8, ('i', (va + p + d) & M64))
    if op == 0xeb:
        d = sx(imm(1), 8)
        return done('jmp', 8, ('i', (va + p + d) & M64))
    if op in (0x72, 0x74, 0x75):
        d = sx(imm(1), 8)
        return done({0x72: 'jb', 0x74: 'je', 0x75: 'jne'}[op], 8, ('i', (va + p + d) & M64))
    if op == 0xc3:
        return done('ret')
    if op == 0xcc:
        return done('int3')
    if op == 0xff:
        rm, reg = modrm()
        if reg & 7 == 2:
            return done('callm', 8, rm)
        if reg & 7 == 4:
            return done('jmpm', 8, rm)
        raise ValueError('FF extension')
    if op == 0x0f:
        op2 = code[p]
        p += 1
        if op2 == 0x0b:
            return done('ud2')
        if op2 == 0x1f:
            modrm()
            return done('nop')
        if op2 == 0xb6:
            rm, reg = modrm()
            return done('movzx8', 4, ('r', reg), rm)
        if op2 in (0x92, 0x93):
            rm, reg = modrm()
            return done('setb' if op2 == 0x92 else 'setae', 1, rm)
        if op2 in (0x10, 0x11):
            rm, reg = modrm()
            width = 8 if pf2 else 16
            if op2 == 0x10:
                return done('xload', width, ('x', reg), rm)
            return done('xstore', width, rm, ('x', reg))
    raise ValueError('instruction outside the subset at %#x' % va)


# ------------------------------------------------------------- interpreter

class Machine:
    """Byte-addressed sparse memory plus the registers the subset touches."""

    def __init__(self, image, hooks, mem):
        self.image, self.hooks, self.mem = image, hooks, mem
        self.reg = [0] * 16
        self.xmm = [0, 0]
        self.flags = 0
        self.log = []
        self.cache = {}
        self.counts = None

    # memory ----------------------------------------------------------
    def load(self, addr, size):
        addr &= M64
        if STACK_TOP - 0x1000 <= addr < STACK_TOP + 0x10:
            out = 0
            for i in range(size):
                out |= self.mem.get(addr + i, 0) << (8 * i)
            return out
        out = 0
        for i in range(size):
            if addr + i in self.mem:
                out |= self.mem[addr + i] << (8 * i)
                continue
            try:
                out |= self.image.read(addr + i, 1)[0] << (8 * i)
            except ValueError:
                raise Fault('unmapped read %#x' % (addr + i))
        return out

    def store(self, addr, size, value):
        addr &= M64
        stack = STACK_TOP - 0x1000 <= addr < STACK_TOP + 0x10
        for i in range(size):
            if not stack and addr + i not in self.mem:
                raise Fault('unmapped write %#x' % (addr + i))
            self.mem[addr + i] = (value >> (8 * i)) & 0xff

    def ea(self, op, nxt):
        _, base, index, scale, disp = op
        if base == 'rip':
            return (nxt + disp) & M64
        a = self.reg[base] + disp
        if index is not None:
            a += self.reg[index] * scale
        return a & M64

    def get(self, op, size, nxt):
        kind = op[0]
        if kind == 'i':
            return op[1] & ((1 << (8 * size)) - 1)
        if kind == 'r':
            return self.reg[op[1]] & ((1 << (8 * size)) - 1)
        if kind == 'm':
            return self.load(self.ea(op, nxt), size)
        raise Fault('operand')

    def put(self, op, size, value, nxt):
        value &= (1 << (8 * size)) - 1
        if op[0] == 'r':
            i = op[1]
            if size >= 4:
                self.reg[i] = value
            else:
                mask = (1 << (8 * size)) - 1
                self.reg[i] = (self.reg[i] & ~mask & M64) | value
        elif op[0] == 'm':
            self.store(self.ea(op, nxt), size, value)
        else:
            raise Fault('operand')

    def fetch(self, va):
        ins = self.cache.get(va)
        if ins is None:
            ins = decode(self.image.read(va, 16), va)
            self.cache[va] = ins
        return ins

    def setflags(self, result, size, carry):
        bits = 8 * size
        mask = (1 << bits) - 1
        self.flags = (CF if carry else 0) | (ZF if result & mask == 0 else 0)

    # execution -------------------------------------------------------
    def push(self, v):
        self.reg[4] = (self.reg[4] - 8) & M64
        self.store(self.reg[4], 8, v)

    def pop(self):
        v = self.load(self.reg[4], 8)
        self.reg[4] = (self.reg[4] + 8) & M64
        return v

    def call(self, target):
        hook = self.hooks.get(target)
        if hook is None:
            raise Fault('call to unmodelled target %#x' % target)
        self.log.append((hook.__name__, self.reg[7], self.reg[6], self.reg[2], self.reg[1]))
        out = hook(self)
        if out == 'noreturn':
            raise Fault('noreturn:%s' % hook.__name__)
        if out is not None:
            self.reg[0], self.reg[2] = out[0] & M64, out[1] & M64

    def run(self, entry, limit=4000):
        va = entry
        for _ in range(limit):
            ins = self.fetch(va)
            nxt = va + ins.length
            op = ins.op
            if self.counts is not None:
                self.counts[va] = self.counts.get(va, 0) + 1
            if op == 'push':
                self.push(self.reg[ins.a[1]])
            elif op == 'pop':
                self.reg[ins.a[1]] = self.pop()
            elif op in ('mov', 'movzx8', 'movslq'):
                size = ins.size
                if op == 'movzx8':
                    self.put(ins.a, 4, self.get(ins.b, 1, nxt), nxt)
                elif op == 'movslq':
                    self.put(ins.a, 8, sx(self.get(ins.b, 4, nxt), 32) & M64, nxt)
                else:
                    self.put(ins.a, size, self.get(ins.b, size, nxt), nxt)
            elif op == 'lea':
                self.put(ins.a, 8, self.ea(ins.b, nxt), nxt)
            elif op in ('add', 'sub', 'cmp', 'xor', 'and', 'test'):
                s = ins.size
                mask = (1 << (8 * s)) - 1
                x = self.get(ins.a, s, nxt)
                y = self.get(ins.b, s, nxt)
                if op == 'add':
                    r = x + y
                    carry = r > mask
                elif op in ('sub', 'cmp'):
                    r = x - y
                    carry = x < y
                elif op == 'xor':
                    r, carry = x ^ y, False
                else:
                    r, carry = x & y, False
                self.setflags(r, s, carry)
                if op not in ('cmp', 'test'):
                    self.put(ins.a, s, r, nxt)
            elif op == 'setb':
                self.put(ins.a, 1, 1 if self.flags & CF else 0, nxt)
            elif op == 'setae':
                self.put(ins.a, 1, 0 if self.flags & CF else 1, nxt)
            elif op == 'xload':
                width = ins.size
                if ins.b[0] == 'm':
                    v = self.load(self.ea(ins.b, nxt), width)
                else:
                    raise Fault('xmm register move')
                self.xmm[ins.a[1]] = v
            elif op == 'xstore':
                self.store(self.ea(ins.a, nxt), ins.size, self.xmm[ins.b[1]] & ((1 << (8 * ins.size)) - 1))
            elif op == 'jmp':
                nxt = ins.a[1]
            elif op in ('jb', 'je', 'jne'):
                take = {'jb': bool(self.flags & CF), 'je': bool(self.flags & ZF),
                        'jne': not self.flags & ZF}[op]
                if take:
                    nxt = ins.a[1]
            elif op == 'jmpm':
                nxt = self.get(ins.a, 8, nxt)
            elif op == 'call':
                self.push(nxt)
                self.call(ins.a[1])
                self.pop()
            elif op == 'callm':
                slot = self.ea(ins.a, nxt)
                self.push(nxt)
                self.call(slot)
                self.pop()
            elif op == 'ret':
                ret = self.pop()
                if ret != SENTINEL:
                    raise Fault('return to unexpected address')
                return 'ret'
            elif op in ('ud2', 'int3'):
                raise Fault('trap:%s' % op)
            elif op == 'nop':
                pass
            else:
                raise Fault('unhandled op %s' % op)
            va = nxt
        raise Fault('step limit')


def mix(*values):
    h = 0xcbf29ce484222325
    for v in values:
        h = ((h ^ (v & M64)) * 0x100000001b3) & M64
    return h


# --------------------------------------------------------------------------
# Case-supplied models of the callees.  They are shared by the interpreter run
# and by the reconstruction, so the comparison isolates the shell logic.

class Script:
    """Deterministic callee behaviour for one case."""

    def __init__(self, steps, inner):
        self.steps = list(steps)
        self.inner = inner
        self.i = 0

    def next_step(self):
        if self.i >= len(self.steps):
            return (0, 0, 0)
        self.i += 1
        return self.steps[self.i - 1]


def cursor_write(mem_get, mem_put, script, stream, cursor):
    """Model of 0x5cdfa50: returns (pending_flag, error); may advance pos."""
    pending, err, adv = script.next_step()
    if not pending and not err:
        pos = mem_get(cursor + 0x10, 8)
        mem_put(cursor + 0x10, 8, (pos + adv) & M64)
    return (1 if pending else 0) | (mix(stream, cursor) & 0xfe00), err


def const_error(kind, msg, length):
    return mix(0xe1, kind, msg, length)


def convert_error(err):
    return mix(0xc0, err)


def make_hooks(script):
    def h_cursor(m):
        flag, err = cursor_write(lambda a, s: m.load(a, s), lambda a, s, v: m.store(a, s, v),
                                 script, m.reg[7], m.reg[2])
        return flag, err

    def h_convert(m):
        return convert_error(m.reg[7]), m.reg[2]

    def h_inner(m):
        return script.inner

    def h_drop(m):
        return (m.reg[0], m.reg[2])

    def h_resume(m):
        raise Fault('resume')

    def h_const(m):
        return const_error(m.reg[7], m.reg[6], m.reg[2]), m.reg[2]

    hooks = {CALLEE_WRITE: h_cursor, CALLEE_ERR: h_convert, CALLEE_GATE: h_inner,
             CALLEE_DROP: h_drop, UNWIND_RESUME: h_resume}
    h_cursor.__name__ = 'cursor_write'
    h_convert.__name__ = 'convert_error'
    h_inner.__name__ = 'inner_poll'
    h_drop.__name__ = 'inner_drop'
    h_resume.__name__ = 'unwind_resume'
    h_const.__name__ = 'const_error'
    hooks[SLOT_CONST_ERR] = h_const
    for slot in SLOT_PANICS:
        def make(slot):
            def h(m):
                return 'noreturn'
            h.__name__ = 'panic_%x' % slot
            return h
        hooks[slot] = make(slot)
    return hooks


# --------------------------------------------------------- reconstruction

LOC_SLICE = 0x64bad88
LOC_STATE = 0x64bb068
LOC_GATE_STATE = 0x64bb1b8
MSG_ZERO = 0x94d48e
HOOK_ARGS = {'cursor_write': (7, 6, 2), 'convert_error': (7,), 'inner_poll': (7,),
             'inner_drop': (7,), 'unwind_resume': (7,), 'const_error': (7, 6, 2)}
PANIC_ARGS = (7,)


class Mem:
    """Mapped-byte memory used by the reconstruction (same fault rules)."""

    def __init__(self, mem):
        self.mem = mem

    def load(self, addr, size):
        out = 0
        for i in range(size):
            if addr + i not in self.mem:
                raise Fault('unmapped read %#x' % (addr + i))
            out |= self.mem[addr + i] << (8 * i)
        return out

    def store(self, addr, size, value):
        for i in range(size):
            if addr + i not in self.mem:
                raise Fault('unmapped write %#x' % (addr + i))
            self.mem[addr + i] = (value >> (8 * i)) & 0xff


def panic(log, slot, loc):
    log.append(('panic_%x' % slot, loc))
    raise Fault('noreturn:panic_%x' % slot)


def write_all_poll(mem, base, cx, script, log, mutation=None):
    """Reconstruction of 0x5ab3a50: poll a write-all future over a cursor."""
    state = mem.load(base + 0x40, 1)
    if state == 0:
        owner = mem.load(base, 8)
        counter_at = mem.load(owner + 0x60, 8) + 0x10
        n = mem.load(base + 0x10, 8)
        if mutation != 'no-counter':
            mem.store(counter_at, 8, (mem.load(counter_at, 8) + n) & M64)
        mem.store(base + 0x18, 8, mem.load(base, 8))
        if mutation != 'no-buf-copy':
            mem.store(base + 0x20, 8, mem.load(base + 8, 8))
        mem.store(base + 0x28, 8, n)
        mem.store(base + 0x30, 8, 1 if mutation == 'pos-init' else 0)
        if mutation != 'len-skip':
            mem.store(base + 0x38, 8, n)
        length, pos = n, (1 if mutation == 'pos-init' else 0)
    elif state == 3:
        length, pos = mem.load(base + 0x28, 8), mem.load(base + 0x30, 8)
    elif state == 1:
        panic(log, 0x64e1368, LOC_STATE)
    elif state == 2:
        panic(log, 0x64e1360, LOC_STATE)
    else:
        raise Fault('state outside jump table')
    while True:
        if length < pos:
            panic(log, 0x64df848, LOC_SLICE)
        remaining = (length - pos) & M64
        if remaining == 0:
            mem.store(base + 0x40, 1, 1)
            return 0, (0 if mutation == 'ready-rdx' else pos)
        stream = mem.load(base + 0x18, 8)
        log.append(('cursor_write', stream, cx, base + 0x20))
        flag, err = cursor_write(mem.load, mem.store, script, stream, base + 0x20)
        if flag & 1:
            mem.store(base + 0x40, 1, 1 if mutation == 'pending-state' else 3)
            return 2, err
        if err == 0:
            length, pos = mem.load(base + 0x28, 8), mem.load(base + 0x30, 8)
            if length < pos:
                panic(log, 0x64df848, LOC_SLICE)
            if ((length - pos) & M64 < remaining) if mutation == 'progress-eq' else ((length - pos) & M64 != remaining):
                continue
            kind = 0x24 if mutation == 'kind' else 0x25
            msg = MSG_ZERO + 1 if mutation == 'msg' else MSG_ZERO
            log.append(('const_error', kind, msg, 9))
            err = const_error(kind, msg, 9)
        log.append(('convert_error', err))
        mem.store(base + 0x40, 1, 1)
        return 1, convert_error(err)


def gate_poll(mem, base, script, log, mutation=None):
    """Reconstruction of 0x5ab6ce0: size/option gate, then poll the inner body."""
    state = mem.load(base + 0x310, 1)
    if state == 0:
        n = mem.load(base + 0x20, 8)
        ctx = mem.load(base + 0x10, 8)
        field = mem.load(ctx + (0x94 if mutation == 'ctx-wrong' else 0x90), 4)
        threshold = 0x400 if mutation == 'threshold' else 0x401
        bound = 0xffff if mutation == 'bound' else 0xfffe
        shifted = (field + 0xfffff060) & (0xffffffff if mutation == 'width' else 0xffff)
        flag = int(n >= threshold and shifted < bound)
        if mutation == 'swap-conjunct':
            flag = int(n >= threshold or shifted < bound)
        mem.store(base + 0x28, 8, mem.load(base, 8))
        mem.store(base + 0x30, 8, mem.load(base + 8, 8))
        mem.store(base + 0x38, 16, mem.load(base + 0x10, 16))
        mem.store(base + 0x48, 8, n + 1 & M64 if mutation == 'n-store' else n)
        mem.store(base + 0x308, 1, flag)
        if mutation != 'no-flag-clear':
            mem.store(base + 0x309, 1, 0)
    elif state == 1:
        panic(log, 0x64e1368, LOC_GATE_STATE)
    elif state == 2:
        panic(log, 0x64e1360, LOC_GATE_STATE)
    elif state != 3:
        raise Fault('state outside jump table')
    log.append(('inner_poll', base + 0x28))
    rax, rdx = script.inner
    if rax & 1:
        mem.store(base + 0x310, 1, 3)
        return (0 if mutation == 'pending-ret' else 1), rdx
    if mutation != 'no-drop':
        log.append(('inner_drop', base + 0x28))
    mem.store(base + 0x310, 1, 1)
    return rax, rdx


# ------------------------------------------------------------------- cases

class Rng:
    def __init__(self, seed):
        self.s = seed & M64 or 1

    def next(self):
        x = self.s
        x ^= (x << 13) & M64
        x ^= x >> 7
        x ^= (x << 17) & M64
        self.s = x
        return x

    def below(self, n):
        return self.next() % n

    def pick(self, seq):
        return seq[self.below(len(seq))]


BASE = 0x10000000
OWNER = 0x20000000
COUNTER = 0x30000000
CTX = 0x40000000
EDGE = (0, 1, 2, 7, 8, 0x400, 0x401, 0x402, 0xffff, 0x10000, 0xffffffff, 1 << 32,
        (1 << 63) - 1, 1 << 63, M64 - 1, M64)
EDGE_FIELDS = (0, 3998, 3999, 4000, 3997, 0xffff, 0x10000 + 3998, 0x10000 + 3999,
               0x7fffffff, 0xffffffff, 0xf060, 0x10f5e, 0x10f5f, 0x1f5e)


def put_bytes(mem, addr, size, value):
    for i in range(size):
        mem[addr + i] = (value >> (8 * i)) & 0xff


def write_case(r):
    state = r.pick((0, 0, 3, 3, 3, 1, 2))
    n = r.pick(EDGE) if r.below(3) == 0 else r.below(1 << r.pick((3, 8, 16, 32, 63)))
    pos = 0
    if state == 3:
        pos = r.pick((0, n, (n + 1) & M64, r.below(n + 1), r.below(8)))
    steps = []
    for _ in range(r.pick((1, 2, 3, 4))):
        kind = r.below(6)
        adv = r.below(min(n, 1 << 20) + 2) if r.below(2) else r.pick((0, 1, 2))
        if r.below(6) == 0:
            adv = r.pick((M64, M64 - 1, M64 - 3))
        if kind == 0:
            steps.append((1, 0, 0))
        elif kind == 1:
            steps.append((0, r.next() | 1, adv))
        elif kind == 2:
            steps.append((0, 0, 0))
        else:
            steps.append((0, 0, adv if r.below(8) else r.next()))
    mem = {}
    put_bytes(mem, BASE, 0x48, 0)
    put_bytes(mem, BASE, 8, OWNER)
    for off in (8, 0x18, 0x20, 0x38):
        put_bytes(mem, BASE + off, 8, r.next())
    put_bytes(mem, BASE + 0x10, 8, r.next() if state == 3 else n)
    put_bytes(mem, BASE + 0x28, 8, n if state == 3 else r.next())
    put_bytes(mem, BASE + 0x30, 8, pos if state == 3 else r.next())
    put_bytes(mem, BASE + 0x40, 1, state)
    put_bytes(mem, OWNER + 0x60, 8, COUNTER)
    put_bytes(mem, COUNTER + 0x10, 8, r.pick((0, 5, M64, r.next())))
    return dict(fn=WRITE_ALL, mem=mem, cx=r.next(), steps=steps, inner=(0, 0), state=state)


def gate_case(r):
    state = r.pick((0, 0, 0, 3, 3, 1, 2))
    n = r.pick(EDGE) if r.below(2) == 0 else r.below(1 << r.pick((4, 10, 12, 20, 40)))
    field = r.pick(EDGE_FIELDS) if r.below(2) == 0 else r.below(1 << 32)
    inner = (r.pick((0, 1, 2, 3, r.next())), r.next())
    mem = {}
    put_bytes(mem, BASE, 0x318, 0)
    for off in range(0, 0x50, 8):
        put_bytes(mem, BASE + off, 8, r.next())
    put_bytes(mem, BASE + 0x10, 8, CTX)
    put_bytes(mem, BASE + 0x20, 8, n)
    put_bytes(mem, BASE + 0x310, 1, state)
    put_bytes(mem, BASE + 0x308, 2, r.next())
    put_bytes(mem, CTX, 0x98, 0)
    put_bytes(mem, CTX + 0x90, 4, field)
    return dict(fn=GATE, mem=mem, cx=0, steps=[(0, 0, 0)], inner=inner, state=state)


def hook_log(machine_log):
    out = []
    for name, rdi, rsi, rdx, _rcx in machine_log:
        regs = {7: rdi, 6: rsi, 2: rdx}
        out.append((name,) + tuple(regs[i] for i in HOOK_ARGS.get(name, PANIC_ARGS)))
    return out


def observe(kind, mem, rax, rdx, log, extra=''):
    return (kind, rax, rdx, tuple(sorted(mem.items())), tuple(log), extra)


def run_original(image, case, cache=None, counts=None):
    """Interpret the captured bytes on one case."""
    mem = dict(case['mem'])
    script = Script(case['steps'], case['inner'])
    m = Machine(image, make_hooks(script), mem)
    if cache is not None:
        m.cache = cache
    m.counts = counts
    m.reg[7], m.reg[6] = BASE, case['cx']
    for i in (1, 2, 8, 9, 10, 11, 13):
        m.reg[i] = 0x1111111100000000 + i
    m.reg[3], m.reg[12], m.reg[14], m.reg[15] = 0x33, 0x1212, 0x1414, 0x1515
    initial = list(m.reg)
    m.reg[4] = STACK_TOP
    m.push(SENTINEL)
    try:
        end = m.run(case['fn'])
    except Fault as f:
        end = str(f)
    except (ValueError, IndexError, KeyError, struct.error) as e:
        end = 'decode:%s' % type(e).__name__
    extra = ''
    if end == 'ret':
        saved = all(m.reg[i] == initial[i] for i in (3, 12, 14, 15))
        extra = '' if saved and m.reg[4] == STACK_TOP else 'abi'
    clean = {a: v for a, v in m.mem.items() if not STACK_TOP - 0x1000 <= a < STACK_TOP + 0x10}
    return observe(end, clean, m.reg[0] if end == 'ret' else 0, m.reg[2] if end == 'ret' else 0,
                   hook_log(m.log), extra)


def run_model(case, mutation=None):
    mem = Mem(dict(case['mem']))
    script = Script(case['steps'], case['inner'])
    log = []
    rax = rdx = 0
    try:
        if case['fn'] == WRITE_ALL:
            rax, rdx = write_all_poll(mem, BASE, case['cx'], script, log, mutation)
        else:
            rax, rdx = gate_poll(mem, BASE, script, log, mutation)
        end = 'ret'
    except Fault as f:
        end = str(f)
    return observe(end, mem.mem, rax & M64 if end == 'ret' else 0,
                   rdx & M64 if end == 'ret' else 0, log, '')


# ------------------------------------------------------- unwind landing pads

# (function, pad VA, drops the inner object first)
PADS = ((WRITE_ALL, 0x5ab3b5d, False), (WRITE_ALL, 0x5ab3b69, False), (WRITE_ALL, 0x5ab3b75, False),
        (GATE, 0x5ab6db9, False), (GATE, 0x5ab6dcb, True))
PAD_CASES = 300
STATE_AT = {WRITE_ALL: 0x40, GATE: 0x310}


def pad_case(function, pad, drop, r):
    mem = {}
    put_bytes(mem, BASE, 0x318, 0)
    put_bytes(mem, BASE + STATE_AT[function], 1, r.below(256))
    return dict(fn=function, pad=pad, drop=drop, mem=mem, exc=r.next(), state=0)


def run_pad_original(image, case, cache=None, counts=None):
    """Enter a landing pad with rax = exception object, rbx = base, r12 = inner."""
    mem = dict(case['mem'])
    m = Machine(image, make_hooks(Script([], (0, 0))), mem)
    if cache is not None:
        m.cache = cache
    m.counts = counts
    m.reg[3], m.reg[0], m.reg[12] = BASE, case['exc'], BASE + 0x28
    m.reg[4] = STACK_TOP
    try:
        end = m.run(case['pad'])
    except Fault as f:
        end = str(f)
    except (ValueError, IndexError, KeyError, struct.error) as e:
        end = 'decode:%s' % type(e).__name__
    clean = {a: v for a, v in m.mem.items() if not STACK_TOP - 0x1000 <= a < STACK_TOP + 0x10}
    return observe(end, clean, 0, 0, hook_log(m.log), '')


def run_pad_model(case, mutation=None):
    mem = Mem(dict(case['mem']))
    log = []
    if case['drop']:
        log.append(('inner_drop', BASE + 0x28))
    mem.store(BASE + STATE_AT[case['fn']], 1, 3 if mutation == 'pad-state' else 2)
    log.append(('unwind_resume', case['exc']))
    return observe('resume', mem.mem, 0, 0, log, '')


# ----------------------------------------------------------------- driver

CASES_PER_FUNCTION = 6000
CONTROL_CASES = 1500
SAMPLE_ROWS = 160
SEEDS = {WRITE_ALL: 0x5ab3a50, GATE: 0x5ab6ce0}
GENERATORS = {WRITE_ALL: write_case, GATE: gate_case}
WRITE_MUTATIONS = ('no-counter', 'pending-state', 'kind', 'msg', 'progress-eq', 'pos-init',
                   'ready-rdx', 'no-buf-copy', 'len-skip')
GATE_MUTATIONS = ('threshold', 'bound', 'width', 'swap-conjunct', 'pending-ret',
                  'no-flag-clear', 'no-drop', 'n-store', 'ctx-wrong')
# (name, function, absolute VA, replacement byte)
CORRUPTIONS = (
    ('jb-to-jae', WRITE_ALL, 0x5ab3ab6, 0x73),
    ('je-to-jne', WRITE_ALL, 0x5ab3ab8, 0x75),
    ('pending-test-bit', WRITE_ALL, 0x5ab3aca, 0x02),
    ('error-return-code', WRITE_ALL, 0x5ab3b0d, 0x02),
    ('pending-return-code', WRITE_ALL, 0x5ab3b24, 0x03),
    ('pending-state-byte', WRITE_ALL, 0x5ab3b22, 0x04),
    ('lock-add-to-sub', WRITE_ALL, 0x5ab3a82, 0x29),
    ('error-kind', WRITE_ALL, 0x5ab3af4, 0x26),
    ('error-length', WRITE_ALL, 0x5ab3aef, 0x08),
    ('threshold-imm', GATE, 0x5ab6d10, 0x02),
    ('bound-imm', GATE, 0x5ab6d30, 0xfd),
    ('setae-to-setb', GATE, 0x5ab6d15, 0x92),
    ('field-displacement', GATE, 0x5ab6d28, 0x94),
    ('done-state-byte', GATE, 0x5ab6d8c, 0x04),
    ('pending-state-byte', GATE, 0x5ab6d75, 0x04),
    ('flag-store-disp', GATE, 0x5ab6d4c, 0x09),
)
BAD_STATES = (4, 5, 127, 255)


def validate_case(case):
    """Reject inputs outside the proved domain (state byte beyond the jump table)."""
    if case['state'] not in (0, 1, 2, 3):
        raise ValueError('state byte outside the four-entry jump table')
    return case


def case_stream(function, count):
    rng = Rng(SEEDS[function])
    for index in range(count):
        yield index, GENERATORS[function](rng)


def first_difference(function, count, left, right):
    """Index of the first case where left(case) != right(case), else -1."""
    for index, case in case_stream(function, count):
        try:
            a = left(case)
        except (Fault, ValueError, IndexError, KeyError, struct.error):
            return index
        if a != right(case):
            return index
    return -1


def outcome_class(case, obs):
    end = obs[0]
    if end.startswith('noreturn:panic_'):
        end = end.split(':')[1]
    rax = obs[1]
    if end == 'ret':
        if case['fn'] == WRITE_ALL:
            return 'ret-%d' % rax if rax in (0, 1, 2) else 'ret-other'
        return 'ret-pending' if case['state'] != 9 and obs[3] and rax == 1 and \
            dict(obs[3]).get(BASE + 0x310) == 3 else 'ret-ready'
    return end


def disassemble(image, start, length):
    out, va = [], start
    while va < start + length:
        ins = decode(image.read(va, 16), va)
        out.append(ins)
        va += ins.length
    require(va == start + length, 'instruction boundary at function end')
    return out


def jump_table(image, table_va, first, last):
    """Targets of the signed-relative jump table that fall inside the function."""
    out = []
    for i in range(16):
        target = (table_va + sx(struct.unpack('<I', image.read(table_va + 4 * i, 4))[0], 32)) & M64
        if not first <= target < last:
            break
        out.append(target)
    return out


def run(target=TARGET):
    data = Path(target).read_bytes()
    authenticate(data)
    image = Image(data)
    fdes = {f['start']: f for f in fde_extents.fde_extents(data)[1] if f['start'] in FUNCTIONS}
    require(set(fdes) == set(FUNCTIONS), 'both functions have FDEs')
    extents = {}
    for start, f in fdes.items():
        pad = image.read(f['end'], f['next_index_upper_bound'] - f['end'])
        require(set(pad) <= {0xcc}, 'int3 padding after FDE end')
        extents[start] = f['end'] - start
    insns = {s: disassemble(image, s, extents[s]) for s in FUNCTIONS}
    tables = {}
    for s in FUNCTIONS:
        lea = next(i for i in insns[s] if i.op == 'lea' and i.b[1] == 'rip')
        table_va = (lea.va + lea.length + lea.b[4]) & M64
        tables[s] = (table_va, jump_table(image, table_va, s, s + extents[s]))
        require(len(tables[s][1]) == 4, 'four jump-table states')
    counts = {s: {} for s in FUNCTIONS}
    classes = {s: {} for s in FUNCTIONS}
    samples = {s: [] for s in FUNCTIONS}
    cache = {}
    total = mismatches = 0
    for function in FUNCTIONS:
        for index, case in case_stream(function, CASES_PER_FUNCTION):
            validate_case(case)
            a = run_original(image, case, cache, counts[function])
            b = run_model(case)
            total += 1
            mismatches += a != b
            cls = outcome_class(case, a)
            classes[function][cls] = classes[function].get(cls, 0) + 1
            if index < SAMPLE_ROWS:
                samples[function].append((index, case, a))
    rng = Rng(0x7e)
    for function, pad, drop in PADS:
        for _ in range(PAD_CASES):
            case = pad_case(function, pad, drop, rng)
            total += 1
            mismatches += run_pad_original(image, case, cache, counts[function]) != run_pad_model(case)
    require(mismatches == 0, 'reconstruction differs from the captured bytes')
    controls = run_controls(image, data)
    return dict(data=data, image=image, extents=extents, insns=insns, tables=tables,
                counts=counts, classes=classes, samples=samples, total=total,
                mismatches=mismatches, controls=controls)


def run_controls(image, data):
    rows = []

    def add(name, kind, detected, where):
        rows.append((name, kind, bool(detected), where))

    pairs = [(WRITE_ALL, m) for m in WRITE_MUTATIONS] + [(GATE, m) for m in GATE_MUTATIONS]
    for function, mutation in pairs:
        cache = {}
        at = first_difference(function, CONTROL_CASES,
                              lambda c: run_original(image, c, cache),
                              lambda c, mu=mutation: run_model(c, mu))
        add('%s:%s' % ('write-all' if function == WRITE_ALL else 'gate', mutation),
            'reconstruction-mutant', at >= 0, at)
    for name, function, va, byte in CORRUPTIONS:
        broken = Image(data)
        broken.patch[va] = byte
        at = first_difference(function, CONTROL_CASES,
                              lambda c, b=broken: run_original(b, c, {}),
                              run_model)
        add('%s:%s' % ('write-all' if function == WRITE_ALL else 'gate', name),
            'byte-corruption', at >= 0, at)
    pad_rng = Rng(0x51)
    for function, pad, drop in PADS[:1] + PADS[3:]:
        case = pad_case(function, pad, drop, pad_rng)
        add('pad-%x-state-mutant' % pad, 'reconstruction-mutant',
            run_pad_original(image, case, {}) != run_pad_model(case, 'pad-state'), -1)
    for function, pad, va, byte in ((WRITE_ALL, 0x5ab3b5d, 0x5ab3b60, 0x03),
                                    (GATE, 0x5ab6dcb, 0x5ab6ddc, 0x03)):
        broken = Image(data)
        broken.patch[va] = byte
        case = pad_case(function, pad, pad == 0x5ab6dcb, pad_rng)
        add('pad-%x-byte-corruption' % pad, 'byte-corruption',
            run_pad_original(broken, case, {}) != run_pad_model(case), -1)
    for state in BAD_STATES:
        case = write_case(Rng(7))
        case['state'] = state
        try:
            validate_case(case)
            rejected = False
        except ValueError:
            rejected = True
        add('state-byte-%d' % state, 'out-of-domain', rejected, -1)
    bad = bytearray(data)
    bad[len(bad) // 2] ^= 1
    try:
        authenticate(bytes(bad))
        add('flipped-bit', 'bad-digest', False, -1)
    except ValueError:
        add('flipped-bit', 'bad-digest', True, -1)
    try:
        authenticate(data[:-1])
        add('truncated-file', 'bad-digest', False, -1)
    except ValueError:
        add('truncated-file', 'bad-digest', True, -1)
    shifted = write_case(Rng(9))
    put_bytes(shifted['mem'], BASE + 0x40, 1, 0)
    shifted['state'] = 0
    shifted['fn'] = WRITE_ALL + 3
    obs = run_original(image, shifted, {})
    add('entry-off-boundary', 'range', obs[0].startswith('decode:') or obs != run_model(
        dict(shifted, fn=WRITE_ALL)), -1)
    unmapped = write_case(Rng(11))
    unmapped['mem'] = {a: v for a, v in unmapped['mem'].items() if a < BASE + 0x40}
    unmapped['state'] = 0
    obs = run_original(image, unmapped, {})
    add('missing-owner-memory', 'range', obs[0].startswith('unmapped'), -1)
    return rows


def hexa(v):
    return '0x%x' % v


def emit(out, result):
    out.mkdir(parents=True, exist_ok=True)
    extents, insns, tables = result['extents'], result['insns'], result['tables']
    name = {WRITE_ALL: 'write-all', GATE: 'gate'}

    def write(filename, header, rows):
        with open(out / filename, 'w', newline='\n') as f:
            f.write(header + '\n')
            for row in rows:
                f.write('\t'.join(str(c) for c in row) + '\n')

    rows = []
    for s in FUNCTIONS:
        for i in insns[s]:
            rows.append((name[s], hexa(i.va), i.raw.hex(), i.op,
                         result['counts'][s].get(i.va, 0)))
    write('instructions.tsv', 'function\tva\tbytes\top\texecuted', rows)
    rows = []
    for s in FUNCTIONS:
        table_va, targets = tables[s]
        for state, target in enumerate(targets):
            rows.append((name[s], state, hexa(table_va + 4 * state), hexa(target),
                         ('start', 'resumed-after-return', 'resumed-after-panic', 'repoll')[state]))
    write('state-table.tsv', 'function\tstate\tslot_va\ttarget_va\tmeaning', rows)
    rows = []
    for s in FUNCTIONS:
        for index, case, obs in result['samples'][s]:
            rows.append((name[s], index, case['state'], hexa(case['cx']), len(case['steps']),
                         outcome_class(case, obs), hexa(obs[1]), hexa(obs[2]),
                         ','.join(e[0] for e in obs[4])))
    write('cases-sample.tsv', 'function\tcase\tstate\tcx\tcallee_steps\toutcome\trax\trdx\tcalls', rows)
    rows = []
    for s in FUNCTIONS:
        for cls in sorted(result['classes'][s]):
            rows.append((name[s], cls, result['classes'][s][cls]))
    write('outcome-classes.tsv', 'function\toutcome\tcases', rows)
    rows = [(i, n, k, 'detected' if d else 'MISSED', w) for i, (n, k, d, w) in
            enumerate(result['controls'])]
    write('controls.tsv', 'id\tcontrol\tkind\tresult\tfirst_difference_case', rows)
    controls = result['controls']
    covered = {name[s]: [sum(1 for i in insns[s] if result['counts'][s].get(i.va, 0)),
                         len(insns[s])] for s in FUNCTIONS}
    summary = dict(
        binary_sha256=DIGEST, binary_size=SIZE,
        functions={name[s]: dict(start=hexa(s), bytes=extents[s],
                                 instructions=len(insns[s]),
                                 jump_table=hexa(tables[s][0]),
                                 state_targets=[hexa(t) for t in tables[s][1]])
                   for s in FUNCTIONS},
        cases_per_function=CASES_PER_FUNCTION, pad_cases=PAD_CASES * len(PADS), cases=result['total'],
        mismatches=result['mismatches'], instructions_executed=covered,
        callee_models=dict(cursor_write=hexa(CALLEE_WRITE), convert_error=hexa(CALLEE_ERR),
                           inner_poll=hexa(CALLEE_GATE), inner_drop=hexa(CALLEE_DROP)))
    with open(out / 'summary.json', 'w', newline='\n') as f:
        json.dump(summary, f, indent=1, sort_keys=True)
        f.write('\n')
    with open(out / 'measure.json', 'w', newline='\n') as f:
        json.dump(dict(cases=result['total'], negative_controls=len(controls),
                       negative_detected=sum(1 for c in controls if c[2])),
                  f, indent=1, sort_keys=True)
        f.write('\n')
    names = sorted(p.name for p in out.iterdir()
                   if p.is_file() and p.name not in ('MANIFEST.sha256', 'README.md'))
    return names


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True, type=Path)
    args = ap.parse_args(argv)
    result = run()
    for name in emit(args.out, result):
        print(name)
    missed = [c for c in result['controls'] if not c[2]]
    print('cases', result['total'], 'controls', len(result['controls']), 'missed', len(missed))
    return 1 if missed else 0


if __name__ == '__main__':
    sys.exit(main())
