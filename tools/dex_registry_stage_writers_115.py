#!/usr/bin/env python3
"""Reconstruct the node #115 msgpack stage writers below the Hip3 container writers.

The container loops of the Hip3 `schema` record (map loop 0x2202220, sequence
loop 0x2205280 and their copies) hand every entry to four outlined "stage
writers": a key writer, a value writer, an end writer and a sequence element
writer.  The previous packet left them stubbed.  This producer runs the
ORIGINAL machine code of all of them, in the three copy families of the
capture, together with the msgpack leaf writers they reach:

* key / value stage (0x2296160 0x2296fa0, copy 2 0x41cfc10 0x41d06f0, copy 3
  0x53206b0 0x5320130), end stage (0x22999e0), tuple stage (0x2299050) and the
  sequence element writer (0x22927f0) with the unsigned integer writer
  (0x25e9f10) and the binary header writer (0x25e80c0);
* the complete map write path (map loop, iterators, entry writer, all three
  stage writers, integer writer, array header) with no stubbed role;
* the sequence element path, where only the enum-variant name writer and the
  address-set writer (both outside this packet) are role stubs.

Every interpreted result (output bytes, result words, state words, call log,
allocator log) is compared with an independent pure-Python reconstruction.
Deliberately wrong reconstructions, byte-corrupted copies of the capture and
out-of-range inputs run through the same comparison and must all be caught.

Only the standard library and the repository's shared ELF/unwind parsers are
used.  The capture is never executed; no external program is invoked.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402,F401
import fde_extents  # noqa: E402
import hip3_subrecord_helpers_115 as eng  # noqa: E402  (shared image reader)

TARGET = eng.TARGET
SHA115 = eng.SHA115
MASK = (1 << 64) - 1
Reject = eng.Reject
Image = eng.Image
sx = eng.sx

# ------------------------------------------------------------------ decoder

CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g']
ALU = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']


class Insn:
    __slots__ = ('va', 'length', 'raw', 'mn', 'size', 'a', 'b', 'imm', 'target')

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


def decode(image, va):
    """Decode one instruction of the supported subset; raise Reject otherwise."""
    if va in image.cache:
        return image.cache[va]
    raw = image.read(va, 16)
    i = 0
    p66 = rep = False
    while raw[i] in (0x66, 0x2e, 0xf3):
        if raw[i] == 0x66:
            p66 = True
        elif raw[i] == 0xf3:
            rep = True
        i += 1
    rex = 0
    if 0x40 <= raw[i] <= 0x4f:
        rex = raw[i]
        i += 1
    w = bool(rex & 8)
    rr, rx, rb = (rex >> 2) & 1, (rex >> 1) & 1, rex & 1
    op = raw[i]
    i += 1
    two = False
    if op == 0x0f:
        op = 0x0f00 | raw[i]
        i += 1
        two = True
    osz = 8 if w else (2 if p66 else 4)

    def modrm():
        nonlocal i
        m = raw[i]
        i += 1
        mod, reg, rm = m >> 6, ((m >> 3) & 7) | (rr << 3), m & 7
        if mod == 3:
            return reg, ('r', rm | (rb << 3)), (m >> 3) & 7
        base = index = None
        scale, disp, rip = 1, 0, False
        if rm == 4:
            sib = raw[i]
            i += 1
            scale = 1 << (sib >> 6)
            idx = ((sib >> 3) & 7) | (rx << 3)
            index = None if idx == 4 else idx
            b = sib & 7
            if b == 5 and mod == 0:
                disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
                i += 4
            else:
                base = b | (rb << 3)
        elif rm == 5 and mod == 0:
            rip = True
            disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
            i += 4
        else:
            base = rm | (rb << 3)
        if mod == 1:
            disp = sx(raw[i], 8)
            i += 1
        elif mod == 2:
            disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
            i += 4
        return reg, ('m', base, index, scale, disp, rip), (m >> 3) & 7

    def imm(n):
        nonlocal i
        v = int.from_bytes(raw[i:i + n], 'little')
        i += n
        return v

    def byte_reg_ok(*ops):
        for o in ops:
            if o[0] == 'r' and not rex and 4 <= o[1] <= 7:
                raise Reject('legacy high-byte register at 0x%x' % va)

    kw = dict(va=va, size=osz)
    if not two and op < 0x40 and (op & 7) < 6 and (op & 0xf8) in (0, 8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
        name = ALU[op >> 3]
        low = op & 7
        if low in (0, 1, 2, 3):
            reg, rm, _ = modrm()
            sz = 1 if low in (0, 2) else osz
            if sz == 1:
                byte_reg_ok(('r', reg), rm)
            if low in (0, 1):
                kw.update(mn=name, size=sz, a=rm, b=('r', reg))
            else:
                kw.update(mn=name, size=sz, a=('r', reg), b=rm)
        elif low == 4:
            kw.update(mn=name, size=1, a=('r', 0), b=('i', imm(1)))
        else:
            kw.update(mn=name, size=osz, a=('r', 0), b=('i', sx(imm(4), 32) if w else imm(4)))
    elif not two and op in (0x80, 0x81, 0x83):
        _, rm, sub = modrm()
        if sub == 2 or sub == 1 and False:
            raise Reject('unsupported group-1 form at 0x%x' % va)
        if op == 0x80:
            byte_reg_ok(rm)
            kw.update(mn=ALU[sub], size=1, a=rm, b=('i', imm(1)))
        else:
            v = sx(imm(1), 8) if op == 0x83 else (sx(imm(4), 32) if w else imm(4))
            kw.update(mn=ALU[sub], a=rm, b=('i', v & MASK if w else v & 0xffffffff))
    elif not two and op in (0x84, 0x85):
        reg, rm, _ = modrm()
        if op == 0x84:
            byte_reg_ok(('r', reg), rm)
        kw.update(mn='test', size=1 if op == 0x84 else osz, a=rm, b=('r', reg))
    elif not two and op in (0x88, 0x89, 0x8a, 0x8b):
        reg, rm, _ = modrm()
        sz = 1 if op in (0x88, 0x8a) else osz
        if sz == 1:
            byte_reg_ok(('r', reg), rm)
        if op in (0x88, 0x89):
            kw.update(mn='mov', size=sz, a=rm, b=('r', reg))
        else:
            kw.update(mn='mov', size=sz, a=('r', reg), b=rm)
    elif not two and op == 0x8d:
        reg, rm, _ = modrm()
        if rm[0] != 'm':
            raise Reject('lea of a register at 0x%x' % va)
        kw.update(mn='lea', a=('r', reg), b=rm)
    elif not two and op == 0x63 and w:
        reg, rm, _ = modrm()
        kw.update(mn='movsxd', a=('r', reg), b=rm)
    elif not two and 0xb0 <= op <= 0xb7:
        r = (op - 0xb0) | (rb << 3)
        byte_reg_ok(('r', r))
        kw.update(mn='mov', size=1, a=('r', r), b=('i', imm(1)))
    elif not two and 0xb8 <= op <= 0xbf:
        r = (op - 0xb8) | (rb << 3)
        kw.update(mn='mov', a=('r', r), b=('i', imm(8) if w else imm(4)))
    elif not two and op in (0xc6, 0xc7):
        _, rm, sub = modrm()
        if sub != 0:
            raise Reject('unsupported c6/c7 form at 0x%x' % va)
        if op == 0xc6:
            byte_reg_ok(rm)
            kw.update(mn='mov', size=1, a=rm, b=('i', imm(1)))
        else:
            v = imm(2 if p66 else 4)
            kw.update(mn='mov', a=rm, b=('i', (sx(v, 32) & MASK) if w else v))
    elif not two and op == 0xc1:
        _, rm, sub = modrm()
        if sub not in (0, 4, 5):
            raise Reject('unsupported c1 form at 0x%x' % va)
        kw.update(mn={0: 'rol', 4: 'shl', 5: 'shr'}[sub], a=rm, b=('i', imm(1)))
    elif not two and op == 0xf7:
        _, rm, sub = modrm()
        if sub not in (3, 4):
            raise Reject('unsupported f7 form at 0x%x' % va)
        kw.update(mn={3: 'neg', 4: 'mul'}[sub], a=rm)
    elif not two and op == 0xff:
        _, rm, sub = modrm()
        if sub in (0, 1):
            kw.update(mn=('inc', 'dec')[sub], a=rm)
        elif sub == 2 and rm[0] == 'm':
            kw.update(mn='call_mem', a=rm)
        elif sub == 4 and rm[0] == 'm':
            kw.update(mn='jmp_mem', a=rm)
        else:
            raise Reject('unsupported ff form at 0x%x' % va)
    elif not two and 0x50 <= op <= 0x57:
        kw.update(mn='push', a=('r', (op - 0x50) | (rb << 3)))
    elif not two and 0x58 <= op <= 0x5f:
        kw.update(mn='pop', a=('r', (op - 0x58) | (rb << 3)))
    elif not two and 0x70 <= op <= 0x7f:
        rel = sx(imm(1), 8)
        kw.update(mn='j' + CC[op - 0x70], target=va + i + rel)
    elif two and 0x0f80 <= op <= 0x0f8f:
        rel = sx(imm(4), 32)
        kw.update(mn='j' + CC[op - 0x0f80], target=va + i + rel)
    elif two and 0x0f90 <= op <= 0x0f9f:
        _, rm, _ = modrm()
        byte_reg_ok(rm)
        kw.update(mn='set' + CC[op - 0x0f90], size=1, a=rm)
    elif two and 0x0f40 <= op <= 0x0f4f:
        reg, rm, _ = modrm()
        kw.update(mn='cmov' + CC[op - 0x0f40], a=('r', reg), b=rm)
    elif not two and op in (0xe8, 0xe9):
        kw.update(mn='call' if op == 0xe8 else 'jmp', target=va + 5 + sx(imm(4), 32))
    elif not two and op == 0xeb:
        kw.update(mn='jmp', target=va + 2 + sx(imm(1), 8))
    elif not two and op == 0xc3:
        kw.update(mn='ret')
    elif not two and op == 0x90:
        kw.update(mn='nop')
    elif two and op == 0x0f1f:
        modrm()
        kw.update(mn='nop')
    elif two and op == 0x0f0b:
        kw.update(mn='ud2')
    elif two and op in (0x0fb6, 0x0fb7):
        reg, rm, _ = modrm()
        if op == 0x0fb6:
            byte_reg_ok(rm)
        kw.update(mn='movzx', a=('r', reg), b=rm, imm=1 if op == 0x0fb6 else 2)
    elif two and op in (0x0f10, 0x0f11, 0x0f28, 0x0f29):
        reg, rm, _ = modrm()
        kw.update(mn='movaps' if op in (0x0f28, 0x0f29) else 'movups', size=16,
                  a=('x', reg) if op in (0x0f10, 0x0f28) else rm, b=rm if op in (0x0f10, 0x0f28) else ('x', reg))
    elif two and op == 0x0f57:
        reg, rm, _ = modrm()
        if rm != ('r', reg):
            raise Reject('unsupported xorps form at 0x%x' % va)
        kw.update(mn='xorps', size=16, a=('x', reg))
    elif two and 0x0fc8 <= op <= 0x0fcf:
        kw.update(mn='bswap', a=('r', (op - 0x0fc8) | (rb << 3)))
    elif two and op == 0x0fbc and rep:
        reg, rm, _ = modrm()
        kw.update(mn='tzcnt', a=('r', reg), b=rm)
    else:
        raise Reject('unsupported opcode 0x%x at 0x%x' % (op, va))
    kw['length'] = i
    kw['raw'] = bytes(raw[:i])
    for k in ('a', 'b'):
        o = kw.get(k)
        if o and o[0] == 'm' and o[5]:
            kw[k] = ('m', None, None, 1, va + i + o[4], True)
    ins = Insn(**kw)
    image.cache[va] = ins
    return ins


def linear(image, entry, end):
    rows, pc = [], entry
    while pc < end:
        ins = decode(image, pc)
        rows.append(ins)
        pc += ins.length
    if pc != end:
        raise Reject('decode did not land on the FDE end of 0x%x' % entry)
    return rows


# ------------------------------------------------------------------ machine

STACK_TOP = 0x7f00_0000
SENTINEL = 0xdead_0000
HEAP_BASE = 0x3000_0000
NICHE = 1 << 63
OK_WORD = NICHE + 4
SCRATCH_LO, SCRATCH_HI = 0x1000_0000, 0x8000_0000
CLOBBER = 0x5c5c_5c5c_5c5c_5c5c


class Panic(Exception):
    pass


def mask(size):
    return (1 << (8 * size)) - 1


class Machine:
    """Interpreter for the decoded subset with ZF CF SF OF.

    `real` is the set of body entries that run as original code; `stubs`
    maps a call target (or allocator/panic slot) to a Python callable that
    records its arguments.  Anything else is refused."""

    def __init__(self, image, real, stubs, slots, cover):
        self.image, self.real, self.stubs, self.slots, self.cover = image, real, stubs, slots, cover
        self.regs = [0] * 16
        self.xmm = [0] * 16
        self.mem = {}
        self.zf = self.cf = self.sf = self.of = False
        self.log = []
        self.steps = 0
        self.heap = HEAP_BASE
        self.sizes = {}
        # stack garbage: padding bytes of spilled words are never written by the code
        for a in range(STACK_TOP - 0x600, STACK_TOP):
            self.mem[a] = 0xa5

    # memory
    def load(self, addr, n):
        if n == 8 and addr in self.image.reloc:
            return self.image.reloc[addr]
        if addr < SCRATCH_LO:
            if any((addr + k) in self.mem for k in range(n)):
                raise Reject('mixed image/scratch read at 0x%x' % addr)
            return int.from_bytes(self.image.read(addr, n), 'little')
        out = bytearray()
        for k in range(n):
            b = self.mem.get(addr + k)
            if b is None:
                raise Reject('read of unset scratch byte 0x%x' % (addr + k))
            out.append(b)
        return int.from_bytes(out, 'little')

    def store(self, addr, value, n):
        if not (SCRATCH_LO <= addr and addr + n <= SCRATCH_HI):
            raise Reject('store outside scratch memory at 0x%x' % addr)
        data = (value & mask(n)).to_bytes(n, 'little')
        for k in range(n):
            self.mem[addr + k] = data[k]

    def poke(self, addr, data):
        for k, b in enumerate(data):
            self.mem[addr + k] = b

    def peek(self, addr, n):
        return bytes(self.mem[addr + k] for k in range(n))

    def w64(self, addr, v):
        self.store(addr, v, 8)

    def r64(self, addr):
        return self.load(addr, 8)

    def ea(self, o):
        _, base, index, scale, disp, rip = o
        if rip:
            return disp
        a = disp
        if base is not None:
            a += self.regs[base]
        if index is not None:
            a += self.regs[index] * scale
        return a & MASK

    def get(self, o, size):
        k = o[0]
        if k == 'i':
            return o[1] & mask(size)
        if k == 'r':
            return self.regs[o[1]] & mask(size)
        if k == 'x':
            return self.xmm[o[1]]
        return self.load(self.ea(o), size)

    def put(self, o, v, size):
        v &= mask(size)
        k = o[0]
        if k == 'x':
            self.xmm[o[1]] = v
        elif k == 'r':
            r = o[1]
            if size >= 4:
                self.regs[r] = v
            else:
                self.regs[r] = (self.regs[r] & (MASK ^ mask(size))) | v
        else:
            self.store(self.ea(o), v, size)

    def flags(self, r, size, cf, of):
        m = mask(size)
        self.zf = (r & m) == 0
        self.sf = bool((r >> (8 * size - 1)) & 1)
        self.cf, self.of = cf, of

    def cond(self, c):
        z, cf, sf, of = self.zf, self.cf, self.sf, self.of
        if None in (z, cf, sf, of) and c in (0, 1, 12, 13, 14, 15):
            if of is None:
                raise Reject('use of undefined overflow flag')
        if z is None or sf is None:
            if c in (4, 5, 6, 7, 8, 9, 12, 13, 14, 15):
                raise Reject('use of undefined zero/sign flag')
        return [of, not of, cf, not cf, z, not z, cf or z, not (cf or z), sf, not sf, False, True,
                sf != of, sf == of, z or sf != of, (not z) and sf == of][c]

    def alu(self, mn, a, b, size):
        m = mask(size)
        sign = 1 << (8 * size - 1)
        a &= m
        b &= m
        if mn == 'add':
            r = a + b
            self.flags(r, size, r > m, bool((a ^ r) & (b ^ r) & sign))
        elif mn in ('sub', 'cmp', 'sbb'):
            c = int(self.cf) if mn == 'sbb' else 0
            r = (a - b - c) & m
            self.flags(r, size, a < b + c, bool((a ^ b) & (a ^ r) & sign))
        else:
            r = {'and': a & b, 'or': a | b, 'xor': a ^ b, 'test': a & b}[mn]
            self.flags(r, size, False, False)
        return r & m

    def push(self, v):
        self.regs[4] -= 8
        self.store(self.regs[4], v, 8)

    def pop(self):
        v = self.load(self.regs[4], 8)
        self.regs[4] += 8
        return v

    def call_stub(self, fn):
        args = tuple(self.regs[r] for r in (7, 6, 2, 1, 8, 9))
        for r in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            self.regs[r] = CLOBBER
        fn(self, args)

    def run(self, entry, limit=60000):
        self.regs[4] = STACK_TOP - 8
        self.store(self.regs[4], SENTINEL, 8)
        pc = entry
        for _ in range(limit):
            ins = decode(self.image, pc)
            self.cover.add(pc)
            self.steps += 1
            nxt = pc + ins.length
            mn, size = ins.mn, ins.size
            if mn in ('add', 'sub', 'cmp', 'xor', 'or', 'and', 'test', 'sbb'):
                a, b = self.get(ins.a, size), self.get(ins.b, size)
                r = self.alu(mn, a, b, size)
                if mn not in ('cmp', 'test'):
                    self.put(ins.a, r, size)
            elif mn == 'adc':
                raise Reject('adc is not modelled')
            elif mn == 'mov':
                self.put(ins.a, self.get(ins.b, size), size)
            elif mn == 'lea':
                self.put(ins.a, self.ea(ins.b), size)
            elif mn == 'movzx':
                self.put(ins.a, self.get(ins.b, ins.imm), size)
            elif mn == 'movsxd':
                self.put(ins.a, sx(self.get(ins.b, 4), 32), 8)
            elif mn in ('movups', 'movaps'):
                if mn == 'movaps':
                    o = ins.a if ins.a[0] == 'm' else ins.b
                    if o[0] == 'm' and self.ea(o) % 16:
                        raise Reject('misaligned movaps at 0x%x' % pc)
                self.put(ins.a, self.get(ins.b, 16), 16)
            elif mn == 'xorps':
                self.xmm[ins.a[1]] = 0
            elif mn == 'push':
                self.push(self.regs[ins.a[1]])
            elif mn == 'pop':
                self.regs[ins.a[1]] = self.pop()
            elif mn == 'neg':
                a = self.get(ins.a, size)
                r = (-a) & mask(size)
                self.flags(r, size, a != 0, a == 1 << (8 * size - 1))
                self.put(ins.a, r, size)
            elif mn == 'mul':
                r = self.regs[0] * self.get(ins.a, 8)
                self.regs[0], self.regs[2] = r & MASK, r >> 64
                self.cf = self.of = bool(r >> 64)
                self.zf = self.sf = None
            elif mn in ('inc', 'dec'):
                a = self.get(ins.a, size)
                r = (a + (1 if mn == 'inc' else -1)) & mask(size)
                sign = 1 << (8 * size - 1)
                cf = self.cf
                self.flags(r, size, cf, (a == sign - 1) if mn == 'inc' else (a == sign))
                self.put(ins.a, r, size)
            elif mn in ('shl', 'shr', 'rol'):
                bits = 8 * size
                cnt = self.get(ins.b, 1) & (63 if size == 8 else 31)
                a = self.get(ins.a, size)
                if mn == 'rol':
                    cnt %= bits
                    r = ((a << cnt) | (a >> (bits - cnt))) & mask(size) if cnt else a
                    if cnt:
                        self.cf = bool(r & 1)
                        self.of = bool(((r >> (bits - 1)) & 1) ^ (r & 1)) if cnt == 1 else None
                elif cnt:
                    if mn == 'shl':
                        r = (a << cnt) & mask(size)
                        cf = bool((a >> (bits - cnt)) & 1)
                        of = bool(((r >> (bits - 1)) & 1) ^ cf) if cnt == 1 else None
                    else:
                        r = a >> cnt
                        cf = bool((a >> (cnt - 1)) & 1)
                        of = bool((a >> (bits - 1)) & 1) if cnt == 1 else None
                    self.flags(r, size, cf, of)
                else:
                    r = a
                self.put(ins.a, r, size)
            elif mn == 'bswap':
                self.put(ins.a, int.from_bytes(self.get(ins.a, size).to_bytes(size, 'little'), 'big'), size)
            elif mn == 'tzcnt':
                v = self.get(ins.b, size)
                r = (v & -v).bit_length() - 1 if v else 8 * size
                self.flags(r, size, v == 0, None)
                self.put(ins.a, r, size)
            elif mn.startswith('set'):
                self.put(ins.a, int(self.cond(CC.index(mn[3:]))), 1)
            elif mn.startswith('cmov'):
                if size not in (4, 8):
                    raise Reject('16-bit cmov is not modelled')
                if self.cond(CC.index(mn[4:])):
                    self.put(ins.a, self.get(ins.b, size), size)
                elif size == 4:
                    self.put(ins.a, self.get(ins.a, 4), 4)
            elif mn.startswith('j') and mn not in ('jmp', 'jmp_mem') and ins.target is not None:
                if self.cond(CC.index(mn[1:])):
                    nxt = ins.target
            elif mn == 'jmp' and ins.target in self.stubs:
                self.call_stub(self.stubs[ins.target])
                nxt = self.pop()
                if nxt == SENTINEL:
                    if self.regs[4] != STACK_TOP:
                        raise Reject('unbalanced stack at tail call 0x%x' % pc)
                    return
            elif mn == 'jmp':
                nxt = ins.target
            elif mn == 'call':
                t = ins.target
                if t in self.stubs:
                    self.call_stub(self.stubs[t])
                elif t in self.real:
                    self.push(nxt)
                    nxt = t
                else:
                    raise Reject('call to unmodelled target 0x%x at 0x%x' % (t, pc))
            elif mn in ('call_mem', 'jmp_mem'):
                slot = self.ea(ins.a)
                if slot not in self.stubs:
                    raise Reject('call through unmodelled slot 0x%x at 0x%x' % (slot, pc))
                self.call_stub(self.stubs[slot])
                if mn == 'jmp_mem':
                    nxt = self.pop()
            elif mn == 'ret':
                nxt = self.pop()
                if nxt == SENTINEL:
                    if self.regs[4] != STACK_TOP:
                        raise Reject('unbalanced stack at return 0x%x' % pc)
                    return
            elif mn == 'ud2':
                raise Reject('reached ud2 at 0x%x' % pc)
            elif mn == 'nop':
                pass
            else:
                raise Reject('no semantics for %s at 0x%x' % (mn, pc))
            pc = nxt
        raise Reject('step limit reached')


# ------------------------------------------------------------------ targets

SLOT = dict(alloc=0x64df480, alloc_err=0x64df498, dealloc=0x64df4a0, memcpy=0x64df508, panic=0x64df520,
            realloc_al=0x64df580, realloc=0x64df588, alloc_al=0x64df590, panic_loc=0x64df830)

# one row per copy family: copy 1, 2, 3
COPIES = (
    dict(copy=1, map=0x2202220, seq=0x2205280, wrap=0x2d562f0, head=0x25e7c10, fin=0x227e1b0, ent=0x22877f0,
         nmap=0x2388170, nseq=0x23896a0, mark=0x25eab50, res=0x231e050, grow=0x231dc90,
         key=0x2296160, val=0x2296fa0, end=0x22999e0, elem=0x22927f0),
    dict(copy=2, map=0x4151980, seq=0x4177540, wrap=0x3c6f250, head=0x3d50540, fin=0x41acd70, ent=0x41bf660,
         nmap=0x37c3750, nseq=0x37cd990, mark=0x3d52310, res=0x43bd910, grow=0x43bd550,
         key=0x41cfc10, val=0x41d06f0, end=0x41d4150, elem=0x41c2c30),
    dict(copy=3, map=0x52c5a70, seq=0x52b19d0, wrap=0x4da9790, head=0x57cee80, fin=0x5306d60, ent=0x5315e20,
         nmap=0x51347f0, nseq=0x5134a00, mark=0x57d0b20, res=0x5963a10, grow=0x5963650,
         key=0x5320130, val=0x53206b0, end=0x5325140, elem=0x5312380),
)
# the second-copy and third-copy map loop of the seq family use their own wrappers' callees
SEQ_NEXT = {1: 0x23896a0, 2: 0x37cd990, 3: 0x5134a00}
REAL_KEYS = ('map', 'seq', 'wrap', 'head', 'fin', 'ent', 'nmap', 'nseq', 'mark', 'res', 'grow')
STUB_KEYS = ('key', 'val', 'end', 'elem')
# The seq loop of copy 2 and 3 call the seq iterator of the same family; the wrapper calls the seq loop of
# its own family.  `wrap` of copy 2 reaches 0x4177540 and of copy 3 reaches 0x52b19d0 (checked from the bytes).
IT, OUT, WR, VB, CT, EL1, EL2, TREE = 0x1000_0000, 0x2000_0000, 0x2100_0000, 0x2200_0000, 0x2300_0000, \
    0x2400_0000, 0x2500_0000, 0x3800_0000
MAP_ELEM, SEQ_ELEM = 16, 32

# B-tree node layouts read from the two iterator bodies: (key_off, key_stride, val_off, val_stride, pidx_off,
# len_off, edge_off, leaf_size, internal_size)
LAYOUT = dict(map=(8, 8, 0x60, 8, 0xb8, 0xba, 0xc0, 0xc0, 0x120), seq=(0x114, 1, 8, 24, 0x110, 0x112, 0x120, 0x120, 0x180))


class PatchedImage(Image):
    """Capture image with byte overrides (used only for byte-corruption controls)."""

    def __init__(self, data, patches):
        super().__init__(data)
        self.patches = dict(patches)

    def read(self, va, n):
        b = bytearray(super().read(va, n))
        for p, v in self.patches.items():
            if va <= p < va + n:
                b[p - va] = v
        return bytes(b)


class Rng:
    def __init__(self, seed):
        self.s = (seed * 0x9E3779B97F4A7C15 + 1) & MASK

    def next(self):
        x = self.s
        x ^= (x << 13) & MASK
        x ^= x >> 7
        x ^= (x << 17) & MASK
        self.s = x
        return x

    def below(self, n):
        return self.next() % n

    def pick(self, seq):
        return seq[self.below(len(seq))]


def bsl_reserve(cap, ln, add, bad=None):
    """Vec<u8>::reserve growth: max(2*cap, len+add, 8)."""
    if bad == 'reserve_min4':
        return max(2 * cap, ln + add, 4)
    if bad == 'reserve_nodouble':
        return max(ln + add, 8)
    return max(2 * cap, ln + add, 8)


# ------------------------------------------------------------------ reconstruction (independent model)

class Vec:
    def __init__(self, cap, data):
        self.cap, self.buf = cap, bytearray(data)

    def room(self):
        return self.cap - len(self.buf)


def m_push(vec, data, log, bad=None):
    n = len(data)
    if vec.room() < n:
        grow = bsl_reserve(vec.cap, len(vec.buf), n, bad)
        log.append(('alloc' if vec.cap == 0 else 'realloc', grow))
        vec.cap = grow
    vec.buf += data


def m_header(vec, n, log, bad=None):
    if n < 16:
        kind = 0x90
    elif n < 0x10000:
        kind = 0xdc
    else:
        kind = 0xdd
    if bad == 'hdr_limit':
        kind = 0x90 if n < 15 else (0xdc if n < 0x10000 else 0xdd)
    if bad == 'hdr_marker' and kind == 0xdc:
        kind = 0xdd
    m_push(vec, bytes([0x90 | n if kind == 0x90 else kind]), log, bad)
    if kind == 0xdc:
        m_push(vec, (n & 0xffff).to_bytes(2, 'big' if bad != 'hdr_endian' else 'little'), log, bad)
    elif kind == 0xdd:
        m_push(vec, (n & 0xffffffff).to_bytes(4, 'big'), log, bad)
    return (2, kind, n & 0xff)


def state_tuple(cfg, target):
    return (0 if cfg[2] == 2 else NICHE, 1, 0, target, 2, cfg)


def m_entry(vec, cfg, target, item, plan, counters, log, bad=None):
    """Map entry: array-of-two marker unless the struct flag is 2, then key, value, end.  Returns error or None."""
    if cfg[2] != 2 or bad == 'flag_skip':
        m_push(vec, b'\x92', log, bad)
    st = state_tuple(cfg, target)
    for stage in ('key', 'val', 'end'):
        log.append((stage, st, None if stage == 'end' else item))
        k = counters[stage]
        counters[stage] += 1
        if plan and plan[0] == stage and plan[1] == k:
            return err_words(stage, k)
    return None


def err_words(stage, k):
    sid = ('key', 'val', 'end', 'elem').index(stage)
    return (0x0e10_0000_0000_0000 | (sid << 40) | k, 0x0e20_0000_0000_0000 | sid, 0x0e30_0000_0000_0000 | k)


def m_elem(cfg, target, item, plan, counters, log, bad=None):
    log.append(('elem', target, cfg, item))
    k = counters['elem']
    counters['elem'] += 1
    if plan and plan[0] == 'elem' and plan[1] == k:
        return err_words('elem', k)
    return None


def m_loop(kind, words, vec, cfg, items, plan, alloc_fail, bad=None):
    """Whole-loop reconstruction.  Returns (out words, log, panic)."""
    log = []
    elem = MAP_ELEM if kind == 'map' else SEQ_ELEM
    allocs = [0]

    def vec_alloc_fail_check(before):
        pass

    if words[0] == 2:
        n = ((words[2] - words[1]) & MASK) // elem + ((words[4] - words[3]) & MASK) // elem
    else:
        n = words[8]
    counters = dict(key=0, val=0, end=0, elem=0)
    buffered = (n >> 32) != 0
    if bad == 'buffered_limit':
        buffered = (n >> 32) != 0 or n > 18
    if not buffered:
        m_header(vec, n, log, bad)
        target, tvec = 'W', vec
    else:
        log.append(('alloc', 0x80))
        target, tvec = 'B', Vec(0x80, b'')
        cfg_b = (cfg[0], cfg[1] & 0x101, cfg[2])
    cnt = 0
    tcfg = cfg if not buffered else cfg_b
    seq_items = items if words[0] == 2 else items
    take = list(seq_items[:n]) if n < (1 << 40) else list(seq_items)
    if bad == 'tree_reverse' and words[0] != 2:
        take.reverse()
    exhausted_panic = n > len(seq_items) and words[0] != 2
    out = None
    for idx, item in enumerate(take):
        if kind == 'map':
            err = m_entry(tvec, tcfg, target, item, plan, counters, log, bad)
        else:
            err = m_elem(tcfg, target, item, plan, counters, log, bad)
        if err:
            out = err
            break
        cnt += 1
    if out is None and exhausted_panic:
        return None, log, 'next_exhausted'
    if out is not None:
        if buffered and bad != 'error_no_dealloc':
            log.append(('dealloc', tvec.cap))
        return out, log, None
    if not buffered:
        return (OK_WORD, None, None), log, None
    m_finish_tail(vec, tvec.cap, bytes(tvec.buf), cnt, log, bad)
    return (OK_WORD, None, None), log, None


def m_wrapper(repr_words):
    """The seq wrapper: container words (cap, ptr, head, len) -> nine iterator words."""
    cap, ptr, head, ln = repr_words
    if cap == NICHE:
        root, height, ln2 = ptr, head, ln
        p = int(root != 0)
        r8 = ln2 if root else 0
        return (p, 0, root, height, p, 0, root, height, r8)
    if ln == 0:
        s1, e1, base, c2, r8 = ptr, ptr, ptr, ptr, 0
        return (2, s1, e1, base, c2, 0, e1, base, r8)
    h = head - cap if head >= cap else head
    first = cap - h
    if ln > first:
        end1, second = cap, ln - first
        r8 = ln
    else:
        end1, second = h + ln, 0
        r8 = ln + h
    return (2, ptr + h * SEQ_ELEM, ptr + end1 * SEQ_ELEM, ptr, ptr + second * SEQ_ELEM, 0,
            ptr + end1 * SEQ_ELEM, ptr, r8)


def calls_in_order(image, by_start, entry):
    """Distinct direct-call targets that are unwind-table entries, in first-call order."""
    out = []
    for i in linear(image, entry, by_start[entry]['end']):
        if i.mn == 'call' and i.target in by_start and i.target not in out:
            out.append(i.target)
    return out


def derive_copies(image, by_start):
    """Stage roles come from call order inside the original bodies (first, second and third callee of the
    entry writer; the one non-iterator, non-header, non-finish callee of the sequence loop)."""
    for c in COPIES:
        ec = [t for t in calls_in_order(image, by_start, c['ent']) if t != c['res']]
        if len(ec) != 3:
            raise Reject('entry writer 0x%x does not call three stage writers' % c['ent'])
        c['key'], c['val'], c['end'] = ec
        sc = [t for t in calls_in_order(image, by_start, c['seq']) if t not in (c['head'], c['fin'], c['nseq'])]
        if len(sc) != 1:
            raise Reject('sequence loop 0x%x has no unique element writer' % c['seq'])
        c['elem'] = sc[0]
        wc = calls_in_order(image, by_start, c['wrap'])
        if wc != [c['seq']]:
            raise Reject('wrapper 0x%x does not call its sequence loop' % c['wrap'])
        mc = [t for t in calls_in_order(image, by_start, c['map']) if t not in (c['head'], c['fin'], c['nmap'], c['ent'])]
        if mc:
            raise Reject('map loop 0x%x has an unexpected callee' % c['map'])


def m_finish_tail(vec, tcap, tbuf, cnt, log, bad=None):
    """Finish of a buffered writer: array header with the count, the buffered bytes, then the buffer is freed."""
    m_header(vec, cnt + (1 if bad == 'count_plus1' else 0), log, bad)
    nb = len(tbuf)
    if nb > vec.room():
        grow = bsl_reserve(vec.cap, len(vec.buf), nb, bad)
        log.append(('alloc' if vec.cap == 0 else 'realloc', grow))
        vec.cap = grow
    if nb or bad == 'memcpy_empty':
        log.append(('memcpy', nb))
        vec.buf += tbuf
    if tcap and bad != 'finish_no_dealloc':
        log.append(('dealloc', tcap))


# ------------------------------------------------------------------ fixtures and runner

class World:
    def __init__(self, plan, alloc_fail, names):
        self.plan, self.alloc_fail, self.names = plan, alloc_fail, names
        self.counters = dict(key=0, val=0, end=0, elem=0)
        self.nalloc = 0

    def item(self, key, val):
        idx = self.names.get(key)
        if idx is None or self.names.get(('vk', val)) != idx:
            return ('?', key, val)
        return idx

    def key_only(self, key):
        return self.names.get(key, ('?', key))

    def val_only(self, val):
        return self.names.get(('vk', val), ('?', val))

    def tgt(self, ptr):
        return 'W' if ptr == WR else ('B' if ptr >= STACK_TOP - 0x10000 else ('?', ptr))


def cfg_of(m, p):
    return (m.load(p + 0x18, 2), m.load(p + 0x1a, 2), m.load(p + 0x1c, 1))


def make_stubs(world, cp):
    st = {}

    def do_alloc(m, a):
        size = a[0]
        n = world.nalloc
        world.nalloc += 1
        m.log.append(('alloc', size))
        if world.alloc_fail == n:
            m.regs[0] = 0
            return
        ptr = m.heap
        m.heap += ((size + 15) & ~15) + 16
        m.sizes[ptr] = size
        m.regs[0] = ptr

    def do_realloc(m, a):
        ptr, size = a[0], a[1]
        n = world.nalloc
        world.nalloc += 1
        m.log.append(('realloc', size))
        if world.alloc_fail == n:
            m.regs[0] = 0
            return
        new = m.heap
        m.heap += ((size + 15) & ~15) + 16
        old = m.sizes.get(ptr, 0)
        for k in range(min(old, size)):
            if ptr + k in m.mem:
                m.mem[new + k] = m.mem[ptr + k]
        m.sizes[new] = size
        m.regs[0] = new

    def do_alloc_err(m, a):
        raise Panic(('alloc_error', a[0], a[1]))

    def do_dealloc(m, a):
        m.log.append(('dealloc', a[1]))

    def do_memcpy(m, a):
        dst, src, n = a[0], a[1], a[2]
        m.log.append(('memcpy', n))
        for k in range(n):
            m.mem[dst + k] = m.mem[src + k]
        m.regs[0] = dst

    def do_panic(m, a):
        raise Panic(('panic', 'loc'))

    st[SLOT['alloc']] = do_alloc
    st[SLOT['alloc_al']] = do_alloc
    st[SLOT['realloc']] = do_realloc
    st[SLOT['realloc_al']] = do_realloc
    st[SLOT['alloc_err']] = do_alloc_err
    st[SLOT['dealloc']] = do_dealloc
    st[SLOT['memcpy']] = do_memcpy
    st[SLOT['panic']] = do_panic
    st[SLOT['panic_loc']] = do_panic

    def leaf(stage, nargs_state):
        def fn(m, a):
            out = a[0]
            k = world.counters[stage]
            world.counters[stage] += 1
            if stage == 'elem':
                m.log.append(('elem', world.tgt(a[3]), cfg_of(m, a[3]), world.item(a[1], a[2])))
            else:
                state = tuple(m.r64(a[1] + 8 * j) for j in range(4)) + (m.load(a[1] + 0x20, 4),)
                tgt = world.tgt(state[3])
                row = (state[0], state[1], state[2], tgt, state[4], cfg_of(m, state[3]))
                if stage == 'end':
                    m.log.append(('end', row, None))
                elif stage == 'key':
                    m.log.append(('key', row, world.key_only(a[2])))
                else:
                    m.log.append(('val', row, world.val_only(a[2])))
            plan = world.plan
            words = err_words(stage, k) if plan and plan[0] == stage and plan[1] == k else (OK_WORD, 0, 0)
            for j, wv in enumerate(words):
                m.w64(out + 8 * j, wv)
        return fn

    st[cp['key']] = leaf('key', 5)
    st[cp['val']] = leaf('val', 5)
    st[cp['end']] = leaf('end', 5)
    st[cp['elem']] = leaf('elem', 0)
    return st


def write_writer(m, cap, data, flag, w18, w1a):
    m.w64(WR, cap)
    if cap == 0:
        m.w64(WR + 8, 1)
    else:
        m.w64(WR + 8, VB)
        m.poke(VB, bytes(data))
        m.sizes[VB] = cap
    m.w64(WR + 0x10, len(data))
    m.store(WR + 0x18, w18, 2)
    m.store(WR + 0x1a, w1a, 2)
    m.store(WR + 0x1c, flag, 1)
    m.poke(WR + 0x1d, bytes(0x13))


class TreeBuilder:
    def __init__(self, m, kind):
        self.m, self.kind = m, kind
        self.lay = LAYOUT[kind]
        self.next_addr = TREE

    def node(self, internal):
        a = self.next_addr
        self.next_addr += 0x400
        return a

    def build(self, rng, height, maxlen):
        """Returns (root, items) with items the in-order (key ptr, val ptr) pairs."""
        ko, ks, vo, vs, po, lo, eo, _, _ = self.lay
        m = self.m
        items = []

        def gen(h, parent, pidx):
            a = self.node(h > 0)
            n = 1 + rng.below(maxlen)
            m.w64(a, parent)
            m.store(a + po, pidx, 2)
            m.store(a + lo, n, 2)
            if h == 0:
                for i in range(n):
                    items.append((a + ko + ks * i, a + vo + vs * i))
                return a
            for i in range(n + 1):
                c = gen(h - 1, a, i)
                m.w64(a + eo + 8 * i, c)
                if i < n:
                    items.append((a + ko + ks * i, a + vo + vs * i))
            return a

        root = gen(height, 0, 0)
        return root, items


def prepare_names(items):
    names = {}
    for idx, (k, v) in enumerate(items):
        names[k] = idx
        names[('vk', v)] = idx
    return names


def run_machine(image, cover, cp, case, kind):
    """Build the fixture of one case and run the original code; return (m, world, items, words, panic)."""
    rng = Rng(case['seed'])
    items = []
    m_holder = {}
    world = World(case.get('plan'), case.get('alloc_fail'), {})
    real = set()
    for c in COPIES:
        real.update(c[k] for k in REAL_KEYS)
    m = Machine(image, real, make_stubs(world, cp), SLOT, cover)
    elem = MAP_ELEM if kind == 'map' else SEQ_ELEM
    spec = case['iter']
    if spec[0] == 'slices':
        _, n1, n2 = spec
        words = (2, EL1, EL1 + n1 * elem, EL2, EL2 + n2 * elem, 0x7777, 0x7777, 0x7777, 0x7777)
        items = [(EL1 + elem * k, EL1 + elem * k + 8) for k in range(n1)] + \
                [(EL2 + elem * k, EL2 + elem * k + 8) for k in range(n2)]
    elif spec[0] == 'tree':
        _, height, maxlen, lenmod = spec
        tb = TreeBuilder(m, kind)
        root, items = tb.build(rng, height, maxlen)
        words = (1, 0, root, height, 1, 0, root, height, len(items) + lenmod)
    else:
        words = (0,) * 9
    world.names = prepare_names(items)
    for j, wv in enumerate(words):
        m.w64(IT + 8 * j, wv)
    write_writer(m, *case['writer'])
    m.w64(OUT, 0x1111)
    m.w64(OUT + 8, 0x2222)
    m.w64(OUT + 0x10, 0x3333)
    m.regs[7], m.regs[6], m.regs[2] = OUT, WR, IT
    panic = None
    try:
        m.run(cp[kind])
    except Panic as p:
        panic = p.args[0]
    return m, world, items, words, panic


def observe(m, panic):
    cap = m.r64(WR)
    ln = m.r64(WR + 0x10)
    ptr = m.r64(WR + 8)
    data = m.peek(ptr, ln) if ln else b''
    out = tuple(m.r64(OUT + 8 * j) for j in range(3))
    return dict(out=out, cap=cap, data=data, log=list(m.log), panic=panic)


def expect(kind, case, items, words, bad=None):
    cap, data, flag, w18, w1a = case['writer']
    vec = Vec(cap, data)
    out, log, panic = m_loop(kind, words, vec, (w18, w1a, flag), [k for k in range(len(items))], case.get('plan'),
                             case.get('alloc_fail'), bad)
    exp = dict(out=out, cap=vec.cap, data=bytes(vec.buf), log=log, panic=None)
    af = case.get('alloc_fail')
    if af is not None:
        seen = -1
        for pos, ev in enumerate(log):
            if ev[0] in ('alloc', 'realloc'):
                seen += 1
                if seen == af:
                    exp.update(log=log[:pos + 1], panic='alloc')
                    break
    if panic and exp['panic'] is None:
        exp['panic'] = 'next'
    return exp


def norm_log(log, items_n):
    out = []
    for ev in log:
        if ev[0] in ('key', 'val') and isinstance(ev[2], int):
            out.append((ev[0], ev[1], ev[2]))
        else:
            out.append(ev)
    return out


def compare(kind, got, exp):
    """None when equal, else a short reason (no raw bytes in the text)."""
    gp = got['panic']
    ep = exp['panic']
    gk = None if gp is None else ('alloc' if gp[0] == 'alloc_error' else 'next')
    if gk != ep:
        return 'panic kind %s vs %s' % (gk, ep)
    if got['log'] != exp['log']:
        for k, (a, b) in enumerate(zip(got['log'], exp['log'])):
            if a != b:
                return 'log row %d differs' % k
        return 'log length %d vs %d' % (len(got['log']), len(exp['log']))
    if ep is None:
        if any(e is not None and g != e for g, e in zip(got['out'], exp['out'])):
            return 'result words differ'
        if got['cap'] != exp['cap']:
            return 'capacity %d vs %d' % (got['cap'], exp['cap'])
        if got['data'] != exp['data']:
            return 'output bytes differ'
        if 'hdr' in got and got['hdr'] != exp['hdr']:
            return 'header bytes differ'
    return None


# ------------------------------------------------------------------ direct entry families



# ------------------------------------------------------------------ stage-writer targets

NEW_KEYS = ('key', 'val', 'end', 'elem', 'uint', 'binhdr', 'tup')
OLD_KEYS = ('map', 'seq', 'wrap', 'head', 'fin', 'ent', 'nmap', 'nseq', 'mark', 'res', 'grow')
BODY_KEYS = NEW_KEYS + OLD_KEYS
NAMES = dict(key='key stage', val='value stage', end='end stage', elem='sequence element writer',
             uint='unsigned integer writer', binhdr='binary header writer', tup='tuple stage',
             map='map loop', seq='sequence loop', wrap='sequence wrapper', head='array header', fin='finish',
             ent='map entry writer', nmap='map iterator next', nseq='sequence iterator next',
             mark='marker normaliser', res='vec reserve', grow='grow helper')
STAGES = ('key', 'val', 'end', 'elem', 'uint', 'hdr', 'binhdr', 'variant', 'set')
SLOT_NAMES = {SLOT['alloc']: 'alloc', SLOT['alloc_err']: 'alloc_error', SLOT['dealloc']: 'dealloc',
              SLOT['memcpy']: 'memcpy', SLOT['panic']: 'panic', SLOT['realloc_al']: 'realloc_aligned',
              SLOT['realloc']: 'realloc', SLOT['alloc_al']: 'alloc_aligned', SLOT['panic_loc']: 'panic_location'}

BUFP = 0x2600_0000
ST, ITEM, ITEM3, TAGP = 0x2300_0000, 0x2700_0000, 0x2700_0100, 0x2700_0200
OUTFILL = 0xa7


def derive_stage(image, by_start):
    """Roles of the new bodies come from call order inside the original bodies."""
    derive_copies(image, by_start)
    for c in COPIES:
        ec = calls_in_order(image, by_start, c['elem'])
        if len(ec) != 5 or ec[0] != c['head'] or ec[3] != c['end'] or ec[4] != c['res']:
            raise Reject('element writer 0x%x has an unexpected callee list' % c['elem'])
        c['variant'], c['tup'] = ec[1], ec[2]
        kc = calls_in_order(image, by_start, c['key'])
        if len(kc) != 2 or kc[0] != c['head']:
            raise Reject('key stage 0x%x has an unexpected callee list' % c['key'])
        c['uint'] = kc[1]
        if calls_in_order(image, by_start, c['val']) != kc:
            raise Reject('value stage 0x%x differs from the key stage callees' % c['val'])
        bc = calls_in_order(image, by_start, c['end'])
        if len(bc) != 3 or bc[1:] != [c['head'], c['res']]:
            raise Reject('end stage 0x%x has an unexpected callee list' % c['end'])
        c['binhdr'] = bc[0]
        if calls_in_order(image, by_start, c['tup']) != [c['head'], c['uint']]:
            raise Reject('tuple stage 0x%x has an unexpected callee list' % c['tup'])
        tails = [i.target for i in linear(image, c['tup'], by_start[c['tup']]['end'])
                 if i.mn == 'jmp' and i.target in by_start]
        if len(tails) != 1:
            raise Reject('tuple stage 0x%x has no unique tail call' % c['tup'])
        c['setw'] = tails[0]


def real_set():
    real = set()
    for c in COPIES:
        real.update(c[k] for k in BODY_KEYS)
    return real


def err_words2(stage, k):
    sid = STAGES.index(stage)
    return (0x0e10_0000_0000_0000 | (sid << 40) | k, 0x0e20_0000_0000_0000 | sid, 0x0e30_0000_0000_0000 | k)


# ------------------------------------------------------------------ reconstruction (independent model)

def m_uint(vec, v, log, bad=None):
    """rmp write_uint: positive fixint below 0x80, then u8/u16/u32/u64 with a marker byte."""
    if v < (0x7f if bad == 'uint_fixint' else 0x80):
        m_push(vec, bytes([v]), log, bad)
        return 0, v
    if v < 0x100:
        m_push(vec, b'\xcc', log, bad)
        m_push(vec, bytes([v]), log, bad)
        return 0xcc, None
    if v < 0x10000:
        m_push(vec, b'\xcd', log, bad)
        m_push(vec, v.to_bytes(2, 'little' if bad == 'uint_le' else 'big'), log, bad)
        return 0xcd, None
    if v < 1 << 32:
        m_push(vec, b'\xce' if bad != 'uint_marker' else b'\xcf', log, bad)
        m_push(vec, v.to_bytes(4, 'big'), log, bad)
        return 0xce, None
    m_push(vec, b'\xcf', log, bad)
    m_push(vec, v.to_bytes(8, 'big'), log, bad)
    return 0xcf, None


def m_binhdr(vec, n, log, bad=None):
    """Binary header: bin8 / bin16 / bin32 marker and big-endian length."""
    lim8 = 0x101 if bad == 'bin_limit' else 0x100
    if n < lim8:
        mk = 0xc4
    elif n < 0x10000:
        mk = 0xc5
    else:
        mk = 0xc6
    m_push(vec, bytes([mk]), log, bad)
    if mk == 0xc4:
        m_push(vec, bytes([n & 0xff]), log, bad)
    elif mk == 0xc5:
        m_push(vec, (n & 0xffff).to_bytes(2, 'little' if bad == 'bin_le' else 'big'), log, bad)
    else:
        m_push(vec, (n & 0xffffffff).to_bytes(4, 'big'), log, bad)
    return mk


class Sink:
    """The three leaf writers.  `real` mode writes into the writer vector, `stub` mode only records the call
    (and may fail the k-th call of one stage); `variant` and `set` are always role stubs."""

    def __init__(self, mode, vec, plan, log, bad):
        self.mode, self.vec, self.plan, self.log, self.bad = mode, vec, plan, log, bad
        self.count = {}

    def tick(self, stage):
        k = self.count.get(stage, 0)
        self.count[stage] = k + 1
        return k, bool(self.plan) and self.plan[0] == stage and self.plan[1] == k

    def leaf(self, stage, v, real_fn):
        k, fail = self.tick(stage)
        if self.mode == 'stub':
            self.log.append((stage, v))
            return err_words2(stage, k) if fail else None
        real_fn()
        return None

    def uint(self, v):
        return self.leaf('uint', v, lambda: m_uint(self.vec, v, self.log, self.bad))

    def hdr(self, n):
        n &= 0xffffffff
        return self.leaf('hdr', n, lambda: m_header(self.vec, n, self.log, self.bad))

    def binhdr(self, n):
        n &= 0xffffffff
        return self.leaf('binhdr', n, lambda: m_binhdr(self.vec, n, self.log, self.bad))

    def role(self, stage, row):
        k, fail = self.tick(stage)
        self.log.append((stage,) + row)
        return err_words2(stage, k) if fail else (OK_WORD, 0, 0)


def m_flush(sink, st, log, bad=None):
    """A buffered state turns into a streaming one: array header with the hint, the pending bytes as integers,
    then the buffer is freed."""
    if bad == 'flush_hint_zero':
        e = sink.hdr(0)
    else:
        e = sink.hdr(st['hint'])
    if e:
        return e
    for b in (reversed(st['buf']) if bad == 'flush_reverse' else st['buf']):
        e = sink.uint(b)
        if e:
            return e
    if st['cap'] != 0 and bad != 'flush_no_free':
        log.append(('dealloc', st['cap']))
    if bad != 'flush_keep_state':
        st['cap'] = NICHE
    return None


def m_key(sink, st, item, log, bad=None):
    """Key and value stage (identical bodies)."""
    if st['cap'] != NICHE:
        e = m_flush(sink, st, log, bad)
        if e:
            return (NICHE, e[0], e[1])
    e = sink.uint(item)
    if e:
        return (NICHE, e[0], e[1])
    return (OK_WORD, None, None)


def m_tup(sink, st, item3, log, bad=None):
    if st['cap'] != NICHE and bad != 'tup_no_flush':
        e = m_flush(sink, st, log, bad)
        if e:
            return (NICHE, e[0], e[1])
    return sink.role('set', (len(sink.vec.buf),) + tuple(item3))


def m_end(sink, st, log, bad=None):
    if st['cap'] == NICHE:
        return (OK_WORD, None, None)
    buf, hint = st['buf'], st['hint']
    if bad == 'end_ascii_any':
        ascii_ = True
    else:
        ascii_ = all(b < 0x80 for b in buf)
    lim = 0x11 if bad == 'end_hint_17' else 0x10
    e = sink.hdr(hint) if hint < lim and ascii_ else sink.binhdr(hint)
    if e:
        if st['cap'] != 0 and bad != 'end_error_no_dealloc':
            log.append(('dealloc', st['cap']))
        return (NICHE, e[0], e[1])
    vec, nb = sink.vec, len(buf)
    if nb > vec.room():
        grow = bsl_reserve(vec.cap, len(vec.buf), nb, bad)
        log.append(('alloc' if vec.cap == 0 else 'realloc', grow))
        vec.cap = grow
    if nb or bad == 'end_memcpy_empty':
        log.append(('memcpy', nb))
    vec.buf += buf
    if st['cap'] != 0:
        log.append(('dealloc', st['cap']))
    return (OK_WORD, None, None)


def m_elem2(sink, flag, tag, item3, log, bad=None):
    vec = sink.vec
    if flag != 2 or bad == 'elem_flag2_push':
        m_push(vec, b'\x92', log, bad)
    else:
        e = sink.hdr(2)
        if e:
            return (NICHE, e[0], e[1])
    r = sink.role('variant', (tag, len(vec.buf)))
    if r[0] != OK_WORD:
        return r
    st = dict(cap=NICHE, buf=b'', hint=2)
    r = m_tup(sink, st, item3, log, bad)
    if r[0] != OK_WORD:
        return r
    return m_end(sink, st, log, bad)


def m_entry2(sink, flag, kv, log, bad=None):
    vec = sink.vec
    if flag != 2:
        m_push(vec, b'\x92', log, bad)
    st = dict(cap=0 if flag == 2 else NICHE, buf=b'', hint=2)
    order = (kv[1], kv[0]) if bad == 'entry_swap' else kv
    for item in order:
        r = m_key(sink, st, item, log, bad)
        if r[0] != OK_WORD:
            return r
    return m_end(sink, st, log, bad)


def m_loop2(kind, words, vec, flag, items, plan, bad=None):
    """Whole unbuffered loop with real stage writers.  Returns (out words, log, panic)."""
    log = []
    elem = MAP_ELEM if kind == 'map' else SEQ_ELEM
    if words[0] == 2:
        n = ((words[2] - words[1]) & MASK) // elem + ((words[4] - words[3]) & MASK) // elem
    else:
        n = words[8]
    m_header(vec, n, log, bad)
    sink = Sink('real', vec, plan, log, bad)
    for it in list(items[:n]):
        r = m_entry2(sink, flag, it, log, bad) if kind == 'map' else m_elem2(sink, flag, it[0], it[1], log, bad)
        if r[0] != OK_WORD:
            return r, log, None
    if n > len(items) and words[0] != 2:
        return None, log, 'next_exhausted'
    return (OK_WORD, None, None), log, None


# ------------------------------------------------------------------ fixtures and runner

class Env:
    def __init__(self, mode, plan, alloc_fail):
        self.mode, self.plan, self.alloc_fail = mode, plan, alloc_fail
        self.count = {}

    def tick(self, stage):
        k = self.count.get(stage, 0)
        self.count[stage] = k + 1
        return k, bool(self.plan) and self.plan[0] == stage and self.plan[1] == k


def make_stubs2(env, cp):
    world = World(None, env.alloc_fail, {})
    st = make_stubs(world, cp)
    for k in STUB_KEYS:
        st.pop(cp[k])

    def put_words(m, out, words):
        for j, wv in enumerate(words):
            m.w64(out + 8 * j, wv)

    def role(stage, row_fn):
        def fn(m, a):
            k, fail = env.tick(stage)
            m.log.append((stage,) + row_fn(m, a))
            put_words(m, a[0], err_words2(stage, k) if fail else (OK_WORD, 0, 0))
        return fn

    st[cp['variant']] = role('variant', lambda m, a: (m.load(a[1], 1), m.r64(a[2] + 0x10)))
    st[cp['setw']] = role('set', lambda m, a: (m.r64(a[1] + 0x10),) + tuple(m.r64(a[2] + 8 * j) for j in range(3)))
    if env.mode == 'stub':
        for stage, key, width in (('uint', 'uint', 8), ('hdr', 'head', 4), ('binhdr', 'binhdr', 4)):
            def mk(stage=stage, width=width):
                def fn(m, a):
                    k, fail = env.tick(stage)
                    m.log.append((stage, a[2] & ((1 << (8 * width)) - 1)))
                    put_words(m, a[0], (err_words2(stage, k) if fail else (2, 0, 0))[:2])
                return fn
            st[cp[key]] = mk()
    return st


def setup_state(m, st):
    m.w64(ST, st['cap'])
    if st['buf']:
        m.w64(ST + 8, BUFP)
        m.poke(BUFP, bytes(st['buf']))
    else:
        m.w64(ST + 8, 1)
    m.w64(ST + 0x10, len(st['buf']))
    m.w64(ST + 0x18, WR)
    m.store(ST + 0x20, st['hint'], 4)
    if st['cap'] not in (NICHE, 0):
        m.sizes[BUFP] = st['cap']


def fill_out(m):
    m.poke(OUT, bytes([OUTFILL]) * 24)


def run_loop2(image, cover, cp, case):
    kind = case['kind']
    rng = Rng(case['seed'])
    env = Env('real', case.get('plan'), case.get('alloc_fail'))
    m = Machine(image, real_set(), make_stubs2(env, cp), SLOT, cover)
    elem = MAP_ELEM if kind == 'map' else SEQ_ELEM
    spec = case['iter']
    if spec[0] == 'slices':
        _, n1, n2 = spec
        words = (2, EL1, EL1 + n1 * elem, EL2, EL2 + n2 * elem, 0x7777, 0x7777, 0x7777, 0x7777)
        items = [(EL1 + elem * k, EL1 + elem * k + 8) for k in range(n1)] + \
                [(EL2 + elem * k, EL2 + elem * k + 8) for k in range(n2)]
    else:
        _, height, maxlen, lenmod = spec
        tb = TreeBuilder(m, kind)
        root, items = tb.build(rng, height, maxlen)
        words = (1, 0, root, height, 1, 0, root, height, len(items) + lenmod)
    vals = []
    for kp, vp in items:
        if kind == 'map':
            kv = (pick_value(rng), pick_value(rng))
            m.w64(kp, kv[0])
            m.w64(vp, kv[1])
            vals.append(kv)
        else:
            tag = rng.below(24)
            w3 = tuple(rng.next() >> rng.below(60) for _ in range(3))
            m.store(kp, tag, 1)
            for j, wv in enumerate(w3):
                m.w64(vp + 8 * j, wv)
            vals.append((tag, w3))
    for j, wv in enumerate(words):
        m.w64(IT + 8 * j, wv)
    write_writer(m, *case['writer'])
    fill_out(m)
    m.regs[7], m.regs[6], m.regs[2] = OUT, WR, IT
    panic = None
    try:
        m.run(cp[kind])
    except Panic as p:
        panic = p.args[0]
    cap, data, flag, w18, w1a = case['writer']
    vec = Vec(cap, data)
    out, log, p = m_loop2(kind, words, vec, flag, vals, case.get('plan'), case.get('bad'))
    exp = dict(out=out, cap=vec.cap, data=bytes(vec.buf), log=log, panic=None)
    apply_alloc_fail(exp, log, case.get('alloc_fail'))
    if p and exp['panic'] is None:
        exp['panic'] = 'next'
    got = observe(m, panic)
    add_semantics(got, exp, case, kind, words, vals)
    return got, exp, m.steps


def apply_alloc_fail(exp, log, af):
    if af is None:
        return
    seen = -1
    for pos, ev in enumerate(log):
        if ev[0] in ('alloc', 'realloc'):
            seen += 1
            if seen == af:
                exp.update(log=log[:pos + 1], panic='alloc')
                return


def run_stage(image, cover, cp, case):
    """One stage writer on its own: uint, binhdr, key, val, tup, end or elem."""
    fam, mode = case['fam'], case['mode']
    env = Env(mode, case.get('plan'), case.get('alloc_fail'))
    real = real_set()
    m = Machine(image, real, make_stubs2(env, cp), SLOT, cover)
    cap, data, flag, w18, w1a = case['writer']
    write_writer(m, cap, data, flag, w18, w1a)
    vec = Vec(cap, data)
    fill_out(m)
    log, bad, plan = [], case.get('bad'), case.get('plan')
    sink = Sink(mode, vec, plan, log, bad)
    st = case.get('state')
    exp_out = None
    obytes = None
    stcap = None
    if st is not None:
        setup_state(m, st)
        mst = dict(st)
    m.regs[7] = OUT
    if fam == 'uint':
        v = case['value']
        m.regs[6], m.regs[2] = WR, v
        entry = cp['uint']
        mk, fix = m_uint(vec, v, log, bad)
        ob = bytearray([OUTFILL]) * 24
        ob[0:8] = (2).to_bytes(8, 'little')
        if fix is None:
            ob[8] = mk
        else:
            ob[8], ob[9] = 0, fix
        exp_out, obytes = (2, None, None), bytes(ob[:10])
    elif fam == 'binhdr':
        n = case['value']
        m.regs[6], m.regs[2] = WR, n
        entry = cp['binhdr']
        mk = m_binhdr(vec, n, log, bad)
        exp_out, obytes = (2, None, None), (2).to_bytes(8, 'little') + bytes([mk])
    elif fam in ('key', 'val'):
        m.w64(ITEM, case['value'])
        m.regs[6], m.regs[2] = ST, ITEM
        entry = cp[fam]
        exp_out = m_key(sink, mst, case['value'], log, bad)
        stcap = mst['cap']
    elif fam == 'tup':
        w3 = case['item3']
        for j, wv in enumerate(w3):
            m.w64(ITEM3 + 8 * j, wv)
        m.regs[6], m.regs[2] = ST, ITEM3
        entry = cp['tup']
        exp_out = m_tup(sink, mst, w3, log, bad)
        stcap = mst['cap']
    elif fam == 'end':
        m.regs[6] = ST
        entry = cp['end']
        exp_out = m_end(sink, mst, log, bad)
        stcap = mst['cap']
    else:
        w3 = case['item3']
        for j, wv in enumerate(w3):
            m.w64(ITEM3 + 8 * j, wv)
        m.store(TAGP, case['tag'], 1)
        m.regs[6], m.regs[2], m.regs[1] = TAGP, ITEM3, WR
        entry = cp['elem']
        exp_out = m_elem2(sink, flag, case['tag'], w3, log, bad)
    panic = None
    try:
        m.run(entry)
    except Panic as p:
        panic = p.args[0]
    got = observe(m, panic)
    got['ob'] = m.peek(OUT, len(obytes)) if obytes else None
    got['stcap'] = m.r64(ST) if stcap is not None else None
    exp = dict(out=exp_out, cap=vec.cap, data=bytes(vec.buf), log=log, panic=None, ob=obytes, stcap=stcap)
    apply_alloc_fail(exp, log, case.get('alloc_fail'))
    return got, exp, m.steps


def compare2(got, exp):
    r = compare('stage', got, exp)
    if r:
        return r
    if exp['panic'] is None:
        if exp.get('ob') is not None and got.get('ob') != exp['ob']:
            return 'result bytes differ'
        if exp.get('stcap') is not None and got.get('stcap') != exp['stcap']:
            return 'state word differs'
        if 'sem' in exp and got.get('sem') != exp['sem']:
            return 'decoded wire form differs'
    return None


def run_case(image, cover, ci, case, bad=None):
    cp = COPIES[ci]
    if bad:
        case = dict(case, bad=bad)
    if case['fam'] == 'wseq':
        return run_wrapper(image, cover, cp, case)
    if case['fam'] in ('map', 'seq'):
        case = dict(case, kind=case['fam'])
        return run_loop2(image, cover, cp, case)
    return run_stage(image, cover, cp, case)


def decode_wire(data):
    """Independent reader of the produced bytes: arrays and unsigned integers only."""
    def one(pos):
        b = data[pos]
        if b < 0x80:
            return b, pos + 1
        if 0x90 <= b <= 0x9f:
            return arr(b & 0xf, pos + 1)
        widths = {0xcc: 1, 0xcd: 2, 0xce: 4, 0xcf: 8}
        if b in widths:
            w = widths[b]
            return int.from_bytes(data[pos + 1:pos + 1 + w], 'big'), pos + 1 + w
        if b == 0xdc:
            return arr(int.from_bytes(data[pos + 1:pos + 3], 'big'), pos + 3)
        if b == 0xdd:
            return arr(int.from_bytes(data[pos + 1:pos + 5], 'big'), pos + 5)
        raise ValueError('marker 0x%x' % b)

    def arr(n, pos):
        out = []
        for _ in range(n):
            v, pos = one(pos)
            out.append(v)
        return out, pos

    value, end = one(0)
    if end != len(data):
        raise ValueError('trailing bytes')
    return value


def add_semantics(got, exp, case, kind, words, vals):
    """A map run that succeeds must decode to the list of [key, value] pairs it was given."""
    if kind != 'map' or exp['panic'] is not None or exp['out'] is None or exp['out'][0] != OK_WORD:
        return
    elem = MAP_ELEM
    n = ((words[2] - words[1]) // elem + (words[4] - words[3]) // elem) if words[0] == 2 else words[8]
    new = got['data'][len(case['writer'][1]):]
    try:
        got['sem'] = decode_wire(new)
    except (ValueError, IndexError):
        got['sem'] = 'undecodable'
    exp['sem'] = [[k, v] for k, v in vals[:n]]


RING = 0x2800_0000


def run_wrapper(image, cover, cp, case):
    """Container words -> wrapper -> sequence loop -> element writer, all original code (variant and set stubbed)."""
    rng = Rng(case['seed'])
    env = Env('real', case.get('plan'), case.get('alloc_fail'))
    m = Machine(image, real_set(), make_stubs2(env, cp), SLOT, cover)
    c = case['container']
    vals = {}

    def fill(kp, vp):
        tag = rng.below(24)
        w3 = tuple(rng.next() >> rng.below(60) for _ in range(3))
        m.store(kp, tag, 1)
        for j, wv in enumerate(w3):
            m.w64(vp + 8 * j, wv)
        vals[kp] = (tag, w3)

    if c['kind'] == 'ring':
        for i in range(c['cap']):
            fill(RING + SEQ_ELEM * i, RING + SEQ_ELEM * i + 8)
        cwords = (c['cap'], RING, c['head'], c['len'])
        titems = None
    else:
        tb = TreeBuilder(m, 'seq')
        root, titems = tb.build(rng, c['height'], c['maxlen'])
        for kp, vp in titems:
            fill(kp, vp)
        cwords = (NICHE, root, c['height'], len(titems) + c['lenmod'])
    for j, wv in enumerate(cwords):
        m.w64(CT + 8 * j, wv)
    write_writer(m, *case['writer'])
    fill_out(m)
    m.regs[7], m.regs[6], m.regs[2] = OUT, CT, WR
    panic = None
    try:
        m.run(cp['wrap'])
    except Panic as p:
        panic = p.args[0]
    it = m_wrapper(cwords)
    if it[0] == 2:
        addrs = [it[1] + SEQ_ELEM * k for k in range((it[2] - it[1]) // SEQ_ELEM)] + \
                [it[3] + SEQ_ELEM * k for k in range((it[4] - it[3]) // SEQ_ELEM)]
    else:
        addrs = [kp for kp, _ in titems]
    seq_vals = [vals[a] for a in addrs]
    if case.get('bad') == 'wrap_reverse':
        seq_vals.reverse()
    cap, data, flag, w18, w1a = case['writer']
    vec = Vec(cap, data)
    out, log, p = m_loop2('seq', it, vec, flag, seq_vals, case.get('plan'), case.get('bad'))
    exp = dict(out=out, cap=vec.cap, data=bytes(vec.buf), log=log, panic=None)
    apply_alloc_fail(exp, log, case.get('alloc_fail'))
    if p and exp['panic'] is None:
        exp['panic'] = 'next'
    return observe(m, panic), exp, m.steps


# ------------------------------------------------------------------ cases

VALUE_EDGES = (0, 1, 0x7e, 0x7f, 0x80, 0x81, 0xfe, 0xff, 0x100, 0x101, 0xfffe, 0xffff, 0x10000, 0x10001,
               0xfffffffe, 0xffffffff, 1 << 32, (1 << 32) + 1, (1 << 63), MASK - 1, MASK)
ROOMS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16)
HINTS = (0, 1, 2, 3, 9, 14, 15, 16, 17, 31, 0xff, 0x100, 0x101, 0xffff, 0x10000, 0x12345, 0xffffffff)
FLAGS2 = (0, 1, 2, 3, 0x80, 0xff, 2, 2)


def pick_value(rng):
    c = rng.below(8)
    if c == 0:
        return rng.below(0x80)
    if c == 1:
        return 0x80 + rng.below(0x80)
    if c == 2:
        return 0x100 + rng.below(0xff00)
    if c == 3:
        return 0x10000 + rng.below(0xffff0000)
    if c == 4:
        return (1 << 32) + (rng.next() % ((MASK >> 32) << 32))
    if c == 5:
        return rng.pick(VALUE_EDGES)
    return rng.below(300)


def pick_writer(rng, room=None, flag=None):
    if room is None:
        room = rng.pick(ROOMS)
    ln = rng.below(5) if rng.below(3) else rng.below(20)
    cap = ln + room if (ln + room) else 0
    if cap == 0:
        ln = 0
    data = bytes(rng.below(256) for _ in range(ln))
    return (cap, data, FLAGS2[rng.below(len(FLAGS2))] if flag is None else flag, rng.below(0x10000),
            rng.below(0x10000))


def pick_state(rng, allow_nonempty=True):
    c = rng.below(10)
    hint = rng.pick(HINTS) if rng.below(2) else rng.below(20)
    if c < 4:
        return dict(cap=NICHE, buf=b'', hint=hint)
    if c < 6 or not allow_nonempty:
        return dict(cap=0, buf=b'', hint=hint)
    n = rng.below(7)
    buf = bytes((rng.below(0x80) if rng.below(3) else rng.below(256)) if rng.below(8) else 0 for _ in range(n))
    if rng.below(5) == 0 and n:
        buf = bytes(b & 0x7f for b in buf)
    return dict(cap=n + rng.below(4) + (1 if n == 0 else 0), buf=buf, hint=hint)


def pick_plan(rng, stages):
    if rng.below(3) == 0:
        return None
    return (rng.pick(stages), rng.below(3))


def stage_case(rng, fam, n):
    seed = rng.next()
    mode = 'real' if rng.below(3) else 'stub'
    case = dict(fam=fam, mode=mode, seed=seed)
    if fam in ('uint', 'binhdr'):
        case['mode'] = 'real'
        case['value'] = VALUE_EDGES[n % len(VALUE_EDGES)] if n % 3 == 0 else pick_value(rng)
        if fam == 'binhdr':
            case['value'] &= 0xffffffff
        case['writer'] = pick_writer(rng, room=ROOMS[(n // 3) % len(ROOMS)] if n % 2 == 0 else None)
    elif fam in ('key', 'val', 'tup', 'end', 'elem'):
        case['writer'] = pick_writer(rng)
        if fam in ('key', 'val'):
            case['value'] = pick_value(rng)
        if fam in ('tup', 'elem'):
            case['item3'] = tuple(pick_value(rng) for _ in range(3))
        if fam == 'elem':
            case['tag'] = rng.below(24)
        if fam != 'elem':
            case['state'] = pick_state(rng)
        if fam == 'elem':
            case['state'] = None
        if fam == 'elem' and mode == 'real':
            case['plan'] = pick_plan(rng, ('variant', 'set'))
        elif mode == 'stub':
            stages = {'key': ('uint', 'hdr'), 'val': ('uint', 'hdr'), 'tup': ('uint', 'hdr', 'set'),
                      'end': ('hdr', 'binhdr'), 'elem': ('hdr', 'variant', 'set')}[fam]
            case['plan'] = pick_plan(rng, stages)
        else:
            case['plan'] = pick_plan(rng, ('set',)) if fam == 'tup' else None
    mode = case['mode']
    if mode == 'real' and rng.below(10) == 0 and fam != 'binhdr':
        case['alloc_fail'] = rng.below(2)
    case['writer'] = case['writer']
    return case


def loop_case(rng, kind):
    seed = rng.next()
    if rng.below(2):
        it = ('slices', rng.below(7), rng.below(7))
    else:
        it = ('tree', rng.below(3), 1 + rng.below(4), rng.pick((0, 0, 0, 0, 1, -1, 2)))
    case = dict(fam=kind, seed=seed, iter=it, writer=pick_writer(rng), mode='real')
    if rng.below(4) == 0:
        case['plan'] = (rng.pick(('uint',) if kind == 'map' else ('variant', 'set')), rng.below(4))
        if kind == 'map':
            case.pop('plan')
    if kind == 'seq' and rng.below(4) == 0:
        case['plan'] = (rng.pick(('variant', 'set')), rng.below(4))
    if rng.below(8) == 0:
        case['alloc_fail'] = rng.below(3)
    return case


FAMILY_COUNTS = (('uint', 600), ('binhdr', 330), ('key', 300), ('val', 300), ('tup', 400), ('end', 450),
                 ('elem', 600), ('map', 450), ('seq', 400), ('wseq', 450))


def wrap_case(rng):
    seed = rng.next()
    if rng.below(3):
        cap = 1 + rng.below(6)
        cont = dict(kind='ring', cap=cap, head=rng.below(cap), len=rng.below(cap + 1))
    else:
        cont = dict(kind='tree', height=rng.below(3), maxlen=1 + rng.below(4), lenmod=rng.pick((0, 0, 0, 1, -1)))
    case = dict(fam='wseq', seed=seed, container=cont, writer=pick_writer(rng), mode='real')
    if rng.below(4) == 0:
        case['plan'] = (rng.pick(('variant', 'set')), rng.below(4))
    if rng.below(8) == 0:
        case['alloc_fail'] = rng.below(3)
    return case


def gen_cases():
    """Deterministic case stream: (family, copy index, case)."""
    for ci in range(3):
        rng = Rng(0x5eed0000 + ci)
        for fam, count in FAMILY_COUNTS:
            for n in range(count):
                if fam == 'wseq':
                    yield fam, ci, wrap_case(rng)
                elif fam in ('map', 'seq'):
                    yield fam, ci, loop_case(rng, fam)
                else:
                    yield fam, ci, stage_case(rng, fam, n)


# ------------------------------------------------------------------ negative controls

MODEL_MUTANTS = ('hdr_limit', 'hdr_endian', 'reserve_min4', 'reserve_nodouble', 'uint_fixint', 'uint_le',
                 'uint_marker', 'bin_limit', 'bin_le', 'flush_no_free', 'flush_reverse', 'flush_keep_state',
                 'flush_hint_zero', 'tup_no_flush', 'end_ascii_any', 'end_hint_17', 'end_error_no_dealloc',
                 'end_memcpy_empty', 'elem_flag2_push', 'entry_swap', 'wrap_reverse')


def mem_disp(o):
    return o[4] if o and o[0] == 'm' else None


# (name, copy index, body key, insn, predicate, bytes from the instruction end, new byte)
BYTE_CONTROLS = (
    ('uint cmp 0x100', 0, 'uint', 'cmp', lambda i: i.b == ('i', 0x100) and i.size == 8, 3, 0x02),
    ('uint cmp 0x10000', 1, 'uint', 'cmp', lambda i: i.b == ('i', 0x10000) and i.size == 8, 2, 0x02),
    ('uint shr 0x20', 2, 'uint', 'shr', lambda i: i.b == ('i', 0x20), 1, 0x21),
    ('uint u16 marker', 0, 'uint', 'mov', lambda i: i.size == 1 and i.b == ('i', 0xcd), 1, 0xce),
    ('uint u64 room test', 1, 'uint', 'cmp', lambda i: i.b == ('i', 7) and i.size == 8, 1, 0x06),
    ('uint u32 room test', 2, 'uint', 'cmp', lambda i: i.b == ('i', 3) and i.size == 8, 1, 0x02),
    ('binhdr cmp 0x10000', 0, 'binhdr', 'cmp', lambda i: i.b == ('i', 0x10000) and i.size == 4, 2, 0x02),
    ('binhdr cmp 0x100', 1, 'binhdr', 'cmp', lambda i: i.b == ('i', 0x100) and i.size == 4, 3, 0x02),
    ('binhdr bin16 marker', 2, 'binhdr', 'mov', lambda i: i.size == 1 and i.b == ('i', 0xc6), 1, 0xc7),
    ('binhdr bin8 marker', 0, 'binhdr', 'mov', lambda i: i.a == ('r', 5) and i.b == ('i', 0xc4), 4, 0xc3),
    ('binhdr rol 8', 1, 'binhdr', 'rol', lambda i: i.b == ('i', 8), 1, 0x04),
    ('binhdr marker compare', 2, 'binhdr', 'cmp', lambda i: i.size == 1 and i.b == ('i', 0xc5), 1, 0xc6),
    ('key header result', 0, 'key', 'cmp', lambda i: i.b == ('i', 2) and i.size == 8, 1, 0x03),
    ('key ok word', 1, 'key', 'add', lambda i: i.a == ('r', 12) and i.b == ('i', 4), 1, 0x05),
    ('key hint load', 2, 'key', 'mov', lambda i: i.size == 4 and mem_disp(i.b) == 0x20, 1, 0x28),
    ('value ok word', 0, 'val', 'add', lambda i: i.a == ('r', 12) and i.b == ('i', 4), 1, 0x05),
    ('tuple writer load', 1, 'tup', 'mov', lambda i: i.a == ('r', 14) and mem_disp(i.b) == 0x18, 1, 0x20),
    ('tuple header result', 2, 'tup', 'cmp', lambda i: i.b == ('i', 2) and i.size == 8, 1, 0x03),
    ('end hint limit', 0, 'end', 'cmp', lambda i: i.size == 4 and i.b == ('i', 0x10), 1, 0x11),
    ('end ascii test', 1, 'end', 'cmp', lambda i: i.size == 1 and i.b == ('i', 0), 1, 0x01),
    ('end header result', 2, 'end', 'cmp', lambda i: i.b == ('i', 2) and i.size == 8, 1, 0x03),
    ('end ok word', 0, 'end', 'add', lambda i: i.a == ('r', 14) and i.b == ('i', 4), 1, 0x05),
    ('element flag compare', 0, 'elem', 'cmp', lambda i: i.size == 1 and i.b == ('i', 2), 1, 0x03),
    ('element pair marker', 1, 'elem', 'mov', lambda i: i.size == 1 and i.b == ('i', 0x92), 1, 0x93),
    ('element header size', 2, 'elem', 'mov', lambda i: i.a == ('r', 2) and i.b == ('i', 2), 4, 0x03),
    ('element ok word', 0, 'elem', 'lea', lambda i: mem_disp(i.b) == 4, 1, 0x05),
    ('wrapper slice scale', 0, 'wrap', 'shl', lambda i: i.a == ('r', 7) and i.b == ('i', 5), 1, 0x04),
    ('finish ok word', 1, 'fin', 'add', lambda i: i.a == ('r', 14) and i.b == ('i', 4), 1, 0x05),
)


def find_patch(image, by_start, cp, key, mn, pred, from_end, new):
    ent = cp[key]
    hits = [i for i in linear(image, ent, by_start[ent]['end']) if i.mn == mn and pred(i)]
    if not hits:
        raise Reject('no instruction for the control at 0x%x' % ent)
    ins = hits[0]
    return {ins.va + ins.length - from_end: new}


def control_cases():
    """Every fifth case plus the first 60 of each family and copy (boundary values come first)."""
    per = {}
    for n, (fam, ci, case) in enumerate(gen_cases()):
        k = per.get((fam, ci), 0)
        per[(fam, ci)] = k + 1
        if k < 60 or n % 5 == 0:
            yield fam, ci, case


def run_control(image, cover, patches=None, bad=None):
    """A mismatch (or a refusal) is seen: the wrong reconstruction or the corrupted bytes are caught."""
    img = image if not patches else PatchedImage(image.data, patches)
    for fam, ci, case in control_cases():
        try:
            got, exp, _ = run_case(img, cover, ci, case, bad)
            r = compare2(got, exp)
        except (Reject, Panic, KeyError, IndexError, ValueError) as e:
            return 'refused: %s' % str(e)[:60]
        if r:
            return r
    return None


def range_controls(image, by_start):
    rows = []
    try:
        check_input(b'not the capture')
        rows.append(('input digest', 0, 'accepted a wrong input'))
    except Reject as e:
        rows.append(('input digest', 1, str(e)))
    try:
        image.read(0x1, 4)
        rows.append(('address outside sections', 0, 'read succeeded'))
    except Reject as e:
        rows.append(('address outside sections', 1, str(e)))
    ent = COPIES[0]['uint']
    try:
        linear(image, ent, by_start[ent]['end'] - 1)
        rows.append(('short unwind extent', 0, 'decoded'))
    except Reject as e:
        rows.append(('short unwind extent', 1, str(e)))
    try:
        m = Machine(image, {COPIES[0]['key']}, {}, SLOT, set())
        setup_state(m, dict(cap=NICHE, buf=b'', hint=2))
        m.w64(ITEM, 5)
        write_writer(m, 8, b'', 0, 0, 0)
        m.regs[7], m.regs[6], m.regs[2] = OUT, ST, ITEM
        m.run(COPIES[0]['key'])
        rows.append(('unmodelled callee', 0, 'ran'))
    except Reject as e:
        rows.append(('unmodelled callee', 1, str(e)))
    try:
        m = Machine(image, real_set(), {}, SLOT, set())
        write_writer(m, 0, b'', 0, 0, 0)
        m.regs[7], m.regs[6], m.regs[2] = OUT, WR, 0x1234
        m.run(COPIES[0]['uint'])
        rows.append(('unmodelled allocator slot', 0, 'ran'))
    except Reject as e:
        rows.append(('unmodelled allocator slot', 1, str(e)))
    return rows


def check_input(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')


# ------------------------------------------------------------------ evidence

def tsv(header, rows):
    return '\n'.join(['\t'.join(header)] + ['\t'.join(str(c) for c in r) for r in rows]) + '\n'


def build(data, out):
    check_input(data)
    image = Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = dict((r['start'], r) for r in recs)
    derive_stage(image, by_start)
    cover = set()
    bodies = []
    for cp in COPIES:
        for key in BODY_KEYS:
            ent = cp[key]
            if ent not in by_start:
                raise Reject('0x%x is not an FDE start' % ent)
            bodies.append((cp['copy'], key, ent, linear(image, ent, by_start[ent]['end'])))
    slot_sites = {}
    for cp_, key, ent, rows in bodies:
        for r in rows:
            if r.mn in ('call_mem', 'jmp_mem'):
                slot_sites[r.a[4]] = slot_sites.get(r.a[4], 0) + 1
    unknown = sorted(set(slot_sites) - set(SLOT.values()))
    if unknown:
        raise Reject('unmodelled slot 0x%x' % unknown[0])
    rel = image.relative_addends(set(slot_sites))
    slot_rows = [('0x%x' % s, SLOT_NAMES[s], slot_sites[s], '0x%x' % rel[s][1] if s in rel else 'none')
                 for s in sorted(slot_sites)]
    role_rows = []
    for cp in COPIES:
        for role, how in (('key', 'first callee of the entry writer'), ('val', 'second callee of the entry writer'),
                          ('end', 'third callee of the entry writer'),
                          ('elem', 'only non-iterator callee of the sequence loop'),
                          ('uint', 'second callee of the key stage'), ('binhdr', 'first callee of the end stage'),
                          ('tup', 'third callee of the element writer'),
                          ('variant', 'second callee of the element writer (role stub)'),
                          ('setw', 'unique tail call of the tuple stage (role stub)')):
            role_rows.append((cp['copy'], role, '0x%x' % cp[role], how))
    digest = hashlib.sha256()
    case_rows, counts, steps_total = [], {}, 0
    total = mism = 0
    for n, (fam, ci, case) in enumerate(gen_cases()):
        got, exp, steps = run_case(image, cover, ci, case)
        r = compare2(got, exp)
        total += 1
        steps_total += steps
        if r:
            mism += 1
            if mism <= 5:
                print('MISMATCH', n, fam, ci + 1, case.get('mode'), case.get('plan'), r, file=sys.stderr)
        counts[fam] = counts.get(fam, 0) + 1
        digest.update(('%d|%s|%d|%d|%x|%d|%d|%d|%s' % (n, fam, ci + 1, steps, got['out'][0], got['cap'], len(got['data']),
                                                       len(got['log']), got['panic'] is not None)).encode())
        if n % 32 == 0:
            spec = case.get('iter') or case.get('value') or case.get('item3') or case.get('state') or ''
            case_rows.append((n, fam, ci + 1, case['mode'], json.dumps(spec, default=lambda o: o.hex() if isinstance(o, bytes) else str(o), sort_keys=True),
                              json.dumps(case['writer'][:1] + (len(case['writer'][1]),) + case['writer'][2:]),
                              json.dumps(case.get('plan')), case.get('alloc_fail', ''), steps, '%x' % got['out'][0],
                              got['cap'], len(got['data']), len(got['log']), 'ok' if not r else 'MISMATCH'))
    if mism:
        raise Reject('%d of %d cases differ from the reconstruction' % (mism, total))
    fun_rows, unexec, ins_rows = [], [], []
    for cp_, key, ent, rows in bodies:
        ex = sum(1 for r in rows if r.va in cover)
        if key in NEW_KEYS + ('wrap', 'fin'):
            for r in rows:
                ins_rows.append((NAMES[key], cp_, '0x%x' % ent, '0x%x' % r.va, r.length, r.raw.hex(), r.mn,
                                 '' if r.target is None else '0x%x' % r.target))
        fun_rows.append((NAMES[key], cp_, '0x%x' % ent, '0x%x' % by_start[ent]['end'], by_start[ent]['end'] - ent,
                         len(rows), ex, hashlib.sha256(image.read(ent, by_start[ent]['end'] - ent)).hexdigest()))
        if key in NEW_KEYS:
            for r in rows:
                if r.va not in cover and r.mn != 'nop':
                    unexec.append((NAMES[key], cp_, '0x%x' % ent, '0x%x' % r.va, r.mn))
    control_rows = []
    for name in MODEL_MUTANTS:
        r = run_control(image, set(), None, name)
        control_rows.append(('wrong reconstruction', name, int(r is not None), r or 'NOT DETECTED'))
    for name, ci, key, mn, pred, from_end, new in BYTE_CONTROLS:
        patch = find_patch(image, by_start, COPIES[ci], key, mn, pred, from_end, new)
        r = run_control(image, set(), patch)
        control_rows.append(('byte corruption', '%s (copy %d)' % (name, ci + 1), int(r is not None), r or 'NOT DETECTED'))
    for name, ok, why in range_controls(image, by_start):
        control_rows.append(('out of range input', name, ok, why))
    detected = sum(r[2] for r in control_rows)
    summary = dict(
        cases=total, case_families=dict(sorted(counts.items())),
        negative_controls=len(control_rows), negative_detected=detected, mismatches=mism,
        interpreted_steps=steps_total, all_cases_sha256=digest.hexdigest(),
        bodies=len(bodies), instructions=sum(len(b[3]) for b in bodies), executed_instructions=len(cover),
        unexecuted_new_instructions=len(unexec))
    files = {
        'functions.tsv': tsv(('role', 'copy', 'entry', 'end', 'bytes', 'instructions', 'executed', 'body_sha256'), fun_rows),
        'instructions.tsv': tsv(('role', 'copy', 'entry', 'va', 'length', 'raw', 'insn', 'target'), ins_rows),
        'stage-roles.tsv': tsv(('copy', 'role', 'entry', 'derivation'), role_rows),
        'slots.tsv': tsv(('slot', 'role', 'sites', 'relative_target'), slot_rows),
        'unexecuted.tsv': tsv(('role', 'copy', 'entry', 'va', 'insn'), unexec),
        'cases.tsv': tsv(('id', 'family', 'copy', 'mode', 'input', 'writer', 'plan', 'alloc_fail', 'steps', 'result0', 'cap',
                          'len', 'log_rows', 'verdict'), case_rows),
        'controls.tsv': tsv(('class', 'control', 'detected', 'first_reason'), control_rows),
        'summary.json': json.dumps(summary, indent=1, sort_keys=True) + '\n',
        'measure.json': json.dumps(dict(cases=total, negative_controls=len(control_rows), negative_detected=detected),
                                   indent=1, sort_keys=True) + '\n',
    }
    if detected != len(control_rows):
        raise Reject('a negative control was not detected: %s' % [r for r in control_rows if not r[2]])
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (out / name).write_text(files[name])
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, help='work-item folder that receives the generated evidence')
    args = ap.parse_args(argv)
    summary = build(TARGET.read_bytes(), args.out)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
