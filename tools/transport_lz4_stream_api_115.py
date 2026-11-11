#!/usr/bin/env python3
"""Reconstruct the node #115 native LZ4 stream-management entry points.

Python 3 standard library plus the repository ELF section reader only.  The
tool reads the pinned node #115 bytes, decodes the selected function bodies with
a small fixed-pattern x86-64 decoder, evaluates them concretely over generated
inputs (the target is never executed), and compares every outcome with an
independent Python re-implementation.  Output files are deterministic.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402

NODE_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
NODE_PATH = 'artifacts/node/115/hl-node'
M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
STEP_LIMIT = [400000]

# name -> start VA of the function body in node #115 (FDE starts, checked below)
FUNCTIONS = {
    'LZ4_compressBound': 0x62e5bf0,
    'LZ4_initStream': 0x62e5c20,
    'LZ4_createStream': 0x62e5c60,
    'LZ4_resetStream': 0x62e5c90,
    'LZ4_freeStream': 0x62e5ca0,
    'LZ4_loadDict': 0x62e5cd0,
    'LZ4_createStreamDecode': 0x62ed7a0,
    'LZ4_freeStreamDecode': 0x62ed7c0,
    'LZ4_setStreamDecode': 0x62ed7f0,
    'LZ4_freeStreamHC': 0x6300640,
    'LZ4_setCompressionLevel': 0x6300670,
    'LZ4_createStreamHC': 0x6300690,
    'LZ4_initStreamHC': 0x63006c0,
    'LZ4_resetStreamHC': 0x6300710,
}
# labels follow the vendored lz4 1.10.0 naming recorded by the vendor census;
# the bytes, not the labels, are what this tool evaluates.

CTX_SIZE = 0x4020
HC_SIZE = 0x40038
DICT_MAX = 0x10000
HASH_MUL = 0xcf1bbcdcbb000000
FAULT = 'fault'


class ToolError(Exception):
    pass


class Fault(Exception):
    """Evaluation left the supported byte patterns or the selected extents."""


def fail(message):
    raise ToolError(message)


def s32(v):
    v &= M32
    return v - (1 << 32) if v >> 31 else v


def s64(v):
    v &= M64
    return v - (1 << 64) if v >> 63 else v


# --------------------------------------------------------------------------
# image access
# --------------------------------------------------------------------------

class Image:
    def __init__(self, data):
        if hashlib.sha256(data).hexdigest() != NODE_SHA256:
            fail('input is not node #115 (SHA-256 mismatch)')
        self.data = data
        self.secs = [s for s in elf_index.sections(data) if s['type'] != 8]
        self.patches = {}
        self.cache = {}
        self.starts = self._fde_starts()
        self.plt = self._plt_names()

    def offset(self, va):
        for s in self.secs:
            if s['address'] and s['address'] <= va < s['address'] + s['size']:
                return va - s['address'] + s['offset']
        raise Fault(f'address {va:#x} outside every file-backed section')

    def byte(self, va):
        if va in self.patches:
            return self.patches[va]
        return self.data[self.offset(va)]

    def window(self, va, n=16):
        return bytes(self.byte(va + i) for i in range(n))

    def _section(self, name):
        for s in self.secs:
            if s['name'] == name:
                return s
        fail(f'missing section {name}')

    def _fde_starts(self):
        hdr = self._section('.eh_frame_hdr')
        off = hdr['offset']
        if self.data[off + 3] != 0x3b:
            fail('unexpected eh_frame_hdr table encoding')
        count = struct.unpack_from('<I', self.data, off + 8)[0]
        out = []
        for i in range(count):
            start = struct.unpack_from('<i', self.data, off + 12 + 8 * i)[0]
            out.append(start + hdr['address'])
        return sorted(set(out))

    def extent(self, start):
        i = bisect.bisect_left(self.starts, start)
        if i >= len(self.starts) - 1 or self.starts[i] != start:
            fail(f'{start:#x} is not an FDE start')
        return start, self.starts[i + 1]

    def _plt_names(self):
        rela = self._section('.rela.plt')
        symtab = self._section('.dynsym')
        strtab = self._section('.dynstr')
        slot_name = {}
        for i in range(rela['size'] // 24):
            slot, info, _ = struct.unpack_from('<QQq', self.data, rela['offset'] + 24 * i)
            if info & 0xffffffff != 7:
                continue
            sym = info >> 32
            name_off = struct.unpack_from('<I', self.data, symtab['offset'] + 24 * sym)[0]
            end = self.data.index(b'\0', strtab['offset'] + name_off)
            slot_name[slot] = self.data[strtab['offset'] + name_off:end].decode()
        plt = self._section('.plt')
        names = {}
        for va in range(plt['address'], plt['address'] + plt['size'], 16):
            o = va - plt['address'] + plt['offset']
            if self.data[o:o + 2] == b'\xff\x25':
                disp = struct.unpack_from('<i', self.data, o + 2)[0]
                slot = va + 6 + disp
                if slot in slot_name:
                    names[va] = slot_name[slot]
        return names


# --------------------------------------------------------------------------
# decoder: fixed byte patterns only
# --------------------------------------------------------------------------

REGS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g']
ALU = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']


class Insn:
    __slots__ = ('va', 'size', 'op', 'bits', 'dst', 'src', 'imm', 'cc', 'raw')

    def __init__(self, va, size, op, bits=64, dst=None, src=None, imm=0, cc=None):
        self.va, self.size, self.op, self.bits = va, size, op, bits
        self.dst, self.src, self.imm, self.cc = dst, src, imm, cc
        self.raw = b''

    def text(self):
        parts = [self.op if self.cc is None else self.op + self.cc, str(self.bits)]
        for field in (self.dst, self.src):
            parts.append('-' if field is None else field_text(field))
        parts.append(hex(self.imm & M64))
        return ' '.join(parts)


def field_text(f):
    if f[0] == 'r':
        return REGS[f[1]]
    if f[0] == 'm':
        _, base, index, scale, disp = f
        s = '[' + ('' if base is None else REGS[base])
        if index is not None:
            s += f'+{REGS[index]}*{scale}'
        return s + f'{disp:+#x}]'
    return str(f)


def modrm(img, p, rex):
    """Return (mod, reg, rm_operand, next_p)."""
    b = img.byte(p)
    mod, reg, rm = b >> 6, ((b >> 3) & 7) | ((rex & 4) << 1), b & 7
    p += 1
    if mod == 3:
        return mod, reg, ('r', rm | ((rex & 1) << 3)), p
    base = index = None
    scale = 1
    if rm == 4:
        sib = img.byte(p)
        p += 1
        scale = 1 << (sib >> 6)
        idx = ((sib >> 3) & 7) | ((rex & 2) << 2)
        if idx != 4:
            index = idx
        base = (sib & 7) | ((rex & 1) << 3)
        if sib & 7 == 5 and mod == 0:
            raise Fault('absolute sib base unsupported')
    elif rm == 5 and mod == 0:
        raise Fault('rip-relative operand unsupported in selected bodies')
    else:
        base = rm | ((rex & 1) << 3)
    disp = 0
    if mod == 1:
        disp = struct.unpack('<b', bytes([img.byte(p)]))[0]
        p += 1
    elif mod == 2:
        disp = struct.unpack('<i', img.window(p, 4))[0]
        p += 4
    return mod, reg, ('m', base, index, scale, disp), p


def decode(img, va):
    key = (va, tuple(sorted(img.patches.items())))
    hit = img.cache.get(key)
    if hit is None:
        hit = img.cache[key] = decode_uncached(img, va)
    return hit


def decode_uncached(img, va):
    p = va
    opsize16 = False
    rex = 0
    while True:
        b = img.byte(p)
        if b == 0x66:
            opsize16 = True
            p += 1
        elif b == 0xf3:
            p += 1
        else:
            break
    b = img.byte(p)
    if 0x40 <= b <= 0x4f:
        rex = b
        p += 1
        b = img.byte(p)
    wide = 64 if rex & 8 else (16 if opsize16 else 32)
    p += 1

    def done(op, **kw):
        ins = Insn(va, p - va, op, **kw)
        ins.raw = img.window(va, ins.size)
        return ins

    if b == 0x0f:
        b2 = img.byte(p)
        p += 1
        if b2 == 0x1e:  # endbr64 (f3 0f 1e fa)
            if img.byte(p) != 0xfa:
                raise Fault('unsupported 0f 1e form')
            p += 1
            return done('nop')
        if b2 == 0x1f:
            _, _, rm, p = modrm(img, p, rex)
            return done('nop')
        if 0x80 <= b2 <= 0x8f:
            rel = struct.unpack('<i', img.window(p, 4))[0]
            p += 4
            return done('jcc', cc=CC[b2 - 0x80], imm=p + rel)
        if 0x40 <= b2 <= 0x4f:
            _, reg, rm, p = modrm(img, p, rex)
            return done('cmov', bits=wide, dst=('r', reg), src=rm, cc=CC[b2 - 0x40])
        if b2 == 0xaf:
            _, reg, rm, p = modrm(img, p, rex)
            return done('imul2', bits=wide, dst=('r', reg), src=rm)
        raise Fault(f'unsupported 0f {b2:02x} at {va:#x}')
    if b in (0x31, 0x01, 0x29, 0x39, 0x85, 0x89, 0x21, 0x09):
        _, reg, rm, p = modrm(img, p, rex)
        op = {0x31: 'xor', 0x01: 'add', 0x29: 'sub', 0x39: 'cmp', 0x85: 'test',
              0x89: 'mov', 0x21: 'and', 0x09: 'or'}[b]
        return done(op, bits=wide, dst=rm, src=('r', reg))
    if b in (0x33, 0x03, 0x2b, 0x3b, 0x8b):
        _, reg, rm, p = modrm(img, p, rex)
        op = {0x33: 'xor', 0x03: 'add', 0x2b: 'sub', 0x3b: 'cmp', 0x8b: 'mov'}[b]
        return done(op, bits=wide, dst=('r', reg), src=rm)
    if b == 0x63:
        _, reg, rm, p = modrm(img, p, rex)
        return done('movsxd', bits=64, dst=('r', reg), src=rm)
    if b == 0x8d:
        _, reg, rm, p = modrm(img, p, rex)
        return done('lea', bits=wide, dst=('r', reg), src=rm)
    if b == 0x69:
        _, reg, rm, p = modrm(img, p, rex)
        imm = struct.unpack('<i', img.window(p, 4))[0]
        p += 4
        return done('imul3', bits=wide, dst=('r', reg), src=rm, imm=imm)
    if b in (0x81, 0x83):
        _, sub, rm, p = modrm(img, p, rex)
        sub &= 7
        if b == 0x83:
            imm = struct.unpack('<b', bytes([img.byte(p)]))[0]
            p += 1
        else:
            imm = struct.unpack('<i', img.window(p, 4))[0]
            p += 4
        return done(ALU[sub], bits=wide, dst=rm, imm=imm)
    if b == 0xc1:
        _, sub, rm, p = modrm(img, p, rex)
        imm = img.byte(p)
        p += 1
        op = {4: 'shl', 5: 'shr', 7: 'sar'}.get(sub & 7)
        if op is None:
            raise Fault('unsupported shift form')
        return done(op, bits=wide, dst=rm, imm=imm)
    if b == 0xf6:
        _, sub, rm, p = modrm(img, p, rex)
        if sub & 7 != 0:
            raise Fault('unsupported f6 form')
        imm = img.byte(p)
        p += 1
        return done('test8', bits=8, dst=rm, imm=imm)
    if b == 0xc7:
        _, sub, rm, p = modrm(img, p, rex)
        if sub & 7 != 0:
            raise Fault('unsupported c7 form')
        imm = struct.unpack('<i', img.window(p, 4))[0]
        p += 4
        return done('mov', bits=wide, dst=rm, imm=imm, src=('i',))
    if 0xb8 <= b <= 0xbf:
        reg = (b - 0xb8) | ((rex & 1) << 3)
        if rex & 8:
            imm = struct.unpack('<Q', img.window(p, 8))[0]
            p += 8
        else:
            imm = struct.unpack('<I', img.window(p, 4))[0]
            p += 4
        return done('mov', bits=wide, dst=('r', reg), imm=imm, src=('i',))
    if 0x50 <= b <= 0x57:
        return done('push', dst=('r', (b - 0x50) | ((rex & 1) << 3)))
    if 0x58 <= b <= 0x5f:
        return done('pop', dst=('r', (b - 0x58) | ((rex & 1) << 3)))
    if 0x70 <= b <= 0x7f:
        rel = struct.unpack('<b', bytes([img.byte(p)]))[0]
        p += 1
        return done('jcc', cc=CC[b - 0x70], imm=p + rel)
    if b == 0xe8:
        rel = struct.unpack('<i', img.window(p, 4))[0]
        p += 4
        return done('call', imm=p + rel)
    if b == 0xe9:
        rel = struct.unpack('<i', img.window(p, 4))[0]
        p += 4
        return done('jmp', imm=p + rel)
    if b == 0xeb:
        rel = struct.unpack('<b', bytes([img.byte(p)]))[0]
        p += 1
        return done('jmp', imm=p + rel)
    if b == 0xc3:
        return done('ret')
    if b == 0x90:
        return done('nop')
    if b == 0xcc:
        return done('int3')
    raise Fault(f'unsupported opcode {b:02x} at {va:#x}')


# --------------------------------------------------------------------------
# concrete evaluator with recorded external calls
# --------------------------------------------------------------------------

STACK_TOP = 0x7ff000000000
RETURN_MARK = 0x5eed00000000
HEAP_BASE = 0x20000000000


def provider_byte(seed, addr):
    """Deterministic pseudo-random byte for every address not yet written."""
    return ((addr * 0x9E3779B1 + seed * 0x85EBCA6B) >> 7) & 0xff


class Machine:
    def __init__(self, img, lo, hi, seed=1, malloc_fail=False):
        self.img = img
        self.lo, self.hi = lo, hi
        self.regs = [0] * 16
        self.regs[4] = STACK_TOP
        self.flags = {'zf': 0, 'sf': 0, 'cf': 0, 'of': 0}
        self.writes = {}
        self.fills = []
        self.trace = []
        self.seed = seed
        self.malloc_fail = malloc_fail
        self.heap = HEAP_BASE
        self.steps = 0
        self.max_steps = STEP_LIMIT[0]

    # memory ----------------------------------------------------------
    def load_byte(self, a):
        if a in self.writes:
            return self.writes[a]
        for lo, hi, v in reversed(self.fills):
            if lo <= a < hi:
                return v
        return provider_byte(self.seed, a)

    def load(self, a, n):
        return int.from_bytes(bytes(self.load_byte((a + i) & M64) for i in range(n)), 'little')

    def store(self, a, n, v, record=True):
        for i in range(n):
            self.writes[(a + i) & M64] = (v >> (8 * i)) & 0xff
        if record:
            self.trace.append(('store', a, n, v & ((1 << (8 * n)) - 1)))

    # operands --------------------------------------------------------
    def addr(self, m):
        _, base, index, scale, disp = m
        a = disp
        if base is not None:
            a += self.regs[base]
        if index is not None:
            a += self.regs[index] * scale
        return a & M64

    def read(self, f, bits, imm=0):
        mask = (1 << bits) - 1
        if f[0] == 'r':
            return self.regs[f[1]] & mask
        if f[0] == 'm':
            return self.load(self.addr(f), bits // 8)
        if f[0] == 'i':
            return imm & mask
        raise Fault('bad operand')

    def write(self, f, bits, v):
        v &= (1 << bits) - 1
        if f[0] == 'r':
            if bits == 64:
                self.regs[f[1]] = v
            elif bits == 32:
                self.regs[f[1]] = v
            else:
                self.regs[f[1]] = (self.regs[f[1]] & ~0xffff & M64) | v
        elif f[0] == 'm':
            self.store(self.addr(f), bits // 8, v)
        else:
            raise Fault('bad destination')

    def push(self, v):
        self.regs[4] = (self.regs[4] - 8) & M64
        self.store(self.regs[4], 8, v, record=False)

    def pop(self):
        v = self.load(self.regs[4], 8)
        self.regs[4] = (self.regs[4] + 8) & M64
        return v

    # flags -----------------------------------------------------------
    def set_logic(self, r, bits):
        r &= (1 << bits) - 1
        self.flags.update(zf=int(r == 0), sf=r >> (bits - 1), cf=0, of=0)

    def set_add(self, a, b, bits, sub, carry_in=0):
        m = (1 << bits) - 1
        if sub:
            r = (a - b) & m
            cf = int(a < b)
            of = int(((a ^ b) & (a ^ r)) >> (bits - 1) & 1)
        else:
            full = a + b
            r = full & m
            cf = int(full > m)
            of = int((~(a ^ b) & (a ^ r)) >> (bits - 1) & 1)
        self.flags.update(zf=int(r == 0), sf=r >> (bits - 1), cf=cf, of=of)
        return r

    def cond(self, cc):
        f = self.flags
        table = {
            'o': f['of'], 'no': 1 - f['of'], 'b': f['cf'], 'ae': 1 - f['cf'],
            'e': f['zf'], 'ne': 1 - f['zf'], 'be': f['cf'] | f['zf'],
            'a': 1 - (f['cf'] | f['zf']), 's': f['sf'], 'ns': 1 - f['sf'],
            'l': int(f['sf'] != f['of']), 'ge': int(f['sf'] == f['of']),
            'le': f['zf'] | int(f['sf'] != f['of']),
            'g': 1 - (f['zf'] | int(f['sf'] != f['of'])),
        }
        if cc not in table:
            raise Fault('parity condition unsupported')
        return table[cc]

    # external calls ---------------------------------------------------
    def external(self, name):
        r = self.regs
        if name == 'memset':
            p, v, n = r[7], r[6] & 0xff, r[2]
            self.trace.append(('memset', p, v, n))
            self.fills.append((p, p + n, v))
            r[0] = p
        elif name == 'malloc':
            self.trace.append(('malloc', r[7]))
            if self.malloc_fail:
                r[0] = 0
            else:
                r[0] = self.heap
                self.heap += (r[7] + 63) & ~63
        elif name == 'calloc':
            self.trace.append(('calloc', r[7], r[6]))
            if self.malloc_fail:
                r[0] = 0
            else:
                r[0] = self.heap
                n = r[7] * r[6]
                self.fills.append((self.heap, self.heap + n, 0))
                self.heap += (n + 63) & ~63
        elif name == 'free':
            self.trace.append(('free', r[7]))
            r[0] = 0
        else:
            raise Fault(f'unsupported import {name}')

    # execution -------------------------------------------------------
    def run(self, entry, args):
        order = [7, 6, 2, 1, 8, 9]
        for reg, v in zip(order, args):
            self.regs[reg] = v & M64
        self.push(RETURN_MARK)
        pc = entry
        while True:
            if pc == RETURN_MARK:
                return self.regs[0], self.trace
            self.steps += 1
            if self.steps > self.max_steps:
                raise Fault('step limit')
            if pc in self.img.plt:
                self.external(self.img.plt[pc])
                pc = self.pop()
                continue
            if not self.lo <= pc < self.hi:
                raise Fault(f'control left the selected extents at {pc:#x}')
            ins = decode(self.img, pc)
            pc = self.step(ins)

    def step(self, ins):
        op, bits = ins.op, ins.bits
        nxt = ins.va + ins.size
        r = self.regs
        mask = (1 << bits) - 1 if bits else 0
        if op == 'nop':
            return nxt
        if op == 'int3':
            raise Fault('int3 reached')
        if op in ('mov', 'xor', 'add', 'sub', 'cmp', 'test', 'and', 'or'):
            if ins.src is not None and ins.src[0] == 'i':
                src = ins.imm & mask
            elif ins.src is not None:
                src = self.read(ins.src, bits)
            else:
                src = ins.imm & mask
            if op == 'mov':
                self.write(ins.dst, bits, src)
                return nxt
            dst = self.read(ins.dst, bits)
            if op == 'cmp':
                self.set_add(dst, src, bits, True)
            elif op == 'test':
                self.set_logic(dst & src, bits)
            elif op == 'sub':
                self.write(ins.dst, bits, self.set_add(dst, src, bits, True))
            elif op == 'add':
                self.write(ins.dst, bits, self.set_add(dst, src, bits, False))
            else:
                res = {'xor': dst ^ src, 'and': dst & src, 'or': dst | src}[op]
                self.set_logic(res, bits)
                self.write(ins.dst, bits, res)
            return nxt
        if op == 'test8':
            self.set_logic(self.read(ins.dst, 8) & ins.imm, 8)
            return nxt
        if op == 'movsxd':
            v = self.read(ins.src, 32)
            self.write(ins.dst, 64, s32(v))
            return nxt
        if op == 'lea':
            self.write(ins.dst, bits, self.addr(ins.src))
            return nxt
        if op in ('imul3', 'imul2'):
            a = self.read(ins.src, bits)
            b = ins.imm & mask if op == 'imul3' else self.read(ins.dst, bits)
            sa = a - (1 << bits) if a >> (bits - 1) else a
            sb = b - (1 << bits) if b >> (bits - 1) else b
            full = sa * sb
            res = full & mask
            sres = res - (1 << bits) if res >> (bits - 1) else res
            ovf = int(sres != full)
            self.flags.update(cf=ovf, of=ovf)
            self.write(ins.dst, bits, res)
            return nxt
        if op in ('shl', 'shr', 'sar'):
            v = self.read(ins.dst, bits)
            n = ins.imm & (0x3f if bits == 64 else 0x1f)
            if op == 'shl':
                res = (v << n) & mask
            elif op == 'shr':
                res = v >> n
            else:
                sv = v - (1 << bits) if v >> (bits - 1) else v
                res = (sv >> n) & mask
            if n:
                self.set_logic(res, bits)
            self.write(ins.dst, bits, res)
            return nxt
        if op == 'cmov':
            if self.cond(ins.cc):
                self.write(ins.dst, bits, self.read(ins.src, bits))
            elif bits == 32:
                r[ins.dst[1]] &= M32
            return nxt
        if op == 'jcc':
            return ins.imm if self.cond(ins.cc) else nxt
        if op == 'jmp':
            return ins.imm
        if op == 'call':
            self.push(nxt)
            return ins.imm
        if op == 'ret':
            return self.pop()
        if op == 'push':
            self.push(r[ins.dst[1]])
            return nxt
        if op == 'pop':
            r[ins.dst[1]] = self.pop()
            return nxt
        raise Fault(f'unimplemented operation {op}')


# --------------------------------------------------------------------------
# independent specification (no use of the byte evaluator)
# --------------------------------------------------------------------------

def spec_bound(n):
    n &= M32
    if n > 0x7e000000:
        return 0, []
    return (n + n // 255 + 16) & M32, []


def spec_init(p, size):
    if size < CTX_SIZE or p == 0 or p & 7:
        return 0, []
    return p, [('memset', p, 0, CTX_SIZE)]


def spec_create(fail_alloc, heap=HEAP_BASE):
    t = [('malloc', CTX_SIZE)]
    if fail_alloc:
        return 0, t
    return heap, t + spec_init(heap, CTX_SIZE)[1]


def spec_reset(p):
    return p, [('memset', p, 0, CTX_SIZE)]


def spec_free(p):
    return 0, ([('free', p)] if p else [])


def spec_load_dict(ctx, dic, size, seed):
    size &= M32
    t = [('memset', ctx, 0, CTX_SIZE)]
    cur = 0x10000
    t.append(('store', ctx + 0x4010, 4, cur))
    ssize = s32(size)
    if ssize <= 7:
        return 0, t
    end = (dic + ssize) & M64
    p = dic
    n = ssize
    if ssize > DICT_MAX:
        p = (end - DICT_MAX) & M64
        n = DICT_MAX
    base = (end - cur) & M64
    t.append(('store', ctx + 0x4000, 8, p))
    t.append(('store', ctx + 0x4018, 4, n))
    t.append(('store', ctx + 0x4014, 4, 2))
    limit = (end - 8) & M64
    while p <= limit:
        word = sum(provider_byte(seed, p + i) << (8 * i) for i in range(8))
        h = ((word * HASH_MUL) & M64) >> 52
        t.append(('store', ctx + 4 * h, 4, (p - base) & M32))
        p = (p + 3) & M64
    return n, t


def spec_create_decode(fail_alloc):
    t = [('calloc', 1, 0x20)]
    return (0 if fail_alloc else HEAP_BASE), t


def spec_set_decode(p, dic, size):
    size &= M32
    ssize = s32(size)
    end = (dic + ssize) & M64 if ssize else dic
    t = [('store', p, 8, 0), ('store', p + 0x18, 8, ssize & M64),
         ('store', p + 0x10, 8, 0), ('store', p + 8, 8, end)]
    return 1, t


def spec_level(p, lvl):
    lvl = s32(lvl)
    v = 9 if lvl <= 0 else min(lvl, 12)
    return None, [('store', (p + 0x40024) & M64, 2, v)]


def spec_create_hc(fail_alloc):
    t = [('calloc', 1, HC_SIZE)]
    if fail_alloc:
        return 0, t
    return HEAP_BASE, t + spec_level(HEAP_BASE, 9)[1]


def spec_init_hc(p, size):
    if size < HC_SIZE:
        return 0, []
    if p == 0 or p & 7:
        return 0, []
    return p, [('memset', p, 0, 0x40030)] + spec_level(p, 9)[1]


def spec_reset_hc(p, lvl):
    # clears through the init body with the full size, then applies the level
    t = spec_init_hc(p, HC_SIZE)
    if t[0] == 0:
        return None, t[1] + spec_level(p, lvl)[1]
    return None, t[1][:1] + spec_level(p, 9)[1] + spec_level(p, lvl)[1]


# --------------------------------------------------------------------------
# case generation (deterministic)
# --------------------------------------------------------------------------

def signed_edges():
    base = [0, 1, 2, 7, 8, 9, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000, 0x10001,
            0x7e000000, 0x7e000001, 0x7fffffff, 0x80000000, 0xffffffff, 0xfffffff8]
    return base


class Case:
    __slots__ = ('func', 'args', 'seed', 'fail', 'expect', 'tag')

    def __init__(self, func, args, seed=1, fail=False, tag=''):
        self.func, self.args, self.seed, self.fail, self.tag = func, args, seed, fail, tag


def gen_cases(rng):
    cases = []
    add = cases.append
    # LZ4_compressBound: edges, divisor boundaries, random 32-bit
    for v in signed_edges():
        add(Case('LZ4_compressBound', (v,), tag='edge'))
    for k in range(0, 3000):
        add(Case('LZ4_compressBound', (255 * k + rng.choice((-1, 0, 1)) & M32,), tag='mul255'))
    for _ in range(2500):
        add(Case('LZ4_compressBound', (rng.getrandbits(32),), tag='rand32'))
    for _ in range(1500):
        add(Case('LZ4_compressBound', (0x7e000000 + rng.randint(-300, 300) & M32,), tag='cap'))
    # initStream / initStreamHC
    sizes = [0, 1, 0x401f, 0x4020, 0x4021, CTX_SIZE * 2, 1 << 40, M64]
    hc_sizes = [0, 0x40036, 0x40037, 0x40038, 0x40039, 1 << 40]
    ptrs = [0, 8, 0x1000, 0x1001, 0x1002, 0x1004, 0x1007, 0x1008, 0x7ff0, M64 & ~7]
    for p in ptrs:
        for s in sizes:
            add(Case('LZ4_initStream', (p, s), tag='grid'))
        for s in hc_sizes:
            add(Case('LZ4_initStreamHC', (p, s), tag='grid'))
    for _ in range(600):
        add(Case('LZ4_initStream', (rng.getrandbits(48) & ~rng.choice((0, 1, 2, 4, 7)),
                                    rng.choice(sizes) + rng.randint(-2, 2) & M64), tag='rand'))
        add(Case('LZ4_initStreamHC', (rng.getrandbits(48) & ~rng.choice((0, 1, 2, 4, 7)),
                                      rng.choice(hc_sizes) + rng.randint(-2, 2) & M64), tag='rand'))
    # create / free / reset
    for fail_alloc in (False, True):
        for name in ('LZ4_createStream', 'LZ4_createStreamDecode', 'LZ4_createStreamHC'):
            add(Case(name, (), fail=fail_alloc, tag='alloc'))
    for p in ptrs + [rng.getrandbits(47) for _ in range(300)]:
        for name in ('LZ4_freeStream', 'LZ4_freeStreamDecode', 'LZ4_freeStreamHC', 'LZ4_resetStream'):
            add(Case(name, (p,), tag='ptr'))
    # setCompressionLevel / resetStreamHC level clamp
    levels = list(range(-3, 20)) + [0x7fffffff, 0x80000000, 0xffffffff, 0x10000, 0xfffffff4, 0x8000000c]
    for lv in levels:
        add(Case('LZ4_setCompressionLevel', (0x4000, lv & M32), tag='level'))
    for _ in range(1500):
        add(Case('LZ4_setCompressionLevel', (rng.getrandbits(40) << 3, rng.getrandbits(32)), tag='level'))
    for p in (0x1000, 0x2008, 0x7ff8):
        for lv in levels:
            add(Case('LZ4_resetStreamHC', (p, lv & M32), tag='level'))
    for _ in range(800):
        add(Case('LZ4_resetStreamHC', (rng.getrandbits(40) << 3, rng.getrandbits(32)), tag='level'))
    # setStreamDecode
    for _ in range(2500):
        size = rng.choice((0, 1, 5, 0x7fffffff, 0x80000000, 0xffffffff, rng.getrandbits(32), rng.randint(0, 99999)))
        add(Case('LZ4_setStreamDecode', (rng.getrandbits(47) & ~7, rng.getrandbits(47), size), tag='decode'))
    # loadDict: small sizes dominate, a few at and beyond the 64 KiB window
    for size in list(range(0, 40)) + [0x10001, 0x80000000, 0xfffffffe]:
        for seed in ((1, 2) if size < 64 else (1,)):
            if size in (0x80000000, 0xfffffffe):
                add(Case('LZ4_loadDict', (0x5000, 0x100000, size), seed=seed, tag='dict'))
            elif size <= 0x10001:
                add(Case('LZ4_loadDict', (0x5000, 0x100000, size), seed=seed, tag='dict'))
    for _ in range(1500):
        size = rng.choice((rng.randint(0, 24), rng.randint(0, 300), rng.randint(0, 600)))
        add(Case('LZ4_loadDict', (rng.getrandbits(36) << 3, rng.getrandbits(44), size),
                 seed=rng.randint(1, 9), tag='dict'))
    for size in (0x10002, 0x20000):
        add(Case('LZ4_loadDict', (0x5000, 0x100000, size), seed=3, tag='bigdict'))
    return cases


SPEC = {
    'LZ4_compressBound': lambda c: spec_bound(c.args[0]),
    'LZ4_initStream': lambda c: spec_init(*c.args),
    'LZ4_createStream': lambda c: spec_create(c.fail),
    'LZ4_resetStream': lambda c: spec_reset(c.args[0]),
    'LZ4_freeStream': lambda c: spec_free(c.args[0]),
    'LZ4_loadDict': lambda c: spec_load_dict(c.args[0], c.args[1], c.args[2], c.seed),
    'LZ4_createStreamDecode': lambda c: spec_create_decode(c.fail),
    'LZ4_freeStreamDecode': lambda c: spec_free(c.args[0]),
    'LZ4_setStreamDecode': lambda c: spec_set_decode(*c.args),
    'LZ4_freeStreamHC': lambda c: spec_free(c.args[0]),
    'LZ4_setCompressionLevel': lambda c: spec_level(*c.args),
    'LZ4_createStreamHC': lambda c: spec_create_hc(c.fail),
    'LZ4_initStreamHC': lambda c: spec_init_hc(*c.args),
    'LZ4_resetStreamHC': lambda c: spec_reset_hc(*c.args),
}
# return values that the C prototype leaves unspecified (void functions)
VOID_RETURN = {'LZ4_setCompressionLevel', 'LZ4_resetStreamHC'}
# compressBound returns int; initStream results are pointers; the rest as noted
NARROW_RETURN = {'LZ4_compressBound': M32, 'LZ4_loadDict': M32, 'LZ4_setStreamDecode': M32}


def normalise(func, ret, trace):
    if func in VOID_RETURN:
        ret = None
    elif func in NARROW_RETURN:
        ret &= NARROW_RETURN[func]
    return ret, [tuple(t) for t in trace]


def run_target(img, case, spec=None):
    start, end = img.extent(FUNCTIONS[case.func])
    m = Machine(img, start, end + 0, seed=case.seed, malloc_fail=case.fail)
    # selected extents of internally called members are allowed through hi bound
    m.lo, m.hi = min(FUNCTIONS.values()) - 0x10, max(FUNCTIONS.values()) + 0x100
    ret, trace = m.run(start, case.args)
    return normalise(case.func, ret, trace)


def run_spec(case, spec):
    ret, trace = spec(case)
    return normalise(case.func, ret, trace)


def check_all(img, cases, spec_table):
    """Return (agreeing, total, first_mismatch, steps)."""
    ok = 0
    first = None
    for case in cases:
        try:
            got = run_target(img, case)
        except Fault as exc:
            got = (FAULT, str(exc))
        want = run_spec(case, spec_table[case.func])
        if got == want:
            ok += 1
        elif first is None:
            first = (case.func, case.args, case.seed)
    return ok, len(cases), first


# --------------------------------------------------------------------------
# negative controls
# --------------------------------------------------------------------------

def mutated_specs():
    """Deliberately wrong re-implementations, each paired with its function."""
    out = []

    def variant(label, func, fn):
        table = dict(SPEC)
        table[func] = fn
        out.append((label, func, table))

    variant('bound-divisor-256', 'LZ4_compressBound',
            lambda c: ((c.args[0] + c.args[0] // 256 + 16) & M32, []) if c.args[0] <= 0x7e000000 else (0, []))
    variant('bound-limit-inclusive', 'LZ4_compressBound',
            lambda c: ((c.args[0] + c.args[0] // 255 + 16) & M32, []) if c.args[0] < 0x7e000000 else (0, []))
    variant('bound-plus-17', 'LZ4_compressBound',
            lambda c: ((c.args[0] + c.args[0] // 255 + 17) & M32, []) if c.args[0] <= 0x7e000000 else (0, []))
    variant('init-size-gate-off-by-one', 'LZ4_initStream',
            lambda c: spec_init(c.args[0], c.args[1] + 1))
    variant('init-ignore-alignment', 'LZ4_initStream',
            lambda c: (c.args[0], [('memset', c.args[0], 0, CTX_SIZE)]) if c.args[1] >= CTX_SIZE and c.args[0] else (0, []))
    variant('init-short-clear', 'LZ4_initStream',
            lambda c: (lambda r: (r[0], [('memset', c.args[0], 0, CTX_SIZE - 8)] if r[1] else []))(spec_init(*c.args)))
    variant('create-no-init', 'LZ4_createStream',
            lambda c: (0, [('malloc', CTX_SIZE)]) if c.fail else (HEAP_BASE, [('malloc', CTX_SIZE)]))
    variant('free-null-calls-free', 'LZ4_freeStream', lambda c: (0, [('free', c.args[0])]))
    variant('level-cap-11', 'LZ4_setCompressionLevel',
            lambda c: (None, [('store', c.args[0] + 0x40024, 2, 9 if s32(c.args[1]) <= 0 else min(s32(c.args[1]), 11))]))
    variant('level-zero-keeps-zero', 'LZ4_setCompressionLevel',
            lambda c: (None, [('store', c.args[0] + 0x40024, 2, max(s32(c.args[1]), 0) if s32(c.args[1]) <= 12 else 12)]))
    variant('level-unsigned', 'LZ4_setCompressionLevel',
            lambda c: (None, [('store', c.args[0] + 0x40024, 2, 12 if c.args[1] > 12 else (9 if c.args[1] == 0 else c.args[1]))]))
    variant('dict-hash-shift-51', 'LZ4_loadDict', lambda c: spec_load_dict_shift(c, 51))
    variant('dict-step-two', 'LZ4_loadDict', lambda c: spec_load_dict_step(c, 2))
    variant('dict-window-256', 'LZ4_loadDict', lambda c: spec_load_dict_window(c, 256))
    variant('decode-unsigned-size', 'LZ4_setStreamDecode',
            lambda c: (1, [('store', c.args[0], 8, 0), ('store', c.args[0] + 0x18, 8, c.args[2] & M32),
                           ('store', c.args[0] + 0x10, 8, 0),
                           ('store', c.args[0] + 8, 8, (c.args[1] + (c.args[2] & M32)) & M64)]))
    variant('hc-init-wrong-limit', 'LZ4_initStreamHC', lambda c: spec_init_hc(c.args[0], c.args[1] + 8))
    variant('hc-create-level-10', 'LZ4_createStreamHC',
            lambda c: (lambda r: (r[0], r[1][:1] if not r[0] else r[1][:1] + [('store', r[0] + 0x40024, 2, 10)]))(spec_create_hc(c.fail)))
    return out


def _load_variant(c, shift=52, step=3, window=DICT_MAX):
    ctx, dic, size, seed = c.args[0], c.args[1], c.args[2], c.seed
    t = [('memset', ctx, 0, CTX_SIZE), ('store', ctx + 0x4010, 4, 0x10000)]
    ssize = s32(size)
    if ssize <= 7:
        return 0, t
    end = (dic + ssize) & M64
    p, n = dic, ssize
    if ssize > window:
        p, n = (end - window) & M64, window
    base = (end - 0x10000) & M64
    t += [('store', ctx + 0x4000, 8, p), ('store', ctx + 0x4018, 4, n), ('store', ctx + 0x4014, 4, 2)]
    while p <= (end - 8) & M64:
        word = sum(provider_byte(seed, p + i) << (8 * i) for i in range(8))
        h = ((word * HASH_MUL) & M64) >> shift
        t.append(('store', ctx + 4 * h, 4, (p - base) & M32))
        p = (p + step) & M64
    return n, t


def spec_load_dict_shift(c, shift):
    return _load_variant(c, shift=shift)


def spec_load_dict_step(c, step):
    return _load_variant(c, step=step)


def spec_load_dict_window(c, window):
    return _load_variant(c, window=window)


# byte damage: (label, function, va, xor mask) -- one byte of one instruction
BYTE_DAMAGE = [
    ('bound-cmp-immediate', 'LZ4_compressBound', 0x62e5bfb, 0x01),
    ('bound-branch-condition', 'LZ4_compressBound', 0x62e5bfc, 0x01),
    ('bound-add-constant', 'LZ4_compressBound', 0x62e5c1b, 0x01),
    ('bound-shift-count', 'LZ4_compressBound', 0x62e5c15, 0x01),
    ('init-size-gate', 'LZ4_initStream', 0x62e5c28, 0x01),
    ('init-null-test', 'LZ4_initStream', 0x62e5c30, 0x01),
    ('init-align-mask', 'LZ4_initStream', 0x62e5c37, 0x02),
    ('init-memset-length', 'LZ4_initStream', 0x62e5c3f, 0x01),
    ('create-malloc-size', 'LZ4_createStream', 0x62e5c66, 0x01),
    ('free-null-branch', 'LZ4_freeStream', 0x62e5ca7, 0x01),
    ('level-default', 'LZ4_setCompressionLevel', 0x630067a, 0x01),
    ('level-cap', 'LZ4_setCompressionLevel', 0x6300675, 0x01),
    ('level-store-offset', 'LZ4_setCompressionLevel', 0x630068b, 0x01),
    ('hc-calloc-size', 'LZ4_createStreamHC', 0x6300696, 0x01),
    ('hc-init-limit', 'LZ4_initStreamHC', 0x63006c7, 0x01),
    ('hc-memset-length', 'LZ4_initStreamHC', 0x63006df, 0x01),
    ('decode-store-offset', 'LZ4_setStreamDecode', 0x62ed800, 0x08),
    ('decode-cmov', 'LZ4_setStreamDecode', 0x62ed808, 0x01),
    ('dict-min-size', 'LZ4_loadDict', 0x62e5cfc, 0x01),
    ('dict-window', 'LZ4_loadDict', 0x62e5d0e, 0x01),
    ('dict-step', 'LZ4_loadDict', 0x62e5d50, 0x01),
    ('dict-multiplier', 'LZ4_loadDict', 0x62e5d3d, 0x01),
    ('dict-shift', 'LZ4_loadDict', 0x62e5d5b, 0x01),
    ('dict-table-scale', 'LZ4_loadDict', 0x62e5d5f, 0x01),
]


def run_controls(img, cases):
    rows = []
    by_func = {}
    for case in cases:
        by_func.setdefault(case.func, []).append(case)
    STEP_LIMIT[0] = 20000
    by_func['LZ4_loadDict'] = [c for c in by_func['LZ4_loadDict']
                               if c.args[2] <= 600 or c.args[2] >= 0x7ffffff0]
    for func in by_func:
        rest = by_func[func][60:]
        by_func[func] = by_func[func][:60] + rest[::max(1, len(rest) // 300)]
    for label, func, table in mutated_specs():
        ok, total, first = check_all(img, by_func[func], table)
        rows.append(('mutant-spec', label, func, int(ok != total), '' if first is None else repr(first)))
    for label, func, va, mask in BYTE_DAMAGE:
        original = img.byte(va)
        img.patches[va] = original ^ mask
        try:
            ok, total, first = check_all(img, by_func[func], SPEC)
        finally:
            del img.patches[va]
        rows.append(('byte-damage', label, func, int(ok != total), '' if first is None else repr(first)))
    # corrupted-input and out-of-range controls
    bad = bytearray(img.data[:4096])
    try:
        Image(bytes(bad))
        rows.append(('input', 'short-image-hash', '-', 0, ''))
    except ToolError:
        rows.append(('input', 'short-image-hash', '-', 1, 'rejected'))
    flipped = bytearray(img.data)
    flipped[len(flipped) // 2] ^= 1
    try:
        Image(bytes(flipped))
        rows.append(('input', 'flipped-byte-hash', '-', 0, ''))
    except ToolError:
        rows.append(('input', 'flipped-byte-hash', '-', 1, 'rejected'))
    try:
        img.extent(FUNCTIONS['LZ4_compressBound'] + 4)
        rows.append(('range', 'non-fde-start', '-', 0, ''))
    except ToolError:
        rows.append(('range', 'non-fde-start', '-', 1, 'rejected'))
    try:
        img.offset(0x7000000000)
        rows.append(('range', 'unmapped-va', '-', 0, ''))
    except Fault:
        rows.append(('range', 'unmapped-va', '-', 1, 'rejected'))
    m = Machine(img, 0x62e5bf0, 0x62e5c20)
    try:
        m.run(0x62e5c60, (0,))
        rows.append(('range', 'entry-outside-extents', '-', 0, ''))
    except Fault:
        rows.append(('range', 'entry-outside-extents', '-', 1, 'rejected'))
    return rows


# --------------------------------------------------------------------------
# evidence
# --------------------------------------------------------------------------

def listing(img):
    """Linear sweep of every selected extent; int3 padding is skipped."""
    rows = []
    for name, start in FUNCTIONS.items():
        lo, hi = img.extent(start)
        va = lo
        while va < hi:
            if img.byte(va) == 0xcc:
                va += 1
                continue
            ins = decode(img, va)
            rows.append((name, hex(va), ins.raw.hex(), ins.text()))
            va += ins.size
    return rows


def write_lines(path, header, rows):
    with path.open('w', newline='') as f:
        f.write('\t'.join(header) + '\n')
        for row in rows:
            f.write('\t'.join(str(x) for x in row) + '\n')


def generate(out):
    binary = ROOT / NODE_PATH
    img = Image(binary.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(115115)
    cases = gen_cases(rng)

    functions = []
    for name, start in FUNCTIONS.items():
        lo, hi = img.extent(start)
        body = bytes(img.byte(v) for v in range(lo, hi))
        functions.append({'name': name, 'start': hex(lo), 'end': hex(hi), 'bytes': hi - lo,
                          'sha256': hashlib.sha256(body).hexdigest()})
    plt = {hex(k): v for k, v in sorted(img.plt.items()) if v in ('memset', 'malloc', 'calloc', 'free')}

    sample_rows = []
    per_func = {}
    agree = 0
    for case in cases:
        try:
            got = run_target(img, case)
        except Fault as exc:
            got = (FAULT, str(exc))
        want = run_spec(case, SPEC[case.func])
        stats = per_func.setdefault(case.func, [0, 0])
        stats[1] += 1
        if got == want:
            agree += 1
            stats[0] += 1
        n = len(sample_rows)
        if stats[1] <= 12 or (stats[1] % 97 == 0 and n < 900):
            ret, trace = want
            digest = hashlib.sha256(repr((ret, trace)).encode()).hexdigest()[:16]
            sample_rows.append((case.func, ','.join(hex(a) for a in case.args), case.seed,
                                int(case.fail), case.tag, 'agree' if got == want else 'DIFF',
                                'none' if ret is None else hex(ret), len(trace), digest))
    controls = run_controls(img, cases)
    detected = sum(r[3] for r in controls)

    write_lines(out / 'instructions.tsv', ['function', 'va', 'bytes', 'decoded'], listing(img))
    write_lines(out / 'cases.tsv', ['function', 'args', 'seed', 'alloc_fails', 'class', 'verdict',
                                    'return', 'effects', 'effect_digest'], sample_rows)
    write_lines(out / 'controls.tsv', ['kind', 'label', 'function', 'detected', 'first_divergence'], controls)
    summary = {
        'target_sha256': NODE_SHA256,
        'functions': functions,
        'import_stubs': plt,
        'cases_total': len(cases),
        'cases_agree': agree,
        'per_function': {k: {'agree': v[0], 'total': v[1]} for k, v in sorted(per_func.items())},
        'sample_rows': len(sample_rows),
        'constants': {'stream_size': CTX_SIZE, 'hc_size': HC_SIZE, 'dict_window': DICT_MAX,
                      'hash_multiplier': hex(HASH_MUL), 'hash_shift': 52, 'bound_cap': hex(0x7e000000)},
    }
    (out / 'summary.json').write_bytes((json.dumps(summary, indent=2, sort_keys=True) + '\n').encode())
    measure = {'cases': len(cases), 'negative_controls': len(controls), 'negative_detected': detected,
               'cases_agree': agree}
    (out / 'measure.json').write_bytes((json.dumps(measure, indent=2, sort_keys=True) + '\n').encode())
    return summary, measure


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True, type=Path)
    args = ap.parse_args()
    summary, measure = generate(args.out)
    print(json.dumps(measure, sort_keys=True))
    if measure['cases_agree'] != measure['cases'] or measure['negative_detected'] != measure['negative_controls']:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
