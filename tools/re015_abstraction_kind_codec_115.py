#!/usr/bin/env python3
"""Reconstruct the node #115 seven-name abstraction-kind name decoder and prove it.

The producer authenticates the #115 capture, locates five selected visitor
bodies by their unwind (FDE) extents, and runs each body's original machine
code in a small interpreter for the fixed x86-64 instruction subset those
bodies use (including the four SSE2 forms of the 22-byte compares).  Every
interpreted result is compared with an independent pure-Python
reconstruction: an exact-name classifier over the seven names read from the
variant-name pool entry that the bodies pass to their unknown-variant error
callee.  The length jump tables and the variant pool entry are decoded from
the bytes and relocations.  Deliberately wrong reconstructions are run
through the same comparison and must be caught.

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
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
MASK = (1 << 64) - 1

NAMES = (b'Perp', b'Spot', b'Token', b'Pdi', b'ActivateDexAbstraction',
         b'ActivateUnifiedAccount', b'AllBoleTokens')
# &[&str; 7] entries passed to the unknown-variant callee (one per copy family)
VARIANT_POOLS = (0x642f400, 0x6476120, 0x649c2f8)

# Selected bodies: (role, entry VA).  Entries are FDE starts; the producer
# rejects the input if any entry is not an exact FDE start.
VISITORS_TAGGED = (0x23c65f0, 0x3bdd720, 0x4d6b5d0)   # writes word 0x09 | tag << 8
VISITORS_RESULT = (0x23c6720, 0x3bdd5e0)              # writes Result<u8, E> (byte 0 ok/err, byte 1 tag)
FUNCTIONS = ([('visitor_tagged', va) for va in VISITORS_TAGGED]
             + [('visitor_result', va) for va in VISITORS_RESULT])

# Interpreter memory regions (outside every mapped section of the capture).
IN_BASE = 0x1000_0000
OUT_BASE = 0x2000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
ERR_SENTINEL = 0xe770_0000_0000_0001


class Reject(Exception):
    pass


def u64(x):
    return x & MASK


def sx(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = [s for s in elf_index.sections(data) if s['type'] != 8 and s['address']]
        rela = [s for s in elf_index.sections(data) if s['type'] == 4 and s['name'] == '.rela.dyn']
        if len(rela) != 1:
            raise Reject('expected one .rela.dyn')
        self.rela = rela[0]

    def section_of(self, va):
        hits = [s for s in self.secs if s['address'] <= va < s['address'] + s['size']]
        if len(hits) != 1:
            raise Reject('VA 0x%x is not in exactly one file-backed section' % va)
        return hits[0]

    def read(self, va, n):
        s = self.section_of(va)
        if va + n > s['address'] + s['size']:
            raise Reject('read crosses section end at 0x%x' % va)
        off = s['offset'] + va - s['address']
        return self.data[off:off + n]

    def relative_addends(self, wanted):
        out = {}
        base, size = self.rela['offset'], self.rela['size']
        for pos in range(base, base + size - size % 24, 24):
            r_off, r_info, r_add = struct.unpack_from('<QQq', self.data, pos)
            if r_off in wanted and (r_info & 0xffffffff) == 8:
                if r_off in out:
                    raise Reject('duplicate relocation at 0x%x' % r_off)
                out[r_off] = (pos, r_add)
        return out


REG64 = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')


class Insn:
    __slots__ = ('va', 'length', 'raw', 'op', 'w', 'size', 'reg', 'rm', 'mem', 'imm', 'target', 'ext')

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


def decode(image, va):
    """Decode one instruction of the supported subset; raise Reject otherwise."""
    raw = image.read(va, 16)
    i = 0
    opsize16 = False
    rep = False
    if raw[i] == 0x66:
        opsize16 = True
        i += 1
    elif raw[i] == 0xf3:
        rep = True
        i += 1
    rex = 0
    if 0x40 <= raw[i] <= 0x4f:
        rex = raw[i]
        i += 1
    w = bool(rex & 8)
    rex_r, rex_x, rex_b = (rex >> 2) & 1, (rex >> 1) & 1, rex & 1
    op = raw[i]
    i += 1
    two = False
    if op == 0x0f:
        op = 0x0f00 | raw[i]
        i += 1
        two = True
    size = 8 if w else (2 if opsize16 else 4)

    def modrm():
        nonlocal i
        m = raw[i]
        i += 1
        mod, reg, rm = m >> 6, ((m >> 3) & 7) | (rex_r << 3), m & 7
        if mod == 3:
            return reg, ('reg', rm | (rex_b << 3)), (m >> 3) & 7
        base = index = None
        scale = 1
        disp = 0
        riprel = False
        if rm == 4:
            sib = raw[i]
            i += 1
            scale = 1 << (sib >> 6)
            idx = ((sib >> 3) & 7) | (rex_x << 3)
            index = None if idx == 4 else idx
            b = sib & 7
            if b == 5 and mod == 0:
                disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
                i += 4
            else:
                base = b | (rex_b << 3)
        elif rm == 5 and mod == 0:
            riprel = True
            disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
            i += 4
        else:
            base = rm | (rex_b << 3)
        if mod == 1:
            disp = sx(raw[i], 8)
            i += 1
        elif mod == 2:
            disp = sx(struct.unpack_from('<I', raw, i)[0], 32)
            i += 4
        return reg, ('mem', base, index, scale, disp, riprel), (m >> 3) & 7

    def imm(n):
        nonlocal i
        v = int.from_bytes(raw[i:i + n], 'little')
        i += n
        return v

    kw = dict(va=va, w=w, size=size)
    if not two and op in (0x01, 0x03, 0x09, 0x0b, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b, 0x85, 0x89, 0x8b, 0x88, 0x8d, 0x63):
        reg, rm, _ = modrm()
        names = {0x01: 'add', 0x03: 'add', 0x09: 'or', 0x0b: 'or', 0x29: 'sub', 0x2b: 'sub', 0x31: 'xor', 0x33: 'xor',
                 0x39: 'cmp', 0x3b: 'cmp', 0x85: 'test', 0x89: 'mov', 0x8b: 'mov', 0x88: 'mov', 0x8d: 'lea', 0x63: 'movsxd'}
        to_reg = op in (0x03, 0x0b, 0x2b, 0x33, 0x3b, 0x8b, 0x8d, 0x63)
        if op == 0x88:
            kw['size'] = 1
        if op == 0x63:
            if not w:
                raise Reject('movsxd without REX.W at 0x%x' % va)
        kw.update(op=names[op], reg=reg, rm=rm, ext='to_reg' if to_reg else 'to_rm')
    elif not two and op in (0x83, 0x81):
        reg, rm, sub = modrm()
        names = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}
        if sub not in names:
            raise Reject('unsupported group-1 form at 0x%x' % va)
        v = sx(imm(1), 8) if op == 0x83 else sx(imm(4), 32)
        kw.update(op=names[sub], rm=rm, imm=v, ext='imm')
    elif not two and op in (0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d):
        names = {0x05: 'add', 0x0d: 'or', 0x25: 'and', 0x2d: 'sub', 0x35: 'xor', 0x3d: 'cmp'}
        v = imm(2) if size == 2 else sx(imm(4), 32)
        kw.update(op=names[op], rm=('reg', 0), imm=v, ext='imm')
    elif not two and 0xb8 <= op <= 0xbf:
        r = (op - 0xb8) | (rex_b << 3)
        v = imm(8) if w else imm(4)
        kw.update(op='movimm', reg=r, imm=v, size=8 if w else 4)
    elif not two and 0xb0 <= op <= 0xb7:
        if not rex and op >= 0xb4:
            raise Reject('legacy high-byte register at 0x%x' % va)
        kw.update(op='movimm', reg=(op - 0xb0) | (rex_b << 3), imm=imm(1), size=1)
    elif not two and op in (0xc6, 0xc7):
        reg, rm, sub = modrm()
        if sub != 0:
            raise Reject('unsupported c6/c7 form at 0x%x' % va)
        if op == 0xc6:
            kw.update(op='mov', rm=rm, imm=imm(1), size=1, ext='imm')
        else:
            n = 2 if opsize16 else 4
            v = imm(n)
            if w:
                v = u64(sx(v, 32))
            kw.update(op='mov', rm=rm, imm=v, ext='imm')
    elif rep and not two:
        raise Reject('unsupported f3-prefixed opcode at 0x%x' % va)
    elif two and rep and op == 0x0f6f:
        reg, rm, _ = modrm()
        kw.update(op='movdqu', reg=reg, rm=rm, size=16)
    elif two and opsize16 and op in (0x0f74, 0x0fdb, 0x0fd7):
        reg, rm, _ = modrm()
        kw.update(op={0x0f74: 'pcmpeqb', 0x0fdb: 'pand', 0x0fd7: 'pmovmskb'}[op], reg=reg, rm=rm, size=16)
        if op == 0x0fd7 and rm[0] != 'reg':
            raise Reject('pmovmskb with memory operand at 0x%x' % va)
    elif rep or (two and opsize16):
        raise Reject('unsupported prefixed two-byte opcode at 0x%x' % va)
    elif two and op == 0x0fb6:
        reg, rm, _ = modrm()
        kw.update(op='movzx8', reg=reg, rm=rm)
    elif two and op == 0x0fb7:
        reg, rm, _ = modrm()
        kw.update(op='movzx16', reg=reg, rm=rm)
    elif not two and op in (0x74, 0x75, 0x72, 0x73, 0x76, 0x77, 0xeb):
        rel = sx(imm(1), 8)
        kw.update(op={0x74: 'je', 0x75: 'jne', 0x72: 'jb', 0x73: 'jae', 0x76: 'jbe', 0x77: 'ja', 0xeb: 'jmp'}[op])
        kw['target'] = va + i + rel
    elif two and op in (0x0f84, 0x0f85, 0x0f82, 0x0f83, 0x0f86, 0x0f87):
        rel = sx(imm(4), 32)
        kw.update(op={0x0f84: 'je', 0x0f85: 'jne', 0x0f82: 'jb', 0x0f83: 'jae', 0x0f86: 'jbe', 0x0f87: 'ja'}[op])
        kw['target'] = va + i + rel
    elif not two and op in (0xe8, 0xe9):
        rel = sx(imm(4), 32)
        kw.update(op='call' if op == 0xe8 else 'jmp')
        kw['target'] = va + i + rel
    elif not two and op == 0xff:
        reg, rm, sub = modrm()
        if sub == 4:
            kw.update(op='jmpind', rm=rm, size=8)
        elif sub == 0:
            kw.update(op='inc', rm=rm)
        else:
            raise Reject('unsupported ff form at 0x%x' % va)
    elif not two and 0x50 <= op <= 0x57:
        kw.update(op='push', reg=(op - 0x50) | (rex_b << 3))
    elif not two and 0x58 <= op <= 0x5f:
        kw.update(op='pop', reg=(op - 0x58) | (rex_b << 3))
    elif not two and op == 0xc3:
        kw.update(op='ret')
    else:
        raise Reject('unsupported opcode 0x%x at 0x%x' % (op, va))
    kw['length'] = i
    kw['raw'] = bytes(raw[:i])
    if kw.get('rm') and kw['rm'][0] == 'mem' and kw['rm'][5]:
        kw['rm'] = ('mem', None, None, 1, va + i + kw['rm'][4], True)
    return Insn(**kw)


class Machine:
    """Interpreter for the decoded subset.  Flags kept: ZF and CF."""

    def __init__(self, image, stubs):
        self.image = image
        self.stubs = stubs
        self.regs = {n: 0 for n in range(16)}
        self.xmm = {n: 0 for n in range(16)}
        self.mem = {}
        self.zf = self.cf = False
        self.calls = []
        self.trace = []

    def load(self, addr, n):
        out = bytearray()
        for k in range(n):
            a = addr + k
            if a in self.mem:
                out.append(self.mem[a])
            elif a < 0x1000_0000 or a >= 0x8000_0000:
                out += self.image.read(a, 1)
            else:
                raise Reject('read of unset scratch byte 0x%x' % a)
        return int.from_bytes(out, 'little')

    def store(self, addr, value, n):
        if not (0x1000_0000 <= addr and addr + n <= 0x8000_0000):
            raise Reject('store outside scratch memory at 0x%x' % addr)
        for k, b in enumerate(int(value & ((1 << (8 * n)) - 1)).to_bytes(n, 'little')):
            self.mem[addr + k] = b

    def ea(self, rm):
        _, base, index, scale, disp, riprel = rm
        if riprel:
            return disp
        a = disp
        if base is not None:
            a += self.regs[base]
        if index is not None:
            a += self.regs[index] * scale
        return u64(a)

    def get(self, rm, size):
        if rm[0] == 'reg':
            return self.regs[rm[1]] & ((1 << (8 * size)) - 1)
        return self.load(self.ea(rm), size)

    def put(self, rm, value, size):
        value &= (1 << (8 * size)) - 1
        if rm[0] == 'reg':
            r = rm[1]
            if size >= 4:
                self.regs[r] = value  # 32-bit writes zero-extend
            else:
                keep = MASK ^ ((1 << (8 * size)) - 1)
                self.regs[r] = (self.regs[r] & keep) | value
        else:
            self.store(self.ea(rm), value, size)

    def setflags(self, result, size, cf=False):
        m = (1 << (8 * size)) - 1
        self.zf = (result & m) == 0
        self.cf = cf

    def run(self, entry, limit=400):
        self.regs[4] = STACK_TOP
        self.regs[4] -= 8
        self.store(self.regs[4], RETURN_SENTINEL, 8)
        pc = entry
        for _ in range(limit):
            ins = decode(self.image, pc)
            self.trace.append(pc)
            nxt = pc + ins.length
            op, size = ins.op, ins.size
            m = (1 << (8 * size)) - 1
            if op in ('add', 'sub', 'cmp', 'xor', 'or', 'and', 'test'):
                if ins.ext == 'imm':
                    a, b, dst = self.get(ins.rm, size), ins.imm & m, ins.rm
                elif ins.ext == 'to_reg':
                    a, b, dst = self.regs[ins.reg] & m, self.get(ins.rm, size), ('reg', ins.reg)
                else:
                    a, b, dst = self.get(ins.rm, size), self.regs[ins.reg] & m, ins.rm
                if op == 'add':
                    r = a + b
                    self.setflags(r, size, r > m)
                    self.put(dst, r, size)
                elif op in ('sub', 'cmp'):
                    r = (a - b) & m
                    self.setflags(r, size, a < b)
                    if op == 'sub':
                        self.put(dst, r, size)
                elif op == 'test':
                    self.setflags(a & b, size)
                else:
                    r = {'xor': a ^ b, 'or': a | b, 'and': a & b}[op]
                    self.setflags(r, size)
                    self.put(dst, r, size)
            elif op == 'mov':
                if ins.ext == 'imm':
                    self.put(ins.rm, ins.imm, size)
                elif ins.ext == 'to_reg':
                    self.put(('reg', ins.reg), self.get(ins.rm, size), size)
                else:
                    self.put(ins.rm, self.regs[ins.reg], size)
            elif op == 'movimm':
                self.put(('reg', ins.reg), ins.imm, max(size, 4) if size != 1 else 1)
            elif op == 'lea':
                self.put(('reg', ins.reg), self.ea(ins.rm), size)
            elif op == 'movsxd':
                self.regs[ins.reg] = u64(sx(self.get(ins.rm, 4), 32))
            elif op == 'movzx8':
                self.put(('reg', ins.reg), self.get(ins.rm, 1), size)
            elif op == 'movzx16':
                self.put(('reg', ins.reg), self.get(ins.rm, 2), size)
            elif op in ('movdqu', 'pcmpeqb', 'pand'):
                src = self.xmm[ins.rm[1]] if ins.rm[0] == 'reg' else self.load(self.ea(ins.rm), 16)
                if op == 'movdqu':
                    self.xmm[ins.reg] = src
                elif op == 'pand':
                    self.xmm[ins.reg] &= src
                else:
                    a = self.xmm[ins.reg]
                    self.xmm[ins.reg] = sum((0xff << (8 * k)) for k in range(16)
                                            if (a >> (8 * k)) & 0xff == (src >> (8 * k)) & 0xff)
            elif op == 'pmovmskb':
                v = self.xmm[ins.rm[1]]
                self.regs[ins.reg] = sum(1 << k for k in range(16) if (v >> (8 * k + 7)) & 1)
            elif op == 'inc':
                r = (self.get(ins.rm, size) + 1) & m
                self.zf = r == 0
                self.put(ins.rm, r, size)
            elif op in ('je', 'jne', 'jb', 'jae', 'jbe', 'ja'):
                take = {'je': self.zf, 'jne': not self.zf, 'jb': self.cf, 'jae': not self.cf,
                        'jbe': self.cf or self.zf, 'ja': not (self.cf or self.zf)}[op]
                if take:
                    nxt = ins.target
            elif op == 'jmp':
                nxt = ins.target
            elif op == 'jmpind':
                nxt = self.get(ins.rm, 8)
            elif op == 'push':
                self.regs[4] -= 8
                self.store(self.regs[4], self.regs[ins.reg], 8)
            elif op == 'pop':
                self.regs[ins.reg] = self.load(self.regs[4], 8)
                self.regs[4] += 8
            elif op == 'call':
                if ins.target not in self.stubs:
                    raise Reject('call to unmodelled target 0x%x at 0x%x' % (ins.target, pc))
                args = tuple(self.regs[r] for r in (7, 6, 2, 1, 8))
                self.calls.append((pc, ins.target, args))
                self.regs[0] = self.stubs[ins.target](self, args)
                for r in (1, 2, 6, 7, 8, 9, 10, 11):
                    self.regs[r] = 0x5c5c_5c5c_5c5c_5c5c  # caller-saved clobber
            elif op == 'ret':
                target = self.load(self.regs[4], 8)
                self.regs[4] += 8
                if target == RETURN_SENTINEL:
                    if self.regs[4] != STACK_TOP:
                        raise Reject('unbalanced stack at return 0x%x' % pc)
                    return
                raise Reject('return to unexpected address at 0x%x' % pc)
            else:
                raise Reject('no semantics for %s' % op)
            pc = nxt
        raise Reject('step limit reached')


def error_stub(machine, args):
    return ERR_SENTINEL


def callee_of(image, entry, end):
    """Every direct call target inside [entry, end) by linear decode."""
    out = []
    pc = entry
    while pc < end:
        if image.read(pc, 1) == b'\xcc':
            break
        ins = decode(image, pc)
        if ins.op == 'call':
            out.append((pc, ins.target))
        pc += ins.length
    return out


def linear(image, entry, end):
    rows = []
    pc = entry
    while pc < end:
        if image.read(pc, 1) == b'\xcc':
            if any(b != 0xcc for b in image.read(pc, end - pc)):
                raise Reject('non-int3 bytes after the body of 0x%x' % entry)
            break
        ins = decode(image, pc)
        rows.append(ins)
        pc += ins.length
    if pc > end:
        raise Reject('decode overran the FDE of 0x%x' % entry)
    return rows


# ---------------------------------------------------------------- reconstruction

def recon_classify(text):
    """Exact byte-for-byte match against the seven names; declaration order is the tag."""
    return NAMES.index(text) if text in NAMES else None


def recon_visitor_tagged(text):
    tag = recon_classify(text)
    if tag is None:
        return ('err', None)
    return ('ok', 0x09 | (tag << 8))


def recon_visitor_result(text):
    tag = recon_classify(text)
    if tag is None:
        return ('err', None)
    return ('ok', tag)


# Deliberately wrong reconstructions (negative controls).
def wrong_prefix(text):
    for k, n in enumerate(NAMES):
        if text[:len(n)] == n:
            return k
    return None


def wrong_casefold(text):
    low = [n.lower() for n in NAMES]
    return low.index(text.lower()) if text.lower() in low else None


def wrong_swap(text):
    t = recon_classify(text)
    return {4: 5, 5: 4}.get(t, t)


def wrong_low16(text):
    """Compares only the first 16 bytes of the 22-byte names (drops the [rsi+6] window)."""
    for k, n in enumerate(NAMES):
        if len(text) == len(n) and (text == n or (len(n) == 22 and text[:16] == n[:16])):
            return k
    return None


def wrong_bole_overlap(text):
    """Compares AllBoleTokens as two disjoint qwords at +0 and +8 only up to byte 12 exclusive."""
    for k, n in enumerate(NAMES):
        if len(text) == len(n) and (text == n or (k == 6 and text[:12] == n[:12])):
            return k
    return None


def wrong_order(text):
    """Tags assigned by name length order instead of declaration order."""
    t = recon_classify(text)
    if t is None:
        return None
    ranked = sorted(range(len(NAMES)), key=lambda i: (len(NAMES[i]), NAMES[i]))
    return ranked.index(t)


# ---------------------------------------------------------------- interpretation drivers

def run_visitor(image, entry, stubs, kind, text, pool):
    m = Machine(image, stubs)
    m.store(OUT_BASE, 0xa5a5_a5a5_a5a5_a5a5, 8)
    m.store(OUT_BASE + 8, 0xa5a5_a5a5_a5a5_a5a5, 8)
    # The bodies may read whole words past the end of a short input (for
    # example a 16-byte load at +6); pad with zero bytes so such reads are
    # defined.  Zero is not a byte of any name.
    for k in range(48):
        m.store(IN_BASE + k, 0x00, 1)
    for k, b in enumerate(text):
        m.store(IN_BASE + k, b, 1)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, len(text)
    m.run(entry)
    if kind == 'visitor_tagged':
        if m.calls:
            (site, target, args), = m.calls
            if args[:3] != (OUT_BASE, IN_BASE, len(text)) or args[3] != pool or args[4] != len(NAMES):
                raise Reject('error call arguments differ at 0x%x' % site)
            return ('err', None), m
        return ('ok', m.load(OUT_BASE, 2)), m
    flag = m.load(OUT_BASE, 1)
    if flag == 0 and not m.calls:
        return ('ok', m.load(OUT_BASE + 1, 1)), m
    if flag == 1 and m.load(OUT_BASE + 8, 8) == ERR_SENTINEL and len(m.calls) == 1:
        site, target, args = m.calls[0]
        if args[:4] != (IN_BASE, len(text), pool, len(NAMES)):
            raise Reject('error call arguments differ at 0x%x' % site)
        return ('err', None), m
    raise Reject('unrecognised visitor result')


# Replacement bytes for the single-position mutations: every printable ASCII
# byte plus the NUL, control, high-bit and all-ones edges.
MUTATION_BYTES = (0x00, 0x09, 0x0a) + tuple(range(0x20, 0x7f)) + (0x7f, 0x80, 0xc0, 0xff)


def visitor_inputs():
    seen = []
    have = set()

    def add(t):
        if t not in have:
            have.add(t)
            seen.append(t)
    add(b'')
    for n in NAMES:
        add(n)
        for k in range(len(n) + 1):
            add(n[:k])
        add(n + b'x')
        add(n + n[-1:])
        add(n.lower())
        add(n.upper())
        for pos in range(len(n)):
            for v in MUTATION_BYTES:
                add(n[:pos] + bytes([v]) + n[pos + 1:])
    for a in NAMES:
        for b in NAMES:
            if a != b:
                add(a[:len(a) // 2] + b[len(b) // 2:])
                if len(a) == len(b):
                    add(a[:4] + b[4:])
                    add(b[:16] + a[16:])
    for ln in range(0, 25):
        add(b'A' * ln)
    return seen


def esc(b):
    return b.hex()


def body_parts(rows):
    """First conditional jump target (reject arm), jump-table base and variant-pool lea."""
    ja = [r for r in rows if r.op == 'ja']
    leas = [r for r in rows if r.op == 'lea' and r.rm[5]]
    if not ja or len(leas) != 2:
        raise Reject('visitor prologue shape differs')
    return ja[0], leas[0], leas[1]


def build(data):
    if hashlib.sha256(data).hexdigest() != SHA115:
        raise Reject('input is not node #115')
    image = Image(data)
    _, recs, _ = fde_extents.fde_extents(data)
    by_start = {r['start']: r for r in recs}
    functions, insn_rows = [], []
    bodies = {}
    for role, va in FUNCTIONS:
        if va not in by_start:
            raise Reject('0x%x is not an FDE start' % va)
        rec = by_start[va]
        rows = linear(image, va, rec['end'])
        bodies[va] = (role, rec, rows)
        body = image.read(va, rec['end'] - va)
        calls = [(r.va, r.target) for r in rows if r.op == 'call']
        functions.append(dict(role=role, entry='0x%x' % va, fde_end='0x%x' % rec['end'], fde_bytes=rec['end'] - va,
                              decoded_instructions=len(rows), decoded_bytes=sum(r.length for r in rows),
                              lsda='none' if rec['lsda'] is None else '0x%x' % rec['lsda'],
                              sha256=hashlib.sha256(body).hexdigest(),
                              callees=','.join('0x%x' % t for t in sorted(set(t for _, t in calls)))))
        for r in rows:
            insn_rows.append((role, '0x%x' % va, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                              '' if r.target is None else '0x%x' % r.target))

    err_targets = sorted(set(t for va in VISITORS_TAGGED + VISITORS_RESULT
                             for _, t in callee_of(image, va, by_start[va]['end'])))
    stubs = {t: error_stub for t in err_targets}

    # Length dispatch: bound check (len - 3 > 0x13 rejects), then a rel32 table of 20 arms.
    jt_rows, var_rows, tables, pools = [], [], set(), {}
    for va in VISITORS_TAGGED + VISITORS_RESULT:
        rows = bodies[va][2]
        ja, jt_lea, pool_lea = body_parts(rows)
        cmp_rows = [r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.va < ja.va]
        sub_rows = [r for r in rows if r.op == 'lea' and not r.rm[5] and r.va < ja.va]
        if len(cmp_rows) != 1 or len(sub_rows) != 1:
            raise Reject('length bound shape differs at 0x%x' % va)
        low, span = -sub_rows[0].rm[4], cmp_rows[0].imm
        base = jt_lea.rm[4]
        for k in range(span + 1):
            rel = sx(struct.unpack('<I', image.read(base + 4 * k, 4))[0], 32)
            arm = u64(base + rel)
            names = [n.decode() for n in NAMES if len(n) == low + k]
            jt_rows.append(('0x%x' % va, '0x%x' % base, low + k, '0x%x' % (base + 4 * k), rel, '0x%x' % arm,
                            'reject' if arm == ja.target else 'compare',
                            ','.join(names) or '-'))
            if (arm == ja.target) != (not names):
                raise Reject('jump table arm for length %d disagrees with the name set' % (low + k))
        tables.add(pool_lea.rm[4])
        pools[va] = pool_lea.rm[4]
        var_rows.append(('0x%x' % va, '0x%x' % ja.va, '0x%x' % ja.target, low, low + span,
                         '0x%x' % jt_lea.va, '0x%x' % base, '0x%x' % pool_lea.va, '0x%x' % pool_lea.rm[4]))
    if tables != set(VARIANT_POOLS):
        raise Reject('variant pool references differ')

    # Variant-name pool entries: seven (ptr, len) slots each, ptr by R_X86_64_RELATIVE.
    table_rows = []
    for pool in VARIANT_POOLS:
        relocs = image.relative_addends({pool + 16 * k for k in range(len(NAMES))})
        texts = []
        for k in range(len(NAMES)):
            slot = pool + 16 * k
            if slot not in relocs:
                raise Reject('no RELATIVE relocation for variant slot 0x%x' % slot)
            pos, add = relocs[slot]
            ln = struct.unpack('<Q', image.read(slot + 8, 8))[0]
            text = image.read(add, ln)
            texts.append(text)
            table_rows.append(('0x%x' % pool, k, '0x%x' % slot, '0x%x' % pos, '0x%x' % add, ln, text.decode('ascii')))
        if tuple(texts) != NAMES:
            raise Reject('variant name pool 0x%x differs from reconstruction order' % pool)

    # Literal operands of the compare arms (immediates and rip-relative 16-byte constants).
    lit_rows = []
    for va in VISITORS_TAGGED + VISITORS_RESULT:
        for r in bodies[va][2]:
            if r.op == 'pcmpeqb' and r.rm[0] == 'mem':
                form, where, raw = 'xmm16', '0x%x' % r.rm[4], image.read(r.rm[4], 16)
            elif r.op in ('cmp', 'xor') and r.ext == 'imm':
                form, where = 'imm%d' % (8 * min(r.size, 4)), '-'
                raw = (r.imm & 0xffffffff).to_bytes(4, 'little').rstrip(b'\0')
            elif r.op == 'movimm' and r.size in (4, 8):
                form, where, raw = 'imm%d' % (8 * r.size), '-', r.imm.to_bytes(r.size, 'little').rstrip(b'\0')
            else:
                continue
            if raw and all(0x41 <= c <= 0x7a for c in raw):
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, form, where, raw.decode('ascii')))

    # Visitor comparison.
    inputs = visitor_inputs()
    vis_rows, vis_ok, vis_total = [], 0, 0
    neg_vis = {'prefix_match': [wrong_prefix, 0], 'case_fold': [wrong_casefold, 0],
               'swap_dex_unified': [wrong_swap, 0], 'low16_only_for_22_byte_names': [wrong_low16, 0],
               'bole_first12_only': [wrong_bole_overlap, 0], 'length_order_tags': [wrong_order, 0]}
    path_counts = {}
    for text in inputs:
        row = [esc(text) if text else '-', len(text)]
        want_tag = recon_classify(text)
        outcomes = []
        for va in VISITORS_TAGGED + VISITORS_RESULT:
            kind = 'visitor_tagged' if va in VISITORS_TAGGED else 'visitor_result'
            (status, value), m = run_visitor(image, va, stubs, kind, text, pools[va])
            want = recon_visitor_tagged(text) if kind == 'visitor_tagged' else recon_visitor_result(text)
            same = (status, value) == want
            vis_total += 1
            vis_ok += same
            key = (va, len(m.trace), status)
            path_counts[key] = path_counts.get(key, 0) + 1
            outcomes.append('%s:%s' % (status, '-' if value is None else '0x%x' % value))
            got_tag = None if status == 'err' else (value >> 8 if kind == 'visitor_tagged' else value)
            for k, item in neg_vis.items():
                if item[0](text) != got_tag:
                    item[1] += 1
            if not same:
                outcomes[-1] += '!'
        row += outcomes
        row.append('-' if want_tag is None else NAMES[want_tag].decode())
        row.append('match' if all(not o.endswith('!') for o in outcomes) else 'MISMATCH')
        vis_rows.append(tuple(row))

    paths = [('0x%x' % va, steps, status, n) for (va, steps, status), n in sorted(path_counts.items())]
    negatives = [('visitor', k, v[1], vis_total) for k, v in sorted(neg_vis.items())]
    accepted = sum(1 for r in vis_rows if r[-2] != '-')
    summary = dict(
        target='node115', sha256=SHA115, component='constants', task='RE-015',
        functions=len(FUNCTIONS), decoded_instructions=len(insn_rows),
        names=[n.decode() for n in NAMES], variant_pools=['0x%x' % p for p in VARIANT_POOLS],
        visitor_inputs=len(inputs), accepted_inputs=accepted, visitor_cases=vis_total, visitor_matches=vis_ok,
        error_callees=['0x%x' % t for t in err_targets],
        negative_controls={'%s/%s' % (a, b): n for a, b, n, _ in negatives},
        all_negative_controls_caught=all(n > 0 for _, _, n, _ in negatives),
        reconstruction_matches_all=(vis_ok == vis_total),
    )
    return dict(functions=functions, instructions=insn_rows, jump=jt_rows, dispatch=var_rows,
                variant_tables=table_rows, literals=lit_rows, visitor=vis_rows, paths=paths,
                negatives=negatives, summary=summary)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    f = result['functions']
    keys = list(f[0].keys())
    return {
        'functions.tsv': tsv(keys, [[row[k] for k in keys] for row in f]),
        'instructions.tsv': tsv(('role', 'function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'length-dispatch.tsv': tsv(('visitor', 'bound_ja', 'reject_arm', 'min_length', 'max_length', 'table_lea', 'table', 'pool_lea', 'pool'), result['dispatch']),
        'jump-table.tsv': tsv(('visitor', 'table', 'length', 'entry_va', 'rel32', 'arm', 'kind', 'names'), result['jump']),
        'variant-pool.tsv': tsv(('pool', 'index', 'slot', 'rela_file_offset', 'text_va', 'length', 'text'), result['variant_tables']),
        'compare-literals.tsv': tsv(('visitor', 'va', 'form', 'constant_va', 'bytes'), result['literals']),
        'visitor-cases.tsv': tsv(('input_hex', 'length') + tuple('0x%x' % v for v in VISITORS_TAGGED + VISITORS_RESULT) + ('reconstruction', 'verdict'), result['visitor']),
        'paths.tsv': tsv(('function', 'steps', 'status', 'inputs'), result['paths']),
        'negative-controls.tsv': tsv(('family', 'wrong_reconstruction', 'mismatching_cases', 'cases'), result['negatives']),
        'summary.json': json.dumps(result['summary'], indent=2, sort_keys=True) + '\n',
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True)
    ap.add_argument('--binary', default=str(TARGET))
    args = ap.parse_args(argv)
    data = Path(args.binary).read_bytes()
    try:
        result = build(data)
    except Reject as exc:
        print('rejected: %s' % exc, file=sys.stderr)
        return 1
    if not result['summary']['reconstruction_matches_all'] or not result['summary']['all_negative_controls_caught']:
        print('reconstruction or negative controls failed', file=sys.stderr)
        return 1
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render(result).items():
        (out / name).write_text(text, encoding='ascii', newline='\n')
    s = result['summary']
    print('visitor %d/%d, negatives caught: %s' % (
        s['visitor_matches'], s['visitor_cases'],
        s['all_negative_controls_caught']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
