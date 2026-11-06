#!/usr/bin/env python3
"""Reconstruct the node #115 HIP-3 DEX `disabled_state` name codec and prove it.

The per-DEX HIP-3 state record serializes a field `disabled_state` whose enum
has the four wire names Na, UserDisabled, ValidatorDisabled and m (tags 0..3
in declaration order; the visitors report "variant index 0 <= i < 4").  The
producer authenticates the #115 capture, locates fourteen bodies by their
unwind (FDE) extents and runs each body's original machine code in a small
interpreter for the fixed x86-64 instruction subset those bodies use:

* eight exact-name visitors in three copy families: `&str` visitors (tagged
  or Result output) and `&[u8]` visitors that dispatch on the input length
  through a 17-entry jump table (lengths 1..17), compare bytes, a word, a
  qword+dword pair or an SSE2 16+1-byte block, and otherwise report an
  unknown variant against the four-name pool (the `&[u8]` form first makes a
  lossy UTF-8 copy and frees it when owned);
* three serde_json unit-variant writers: a 4-entry jump table on the tag byte
  selects (name, length); each writes '"', the escaped name and '"' into the
  output Vec<u8>, growing it through the reserve callee when full;
* three rmp (MessagePack) writers of the enclosing per-DEX state record
  (last_settlement_time, deploy_time, n_reserve_deployments_used,
  disabled_state, m): a header call chosen by the serializer flag byte at
  +0xb, keys written only for flag 1 except the disabled_state key (any
  non-zero flag), the enum name via a 4-entry tag jump table, and every
  callee failure propagated into the 24-byte result.

Every interpreted result is compared with an independent pure-Python
reconstruction.  Visitor literals, all jump tables and the three name pools
(RELATIVE relocations) are decoded from the file bytes.  Deliberately wrong
reconstructions run through the same comparison and must be caught.

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

NAMES = (b'Na', b'UserDisabled', b'ValidatorDisabled', b'm')
# &[&str; 4] pools passed to the unknown-variant callees, one per copy family
VARIANT_POOLS = (0x644cbe8, 0x648a5b8, 0x64a9c70)
CODEC_NAMES = {'disabled_state': NAMES}
CODEC_POOLS = {'disabled_state': VARIANT_POOLS}

# (entry, family, input kind, output form, codec)
VISITORS = (
    (0x2b95310, 1, 'bytes', 'tagged', 'disabled_state'),
    (0x2b954f0, 1, 'str', 'result', 'disabled_state'),
    (0x2b955c0, 1, 'str', 'tagged', 'disabled_state'),
    (0x4446b40, 2, 'bytes', 'tagged', 'disabled_state'),
    (0x4446d20, 2, 'str', 'tagged', 'disabled_state'),
    (0x4446dd0, 2, 'str', 'result', 'disabled_state'),
    (0x546a1a0, 3, 'bytes', 'tagged', 'disabled_state'),
    (0x546a380, 3, 'str', 'tagged', 'disabled_state'),
)
# serde_json unit-variant writers: (entry, family)
WRITERS = (
    (0x2bc4310, 1),
    (0x44a0ca0, 2),
    (0x549f030, 3),
)
FUNCTIONS = ([('hip3_state_rmp_record_writer', va) for va in (0x2bc06a0, 0x449d950, 0x549b410)]
             + [('disabled_state_json_writer', va) for va, _ in WRITERS]
             + [('%s_visitor_%s_%s' % (codec, kind, form), va) for va, _, kind, form, codec in VISITORS])

IN_BASE = 0x1000_0000
OUT_BASE = 0x2000_0000
OWNED_BASE = 0x5000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
ERR_SENTINEL = 0xe770_0000_0000_0001
ERR_FILL = bytes(range(0xc0, 0xe0))
DE_BASE = 0x6000_0000
BORROWED = 0x8000000000000000
CLOBBER = 0x5c5c_5c5c_5c5c_5c5c


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
        self.cache = {}

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


class Insn:
    __slots__ = ('va', 'length', 'raw', 'op', 'w', 'size', 'reg', 'rm', 'imm', 'target', 'ext')

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


JCC8 = {0x74: 'je', 0x75: 'jne', 0x72: 'jb', 0x73: 'jae', 0x76: 'jbe', 0x77: 'ja', 0x7e: 'jle', 0x7f: 'jg',
        0xeb: 'jmp'}
JCC32 = {0x0f84: 'je', 0x0f85: 'jne', 0x0f82: 'jb', 0x0f83: 'jae', 0x0f86: 'jbe', 0x0f87: 'ja', 0x0f8e: 'jle',
         0x0f8f: 'jg'}


def decode(image, va):
    """Decode one instruction of the supported subset; raise Reject otherwise."""
    if va in image.cache:
        return image.cache[va]
    raw = image.read(va, 16)
    i = 0
    opsize16 = rep = False
    while raw[i] in (0x66, 0xf3):
        if raw[i] == 0x66:
            opsize16 = True
        else:
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
    if rep and not (two and op == 0x0f6f):
        raise Reject('unsupported f3 form at 0x%x' % va)
    if not two and op in (0x01, 0x03, 0x09, 0x0b, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b, 0x85, 0x89, 0x8b, 0x88, 0x8d, 0x63):
        reg, rm, _ = modrm()
        names = {0x01: 'add', 0x03: 'add', 0x09: 'or', 0x0b: 'or', 0x29: 'sub', 0x2b: 'sub', 0x31: 'xor', 0x33: 'xor',
                 0x39: 'cmp', 0x3b: 'cmp', 0x85: 'test', 0x89: 'mov', 0x8b: 'mov', 0x88: 'mov', 0x8d: 'lea', 0x63: 'movsxd'}
        to_reg = op in (0x03, 0x0b, 0x2b, 0x33, 0x3b, 0x8b, 0x8d, 0x63)
        if op == 0x88:
            kw['size'] = 1
            if not rex and (reg & 7) >= 4:
                raise Reject('legacy high-byte register at 0x%x' % va)
        if op == 0x63 and not w:
            raise Reject('movsxd without REX.W at 0x%x' % va)
        kw.update(op=names[op], reg=reg, rm=rm, ext='to_reg' if to_reg else 'to_rm')
    elif not two and op in (0x83, 0x81, 0x80):
        reg, rm, sub = modrm()
        names = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}
        if sub not in names:
            raise Reject('unsupported group-1 form at 0x%x' % va)
        if op == 0x80:
            kw['size'] = 1
            v = imm(1)
        elif op == 0x83:
            v = sx(imm(1), 8)
        else:
            v = sx(imm(2), 16) if opsize16 else sx(imm(4), 32)
        kw.update(op=names[sub], rm=rm, imm=v, ext='imm')
    elif not two and op in (0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d):
        v = sx(imm(2), 16) if opsize16 else sx(imm(4), 32)
        names = {0x05: 'add', 0x0d: 'or', 0x25: 'and', 0x2d: 'sub', 0x35: 'xor', 0x3d: 'cmp'}
        kw.update(op=names[op], rm=('reg', 0), imm=v, ext='imm')
    elif not two and op == 0xf7:
        reg, rm, sub = modrm()
        if sub != 3:
            raise Reject('unsupported f7 form at 0x%x' % va)
        kw.update(op='neg', rm=rm)
    elif two and op == 0x0fa3:
        reg, rm, _ = modrm()
        if rm[0] != 'reg':
            raise Reject('bt on memory at 0x%x' % va)
        kw.update(op='bt', reg=reg, rm=rm)
    elif not two and op == 0xc0:
        reg, rm, sub = modrm()
        if sub != 4:
            raise Reject('unsupported c0 form at 0x%x' % va)
        kw.update(op='shl', rm=rm, imm=imm(1), size=1, ext='imm')
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
    elif two and op in (0x0fb6, 0x0fb7):
        reg, rm, _ = modrm()
        kw.update(op='movzx8' if op == 0x0fb6 else 'movzx16', reg=reg, rm=rm)
    elif two and op in (0x0f10, 0x0f11) and not opsize16:
        reg, rm, _ = modrm()
        kw.update(op='movups_load' if op == 0x0f10 else 'movups_store', reg=reg, rm=rm, size=16)
    elif two and op == 0x0f6f and rep:
        reg, rm, _ = modrm()
        kw.update(op='movups_load', reg=reg, rm=rm, size=16)
    elif two and op == 0x0f6e and opsize16:
        reg, rm, _ = modrm()
        kw.update(op='movd', reg=reg, rm=rm, size=4)
    elif two and op in (0x0f74, 0x0fdb) and opsize16:
        reg, rm, _ = modrm()
        kw.update(op='pcmpeqb' if op == 0x0f74 else 'pand', reg=reg, rm=rm, size=16)
    elif two and op == 0x0fd7 and opsize16:
        reg, rm, _ = modrm()
        if rm[0] != 'reg':
            raise Reject('pmovmskb from memory at 0x%x' % va)
        kw.update(op='pmovmskb', reg=reg, rm=rm, size=4)
    elif not two and op in JCC8:
        rel = sx(imm(1), 8)
        kw.update(op=JCC8[op])
        kw['target'] = va + i + rel
    elif two and op in JCC32:
        rel = sx(imm(4), 32)
        kw.update(op=JCC32[op])
        kw['target'] = va + i + rel
    elif not two and op in (0xe8, 0xe9):
        rel = sx(imm(4), 32)
        kw.update(op='call' if op == 0xe8 else 'jmp')
        kw['target'] = va + i + rel
    elif not two and op == 0xff:
        reg, rm, sub = modrm()
        if sub == 4:
            kw.update(op='jmpind', rm=rm, size=8)
        elif sub == 2:
            if rm[0] != 'mem' or not rm[5]:
                raise Reject('indirect call not through a rip slot at 0x%x' % va)
            kw.update(op='callslot', rm=rm, size=8)
        elif sub == 0:
            kw.update(op='inc', rm=rm)
        elif sub == 1:
            kw.update(op='dec', rm=rm)
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
    ins = Insn(**kw)
    image.cache[va] = ins
    return ins


class Machine:
    """Interpreter for the decoded subset.  Flags kept: ZF, CF, SF and OF."""

    def __init__(self, image, stubs):
        self.image = image
        self.stubs = stubs
        self.regs = {n: 0 for n in range(16)}
        self.xmm = {n: 0 for n in range(16)}
        self.mem = {}
        self.zf = self.cf = self.sf = self.of = False
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

    def xget(self, rm):
        if rm[0] == 'reg':
            return self.xmm[rm[1]]
        return self.load(self.ea(rm), 16)

    def setflags(self, result, size, cf=False, of=False):
        m = (1 << (8 * size)) - 1
        self.zf = (result & m) == 0
        self.sf = bool((result >> (8 * size - 1)) & 1)
        self.cf = cf
        self.of = of

    def run(self, entry, limit=600):
        self.regs[4] = STACK_TOP - 8
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
                top = 1 << (8 * size - 1)
                if op == 'add':
                    r = a + b
                    self.setflags(r, size, r > m, bool(~(a ^ b) & (a ^ r) & top))
                    self.put(dst, r, size)
                elif op in ('sub', 'cmp'):
                    r = (a - b) & m
                    self.setflags(r, size, a < b, bool((a ^ b) & (a ^ r) & top))
                    if op == 'sub':
                        self.put(dst, r, size)
                elif op == 'test':
                    self.setflags(a & b, size)
                else:
                    r = {'xor': a ^ b, 'or': a | b, 'and': a & b}[op]
                    self.setflags(r, size)
                    self.put(dst, r, size)
            elif op == 'shl':
                a = self.get(ins.rm, size)
                n = ins.imm & 0x1f
                r = (a << n) & m
                self.setflags(r, size, bool(n and (a >> (8 * size - n)) & 1))
                self.put(ins.rm, r, size)
            elif op == 'mov':
                if ins.ext == 'imm':
                    self.put(ins.rm, ins.imm, size)
                elif ins.ext == 'to_reg':
                    self.put(('reg', ins.reg), self.get(ins.rm, size), size)
                else:
                    self.put(ins.rm, self.regs[ins.reg], size)
            elif op == 'movimm':
                self.put(('reg', ins.reg), ins.imm, size)
            elif op == 'lea':
                self.put(('reg', ins.reg), self.ea(ins.rm), size)
            elif op == 'movsxd':
                self.regs[ins.reg] = u64(sx(self.get(ins.rm, 4), 32))
            elif op == 'movzx8':
                self.put(('reg', ins.reg), self.get(ins.rm, 1), max(size, 4))
            elif op == 'movzx16':
                self.put(('reg', ins.reg), self.get(ins.rm, 2), max(size, 4))
            elif op == 'movups_load':
                self.xmm[ins.reg] = self.xget(ins.rm)
            elif op == 'movups_store':
                if ins.rm[0] == 'reg':
                    self.xmm[ins.rm[1]] = self.xmm[ins.reg]
                else:
                    self.store(self.ea(ins.rm), self.xmm[ins.reg], 16)
            elif op == 'movd':
                self.xmm[ins.reg] = self.get(ins.rm, 4)
            elif op == 'pcmpeqb':
                a, b = self.xmm[ins.reg], self.xget(ins.rm)
                r = 0
                for k in range(16):
                    if (a >> (8 * k)) & 0xff == (b >> (8 * k)) & 0xff:
                        r |= 0xff << (8 * k)
                self.xmm[ins.reg] = r
            elif op == 'pand':
                self.xmm[ins.reg] &= self.xget(ins.rm)
            elif op == 'pmovmskb':
                v = self.xmm[ins.rm[1]]
                self.regs[ins.reg] = sum(((v >> (8 * k + 7)) & 1) << k for k in range(16))
            elif op == 'neg':
                a = self.get(ins.rm, size)
                r = (-a) & m
                self.setflags(r, size, a != 0, a == (1 << (8 * size - 1)))
                self.put(ins.rm, r, size)
            elif op == 'bt':
                bit = self.regs[ins.reg] & (8 * size - 1)
                self.cf = bool((self.get(ins.rm, size) >> bit) & 1)
            elif op in ('inc', 'dec'):
                r = (self.get(ins.rm, size) + (1 if op == 'inc' else -1)) & m
                self.zf = r == 0
                self.sf = bool(r >> (8 * size - 1))
                self.put(ins.rm, r, size)
            elif op in ('je', 'jne', 'jb', 'jae', 'jbe', 'ja', 'jle', 'jg'):
                le = self.zf or (self.sf != self.of)
                take = {'je': self.zf, 'jne': not self.zf, 'jb': self.cf, 'jae': not self.cf,
                        'jbe': self.cf or self.zf, 'ja': not (self.cf or self.zf),
                        'jle': le, 'jg': not le}[op]
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
            elif op in ('call', 'callslot'):
                key = ins.target if op == 'call' else ('slot', ins.rm[4])
                if key not in self.stubs:
                    raise Reject('call to unmodelled target %s at 0x%x' % (key, pc))
                args = tuple(self.regs[r] for r in (7, 6, 2, 1, 8))
                self.calls.append((pc, key, args))
                res = self.stubs[key](self, args)
                for r in (1, 2, 6, 7, 8, 9, 10, 11):
                    self.regs[r] = CLOBBER  # caller-saved clobber
                if isinstance(res, tuple):
                    self.regs[0], self.regs[2] = res  # (rax, rdx) pair returns
                else:
                    self.regs[0] = res
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


# ---------------------------------------------------------------- stubs

def lossy_stub(machine, args):
    """from_utf8_lossy-shaped callee: writes Cow<str> (cap or borrowed niche, ptr, len) at rdi."""
    out, ptr, length = args[0], args[1], args[2]
    raw = bytes(machine.load(ptr + k, 1) for k in range(length))
    try:
        raw.decode('utf-8')
        cow = (BORROWED, ptr, length)
    except UnicodeDecodeError:
        text = raw.decode('utf-8', 'replace').encode('utf-8')
        for k, b in enumerate(text):
            machine.store(OWNED_BASE + k, b, 1)
        cow = (len(text), OWNED_BASE, len(text))
    for k, v in enumerate(cow):
        machine.store(out + 8 * k, v, 8)
    return out


def free_stub(machine, args):
    return 0


def unknown_ptr_stub(machine, args):
    return ERR_SENTINEL


def unknown_fill_stub(machine, args):
    for k, b in enumerate(ERR_FILL):
        machine.store(args[0] + k, b, 1)
    return args[0]


# ---------------------------------------------------------------- reconstruction

def recon_classify(text, names=NAMES):
    """Exact byte-for-byte match against the name set; declaration order is the tag."""
    return names.index(text) if text in names else None


def lossy(text):
    try:
        text.decode('utf-8')
        return text, False
    except UnicodeDecodeError:
        return text.decode('utf-8', 'replace').encode('utf-8'), True


def recon_visitor(kind, form, text, classify=recon_classify, names=NAMES):
    """Observable outcome of one visitor: (status, value, error text, freed owned copy)."""
    tag = classify(text, names)
    if tag is not None:
        return ('ok', tag if form == 'result' else 0x09 | (tag << 8), None, False)
    if kind == 'str':
        return ('err', None, text, False)
    shown, owned = lossy(text)
    return ('err', None, shown, owned)


# Deliberately wrong reconstructions (negative controls).
def wrong_prefix(text, names):
    for k, n in enumerate(names):
        if text[:len(n)] == n:
            return k
    return None


def wrong_casefold(text, names):
    low = [n.lower() for n in names]
    return low.index(text.lower()) if text.lower() in low else None


def wrong_swap(text, names):
    t = recon_classify(text, names)
    return {0: 1, 1: 0}.get(t, t)


def wrong_first4(text, names):
    """Compares only the first dword of each name (drops the trailing word/byte compares)."""
    for k, n in enumerate(names):
        if len(text) == len(n) and text[:4] == n[:4]:
            return k
    return None


def wrong_length_only(text, names):
    """Selects a name by the length gate alone (drops every byte compare)."""
    for k, n in enumerate(names):
        if len(text) == len(n):
            return k
    return None


def wrong_first_byte(text, names):
    """Selects a name by its length and first byte alone (drops the remaining compares)."""
    for k, n in enumerate(names):
        if len(text) == len(n) and text[:1] == n[:1]:
            return k
    return None


def wrong_raw_error(kind, form, text, names):
    tag = recon_classify(text, names)
    if tag is not None:
        return recon_visitor(kind, form, text, names=names)
    return ('err', None, text, False)


# ---------------------------------------------------------------- interpretation drivers

VEC = DE_BASE + 0x100
BUF_BASE = 0x3000_0000
BUF_STRIDE = 0x0100_0000


def grow_cap(cap, length, need):
    """Capacity policy of the reserve/escape stand-ins (amortized doubling)."""
    return max(cap * 2, length + need, 8)


class VecModel:
    """The output Vec<u8> {cap, ptr, len} the writer reaches through `*rsi`."""

    def __init__(self, machine, cap, prefix):
        self.m = machine
        self.moves = 0
        machine.store(DE_BASE, VEC, 8)
        machine.store(VEC, cap, 8)
        machine.store(VEC + 8, BUF_BASE, 8)
        machine.store(VEC + 0x10, len(prefix), 8)
        for k, b in enumerate(prefix):
            machine.store(BUF_BASE + k, b, 1)

    def state(self):
        return self.m.load(VEC, 8), self.m.load(VEC + 8, 8), self.m.load(VEC + 0x10, 8)

    def grow(self, need):
        cap, ptr, length = self.state()
        new_cap = grow_cap(cap, length, need)
        self.moves += 1
        new_ptr = BUF_BASE + BUF_STRIDE * self.moves
        for k in range(length):
            self.m.store(new_ptr + k, self.m.load(ptr + k, 1), 1)
        self.m.store(VEC, new_cap, 8)
        self.m.store(VEC + 8, new_ptr, 8)

    def content(self):
        cap, ptr, length = self.state()
        if length > cap:
            raise Reject('vector length exceeds capacity')
        return bytes(self.m.load(ptr + k, 1) for k in range(length))


def writer_stubs(roles, vec, events):
    def escape(machine, args):
        # format_escaped_str_contents stand-in: the four names need no escape
        if args[0] != VEC:
            raise Reject('escape callee writer argument differs')
        text = bytes(machine.load(args[1] + k, 1) for k in range(args[2]))
        if any(c < 0x20 or c in (0x22, 0x5c) or c >= 0x80 for c in text):
            raise Reject('escape callee would need escaping')
        cap, ptr, length = vec.state()
        if cap - length < len(text):
            vec.grow(len(text))
        cap, ptr, length = vec.state()
        for k, b in enumerate(text):
            machine.store(ptr + length + k, b, 1)
        machine.store(VEC + 0x10, length + len(text), 8)
        events.append(('escape', text))
        return 0

    def reserve(machine, args):
        cap, ptr, length = vec.state()
        if args != (VEC, length, 1, 1, 1):
            raise Reject('reserve callee arguments differ: %s' % (args,))
        events.append(('reserve', length))
        vec.grow(1)
        return 0
    table = {'escape_str': escape, 'reserve': reserve}
    return {k: table[v] for k, v in roles.items()}


def run_writer(image, entry, roles, tag, cap, prefix):
    events = []
    m = Machine(image, {})
    vec = VecModel(m, cap, prefix)
    m.stubs = writer_stubs(roles, vec, events)
    m.store(IN_BASE, tag, 1)
    for k in range(1, 8):
        m.store(IN_BASE + k, 0xa5, 1)
    m.regs[7], m.regs[6] = IN_BASE, DE_BASE
    m.run(entry, limit=200)
    if m.regs[0] != 0:
        raise Reject('writer 0x%x does not return Ok' % entry)
    return (vec.content(), tuple(events), vec.state()[0]), m


def recon_writer(tag, cap, prefix, names=NAMES, quote=b'"', grow_when_free=0, close=True):
    """Observable effect of one unit-variant writer: (bytes, events, final cap).
    Keyword arguments only exist for the negative controls."""
    buf = bytearray(prefix)
    events = []

    def put(byte):
        nonlocal cap
        if cap - len(buf) <= grow_when_free:
            events.append(('reserve', len(buf)))
            cap = grow_cap(cap, len(buf), 1)
        buf.extend(byte)
    put(quote)
    name = names[tag]
    if cap - len(buf) < len(name):
        cap = grow_cap(cap, len(buf), len(name))
    buf.extend(name)
    events.append(('escape', name))
    if close:
        put(quote)
    return bytes(buf), tuple(events), cap


def writer_inputs():
    """(tag, cap, prefix) triples: every tag, prefixes of growing length and
    capacities that leave 0, 1, 2, name-length and plenty of free bytes."""
    out = []
    for tag in range(len(NAMES)):
        n = len(NAMES[tag])
        for plen in range(0, 41):
            prefix = bytes((0x30 + (k * 7) % 0x4a) for k in range(plen))
            for slack in sorted(set((0, 1, 2, n, n + 1, n + 2, n + 3, 64))):
                out.append((tag, plen + slack, prefix))
    return out


WRITER_NEGATIVES = {
    'reversed_names': dict(names=tuple(reversed(NAMES))),
    'swap_user_validator': dict(names=(NAMES[0], NAMES[2], NAMES[1], NAMES[3])),
    'single_quote': dict(quote=b"'"),
    'no_closing_quote': dict(close=False),
    'grow_with_one_free_byte': dict(grow_when_free=1),
}


def show_writer(got):
    data, events, cap = got
    ev = ','.join('%s:%s' % (k, v.decode() if isinstance(v, bytes) else v) for k, v in events)
    return '%s|%s|cap=%d' % (data[-20:].decode('ascii'), ev, cap)


def run_visitor(image, entry, kind, form, codec, stubs, roles, text, pool):
    m = Machine(image, stubs)
    for k in range(32):
        m.store(OUT_BASE + k, 0xa5, 1)
    # Pad past the input so that any whole-word read is defined.  Zero is not
    # a byte of any name.
    for k in range(48):
        m.store(IN_BASE + k, 0x00, 1)
    for k, b in enumerate(text):
        m.store(IN_BASE + k, b, 1)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, len(text)
    m.run(entry)
    if m.regs[0] != OUT_BASE:
        raise Reject('visitor 0x%x does not return its output pointer' % entry)
    seq = [roles[key] for _, key, _ in m.calls]
    if not m.calls:
        if form == 'result':
            if m.load(OUT_BASE, 1) != 0:
                raise Reject('result visitor 0x%x wrote a non-Ok byte without an error call' % entry)
            return ('ok', m.load(OUT_BASE + 1, 1), None, False), m
        return ('ok', m.load(OUT_BASE, 2), None, False), m
    want_seq = (['lossy'] if kind == 'bytes' else []) + ['unknown_variant_' + form]
    if seq[:len(want_seq)] != want_seq or seq[len(want_seq):] not in ([], ['free']):
        raise Reject('visitor 0x%x call sequence %s' % (entry, seq))
    freed = seq[-1] == 'free'
    idx = len(want_seq) - 1
    site, key, args = m.calls[idx]
    if form == 'result':
        ptr, ln, got_pool, count = args[0], args[1], args[2], args[3]
    else:
        ptr, ln, got_pool, count = args[1], args[2], args[3], args[4]
    if (got_pool, count) != (pool, len(CODEC_NAMES[codec])):
        raise Reject('unknown-%s call arguments differ at 0x%x' % (codec, site))
    shown = bytes(m.load(ptr + k, 1) for k in range(ln))
    if kind == 'bytes':
        cow = m.calls[0][2][0]
        if ptr != m.load(cow + 8, 8) or ln != m.load(cow + 16, 8):
            raise Reject('visitor 0x%x does not report the converted text' % entry)
        if freed:
            fa = m.calls[-1][2]
            if (fa[0], fa[1], fa[2]) != (OWNED_BASE, m.load(cow, 8), 0):
                raise Reject('visitor 0x%x frees the wrong buffer' % entry)
    if form == 'result':
        if m.load(OUT_BASE, 1) != 1 or m.load(OUT_BASE + 8, 8) != ERR_SENTINEL:
            raise Reject('result visitor 0x%x does not store Err(error)' % entry)
    else:
        if bytes(m.load(OUT_BASE + k, 1) for k in range(32)) != ERR_FILL:
            raise Reject('tagged visitor 0x%x does not carry the 32-byte error' % entry)
    return ('err', None, shown, freed), m


MUTATION_BYTES = (0x00, 0x09, 0x0a, 0x80, 0xc3, 0xe2, 0xff) + tuple(range(0x20, 0x7f, 2))


def visitor_inputs():
    seen = []
    have = set()

    def add(t):
        if t not in have:
            have.add(t)
            seen.append(t)
    add(b'')
    every = NAMES
    for n in every:
        add(n)
        for k in range(len(n) + 1):
            add(n[:k])
        add(n + b'x')
        add(n + n[-1:])
        add(n + b'\0')
        add(n.lower())
        add(n.upper())
        add(n[:-1] + b'\xff')
        add(n[:1] + b'\xc3\xa9' + n[3:])
        for v in range(0x30, 0x3a):
            add(n[:3] + bytes([v]) + n[4:])
        for pos in range(len(n)):
            for v in MUTATION_BYTES:
                add(n[:pos] + bytes([v]) + n[pos + 1:])
            add(n[:pos] + bytes([n[pos] ^ 0x20]) + n[pos + 1:])
    for a in every:
        for b in every:
            if a != b:
                add(a[:len(a) // 2] + b[len(b) // 2:])
                add(a + b)
    for ln in range(0, 20):
        add(b'A' * ln)
        add(b'\x80' * ln)
    return seen


def esc(b):
    return b.hex() if b else '-'


# ---------------------------------------------------------------- msgpack record writer

# rmp record writers of the HIP-3 per-DEX state record that carries the enum:
# (entry, family).  Field keys are read from the bytes.
RECORDS = (
    (0x2bc06a0, 1),
    (0x449d950, 2),
    (0x549b410, 3),
)
REC_KEYS = (b'last_settlement_time', b'deploy_time', b'n_reserve_deployments_used', b'disabled_state', b'm')
OK_RESULT = 2                      # rmp write result: Ok
OK_NICHE = 0x8000000000000004      # Ok niche of the 24-byte field results
ERR_NICHE = 0x8000000000000000     # niche the record writer stores before an (rax, rdx) error
REC_ROLES = ('header_flag_nonzero', 'header_flag_zero', 'str', 'time_field', 'u64_field', 'u8_field')


def bind_record_roles(image, rows, va):
    """Name each record-writer callee from its call-site shape."""
    roles = {}

    def bind(key, role):
        if roles.get(key, role) != role:
            raise Reject('record callee 0x%x has two roles' % key)
        roles[key] = role
    calls = [k for k, r in enumerate(rows) if r.op == 'call']
    headers = []
    for n, k in enumerate(calls):
        r = rows[k]
        prev = rows[max(0, k - 6, calls[n - 1] + 1 if n else 0):k]
        if any(x.op == 'movimm' and x.reg == 2 and x.imm == len(REC_KEYS) for x in prev):
            headers.append(r.target)
        elif any(x.op == 'lea' and x.reg == 6 and x.rm[5] for x in prev):
            bind(r.target, 'str')
        elif any(x.op == 'movzx8' and x.reg == 2 for x in prev):
            bind(r.target, 'u8_field')
        elif any(x.op == 'mov' and x.ext == 'to_rm' and x.rm == ('reg', 2) and x.reg == 12 for x in prev):
            bind(r.target, 'u64_field')
        else:
            bind(r.target, 'time_field')
    if len(headers) != 2:
        raise Reject('record writer 0x%x has %d header calls' % (va, len(headers)))
    bind(headers[0], 'header_flag_nonzero')
    bind(headers[1], 'header_flag_zero')
    if sorted(roles.values()) != sorted(REC_ROLES):
        raise Reject('record writer 0x%x roles %s' % (va, sorted(roles.values())))
    return roles


def record_err(k):
    return (0x1000 * (k + 1) + 0x11, 0xe0 + k, 0xf0 + k)


def record_stubs(roles, fail_at, log):
    def nth():
        return len(log) - 1

    def header(role):
        return lambda machine, args: header_call(role, machine, args)

    def header_call(role, machine, args):
        if args[1] != DE_BASE:
            raise Reject('header serializer argument differs')
        log.append((role, args[2]))
        e = record_err(nth())
        if nth() == fail_at:
            machine.store(args[0], e[0], 8)
            machine.store(args[0] + 8, e[1], 8)
        else:
            machine.store(args[0], OK_RESULT, 8)
        return args[0]

    def text(machine, args):
        if args[0] != DE_BASE:
            raise Reject('str serializer argument differs')
        log.append(('str', bytes(machine.load(args[1] + k, 1) for k in range(args[2]))))
        e = record_err(nth())
        return (e[0], e[1]) if nth() == fail_at else (OK_RESULT, CLOBBER)

    def field(kind):
        def stub(machine, args):
            if args[1] != DE_BASE:
                raise Reject('%s serializer argument differs' % kind)
            if kind == 'time':
                # family 1 passes (vtable, 4, &field); family 2/3 pass &&field
                if STACK_TOP - 0x1000 <= args[2] < STACK_TOP:
                    ptr = machine.load(machine.load(args[2], 8), 8)
                else:
                    if args[3] != 4:
                        raise Reject('time serializer length argument differs')
                    ptr = args[4]
                log.append(('time', ptr - IN_BASE))
            elif kind == 'u64':
                log.append(('u64', args[2]))
            else:
                log.append(('u8', args[2] & 0xff))
            e = record_err(nth())
            if nth() == fail_at:
                for j, w in enumerate(e):
                    machine.store(args[0] + 8 * j, w, 8)
            elif kind == 'u64':
                machine.store(args[0], OK_RESULT, 8)
            else:
                machine.store(args[0], OK_NICHE, 8)
            return args[0]
        return stub
    table = {'header_flag_nonzero': header('header_flag_nonzero'), 'header_flag_zero': header('header_flag_zero'), 'str': text,
             'time_field': field('time'), 'u64_field': field('u64'), 'u8_field': field('u8')}
    return {k: table[v] for k, v in roles.items()}


def run_record(image, entry, roles, flag, tag, n_reserve, m_byte, fail_at):
    log = []
    m = Machine(image, record_stubs(roles, fail_at, log))
    for k in range(24):
        m.store(OUT_BASE + k, 0xa5, 1)
    m.store(IN_BASE, n_reserve, 8)
    for k in range(8, 0x20):
        m.store(IN_BASE + k, 0x40 + k, 1)
    m.store(IN_BASE + 0x20, tag, 1)
    m.store(IN_BASE + 0x21, m_byte, 1)
    for k in range(16):
        m.store(DE_BASE + k, 0x00, 1)
    m.store(DE_BASE + 0xb, flag, 1)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, DE_BASE
    m.run(entry, limit=400)
    if m.regs[0] != OUT_BASE:
        raise Reject('record writer 0x%x does not return its output pointer' % entry)
    out = tuple(m.load(OUT_BASE + 8 * j, 8) for j in range(3))
    if out[0] == OK_NICHE:
        out = (OK_NICHE,)
    return (out, tuple(log)), m


def recon_record(flag, tag, n_reserve, m_byte, fail_at, keys=REC_KEYS, names=NAMES, enum_key_rule='nonzero',
                 header_rule='nonzero', field_order=('time8', 'time20', 'u64', 'enum', 'u8')):
    """Observable effect of the record writer: (result words, callee log).
    Keyword arguments only exist for the negative controls."""
    log = []

    def call(entry, kind):
        log.append(entry)
        k = len(log) - 1
        if k != fail_at:
            return None
        e = record_err(k)
        if kind in ('header', 'u64', 'str'):
            return (ERR_NICHE, e[0], e[1])
        return e
    hdr = flag != 0 if header_rule == 'nonzero' else flag == 1
    err = call(('header_flag_nonzero' if hdr else 'header_flag_zero', len(keys)), 'header')
    if err:
        return err, tuple(log)
    for key, field in zip(keys, field_order):
        write_key = (flag != 0) if (field == 'enum' and enum_key_rule == 'nonzero') else (flag == 1)
        if write_key:
            err = call(('str', key), 'str')
            if err:
                return err, tuple(log)
        if field == 'time8':
            err = call(('time', 8), 'time')
        elif field == 'time20':
            err = call(('time', 0x14), 'time')
        elif field == 'u64':
            err = call(('u64', n_reserve), 'u64')
        elif field == 'enum':
            err = call(('str', names[tag]), 'str')
        else:
            err = call(('u8', m_byte), 'u8')
        if err:
            return err, tuple(log)
    return (OK_NICHE,), tuple(log)


RECORD_NEGATIVES = {
    'enum_key_only_when_flag_one': dict(enum_key_rule='one'),
    'header_nonzero_only_when_flag_one': dict(header_rule='one'),
    'reversed_variant_names': dict(names=tuple(reversed(NAMES))),
    'u64_before_times': dict(field_order=('u64', 'time8', 'time20', 'enum', 'u8')),
    'deploy_key_typo': dict(keys=(REC_KEYS[0], b'deploy_times') + REC_KEYS[2:]),
}


def record_inputs():
    out = []
    for flag in (0, 1, 2, 0xff):
        n_calls = 6 + (5 if flag == 1 else (1 if flag else 0))
        for tag in range(len(NAMES)):
            for n_reserve, m_byte in ((0, 0), (MASK, 1), (7, 0xff)):
                for fail_at in [None] + list(range(n_calls)):
                    out.append((flag, tag, n_reserve, m_byte, fail_at))
    return out


def show_record(got):
    words, log = got
    parts = []
    for e in log:
        v = e[1]
        parts.append('%s:%s' % (e[0], v.decode() if isinstance(v, bytes) else ('0x%x' % v)))
    return ' '.join('0x%x' % w for w in words), ','.join(parts)


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
        bodies[va] = rows
        body = image.read(va, rec['end'] - va)
        calls = sorted(set('0x%x' % r.target for r in rows if r.op == 'call')
                       | set('slot:0x%x' % r.rm[4] for r in rows if r.op == 'callslot'))
        functions.append(dict(role=role, entry='0x%x' % va, fde_end='0x%x' % rec['end'], fde_bytes=rec['end'] - va,
                              decoded_instructions=len(rows), decoded_bytes=sum(r.length for r in rows),
                              lsda='none' if rec['lsda'] is None else '0x%x' % rec['lsda'],
                              sha256=hashlib.sha256(body).hexdigest(), callees=','.join(calls)))
        for r in rows:
            insn_rows.append((role, '0x%x' % va, '0x%x' % r.va, r.length, r.raw.hex(), r.op,
                              '' if r.target is None else '0x%x' % r.target))

    # Visitor callee roles from the body shapes: a bytes visitor's first slot
    # call is the lossy conversion and its second the free; a visitor's
    # direct call is the unknown-variant callee.  _Unwind_Resume sits on
    # landing pads only.
    stubs, roles = {}, {}

    def bind(key, role, fn):
        if roles.get(key, role) != role:
            raise Reject('callee %s has two roles' % (key,))
        roles[key] = role
        stubs[key] = fn
    unwind = set()
    for va, fam, kind, form, codec in VISITORS:
        rows = bodies[va]
        slots = []
        for r in rows:
            if r.op == 'callslot' and r.rm[4] not in slots:
                slots.append(r.rm[4])
        if kind == 'bytes':
            if len(slots) != 2:
                raise Reject('bytes visitor 0x%x does not use two slots' % va)
            bind(('slot', slots[0]), 'lossy', lossy_stub)
            bind(('slot', slots[1]), 'free', free_stub)
        elif slots:
            raise Reject('str visitor 0x%x calls through a slot' % va)
        direct = sorted(set(r.target for r in rows if r.op == 'call'))
        last = [r for r in rows if r.op == 'call'][-1].target if kind == 'bytes' else None
        for t in direct:
            if t == last:
                unwind.add(t)
                continue
            bind(t, 'unknown_variant_' + form, unknown_ptr_stub if form == 'result' else unknown_fill_stub)
    if len(unwind) != 1:
        raise Reject('landing-pad resume target is not unique')
    callee_rows = sorted(('slot:0x%x' % k[1] if isinstance(k, tuple) else '0x%x' % k, v) for k, v in roles.items())
    callee_rows.append(('0x%x' % unwind.pop(), 'unwind_resume (landing pads only)'))

    # Writer roles from the call-site shape: the call preceded by `mov r8d, 1`
    # is the Vec reserve (len, 1, 1, 1); the other direct call receives the
    # name pointer/length and is the escaped-string writer.  Each writer's tag
    # jump table (4 entries) maps tag -> (name lea, length immediate).
    writer_roles, jt_rows, writer_name_rows = {}, [], []
    for va, fam in WRITERS:
        rows = bodies[va]
        idx = {r.va: k for k, r in enumerate(rows)}
        rr = {}
        for k, r in enumerate(rows):
            if r.op != 'call':
                continue
            prev = rows[max(0, k - 5):k]
            role = 'reserve' if any(x.op == 'movimm' and x.reg == 8 and x.imm == 1 for x in prev) else 'escape_str'
            if rr.get(r.target, role) != role:
                raise Reject('writer callee 0x%x has two roles' % r.target)
            rr[r.target] = role
        if sorted(rr.values()) != ['escape_str', 'reserve']:
            raise Reject('writer 0x%x callee roles %s' % (va, sorted(rr.values())))
        writer_roles[va] = rr
        tabs = [r for r in rows if r.op == 'lea' and r.rm[5] and image.section_of(r.rm[4])['name'] == '.rodata']
        tabs = [r for r in tabs if rows[idx[r.va] + 1].op == 'movsxd']
        if len(tabs) != 1:
            raise Reject('writer 0x%x has no unique jump table' % va)
        table = tabs[0].rm[4]
        for tag in range(len(NAMES)):
            target = u64(table + sx(struct.unpack('<I', image.read(table + 4 * tag, 4))[0], 32))
            if target not in idx:
                raise Reject('writer 0x%x jump target 0x%x is not an instruction' % (va, target))
            k = idx[target]
            seq = rows[k:k + 12]
            lea = [x for x in seq if x.op == 'lea' and x.reg == 6 and x.rm[5]]
            ln = [x for x in seq if x.op == 'movimm' and x.reg == 2]
            if not lea or not ln:
                raise Reject('writer 0x%x arm %d has no name argument' % (va, tag))
            text = image.read(lea[0].rm[4], ln[0].imm)
            if text != NAMES[tag]:
                raise Reject('writer 0x%x arm %d writes %r' % (va, tag, text))
            jt_rows.append(('0x%x' % va, 'writer_tag', '0x%x' % table, tag, '0x%x' % target, text.decode()))
            writer_name_rows.append(('0x%x' % va, fam, tag, '0x%x' % lea[0].va, '0x%x' % lea[0].rm[4], ln[0].imm,
                                     text.decode()))
        quotes = [r for r in rows if r.op == 'mov' and r.ext == 'imm' and r.size == 1 and r.rm[0] == 'mem']
        if len(quotes) != 5 or any(r.imm != 0x22 for r in quotes):
            raise Reject('writer 0x%x quote stores differ' % va)
    callee_rows += sorted(set(('0x%x' % k, 'writer_' + v) for rr in writer_roles.values() for k, v in rr.items()))

    # Visitor length jump tables (17 entries: input lengths 1..17).
    for va, fam, kind, form, codec in VISITORS:
        rows = bodies[va]
        idx = {r.va: k for k, r in enumerate(rows)}
        tabs = [r for r in rows if r.op == 'lea' and r.rm[5] and image.section_of(r.rm[4])['name'] == '.rodata'
                and idx[r.va] + 1 < len(rows) and rows[idx[r.va] + 1].op == 'movsxd']
        gate = [r for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg']
        if len(tabs) != 1 or not gate or gate[0].imm != 0x10:
            raise Reject('visitor 0x%x length dispatch differs' % va)
        table = tabs[0].rm[4]
        for k in range(gate[0].imm + 1):
            target = u64(table + sx(struct.unpack('<I', image.read(table + 4 * k, 4))[0], 32))
            if target not in idx:
                raise Reject('visitor 0x%x jump target 0x%x is not an instruction' % (va, target))
            jt_rows.append(('0x%x' % va, 'visitor_length', '0x%x' % table, k + 1, '0x%x' % target,
                            next((n.decode() for n in NAMES if len(n) == k + 1), '-')))

    # Record writers: callee roles, field keys (lea + length before each str
    # call) and the enum's tag jump table.
    record_roles, key_rows = {}, []
    for va, fam in RECORDS:
        if (('hip3_state_rmp_record_writer', va)) not in FUNCTIONS:
            raise Reject('record writer 0x%x is not listed' % va)
        rows = bodies[va]
        idx = {r.va: k for k, r in enumerate(rows)}
        rr = bind_record_roles(image, rows, va)
        record_roles[va] = rr
        keys = []
        for k, r in enumerate(rows):
            if r.op == 'call' and rr[r.target] == 'str':
                lea = [x for x in rows[max(0, k - 4):k] if x.op == 'lea' and x.reg == 6 and x.rm[5]]
                ln = [x for x in rows[max(0, k - 4):k] if x.op == 'movimm' and x.reg == 2]
                if lea and ln:
                    text = image.read(lea[0].rm[4], ln[0].imm)
                    keys.append(text)
                    key_rows.append(('0x%x' % va, fam, '0x%x' % r.va, '0x%x' % lea[0].va, '0x%x' % lea[0].rm[4],
                                     ln[0].imm, text.decode('ascii')))
        tabs = [r for r in rows if r.op == 'lea' and r.rm[5] and image.section_of(r.rm[4])['name'] == '.rodata'
                and idx[r.va] + 1 < len(rows) and rows[idx[r.va] + 1].op == 'movsxd']
        if len(tabs) != 1:
            raise Reject('record writer 0x%x has no unique enum jump table' % va)
        table = tabs[0].rm[4]
        for tag in range(len(NAMES)):
            target = u64(table + sx(struct.unpack('<I', image.read(table + 4 * tag, 4))[0], 32))
            k = idx.get(target)
            lea = rows[k] if k is not None else None
            if lea is None or lea.op != 'lea' or rows[k + 1].op != 'movimm':
                raise Reject('record writer 0x%x arm %d shape differs' % (va, tag))
            text = image.read(lea.rm[4], rows[k + 1].imm)
            if text != NAMES[tag]:
                raise Reject('record writer 0x%x arm %d writes %r' % (va, tag, text))
            jt_rows.append(('0x%x' % va, 'record_enum_tag', '0x%x' % table, tag, '0x%x' % target, text.decode()))
        named = [kk for kk in keys if kk not in NAMES[:3]]
        if named != list(REC_KEYS):
            raise Reject('record writer 0x%x keys %s' % (va, named))
        flags = sorted(set((r.imm, r.rm[4]) for r in rows if r.op == 'cmp' and r.ext == 'imm' and r.size == 1
                           and r.rm[0] == 'mem' and r.rm[1] == 14))
        if flags != [(0, 0xb), (1, 0xb)]:
            raise Reject('record writer 0x%x flag compares differ: %s' % (va, flags))
    callee_rows += sorted(set(('0x%x' % k, 'record_' + v) for rr in record_roles.values() for k, v in rr.items()))

    # Visitor literals and variant-pool references.
    lit_rows, var_rows, pools = [], [], {}
    for va, fam, kind, form, codec in VISITORS:
        rows = bodies[va]
        leas = [r for r in rows if r.op == 'lea' and r.rm[5]
                and image.section_of(r.rm[4])['name'] == '.data.rel.ro']
        if len(leas) != 1:
            raise Reject('visitor 0x%x does not reference exactly one pool' % va)
        pools[va] = leas[0].rm[4]
        var_rows.append(('0x%x' % va, codec, fam, kind, form, '0x%x' % leas[0].va, '0x%x' % pools[va]))
        for r in rows:
            if r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg' and r.rm[1] == 2:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'length_gate', '%d' % r.imm))
            elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 1:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'byte+%d' % r.rm[4], chr(r.imm)))
            elif r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'mem' and r.size == 2:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'word+%d' % r.rm[4], r.imm.to_bytes(2, 'little').decode('ascii')))
            elif r.op == 'xor' and r.ext == 'imm' and r.rm[0] == 'reg':
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'xor_imm32', (r.imm & 0xffffffff).to_bytes(4, 'little').decode('ascii')))
            elif r.op == 'movimm' and r.size == 8:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'movabs_imm64', r.imm.to_bytes(8, 'little').decode('ascii')))
            elif r.op == 'pcmpeqb' and r.rm[0] == 'mem':
                raw = image.read(r.rm[4], 16)
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'pcmpeqb_rip_0x%x' % r.rm[4], raw.hex()))
            elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem' and r.rm[1] in (0, 7):
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'result_store%d+%d' % (8 * r.size, r.rm[4]), '0x%x' % r.imm))
    for codec, want_pools in sorted(CODEC_POOLS.items()):
        got = tuple(sorted(set(pools[v[0]] for v in VISITORS if v[4] == codec)))
        if got != want_pools:
            raise Reject('%s pool references differ: %s' % (codec, ['0x%x' % p for p in got]))

    table_rows = []
    for codec in ('disabled_state',):
        names = CODEC_NAMES[codec]
        for pool in CODEC_POOLS[codec]:
            relocs = image.relative_addends({pool + 16 * k for k in range(len(names))})
            texts = []
            for k in range(len(names)):
                slot = pool + 16 * k
                if slot not in relocs:
                    raise Reject('no RELATIVE relocation for %s slot 0x%x' % (codec, slot))
                pos, add = relocs[slot]
                ln = struct.unpack('<Q', image.read(slot + 8, 8))[0]
                text = image.read(add, ln)
                texts.append(text)
                table_rows.append((codec, '0x%x' % pool, k, '0x%x' % slot, '0x%x' % pos, '0x%x' % add, ln,
                                   text.decode('ascii')))
            if tuple(texts) != names:
                raise Reject('%s name pool 0x%x differs from reconstruction order' % (codec, pool))

    path_counts = {}
    # Writer comparison: one row per (writer, input).
    winputs = writer_inputs()
    wr_rows, wr_ok, wr_total = [], 0, 0
    neg_wr = {k: 0 for k in WRITER_NEGATIVES}
    reserves = 0
    for va, fam in WRITERS:
        for tag, cap, prefix in winputs:
            got, m = run_writer(image, va, writer_roles[va], tag, cap, prefix)
            want = recon_writer(tag, cap, prefix)
            same = got == want
            wr_total += 1
            wr_ok += same
            n_res = sum(1 for e in got[1] if e[0] == 'reserve')
            reserves += n_res
            key = (va, len(m.trace), 'ok+reserve%d' % n_res)
            path_counts[key] = path_counts.get(key, 0) + 1
            for name, kw in WRITER_NEGATIVES.items():
                neg_wr[name] += got != recon_writer(tag, cap, prefix, **kw)
            wr_rows.append(('0x%x' % va, tag, NAMES[tag].decode(), len(prefix), cap, show_writer(got),
                            'match' if same else 'MISMATCH'))

    # Record comparison: one row per (record writer, input).
    rinputs = record_inputs()
    rec_rows, rec_ok, rec_total = [], 0, 0
    neg_rec = {k: 0 for k in RECORD_NEGATIVES}
    rec_errs = 0
    for va, fam in RECORDS:
        for flag, tag, n_reserve, m_byte, fail_at in rinputs:
            got, m = run_record(image, va, record_roles[va], flag, tag, n_reserve, m_byte, fail_at)
            want = recon_record(flag, tag, n_reserve, m_byte, fail_at)
            same = got == want
            rec_total += 1
            rec_ok += same
            status = 'ok' if got[0] == (OK_NICHE,) else 'err@%d' % (len(got[1]) - 1)
            rec_errs += status != 'ok'
            key = (va, len(m.trace), status)
            path_counts[key] = path_counts.get(key, 0) + 1
            for name, kw in RECORD_NEGATIVES.items():
                neg_rec[name] += got != recon_record(flag, tag, n_reserve, m_byte, fail_at, **kw)
            words, log = show_record(got)
            rec_rows.append(('0x%x' % va, flag, tag, '0x%x' % n_reserve, m_byte, '-' if fail_at is None else fail_at,
                             words, log, 'match' if same else 'MISMATCH'))

    # Visitor comparison.
    inputs = visitor_inputs()
    vis_rows, vis_ok, vis_total = [], 0, 0
    neg_vis = {'prefix_match': wrong_prefix, 'case_fold': wrong_casefold, 'swap_first_two': wrong_swap,
               'first4_only': wrong_first4, 'length_only': wrong_length_only,
               'first_byte_only': wrong_first_byte}
    neg_counts = {k: 0 for k in neg_vis}
    neg_counts['raw_error_text'] = 0
    lossy_inputs = owned_frees = 0
    for text in inputs:
        row = [esc(text), len(text)]
        outcomes = []
        for va, fam, kind, form, codec in VISITORS:
            names = CODEC_NAMES[codec]
            got, m = run_visitor(image, va, kind, form, codec, stubs, roles, text, pools[va])
            want = recon_visitor(kind, form, text, names=names)
            same = got == want
            vis_total += 1
            vis_ok += same
            key = (va, len(m.trace), got[0] + ('+free' if got[3] else ''))
            path_counts[key] = path_counts.get(key, 0) + 1
            owned_frees += got[3]
            for name, fn in neg_vis.items():
                neg_counts[name] += got != recon_visitor(kind, form, text, fn, names)
            neg_counts['raw_error_text'] += got != wrong_raw_error(kind, form, text, names)
            if got[0] == 'ok':
                cell = 'ok:0x%x' % got[1]
            else:
                cell = 'err' + (':lossy' if got[2] != text else '') + (':free' if got[3] else '')
            outcomes.append(cell + ('' if same else '!'))
        lossy_inputs += lossy(text)[1]
        row += outcomes
        tag = recon_classify(text, NAMES)
        row.append('-' if tag is None else NAMES[tag].decode())
        row.append('match' if all(not o.endswith('!') for o in outcomes) else 'MISMATCH')
        vis_rows.append(tuple(row))

    paths = [('0x%x' % va, steps, status, n) for (va, steps, status), n in sorted(path_counts.items())]
    negatives = ([('record', k, v, rec_total) for k, v in sorted(neg_rec.items())]
                 + [('writer', k, v, wr_total) for k, v in sorted(neg_wr.items())]
                 + [('visitor', k, v, vis_total) for k, v in sorted(neg_counts.items())])
    accepted = sum(1 for r in vis_rows if r[-2] != '-')
    summary = dict(
        target='node115', sha256=SHA115, component='dex-registry', task='RE-007',
        functions=len(FUNCTIONS), decoded_instructions=len(insn_rows),
        disabled_state_names=[n.decode() for n in NAMES], disabled_state_pools=['0x%x' % p for p in VARIANT_POOLS],
        writers=len(WRITERS), writer_inputs=len(winputs), writer_cases=wr_total, writer_matches=wr_ok,
        writer_reserve_calls=reserves,
        record_writers=len(RECORDS), record_inputs=len(rinputs), record_cases=rec_total, record_matches=rec_ok,
        record_error_cases=rec_errs, record_keys=[k.decode() for k in REC_KEYS],
        visitor_inputs=len(inputs), accepted_inputs=accepted, invalid_utf8_inputs=lossy_inputs,
        visitor_cases=vis_total, visitor_matches=vis_ok, owned_copy_frees=owned_frees,
        callees={a: b for a, b in callee_rows},
        distinct_paths=len(paths),
        negative_controls={'%s/%s' % (a, b): n for a, b, n, _ in negatives},
        all_negative_controls_caught=all(n > 0 for _, _, n, _ in negatives),
        reconstruction_matches_all=(wr_ok == wr_total and vis_ok == vis_total and rec_ok == rec_total),
    )
    return dict(functions=functions, instructions=insn_rows, literals=lit_rows, jump_tables=jt_rows,
                writer_names=writer_name_rows, variant_refs=var_rows, variant_tables=table_rows, callees=callee_rows,
                writer=wr_rows, record=rec_rows, record_keys=key_rows, visitor=vis_rows, paths=paths, negatives=negatives, summary=summary)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    f = result['functions']
    keys = list(f[0].keys())
    return {
        'functions.tsv': tsv(keys, [[row[k] for k in keys] for row in f]),
        'instructions.tsv': tsv(('role', 'function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'callees.tsv': tsv(('callee', 'role'), result['callees']),
        'visitor-literals.tsv': tsv(('visitor', 'va', 'form', 'value'), result['literals']),
        'jump-tables.tsv': tsv(('function', 'table_kind', 'table', 'index', 'target', 'name'), result['jump_tables']),
        'writer-names.tsv': tsv(('writer', 'family', 'tag', 'lea_va', 'text_va', 'length', 'text'),
                                result['writer_names']),
        'name-pool-refs.tsv': tsv(('function', 'codec', 'family', 'input', 'output', 'lea_va', 'pool'),
                                  result['variant_refs']),
        'name-pools.tsv': tsv(('codec', 'pool', 'index', 'slot', 'rela_file_offset', 'text_va', 'length', 'text'),
                              result['variant_tables']),
        'record-cases.tsv': tsv(('record_writer', 'flag', 'tag', 'n_reserve', 'm', 'fail_at', 'result_words',
                                 'callee_log', 'verdict'), result['record']),
        'record-keys.tsv': tsv(('record_writer', 'family', 'call_va', 'lea_va', 'text_va', 'length', 'text'),
                               result['record_keys']),
        'writer-cases.tsv': tsv(('writer', 'tag', 'name', 'prefix_len', 'cap', 'tail|events|final_cap', 'verdict'),
                                result['writer']),
        'visitor-cases.tsv': tsv(('input_hex', 'length') + tuple('0x%x' % v[0] for v in VISITORS)
                                 + ('disabled_state', 'verdict'), result['visitor']),
        'paths.tsv': tsv(('function', 'steps', 'outcome', 'inputs'), result['paths']),
        'negative-controls.tsv': tsv(('family', 'wrong_reconstruction', 'mismatching_cases', 'cases'),
                                     result['negatives']),
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
        print(json.dumps(result['summary'], indent=1, sort_keys=True), file=sys.stderr)
        return 1
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    for name, text in render(result).items():
        (out / name).write_text(text, encoding='ascii', newline='\n')
    s = result['summary']
    print('record %d/%d, writer %d/%d, visitor %d/%d, negatives caught: %s' % (
        s['record_matches'], s['record_cases'], s['writer_matches'], s['writer_cases'], s['visitor_matches'], s['visitor_cases'],
        s['all_negative_controls_caught']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
