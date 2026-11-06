#!/usr/bin/env python3
"""Reconstruct the node #115 three-name Spot/Mark/ExternalPerp codec and prove it.

The producer authenticates the #115 capture, locates six selected bodies by
their unwind (FDE) extents, and runs each body's original machine code in a
small interpreter for the fixed x86-64 instruction subset those bodies use.
Every interpreted result is compared with an independent pure-Python
reconstruction: a msgpack fixstr writer (three serializer copies, including
the two capacity-reserve branches of each arm and the out-of-range tag
fall-through) and an exact-name classifier (three visitor copies).  The
variant-name pool each visitor passes to its unknown-variant callee is decoded
from RELATIVE relocations.  Deliberately wrong reconstructions are run
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

NAMES = (b'Spot', b'Mark', b'ExternalPerp')
# &[&str; 3] entries passed to the unknown-variant callee (one per copy family)
VARIANT_POOLS = (0x642d150, 0x6479be0, 0x64a7c68)

# Selected bodies: (role, entry VA).  Entries are FDE starts; the producer
# rejects the input if any entry is not an exact FDE start.
SERIALIZERS = (0x22e3810, 0x3d4d420, 0x5361090)
VISITORS_TAGGED = (0x22e20d0, 0x3d47cb0, 0x535bee0)   # writes word 0x09 | tag << 8
FUNCTIONS = ([('serializer', va) for va in SERIALIZERS]
             + [('visitor_tagged', va) for va in VISITORS_TAGGED])

# Interpreter memory regions (outside every mapped section of the capture).
IN_BASE = 0x1000_0000
OUT_BASE = 0x2000_0000
VEC_BASE = 0x3000_0000
DATA_BASE = 0x4000_0000
STACK_TOP = 0x7f00_0000
RETURN_SENTINEL = 0xdead_0000
ERR_SENTINEL = 0xe770_0000_0000_0001
OK_WORD = 0x8000000000000004


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
    if raw[i] == 0x66:
        opsize16 = True
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
    elif two and op == 0x0fb6:
        reg, rm, _ = modrm()
        kw.update(op='movzx8', reg=reg, rm=rm)
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


def grow_stub(machine, args):
    vec, length, additional, align, elem = args
    if (align, elem) != (1, 1):
        raise Reject('unexpected element layout in grow call')
    cap = machine.load(vec, 8)
    machine.store(vec, max(cap * 2, length + additional, 8), 8)
    return 0


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

def recon_tag_name(tag):
    """Arm selection of the serializers: 0 -> Spot, 1 -> Mark, any other byte -> ExternalPerp."""
    return NAMES[tag] if tag < 2 else NAMES[2]


def recon_serialize(tag, cap, length):
    """Reconstruction of the serializer: msgpack fixstr of the arm's name appended to a Vec<u8>.

    Returns (appended bytes, grow calls as (length, additional), final length, result word).
    """
    name = recon_tag_name(tag)
    grows = []
    if cap == length:
        grows.append((length, 1))
        cap = max(cap * 2, length + 1, 8)
    length += 1
    if cap - length < len(name):
        grows.append((length, len(name)))
        cap = max(cap * 2, length + len(name), 8)
    length += len(name)
    return bytes([0xa0 | len(name)]) + name, grows, length, OK_WORD


def recon_classify(text):
    """Exact byte-for-byte match against the three names; declaration order is the tag."""
    return NAMES.index(text) if text in NAMES else None


def recon_visitor_tagged(text):
    tag = recon_classify(text)
    if tag is None:
        return ('err', None)
    return ('ok', 0x09 | (tag << 8))


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
    return {0: 1, 1: 0}.get(t, t)


def wrong_first8(text):
    """Compares only the first qword of ExternalPerp (drops the dword at +8)."""
    for k, n in enumerate(NAMES):
        if len(text) == len(n) and text[:8] == n[:8]:
            return k
    return None


def wrong_length_free(text):
    """Accepts a four-byte name prefix of any length >= 4 (drops the length gate)."""
    if len(text) >= 4 and text[:4] in NAMES[:2]:
        return NAMES.index(text[:4])
    return recon_classify(text)


def wrong_serialize_no_reserve(tag, cap, length):
    data, grows, end, word = recon_serialize(tag, cap, length)
    return data, [g for g in grows if g[1] == 1], end, word


def wrong_serialize_marker(tag, cap, length):
    data, grows, end, word = recon_serialize(tag, cap, length)
    name = recon_tag_name(tag)
    return bytes([0xd9, len(name)]) + name, grows, end + 1, word


def wrong_serialize_strict(tag, cap, length):
    name = recon_tag_name(tag)
    grows = []
    if cap == length:
        grows.append((length, 1))
        cap = max(cap * 2, length + 1, 8)
    length += 1
    if cap - length <= len(name):
        grows.append((length, len(name)))
    return bytes([0xa0 | len(name)]) + name, grows, length + len(name), OK_WORD


def wrong_serialize_range(tag, cap, length):
    """Treats tags above 2 as Spot (a range-checked jump table) instead of the ExternalPerp fall-through."""
    return recon_serialize(tag if tag < 3 else 0, cap, length)


# ---------------------------------------------------------------- interpretation drivers

def run_serializer(image, entry, stubs, tag, cap, length):
    m = Machine(image, stubs)
    m.store(OUT_BASE, 0x1111_1111_1111_1111, 8)
    m.store(IN_BASE, tag, 1)
    m.store(VEC_BASE, cap, 8)
    m.store(VEC_BASE + 8, DATA_BASE, 8)
    m.store(VEC_BASE + 16, length, 8)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, VEC_BASE
    m.run(entry)
    end = m.load(VEC_BASE + 16, 8)
    data = bytes(m.load(DATA_BASE + k, 1) for k in range(length, end))
    grows = []
    for site, target, args in m.calls:
        if args[0] != VEC_BASE:
            raise Reject('grow call vector argument differs at 0x%x' % site)
        grows.append((args[1], args[2]))
    return data, grows, end, m.load(OUT_BASE, 8), m


def run_visitor(image, entry, stubs, text, pool):
    m = Machine(image, stubs)
    m.store(OUT_BASE, 0xa5a5_a5a5_a5a5_a5a5, 8)
    m.store(OUT_BASE + 8, 0xa5a5_a5a5_a5a5_a5a5, 8)
    # Pad past the input so that any whole-word read is defined.  Zero is not
    # a byte of any name.
    for k in range(32):
        m.store(IN_BASE + k, 0x00, 1)
    for k, b in enumerate(text):
        m.store(IN_BASE + k, b, 1)
    m.regs[7], m.regs[6], m.regs[2] = OUT_BASE, IN_BASE, len(text)
    m.run(entry)
    if m.regs[0] != OUT_BASE:
        raise Reject('visitor 0x%x does not return its output pointer' % entry)
    if m.calls:
        (site, target, args), = m.calls
        if args != (OUT_BASE, IN_BASE, len(text), pool, len(NAMES)):
            raise Reject('error call arguments differ at 0x%x' % site)
        return ('err', None), m
    return ('ok', m.load(OUT_BASE, 2)), m


# Replacement bytes for the single-position mutations: every byte value.
MUTATION_BYTES = tuple(range(256))


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
        add(n + b'\0')
        add(n.lower())
        add(n.upper())
        for pos in range(len(n)):
            for v in MUTATION_BYTES:
                add(n[:pos] + bytes([v]) + n[pos + 1:])
    for a in NAMES:
        for b in NAMES:
            if a != b:
                add(a[:len(a) // 2] + b[len(b) // 2:])
                add(a + b)
    for ln in range(0, 17):
        add(b'A' * ln)
    return seen


def serializer_inputs():
    """(tag, capacity, length): valid tags across every reserve edge, then every other tag byte."""
    rows = []
    for tag in range(3):
        for length in (0, 1, 7, 64):
            for spare in range(0, 16):
                rows.append((tag, length + spare, length))
    for tag in range(3, 256):
        rows.append((tag, 64, 0))
    return rows


def esc(b):
    return b.hex()


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

    grow_targets = sorted(set(t for va in SERIALIZERS for _, t in callee_of(image, va, by_start[va]['end'])))
    err_targets = sorted(set(t for va in VISITORS_TAGGED for _, t in callee_of(image, va, by_start[va]['end'])))
    if set(grow_targets) & set(err_targets):
        raise Reject('serializer and visitor callees overlap')
    stubs = {t: grow_stub for t in grow_targets}
    stubs.update({t: error_stub for t in err_targets})

    # Serializer arms: every immediate store into the vector (marker byte and
    # name words) and every reserve bound, in body order.
    arm_rows = []
    for va in SERIALIZERS:
        for r in bodies[va][2]:
            if r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem':
                raw = (r.imm & ((1 << (8 * r.size)) - 1)).to_bytes(r.size, 'little')
                kind = 'marker' if r.size == 1 else ('result_word' if r.size == 8 else 'name_bytes')
                arm_rows.append(('0x%x' % va, '0x%x' % r.va, 'store%d' % (8 * r.size), kind, raw.hex(),
                                 raw.decode('ascii') if kind == 'name_bytes' else '-'))
            elif r.op == 'movimm' and r.size == 8:
                raw = r.imm.to_bytes(8, 'little')
                text = raw.decode('ascii') if all(0x20 <= c < 0x7f for c in raw) else '-'
                arm_rows.append(('0x%x' % va, '0x%x' % r.va, 'movabs', 'name_bytes' if text != '-' else 'result_word',
                                 raw.hex(), text))
            elif r.op == 'cmp' and r.ext == 'imm':
                arm_rows.append(('0x%x' % va, '0x%x' % r.va, 'cmp_imm', 'tag' if r.rm[0] == 'reg' and r.rm[1] == 1 and r.imm < 2 else 'reserve_bound',
                                 '%d' % r.imm, '-'))

    # Visitor length gates, name literals and variant-pool references.
    lit_rows, var_rows, pools = [], [], {}
    for va in VISITORS_TAGGED:
        rows = bodies[va][2]
        leas = [r for r in rows if r.op == 'lea' and r.rm[5]]
        if len(leas) != 1:
            raise Reject('visitor 0x%x does not reference exactly one pool' % va)
        pools[va] = leas[0].rm[4]
        count = [r for r in rows if r.op == 'movimm' and r.reg == 8]
        if len(count) != 1:
            raise Reject('visitor 0x%x does not set exactly one variant count' % va)
        var_rows.append(('0x%x' % va, '0x%x' % leas[0].va, '0x%x' % leas[0].rm[4], '0x%x' % count[0].va, count[0].imm))
        for r in rows:
            if r.op == 'cmp' and r.ext == 'imm' and r.rm[0] == 'reg':
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'length_gate', '%d' % r.imm))
            elif r.op in ('cmp', 'xor') and r.ext == 'imm':
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, '%s_imm32' % r.op,
                                 (r.imm & 0xffffffff).to_bytes(4, 'little').decode('ascii')))
            elif r.op == 'movimm' and r.size == 8:
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'movabs_imm64', r.imm.to_bytes(8, 'little').decode('ascii')))
            elif r.op == 'mov' and r.ext == 'imm' and r.rm[0] == 'mem':
                lit_rows.append(('0x%x' % va, '0x%x' % r.va, 'result_store%d' % (8 * r.size), '0x%x' % r.imm))
    if tuple(sorted(set(pools.values()))) != VARIANT_POOLS:
        raise Reject('variant pool references differ: %s' % sorted('0x%x' % p for p in set(pools.values())))

    # Variant-name pool entries: (ptr, len) slots, ptr by R_X86_64_RELATIVE.
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

    # Serializer comparison.
    ser_rows, ser_ok, ser_total = [], 0, 0
    neg_ser = {'no_reserve': [wrong_serialize_no_reserve, 0], 'str8_marker': [wrong_serialize_marker, 0],
               'reserve_on_equal': [wrong_serialize_strict, 0], 'range_checked_tag': [wrong_serialize_range, 0]}
    path_counts = {}
    for va in SERIALIZERS:
        for tag, cap, length in serializer_inputs():
            got, grows, end, word, m = run_serializer(image, va, stubs, tag, cap, length)
            want = recon_serialize(tag, cap, length)
            same = (got, grows, end, word) == want
            ser_total += 1
            ser_ok += same
            key = (va, len(m.trace), 'grow%d' % len(grows))
            path_counts[key] = path_counts.get(key, 0) + 1
            for item in neg_ser.values():
                item[1] += (got, grows, end, word) != item[0](tag, cap, length)
            ser_rows.append(('0x%x' % va, tag, cap, length, esc(got),
                             ';'.join('%d+%d' % g for g in grows) or '-', end, '0x%016x' % word,
                             recon_tag_name(tag).decode(), 'match' if same else 'MISMATCH'))

    # Visitor comparison.
    inputs = visitor_inputs()
    vis_rows, vis_ok, vis_total = [], 0, 0
    neg_vis = {'prefix_match': [wrong_prefix, 0], 'case_fold': [wrong_casefold, 0],
               'swap_spot_mark': [wrong_swap, 0], 'first_qword_only': [wrong_first8, 0],
               'no_length_gate': [wrong_length_free, 0]}
    for text in inputs:
        row = [esc(text) if text else '-', len(text)]
        want_tag = recon_classify(text)
        outcomes = []
        for va in VISITORS_TAGGED:
            (status, value), m = run_visitor(image, va, stubs, text, pools[va])
            want = recon_visitor_tagged(text)
            same = (status, value) == want
            vis_total += 1
            vis_ok += same
            key = (va, len(m.trace), status)
            path_counts[key] = path_counts.get(key, 0) + 1
            outcomes.append('%s:%s' % (status, '-' if value is None else '0x%x' % value))
            got_tag = None if status == 'err' else value >> 8
            if status == 'ok' and value & 0xff != 0x09:
                raise Reject('visitor 0x%x wrote an unexpected low byte' % va)
            for item in neg_vis.values():
                if item[0](text) != got_tag:
                    item[1] += 1
            if not same:
                outcomes[-1] += '!'
        row += outcomes
        row.append('-' if want_tag is None else NAMES[want_tag].decode())
        row.append('match' if all(not o.endswith('!') for o in outcomes) else 'MISMATCH')
        vis_rows.append(tuple(row))

    paths = [('0x%x' % va, steps, status, n) for (va, steps, status), n in sorted(path_counts.items())]
    negatives = ([('serializer', k, v[1], ser_total) for k, v in sorted(neg_ser.items())]
                 + [('visitor', k, v[1], vis_total) for k, v in sorted(neg_vis.items())])
    accepted = sum(1 for r in vis_rows if r[-2] != '-')
    summary = dict(
        target='node115', sha256=SHA115, component='constants', task='RE-015',
        functions=len(FUNCTIONS), decoded_instructions=len(insn_rows),
        names=[n.decode() for n in NAMES], variant_pools=['0x%x' % p for p in VARIANT_POOLS],
        serializer_cases=ser_total, serializer_matches=ser_ok,
        visitor_inputs=len(inputs), accepted_inputs=accepted, visitor_cases=vis_total, visitor_matches=vis_ok,
        grow_callees=['0x%x' % t for t in grow_targets], error_callees=['0x%x' % t for t in err_targets],
        distinct_paths=len(paths),
        negative_controls={'%s/%s' % (a, b): n for a, b, n, _ in negatives},
        all_negative_controls_caught=all(n > 0 for _, _, n, _ in negatives),
        reconstruction_matches_all=(ser_ok == ser_total and vis_ok == vis_total),
    )
    return dict(functions=functions, instructions=insn_rows, arms=arm_rows, literals=lit_rows, variant_refs=var_rows,
                variant_tables=table_rows, serializer=ser_rows, visitor=vis_rows, paths=paths,
                negatives=negatives, summary=summary)


def tsv(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(c) for c in r) + '\n' for r in rows)


def render(result):
    f = result['functions']
    keys = list(f[0].keys())
    return {
        'functions.tsv': tsv(keys, [[row[k] for k in keys] for row in f]),
        'instructions.tsv': tsv(('role', 'function', 'va', 'length', 'bytes', 'op', 'target'), result['instructions']),
        'serializer-arms.tsv': tsv(('serializer', 'va', 'form', 'kind', 'value_hex', 'text'), result['arms']),
        'visitor-literals.tsv': tsv(('visitor', 'va', 'form', 'value'), result['literals']),
        'variant-refs.tsv': tsv(('visitor', 'lea_va', 'pool', 'count_va', 'count'), result['variant_refs']),
        'variant-pool.tsv': tsv(('pool', 'index', 'slot', 'rela_file_offset', 'text_va', 'length', 'text'), result['variant_tables']),
        'serializer-cases.tsv': tsv(('serializer', 'tag', 'capacity', 'length', 'appended_hex', 'grow_calls', 'final_length', 'result_word', 'arm', 'verdict'), result['serializer']),
        'visitor-cases.tsv': tsv(('input_hex', 'length') + tuple('0x%x' % v for v in VISITORS_TAGGED) + ('reconstruction', 'verdict'), result['visitor']),
        'paths.tsv': tsv(('function', 'steps', 'outcome', 'inputs'), result['paths']),
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
    print('serializer %d/%d, visitor %d/%d, negatives caught: %s' % (
        s['serializer_matches'], s['serializer_cases'], s['visitor_matches'], s['visitor_cases'],
        s['all_negative_controls_caught']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
