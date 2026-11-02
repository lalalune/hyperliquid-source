"""Shared ELF/instruction helpers retained for the node #115 validators.

Extracted from the historical research module; no retired-target entry point.
"""
import argparse


import bisect


import hashlib


import json


import re


import struct


import subprocess


import sys


from functools import partial


from pathlib import Path


from gnu_binutils import gnu_objdump  # noqa: E402


MASK = (1 << 64) - 1


RET_MAGIC = 0x7fff0000


MEMSET_STUB, MEMCPY_STUB = 0x7fff0010, 0x7fff0020


RAM_BASE, RAM_SIZE = 0x7000000, 0x10000


STACK_TOP = RAM_BASE + 0xf000 - 8    # entry rsp + 8 is 16-aligned, as the ABI requires


BUFFER = RAM_BASE + 0x100


REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)


R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)


REGS = {name: (i, 8) for i, name in enumerate(REG64)}


for i, name in enumerate(['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                          'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']):
    REGS[name] = (i, 4)


for i, name in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
                          'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']):
    REGS[name] = (i, 2)


for i, name in enumerate(['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
                          'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']):
    REGS[name] = (i, 1)


class EvidenceError(Exception):
    pass


class Unmodelled(Exception):
    pass


def sections(data):
    if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64:
        raise EvidenceError('not an ELF64 little-endian file')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    if shentsize < 64 or shstrndx >= shnum or shoff + shentsize * shnum > len(data):
        raise EvidenceError('Invalid or unsupported ELF section table')
    raw = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff, strsize = raw[shstrndx][4], raw[shstrndx][5]
    if stroff > len(data) or strsize > len(data) - stroff:
        raise EvidenceError('section name table extends past end of file')
    table = data[stroff:stroff + strsize]
    out = {}
    for name, typ, _flags, addr, off, size, *_ in raw:
        if typ == 8:  # SHT_NOBITS has no file bytes.
            continue
        if name >= len(table):
            raise EvidenceError('section name offset outside .shstrtab')
        end = table.find(b'\0', name)
        if end < 0:
            raise EvidenceError('unterminated section name')
        try:
            decoded = table[name:end].decode()
        except UnicodeDecodeError:
            raise EvidenceError('Non-UTF8 section name') from None
        out[decoded] = (addr, off, size)
    return out


class Image:
    def __init__(self, data):
        self.data = data
        self.sec = sections(data)

    def off(self, va, size=1):
        for addr, off, sz in self.sec.values():
            if addr and addr <= va and va + size <= addr + sz:
                return off + va - addr
        raise EvidenceError(f'VA {va:#x} is outside every allocated section')

    def read(self, va, size):
        o = self.off(va, size)
        return self.data[o:o + size]

    def section(self, name):
        try:
            return self.sec[name]
        except KeyError:
            raise EvidenceError(f'missing required section {name}') from None

    def text(self):
        addr, off, size = self.section('.text')
        return addr, self.data[off:off + size]

    def in_rodata(self, va, size):
        addr, _, sz = self.section('.rodata')
        return addr <= va and va + size <= addr + sz

    def slots(self):
        """GOT contents after load: RELATIVE addends, plus the two libc symbols the helpers use."""
        _, off, size = self.section('.rela.dyn')
        if off + size > len(self.data) or size % 24:
            raise EvidenceError('.rela.dyn truncated')
        _, sym_off, sym_size = self.section('.dynsym')
        _, str_off, str_size = self.section('.dynstr')
        if sym_off + sym_size > len(self.data) or str_off + str_size > len(self.data):
            raise EvidenceError('dynamic symbol table extends past end of file')
        got = self.section('.got')
        stubs = {b'memset': MEMSET_STUB, b'memcpy': MEMCPY_STUB}
        out = {}
        for where, info, addend in struct.iter_unpack('<QQq', self.data[off:off + size]):
            typ, sym = info & 0xffffffff, info >> 32
            if not got[0] <= where < got[0] + got[2]:
                continue
            if typ == 8:
                if where in out:
                    raise EvidenceError(f'duplicate RELATIVE relocation slot {where:#x}')
                out[where] = addend & MASK
            elif typ == 6:
                if sym * 24 + 24 > sym_size:
                    raise EvidenceError('dynamic symbol index outside .dynsym')
                n = struct.unpack_from('<I', self.data, sym_off + sym * 24)[0]
                # The symbol name has to end inside .dynstr. A NUL in the next
                # section is not this symbol's terminator.
                if n >= str_size:
                    raise EvidenceError('dynamic symbol name outside .dynstr')
                end = self.data.find(b'\0', str_off + n, str_off + str_size)
                if end < 0:
                    raise EvidenceError('unterminated dynamic symbol name')
                name = self.data[str_off + n:end]
                if name in stubs:
                    if where in out:
                        raise EvidenceError(f'duplicate GLOB_DAT relocation slot {where:#x}')
                    out[where] = stubs[name]
        return out

    def relative_relocs(self):
        _, off, size = self.section('.rela.dyn')
        if off + size > len(self.data) or size % 24:
            raise EvidenceError('.rela.dyn truncated')
        out = {}
        for where, info, addend in struct.iter_unpack('<QQq', self.data[off:off + size]):
            if info & 0xffffffff == 8:
                if where in out:
                    raise EvidenceError(f'duplicate RELATIVE relocation slot {where:#x}')
                out[where] = addend
        return out


def signed(val, bits):
    return val - (1 << bits) if val >> (bits - 1) else val


class Machine:
    """Byte-accurate integer and SSE-move subset.  Unset state is tracked and never guessed."""

    CC = {'e': lambda s: s.flag('zf'), 'ne': lambda s: not s.flag('zf'),
          'b': lambda s: s.flag('cf'), 'ae': lambda s: not s.flag('cf'),
          'a': lambda s: not (s.flag('cf') or s.flag('zf')), 'be': lambda s: s.flag('cf') or s.flag('zf'),
          's': lambda s: s.flag('sf'), 'ns': lambda s: not s.flag('sf'),
          'o': lambda s: s.flag('of'), 'no': lambda s: not s.flag('of')}

    def __init__(self, insns, img, slots):
        self.img = img
        self.slots = slots
        table = {name[2:]: getattr(self, name) for name in dir(self) if name.startswith('i_')}
        for cc in self.CC:
            table['j' + cc] = partial(self.jcc, cc)
            table['cmov' + cc] = partial(self.cmov, cc)
            table['set' + cc] = partial(self.setcc, cc)
        self.code = {}
        for va, mn, ops, nxt in insns:
            handler = table.get(mn) or partial(self.unknown, mn, va)
            self.code[va] = (handler, ops, nxt)
        self.seen = set()
        self.reset()

    def reset(self):
        self.regs = [0] * 16
        self.known = [0] * 16
        self.xmm = [None] * 16
        self.ram = bytearray(RAM_SIZE)
        self.valid = bytearray(RAM_SIZE)
        self.cf = self.zf = self.sf = self.of = None
        self.steps = 0
        self.pc = None

    # state access

    def setreg(self, idx, val):
        self.regs[idx] = val & MASK
        self.known[idx] = MASK

    def poison(self, *idxs):
        for idx in idxs:
            self.known[idx] = 0

    def flag(self, name):
        val = getattr(self, name)
        if val is None:
            raise Unmodelled(f'read of unset {name} at {self.pc:#x}')
        return val

    def ea(self, op):
        _, _, base, index, scale, disp = op
        val = disp
        if base is not None:
            if self.known[base] != MASK:
                raise Unmodelled(f'unset base at {self.pc:#x}')
            val += self.regs[base]
        if index is not None:
            if self.known[index] != MASK:
                raise Unmodelled(f'unset index at {self.pc:#x}')
            val += self.regs[index] * scale
        return val & MASK

    def load(self, ea, size):
        lo = ea - RAM_BASE
        if 0 <= lo and lo + size <= RAM_SIZE:
            if 0 in self.valid[lo:lo + size]:
                raise Unmodelled(f'read of unset memory {ea:#x}/{size} at {self.pc:#x}')
            return int.from_bytes(self.ram[lo:lo + size], 'little')
        if size == 8 and ea in self.slots:
            return self.slots[ea]
        if self.img.in_rodata(ea, size):
            return int.from_bytes(self.img.read(ea, size), 'little')
        raise Unmodelled(f'read outside the model {ea:#x}/{size} at {self.pc:#x}')

    def store(self, ea, size, val):
        lo = ea - RAM_BASE
        if not (0 <= lo and lo + size <= RAM_SIZE):
            raise Unmodelled(f'write outside RAM {ea:#x} at {self.pc:#x}')
        self.ram[lo:lo + size] = (val & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
        self.valid[lo:lo + size] = b'\x01' * size

    def rd(self, op):
        kind = op[0]
        if kind == 'r':
            idx, size = op[1], op[2]
            mask = (1 << (size * 8)) - 1
            if self.known[idx] & mask != mask:
                raise Unmodelled(f'read of unset {REG64[idx]} at {self.pc:#x}')
            return self.regs[idx] & mask
        if kind == 'i':
            return op[1]
        if kind == 'm':
            return self.load(self.ea(op), op[1])
        if kind == 'a':
            return self.load(op[2], op[1])
        raise Unmodelled(f'operand {op} at {self.pc:#x}')

    def wr(self, op, val):
        kind = op[0]
        if kind == 'r':
            idx, size = op[1], op[2]
            if size >= 4:
                self.regs[idx] = val & (MASK if size == 8 else 0xffffffff)
                self.known[idx] = MASK
            else:
                mask = (1 << (size * 8)) - 1
                self.regs[idx] = (self.regs[idx] & ~mask) | (val & mask)
                self.known[idx] |= mask
        elif kind == 'm':
            self.store(self.ea(op), op[1], val)
        elif kind == 'a':
            raise Unmodelled(f'write to a static address at {self.pc:#x}')
        else:
            raise Unmodelled(f'write to {op} at {self.pc:#x}')

    def size(self, op):
        return op[2] if op[0] == 'r' else op[1]

    def nz(self, res, bits):
        self.zf = res == 0
        self.sf = bool(res >> (bits - 1))

    # moves

    def i_nop(self, ops):
        pass

    def i_mov(self, ops):
        dst, src = ops
        if dst[0] == 'r' and src[0] == 'r' and dst[2] >= 4:
            self.regs[dst[1]] = self.regs[src[1]] & (MASK if dst[2] == 8 else 0xffffffff)
            self.known[dst[1]] = self.known[src[1]] if dst[2] == 8 else (self.known[src[1]] & 0xffffffff) | ~0xffffffff & MASK
            return
        self.wr(dst, self.rd(src))

    i_movabs = i_mov

    def i_movzx(self, ops):
        self.wr(ops[0], self.rd(ops[1]))

    def i_lea(self, ops):
        dst, src = ops
        self.wr(dst, src[2] if src[0] == 'a' else self.ea(src))

    def i_push(self, ops):
        idx = ops[0][1]
        rsp = self.regs[RSP] - 8
        self.regs[RSP] = rsp
        lo = rsp - RAM_BASE
        self.ram[lo:lo + 8] = self.regs[idx].to_bytes(8, 'little')
        self.valid[lo:lo + 8] = bytes((self.known[idx] >> (8 * i)) & 1 for i in range(8))

    def i_pop(self, ops):
        idx = ops[0][1]
        rsp = self.regs[RSP]
        lo = rsp - RAM_BASE
        self.regs[idx] = int.from_bytes(self.ram[lo:lo + 8], 'little')
        self.known[idx] = sum(0xff << (8 * i) for i in range(8) if self.valid[lo + i])
        self.regs[RSP] = rsp + 8

    # integer arithmetic

    def arith(self, ops, carry_in, subtract, store=True):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        a, b = self.rd(ops[0]), self.rd(ops[1]) & mask
        c = int(self.flag('cf')) if carry_in else 0
        if subtract:
            raw = a - b - c
            res = raw & mask
            self.cf = raw < 0
            self.of = bool((((a ^ b) & (a ^ res)) >> (bits - 1)) & 1)
        else:
            raw = a + b + c
            res = raw & mask
            self.cf = raw > mask
            self.of = bool((((a ^ res) & (b ^ res)) >> (bits - 1)) & 1)
        self.nz(res, bits)
        if store:
            self.wr(ops[0], res)

    def i_add(self, ops):
        self.arith(ops, False, False)

    def i_adc(self, ops):
        self.arith(ops, True, False)

    def i_sub(self, ops):
        self.arith(ops, False, True)

    def i_sbb(self, ops):
        self.arith(ops, True, True)

    def i_cmp(self, ops):
        self.arith(ops, False, True, store=False)

    def logic(self, ops, fn, store=True):
        bits = self.size(ops[0]) * 8
        res = fn(self.rd(ops[0]), self.rd(ops[1]) & ((1 << bits) - 1))
        self.cf = self.of = False
        self.nz(res, bits)
        if store:
            self.wr(ops[0], res)

    def i_and(self, ops):
        self.logic(ops, lambda a, b: a & b)

    def i_or(self, ops):
        self.logic(ops, lambda a, b: a | b)

    def i_xor(self, ops):
        if ops[0] == ops[1] and ops[0][0] == 'r':
            self.wr(ops[0], 0)
            self.cf = self.of = self.sf = False
            self.zf = True
            return
        self.logic(ops, lambda a, b: a ^ b)

    def i_test(self, ops):
        self.logic(ops, lambda a, b: a & b, store=False)

    def i_inc(self, ops):
        bits = self.size(ops[0]) * 8
        res = (self.rd(ops[0]) + 1) & ((1 << bits) - 1)
        self.of = res == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_dec(self, ops):
        bits = self.size(ops[0]) * 8
        a = self.rd(ops[0])
        res = (a - 1) & ((1 << bits) - 1)
        self.of = a == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_neg(self, ops):
        bits = self.size(ops[0]) * 8
        a = self.rd(ops[0])
        res = -a & ((1 << bits) - 1)
        self.cf = a != 0
        self.of = a == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_not(self, ops):
        bits = self.size(ops[0]) * 8
        self.wr(ops[0], ~self.rd(ops[0]) & ((1 << bits) - 1))

    def shift(self, ops, kind):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        count = self.rd(ops[1]) & (63 if bits == 64 else 31)
        if count == 0:
            return
        a = self.rd(ops[0])
        if kind == 'shl':
            raw = a << count
            self.cf = bool((raw >> bits) & 1)
        elif kind == 'shr':
            raw = a >> count
            self.cf = bool((a >> (count - 1)) & 1)
        else:
            sa = signed(a, bits)
            raw = sa >> count
            self.cf = bool((sa >> (count - 1)) & 1)
        res = raw & mask
        self.of = None
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_shl(self, ops):
        self.shift(ops, 'shl')

    def i_shr(self, ops):
        self.shift(ops, 'shr')

    def i_sar(self, ops):
        self.shift(ops, 'sar')

    def i_shld(self, ops):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        count = self.rd(ops[2]) & (63 if bits == 64 else 31)
        if count == 0:
            return
        a, b = self.rd(ops[0]), self.rd(ops[1])
        wide = (a << bits | b) << count
        self.cf = bool((wide >> (2 * bits)) & 1)
        res = (wide >> bits) & mask
        self.of = None
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_shrd(self, ops):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        count = self.rd(ops[2]) & (63 if bits == 64 else 31)
        if count == 0:
            return
        a, b = self.rd(ops[0]), self.rd(ops[1])
        wide = b << bits | a
        self.cf = bool((a >> (count - 1)) & 1)
        res = (wide >> count) & mask
        self.of = None
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_bsr(self, ops):
        src = self.rd(ops[1])
        if src == 0:
            raise Unmodelled(f'bsr of zero at {self.pc:#x}')
        self.zf = False
        self.cf = self.of = self.sf = None
        self.wr(ops[0], src.bit_length() - 1)

    def i_mul(self, ops):
        size = self.size(ops[0])
        bits = size * 8
        lo_op, hi_op = ('r', RAX, size), ('r', RDX, size)
        raw = self.rd(lo_op) * self.rd(ops[0])
        self.wr(lo_op, raw)
        self.wr(hi_op, raw >> bits)
        self.cf = self.of = raw >> bits != 0
        self.zf = self.sf = None

    def i_imul(self, ops):
        bits = self.size(ops[0]) * 8
        if len(ops) == 2:
            a, b = self.rd(ops[0]), self.rd(ops[1])
        elif len(ops) == 3:
            a, b = self.rd(ops[1]), self.rd(ops[2])
        else:
            raise Unmodelled(f'one-operand imul at {self.pc:#x}')
        b &= (1 << bits) - 1
        raw = signed(a, bits) * signed(b, bits)
        res = raw & ((1 << bits) - 1)
        self.cf = self.of = signed(res, bits) != raw
        self.zf = self.sf = None
        self.wr(ops[0], res)

    def i_div(self, ops):
        size = self.size(ops[0])
        bits = size * 8
        lo_op, hi_op = ('r', RAX, size), ('r', RDX, size)
        num = (self.rd(hi_op) << bits) | self.rd(lo_op)
        den = self.rd(ops[0])
        if den == 0 or num // den >> bits:
            raise Unmodelled(f'divide fault at {self.pc:#x}')
        self.wr(lo_op, num // den)
        self.wr(hi_op, num % den)
        self.cf = self.of = self.zf = self.sf = None

    # control flow

    def jcc(self, cc, ops):
        if self.CC[cc](self):
            self.pc = ops[0][1]

    def cmov(self, cc, ops):
        dst, src = ops
        val = self.rd(src)
        if self.CC[cc](self):
            self.wr(dst, val)
        elif dst[2] == 4:
            self.wr(dst, self.rd(dst))

    def setcc(self, cc, ops):
        self.wr(ops[0], int(bool(self.CC[cc](self))))

    def target(self, op):
        return op[1] if op[0] == 't' else self.rd(op)

    def i_jmp(self, ops):
        self.pc = self.target(ops[0])

    def i_call(self, ops):
        dest = self.target(ops[0])
        self.regs[RSP] -= 8
        self.store(self.regs[RSP], 8, self.pc)
        self.pc = dest

    def i_ret(self, ops):
        self.pc = self.load(self.regs[RSP], 8)
        self.regs[RSP] += 8

    # SSE moves

    def xrd(self, op):
        if op[0] == 'x':
            if self.xmm[op[1]] is None:
                raise Unmodelled(f'read of unset xmm at {self.pc:#x}')
            return self.xmm[op[1]]
        return self.rd(op)

    def xwr(self, op, val):
        if op[0] == 'x':
            self.xmm[op[1]] = val
        else:
            self.wr(op, val)

    def i_movups(self, ops):
        self.xwr(ops[0], self.xrd(ops[1]))

    def i_movaps(self, ops):
        for op in ops:
            if op[0] == 'm' and self.ea(op) % 16:
                raise Unmodelled(f'misaligned movaps at {self.pc:#x}')
        self.xwr(ops[0], self.xrd(ops[1]))

    def i_xorps(self, ops):
        if ops[0] != ops[1]:
            raise Unmodelled(f'xorps of distinct operands at {self.pc:#x}')
        self.xmm[ops[0][1]] = 0

    def unknown(self, mn, va, ops):
        raise Unmodelled(f'mnemonic {mn} at {va:#x}')

    # libc stubs

    def after_stub(self, result):
        self.setreg(RAX, result)
        self.poison(RCX, RDX, RSI, RDI, R8, R9, R10, R11)
        self.cf = self.zf = self.sf = self.of = None
        self.i_ret(())

    def memset(self):
        dst, val, n = self.regs[RDI], self.regs[RSI] & 0xff, self.regs[RDX]
        for i in range(n):
            self.store(dst + i, 1, val)
        self.after_stub(dst)

    def memcpy(self):
        dst, src, n = self.regs[RDI], self.regs[RSI], self.regs[RDX]
        for i in range(n):
            self.store(dst + i, 1, self.load(src + i, 1))
        self.after_stub(dst)

    def run(self, entry, stop=(), limit=20000):
        self.pc = entry
        code = self.code
        seen = self.seen
        while True:
            pc = self.pc
            if pc == RET_MAGIC or pc in stop:
                return pc
            if pc == MEMSET_STUB:
                self.memset()
                continue
            if pc == MEMCPY_STUB:
                self.memcpy()
                continue
            ins = code.get(pc)
            if ins is None:
                raise Unmodelled(f'no instruction at {pc:#x}')
            self.steps += 1
            if self.steps > limit:
                raise Unmodelled('step limit')
            seen.add(pc)
            self.pc = ins[2]
            ins[0](ins[1])


