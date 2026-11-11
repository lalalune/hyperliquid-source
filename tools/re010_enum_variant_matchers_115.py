#!/usr/bin/env python3
"""Reconstruct three node #115 serde variant matchers (visit_str + visit_bytes) and prove them against the bytes.

The MessagePack identifier decoder of node #115 exists in several 1769-byte
copies. Each copy calls one `visit_bytes` matcher (twice) and one `visit_str`
matcher of serde's derived variant identifier visitor. The `Action` copy
(0x1af3b70) is reconstructed elsewhere; this tool takes the three sibling
copies 0x195c140, 0x1bfca70 and 0x1c2d2c0 and their six matchers:

* PERP: `perpDeploy`-style 17 names (`registerAsset` .. `hip3Star`);
* SHORT114: 114 short names (`a` .. `ttt`);
* TAG18: 18 short tags (`e`, `r`, `b`, `btp`, ...).

This tool:

1. checks the input digest, binds each decoder copy to its matchers by the
   `e8 rel32` calls at the same offsets the `Action` copy uses, and reads every
   VARIANTS slice (`&[&str]`, 16-byte pointer/length pairs filled by
   R_X86_64_RELATIVE relocations) from the `lea rcx; mov r8d, N` pair that
   feeds serde's unknown_variant;
2. interprets the original bytes of all six matchers with a fixed-pattern
   x86-64 subset interpreter (no external programs, the binary is never run);
3. compares every interpreted outcome with one pure reconstruction
   (`reconstructed_match`) over thousands of strings built from the bytes
   (the names, one-byte edits, truncations, extensions, every one-byte input,
   letter pairs and invalid UTF-8 for the byte entry points);
4. runs the visit_bytes landing pads in an unwind mode (LSDA call-site table);
5. proves full instruction coverage, one success store per name, and that
   wrong reconstructions and corrupted images are rejected.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records, uleb  # noqa: E402

BINARY = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# (enum label, decoder copy, visit_bytes matcher, visit_str matcher, VARIANTS slice, VARIANTS length)
ENUMS = (
    ('PERP', 0x195c140, 0x2ba4e30, 0x2ba5c90, 0x644d330, 17),
    ('SHORT114', 0x1bfca70, 0x287dcb0, 0x287ec80, 0x643f1a8, 114),
    ('TAG18', 0x1c2d2c0, 0x286cc60, 0x286cef0, 0x643e4a8, 18),
)
# VARIANTS positions that name the same variant as the position before them (serde aliases).
# The literal is the reconstruction; the success-store immediates in the bytes are the check.
ALIAS_POSITIONS = {'PERP': frozenset({10}), 'SHORT114': frozenset(), 'TAG18': frozenset()}
# The reconstructed `Action` decoder copy and its matchers anchor the call offsets.
ACTION_DECODER, ACTION_BYTES, ACTION_STR = 0x1af3b70, 0x2b9cdb0, 0x2ba1af0
DECODER_BYTES = 1769
BYTES_CALL_OFFSETS = (1057, 1195)
STR_CALL_OFFSET = 1238
UNKNOWN_VARIANT = 0x17fbba0
# GOT slots the byte matchers call through (R_X86_64_RELATIVE targets are checked).
LOSSY_SLOT, LOSSY_TARGET = 0x64df640, 0x141ca00
FREE_SLOT, FREE_TARGET = 0x64df4a0, 0x635de30
UNWIND_RESUME = 0x63f0a50             # PLT stub; its JUMP_SLOT symbol is checked

IN_BASE, OUT_BASE, STACK_TOP, HEAP_BASE = 0x7000_0000_0000, 0x7100_0000_0000, 0x7200_0000_0000, 0x7300_0000_0000
ERR_MARK = bytes(range(0xe0, 0x100))  # 32 bytes the stubbed unknown_variant stores
EXC_PTR = 0x7500_0000_0080            # in-flight exception object handed to the landing pad
BORROWED = 1 << 63                    # Cow<str>::Borrowed niche in the capacity word
OK_TAG = 9
MASK64 = (1 << 64) - 1
STEP_LIMIT = 600


class Fault(Exception):
    pass


class Image:
    def __init__(self, data):
        if hashlib.sha256(data).hexdigest() != SHA256:
            raise ValueError('input binary SHA-256 mismatch')
        self.data = data
        # NOBITS sections carry no file bytes and are excluded from VA reads.
        self.secs = [s for s in sections(data) if s['type'] != 8 and s['address'] and s['size']]
        self.by_name = {s['name']: s for s in self.secs}
        self.relative = {}
        rd = self.by_name['.rela.dyn']
        for i in range(rd['size'] // 24):
            off, info, add = struct.unpack_from('<QQq', data, rd['offset'] + i * 24)
            if info & 0xffffffff == 8:
                self.relative[off] = add

    def off(self, va, n=1):
        for s in self.secs:
            if s['address'] <= va and va + n <= s['address'] + s['size']:
                return s['offset'] + va - s['address']
        raise Fault(f'unmapped static read {va:#x}+{n}')

    def read(self, va, n):
        o = self.off(va, n)
        return self.data[o:o + n]

    def plt_symbol(self, va):
        """Name of the JUMP_SLOT symbol behind a `jmp *GOT(%rip)` PLT stub."""
        stub = self.read(va, 6)
        if stub[:2] != b'\xff\x25':
            raise Fault(f'{va:#x} is not a PLT jmp stub')
        slot = va + 6 + struct.unpack('<i', stub[2:])[0]
        rp = self.by_name['.rela.plt']
        for i in range(rp['size'] // 24):
            off, info, _ = struct.unpack_from('<QQq', self.data, rp['offset'] + i * 24)
            if off == slot and info & 0xffffffff == 7:
                dynsym, dynstr = self.by_name['.dynsym'], self.by_name['.dynstr']
                name = struct.unpack_from('<I', self.data, dynsym['offset'] + 24 * (info >> 32))[0]
                start = dynstr['offset'] + name
                return self.data[start:self.data.index(b'\0', start)].decode()
        raise Fault(f'no JUMP_SLOT relocation for {slot:#x}')

    def call_sites(self, lsda, func_start):
        """LSDA call-site table: (start, end, landing pad or 0, action) as absolute VAs."""
        o = self.off(lsda, 4)
        end_all = o + 4096
        if self.data[o] != 0xff:
            raise Fault('LSDA has a landing-pad base')
        if self.data[o + 1] != 0xff:
            raise Fault('LSDA has a type table')
        if self.data[o + 2] != 0x01:
            raise Fault('LSDA call sites are not uleb128')
        length, p = uleb(self.data, o + 3, end_all)
        rows, stop = [], p + length
        while p < stop:
            start, p = uleb(self.data, p, stop)
            size, p = uleb(self.data, p, stop)
            lp, p = uleb(self.data, p, stop)
            action, p = uleb(self.data, p, stop)
            rows.append((func_start + start, func_start + start + size, func_start + lp if lp else 0, action))
        return rows

    def variants(self, va, count):
        names = []
        for i in range(count):
            slot = va + 16 * i
            if slot not in self.relative:
                raise ValueError(f'VARIANTS slot {slot:#x} has no RELATIVE relocation')
            length = struct.unpack_from('<Q', self.read(slot + 8, 8))[0]
            names.append(self.read(self.relative[slot], length))
        return names

    def direct_call_target(self, va):
        raw = self.read(va, 5)
        if raw[0] != 0xe8:
            raise Fault(f'{va:#x} is not an e8 rel32 call')
        return va + 5 + struct.unpack('<i', raw[1:])[0]


def mutated_image(base, data):
    img = Image.__new__(Image)
    img.data, img.secs, img.by_name, img.relative = data, base.secs, base.by_name, base.relative
    return img


def fde_record(fdes, start):
    rows = [f for f in fdes if f['start'] == start]
    if len(rows) != 1:
        raise Fault(f'{start:#x} is not the start of exactly one FDE')
    return rows[0]


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class Insn:
    __slots__ = ('va', 'size', 'op', 'a', 'b', 'w', 'raw')


ALU = {0x01: 'add', 0x03: 'add', 0x09: 'or', 0x0b: 'or', 0x21: 'and', 0x23: 'and', 0x29: 'sub', 0x2b: 'sub',
       0x31: 'xor', 0x33: 'xor', 0x38: 'cmp', 0x39: 'cmp', 0x3a: 'cmp', 0x3b: 'cmp', 0x84: 'test', 0x85: 'test',
       0x88: 'mov', 0x89: 'mov', 0x8a: 'mov', 0x8b: 'mov'}
ALU_RM_FIRST = (0x01, 0x09, 0x21, 0x29, 0x31, 0x38, 0x39, 0x84, 0x85, 0x88, 0x89)
ALU_BYTE = (0x38, 0x3a, 0x84, 0x88, 0x8a)
ACC = {0x05: 'add', 0x0d: 'or', 0x25: 'and', 0x2d: 'sub', 0x35: 'xor', 0x3d: 'cmp', 0xa9: 'test'}
ACC8 = {0x04: 'add', 0x0c: 'or', 0x24: 'and', 0x2c: 'sub', 0x34: 'xor', 0x3c: 'cmp', 0xa8: 'test'}
GROUP = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}


def decode(img, va):
    """Decode one instruction of the fixed subset used by the six matchers."""
    b = img.read(va, 16)
    p, opsz, rep, rex = 0, None, False, 0
    while b[p] in (0x66, 0xf3):
        opsz = 16 if b[p] == 0x66 else opsz
        rep = rep or b[p] == 0xf3
        p += 1
    if 0x40 <= b[p] <= 0x4f:
        rex = b[p]
        p += 1
    W, R, X, B = rex >> 3 & 1, rex >> 2 & 1, rex >> 1 & 1, rex & 1
    width = 64 if W else (opsz or 32)
    ins = Insn()
    ins.va, ins.w, ins.a, ins.b = va, width, None, None

    def modrm():
        nonlocal p
        m = b[p]
        p += 1
        mod, reg, rm = m >> 6, (m >> 3 & 7) | R << 3, m & 7
        if mod == 3:
            return reg, ('r', rm | B << 3)
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = b[p]
            p += 1
            scale, idx, bs = 1 << (sib >> 6), (sib >> 3 & 7) | X << 3, sib & 7
            index = None if idx == 4 else idx
            if bs == 5 and mod == 0:
                raise Fault(f'absolute SIB address at {va:#x}')
            base = bs | B << 3
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | B << 3
        if rip:
            disp = struct.unpack_from('<i', b, p)[0]
            p += 4
        elif mod == 1:
            disp = sx(b[p], 8)
            p += 1
        elif mod == 2:
            disp = struct.unpack_from('<i', b, p)[0]
            p += 4
        else:
            disp = 0
        return reg, ('m', base, index, scale, disp, rip)

    def low8(opnd):
        # Without REX, byte registers 4..7 are ah/ch/dh/bh; the subset rejects them.
        if opnd[0] == 'r' and not rex and 4 <= opnd[1] <= 7:
            raise Fault(f'high byte register at {va:#x}')
        return opnd

    def imm(n):
        nonlocal p
        v = int.from_bytes(b[p:p + n], 'little')
        p += n
        return v

    op = b[p]
    p += 1
    if op in ALU:
        reg, rm = modrm()
        ins.op = ALU[op]
        ins.a, ins.b = (rm, ('r', reg)) if op in ALU_RM_FIRST else (('r', reg), rm)
        if op in ALU_BYTE:
            ins.w = 8
            low8(ins.a)
            low8(ins.b)
    elif op in ACC:
        ins.op, ins.a = ACC[op], ('r', 0)
        n = 2 if width == 16 else 4
        ins.b = ('i', sx(imm(n), n * 8) & ((1 << width) - 1))
    elif op in ACC8:
        ins.op, ins.a, ins.b, ins.w = ACC8[op], ('r', 0), ('i', imm(1)), 8
    elif op in (0x81, 0x83, 0x80):
        reg, rm = modrm()
        if (reg & 7) not in GROUP:
            raise Fault(f'unsupported group op at {va:#x}')
        ins.op = GROUP[reg & 7]
        if op == 0x80:
            ins.w = 8
            rm = low8(rm)
            ins.b = ('i', imm(1))
        elif op == 0x83:
            ins.b = ('i', sx(imm(1), 8) & ((1 << width) - 1))
        else:
            n = 2 if width == 16 else 4
            ins.b = ('i', sx(imm(n), n * 8) & ((1 << width) - 1))
        ins.a = rm
    elif op == 0x8d:
        reg, rm = modrm()
        ins.op, ins.a, ins.b = 'lea', ('r', reg), rm
    elif op == 0x63:
        reg, rm = modrm()
        ins.op, ins.a, ins.b = 'movsxd', ('r', reg), rm
    elif op == 0xc7:
        reg, rm = modrm()
        n = 2 if width == 16 else 4
        ins.op, ins.a, ins.b = 'mov', rm, ('i', sx(imm(n), n * 8) & ((1 << width) - 1))
    elif op == 0xc6:
        reg, rm = modrm()
        ins.op, ins.a, ins.b, ins.w = 'mov', low8(rm), ('i', imm(1)), 8
    elif 0xb8 <= op <= 0xbf:
        ins.op, ins.a = 'mov', ('r', (op - 0xb8) | B << 3)
        ins.b = ('i', imm(8 if W else 4))
    elif 0x50 <= op <= 0x57:
        ins.op, ins.a, ins.w = 'push', ('r', (op - 0x50) | B << 3), 64
    elif 0x58 <= op <= 0x5f:
        ins.op, ins.a, ins.w = 'pop', ('r', (op - 0x58) | B << 3), 64
    elif 0x70 <= op <= 0x7f:
        ins.op, ins.a = 'j', op & 15
        ins.b = sx(imm(1), 8)
    elif op == 0xeb:
        ins.op, ins.b = 'jmp', sx(imm(1), 8)
    elif op == 0xe9:
        ins.op, ins.b = 'jmp', sx(imm(4), 32)
    elif op == 0xe8:
        ins.op, ins.b = 'call', sx(imm(4), 32)
    elif op == 0xc3:
        ins.op = 'ret'
    elif op == 0xcc:
        ins.op = 'int3'
    elif op == 0xff:
        reg, rm = modrm()
        ins.op = {4: 'jmpr', 2: 'callr'}.get(reg & 7)
        if ins.op is None:
            raise Fault(f'unsupported ff form at {va:#x}')
        ins.a, ins.w = rm, 64
    elif op == 0x0f:
        op2 = b[p]
        p += 1
        if 0x80 <= op2 <= 0x8f:
            ins.op, ins.a, ins.b = 'j', op2 & 15, sx(imm(4), 32)
        elif 0x90 <= op2 <= 0x9f:
            _, rm = modrm()
            ins.op, ins.a, ins.b, ins.w = 'setcc', low8(rm), op2 & 15, 8
        elif op2 in (0xb6, 0xb7):
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'movzx', ('r', reg), rm
            ins.w = 8 if op2 == 0xb6 else 16
            if op2 == 0xb6:
                low8(rm)
        elif op2 == 0x10 and not rep and opsz is None:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'xload', reg, rm
        elif op2 == 0x11 and not rep and opsz is None:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'xstore', rm, reg
        elif op2 == 0x6f and rep and opsz is None:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'xload', reg, rm  # movdqu xmm, m128
        elif op2 == 0x6e and opsz == 16 and not W:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'movd', reg, rm  # movd xmm, r/m32
        elif op2 in (0x74, 0xdb) and opsz == 16 and not rep:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = {0x74: 'pcmpeqb', 0xdb: 'pand'}[op2], reg, rm
        elif op2 == 0xd7 and opsz == 16 and not rep:
            reg, rm = modrm()
            if rm[0] != 'r':
                raise Fault(f'pmovmskb from memory at {va:#x}')
            ins.op, ins.a, ins.b = 'pmovmskb', ('r', reg), rm[1]
        else:
            raise Fault(f'unsupported 0f {op2:02x} at {va:#x}')
    else:
        raise Fault(f'unsupported opcode {op:02x} at {va:#x}')
    ins.size = p
    ins.raw = bytes(b[:p])
    return ins


class Machine:
    """Runs one matcher. kind 'bytes' = visit_bytes (lossy + free path), 'str' = visit_str."""

    def __init__(self, img, kind, start, end, variants, cache, sites):
        self.img, self.kind, self.start, self.end = img, kind, start, end
        self.variants_va, self.count = variants
        self.cache, self.sites = cache, sites

    def run(self, value, unwind=False):
        self.inp = bytes(value)
        self.out = bytearray(32)
        self.heap = bytearray()
        self.stack = bytearray(0x200)
        self.r = [0] * 16
        self.x = [bytes(16)] * 16
        self.r[7], self.r[6], self.r[2] = OUT_BASE, IN_BASE, len(value)
        self.r[4] = STACK_TOP - 8
        self.flags = dict(z=0, c=0, s=0, o=0)
        self.calls, self.trace = [], []
        self.err_text, self.freed = None, []
        self.unwind, self.unwinding = unwind, False
        pc = self.start
        for _ in range(STEP_LIMIT):
            if not self.start <= pc < self.end:
                raise Fault(f'left function at {pc:#x}')
            ins = self.cache.get(pc)
            if ins is None:
                ins = self.cache[pc] = decode(self.img, pc)
            self.trace.append(pc)
            nxt = pc + ins.size
            res = self.step(ins, nxt)
            if res == 'ret':
                if self.unwind:
                    raise Fault('returned normally while unwinding')
                return self.outcome()
            if res == 'resume':
                return ('unwind', len(self.freed))
            pc = nxt if res is None else res
        raise Fault('step limit')

    def outcome(self):
        if self.r[0] != OUT_BASE:
            raise Fault('rax does not return the out pointer')
        if self.out[0] == OK_TAG and not any(self.out[2:]) and self.err_text is None:
            return ('ok', self.out[1])
        if self.err_text is not None and bytes(self.out) == ERR_MARK:
            return ('unknown', self.err_text, len(self.freed))
        raise Fault('unrecognised output ' + self.out.hex())

    # memory -------------------------------------------------------------
    def addr(self, m, nxt):
        _, base, index, scale, disp, rip = m
        a = nxt + disp if rip else disp
        if base is not None:
            a += self.r[base]
        if index is not None:
            a += self.r[index] * scale
        return a & MASK64

    def region(self, a, n):
        for base, buf in ((IN_BASE, self.inp), (OUT_BASE, self.out), (HEAP_BASE, self.heap),
                          (STACK_TOP - len(self.stack), self.stack)):
            if base <= a < base + len(buf) + 64:
                if a + n > base + len(buf):
                    raise Fault(f'access past buffer {a:#x}+{n}')
                return buf, a - base
        return None, None

    def load(self, a, n):
        buf, o = self.region(a, n)
        if buf is None:
            return self.img.read(a, n)
        return bytes(buf[o:o + n])

    def store(self, a, data):
        buf, o = self.region(a, len(data))
        if buf is None or buf is self.inp or buf is self.heap:
            raise Fault(f'store outside writable buffers {a:#x}')
        buf[o:o + len(data)] = data

    def get(self, opnd, w, nxt):
        if opnd[0] == 'r':
            return self.r[opnd[1]] & ((1 << w) - 1)
        if opnd[0] == 'i':
            return opnd[1]
        return int.from_bytes(self.load(self.addr(opnd, nxt), w // 8), 'little')

    def put(self, opnd, w, v, nxt):
        v &= (1 << w) - 1
        if opnd[0] == 'r':
            n = opnd[1]
            if w == 64 or w == 32:
                self.r[n] = v
            else:
                self.r[n] = (self.r[n] & ~((1 << w) - 1) & MASK64) | v
        else:
            self.store(self.addr(opnd, nxt), v.to_bytes(w // 8, 'little'))

    def setf(self, w, res, a=None, b=None, kind='logic'):
        m = (1 << w) - 1
        r = res & m
        self.flags['z'] = int(r == 0)
        self.flags['s'] = r >> (w - 1) & 1
        if kind == 'logic':
            self.flags['c'] = self.flags['o'] = 0
        elif kind == 'sub':
            self.flags['c'] = int(a < b)
            self.flags['o'] = int(sx(a, w) - sx(b, w) != sx(r, w))
        else:
            self.flags['c'] = int(a + b > m)
            self.flags['o'] = int(sx(a, w) + sx(b, w) != sx(r, w))
        return r

    def cond(self, cc):
        f = self.flags
        base = cc >> 1
        v = [f['o'], f['c'], f['z'], f['c'] | f['z'], f['s'], None,
             int(f['s'] != f['o']), int(f['z'] or f['s'] != f['o'])][base]
        if v is None:
            raise Fault('parity flag not modelled')
        return bool(v) ^ bool(cc & 1)

    def step(self, ins, nxt):
        op, w = ins.op, ins.w
        if op in ('add', 'or', 'xor', 'and', 'sub', 'cmp', 'test'):
            a, b = self.get(ins.a, w, nxt), self.get(ins.b, w, nxt)
            if op == 'add':
                r = self.setf(w, a + b, a, b, 'add')
            elif op in ('sub', 'cmp'):
                r = self.setf(w, a - b, a, b, 'sub')
            else:
                r = self.setf(w, {'or': a | b, 'xor': a ^ b, 'and': a & b, 'test': a & b}[op])
            if op not in ('cmp', 'test'):
                self.put(ins.a, w, r, nxt)
        elif op == 'setcc':
            self.put(ins.a, 8, int(self.cond(ins.b)), nxt)
        elif op == 'mov':
            self.put(ins.a, w, self.get(ins.b, w, nxt), nxt)
        elif op == 'lea':
            self.put(ins.a, w, self.addr(ins.b, nxt), nxt)
        elif op == 'movsxd':
            self.put(ins.a, 64, sx(self.get(ins.b, 32, nxt), 32) & MASK64, nxt)
        elif op == 'movzx':
            self.put(ins.a, 32, self.get(ins.b, w, nxt), nxt)
        elif op == 'push':
            self.r[4] -= 8
            self.store(self.r[4], self.r[ins.a[1]].to_bytes(8, 'little'))
        elif op == 'pop':
            self.r[ins.a[1]] = int.from_bytes(self.load(self.r[4], 8), 'little')
            self.r[4] += 8
        elif op == 'j':
            return nxt + ins.b if self.cond(ins.a) else None
        elif op == 'jmp':
            return nxt + ins.b
        elif op == 'jmpr':
            return self.get(ins.a, 64, nxt)
        elif op == 'ret':
            if self.r[4] != STACK_TOP - 8:
                raise Fault('unbalanced stack at ret')
            return 'ret'
        elif op in ('call', 'callr'):
            return self.call(ins, nxt)
        elif op == 'xload':
            self.x[ins.a] = self.load(self.addr(ins.b, nxt), 16) if ins.b[0] == 'm' else self.x[ins.b[1]]
        elif op == 'xstore':
            self.store(self.addr(ins.a, nxt), self.x[ins.b])
        elif op == 'movd':
            self.x[ins.a] = self.get(ins.b, 32, nxt).to_bytes(4, 'little') + bytes(12)
        elif op in ('pcmpeqb', 'pand'):
            other = self.load(self.addr(ins.b, nxt), 16) if ins.b[0] == 'm' else self.x[ins.b[1]]
            mine = self.x[ins.a]
            if op == 'pcmpeqb':
                self.x[ins.a] = bytes(0xff if p == q else 0 for p, q in zip(mine, other))
            else:
                self.x[ins.a] = bytes(p & q for p, q in zip(mine, other))
        elif op == 'pmovmskb':
            self.put(ins.a, 32, sum((v >> 7 & 1) << k for k, v in enumerate(self.x[ins.b])), nxt)
        else:
            raise Fault(f'no semantics for {op}')
        return None

    def clobber(self):
        for n in (1, 2, 6, 7, 8, 9, 10, 11):
            self.r[n] = 0xdead_0000 + n  # caller-saved registers are clobbered

    def call(self, ins, nxt):
        if ins.op == 'callr':
            slot = self.addr(ins.a, nxt)
            target = self.img.relative.get(slot)
            if self.kind != 'bytes':
                raise Fault(f'indirect call through {slot:#x} in a visit_str matcher')
            if slot == LOSSY_SLOT and target == LOSSY_TARGET:
                # String::from_utf8_lossy(out=rdi, bytes=(rsi, rdx)) -> Cow<str>
                if (self.r[6], self.r[2]) != (IN_BASE, len(self.inp)):
                    raise Fault('from_utf8_lossy is not given the input bytes')
                try:
                    self.inp.decode('utf-8')
                    cow = (BORROWED, IN_BASE, len(self.inp))
                except UnicodeDecodeError:
                    self.heap = bytearray(self.inp.decode('utf-8', 'replace').encode('utf-8'))
                    cow = (len(self.heap), HEAP_BASE, len(self.heap))
                self.store(self.r[7], struct.pack('<QQQ', *cow))
                self.calls.append(('from_utf8_lossy', slot))
                self.clobber()
                return None
            if slot == FREE_SLOT and target == FREE_TARGET:
                if (self.r[7], self.r[6], self.r[2]) != (HEAP_BASE, len(self.heap), 0) or not self.heap:
                    raise Fault('free is not given the owned lossy string')
                self.freed.append((self.r[7], self.r[6]))
                self.calls.append(('free', slot))
                self.clobber()
                return None
            raise Fault(f'indirect call through {slot:#x}')
        target = nxt + ins.b
        if target == UNWIND_RESUME:
            if not self.unwinding or self.r[7] != EXC_PTR:
                raise Fault('_Unwind_Resume without the in-flight exception')
            if self.img.plt_symbol(target) != '_Unwind_Resume':
                raise Fault('resume target is not the _Unwind_Resume PLT stub')
            self.calls.append(('_Unwind_Resume', target))
            return 'resume'
        if target != UNKNOWN_VARIANT:
            raise Fault(f'unexpected direct call {target:#x}')
        # unknown_variant(out=rdi, value=(rsi, rdx), expected=(rcx, r8))
        ptr, n, exp, cnt = self.r[6], self.r[2], self.r[1], self.r[8]
        if (exp, cnt) != (self.variants_va, self.count):
            raise Fault('unknown_variant is not given (VARIANTS, count)')
        text = self.load(ptr, n)
        expect = self.inp.decode('utf-8', 'replace').encode('utf-8')
        if text != expect:
            raise Fault('unknown_variant text is not the (lossy) input')
        self.err_text = text
        self.calls.append(('unknown_variant', target))
        out = self.r[7]
        self.clobber()
        if self.unwind:
            # unknown_variant unwinds: resume at the landing pad its LSDA call site names
            site = [c for c in self.sites if c[0] <= ins.va < c[1]]
            if len(site) != 1 or not site[0][2]:
                raise Fault('unknown_variant call has no landing pad')
            self.unwinding = True
            self.r[0], self.r[2] = EXC_PTR, site[0][3]
            return site[0][2]
        self.store(out, ERR_MARK)
        return None


# reconstruction --------------------------------------------------------------
def variant_table(names, alias_positions):
    """(wire name, variant index) per VARIANTS entry.

    serde lists every accepted name (aliases included) in VARIANTS. A position
    in `alias_positions` names the same variant as the entry before it, so the
    variant index is the position minus the aliases at or before it.
    """
    table, index = [], -1
    for pos, name in enumerate(names):
        index += pos not in alias_positions
        table.append((name, index))
    return table


def reconstructed_match(value, table):
    """Pure reconstruction shared by every visit_str / visit_bytes matcher here.

    Exact, case-sensitive, whole-slice match against the wire names of
    `variant_table` -> Ok(variant index); otherwise unknown_variant(lossy
    text, VARIANTS). For the byte entry point the lossy string is owned (and
    freed exactly once) iff the input is not valid UTF-8; a `&str` input is
    always valid UTF-8, so the visit_str form never frees.
    """
    for wire, index in table:
        if value == wire:
            return ('ok', index)
    try:
        value.decode('utf-8')
        owned = 0
    except UnicodeDecodeError:
        owned = 1
    return ('unknown', value.decode('utf-8', 'replace').encode('utf-8'), owned)


def reconstructed_unwind(value):
    """If unknown_variant unwinds, the landing pad drops the lossy string (frees it iff owned) and resumes."""
    return ('unwind', reconstructed_match(value, [])[2])


def _err(s):
    return reconstructed_match(s, [])


def _positional(names):
    return [(n, k) for k, n in enumerate(names)]


MUTANTS = {
    'case_insensitive': lambda s, w: next((('ok', i) for n, i in w if s.lower() == n.lower()), _err(s)),
    'prefix_match': lambda s, w: next((('ok', i) for n, i in w if s and n.startswith(s)), _err(s)),
    'drop_last_variant': lambda s, w: reconstructed_match(s, w[:-1]),
    'drop_first_variant_shift': lambda s, w: reconstructed_match(s, [(n, i - 1) for n, i in w[1:]]),
    'off_by_one_index': lambda s, w: (lambda r: ('ok', r[1] + 1) if r[0] == 'ok' else r)(reconstructed_match(s, w)),
    'swap_indices_3_4': lambda s, w: reconstructed_match(s, w[:3] + [(w[3][0], w[4][1]), (w[4][0], w[3][1])] + w[5:]),
    'sorted_order': lambda s, w: reconstructed_match(s, _positional(sorted(n for n, _ in w))),
    'ignore_last_byte': lambda s, w: next((('ok', i) for n, i in w if len(s) == len(n) and s[:-1] == n[:-1]), _err(s)),
    'first_byte_only': lambda s, w: next((('ok', i) for n, i in w if len(s) == len(n) and s[:1] == n[:1]), _err(s)),
    'accept_trailing_nul': lambda s, w: reconstructed_match(s.rstrip(b'\0'), w),
    'strip_whitespace': lambda s, w: reconstructed_match(s.strip(), w),
    'strict_utf8_text': lambda s, w: (lambda r: ('unknown', s.decode('utf-8', 'ignore').encode('utf-8'), r[2]) if r[0] == 'unknown' else r)(reconstructed_match(s, w)),
    'never_free': lambda s, w: (lambda r: r[:2] + (0,) if r[0] == 'unknown' else r)(reconstructed_match(s, w)),
    'always_free': lambda s, w: (lambda r: r[:2] + (1,) if r[0] == 'unknown' else r)(reconstructed_match(s, w)),
    'lossy_then_match': lambda s, w: reconstructed_match(s.decode('utf-8', 'replace').encode('utf-8'), w),
    'ascii_fold_first_byte': lambda s, w: reconstructed_match(s[:1].lower() + s[1:], w),
}
# Only meaningful where the table has an alias: the positional index ignores it.
ALIAS_MUTANTS = {
    'no_alias_positional_index': lambda s, w: reconstructed_match(s, _positional([n for n, _ in w])),
    'alias_rejected': lambda s, w: reconstructed_match(s, [e for k, e in enumerate(w) if k == 0 or e[1] != w[k - 1][1]]),
}
# Mutants that only differ on invalid UTF-8 cannot be told apart through visit_str.
BYTES_ONLY_MUTANTS = ('always_free', 'lossy_then_match', 'never_free', 'strict_utf8_text')
UNWIND_KINDS = ('truncate', 'invalid_utf8_tail', 'filler_ff', 'truncated_utf8_tail')


def build_cases(names):
    seen, cases = set(), []

    def add(kind, s):
        if s not in seen:
            seen.add(s)
            cases.append((kind, s))
    for n in names:
        add('exact', n)
    for n in names:
        for i in range(len(n)):
            c = n[i]
            add('byte_plus1', n[:i] + bytes([(c + 1) & 0xff]) + n[i + 1:])
            add('byte_minus1', n[:i] + bytes([(c - 1) & 0xff]) + n[i + 1:])
            if 0x41 <= c <= 0x5a or 0x61 <= c <= 0x7a:
                add('case_flip', n[:i] + bytes([c ^ 0x20]) + n[i + 1:])
        add('truncate', n[:-1])
        add('drop_first', n[1:])
        add('extend_s', n + b's')
        add('extend_nul', n + b'\0')
        add('double', n + n)
        add('high_last_byte', n[:-1] + bytes([n[-1] | 0x80]))
        add('invalid_utf8_tail', n + b'\xff')
        add('two_byte_utf8_tail', n[:-1] + b'\xc3\xa9')
        add('truncated_utf8_tail', n[:-1] + b'\xe2\x82')
    for c in range(256):
        add('single_byte', bytes([c]))
    letters = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if max(len(n) for n in names) <= 3:
        # Short-name enums: every two-letter input exercises each compare arm on both sides.
        for x in letters:
            for y in (x, x ^ 0x20, x + 1):
                add('letter_pair', bytes([x, y]))
        for n in names:
            if len(n) == 3:
                for y in letters:
                    add('letter_triple', n[:2] + bytes([y]))
    for length in range(0, 33):
        add('filler', b'a' * length)
        add('filler_ff', b'\xff' * length)
    return cases


def coverage_sweep(img, start, end):
    """Linear sweep of the FDE extent; every byte must belong to a decoded instruction."""
    pc, out = start, []
    while pc < end:
        ins = decode(img, pc)
        out.append(ins)
        pc += ins.size
    if pc != end:
        raise Fault('sweep overran FDE end')
    return out


def jump_tables(img, insns):
    """`lea reg,[rip+T]; movsxd r,[reg+idx*4]; add r,reg; jmp r` -> (lea va, table va, bound, targets)."""
    out = []
    for k in range(len(insns) - 3):
        a, b, c, d = insns[k:k + 4]
        if a.op == 'lea' and a.b[5] and b.op == 'movsxd' and c.op == 'add' and d.op == 'jmpr':
            table = a.va + a.size + a.b[4]
            # the bound is the immediate of the closest preceding `cmp reg, imm` + `ja`
            bound = None
            for q in range(k - 1, max(-1, k - 5), -1):
                if insns[q].op == 'cmp' and insns[q].b[0] == 'i':
                    bound = insns[q].b[1]
                    break
            if bound is None:
                raise Fault(f'jump table at {a.va:#x} has no bound')
            targets = [table + struct.unpack('<i', img.read(table + 4 * i, 4))[0] for i in range(bound + 1)]
            out.append((a.va, table, bound + 1, targets))
    return out


def fmt(r):
    if r is None:
        return '-'
    if r[0] == 'ok':
        return f'ok:{r[1]}'
    if r[0] == 'unwind':
        return f'unwind:free{r[1]}'
    return f'unknown:{r[1].hex()}:free{r[2]}'


def generate(out_dir):
    data = BINARY.read_bytes()
    img = Image(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if img.relative.get(LOSSY_SLOT) != LOSSY_TARGET or img.relative.get(FREE_SLOT) != FREE_TARGET:
        raise Fault('GOT slot targets differ')
    _, fdes = eh_frame_records(data)
    summary = {'binary_sha256': SHA256, 'unknown_variant_callee': f'{UNKNOWN_VARIANT:#x}',
               'got_calls': {'from_utf8_lossy': {'slot': f'{LOSSY_SLOT:#x}', 'relative_target': f'{LOSSY_TARGET:#x}'},
                             'free': {'slot': f'{FREE_SLOT:#x}', 'relative_target': f'{FREE_TARGET:#x}'}},
               'enums': [], 'functions': []}
    bind_rows = ['decoder\tbytes\tcall_offset\tcall_va\ttarget\trole']
    anchor = fde_record(fdes, ACTION_DECODER)
    if anchor['end'] - ACTION_DECODER != DECODER_BYTES:
        raise Fault('anchor decoder size differs')
    for off in BYTES_CALL_OFFSETS + (STR_CALL_OFFSET,):
        role = 'visit_str' if off == STR_CALL_OFFSET else 'visit_bytes'
        want = ACTION_STR if off == STR_CALL_OFFSET else ACTION_BYTES
        got = img.direct_call_target(ACTION_DECODER + off)
        if got != want:
            raise Fault('anchor decoder call offsets differ')
        bind_rows.append(f'{ACTION_DECODER:#x}\t{DECODER_BYTES}\t{off}\t{ACTION_DECODER + off:#x}\t{got:#x}\t{role} (Action anchor)')
    fn_rows = ['enum\tkind\tstart\tfde_end\tbytes\tinstructions\tint3_padding\texecuted\tlsda\tlsda_call_sites\tjump_tables\tsuccess_stores\tcases\tmismatches\tunwind_cases\tunwind_mismatches']
    name_rows = ['enum\tposition\tvariant\twire_name\tlength\tbytes_store_va\tstr_store_va\tresult_word']
    table_rows = ['enum\tkind\tlea_va\ttable_va\tentry\ttarget\ttarget_role']
    site_rows = ['enum\tstart\tend\tlanding_pad\taction\tcalls_in_range']
    insn_rows = ['enum\tkind\tva\tbytes\top\texecuted_cases']
    case_rows = ['enum\tkind\tinput_hex\tlength\treconstructed\tvisit_bytes\tvisit_str']
    unwind_rows = ['enum\tkind\tinput_hex\tlength\treconstructed\tvisit_bytes']
    mutant_rows = ['enum\tmutant\tentry_point\tfirst_disagreeing_case\tdisagreements\tkilled']
    rs = ['// Reconstructed from node #115 bytes by tools/re010_enum_variant_matchers_115.py.',
          '// serde variant identifier visitors (visit_str and visit_bytes share one mapping).']
    model_total = model_killed = 0
    all_bad = []
    for label, decoder, fbytes, fstr, variants_va, count in ENUMS:
        drec = fde_record(fdes, decoder)
        if drec['end'] - decoder != DECODER_BYTES:
            raise Fault(f'decoder {decoder:#x} is not a {DECODER_BYTES}-byte copy')
        for off in BYTES_CALL_OFFSETS + (STR_CALL_OFFSET,):
            want = fstr if off == STR_CALL_OFFSET else fbytes
            got = img.direct_call_target(decoder + off)
            if got != want:
                raise Fault(f'decoder {decoder:#x}+{off} does not call {want:#x}')
            bind_rows.append(f'{decoder:#x}\t{DECODER_BYTES}\t{off}\t{decoder + off:#x}\t{got:#x}\t'
                             f'{"visit_str" if off == STR_CALL_OFFSET else "visit_bytes"} ({label})')
        names = img.variants(variants_va, count)
        if len(set(names)) != count:
            raise Fault('duplicate wire names')
        vtable = variant_table(names, ALIAS_POSITIONS[label])
        variant_count = vtable[-1][1] + 1
        cases = build_cases(names)
        results = {}
        stores = {}
        for kind, start in (('bytes', fbytes), ('str', fstr)):
            rec = fde_record(fdes, start)
            end = rec['end']
            insns = coverage_sweep(img, start, end)
            cache = {i.va: i for i in insns}
            # the VARIANTS pair is read from the bytes: lea rcx,[rip+slice] and, within the next
            # three instructions, mov r8d,count
            pairs = [(insns[k].va + insns[k].size + insns[k].b[4], q.b[1]) for k in range(len(insns) - 1)
                     if insns[k].op == 'lea' and insns[k].a == ('r', 1) and insns[k].b[5]
                     for q in insns[k + 1:k + 4] if q.op == 'mov' and q.a == ('r', 8) and q.b[0] == 'i']
            if pairs != [(variants_va, count)]:
                raise Fault(f'{start:#x} VARIANTS operands differ: {pairs}')
            lsda = rec['lsda']
            sites = img.call_sites(lsda, start) if lsda is not None else []
            if (kind == 'bytes') != (lsda is not None):
                raise Fault(f'{start:#x} LSDA presence differs from its kind')
            m = Machine(img, kind, start, end, (variants_va, count), cache, sites)
            executed, got_all = {}, []
            mismatch = 0
            fstores = {}
            for ckind, s in cases:
                if kind == 'str':
                    try:
                        s.decode('utf-8')
                    except UnicodeDecodeError:
                        got_all.append(None)
                        continue
                got = m.run(s)
                mismatch += got != reconstructed_match(s, vtable)
                got_all.append(got)
                for pc in set(m.trace):
                    executed[pc] = executed.get(pc, 0) + 1
                if ckind == 'exact':
                    st = [pc for pc in m.trace if cache[pc].op == 'mov' and cache[pc].a[0] == 'm' and cache[pc].w == 16]
                    if len(st) != 1:
                        raise Fault(f'{start:#x}: {s!r} does not end in one 16-bit success store')
                    fstores.setdefault(st[0], []).append(names.index(s))
            unwind_mismatch, unwinds = 0, []
            if kind == 'bytes':
                for ckind, s in cases:
                    if ckind not in UNWIND_KINDS:
                        continue
                    got = m.run(s, unwind=True)
                    want = reconstructed_unwind(s)
                    unwind_mismatch += got != want
                    unwinds.append((ckind, s, got, want))
                    for pc in set(m.trace):
                        executed[pc] = executed.get(pc, 0) + 1
                for ckind, s, got, want in unwinds:
                    unwind_rows.append(f'{label}\t{ckind}\t{s.hex()}\t{len(s)}\t{fmt(want)}\t{"=" if got == want else fmt(got)}')
                for c in sites:
                    site_rows.append(f'{label}\t{c[0]:#x}\t{c[1]:#x}\t{c[2]:#x}\t{c[3]}\t'
                                     + ','.join(f'{i.va:#x}' for i in insns if i.op in ('call', 'callr') and c[0] <= i.va < c[1]))
            results[kind] = got_all
            stores[kind] = {pos: va for va, positions in fstores.items() for pos in positions}
            # every name reaches exactly one store whose immediate is (variant << 8) | 9, and
            # the store sites together cover every variant index (an alias may get its own site)
            store_ok = all(cache[va].b[1] == (vtable[pos][1] << 8) | OK_TAG for va, ps in fstores.items() for pos in ps)
            store_variants = sorted({vtable[ps[0]][1] for ps in fstores.values()})
            one_to_one = store_ok and len(stores[kind]) == count and store_variants == list(range(variant_count))
            tables = jump_tables(img, insns)
            for lea_va, table, n, targets in tables:
                for e, t in enumerate(targets):
                    if t not in cache:
                        raise Fault(f'jump table {table:#x} entry {e} is not an instruction start')
                    role = 'ok_store' if t in fstores else ('compare' if cache[t].op != 'push' else 'unknown_variant_tail')
                    table_rows.append(f'{label}\t{kind}\t{lea_va:#x}\t{table:#x}\t{e}\t{t:#x}\t{role}')
            unexecuted = [f'{i.va:#x}' for i in insns if i.va not in executed and i.op != 'int3']
            for ins in insns:
                insn_rows.append(f'{label}\t{kind}\t{ins.va:#x}\t{ins.raw.hex()}\t{ins.op}\t{executed.get(ins.va, 0)}')
            n_cases = sum(1 for g in got_all if g is not None)
            fn = {'enum': label, 'kind': kind, 'start': f'{start:#x}', 'fde_end': f'{end:#x}', 'bytes': end - start,
                  'instructions': len(insns), 'int3_padding': sum(1 for i in insns if i.op == 'int3'),
                  'instructions_executed': len(insns) - len(unexecuted) - sum(1 for i in insns if i.op == 'int3'),
                  'unexecuted_non_padding': unexecuted, 'lsda': f'{lsda:#x}' if lsda is not None else None,
                  'lsda_call_sites': len(sites), 'jump_tables': [{'lea': f'{a:#x}', 'table': f'{t:#x}', 'entries': n}
                                                                 for a, t, n, _ in tables],
                  'success_stores': len(fstores), 'success_stores_one_to_one': one_to_one,
                  'cases': n_cases, 'mismatches': mismatch,
                  'unwind_cases': len(unwinds), 'unwind_mismatches': unwind_mismatch,
                  'outcomes': {'ok': sum(1 for r in got_all if r and r[0] == 'ok'),
                               'unknown_borrowed': sum(1 for r in got_all if r and r[0] == 'unknown' and r[2] == 0),
                               'unknown_owned_freed': sum(1 for r in got_all if r and r[0] == 'unknown' and r[2] == 1)}}
            summary['functions'].append(fn)
            fn_rows.append(f'{label}\t{kind}\t{start:#x}\t{end:#x}\t{end - start}\t{len(insns)}\t{fn["int3_padding"]}\t'
                           f'{fn["instructions_executed"]}\t{fn["lsda"] or "-"}\t{len(sites)}\t{len(tables)}\t{len(fstores)}\t'
                           f'{n_cases}\t{mismatch}\t{len(unwinds)}\t{unwind_mismatch}')
            if mismatch or unwind_mismatch or unexecuted or not one_to_one:
                all_bad.append(f'{label}/{kind}')
        for i, (n, v) in enumerate(vtable):
            name_rows.append(f'{label}\t{i}\t{v}\t{n.decode()}\t{len(n)}\t{stores["bytes"][i]:#x}\t{stores["str"][i]:#x}\t{(v << 8) | OK_TAG:#06x}')
        for i, (ckind, s) in enumerate(cases):
            want = reconstructed_match(s, vtable)
            cols = [('=' if results[k][i] == want else fmt(results[k][i])) if results[k][i] is not None else 'not_str'
                    for k in ('bytes', 'str')]
            case_rows.append(f'{label}\t{ckind}\t{s.hex()}\t{len(s)}\t{fmt(want)}\t{cols[0]}\t{cols[1]}')
        mutants = dict(MUTANTS, **(ALIAS_MUTANTS if ALIAS_POSITIONS[label] else {}))
        for mname in sorted(mutants):
            fnm = mutants[mname]
            for kind in ('bytes', 'str'):
                if kind == 'str' and mname in BYTES_ONLY_MUTANTS:
                    continue
                bad = [(k, s) for (k, s), got in zip(cases, results[kind]) if got is not None and fnm(s, vtable) != got]
                model_total += 1
                model_killed += bool(bad)
                first = f'{bad[0][0]}:{bad[0][1].hex()}' if bad else '-'
                mutant_rows.append(f'{label}\t{mname}\t{kind}\t{first}\t{len(bad)}\t{"yes" if bad else "no"}')
        agree = sum(1 for a, b in zip(results['bytes'], results['str']) if b is not None and a == b)
        comparable = sum(1 for b in results['str'] if b is not None)
        summary['enums'].append({'label': label, 'decoder': f'{decoder:#x}', 'visit_bytes': f'{fbytes:#x}',
                                 'visit_str': f'{fstr:#x}', 'variants_slice': f'{variants_va:#x}', 'variants_len': count,
                                 'variant_count': variant_count,
                                 'alias_positions': sorted(ALIAS_POSITIONS[label]),
                                 'names': [n.decode() for n in names], 'cases': len(cases),
                                 'str_bytes_agree_on_utf8_cases': agree, 'utf8_cases': comparable,
                                 'name_length_histogram': {str(k): sum(1 for n in names if len(n) == k)
                                                           for k in sorted({len(n) for n in names})}})
        rs += ['', f'// {label}: decoder {decoder:#x}, visit_bytes {fbytes:#x}, visit_str {fstr:#x}, VARIANTS {variants_va:#x}',
               f'const {label}_VARIANTS: [&str; {count}] = [' + ', '.join(f'"{n.decode()}"' for n in names) + '];',
               f'fn {label.lower()}_variant(value: &[u8]) -> Result<u8, Error> {{', '    match value {']
        rs += [f'        b"{n.decode()}" => Ok({v}),' + (' // alias' if i in ALIAS_POSITIONS[label] else '')
               for i, (n, v) in enumerate(vtable)]
        rs += ['        _ => {',
               '            let value = String::from_utf8_lossy(value); // Borrowed for valid UTF-8, Owned otherwise',
               f'            Err(Error::unknown_variant(&value, &{label}_VARIANTS)) // Owned is dropped here',
               '        }', '    }', '}']
    summary['mutants'] = {'total': model_total, 'killed': model_killed}
    summary['image_mutants'] = image_mutants(data, img, fdes)
    summary['failed_functions'] = all_bad
    files = {
        'summary.json': json.dumps(summary, indent=2, sort_keys=True) + '\n',
        'decoder-bindings.tsv': '\n'.join(bind_rows) + '\n',
        'functions.tsv': '\n'.join(fn_rows) + '\n',
        'names.tsv': '\n'.join(name_rows) + '\n',
        'jump-tables.tsv': '\n'.join(table_rows) + '\n',
        'cases.tsv': '\n'.join(case_rows) + '\n',
        'unwind-cases.tsv': '\n'.join(unwind_rows) + '\n',
        'lsda-call-sites.tsv': '\n'.join(site_rows) + '\n',
        'insns.tsv': '\n'.join(insn_rows) + '\n',
        'mutants.tsv': '\n'.join(mutant_rows) + '\n',
        'matchers.rs.txt': '\n'.join(rs) + '\n',
    }
    for name, text in files.items():
        (out_dir / name).write_text(text, encoding='utf-8')
    return summary


def image_mutant_sites(insns):
    cmps = [i for i in insns if i.op in ('cmp', 'xor') and i.b and i.b[0] == 'i']
    stores = [i for i in insns if i.op == 'mov' and i.w == 16 and i.a[0] == 'm']
    return cmps[::max(1, len(cmps) // 6)][:6] + stores[::max(1, len(stores) // 3)][:3]


def immediate_length(ins):
    """Length of the trailing immediate: the longest tail that encodes the decoded value."""
    for n in (4, 2, 1):
        if n < ins.size and sx(int.from_bytes(ins.raw[-n:], 'little'), n * 8) & ((1 << ins.w) - 1) == ins.b[1]:
            return n
    raise Fault(f'no immediate tail at {ins.va:#x}')


def image_mutants(data, base, fdes):
    """Flip the low bit of the last byte of sampled compare/store sites in a private copy; require divergence."""
    rows, killed = [], 0
    for label, _, fbytes, fstr, variants_va, count in ENUMS:
        names = base.variants(variants_va, count)
        vtable = variant_table(names, ALIAS_POSITIONS[label])
        probes = names + [bytes([c]) for c in range(0x20, 0x7f)] + [b'a' * k for k in range(25)]
        for kind, start in (('bytes', fbytes), ('str', fstr)):
            rec = fde_record(fdes, start)
            insns = coverage_sweep(base, start, rec['end'])
            sites = base.call_sites(rec['lsda'], start) if rec['lsda'] is not None else []
            for ins in image_mutant_sites(insns):
                buf = bytearray(data)
                site = ins.va + ins.size - 1
                if ins.op in ('cmp', 'xor'):
                    # flip the immediate's low byte: a high byte can be dead when only the
                    # low 16 bits of the result are read (xor eax,imm32 then or ax,cx)
                    site = ins.va + ins.size - immediate_length(ins)
                buf[base.off(site)] ^= 0x01
                m = Machine(mutated_image(base, bytes(buf)), kind, start, rec['end'], (variants_va, count), {}, sites)
                diverged = False
                for n in probes:
                    try:
                        if m.run(n) != reconstructed_match(n, vtable):
                            diverged = True
                            break
                    except Fault:
                        diverged = True
                        break
                killed += diverged
                rows.append({'enum': label, 'kind': kind, 'va': f'{ins.va:#x}', 'flipped_byte': f'{site:#x}', 'killed': diverged})
    return {'total': len(rows), 'killed': killed, 'sites': rows}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    s = generate(args.out)
    for f in s['functions']:
        print(f"{f['enum']} {f['kind']} {f['start']}: {f['cases']} cases, {f['mismatches']} mismatches, "
              f"{f['instructions_executed']}/{f['instructions'] - f['int3_padding']} instructions executed, "
              f"unwind {f['unwind_cases']}/{f['unwind_mismatches']}")
    print(f"mutants {s['mutants']['killed']}/{s['mutants']['total']}, image mutants "
          f"{s['image_mutants']['killed']}/{s['image_mutants']['total']}")
    bad = bool(s['failed_functions']) or s['mutants']['killed'] != s['mutants']['total'] \
        or s['image_mutants']['killed'] != s['image_mutants']['total']
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
