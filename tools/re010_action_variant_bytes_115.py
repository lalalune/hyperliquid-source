#!/usr/bin/env python3
"""Reconstruct the node #115 `Action` variant visit_bytes matchers and prove them against the bytes.

serde's derived variant identifier visitor has a `visit_bytes` method next to
`visit_str`. In node #115 it is compiled into five 15.5 KB copies that compare
the input one byte at a time. Each copy turns a byte string into the variant
index (0..91) or, for an unknown name, converts the bytes with
`String::from_utf8_lossy`, calls serde's unknown_variant with the 92-entry
VARIANTS slice and frees the converted string when it was owned.
This tool:

1. checks the input digest, finds every copy's FDE extent and reads the
   VARIANTS slices (`&[&str]`, 16-byte pointer/length pairs filled by
   R_X86_64_RELATIVE relocations);
2. interprets the original bytes of all five copies with a fixed-pattern x86-64
   subset interpreter (no external programs, the binary is never run);
3. compares every interpreted outcome with a pure reconstruction
   (`reconstructed_visit_bytes`) over thousands of byte strings built from the
   bytes, including invalid UTF-8 inputs that take the owned-string branch;
4. proves full instruction coverage, a one-to-one name -> success-store map, the
   free-iff-owned rule and that wrong reconstructions and corrupted images are
   rejected.
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
VARIANT_COUNT = 92

# (label, function start, form, VARIANTS slice, unknown_variant callee)
# Form A returns a 16-byte Result (tag byte 0 = Ok, 1 = Err + boxed error at +8).
# Form B returns a 32-byte Result (tag byte 9 = Ok, otherwise the 32-byte error).
COPIES = (
    ('A1', 0x2b99100, 'A', 0x644cc40, 0x2cf1360),
    ('A2', 0x3659d20, 'A', 0x6467f98, 0x45a8fe0),
    ('B1', 0x2b9cdb0, 'B', 0x644cc40, 0x17fbba0),
    ('B2', 0x365d9d0, 'B', 0x6467f98, 0x2f7fef0),
    ('B3', 0x4d63870, 'B', 0x649bac8, 0x47d2d80),
)
# GOT slots the copies call through (R_X86_64_RELATIVE targets are checked).
LOSSY_SLOT, LOSSY_TARGET = 0x64df640, 0x141ca00
FREE_SLOT, FREE_TARGET = 0x64df4a0, 0x635de30
# Sibling visit_str matchers already reconstructed (not decoded here).
VISIT_STR_SIBLINGS = ('0x2ba1af0', '0x3662730')

IN_BASE, OUT_BASE, STACK_TOP, HEAP_BASE = 0x7000_0000_0000, 0x7100_0000_0000, 0x7200_0000_0000, 0x7300_0000_0000
ERR_MARK = bytes(range(0xe0, 0x100))  # 32 bytes the stubbed form-B error writer stores
ERR_BOX = 0x7400_0000_0040            # pointer the stubbed form-A error constructor returns
EXC_PTR = 0x7500_0000_0080            # in-flight exception object handed to the landing pad
UNWIND_RESUME = 0x63f0a50             # PLT stub; its JUMP_SLOT symbol is checked
BORROWED = 1 << 63                    # Cow<str>::Borrowed niche in the capacity word
MASK64 = (1 << 64) - 1
STEP_LIMIT = 400


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

    def variants(self, va):
        names = []
        for i in range(VARIANT_COUNT):
            slot = va + 16 * i
            if slot not in self.relative:
                raise ValueError(f'VARIANTS slot {slot:#x} has no RELATIVE relocation')
            length = struct.unpack_from('<Q', self.read(slot + 8, 8))[0]
            names.append(self.read(self.relative[slot], length))
        return names


def mutated_image(base, data):
    img = Image.__new__(Image)
    img.data, img.secs, img.by_name, img.relative = data, base.secs, base.by_name, base.relative
    return img


def fde_end(data, start):
    _, fdes = eh_frame_records(data)
    ends = [f['end'] for f in fdes if f['start'] == start]
    if len(ends) != 1:
        raise Fault(f'{start:#x} is not the start of exactly one FDE')
    return ends[0]


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class Insn:
    __slots__ = ('va', 'size', 'op', 'a', 'b', 'w', 'raw')


def decode(img, va):
    """Decode one instruction of the fixed subset used by the visit_bytes copies."""
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
    alu = {0x01: 'add', 0x03: 'add', 0x09: 'or', 0x0b: 'or', 0x31: 'xor', 0x33: 'xor',
           0x39: 'cmp', 0x3b: 'cmp', 0x85: 'test', 0x89: 'mov', 0x8b: 'mov'}
    grp = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}
    if op in alu:
        reg, rm = modrm()
        ins.op = alu[op]
        ins.a, ins.b = (rm, ('r', reg)) if op in (0x01, 0x09, 0x31, 0x39, 0x85, 0x89) else (('r', reg), rm)
    elif op in (0x81, 0x83, 0x80):
        reg, rm = modrm()
        if (reg & 7) not in grp:
            raise Fault(f'unsupported group op at {va:#x}')
        ins.op = grp[reg & 7]
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
    elif op == 0xd0:
        reg, rm = modrm()
        if reg & 7 != 1 or rm[0] != 'r':
            raise Fault(f'unsupported shift form at {va:#x}')
        ins.op, ins.a, ins.w = 'ror1', low8(rm), 8
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
        else:
            raise Fault(f'unsupported 0f {op2:02x} at {va:#x}')
    else:
        raise Fault(f'unsupported opcode {op:02x} at {va:#x}')
    ins.size = p
    ins.raw = bytes(b[:p])
    return ins


class Machine:
    def __init__(self, img, copy, end, cache, sites):
        self.img, self.copy, self.end, self.cache, self.sites = img, copy, end, cache, sites

    def run(self, value, unwind=False):
        label, start, form, variants_va, err_callee = self.copy
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
        pc = start
        for _ in range(STEP_LIMIT):
            if not start <= pc < self.end:
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
        form = self.copy[2]
        if self.r[0] != OUT_BASE:
            raise Fault('rax does not return the out pointer')
        ok_tag = 0 if form == 'A' else 9
        if self.out[0] == ok_tag and not any(self.out[2:]) and self.err_text is None:
            return ('ok', self.out[1])
        if self.err_text is not None:
            if form == 'A' and self.out[0] == 1 and not any(self.out[1:8]) \
                    and int.from_bytes(self.out[8:16], 'little') == ERR_BOX and not any(self.out[16:]):
                return ('unknown', self.err_text, len(self.freed))
            if form == 'B' and bytes(self.out) == ERR_MARK:
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
        elif op == 'ror1':
            v = self.get(ins.a, 8, nxt)
            r = (v >> 1 | (v & 1) << 7) & 0xff
            self.flags['c'] = r >> 7 & 1
            self.flags['o'] = (r >> 7 ^ r >> 6) & 1
            self.put(ins.a, 8, r, nxt)
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
        else:
            raise Fault(f'no semantics for {op}')
        return None

    def clobber(self):
        for n in (1, 2, 6, 7, 8, 9, 10, 11):
            self.r[n] = 0xdead_0000 + n  # caller-saved registers are clobbered

    def call(self, ins, nxt):
        label, start, form, variants_va, err_callee = self.copy
        if ins.op == 'callr':
            slot = self.addr(ins.a, nxt)
            target = self.img.relative.get(slot)
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
        if target != err_callee:
            raise Fault(f'unexpected direct call {target:#x}')
        if form == 'A':
            # unknown_variant(value=(rdi, rsi), expected=(rdx, rcx)) -> boxed error in rax
            ptr, n, exp, cnt = self.r[7], self.r[6], self.r[2], self.r[1]
        else:
            # unknown_variant(out=rdi, value=(rsi, rdx), expected=(rcx, r8))
            ptr, n, exp, cnt = self.r[6], self.r[2], self.r[1], self.r[8]
        if (exp, cnt) != (variants_va, VARIANT_COUNT):
            raise Fault('unknown_variant is not given (VARIANTS, 92)')
        text = self.load(ptr, n)
        expect = self.inp.decode('utf-8', 'replace').encode('utf-8')
        if text != expect:
            raise Fault('unknown_variant text is not the lossy input')
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
        if form == 'A':
            self.r[0] = ERR_BOX
        else:
            self.store(out, ERR_MARK)
        return None


# reconstruction --------------------------------------------------------------
def reconstructed_visit_bytes(value, wire_names):
    """Pure reconstruction of `__FieldVisitor::visit_bytes` for `Action`.

    Exact, case-sensitive, whole-slice match against the 92 wire names in
    declaration order; otherwise unknown_variant(from_utf8_lossy(value)), and
    the lossy string is freed exactly when it was owned (invalid UTF-8 input).
    """
    for index, wire in enumerate(wire_names):
        if value == wire:
            return ('ok', index)
    try:
        value.decode('utf-8')
        owned = 0
    except UnicodeDecodeError:
        owned = 1
    return ('unknown', value.decode('utf-8', 'replace').encode('utf-8'), owned)


UNWIND_KINDS = ('truncate', 'invalid_utf8_tail', 'filler', 'filler_ff', 'truncated_utf8_tail')


def reconstructed_unwind(value):
    """If unknown_variant unwinds, the landing pad drops the lossy string (frees it iff owned) and resumes."""
    return ('unwind', reconstructed_visit_bytes(value, [])[2])


def _lossy_err(s):
    return reconstructed_visit_bytes(s, [])


MUTANTS = {
    'case_insensitive': lambda s, w: next((('ok', i) for i, n in enumerate(w) if s.lower() == n.lower()), _lossy_err(s)),
    'prefix_match': lambda s, w: next((('ok', i) for i, n in enumerate(w) if s and n.startswith(s)), _lossy_err(s)),
    'drop_last_variant': lambda s, w: reconstructed_visit_bytes(s, w[:-1]),
    'off_by_one_index': lambda s, w: (lambda r: ('ok', r[1] + 1) if r[0] == 'ok' else r)(reconstructed_visit_bytes(s, w)),
    'swap_order_cancel': lambda s, w: reconstructed_visit_bytes(s, [w[i] for i in (lambda l: l[:3] + [l[4], l[3]] + l[5:])(list(range(len(w))))]),
    'ignore_last_byte': lambda s, w: next((('ok', i) for i, n in enumerate(w) if len(s) == len(n) and s[:-1] == n[:-1]), _lossy_err(s)),
    'accept_trailing_nul': lambda s, w: reconstructed_visit_bytes(s.rstrip(b'\0'), w),
    'strict_utf8_text': lambda s, w: (lambda r: ('unknown', s.decode('utf-8', 'ignore').encode('utf-8'), r[2]) if r[0] == 'unknown' else r)(reconstructed_visit_bytes(s, w)),
    'never_free': lambda s, w: (lambda r: r[:2] + (0,) if r[0] == 'unknown' else r)(reconstructed_visit_bytes(s, w)),
    'always_free': lambda s, w: (lambda r: r[:2] + (1,) if r[0] == 'unknown' else r)(reconstructed_visit_bytes(s, w)),
    'lossy_then_match': lambda s, w: reconstructed_visit_bytes(s.decode('utf-8', 'replace').encode('utf-8'), w),
    'ascii_fold_first_byte': lambda s, w: reconstructed_visit_bytes(s[:1].lower() + s[1:], w),
}


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
        for i in range(0, len(n), 3):
            c = n[i]
            if 0x41 <= c <= 0x5a or 0x61 <= c <= 0x7a:
                add('case_flip', n[:i] + bytes([c ^ 0x20]) + n[i + 1:])
        add('truncate', n[:-1])
        add('extend_s', n + b's')
        add('extend_nul', n + b'\0')
        add('high_last_byte', n[:-1] + bytes([n[-1] | 0x80]))
        add('invalid_utf8_tail', n + b'\xff')
        add('two_byte_utf8_tail', n[:-1] + b'\xc3\xa9')
        add('truncated_utf8_tail', n[:-1] + b'\xe2\x82')
    for length in range(0, 49):
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


def length_switch(img, insns):
    """push; push; sub rsp; mov rax,rdi; lea rcx,[rdx-K]; cmp rcx,N; ja; lea rdi,[rip+T]; movsxd; add; jmp rcx."""
    shape = [i.op for i in insns[:11]]
    if shape != ['push', 'push', 'sub', 'mov', 'lea', 'cmp', 'j', 'lea', 'movsxd', 'add', 'jmpr']:
        raise Fault('length switch prologue shape differs: ' + ','.join(shape))
    i0, i1, i2, i3 = insns[4], insns[5], insns[6], insns[7]
    if i2.a != 7:
        raise Fault('length bound is not an unsigned ja')
    bias = -i0.b[4]
    count = i1.b[1] + 1
    table = i3.va + i3.size + i3.b[4]
    rows = []
    for k in range(count):
        rel = struct.unpack('<i', img.read(table + 4 * k, 4))[0]
        rows.append((bias + k, table + rel))
    return bias, count, table, rows, i2.va + i2.size + i2.b


def shape_key(insns):
    """Instruction bytes with rel32/RIP displacements masked: equal keys = same code modulo placement."""
    h = hashlib.sha256()
    for ins in insns:
        raw = bytearray(ins.raw)
        if ins.op in ('call', 'jmp') and ins.size == 5 or ins.op == 'j' and ins.size == 6:
            raw[-4:] = b'\0\0\0\0'
        elif ins.b and isinstance(ins.b, tuple) and ins.b[0] == 'm' and ins.b[5] or \
                ins.a and isinstance(ins.a, tuple) and ins.a[0] == 'm' and ins.a[5]:
            m = ins.b if isinstance(ins.b, tuple) and ins.b[0] == 'm' else ins.a
            pos = ins.raw.find(struct.pack('<i', m[4]))
            raw[pos:pos + 4] = b'\0\0\0\0'
        h.update(bytes(raw))
    # jump-table offsets are relative to their table, so they are position independent
    return h.hexdigest()


def fmt(r):
    if r[0] == 'ok':
        return f'ok:{r[1]}'
    return f'unknown:{r[1].hex()}:free{r[2]}'


def generate(out_dir):
    data = BINARY.read_bytes()
    img = Image(data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {'binary_sha256': SHA256, 'variant_count': VARIANT_COUNT, 'copies': [],
               'visit_str_siblings_not_decoded': list(VISIT_STR_SIBLINGS),
               'got_calls': {'from_utf8_lossy': {'slot': f'{LOSSY_SLOT:#x}', 'relative_target': f'{img.relative.get(LOSSY_SLOT, 0):#x}'},
                             'free': {'slot': f'{FREE_SLOT:#x}', 'relative_target': f'{img.relative.get(FREE_SLOT, 0):#x}'}}}
    if img.relative.get(LOSSY_SLOT) != LOSSY_TARGET or img.relative.get(FREE_SLOT) != FREE_TARGET:
        raise Fault('GOT slot targets differ')
    names_ref = None
    cases = None
    per_copy, per_copy_unwind = {}, {}
    site_rows = ['copy\tstart\tend\tlanding_pad\taction\tcalls_in_range']
    name_rows = ['copy\tindex\twire_name\tlength\tswitch_arm\tsuccess_store_va\tresult_word\tsteps']
    table_rows = ['copy\tlength\tarm_va\tarm_kind\tnames_of_this_length']
    insn_rows = ['copy\tva\tbytes\top\texecuted_cases']
    copy_rows = ['copy\tstart\tfde_end\tbytes\tform\tinstructions\tshape_sha256\tvariants_slice\tunknown_variant_callee\tlsda']
    _, fdes = eh_frame_records(data)
    fde_by_start = {f['start']: f for f in fdes}
    for copy in COPIES:
        label, start, form, variants_va, err_callee = copy
        end = fde_end(data, start)
        names = img.variants(variants_va)
        if names_ref is None:
            names_ref = names
            cases = build_cases(names)
            unwind_cases = [(k, s) for k, s in cases if k in UNWIND_KINDS]
        elif names != names_ref:
            raise Fault('VARIANTS slices differ between copies')
        if len(set(names)) != VARIANT_COUNT:
            raise Fault('duplicate wire names')
        insns = coverage_sweep(img, start, end)
        bias, count, table, rows, default_target = length_switch(img, insns)
        cache = {i.va: i for i in insns}
        lsda = fde_by_start[start]['lsda']
        sites = img.call_sites(lsda, start)
        m = Machine(img, copy, end, cache, sites)
        executed, stores, results, unwinds = {}, {}, [], []
        mismatch = 0
        for kind, s in cases:
            got = m.run(s)
            want = reconstructed_visit_bytes(s, names)
            mismatch += got != want
            results.append(got)
            for pc in set(m.trace):
                executed[pc] = executed.get(pc, 0) + 1
            if kind == 'exact':
                store = next(pc for pc in reversed(m.trace) if cache[pc].op == 'mov' and cache[pc].a[0] == 'm' and cache[pc].w == 16)
                stores.setdefault(store, []).append(s)
                arm = m.trace[m.trace.index(insns[10].va) + 1]
                word = cache[store].b[1]
                name_rows.append(f'{label}\t{got[1]}\t{s.decode()}\t{len(s)}\t{arm:#x}\t{store:#x}\t{word:#06x}\t{len(m.trace)}')
        unwind_mismatch = 0
        for kind, s in unwind_cases:
            got = m.run(s, unwind=True)
            unwind_mismatch += got != reconstructed_unwind(s)
            unwinds.append(got)
            for pc in set(m.trace):
                executed[pc] = executed.get(pc, 0) + 1
        per_copy[label] = results
        per_copy_unwind[label] = unwinds
        for c in sites:
            site_rows.append(f'{label}\t{c[0]:#x}\t{c[1]:#x}\t{c[2]:#x}\t{c[3]}\t'
                             + ','.join(f'{i.va:#x}' for i in insns if i.op in ('call', 'callr') and c[0] <= i.va < c[1]))
        by_len = {}
        for n in names:
            by_len.setdefault(len(n), []).append(n.decode())
        for length, target in rows:
            kind = 'unknown_variant' if target == default_target else 'compare_arm'
            table_rows.append(f'{label}\t{length}\t{target:#x}\t{kind}\t{",".join(by_len.get(length, [])) or "-"}')
        # one full listing per form is enough: copies of a form share shape_sha256;
        # for form B only the error tail and landing pad (the part that differs) are listed
        if label == 'A1' or label == 'B1':
            for ins in insns:
                if label == 'B1' and ins.va < default_target:
                    continue
                insn_rows.append(f'{label}\t{ins.va:#x}\t{ins.raw.hex()}\t{ins.op}\t{executed.get(ins.va, 0)}')
        unexecuted = [i for i in insns if i.va not in executed]
        unexec_code = [f'{i.va:#x}' for i in unexecuted if i.op != 'int3']
        key = shape_key(insns)
        copy_rows.append(f'{label}\t{start:#x}\t{end:#x}\t{end - start}\t{form}\t{len(insns)}\t{key}\t{variants_va:#x}\t{err_callee:#x}\t{lsda:#x}')
        arm_lengths = sorted(l for l, t in rows if t != default_target)
        ok_tags = sorted({cache[s].b[1] & 0xff for s in stores})
        summary['copies'].append({
            'label': label, 'start': f'{start:#x}', 'fde_end': f'{end:#x}', 'bytes': end - start, 'form': form,
            'variants_slice': f'{variants_va:#x}', 'unknown_variant_callee': f'{err_callee:#x}',
            'instructions': len(insns), 'int3_padding': sum(1 for i in insns if i.op == 'int3'),
            'instructions_executed': len(insns) - len(unexecuted), 'unexecuted_non_padding': unexec_code,
            'length_switch': {'bias': bias, 'entries': count, 'table': f'{table:#x}',
                              'compare_arm_lengths': arm_lengths, 'default_target': f'{default_target:#x}'},
            'cases': len(cases), 'mismatches': mismatch,
            'unwind_cases': len(unwind_cases), 'unwind_mismatches': unwind_mismatch, 'lsda': f'{lsda:#x}',
            'lsda_call_sites': len(sites),
            'success_stores': len(stores), 'ok_tag_bytes': ok_tags,
            'success_stores_one_to_one': all(len(v) == 1 for v in stores.values()) and len(stores) == VARIANT_COUNT,
            'outcomes': {'ok': sum(1 for r in results if r[0] == 'ok'),
                         'unknown_borrowed': sum(1 for r in results if r[0] == 'unknown' and r[2] == 0),
                         'unknown_owned_freed': sum(1 for r in results if r[0] == 'unknown' and r[2] == 1)},
        })
    labels = [c[0] for c in COPIES]
    case_rows = ['kind\tinput_hex\tlength\treconstructed\t' + '\t'.join(labels)]
    for i, (kind, s) in enumerate(cases):
        want = fmt(reconstructed_visit_bytes(s, names_ref))
        cols = ['=' if fmt(per_copy[l][i]) == want else fmt(per_copy[l][i]) for l in labels]
        case_rows.append(f'{kind}\t{s.hex()}\t{len(s)}\t{want}\t' + '\t'.join(cols))
    unwind_rows = ['kind\tinput_hex\tlength\treconstructed\t' + '\t'.join(labels)]
    for i, (kind, s) in enumerate(unwind_cases):
        want = reconstructed_unwind(s)
        cols = ['=' if per_copy_unwind[l][i] == want else f'unwind:free{per_copy_unwind[l][i][1]}' for l in labels]
        unwind_rows.append(f'{kind}\t{s.hex()}\t{len(s)}\tunwind:free{want[1]}\t' + '\t'.join(cols))
    mutant_rows = ['mutant\tfirst_disagreeing_case\tdisagreements\tkilled']
    kill_total = 0
    base = per_copy['A1']
    for mname in sorted(MUTANTS):
        fn = MUTANTS[mname]
        bad = [(k, s) for (k, s), got in zip(cases, base) if fn(s, names_ref) != got]
        killed = bool(bad)
        kill_total += killed
        first = f'{bad[0][0]}:{bad[0][1].hex()}' if bad else '-'
        mutant_rows.append(f'{mname}\t{first}\t{len(bad)}\t{"yes" if killed else "no"}')
    summary['mutants'] = {'total': len(MUTANTS), 'killed': kill_total}
    summary['image_mutants'] = image_mutants(data, img, names_ref)
    shapes = {}
    for c in summary['copies']:
        shapes.setdefault(c['form'], set()).add(next(r.split('\t')[6] for r in copy_rows[1:] if r.startswith(c['label'] + '\t')))
    summary['same_shape_within_form'] = {f: len(v) == 1 for f, v in sorted(shapes.items())}
    rs = ['// Reconstructed from node #115 bytes by tools/re010_action_variant_bytes_115.py.',
          '// serde variant identifier visitor for the internally tagged `Action` enum,',
          '// byte-slice entry point (sibling of visit_str).',
          'fn action_variant_from_bytes(value: &[u8]) -> Result<u8, Error> {',
          '    match value {']
    for i, n in enumerate(names_ref):
        rs.append(f'        b"{n.decode()}" => Ok({i}),')
    rs += ['        _ => {',
           '            let value = String::from_utf8_lossy(value); // Borrowed for valid UTF-8, Owned otherwise',
           '            Err(Error::unknown_variant(&value, VARIANTS)) // VARIANTS.len() == 92; Owned is dropped here',
           '        }',
           '    }', '}']
    files = {
        'summary.json': json.dumps(summary, indent=2, sort_keys=True) + '\n',
        'copies.tsv': '\n'.join(copy_rows) + '\n',
        'names.tsv': '\n'.join(name_rows) + '\n',
        'length-switch.tsv': '\n'.join(table_rows) + '\n',
        'cases.tsv': '\n'.join(case_rows) + '\n',
        'insns.tsv': '\n'.join(insn_rows) + '\n',
        'mutants.tsv': '\n'.join(mutant_rows) + '\n',
        'unwind-cases.tsv': '\n'.join(unwind_rows) + '\n',
        'lsda-call-sites.tsv': '\n'.join(site_rows) + '\n',
        'visit_bytes.rs.txt': '\n'.join(rs) + '\n',
    }
    for name, text in files.items():
        (out_dir / name).write_text(text, encoding='utf-8')
    return summary


def image_mutant_sites(insns):
    sites = [i for i in insns if i.op == 'cmp' and i.b and i.b[0] == 'i']
    stores = [i for i in insns if i.op == 'mov' and i.w == 16 and i.a[0] == 'm']
    return sites[::max(1, len(sites) // 14)][:14] + stores[::23] + [insns[5]]


def image_mutants(data, base, names):
    """Flip the low bit of the last byte of sampled compare/store sites in a private copy; require divergence."""
    rows, killed = [], 0
    probes = names + [b'a' * k for k in range(49)] + [n + b'\xff' for n in names[:8]]
    for copy in (COPIES[0], COPIES[2]):
        label, start = copy[0], copy[1]
        end = fde_end(data, start)
        insns = coverage_sweep(base, start, end)
        _, fdes = eh_frame_records(data)
        sites = base.call_sites(next(f['lsda'] for f in fdes if f['start'] == start), start)
        for ins in image_mutant_sites(insns):
            buf = bytearray(data)
            site = ins.va + ins.size - 1 if ins.op == 'cmp' else ins.va + ins.size - 1
            buf[base.off(site)] ^= 0x01
            m = Machine(mutated_image(base, bytes(buf)), copy, end, {}, sites)
            diverged = False
            for n in probes:
                try:
                    if m.run(n) != reconstructed_visit_bytes(n, names):
                        diverged = True
                        break
                except Fault:
                    diverged = True
                    break
            killed += diverged
            rows.append({'copy': label, 'va': f'{ins.va:#x}', 'flipped_byte': f'{site:#x}', 'killed': diverged})
    return {'total': len(rows), 'killed': killed, 'sites': rows}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    s = generate(args.out)
    for c in s['copies']:
        print(f"copy {c['label']} {c['start']}: {c['cases']} cases, {c['mismatches']} mismatches, "
              f"{c['instructions_executed']}/{c['instructions']} instructions executed")
    print(f"mutants {s['mutants']['killed']}/{s['mutants']['total']}, image mutants "
          f"{s['image_mutants']['killed']}/{s['image_mutants']['total']}")
    bad = any(c['mismatches'] or c['unwind_mismatches'] or c['unexecuted_non_padding'] or not c['success_stores_one_to_one'] for c in s['copies'])
    bad = bad or s['mutants']['killed'] != s['mutants']['total'] or s['image_mutants']['killed'] != s['image_mutants']['total']
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
