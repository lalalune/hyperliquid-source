#!/usr/bin/env python3
"""Reconstruct how node #115 turns a MessagePack document into a serde `Content` tree and releases it again.

The flow starts at the generic value reader (three 2,074-byte copies) and runs, as original bytes, everything it
reaches on the way: the scalar leaf, the visit_map / visit_seq collectors, the ext visitor, the access helpers,
`core::str::from_utf8`, the RawVec grow pair, the depth budget, the cleanup of a failed collection, the
landing pads, and the Content / Result drop glue that frees the finished tree.  Only the allocator wrappers
(alloc, realloc, free), the panic / alloc-error functions and `_Unwind_Resume` are contract stubs.

This tool:
1. checks the input digest, lazily decodes every function it reaches with a fixed-pattern x86-64 subset
   decoder and reads their FDE extents and LSDA call-site tables with the shared `fde_extents` parser;
2. interprets the original bytes across calls (the binary is never run): real call frames, a heap that
   rejects use after free, double free and a free with the wrong size, and an unwinder that restores the
   callee-saved registers from the prologue pushes and runs the LSDA landing pads;
3. compares each run with a pure reconstruction (`Model`): the result tree, the allocator call order,
   the final cursor / depth state, the order in which the drop glue frees a tree, and a no-leak check;
4. proves that wrong reconstructions, corrupted images and out-of-range inputs are rejected.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records, uleb  # noqa: E402,F401

BINARY = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
def pattern(*key, n=32):
    """Deterministic stub bytes: sha256 stream keyed by the case words."""
    h, k = b'', 0
    while len(h) < n:
        h += hashlib.sha256((':'.join(map(str, key)) + f':{k}').encode()).digest()
        k += 1
    return h[:n]


class Fault(Exception):
    pass


class Image:
    def __init__(self, data, check=True):
        if check and hashlib.sha256(data).hexdigest() != SHA256:
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
        """LSDA call-site table rows (start, end, landing pad or 0, action) as VAs."""
        o = self.off(lsda, 4)
        if self.data[o] != 0xff:
            raise Fault('LSDA has a landing-pad base')
        p = o + 2
        if self.data[o + 1] != 0xff:
            _, p = uleb(self.data, p, o + 4096)  # type table offset (catch-all terminate entry)
        if self.data[p] != 0x01:
            raise Fault('LSDA call sites are not uleb128')
        length, p = uleb(self.data, p + 1, o + 4096)
        rows, stop = [], p + length
        while p < stop:
            start, p = uleb(self.data, p, stop)
            size, p = uleb(self.data, p, stop)
            lp, p = uleb(self.data, p, stop)
            action, p = uleb(self.data, p, stop)
            rows.append((func_start + start, func_start + start + size, func_start + lp if lp else 0, action))
        return rows

    def table(self, va, n):
        return [va + struct.unpack('<i', self.read(va + 4 * i, 4))[0] for i in range(n)]


def fde_of(data, start):
    _, fdes = eh_frame_records(data)
    rows = [f for f in fdes if f['start'] == start]
    if len(rows) != 1:
        raise Fault(f'{start:#x} is not the start of exactly one FDE')
    return rows[0]


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class Insn:
    __slots__ = ('va', 'size', 'op', 'a', 'b', 'w', 'raw', 'rel', 'immlen', 'cc')


ALU_NAMES = ('add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp')


def decode(img, va):
    """Decode one instruction of the fixed subset used by the visitor copies."""
    b = img.read(va, 16)
    p, opsz, rep, rex = 0, None, False, 0
    while b[p] in (0x66, 0xf3, 0x2e):  # 0x2e only pads multi-byte nops
        opsz = 16 if b[p] == 0x66 else opsz
        rep = rep or b[p] == 0xf3
        p += 1
    if 0x40 <= b[p] <= 0x4f:
        rex = b[p]
        p += 1
    W, R, X, B = rex >> 3 & 1, rex >> 2 & 1, rex >> 1 & 1, rex & 1
    width = 64 if W else (opsz or 32)
    ins = Insn()
    ins.va, ins.w, ins.a, ins.b, ins.rel, ins.immlen = va, width, None, None, None, 0

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
            ins.rel = p
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

    def reg8(n):
        # Without REX, byte registers 4..7 are ah/ch/dh/bh; the subset rejects them.
        if not rex and 4 <= n <= 7:
            raise Fault(f'high byte register at {va:#x}')
        return ('r', n)

    def low8(opnd):
        if opnd[0] == 'r':
            reg8(opnd[1])
        return opnd

    def imm(n):
        nonlocal p
        v = int.from_bytes(b[p:p + n], 'little')
        p += n
        ins.immlen = n
        return v

    op = b[p]
    p += 1
    if op < 0x40 and op & 7 < 4:
        reg, rm = modrm()
        ins.op = ALU_NAMES[op >> 3]
        if ins.op in ('adc', 'sbb'):
            raise Fault(f'carry ALU at {va:#x}')
        if not op & 1:
            ins.w = 8
            rm, reg_o = low8(rm), reg8(reg)
        else:
            reg_o = ('r', reg)
        ins.a, ins.b = (rm, reg_o) if not op & 2 else (reg_o, rm)
    elif op < 0x40 and op & 7 in (4, 5):
        ins.op = ALU_NAMES[op >> 3]
        if op & 7 == 4:
            ins.w, ins.a, ins.b = 8, ('r', 0), ('i', imm(1))
        else:
            n = 2 if width == 16 else 4
            ins.a, ins.b = ('r', 0), ('i', sx(imm(n), n * 8) & ((1 << width) - 1))
    elif op in (0x84, 0x85, 0x88, 0x89, 0x8a, 0x8b):
        reg, rm = modrm()
        ins.op = 'test' if op < 0x88 else 'mov'
        if not op & 1:
            ins.w = 8
            rm, reg_o = low8(rm), reg8(reg)
        else:
            reg_o = ('r', reg)
        ins.a, ins.b = (reg_o, rm) if op == 0x8a or op == 0x8b else (rm, reg_o)
    elif op in (0x81, 0x83, 0x80):
        reg, rm = modrm()
        ins.op = ALU_NAMES[reg & 7]
        if ins.op in ('adc', 'sbb'):
            raise Fault(f'carry ALU at {va:#x}')
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
    elif op == 0xc1:
        reg, rm = modrm()
        if reg & 7 not in (0, 4) or rm[0] != 'r':
            raise Fault(f'unsupported shift form at {va:#x}')
        ins.op, ins.a, ins.b = ('rol' if reg & 7 == 0 else 'shl'), rm, imm(1)
    elif op in (0xfe, 0xff):
        reg, rm = modrm()
        k = reg & 7
        if op == 0xfe:
            if k > 1:
                raise Fault(f'unsupported fe form at {va:#x}')
            ins.op, ins.a, ins.w = ('inc', 'dec')[k], low8(rm), 8
        elif k in (0, 1):
            ins.op, ins.a = ('inc', 'dec')[k], rm
        elif k in (2, 4):
            ins.op, ins.a, ins.w = ('callr' if k == 2 else 'jmpr'), rm, 64
        else:
            raise Fault(f'unsupported ff form at {va:#x}')
    elif op == 0x8d:
        reg, rm = modrm()
        ins.op, ins.a, ins.b = 'lea', ('r', reg), rm
    elif op == 0x63:
        reg, rm = modrm()
        ins.op, ins.a, ins.b = 'movsxd', ('r', reg), rm
    elif op == 0xf7:
        reg, rm = modrm()
        if reg & 7 == 4:
            ins.op, ins.a = 'mul', rm
        elif reg & 7 == 2 and rm[0] == 'r':
            ins.op, ins.a = 'not', rm
        else:
            raise Fault(f'unsupported f7 form at {va:#x}')
    elif op == 0xf6:
        reg, rm = modrm()
        if reg & 7 != 0:
            raise Fault(f'unsupported f6 form at {va:#x}')
        ins.op, ins.a, ins.w = 'test', low8(rm), 8
        ins.b = ('i', imm(1))
    elif op == 0xcc:
        ins.op = 'int3'
    elif op == 0xc7:
        reg, rm = modrm()
        n = 2 if width == 16 else 4
        ins.op, ins.a, ins.b = 'mov', rm, ('i', sx(imm(n), n * 8) & ((1 << width) - 1))
    elif op == 0xc6:
        reg, rm = modrm()
        ins.op, ins.a, ins.b, ins.w = 'mov', low8(rm), ('i', imm(1)), 8
    elif 0xb0 <= op <= 0xb7:
        ins.op, ins.a, ins.w = 'mov', reg8((op - 0xb0) | B << 3), 8
        ins.b = ('i', imm(1))
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
    elif op in (0xe8, 0xe9):
        ins.rel = p
        ins.op, ins.b = ('call' if op == 0xe8 else 'jmp'), sx(imm(4), 32)
    elif op == 0xc3:
        ins.op = 'ret'
    elif op == 0x90:
        ins.op = 'nop'
    elif op == 0x0f:
        op2 = b[p]
        p += 1
        if 0x80 <= op2 <= 0x8f:
            ins.rel = p
            ins.op, ins.a, ins.b = 'j', op2 & 15, sx(imm(4), 32)
        elif op2 in (0xb6, 0xb7):
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'movzx', ('r', reg), rm
            ins.w = 8 if op2 == 0xb6 else 16
            if op2 == 0xb6:
                low8(rm)
        elif op2 in (0x10, 0x28) and not rep and opsz is None:
            reg, rm = modrm()  # movups / movaps load (alignment is not modelled)
            ins.op, ins.a, ins.b = 'xload', reg, rm
        elif op2 in (0x11, 0x29) and not rep and opsz is None:
            reg, rm = modrm()  # movups / movaps store
            ins.op, ins.a, ins.b = 'xstore', rm, reg
        elif 0xc8 <= op2 <= 0xcf:
            ins.op, ins.a = 'bswap', ('r', (op2 - 0xc8) | B << 3)
        elif op2 == 0x0b:
            ins.op = 'ud2'
        elif 0x90 <= op2 <= 0x9f:
            reg, rm = modrm()
            ins.op, ins.a, ins.cc, ins.w = 'setcc', low8(rm), op2 & 15, 8
        elif op2 == 0xbc and rep:
            reg, rm = modrm()
            ins.op, ins.a, ins.b = 'tzcnt', ('r', reg), rm
        elif op2 == 0x1f:
            modrm()  # multi-byte nop
            ins.op = 'nop'
        elif 0x40 <= op2 <= 0x4f:
            reg, rm = modrm()
            ins.op, ins.a, ins.b, ins.cc = 'cmov', ('r', reg), rm, op2 & 15
        else:
            raise Fault(f'unsupported 0f {op2:02x} at {va:#x}')
    else:
        raise Fault(f'unsupported opcode {op:02x} at {va:#x}')
    ins.size = p
    ins.raw = bytes(b[:p])
    return ins


def sweep(img, start, end):
    """Linear decode of [start, end); every byte must belong to a decoded instruction."""
    out, va = [], start
    while va < end:
        ins = decode(img, va)
        out.append(ins)
        va += ins.size
    if va != end:
        raise Fault('instruction sweep overruns the FDE end')
    return out



def reloc_name(img, slot):
    """('glob_dat', symbol) or ('relative', target) for a GOT slot, from .rela.dyn bytes."""
    rd = img.by_name['.rela.dyn']
    for i in range(rd['size'] // 24):
        off, info, add = struct.unpack_from('<QQq', img.data, rd['offset'] + i * 24)
        if off != slot:
            continue
        if info & 0xffffffff == 8:
            return ('relative', add)
        if info & 0xffffffff == 6:
            dynsym, dynstr = img.by_name['.dynsym'], img.by_name['.dynstr']
            name = struct.unpack_from('<I', img.data, dynsym['offset'] + 24 * (info >> 32))[0]
            start = dynstr['offset'] + name
            return ('glob_dat', img.data[start:img.data.index(b'\0', start)].decode())
    return None



def h16(b):
    return hashlib.sha256(bytes(b)).hexdigest()[:16]




# ---------------------------------------------------------------------------------------------
# constants read from the bytes of the three deserializer copies
COPIES = (  # value reader, its eof constant, and the map / seq / ext collectors it calls
    {'vr': 0x17fb290, 'map': 0x21e0380, 'seq': 0x21e1c10, 'ext': 0x21e1930, 'eof': 0x641ccb0, 'drop': 0x18a33d0,
     'drop_result': 0x187d4e0},
    {'vr': 0x2f7f5e0, 'map': 0x3b68660, 'seq': 0x3b69610, 'ext': 0x3b69ad0, 'eof': 0x64622f0, 'drop': 0x302b780,
     'drop_result': 0x3004ed0},
    {'vr': 0x47d2470, 'map': 0x57af090, 'seq': 0x57af540, 'ext': 0x57afa00, 'eof': 0x6497718, 'drop': 0x4877880,
     'drop_result': 0x4852230},
)
UTF8 = 0x16815e0
GROW = (0x16a0730, 0x16a06c0)
FINISH_GROW = 0x16a0810
PRIM = 0x14b9940
# GOT slots (RELATIVE relocations) and the role of the target they hold
SLOT_ROLES = {0x64df480: 'alloc', 0x64df590: 'alloc', 0x64df580: 'realloc', 0x64df588: 'realloc', 0x64df4a0: 'free',
              0x64df490: 'alloc_error', 0x64df498: 'alloc_error', 0x64df520: 'panic_add', 0x64df848: 'panic_sub',
              0x64df4c0: 'terminate'}
REAL_SLOTS = {0x64dffb0: PRIM, 0x64dfca8: UTF8, 0x64e13c0: GROW[0], 0x64e13b8: GROW[1]}
RESUME_SYMBOL = '_Unwind_Resume'
CALLEE_SAVED = (3, 5, 12, 13, 14, 15)
EOF_PRIM, EOF_SHORT = 0x63f8470, 0x2500000003
NO_PEEK, DANGLING = 1, 8
CLAMP = {'map': 0x4000, 'seq': 0x8000}
ELEM = {'map': 64, 'seq': 32}
OUT_BASE, DES_BASE, IN_BASE = 0x7100_0000_0000, 0x7190_0000_0000, 0x7500_0000_0000
HEAP_BASE, STACK_TOP, SCRATCH_BASE = 0x7400_0000_0000, 0x7200_0000_0000, 0x7600_0000_0000
HEAP_STRIDE = 0x1000_0000
MASK64 = (1 << 64) - 1
OUT_FILL, STACK_FILL, DES_FILL, HEAP_FILL = 0xaa, 0x5c, 0x3d, 0xee
OUT_SIZE, DES_SIZE, STACK_SIZE = 0x30, 0x28, 0x100000
EXC = 0xe0c0_0000_0001
STEP_LIMIT = 40_000_000


class Stop(Exception):
    pass


class Prog:
    """Lazy per-function decode of the image: instruction cache, LSDA rows, prologue pushes."""

    def __init__(self, img):
        self.img = img
        _, fdes = eh_frame_records(img.data)
        self.fdes = sorted((f['start'], f['end'], f.get('lsda') or 0) for f in fdes)
        self.starts = [f[0] for f in self.fdes]
        self.cache, self.fns = {}, {}

    def fn_containing(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0 or not self.fdes[i][0] <= va < self.fdes[i][1]:
            raise Fault(f'{va:#x} is not inside any FDE')
        return self.fn(self.fdes[i][0])

    def fn(self, start):
        f = self.fns.get(start)
        if f is None:
            i = bisect.bisect_left(self.starts, start)
            if i >= len(self.starts) or self.starts[i] != start:
                raise Fault(f'{start:#x} is not the start of an FDE')
            _, end, lsda = self.fdes[i]
            insns = sweep(self.img, start, end)
            pushes = []
            for ins in insns:
                if ins.op != 'push':
                    break
                pushes.append(ins.a[1])
            f = Func(start, end, lsda, self.img.call_sites(lsda, start) if lsda else [], insns, pushes)
            self.fns[start] = f
            self.cache.update({x.va: x for x in insns})
        return f

    def at(self, pc):
        ins = self.cache.get(pc)
        if ins is None:
            f = self.fn_containing(pc)
            ins = self.cache.get(pc)
            if ins is None:
                raise Fault(f'jump into the middle of an instruction at {pc:#x}')
        return ins


class Func:
    def __init__(self, start, end, lsda, sites, insns, pushes):
        self.start, self.end, self.lsda, self.sites, self.insns, self.pushes = start, end, lsda, sites, insns, pushes

    def site_of(self, call_va):
        for s, e, lp, a in self.sites:
            if s <= call_va < e:
                return lp, a
        return None


class Frame:
    __slots__ = ('rsp', 'site')

    def __init__(self, rsp, site):
        self.rsp, self.site = rsp, site


class World:
    """x86-64 subset interpreter running real code across calls; only libc-like leaves are stubs."""

    def __init__(self, prog):
        self.prog, self.img = prog, prog.img
        self.cov, self.edges = None, None
        self.stub_target = {}
        for slot, role in SLOT_ROLES.items():
            self.stub_target.setdefault(self.img.relative[slot], role)

    # state ------------------------------------------------------------------------------------
    def setup(self, c):
        self.case = c
        buf = c['buf']
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.des = bytearray([DES_FILL]) * DES_SIZE
        self.inp = bytearray(buf)
        self.stack = bytearray([STACK_FILL]) * STACK_SIZE
        self.blocks = []              # [base, bytearray, size, live]
        self.events, self.allocs, self.frames = [], 0, []
        self.r = [0xdead_0000 + n for n in range(16)]
        self.x = [bytes(16)] * 16
        self.flags = dict(z=0, c=0, s=0, o=0)
        self.r[4] = STACK_TOP - 8
        peek = c.get('peek')
        struct.pack_into('<QQBBH', self.des, 0x10, IN_BASE, len(buf), NO_PEEK if peek is None else peek[0],
                         0x77 if peek is None else peek[1], c['depth'])

    def call_top(self, start, rdi, rsi):
        self.r[7], self.r[6] = rdi, rsi
        self.r[4] = STACK_TOP - 8
        self.frames = []
        return self.run_from(start)

    def run_from(self, pc):
        steps = 0
        cov, edges = self.cov, self.edges
        try:
            while True:
                ins = self.prog.at(pc)
                nxt = pc + ins.size
                res = self.step(ins, nxt)
                if cov is not None:
                    cov.add(pc)
                    if ins.op == 'j':
                        edges.add((pc, res is not None))
                steps += 1
                if steps > STEP_LIMIT:
                    raise Fault('step limit')
                if res == 'ret':
                    return 'ret'
                pc = nxt if res is None else res
        except Stop as s:
            return s.args[0]

    # memory ------------------------------------------------------------------------------------
    def addr(self, m, nxt):
        _, base, index, scale, disp, rip = m
        a = nxt + disp if rip else disp
        if base is not None:
            a += self.r[base]
        if index is not None:
            a += self.r[index] * scale
        return a & MASK64

    def block_at(self, a):
        k = (a - HEAP_BASE) // HEAP_STRIDE
        if 0 <= k < len(self.blocks):
            b = self.blocks[k]
            if b[0] <= a <= b[0] + len(b[1]):
                return b
        return None

    def region(self, a, n):
        for base, buf in ((STACK_TOP - STACK_SIZE, self.stack), (OUT_BASE, self.out), (DES_BASE, self.des),
                          (IN_BASE, self.inp)):
            if base <= a <= base + len(buf):
                if a + n > base + len(buf):
                    raise Fault(f'access past buffer {a:#x}+{n}')
                return buf, a - base
        b = self.block_at(a)
        if b is not None:
            if not b[3]:
                raise Fault(f'use after free {a:#x}')
            if a + n > b[0] + len(b[1]):
                raise Fault(f'heap overrun {a:#x}+{n}')
            return b[1], a - b[0]
        return None, None

    def load(self, a, n):
        buf, o = self.region(a, n)
        if buf is None:
            return self.img.read(a, n)
        return bytes(buf[o:o + n])

    def store(self, a, data):
        buf, o = self.region(a, len(data))
        if buf is None or buf is self.inp:
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
            if w in (64, 32):
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
        elif kind == 'add':
            self.flags['c'] = int(a + b > m)
            self.flags['o'] = int(sx(a, w) + sx(b, w) != sx(r, w))
        return r

    def cond(self, cc):
        f = self.flags
        v = [f['o'], f['c'], f['z'], f['c'] | f['z'], f['s'], None,
             int(f['s'] != f['o']), int(f['z'] or f['s'] != f['o'])][cc >> 1]
        if v is None:
            raise Fault('parity flag not modelled')
        return bool(v) ^ bool(cc & 1)

    # one instruction ----------------------------------------------------------------------------
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
        elif op in ('inc', 'dec'):
            a, c = self.get(ins.a, w, nxt), self.flags['c']
            r = self.setf(w, a + 1, a, 1, 'add') if op == 'inc' else self.setf(w, a - 1, a, 1, 'sub')
            self.flags['c'] = c
            self.put(ins.a, w, r, nxt)
        elif op == 'rol':
            v, n = self.get(ins.a, w, nxt), ins.b % w
            self.put(ins.a, w, (v << n | v >> (w - n)) if n else v, nxt)
            self.flags['c'] = self.flags['o'] = None
        elif op == 'shl':
            v = self.get(ins.a, w, nxt)
            r = self.setf(w, v << ins.b)
            self.put(ins.a, w, r, nxt)
            self.flags['c'] = self.flags['o'] = None
        elif op == 'not':
            self.put(ins.a, w, ~self.get(ins.a, w, nxt), nxt)
        elif op == 'bswap':
            v = self.get(ins.a, w, nxt)
            self.put(ins.a, w, int.from_bytes(v.to_bytes(w // 8, 'little'), 'big'), nxt)
        elif op == 'mul':
            p = self.r[0] * self.get(ins.a, 64, nxt)
            self.r[0], self.r[2] = p & MASK64, p >> 64
            self.flags['c'] = self.flags['o'] = int(self.r[2] != 0)
            self.flags['z'] = self.flags['s'] = 0
        elif op == 'setcc':
            self.put(ins.a, 8, int(self.cond(ins.cc)), nxt)
        elif op == 'tzcnt':
            v = self.get(ins.b, w, nxt)
            res = w if v == 0 else (v & -v).bit_length() - 1
            self.flags['c'], self.flags['z'] = int(v == 0), int(res == 0)
            self.put(ins.a, w, res, nxt)
        elif op == 'mov':
            self.put(ins.a, w, self.get(ins.b, w, nxt), nxt)
        elif op == 'lea':
            self.put(ins.a, w, self.addr(ins.b, nxt), nxt)
        elif op == 'movsxd':
            self.put(ins.a, 64, sx(self.get(ins.b, 32, nxt), 32), nxt)
        elif op == 'cmov':
            v = self.get(ins.b, w, nxt)
            self.put(ins.a, w, v if self.cond(ins.cc) else self.get(ins.a, w, nxt), nxt)
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
            if ins.a[0] == 'm' and ins.a[5]:
                return self.tail_got(ins, nxt)
            return self.get(ins.a, 64, nxt)
        elif op == 'ret':
            if self.r[4] == STACK_TOP - 8:
                return 'ret'
            ret = int.from_bytes(self.load(self.r[4], 8), 'little')
            self.r[4] += 8
            self.frames.pop()
            return ret
        elif op in ('call', 'callr'):
            return self.call(ins, nxt)
        elif op == 'xload':
            self.x[ins.a] = self.load(self.addr(ins.b, nxt), 16) if ins.b[0] == 'm' else self.x[ins.b[1]]
        elif op == 'xstore':
            if ins.a[0] != 'm':
                raise Fault('register-to-register xmm move not modelled')
            self.store(self.addr(ins.a, nxt), self.x[ins.b])
        elif op in ('ud2', 'int3'):
            raise Stop(op)
        elif op == 'nop':
            pass
        else:
            raise Fault(f'no semantics for {op} at {ins.va:#x}')
        return None

    # calls, stubs and unwinding ------------------------------------------------------------------
    def target(self, ins, nxt):
        if ins.op == 'call':
            t = nxt + ins.b
            if self.img.read(t, 2) == b'\xff\x25':
                if self.img.plt_symbol(t) != RESUME_SYMBOL:
                    raise Fault(f'PLT call {t:#x} is not {RESUME_SYMBOL}')
                return None, 'resume'
            return t, None
        if ins.a[0] != 'm' or not ins.a[5]:
            raise Fault(f'{ins.va:#x}: indirect call through a register')
        slot = nxt + ins.a[4]
        if slot in REAL_SLOTS:
            return self.img.relative[slot], None
        if slot not in SLOT_ROLES:
            raise Fault(f'{ins.va:#x}: call through unknown GOT slot {slot:#x}')
        return None, SLOT_ROLES[slot]

    def call(self, ins, nxt):
        t, role = self.target(ins, nxt)
        if role is None:
            self.r[4] -= 8
            self.store(self.r[4], nxt.to_bytes(8, 'little'))
            self.frames.append(Frame(self.r[4] + 8, ins.va))
            return t
        return self.stub(role, ins)

    def tail_got(self, ins, nxt):
        """`jmp [GOT]` leaves the frame: run the stub, then return to the caller."""
        slot = nxt + ins.a[4]
        if slot in REAL_SLOTS:
            return self.img.relative[slot]
        if slot not in SLOT_ROLES:
            raise Fault(f'{ins.va:#x}: jump through unknown GOT slot {slot:#x}')
        role = SLOT_ROLES[slot]
        if role in ('panic_add', 'panic_sub', 'alloc_error', 'terminate'):
            if role == 'terminate':
                self.events.append(('terminate',))
                raise Stop('terminate')
            self.events.append((role,))
            if not self.frames:
                raise Stop('escape')
            fr = self.frames.pop()
            self.r[4] = fr.rsp
            return self.unwind(fr.site)
        self.stub(role, ins)
        if self.r[4] == STACK_TOP - 8:
            return 'ret'
        ret = int.from_bytes(self.load(self.r[4], 8), 'little')
        self.r[4] += 8
        self.frames.pop()
        return ret

    def clobber(self):
        for n in (1, 2, 6, 7, 8, 9, 10, 11):
            self.r[n] = 0xdead_0000 + n

    def new_block(self, n):
        base = HEAP_BASE + len(self.blocks) * HEAP_STRIDE
        self.blocks.append([base, bytearray([HEAP_FILL]) * n, n, True])
        return base

    def stub(self, role, ins):
        r = self.r
        if role == 'alloc':
            k, self.allocs = self.allocs, self.allocs + 1
            self.events.append(('alloc', r[7]))
            p = 0 if k == self.case.get('fail_alloc') else self.new_block(r[7])
            self.clobber()
            r[0] = p
            return None
        if role == 'realloc':
            k, self.allocs = self.allocs, self.allocs + 1
            b = self.block_at(r[7])
            if b is None or b[0] != r[7] or not b[3]:
                raise Fault(f'realloc of a pointer that is not a live block base {r[7]:#x}')
            self.events.append(('realloc', b[2], r[6]))
            if k == self.case.get('fail_alloc'):
                self.clobber()
                r[0] = 0
                return None
            old = bytes(b[1])
            b[3] = False
            p = self.new_block(r[6])
            self.store(p, old[:r[6]])
            self.clobber()
            r[0] = p
            return None
        if role == 'free':
            b = self.block_at(r[7])
            if b is None or b[0] != r[7]:
                raise Fault(f'free of a pointer that is not a block base {r[7]:#x}')
            if not b[3]:
                raise Fault('double free')
            if b[2] != r[6]:
                raise Fault(f'free size {r[6]:#x} differs from the allocation size {b[2]:#x}')
            b[3] = False
            self.events.append(('free', r[6]))
            self.clobber()
            return None
        if role == 'terminate':
            self.events.append(('terminate',))
            raise Stop('terminate')
        if role in ('panic_add', 'panic_sub', 'alloc_error'):
            self.events.append((role,))
            return self.unwind(ins.va)
        if role == 'resume':
            if r[7] != EXC:
                raise Fault('_Unwind_Resume is not given the exception object')
            return self.unwind(ins.va)
        raise Fault(f'no stub for {role}')

    def unwind(self, site_va):
        """Two-phase unwind collapsed to one pass: walk frames, run the first landing pad found."""
        r = self.r
        while True:
            fn = self.prog.fn_containing(site_va)
            row = fn.site_of(site_va)
            if fn.lsda and row is None:
                raise Stop('no_call_site')
            if row is not None and row[0]:
                self.clobber()
                r[0], r[2] = EXC, row[1]
                return row[0]
            if not self.frames:
                raise Stop('escape')
            fr = self.frames[-1]
            entry = fr.rsp - 8
            for k, reg in enumerate(fn.pushes):
                if reg in CALLEE_SAVED:
                    r[reg] = int.from_bytes(self.load(entry - 8 * (k + 1), 8), 'little')
            r[4] = fr.rsp
            site_va = fr.site
            self.frames.pop()

    # tree extraction ------------------------------------------------------------------------------
    def content(self, a):
        raw = self.load(a, 32)
        tag = raw[0]
        if tag == 0:
            return ('bool', raw[1])
        if tag in (1, 2, 3, 4):
            n = {1: 1, 2: 2, 3: 4, 4: 8}[tag]
            off = {1: 1, 2: 2, 3: 4, 4: 8}[tag]
            return (('u8', 'u16', 'u32', 'u64')[tag - 1], int.from_bytes(raw[off:off + n], 'little'))
        if tag in (5, 6, 7, 8):
            n = {5: 1, 6: 2, 7: 4, 8: 8}[tag]
            off = {5: 1, 6: 2, 7: 4, 8: 8}[tag]
            return (('i8', 'i16', 'i32', 'i64')[tag - 5], sx(int.from_bytes(raw[off:off + n], 'little'), 8 * n))
        if tag == 9:
            return ('f32', int.from_bytes(raw[4:8], 'little'))
        if tag == 0xa:
            return ('f64', int.from_bytes(raw[8:16], 'little'))
        if tag in (0xd, 0xf):
            p, n = struct.unpack_from('<QQ', raw, 8)
            if not IN_BASE <= p <= IN_BASE + len(self.inp) or p - IN_BASE + n > len(self.inp):
                raise Fault('borrowed slice leaves the input')
            return ('str' if tag == 0xd else 'bytes', bytes(self.inp[p - IN_BASE:p - IN_BASE + n]))
        if tag == 0x12:
            return ('unit',)
        if tag == 0x13:
            return ('nt', self.content(struct.unpack_from('<Q', raw, 8)[0]))
        if tag in (0x14, 0x15):
            cap, ptr, n = struct.unpack_from('<QQQ', raw, 8)
            if tag == 0x14:
                return ('seq', cap, [self.content(ptr + 32 * i) for i in range(n)])
            return ('map', cap, [(self.content(ptr + 64 * i), self.content(ptr + 64 * i + 32)) for i in range(n)])
        raise Fault(f'content tag {tag:#x} is outside the enum')

    def live(self):
        return sum(1 for b in self.blocks if b[3])


# ---------------------------------------------------------------------------------------------
# reconstruction: Content deserialization from msgpack, allocation and drop order
VARIANTS = ('depth_off_by_one', 'collect_restores_on_err', 'ext_keeps_depth_on_err', 'clamp_seq_half', 'clamp_map_seq_size',
            'no_cleanup_free', 'cleanup_reverse', 'bad_utf8_is_str', 'ext_box_size_16', 'ext_cap_8', 'drop_key_after_value',
            'newtype_free_first', 'no_staged_key_drop', 'str_eof_consumes', 'prim_eof_keeps_input', 'negfix_unsigned',
            'ext_tag_unsigned', 'map_swap_kv', 'free_cap_len', 'seq_elem_32_map_32', 'reserved_marker_ok',
            'bin_is_str', 'fixext_size_2x', 'depth_zero_no_panic')


class Err(Exception):
    pass


class Unwound(Exception):
    pass


def be(buf, pos, n):
    return int.from_bytes(buf[pos:pos + n], 'big')


def utf8_check(b):
    """Reference `core::str::from_utf8` error: None if valid, else (valid_up_to, error_len or None)."""
    i, n = 0, len(b)
    while i < n:
        x = b[i]
        if x < 0x80:
            i += 1
            continue
        if 0xc2 <= x <= 0xdf:
            need, lo, hi = 1, 0x80, 0xbf
        elif x == 0xe0:
            need, lo, hi = 2, 0xa0, 0xbf
        elif x == 0xed:
            need, lo, hi = 2, 0x80, 0x9f
        elif 0xe1 <= x <= 0xef:
            need, lo, hi = 2, 0x80, 0xbf
        elif x == 0xf0:
            need, lo, hi = 3, 0x90, 0xbf
        elif x == 0xf4:
            need, lo, hi = 3, 0x80, 0x8f
        elif 0xf1 <= x <= 0xf3:
            need, lo, hi = 3, 0x80, 0xbf
        else:
            return (i, 1)
        for k in range(1, need + 1):
            if i + k >= n:
                return (i, None)
            y = b[i + k]
            if not (lo <= y <= hi if k == 1 else 0x80 <= y <= 0xbf):
                return (i, k)
        i += need + 1
    return None


class Model:
    def __init__(self, c, copy, variant=None):
        self.c, self.v = c, variant
        self.buf = c['buf']
        self.pos, self.rem = 0, len(self.buf)
        self.depth = c['depth']
        self.peek = c.get('peek')
        self.events, self.allocs = [], 0
        self.eof = COPIES[copy]['eof']
        self.flag = NO_PEEK if self.peek is None else self.peek[0]

    def run(self):
        try:
            node = self.start()
            res = ('ok', node)
            kind = 'ret'
        except Err as e:
            res, kind = ('err',) + e.args[0], 'ret'
        except Unwound:
            res, kind = None, 'escape'
        drop = []
        if kind == 'ret' and res[0] == 'ok':
            self.drop(res[1], drop)
        return (kind, res, tuple(self.events), (self.pos, self.rem, 1 if kind == 'ret' else None, self.depth),
                tuple(drop))

    def ev(self, *e):
        self.events.append(e)

    def alloc(self, kind, *args):
        k, self.allocs = self.allocs, self.allocs + 1
        self.ev(kind, *args)
        if k == self.c.get('fail_alloc'):
            self.ev('alloc_error')
            raise Unwound()

    # drop glue ---------------------------------------------------------------------------------
    def drop(self, node, out):
        t = node[0]
        if t == 'nt':
            if self.v == 'newtype_free_first':
                out.append(('free', 32))
                self.drop(node[1], out)
            else:
                self.drop(node[1], out)
                out.append(('free', 32))
        elif t == 'seq':
            for ch in (node[2][::-1] if self.v == 'cleanup_reverse' else node[2]):
                self.drop(ch, out)
            if node[1] and self.v != 'no_cleanup_free':
                out.append(('free', node[1] * (32 if self.v != 'seq_elem_32_map_32' else 32)))
        elif t == 'map':
            for k, v in node[2]:
                if self.v == 'drop_key_after_value':
                    self.drop(v, out)
                    self.drop(k, out)
                else:
                    self.drop(k, out)
                    self.drop(v, out)
            if node[1] and self.v != 'no_cleanup_free':
                out.append(('free', node[1] * (64 if self.v != 'seq_elem_32_map_32' else 32)))

    def cleanup(self, kind, items, cap):
        out = []
        self.drop(('seq', 0, items) if kind == 'seq' else ('map', 0, items), out)
        self.events.extend(out)
        if cap and self.v != 'no_cleanup_free':
            self.ev('free', cap * (ELEM[kind] if self.v != 'free_cap_len' else len(items) or 1))

    # reader ---------------------------------------------------------------------------------------
    def start(self):
        if self.peek is not None:
            flag, data = self.peek
            self.peek = None
            return self.dispatch(flag, data)
        return self.value()

    def value(self):
        if self.rem == 0:
            raise Err((0, self.eof))
        b = self.buf[self.pos]
        self.pos += 1
        self.rem -= 1
        if b < 0x80:
            return self.prim(0, b)
        if b >= 0xe0:
            return self.prim(0xe0, b)
        if b < 0x90:
            return self.collect('map', b & 0xf)
        if b < 0xa0:
            return self.collect('seq', b & 0xf)
        if b < 0xc0:
            return self.string(b & 0x1f)
        return self.dispatch(b, b & 0x1f)

    def length(self, size):
        if self.rem < size:
            if size > 1:
                self.pos += self.rem
                self.rem = 0
            raise Err((1, self.eof))
        n = be(self.buf, self.pos, size)
        self.pos += size
        self.rem -= size
        return n

    def dispatch(self, disc, dl):
        v = self.v
        if disc in (0, 0xc0, 0xc2, 0xc3, 0xe0) or 0xca <= disc <= 0xd3:
            return self.prim(disc, dl)
        if disc == 0x80:
            return self.collect('map', dl)
        if disc == 0x90:
            return self.collect('seq', dl)
        if disc == 0xa0:
            return self.string(dl)
        if disc == 0xc1:
            if v == 'reserved_marker_ok':
                return ('unit',)
            raise Err((2, 0xc1))
        if disc in (0xc4, 0xc5, 0xc6):
            return self.binary(self.length({0xc4: 1, 0xc5: 2, 0xc6: 4}[disc]))
        if disc in (0xd9, 0xda, 0xdb):
            return self.string(self.length({0xd9: 1, 0xda: 2, 0xdb: 4}[disc]))
        if disc in (0xdc, 0xdd):
            return self.collect('seq', self.length({0xdc: 2, 0xdd: 4}[disc]))
        if disc in (0xde, 0xdf):
            return self.collect('map', self.length({0xde: 2, 0xdf: 4}[disc]))
        if disc in (0xc7, 0xc8, 0xc9):
            return self.ext(self.length({0xc7: 1, 0xc8: 2, 0xc9: 4}[disc]))
        if 0xd4 <= disc <= 0xd8:
            return self.ext((2 if v == 'fixext_size_2x' else 1) * (1 << (disc - 0xd4)))
        raise Stop('ud2')

    def prim(self, disc, cl):
        if disc == 0:
            return ('u8', cl)
        if disc == 0xe0:
            return ('u8', cl) if self.v == 'negfix_unsigned' else ('i8', sx(cl, 8))
        if disc == 0xc0:
            return ('unit',)
        if disc in (0xc2, 0xc3):
            return ('bool', disc - 0xc2)
        name, n = {0xca: ('f32', 4), 0xcb: ('f64', 8), 0xcc: ('u8', 1), 0xcd: ('u16', 2), 0xce: ('u32', 4),
                   0xcf: ('u64', 8), 0xd0: ('i8', 1), 0xd1: ('i16', 2), 0xd2: ('i32', 4), 0xd3: ('i64', 8)}[disc]
        if self.rem < n:
            if n > 1 and self.v != 'prim_eof_keeps_input':
                self.pos += self.rem
                self.rem = 0
            raise Err((1, EOF_PRIM))
        val = be(self.buf, self.pos, n)
        self.pos += n
        self.rem -= n
        if name[0] == 'i':
            val = sx(val, 8 * n)
        return (name, val)

    def string(self, n):
        if n > self.rem:
            if self.v == 'str_eof_consumes':
                self.pos += self.rem
                self.rem = 0
            raise Err((1, EOF_SHORT))
        raw = self.buf[self.pos:self.pos + n]
        self.pos += n
        self.rem -= n
        if self.v == 'bin_is_str':
            return ('str', bytes(raw))
        if utf8_check(raw) is None or self.v == 'bad_utf8_is_str':
            return ('str', bytes(raw))
        return ('bytes', bytes(raw))

    def binary(self, n):
        if n > self.rem:
            raise Err((1, EOF_SHORT))
        raw = self.buf[self.pos:self.pos + n]
        self.pos += n
        self.rem -= n
        return ('bytes', bytes(raw))

    def enter(self):
        if self.depth == 0 and self.v != 'depth_zero_no_panic':
            self.ev('panic_sub')
            raise Unwound()
        self.depth -= 1
        if self.v == 'depth_off_by_one':
            self.depth -= 1
        if self.depth == 0:
            raise Err((8, None))

    def collect(self, kind, n):
        self.enter()
        E = ELEM[kind] if self.v != 'clamp_map_seq_size' else 32
        clamp = CLAMP[kind] // (2 if self.v == 'clamp_seq_half' and kind == 'seq' else 1)
        cap, items = 0, []
        try:
            if n:
                want = min(n, clamp)
                self.alloc('alloc', want * E)
                cap = want
            for _ in range(n):
                if kind == 'seq':
                    item = self.value()
                else:
                    key = self.value()
                    try:
                        val = self.value()
                    except (Err, Unwound):
                        if self.v != 'no_staged_key_drop':
                            out = []
                            self.drop(key, out)
                            self.events.extend(out)
                        raise
                    item = (val, key) if self.v == 'map_swap_kv' else (key, val)
                if len(items) == cap:
                    new = max(2 * cap, 4)
                    try:
                        self.alloc('realloc', cap * E, new * E)
                    except Unwound:
                        out = []
                        self.drop(item if kind == 'seq' else ('map', 0, [item]), out)
                        self.events.extend(out)
                        raise
                    cap = new
                items.append(item)
        except (Err, Unwound):
            self.cleanup(kind, items, cap)
            if self.v == 'collect_restores_on_err':
                self.depth += 1
            raise
        self.depth += 1
        return (kind, cap, items)

    def ext(self, n):
        self.enter()
        items, cap = [], 0
        try:
            if self.rem == 0:
                raise Err((1, self.eof))
            b = self.buf[self.pos]
            self.pos += 1
            self.rem -= 1
            self.alloc('alloc', 128 if self.v != 'ext_cap_8' else 256)
            cap = 4 if self.v != 'ext_cap_8' else 8
            items.append(('u8', b) if self.v == 'ext_tag_unsigned' else ('i8', sx(b, 8)))
            if n > self.rem:
                raise Err((1, EOF_SHORT))
            items.append(('bytes', bytes(self.buf[self.pos:self.pos + n])))
            self.pos += n
            self.rem -= n
            seq = ('seq', cap, items)
            try:
                self.alloc('alloc', 32 if self.v != 'ext_box_size_16' else 16)
            except Unwound:
                out = []
                self.drop(seq, out)
                self.events.extend(out)
                raise
        except Err:
            self.cleanup('seq', items, cap)
            if self.v != 'ext_keeps_depth_on_err':
                self.depth += 1
            raise
        self.depth += 1
        return ('nt', seq)


# ---------------------------------------------------------------------------------------------
# cases: deterministic msgpack documents built from a tiny xorshift generator
class Rng:
    def __init__(self, seed):
        self.s = (seed * 0x9e3779b97f4a7c15 + 1) & MASK64

    def next(self):
        x = self.s
        x ^= x >> 12
        x ^= (x << 25) & MASK64
        x ^= x >> 27
        self.s = x
        return (x * 0x2545F4914F6CDD1D) & MASK64

    def below(self, n):
        return (self.next() >> 11) % n

    def pick(self, seq):
        return seq[self.below(len(seq))]


UINTS = (0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffffff, 0x100000000, 0xffffffffffffffff, 5, 300)
INTS = (-1, -32, -33, -128, -129, -32768, -32769, -2147483648, -2147483649, -(1 << 63), 7, 127, 1000)
STRS = (b'', b'a', b'abc', 'é'.encode(), '€'.encode(), '😀'.encode(), b'x' * 40, 'ab€'.encode() * 9, b'\x80', b'\xc0\x80',
        b'\xe0\x80\x80', b'\xed\xa0\x80', b'\xf0\x80\x80\x80', b'\xf4\x90\x80\x80', b'\xff', b'a\xe2\x82',
        b'\xf0\x9f\x98', b'\xe2\x28\xa1', b'q' * 17 + b'\xf0\x28\x8c\xbc', b'z' * 33 + '😀'.encode())


def gen(rng, d):
    r = rng.below(100)
    if r < 14:
        return ('uint', rng.pick(UINTS))
    if r < 24:
        return ('int', rng.pick(INTS))
    if r < 28:
        return ('nil',)
    if r < 33:
        return ('bool', rng.below(2))
    if r < 38:
        return ('f32', rng.next() & 0xffffffff) if rng.below(2) else ('f64', rng.next())
    if r < 49:
        return ('str', rng.pick(STRS))
    if r < 54:
        return ('bin', bytes(rng.below(256) for _ in range(rng.below(20))))
    if r < 59:
        return ('ext', rng.below(256), bytes(rng.below(256) for _ in range(rng.pick((0, 1, 2, 3, 4, 8, 16, 17)))))
    if d <= 0:
        return ('uint', rng.pick(UINTS))
    if r < 80:
        return ('arr', [gen(rng, d - 1) for _ in range(rng.below(5))])
    return ('map', [(gen(rng, d - 1), gen(rng, d - 1)) for _ in range(rng.below(4))])


def enc_len(rng, n, forms):
    """forms: ((marker, size, limit), ...) widest last; picks any form whose limit fits n."""
    fit = [f for f in forms if n < f[2]]
    m, size, _ = rng.pick(fit)
    return bytes([m]) + n.to_bytes(size, 'big')


def enc(rng, s):
    t = s[0]
    if t == 'uint':
        v = s[1]
        if v < 128 and rng.below(2):
            return bytes([v])
        opts = [(0xcc, 1), (0xcd, 2), (0xce, 4), (0xcf, 8)]
        m, n = rng.pick([o for o in opts if v < 1 << (8 * o[1])])
        return bytes([m]) + v.to_bytes(n, 'big')
    if t == 'int':
        v = s[1]
        if -32 <= v < 0 and rng.below(2):
            return bytes([v & 0xff])
        opts = [(0xd0, 1), (0xd1, 2), (0xd2, 4), (0xd3, 8)]
        m, n = rng.pick([o for o in opts if -(1 << (8 * o[1] - 1)) <= v < 1 << (8 * o[1] - 1)])
        return bytes([m]) + (v & ((1 << 8 * n) - 1)).to_bytes(n, 'big')
    if t == 'nil':
        return b'\xc0'
    if t == 'bool':
        return bytes([0xc2 + s[1]])
    if t == 'f32':
        return b'\xca' + s[1].to_bytes(4, 'big')
    if t == 'f64':
        return b'\xcb' + s[1].to_bytes(8, 'big')
    if t == 'str':
        n = len(s[1])
        if n < 32 and rng.below(2):
            return bytes([0xa0 | n]) + s[1]
        return enc_len(rng, n, ((0xd9, 1, 256), (0xda, 2, 65536), (0xdb, 4, 1 << 32))) + s[1]
    if t == 'bin':
        return enc_len(rng, len(s[1]), ((0xc4, 1, 256), (0xc5, 2, 65536), (0xc6, 4, 1 << 32))) + s[1]
    if t == 'ext':
        n = len(s[2])
        if n in (1, 2, 4, 8, 16) and rng.below(2):
            return bytes([0xd4 + n.bit_length() - 1, s[1]]) + s[2]
        return enc_len(rng, n, ((0xc7, 1, 256), (0xc8, 2, 65536), (0xc9, 4, 1 << 32))) + bytes([s[1]]) + s[2]
    if t == 'arr':
        n = len(s[1])
        head = bytes([0x90 | n]) if n < 16 and rng.below(2) else enc_len(rng, n, ((0xdc, 2, 65536), (0xdd, 4, 1 << 32)))
        return head + b''.join(enc(rng, x) for x in s[1])
    n = len(s[1])
    head = bytes([0x80 | n]) if n < 16 and rng.below(2) else enc_len(rng, n, ((0xde, 2, 65536), (0xdf, 4, 1 << 32)))
    return head + b''.join(enc(rng, k) + enc(rng, v) for k, v in s[1])


def case(buf, label, peek=None, depth=0x400, fail=None):
    c = {'buf': bytes(buf), 'peek': peek, 'depth': depth, 'label': label}
    if fail is not None:
        c['fail_alloc'] = fail
    return c


PEEKS = tuple((d, d & 0x1f) for d in (0xc0, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
                                      0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
                                      0xde, 0xdf, 0xc1)) + ((0, 5), (0, 0x7f), (0xe0, 0x1f), (0xe0, 0xe5), (0x80, 0), (0x80, 2),
                                                           (0x90, 0), (0x90, 3), (0xa0, 0), (0xa0, 2))
TAILS = (b'', b'\x7f', b'\x00\x00\x00', bytes(range(1, 19)))


def all_cases():
    out = []
    for b in range(256):
        for k, t in enumerate(TAILS):
            out.append(case(bytes([b]) + t, 'marker'))
    for fl, dt in PEEKS:
        for t in (b'', b'\x01\x02', b'\x92\x01\x02\xa2ab' + bytes(range(9, 20))):
            out.append(case(t, 'peek', (fl, dt)))
    for s in STRS:
        n = len(s)
        for head in (bytes([0xa0 | n]) if n < 32 else b'', b'\xd9' + bytes([n]), b'\xda' + n.to_bytes(2, 'big'),
                     b'\xdb' + n.to_bytes(4, 'big'), b'\xc4' + bytes([n]) if n < 256 else b''):
            if head:
                out.append(case(head + s, 'str'))
                out.append(case(head + s[:-1], 'str_short') if s else case(head, 'str_short'))
    rng = Rng(115)
    docs = []
    for i in range(1100):
        s = gen(rng, 1 + i % 4)
        docs.append(enc(rng, s))
        out.append(case(docs[-1], 'doc'))
    for i, d in enumerate(docs[:700]):
        if len(d) > 2:
            for cut in (1 + rng.below(len(d) - 1), len(d) - 1):
                out.append(case(d[:cut], 'trunc'))
    for i, d in enumerate(docs[:150]):
        out.append(case(d, 'depth', depth=i % 5))
    for i, d in enumerate(docs[:160]):
        if d[0] >= 0x80 and d[0] not in range(0xa0, 0xc0):
            for k in range(4):
                out.append(case(d, 'fail_alloc', fail=k))
    for tag in (0, 0x7f, 0x80, 0xff):
        for n in (0, 1, 3, 17):
            out.append(case(b'\xc7' + bytes([n, tag]) + bytes(range(n)), 'ext'))
            out.append(case(b'\xc7' + bytes([n, tag]) + bytes(range(n))[:-1], 'ext_short') if n else case(b'\xc7', 'ext_short'))
        for m in range(5):
            n = 1 << m
            out.append(case(bytes([0xd4 + m, tag]) + bytes(range(n)), 'fixext'))
            out.append(case(bytes([0xd4 + m, tag]) + bytes(range(n))[:-1], 'fixext_short'))
            out.append(case(bytes([0xd4 + m, tag]) + bytes(range(n)), 'fixext_fail', fail=1))
    out.append(case(b'\xc8\x00', 'ext16_eof'))
    out.append(case(b'\xc9\x00\x00', 'ext32_eof'))
    for m in (b'\xdd\xff\xff\xff\xff', b'\xdd\x00\x01\x00\x00', b'\xdc\xff\xff', b'\xdf\xff\xff\xff\xff', b'\xde\xff\xff',
              b'\xdf\x00\x00\x40\x01'):
        out.append(case(m + b'\x01\x02', 'huge_len'))
        out.append(case(m + b'\x01\x02', 'huge_len_fail', fail=0))
    for lvl in (1, 2, 3, 10, 200, 1000, 1022, 1023, 1024, 1025):
        out.append(case(b'\x91' * lvl + b'\x01', 'deep_seq'))
        out.append(case(b'\x81\x01' * lvl + b'\x01', 'deep_map'))
    out.append(case(b'\x91' * 5 + b'\x01', 'deep_low', depth=3))
    out.append(case(b'\x92\xc1\x01', 'reserved_nested'))
    out.append(case(b'\x81\xc1\x01', 'reserved_key'))
    out.append(case(b'\x81\x01\xc1', 'reserved_value'))
    return out


def utf8_cases():
    xs = [s for s in STRS]
    for lead in range(0x80, 0x100):
        for sec in (0x00, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0):
            xs.append(bytes([lead, sec]))
    for lead in range(0xe0, 0xf0):
        for sec in (0x7f, 0x80, 0x9f, 0xa0, 0xbf, 0xc0):
            for th in (0x7f, 0x80, 0xbf, 0xc0):
                xs.append(bytes([lead, sec, th]))
    for lead in range(0xf0, 0xf6):
        for sec in (0x7f, 0x80, 0x8f, 0x90, 0xbf, 0xc0):
            for th in (0x80, 0xbf, 0xc0):
                for fo in (0x80, 0xbf, 0x7f):
                    xs.append(bytes([lead, sec, th, fo]))
    out = []
    for i, x in enumerate(xs):
        out.append(x)
        if i % 3 == 0:
            out.append(b'a' * (8 + i % 11) + x)
        if i % 7 == 0:
            out.append(x + b'zzzzzzzzzzzzzzzzzzzz')
    return out


# ---------------------------------------------------------------------------------------------
# running the original bytes
def drain(w, copy):
    """Run drop_result on the result and report (events, live blocks left)."""
    w.events = []
    kind = w.call_top(COPIES[copy]['drop_result'], OUT_BASE, 0)
    return kind, tuple(w.events)


def real_run(w, c, copy):
    w.setup(c)
    try:
        kind = w.call_top(COPIES[copy]['vr'], OUT_BASE, DES_BASE)
        res, state, drop = None, None, ()
        if kind == 'ret':
            if w.r[0] != OUT_BASE:
                raise Fault('rax does not return the out pointer')
            if w.out[0] == 0:
                res = ('ok', w.content(OUT_BASE + 8))
            else:
                tag = w.out[8]
                res = ('err', tag, w.out[9] if tag == 2 else None if tag == 8 else struct.unpack_from('<Q', w.out, 0x10)[0])
            pos, rem, flag, data, depth = struct.unpack_from('<QQBBH', w.des, 0x10)
            state = (pos - IN_BASE, rem, flag, depth)
            events = tuple(w.events)
            dk, drop = drain(w, copy)
            if dk != 'ret':
                raise Fault(f'drop ended with {dk}')
            return (kind, res, events, state, drop, w.live())
        return (kind, None, tuple(w.events), None, (), w.live())
    except (Fault, Stop, IndexError, struct.error, ValueError, MemoryError) as e:
        return ('fault', str(e)[:60], (), None, (), -1)


def model_run(c, copy, variant=None):
    try:
        k, res, ev, st, drop = Model(c, copy, variant).run()
    except (IndexError, KeyError, ValueError, struct.error, OverflowError, Stop):
        return ('model_fault',)
    return (k, res, ev, st if k == 'ret' else None, drop, 0)


def utf8_real(w, raw):
    w.setup(case(raw, 'utf8'))
    try:
        w.r[7], w.r[6], w.r[2] = OUT_BASE, IN_BASE, len(raw)
        w.r[4] = STACK_TOP - 8
        w.frames = []
        kind = w.run_from(UTF8)
        if kind != 'ret':
            return (kind,)
        if struct.unpack_from('<Q', w.out, 0)[0] == 0:
            p, n = struct.unpack_from('<QQ', w.out, 8)
            return ('ok', p - IN_BASE, n)
        valid = struct.unpack_from('<Q', w.out, 8)[0]
        has, ln = w.out[0x10], w.out[0x11]
        return ('err', valid, ln if has else None)
    except (Fault, Stop, IndexError, struct.error) as e:
        return ('fault', str(e)[:40])


def utf8_model(raw, variant=None):
    e = utf8_check(raw)
    if variant == 'python_decode':
        try:
            raw.decode('utf-8')
            e = None
        except UnicodeDecodeError as x:
            e = (x.start, None if x.end >= len(raw) and x.reason.startswith('unexpected end') else x.end - x.start)
    if variant == 'always_ok':
        e = None
    if variant == 'no_surrogate_rule' and e and raw[e[0]:e[0] + 1] == b'\xed':
        e = None
    if e is None:
        return ('ok', 0, len(raw))
    return ('err',) + e


# ---------------------------------------------------------------------------------------------
# controls, evidence and command line
def lea_target(ins):
    return ins.va + ins.size + ins.b[4]


class Patched(Image):
    def __init__(self, base, data):
        super().__init__(data, check=False)


def flip_jcc(img, va, ins):
    d = bytearray(img.data)
    d[img.off(va) + (1 if ins.raw[0] == 0x0f else 0)] ^= 1
    return Patched(img, bytes(d))


# conditional jumps whose inverted condition changed at least one result (found by a sweep over every jcc, then fixed)
IMAGE_MUTANTS = (
    (0x17fb290, 0x1a), (0x17fb290, 0x3c), (0x17fb290, 0x55), (0x17fb290, 0x74), (0x17fb290, 0xd7), (0x17fb290,
    0x10e), (0x17fb290, 0x17f), (0x17fb290, 0x1c8), (0x17fb290, 0x245), (0x17fb290, 0x299), (0x17fb290, 0x30c),
    (0x17fb290, 0x352), (0x17fb290, 0x3b5), (0x17fb290, 0x405), (0x17fb290, 0x47f), (0x17fb290, 0x539),
    (0x17fb290, 0x5d8), (0x17fb290, 0x618), (0x17fb290, 0x66a), (0x17fb290, 0x70e), (0x21e0380, 0x47), (0x21e0380,
    0x115), (0x21e0380, 0x15f), (0x21e0380, 0x253), (0x21e0380, 0x3bb), (0x21e1c10, 0x45), (0x21e1c10, 0xd2),
    (0x21e1c10, 0xff), (0x21e1c10, 0x1ff), (0x21e1930, 0xf4), (0x21e1930, 0x106), (0x21e1930, 0x157), (0x21e1930,
    0x224), (0x18a33d0, 0x15), (0x18a33d0, 0x97), (0x18a33d0, 0xf3), (0x230ce30, 0x64), (0x230ce30, 0xe0),
    (0x187d4e0, 0x7), (0x21d66b0, 0x27), (0x14b9940, 0x11), (0x14b9940, 0x5e), (0x14b9940, 0xc5), (0x14b9940,
    0x135), (0x14b9940, 0x1b7), (0x14b9940, 0x21b), (0x16815e0, 0x18), (0x16815e0, 0x55), (0x16815e0, 0x85),
    (0x16815e0, 0x94), (0x16815e0, 0xbc), (0x16815e0, 0xc8), (0x16815e0, 0xe2), (0x16815e0, 0x106), (0x16815e0,
    0x122), (0x16815e0, 0x151), (0x16815e0, 0x16c), (0x16815e0, 0x183), (0x16815e0, 0x1a7), (0x16815e0, 0x1b6),
    (0x16a0730, 0x3e), (0x16a0810, 0x4a), (0x16a0810, 0xba), (0x21d8eb0, 0x97), (0x21d8eb0, 0xf3), (0x21dbd40,
    0x3d),
)
FN_NAMES = {}
for _i, _c in enumerate(COPIES):
    FN_NAMES[_c['vr']] = 'value_reader'
    FN_NAMES[_c['map']] = 'visit_map'
    FN_NAMES[_c['seq']] = 'visit_seq'
    FN_NAMES[_c['ext']] = 'visit_ext'
    FN_NAMES[_c['drop']] = 'drop_content'
    FN_NAMES[_c['drop_result']] = 'drop_result'
for _a in (0x21d8eb0, 0x230ce30, 0x3b62630, 0x3d91100, 0x57aa810, 0x5b20680):
    FN_NAMES[_a] = 'drop_content_elem'
for _a in (0x21dbd40, 0x3b64e90, 0x57ad0c0):
    FN_NAMES[_a] = 'drop_vec'
for _a in (0x189e140, 0x3025e80, 0x48722a0):
    FN_NAMES[_a] = 'drop_io_error'
for _a in (0x21d66b0, 0x3b5f5b0, 0x57a77e0):
    FN_NAMES[_a] = 'access_helper'
FN_NAMES.update({UTF8: 'from_utf8', PRIM: 'scalar_leaf', GROW[0]: 'grow_one', GROW[1]: 'grow_one_b', FINISH_GROW: 'finish_grow'})


def fnname(a):
    return FN_NAMES.get(a, 'unnamed')


def show(node, lim=70):
    s = repr(node)
    return s if len(s) <= lim else s[:lim - 3] + '...'


def res_text(res):
    if res is None:
        return '-'
    if res[0] == 'ok':
        return 'ok:%s:%s' % (h16(repr(res[1]).encode()), show(res[1], 60))
    return 'err:' + ':'.join('-' if x is None else '%#x' % x for x in res[1:])


def ev_text(evs):
    return ';'.join(','.join(str(x) for x in e) for e in evs) or '-'


def case_cols(c):
    b = c['buf'].hex()
    return [c['label'], (b if len(b) <= 72 else b[:72] + '+%d' % (len(c['buf']) - 36)) or '-',
            '-' if c['peek'] is None else '%x:%x' % c['peek'], '%x' % c['depth'],
            str(c['fail_alloc']) if 'fail_alloc' in c else '-']


def mutation_sample():
    return [c for i, c in enumerate(all_cases()) if i % 12 == 5 or c['label'] == 'huge_len']


def range_controls(img, data):
    res = []

    def rejected(name, thunk):
        try:
            res.append((name, bool(thunk())))
        except (Fault, ValueError, Stop, IndexError, struct.error):
            res.append((name, True))

    bad = bytearray(data)
    bad[len(bad) // 2] ^= 1
    rejected('digest_flip', lambda: Image(bytes(bad)) and False)
    prog = Prog(img)
    rejected('start_not_fde', lambda: prog.fn(COPIES[0]['vr'] + 1) and False)
    rejected('sweep_overrun', lambda: sweep(img, UTF8, UTF8 + 503 - 2) and False)
    rejected('unmapped_read', lambda: img.read(0x7fff_0000_0000, 4) and False)
    rejected('into_instruction', lambda: prog.at(COPIES[0]['vr'] + 1) and False)
    rejected('plt_not_resume', lambda: World(prog).target(prog.at(COPIES[0]['vr'] + 0x7f9), COPIES[0]['vr'] + 0x7f9 + 5)
             and False)
    w = World(Prog(img))
    c = case(b'', 'peek', (0xe1, 0))
    rejected('disc_past_table', lambda: real_run(w, c, 0)[0] == 'fault')
    c = case(b'\x93\xa1a\x01\x91\x02', 'drop')
    w.setup(c)
    w.call_top(COPIES[0]['vr'], OUT_BASE, DES_BASE)
    drain(w, 0)
    rejected('double_drop', lambda: drain(w, 0) and False)
    w.setup(c)
    w.call_top(COPIES[0]['vr'], OUT_BASE, DES_BASE)
    cap = struct.unpack_from('<Q', w.out, 0x10)[0]
    struct.pack_into('<Q', w.out, 0x10, cap + 1)
    rejected('corrupt_capacity', lambda: drain(w, 0) and False)
    w.setup(c)
    w.call_top(COPIES[0]['vr'], OUT_BASE, DES_BASE)
    struct.pack_into('<Q', w.out, 0x18, 0x1234_5678)
    rejected('corrupt_pointer', lambda: drain(w, 0) and False)
    w.setup(case(b'\xa2ab', 'x'))
    w.call_top(COPIES[0]['vr'], OUT_BASE, DES_BASE)
    struct.pack_into('<Q', w.out, 0x10, IN_BASE + 0x1000)
    rejected('slice_outside_input', lambda: w.content(OUT_BASE + 8) and False)
    return res


def generate(out_dir, data=None):
    data = data if data is not None else Path(BINARY).read_bytes()
    img = Image(data)
    prog = Prog(img)
    w = World(prog)
    w.cov, w.edges = set(), set()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cases = all_cases()
    cases.append(case(b'\xdd\x00\x00\x80\x01' + b'\x01' * 0x8001, 'grow_seq'))
    cases.append(case(b'\xdf\x00\x00\x40\x01' + b'\x01\x02' * 0x4001, 'grow_map'))
    total, mismatches, outcomes, digest = 0, 0, {}, hashlib.sha256()
    rows = ['label\tcopy\tbuf\tpeek\tdepth\tfail_alloc\toutcome\tresult\tevents\tdrop_events\tstate']
    for idx, c in enumerate(cases):
        for copy in (0,) if c['label'].startswith('grow') else (0, 1, 2):
            got = real_run(w, c, copy)
            want = model_run(c, copy)
            total += 1
            mismatches += got != want
            outcomes[got[0] + ':' + (got[1][0] if got[1] else '-')] = outcomes.get(got[0] + ':' + (got[1][0] if got[1] else '-'), 0) + 1
            digest.update(repr((idx, copy, got)).encode())
            if copy == 0 and idx % 3 == 0 and not c['label'].startswith('grow'):
                rows.append('\t'.join(case_cols(c) + [got[0], res_text(got[1]), ev_text(got[2]), ev_text(got[4]),
                                                      '-' if got[3] is None else ','.join(map(str, got[3]))]))
    uc = utf8_cases()
    urows = ['input\tref\tresult']
    umis = 0
    for i, raw in enumerate(uc):
        got = utf8_real(w, raw)
        want = utf8_model(raw)
        total += 1
        umis += got != want
        digest.update(repr(('u', i, got)).encode())
        if i % 4 == 0:
            urows.append('\t'.join((raw.hex() or '-', '-'.join(map(str, want)), '-'.join('-' if x is None else str(x) for x in got))))
    mismatches += umis
    # coverage, functions, call sites, LSDA rows, jump tables
    func_rows = ['function\tstart\tsize\tlsda\tinsns\tcovered\tpushes\tcall_sites\tlsda_rows']
    call_rows = ['function\tstart\toffset\top\ttarget\trole']
    lsda_rows = ['function\tstart\tcall_start\tcall_end\tlanding_pad\taction']
    cov_rows = ['function\tstart\toffset\top\tsize\tcovered\tedges']
    for start in sorted(prog.fns):
        fn = prog.fns[start]
        name = fnname(start)
        hit = sum(1 for i in fn.insns if i.va in w.cov)
        calls = [i for i in fn.insns if i.op in ('call', 'callr')]
        func_rows.append('\t'.join(map(str, (name, hx(start), fn.end - start, hx(fn.lsda), len(fn.insns), hit,
                                             ','.join(str(p) for p in fn.pushes) or '-', len(calls), len(fn.sites)))))
        for i in calls:
            nxt = i.va + i.size
            try:
                t, role = w.target(i, nxt)
            except Fault:
                t, role = None, 'unknown'
            call_rows.append('\t'.join((name, hx(start), hx(i.va - start), i.op, hx(t) if t else '-',
                                        role or fnname(t))))
        for s, e, lp, a in fn.sites:
            lsda_rows.append('\t'.join((name, hx(start), hx(s - start), hx(e - start), hx(lp - start) if lp else '-', str(a))))
        if start in {c['vr'] for c in COPIES[:1]} | {c['map'] for c in COPIES[:1]} | {c['seq'] for c in COPIES[:1]} \
                | {COPIES[0]['ext'], COPIES[0]['drop'], COPIES[0]['drop_result'], UTF8, PRIM, FINISH_GROW, GROW[0]}:
            for i in fn.insns:
                e = ''
                if i.op == 'j':
                    e = ('T' if (i.va, True) in w.edges else '') + ('N' if (i.va, False) in w.edges else '')
                cov_rows.append('\t'.join((name, hx(start), hx(i.va - start), i.op, str(i.size), str(int(i.va in w.cov)), e or '-')))
    table_rows = ['table\tindex\ttarget_offset']
    vr = COPIES[0]['vr']
    for name, off, n in (('marker', 0x7e, 0xe1), ('ext', 0xbf, 18)):
        ins = prog.cache[vr + off]
        if ins.op != 'lea':
            raise Fault('table lea moved')
        for k, va in enumerate(img.table(lea_target(ins), n)):
            table_rows.append('%s\t%d\t%s' % (name, k, hx(va - vr)))
    for name, fnv, off, n in (('drop_content', COPIES[0]['drop'], 0x17, 21), ('drop_result', COPIES[0]['drop_result'], 0x12, 7)):
        ins = prog.fn(fnv).insns[0]
        lea = [i for i in prog.fn(fnv).insns if i.op == 'lea' and i.b[0] == 'm' and i.b[5]][0]
        for k, va in enumerate(img.table(lea_target(lea), n)):
            table_rows.append('%s\t%d\t%s' % (name, k, hx(va - fnv)))
    # negative controls
    controls = []
    sample = mutation_sample()
    expected = [model_run(c, 0) for c in sample]
    wr = World(prog)
    realres = [real_run(wr, c, 0) for c in sample]
    if realres != expected:
        raise Fault('sample disagrees before the controls start')
    for v in VARIANTS:
        controls.append(('model', v, any(model_run(c, 0, v) != r for c, r in zip(sample, realres))))
    for v in ('always_ok', 'no_surrogate_rule'):
        controls.append(('utf8_model', v, any(utf8_model(x, v) != utf8_real(wr, x) for x in uc[:400])))
    for f, off in IMAGE_MUTANTS:
        ins = prog.cache[f + off]
        wm = World(Prog(flip_jcc(img, ins.va, ins)))
        controls.append(('image', '%s:%s+%#x' % (fnname(f), hx(f), off),
                         any(real_run(wm, c, 0) != e for c, e in zip(sample, expected))))
    for name, ok in range_controls(img, data):
        controls.append(('range', name, ok))
    mut_rows = ['kind\tcontrol\tdetected'] + ['%s\t%s\t%d' % (k, n, int(ok)) for k, n, ok in controls]
    files = {'cases': rows, 'utf8': urows, 'functions': func_rows, 'calls': call_rows, 'lsda': lsda_rows,
             'coverage': cov_rows, 'tables': table_rows, 'mutants': mut_rows}
    for name, rs in files.items():
        (out / f'{name}.tsv').write_text('\n'.join(rs) + '\n')
    covered = sum(1 for s in prog.fns.values() for i in s.insns if i.va in w.cov)
    allins = sum(len(s.insns) for s in prog.fns.values())
    summary = {'sha256': SHA256, 'cases': total, 'mismatches': mismatches, 'negative_controls': len(controls),
               'negative_detected': sum(1 for c in controls if c[2]), 'functions_executed': len(prog.fns),
               'instructions_covered': f'{covered}/{allins}', 'outcomes': dict(sorted(outcomes.items())),
               'results_sha256': digest.hexdigest(), 'utf8_cases': len(uc),
               'case_rows': len(rows) - 1, 'utf8_rows': len(urows) - 1}
    (out / 'summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    measure = {'cases': total, 'negative_controls': len(controls), 'negative_detected': summary['negative_detected'],
               'mismatches': mismatches}
    (out / 'measure.json').write_text(json.dumps(measure, indent=1, sort_keys=True) + '\n')
    return summary


def hx(v):
    return v if isinstance(v, str) else '%#x' % v


def main():
    sys.setrecursionlimit(30000)
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    s = generate(a.out)
    print(json.dumps(s, sort_keys=True))
    return 0 if s['mismatches'] == 0 and s['negative_controls'] == s['negative_detected'] else 1


if __name__ == '__main__':
    sys.exit(main())
