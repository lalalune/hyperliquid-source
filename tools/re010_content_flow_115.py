#!/usr/bin/env python3
"""Reconstruct the node #115 MessagePack `Content` deserialization as one recursive flow.

Earlier packets rebuilt the pieces one function at a time with the neighbours stubbed:
the value reader (`deserialize_any`, 2,074 B), the map / seq collectors (1,191 B / 666 B)
and the ext visitor (727 B).  Here those four bodies of one deserializer copy run as
real code, calling each other through their actual call sites, so that

  value reader -> map collector -> value reader (key) -> value reader (value) -> ...

is executed by the bytes themselves: depth budget, per-level allocation clamp, vector
growth, early-error cleanup (drop every collected element, free the buffer), the
count check after a collector, UTF-8 fallback to bytes and the ext newtype box.
Three copy sets are rebuilt, bound by their call targets:

  set 0  value reader 0x17fb290  map 0x21e0380  seq 0x21e1c10  ext 0x21e1930
  set 1  value reader 0x2f7f5e0  map 0x3b68660  seq 0x3b69610  ext 0x3b69ad0
  set 2  value reader 0x47d2470  map 0x57af090  seq 0x57af540  ext 0x57afa00

The shared scalar leaf 0x14b9940 also runs real.  Only the allocator, RawVec growth,
free, UTF-8 validation, the drop glue and the panic / alloc-error entries are contract
stubs (the unwind is not walked: a panic ends the run and the call history up to it is
compared).

This tool:
1. checks the input digest, finds every function's FDE extent and LSDA, decodes each
   instruction with a fixed-pattern x86-64 subset decoder, binds every call site to a
   role by its offset and proves that each set is closed under its own real calls;
2. interprets the original bytes (the binary is never run) over MessagePack inputs
   (all 256 marker bytes, nested documents, every truncation point, depth budgets,
   failing allocations) and decodes the resulting `Content` tree out of the interpreter
   heap;
3. compares result tree or error fields, the ordered callee events (alloc / grow /
   free / drop with the dropped subtree / utf8) and the deserializer state with a pure
   recursive reconstruction (`FlowModel` below);
4. proves that wrong reconstructions, corrupted images and out-of-range inputs are
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
from fde_extents import eh_frame_records, uleb  # noqa: E402,F401

BINARY = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

PRIM, PRIM_SIZE = 0x14b9940, 665
# One deserializer copy set = the value reader plus the three collectors it reaches; every
# call between them stays inside the set (checked below), the leaf PRIM is shared.
SETS = (
    {'vr': 0x17fb290, 'map': 0x21e0380, 'seq': 0x21e1c10, 'ext': 0x21e1930},
    {'vr': 0x2f7f5e0, 'map': 0x3b68660, 'seq': 0x3b69610, 'ext': 0x3b69ad0},
    {'vr': 0x47d2470, 'map': 0x57af090, 'seq': 0x57af540, 'ext': 0x57afa00},
)
KINDS = {
    'vr': {'size': 2074, 'frame': 0xb0, 'tables': ((0x7e, 'marker', 0xe1), (0xbf, 'ext', 18)),
           'direct': {0x21e0380: 'map', 0x21e1c10: 'seq', 0x21e1930: 'ext', 0x18a33d0: 'drop_content',
                      0x187d4e0: 'drop_result', 0x21d8eb0: 'drop_ext'}},
    'map': {'size': 1191, 'frame': 0x168, 'tables': (),
            'direct': {0x17fb290: 'read', 0x21d8eb0: 'drop_content', 0x230ce30: 'drop_elem', 0x21d6020: 'drop_entry',
                       0x21d66b0: 'drop_vec', 0x21dbd40: 'drop_vec', 0x22faae0: 'drop_pair'}},
    'seq': {'size': 666, 'frame': 0x98, 'tables': (),
            'direct': {0x17fb290: 'read', 0x21d8eb0: 'drop_content', 0x230ce30: 'drop_elem', 0x21d6020: 'drop_entry',
                       0x21d66b0: 'drop_vec', 0x21dbd40: 'drop_vec', 0x22faae0: 'drop_pair'}},
    'ext': {'size': 727, 'frame': 0x78, 'tables': (),
            'direct': {0x230ce30: 'drop_elem', 0x21d8eb0: 'drop_content', 0x21dbd40: 'drop_vec'}},
}
ELEM = {'vr': 32, 'map': 64, 'seq': 32, 'ext': 32}
CLAMP = {'map': 0x4000, 'seq': 0x8000}
GOT_ROLES = {0x64dffb0: 'prim', 0x64dfca8: 'from_utf8', 0x64df520: 'panic_add', 0x64df848: 'panic_sub',
             0x64df480: 'alloc', 0x64df490: 'alloc_error', 0x64df498: 'alloc_error', 0x64df4a0: 'free',
             0x64e13c0: 'grow', 0x64e13b8: 'grow', 0x64df4c0: 'terminate'}
RESUME_SYMBOL = '_Unwind_Resume'
EOF_LEAS = {'vr': (0x3ce, 0x4dd), 'ext': (0x1eb,)}   # rip-relative loads of the static EOF io::Error
UNWINDS = ('panic_add', 'panic_sub', 'alloc_error')   # never return; they unwind
REAL = {'prim': None, 'map': 'map', 'seq': 'seq', 'ext': 'ext', 'read': 'vr'}   # call role -> callee kind
STACK_SIZE = 0x10000
NO_PEEK = 1                      # Option<Marker>::None niche in the peek slot
EOF_PRIM, EOF_VR, EOF_SHORT = 0x63f8470, 0x641ccb0, 0x2500000003
OUT_BASE, ACC_BASE, DES_BASE, IN_BASE = 0x7100_0000_0000, 0x7180_0000_0000, 0x7190_0000_0000, 0x7500_0000_0000
HEAP_BASE, STACK_TOP = 0x7400_0000_0000, 0x7200_0000_0000
MASK64 = (1 << 64) - 1
OUT_FILL, STACK_FILL, DES_FILL, ACC_FILL, HEAP_FILL = 0xaa, 0x5c, 0x3d, 0x2b, 0xee
OUT_SIZE, DES_SIZE, ACC_SIZE = 0x30, 0x28, 0x20
EXC = 0xe0c0_0000_0001           # exception object token handed to landing pads
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
        if reg & 7 != 2 or rm[0] != 'r':
            raise Fault(f'unsupported f7 form at {va:#x}')
        ins.op, ins.a = 'not', rm
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



def lea_target(ins):
    return ins.va + ins.size + ins.b[4]




class Stop(Exception):
    pass


class Throw(Exception):
    pass


def fde_info(img, start):
    f = fde_of(img.data, start)
    return f['end'], f.get('lsda') or 0



class Fn:
    """Static facts of one body copy, all read from the bytes."""

    def __init__(self, img, kind, start, anchor=None):
        k = KINDS[kind]
        self.kind, self.start = kind, start
        self.end, self.lsda = fde_info(img, start)
        if self.end - start != k['size']:
            raise Fault(f'{start:#x}: FDE extent is {self.end - start} bytes')
        self.sites = img.call_sites(self.lsda, start) if self.lsda else []
        self.insns = sweep(img, start, self.end)
        self.cache = {i.va: i for i in self.insns}
        subs = [i for i in self.insns if i.op == 'sub' and i.a == ('r', 4) and i.b[0] == 'i']
        if not subs or subs[0].b[1] != k['frame']:
            raise Fault(f'{start:#x}: frame size is not {k["frame"]:#x}')
        self.role, self.targets, self.tables = {}, {}, {}
        self.eof = None
        for off in EOF_LEAS.get(kind, ()):
            ins = self.cache[start + off]
            if ins.op != 'lea':
                raise Fault(f'{start:#x}+{off:#x} is not the EOF lea')
            if self.eof not in (None, lea_target(ins)):
                raise Fault(f'{start:#x}: two different EOF constants')
            self.eof = lea_target(ins)
        for i in self.insns:
            if i.op not in ('call', 'callr'):
                continue
            o = i.va - start
            if i.op == 'callr':
                slot = i.va + i.size + i.a[4]
                if i.a[0] != 'm' or not i.a[5] or slot not in GOT_ROLES:
                    raise Fault(f'{i.va:#x}: indirect call is not through a known GOT slot')
                role, t = GOT_ROLES[slot], img.relative.get(slot, slot)
            else:
                t = i.va + i.size + i.b
                if img.read(t, 2) == b'\xff\x25' and img.plt_symbol(t) == RESUME_SYMBOL:
                    role = 'resume'
                elif anchor is None:
                    if t not in k['direct']:
                        raise Fault(f'{i.va:#x}: direct call target {t:#x} has no role')
                    role = k['direct'][t]
                else:
                    role = anchor.role.get(anchor.start + o)
                    if role is None:
                        raise Fault(f'{i.va:#x}: call offset +{o:#x} is not a call in the anchor copy')
            self.role[i.va] = role
            self.targets.setdefault(role, set()).add(t)
        for off, name, n in k['tables']:
            ins = self.cache[start + off]
            if ins.op != 'lea':
                raise Fault(f'{start:#x}+{off:#x} is not the table lea')
            self.tables[name] = (lea_target(ins), n)
        if anchor is not None:
            same = [a.raw == b.raw for a, b in zip(anchor.insns, self.insns) if a.op not in ('call', 'lea', 'callr')]
            if len(anchor.insns) != len(self.insns) or not all(same):
                raise Fault(f'{start:#x}: not a layout copy of {anchor.start:#x}')
            if {self.start + va - anchor.start: r for va, r in anchor.role.items()} != self.role:
                raise Fault(f'{start:#x}: call roles differ from the anchor copy')
            if self.sites != [(s - anchor.start + start, e - anchor.start + start,
                               lp - anchor.start + start if lp else 0, a) for s, e, lp, a in anchor.sites]:
                raise Fault(f'{start:#x}: call-site table differs from the anchor copy')

    def site_of(self, call_va):
        for s, e, lp, a in self.sites:
            if s <= call_va < e:
                return lp, a
        return None

    def table_rows(self, img):
        rows = []
        for name, (t, n) in sorted(self.tables.items()):
            for idx, va in enumerate(img.table(t, n)):
                rows.append((name, idx, va - self.start))
        return rows


class Prim:
    """The shared primitive leaf: decoded and run as real code inside the value reader."""

    def __init__(self, img):
        self.start = PRIM
        self.end, lsda = fde_info(img, PRIM)
        if self.end - PRIM != PRIM_SIZE or lsda:
            raise Fault('primitive leaf extent or LSDA differs')
        self.insns = sweep(img, PRIM, self.end)
        self.cache = {i.va: i for i in self.insns}
        if any(i.op in ('call', 'callr') for i in self.insns):
            raise Fault('primitive leaf is not a leaf')





def load_sets(img):
    sets = []
    anchors = {k: Fn(img, k, SETS[0][k]) for k in KINDS}
    for i, s in enumerate(SETS):
        sets.append({k: anchors[k] if i == 0 else Fn(img, k, s[k], anchors[k]) for k in KINDS})
    return sets


def closure_rows(img, fns):
    """Every call that stays inside the copy set: (caller kind, offset, role, callee kind, callee start)."""
    rows = []
    for kind, fn in fns.items():
        for i in fn.insns:
            role = fn.role.get(i.va)
            if role not in REAL:
                continue
            if role == 'prim':
                tgt = fn.targets['prim']
                if tgt != {PRIM}:
                    raise Fault(f'{fn.start:#x}: primitive slot does not resolve to {PRIM:#x}')
                rows.append((kind, i.va - fn.start, role, 'prim', PRIM))
                continue
            tgt = i.va + i.size + i.b
            callee = REAL[role]
            if fns[callee].start != tgt:
                raise Fault(f'{i.va:#x}: {role} call leaves the copy set ({tgt:#x})')
            rows.append((kind, i.va - fn.start, role, callee, tgt))
    return rows


SCALARS = {1: ('u8', 1, 1), 2: ('u16', 2, 2), 3: ('u32', 4, 4), 4: ('u64', 8, 8), 5: ('i8', 1, 1), 6: ('i16', 2, 2),
           7: ('i32', 4, 4), 8: ('i64', 8, 8), 9: ('f32', 4, 4), 0xa: ('f64', 8, 8)}
NODE_LIMIT = 70000


class Machine:
    """Runs the value reader and everything it calls as real code; only leaf services are contract stubs."""

    def __init__(self, img, fns, prim):
        self.img, self.fns, self.prim = img, fns, prim
        closure_rows(img, fns)
        self.cache = dict(prim.cache)
        self.role, self.owner = {}, []
        for fn in fns.values():
            self.cache.update(fn.cache)
            self.role.update(fn.role)
            self.owner.append((fn.start, fn.end, fn))
        self.starts = {fn.start for fn in fns.values()} | {PRIM}
        self.start = fns['vr'].start
        self.eof_vr, self.eof_ext = fns['vr'].eof, fns['ext'].eof

    def fn_at(self, va):
        for s, e, fn in self.owner:
            if s <= va < e:
                return fn
        raise Fault(f'{va:#x} is not inside a copy-set function')

    def setup(self, c):
        self.case = c
        buf = c['buf']
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.des = bytearray([DES_FILL]) * DES_SIZE
        self.acc = bytearray()
        self.inp = bytearray(buf)
        self.stack = bytearray([STACK_FILL]) * STACK_SIZE
        self.heap, self.events, self.edges, self.trace = [], [], set(), set()
        self.nalloc = 0
        self.r = [0xdead_0000 + n for n in range(16)]
        self.x = [bytes(16)] * 16
        self.r[7], self.r[6], self.r[4] = OUT_BASE, DES_BASE, STACK_TOP - 8
        self.r[8], self.r[9] = 0x4000_0000_0000_0000, 0x5000_0000_0000_0000
        self.flags = dict(z=0, c=0, s=0, o=0)
        peek = c['peek']
        struct.pack_into('<QQBBH', self.des, 0x10, IN_BASE, len(buf),
                         NO_PEEK if peek is None else peek[0], 0x77 if peek is None else peek[1], c['depth'])

    def run(self, c, limit=3_000_000):
        self.setup(c)
        pc = self.start
        try:
            for _ in range(limit):
                ins = self.cache.get(pc)
                if ins is None:
                    raise Fault(f'left the copy set or jumped into an instruction at {pc:#x}')
                self.trace.add(pc)
                nxt = pc + ins.size
                res = self.step(ins, nxt)
                if ins.op == 'j':
                    self.edges.add((pc, res is not None))
                if res == 'ret':
                    if self.r[0] != OUT_BASE:
                        raise Fault('rax does not return the out pointer')
                    return self.result('ret')
                pc = nxt if res is None else res
            raise Fault('step limit')
        except Stop as s:
            return self.result(s.args[0])

    def state(self):
        d = struct.unpack_from('<QQBBH', self.des, 0x10)
        return (d[0] - IN_BASE, d[1], d[2], d[3], d[4])

    def result(self, kind):
        if kind != 'ret':
            return (kind, tuple(self.events))
        if struct.unpack_from('<Q', self.out, 0)[0] == 0:
            val = ('ok', self.tree(OUT_BASE + 8))
        else:
            val = ('err', bytes(self.out[8:0x28]))
        return ('ret', val, tuple(self.events), self.state())

    def tree(self, a, budget=None):
        """Decode the Content at `a` (and everything it owns) into plain tuples."""
        budget = budget if budget is not None else [NODE_LIMIT]
        budget[0] -= 1
        if budget[0] < 0:
            raise Fault('content tree too large')
        c = self.load(a, 32)
        t = c[0]
        if t == 0:
            return ('bool', c[1])
        if t in SCALARS:
            name, off, n = SCALARS[t]
            return (name, int.from_bytes(c[off:off + n], 'little'))
        if t in (0xd, 0xf):
            p, ln = struct.unpack_from('<QQ', c, 8)
            if ln > 1 << 20:
                raise Fault('string too long')
            return ('str' if t == 0xd else 'bytes', self.load(p, ln) if ln else b'')
        if t == 0x12:
            return ('unit',)
        if t == 0x13:
            return ('newtype', self.tree(struct.unpack_from('<Q', c, 8)[0], budget))
        if t in (0x14, 0x15):
            cap, p, ln = struct.unpack_from('<QQQ', c, 8)
            if ln > 1 << 16:
                raise Fault('collection too long')
            if t == 0x14:
                return ('seq', cap, tuple(self.tree(p + 32 * i, budget) for i in range(ln)))
            return ('map', cap, tuple((self.tree(p + 64 * i, budget), self.tree(p + 64 * i + 32, budget))
                                      for i in range(ln)))
        return ('?', t)

    def new_block(self, n):
        base = HEAP_BASE + len(self.heap) * 0x1000_0000
        self.heap.append((base, bytearray([HEAP_FILL]) * n))
        return base

    def clobber(self):
        for n in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            self.r[n] = 0xdead_0000 + n

    def call(self, ins, nxt):
        r, role = self.r, self.role[ins.va]
        if role in REAL:
            tgt = PRIM if role == 'prim' else nxt + ins.b
            if tgt not in self.starts:
                raise Fault(f'{ins.va:#x}: real call target {tgt:#x} is outside the copy set')
            r[4] -= 8
            self.store(r[4], nxt.to_bytes(8, 'little'))
            return tgt
        fn = self.fn_at(ins.va)
        try:
            ev, ret = self.stub(role, r, fn.kind)
        except (IndexError, TypeError, ValueError, KeyError, struct.error) as e:
            raise Fault(f'callee contract violated by {role}: {e}')
        self.events.append(ev)
        if role in UNWINDS:
            raise Stop(f'unwind:{role}:{fn.kind}')
        if role in ('terminate', 'resume'):
            raise Fault(f'{role} reached without an unwind')
        self.clobber()
        if ret is not None:
            r[0] = ret
        return None

    def stub(self, role, r, kind):
        if role == 'alloc':
            self.nalloc += 1
            if self.case.get('fail_alloc') == self.nalloc - 1:
                return ('alloc', r[7]), 0
            return ('alloc', r[7]), self.new_block(r[7])
        if role == 'alloc_error':
            return ('alloc_error', r[7] & 0xffffffff, r[6]), None
        if role in ('panic_add', 'panic_sub'):
            return ('panic', role), None
        if role == 'grow':
            cap, ptr, n = struct.unpack('<QQQ', self.load(r[7], 24))
            e = ELEM[kind]
            new = max(2 * cap, 4)
            base = self.new_block(new * e)
            self.store(base, self.load(ptr, n * e) if n else b'')
            self.store(r[7], struct.pack('<QQ', new, base))
            return ('grow', cap, n, e), None
        if role == 'free':
            return ('free', r[6]), None
        if role == 'from_utf8':
            raw = self.load(r[6], r[2]) if r[2] else b''
            try:
                raw.decode('utf-8')
                self.store(r[7], struct.pack('<QQQ', 0, r[6], r[2]))
            except UnicodeDecodeError as e:
                self.store(r[7], struct.pack('<QQQ', 1, e.start, 0x0101))
            return ('utf8', r[2]), None
        if role in ('drop_content', 'drop_elem'):
            return ('drop', self.tree(r[7])), None
        if role in ('drop_entry', 'drop_pair'):
            return ('drop2', self.tree(r[7]), self.tree(r[7] + 32)), None
        if role == 'drop_vec':
            cap, ptr, n = struct.unpack('<QQQ', self.load(r[7], 24))
            return ('drop_vec', cap, n), None
        if role in ('drop_result', 'drop_ext'):
            return (role, self.load(r[7], 1)[0]), None
        raise Fault(f'no stub for {role}')

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
        for base, buf in [(OUT_BASE, self.out), (DES_BASE, self.des), (ACC_BASE, self.acc), (IN_BASE, self.inp),
                          (STACK_TOP - len(self.stack), self.stack)] + self.heap:
            if base <= a <= base + len(buf):
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
            return self.get(ins.a, 64, nxt)
        elif op == 'ret':
            if self.r[4] == STACK_TOP - 8:
                return 'ret'
            ret = int.from_bytes(self.load(self.r[4], 8), 'little')
            self.r[4] += 8
            return ret
        elif op in ('call', 'callr'):
            return self.call(ins, nxt)
        elif op == 'xload':
            self.x[ins.a] = self.load(self.addr(ins.b, nxt), 16) if ins.b[0] == 'm' else self.x[ins.b[1]]
        elif op == 'xstore':
            if ins.a[0] != 'm':
                raise Fault('register-to-register xmm move not modelled')
            self.store(self.addr(ins.a, nxt), self.x[ins.b])
        elif op == 'ud2':
            raise Stop('ud2')
        elif op == 'nop':
            pass
        else:
            raise Fault(f'no semantics for {op} at {ins.va:#x}')
        return None



# reconstruction ------------------------------------------------------------------
VARIANTS = ('depth_off_by_one', 'depth_never_restored', 'depth_restored_on_err', 'ext_err_no_restore', 'depth_zero_is_err',
            'map_cap_unclamped', 'seq_clamp_is_map', 'grow_one_early', 'grow_adds_four',
            'cleanup_reverse', 'no_free_on_err', 'no_drop_key_on_value_err', 'cleanup_skips_values',
            'ext_tag_unsigned', 'ext_no_newtype', 'ext_len_is_u16', 'fixext_len_double', 'ext_data_len_plus_one',
            'bin_is_str', 'bad_utf8_is_str', 'str_eof_advances', 'prim_i8_unsigned', 'prim_eof_no_advance',
            'map16_is_seq', 'peek_data_ignored', 'swap_key_value', 'map_alloc_elem_32', 'free_on_ok',
            'newtype_alloc_64')
NUM = {0xca: (4, 'f32'), 0xcb: (8, 'f64'), 0xcc: (1, 'u8'), 0xcd: (2, 'u16'), 0xce: (4, 'u32'), 0xcf: (8, 'u64'),
       0xd0: (1, 'i8'), 0xd1: (2, 'i16'), 0xd2: (4, 'i32'), 0xd3: (8, 'i64')}


def be(buf, pos, n):
    return int.from_bytes(buf[pos:pos + n], 'big')


class Err(Exception):
    """A Result::Err; `fields` maps out-buffer offsets to the bytes the original defines there."""

    def __init__(self, fields):
        super().__init__()
        self.fields = fields


class Unwound(Exception):
    def __init__(self, role, kind):
        super().__init__(role, kind)
        self.role, self.kind = role, kind


def err_fields(tag, **extra):
    f = {0: (8, 1), 8: (1, tag)}
    f.update({int(k[1:], 16): v for k, v in extra.items()})
    return f


class FlowModel:
    """Pure recursive reconstruction of the value reader + collectors + ext visitor of one copy set."""

    def __init__(self, c, eof_vr, eof_ext, variant=None):
        self.c, self.v = c, variant
        self.buf, self.pos, self.depth = c['buf'], 0, c['depth']
        self.peek = c['peek']
        self.data0 = 0x77 if c['peek'] is None else c['peek'][1]
        self.eof_vr, self.eof_ext = eof_vr, eof_ext
        self.ev, self.nalloc = [], 0

    @property
    def rem(self):
        return len(self.buf) - self.pos

    def state(self):
        return (self.pos, self.rem, NO_PEEK, 0 if self.v == 'peek_data_ignored' else self.data0, self.depth)

    def run(self):
        try:
            val = ('ok', self.value())
            if self.v == 'free_on_ok':
                self.ev.append(('free', 0))
            return ('ret', val, tuple(self.ev), self.state())
        except Err as e:
            return ('ret', ('err', e.fields), tuple(self.ev), self.state())
        except Unwound as u:
            return (f'unwind:{u.role}:{u.kind}', tuple(self.ev))

    # services --------------------------------------------------------------------
    def alloc(self, size, kind):
        self.nalloc += 1
        self.ev.append(('alloc', size))
        if self.c.get('fail_alloc') == self.nalloc - 1:
            self.ev.append(('alloc_error', 8, size))
            raise Unwound('alloc_error', kind)

    def enter(self):
        if self.depth == 0 and self.v != 'depth_zero_is_err':
            self.ev.append(('panic', 'panic_sub'))
            raise Unwound('panic_sub', 'vr')
        self.depth = (self.depth - (2 if self.v == 'depth_off_by_one' else 1)) & 0xffff
        if self.depth == 0:
            raise Err(err_fields(8))

    def leave(self):
        if self.depth == 0xffff:
            self.ev.append(('panic', 'panic_add'))
            raise Unwound('panic_add', 'vr')
        self.depth += 1

    # the value reader ---------------------------------------------------------------
    def value(self):
        if self.peek is not None:
            flag, data = self.peek
            self.peek = None
            return self.dispatch(flag, data)
        if self.rem == 0:
            raise Err(err_fields(0, x10=(8, self.eof_vr)))
        b = self.buf[self.pos]
        self.pos += 1
        if b < 0x80:
            return ('u8', b)
        if b >= 0xe0:
            return ('i8', b)
        if b < 0x90:
            return self.collect('map', b & 0xf)
        if b < 0xa0:
            return self.collect('seq', b & 0xf)
        if b < 0xc0:
            return self.string(b & 0x1f)
        return self.dispatch(b, b & 0x1f)

    def dispatch(self, disc, dl):
        v = self.v
        if disc == 0:
            return ('u8', dl)
        if disc == 0xe0:
            return ('i8', dl)
        if disc == 0xc0:
            return ('unit',)
        if disc in (0xc2, 0xc3):
            return ('bool', disc - 0xc2)
        if disc in NUM:
            return self.number(disc)
        if disc == 0x80:
            return self.collect('map', dl)
        if disc == 0x90:
            return self.collect('seq', dl)
        if disc == 0xa0:
            return self.string(dl)
        if disc == 0xc1:
            raise Err(err_fields(2, x9=(1, 0xc1)))
        if disc in (0xc4, 0xc5, 0xc6):
            return self.binary(self.length({0xc4: 1, 0xc5: 2, 0xc6: 4}[disc]))
        if disc in (0xd9, 0xda, 0xdb):
            return self.string(self.length({0xd9: 1, 0xda: 2, 0xdb: 4}[disc]))
        if disc in (0xdc, 0xdd):
            return self.collect('seq', self.length({0xdc: 2, 0xdd: 4}[disc]))
        if disc in (0xde, 0xdf):
            return self.collect('seq' if v == 'map16_is_seq' else 'map', self.length({0xde: 2, 0xdf: 4}[disc]))
        if disc in (0xc7, 0xc8, 0xc9):
            return self.ext(self.length({0xc7: 1, 0xc8: 2, 0xc9: 4}[disc], ext=(disc, dl)))
        if 0xd4 <= disc <= 0xd8:
            return self.ext(2 * (1 << (disc - 0xd4)) if v == 'fixext_len_double' else 1 << (disc - 0xd4))
        raise KeyError(disc)

    def length(self, size, ext=None):
        if self.rem < size:
            left = self.rem
            if size > 1:
                self.pos += self.rem
            if ext is not None:
                raise Err(err_fields(1, x9=(1, ext[0]), xa=(1, ext[1] if size == 1 else left & 0xff),
                                     x10=(8, self.eof_vr)))
            raise Err(err_fields(1, x10=(8, self.eof_vr)))
        if self.v == 'ext_len_is_u16' and size == 4:
            size = 2
        n = be(self.buf, self.pos, size)
        self.pos += size
        return n

    def number(self, disc):
        n, name = NUM[disc]
        if self.rem < n:
            if n > 1 and self.v != 'prim_eof_no_advance':
                self.pos += self.rem
            raise Err(err_fields(1, x10=(8, EOF_PRIM)))
        raw = be(self.buf, self.pos, n)
        self.pos += n
        if self.v == 'prim_i8_unsigned' and disc == 0xd0:
            name = 'u8'
        return (name, raw)

    def string(self, n):
        if n > self.rem:
            if self.v == 'str_eof_advances':
                self.pos += self.rem
            raise Err(err_fields(1, x10=(8, EOF_SHORT)))
        raw = bytes(self.buf[self.pos:self.pos + n])
        self.pos += n
        self.ev.append(('utf8', n))
        try:
            raw.decode('utf-8')
            return ('str', raw)
        except UnicodeDecodeError:
            return ('str' if self.v == 'bad_utf8_is_str' else 'bytes', raw)

    def binary(self, n):
        if n > self.rem:
            raise Err(err_fields(1, x10=(8, EOF_SHORT)))
        raw = bytes(self.buf[self.pos:self.pos + n])
        self.pos += n
        return ('str' if self.v == 'bin_is_str' else 'bytes', raw)

    # collectors ------------------------------------------------------------------------
    def collect(self, kind, n):
        self.enter()
        try:
            res = self.visit(kind, n)
        except Err:
            if self.v == 'depth_restored_on_err':
                self.depth += 1
            raise
        if self.v != 'depth_never_restored':
            self.leave()
        return res

    def visit(self, kind, left):
        v = self.v
        E = 32 if kind == 'seq' or v == 'map_alloc_elem_32' else 64
        items, cap = [], 0
        if left:
            clamp = CLAMP['map'] if v == 'seq_clamp_is_map' else CLAMP[kind]
            cap = min(left, clamp * (4 if v == 'map_cap_unclamped' else 1))
            self.alloc(cap * E, kind)
            n = left - 1
            while True:
                try:
                    if kind == 'map':
                        k = self.value()
                        try:
                            val = self.value()
                        except Err:
                            if v != 'no_drop_key_on_value_err':
                                self.ev.append(('drop', k))
                            raise
                        item = (val, k) if v == 'swap_key_value' else (k, val)
                    else:
                        item = self.value()
                except Err:
                    self.cleanup(kind, items, cap, E)
                    raise
                if len(items) == cap or (v == 'grow_one_early' and len(items) + 1 == cap):
                    self.ev.append(('grow', cap, len(items), E))
                    cap = max(2 * cap, 4) if v != 'grow_adds_four' else cap + 4
                items.append(item)
                if n == 0:
                    break
                n -= 1
        return (kind, cap, tuple(items))

    def cleanup(self, kind, items, cap, E):
        seq = list(items)
        if self.v == 'cleanup_reverse':
            seq.reverse()
        for it in seq:
            if kind == 'map':
                self.ev.append(('drop', it[0]))
                if self.v != 'cleanup_skips_values':
                    self.ev.append(('drop', it[1]))
            else:
                self.ev.append(('drop', it))
        if cap and self.v != 'no_free_on_err':
            self.ev.append(('free', cap * E))

    def ext(self, n):
        self.enter()
        try:
            seq = self.visit_ext(n)
        except Err:
            if self.v != 'ext_err_no_restore':
                self.leave()
            raise
        self.alloc(64 if self.v == 'newtype_alloc_64' else 32, 'vr')
        if self.v != 'depth_never_restored':
            self.leave()
        return seq if self.v == 'ext_no_newtype' else ('newtype', seq)

    def visit_ext(self, n):
        """`{tag: i8, data: bytes}` as a two-element Content::Seq; the first push grows the empty vector."""
        if self.rem == 0:
            raise Err(err_fields(1, x10=(8, self.eof_ext), x18=(8, n)))
        b = self.buf[self.pos]
        self.pos += 1
        self.ev.append(('grow', 0, 0, 32))
        tag = ('u8' if self.v == 'ext_tag_unsigned' else 'i8', b)
        if n + (1 if self.v == 'ext_data_len_plus_one' else 0) > self.rem:
            self.ev.append(('drop', tag))
            if self.v != 'no_free_on_err':
                self.ev.append(('free', 4 * 32))
            raise Err(err_fields(1, x9=(1, b), x10=(8, EOF_SHORT), x18=(8, n)))
        data = bytes(self.buf[self.pos:self.pos + n])
        self.pos += n
        return ('seq', 4, (tag, ('bytes', data)))


def reconstructed(case, eofs, variant=None):
    return FlowModel(case, eofs[0], eofs[1], variant).run()


def same(got, want):
    """Machine result vs model result; error payloads are compared on the bytes the original defines."""
    if got[0] != 'ret' or want[0] != 'ret':
        return got == want
    if got[2:] != want[2:]:
        return False
    if got[1][0] != want[1][0]:
        return False
    if got[1][0] == 'ok':
        return got[1][1] == want[1][1]
    out = b'\x01\0\0\0\0\0\0\0' + got[1][1]
    return all(int.from_bytes(out[o:o + n], 'little') == val for o, (n, val) in want[1][1].items())


# cases ---------------------------------------------------------------------------
MASK = (1 << 64) - 1


class Rng:
    """xorshift64 so the documents are the same on every Python version."""

    def __init__(self, seed):
        self.s = (seed * 0x9E3779B97F4A7C15 + 1) & MASK

    def next(self):
        s = self.s
        s ^= (s << 13) & MASK
        s ^= s >> 7
        s ^= (s << 17) & MASK
        self.s = s
        return s

    def below(self, n):
        return self.next() % n


def doc_value(rng, depth):
    """One MessagePack value; containers nest until `depth` runs out."""
    k = rng.below(30 if depth else 21)
    if k == 0:
        return bytes([rng.below(0x80)])
    if k == 1:
        return bytes([0xe0 + rng.below(0x20)])
    if k == 2:
        return bytes([0xc0])
    if k == 3:
        return bytes([0xc2 + rng.below(2)])
    if k < 8:
        n = (1, 2, 4, 8)[k - 4]
        return bytes([(0xcc, 0xcd, 0xce, 0xcf)[k - 4]]) + rng.next().to_bytes(8, 'big')[:n]
    if k < 12:
        n = (1, 2, 4, 8)[k - 8]
        return bytes([(0xd0, 0xd1, 0xd2, 0xd3)[k - 8]]) + rng.next().to_bytes(8, 'big')[:n]
    if k == 12:
        return b'\xca' + rng.next().to_bytes(8, 'big')[:4]
    if k == 13:
        return b'\xcb' + rng.next().to_bytes(8, 'big')
    if k == 14:
        n = rng.below(6)
        return bytes([0xa0 + n]) + bytes(97 + (rng.below(26)) for _ in range(n))
    if k == 15:
        n = rng.below(5)
        return b'\xd9' + bytes([n]) + b'xyzwv'[:n]
    if k == 16:
        return b'\xa3\xff\xfe\x41' if rng.below(2) else b'\xc4\x03\x01\x02\x03'
    if k == 17:
        n = rng.below(4)
        return bytes([0xc5, 0, n]) + bytes(rng.below(256) for _ in range(n))
    if k == 18:
        sz = rng.below(5)
        return bytes([0xd4 + sz, rng.below(256)]) + bytes(rng.below(256) for _ in range(1 << sz))
    if k == 19:
        n = rng.below(4)
        return bytes([0xc7, n, rng.below(256)]) + bytes(rng.below(256) for _ in range(n))
    if k == 20:
        return b'\xc8\x00\x02\xfe\x09\x08'
    n = rng.below(4)
    form = rng.below(3)
    if k < 25:
        head = (bytes([0x90 + n]), b'\xdc' + n.to_bytes(2, 'big'), b'\xdd' + n.to_bytes(4, 'big'))[form]
        return head + b''.join(doc_value(rng, depth - 1) for _ in range(n))
    head = (bytes([0x80 + n]), b'\xde' + n.to_bytes(2, 'big'), b'\xdf' + n.to_bytes(4, 'big'))[form]
    return head + b''.join(doc_value(rng, 0) if rng.below(3) else doc_value(rng, depth - 1)
                           for _ in range(2 * n))


DOCS = tuple(doc_value(Rng(i), 3) for i in range(1, 161))
DOC_DIGEST = 'a3dd60e807d1eec169826fb39b8a0ccc22099bba024425d7add6aaf13b770bb5'   # sha256 of the concatenated documents
TAILS = (b'', b'\x01', b'\x03abc', b'\x92\x01\x02', b'\x81\xa1k\x91\xc3', b'\x82\x01\x02\x03', b'\xa5he',
         b'\x91\x91\x91\x91\x91\x01', b'\xc7\x02\x07ab', b'\xdc\x00\x03\x01\x02', b'\xde\x00\x01\xa1a\xc0')
DEPTHS = (0x400, 1, 2, 4, 0, 0xffff, 8)
PEEK_FLAGS = (0, 0x80, 0x90, 0xa0, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
              0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde,
              0xdf, 0xe0)


def case(buf, peek=None, depth=0x400, **kw):
    c = {'buf': bytes(buf), 'peek': peek, 'depth': depth}
    c.update(kw)
    return c


def cases(copy):
    """Deterministic inputs: markers, peeked classes, nested documents with every cut, budgets, failing allocs."""
    k = 0
    for b in range(256):
        for j in range(0, len(TAILS), 2 if b % 2 else 1):
            k += 1
            yield case(bytes([b]) + TAILS[(j + copy) % len(TAILS)], None, DEPTHS[(k + b) % len(DEPTHS)])
    for flag in PEEK_FLAGS:
        for d in (0, 1, 0x1f, 0x80, 0xff):
            for t in TAILS[:6:2]:
                k += 1
                yield case(t, (flag, d), DEPTHS[(k + flag) % len(DEPTHS)])
    for di, doc in enumerate(DOCS):
        cuts = range(len(doc)) if len(doc) <= 40 else range(0, len(doc), 1 + len(doc) // 40)
        yield case(doc)
        for p in cuts:
            yield case(doc[:p])
        for dep in (1, 2, 3, 4, 5, 0):
            yield case(doc, None, dep)
        for fa in range(4):
            yield case(doc, None, 0x400, fail_alloc=fa)
        yield case(doc + TAILS[di % len(TAILS)])
    for first in (0x91, 0x81, 0xd4, 0xc7, 0xdc, 0xde, 0xdd, 0xdf, 0xc8, 0xc9, 0xd8):
        for dep in (0, 1, 2, 3, 0xfffe, 0xffff):
            yield case(bytes([first]) + b'\x00\x01\x02\x03\x04\x05\x06', None, dep)
    for first in (b'\xdd\xff\xff\xff\xff', b'\xdf\xff\xff\xff\xff', b'\xdd\x00\x00\x80\x01', b'\xdf\x00\x00\x40\x01',
                  b'\xdd\x00\x01\x00\x00', b'\xc9\xff\xff\xff\xff\x07', b'\xdb\xff\xff\xff\xff', b'\xc6\x80\x00\x00\x00'):
        for tail in (b'', b'\x01\x02', b'\xa1a\x02'):
            yield case(first + tail)
            yield case(first + tail, None, 3, fail_alloc=0)
    yield case(b'\xdd\x00\x00\x80\x01' + b'\x07' * 0x8001, None, 3)      # one past the seq clamp: grow at 0x8000
    yield case(b'\xdf\x00\x00\x40\x01' + b'\x01\x02' * 0x4001, None, 3)  # one past the map clamp: grow at 0x4000


def doc_text(tree):
    return repr(tree).replace('\t', ' ')


def hx(v):
    return v if isinstance(v, str) else '%#x' % v


def case_row(c):
    return [c['buf'][:48].hex() + ('+%d' % (len(c['buf']) - 48) if len(c['buf']) > 48 else '') or '-',
            '-' if c['peek'] is None else '%x:%x' % c['peek'], '%x' % c['depth'],
            str(c.get('fail_alloc', '-'))]


def run_case(m, c, eofs, variant=None):
    try:
        got = m.run(c)
    except (Fault, Stop, IndexError, ValueError, MemoryError, struct.error, OverflowError) as e:
        got = ('fault', str(e))
    try:
        want = reconstructed(c, eofs, variant)
    except (IndexError, KeyError, ValueError, struct.error, OverflowError, TypeError):
        want = ('model_fault',)
    return got, want


def events_text(ev):
    return ';'.join(','.join(hx(x) if isinstance(x, int) else (doc_text(x) if isinstance(x, tuple) else str(x))
                             for x in e) for e in ev) or '-'


class Patched(Image):
    def __init__(self, img, data):
        self.__dict__.update(img.__dict__)
        self.data = data


def mutate(img, kind, off, xor):
    data = bytearray(img.data)
    data[img.off(SETS[0][kind] + off)] ^= xor
    return Patched(img, bytes(data))


def patched_fns(m_img, fns, kind):
    f = fns[kind]
    fm = Fn.__new__(Fn)
    fm.__dict__.update(f.__dict__)
    fm.insns = sweep(m_img, f.start, f.end)
    fm.cache = {x.va: x for x in fm.insns}
    out = dict(fns)
    out[kind] = fm
    return out


def run_mutant(img, fns, prim, kind, off, sample, eofs):
    """Flip one conditional-jump condition in the anchor copy and report whether any case differs."""
    m_img = mutate(img, kind, off, 1)
    try:
        m = Machine(m_img, patched_fns(m_img, fns, kind), prim)
        for c in sample:
            got, want = run_case(m, c, eofs)
            if not same(got, want):
                return 1
        return 0
    except (Fault, Stop, IndexError, KeyError, ValueError):
        return 1


def jcc_offsets(fns, kind):
    f = fns[kind]
    return [i.va - f.start + (1 if i.raw[0] == 0x0f else 0) for i in f.insns if i.op == 'j']


# Conditional-jump condition bits (xor 1 at the opcode byte) of the set-0 copies; a first full run
# proved that every listed flip changes at least one result of the sample.
IMAGE_MUTANTS = (
    ('vr', (26, 35, 60, 81, 85, 98, 117, 186, 216, 258, 271, 343, 384, 444, 457, 529, 582, 617, 666, 715, 781, 819, 851,
            904, 950, 997, 1030, 1080, 1151, 1217, 1337, 1410, 1497, 1548, 1561, 1606, 1643, 1696, 1806)),
    ('map', (47, 72, 203, 278, 288, 352, 500, 596, 919, 955)),
    ('seq', (42, 70, 158, 211, 218, 256, 484, 511)),
    ('ext', (60, 245, 253, 263, 276, 344, 438, 548, 575)),
)   # the other flips (vr +0x188 +0x440, map +0x463 +0x47e, seq +0x243 +0x25e, ext +0x293 +0x2ae) guard the
#     count-difference panic and the Vec-overflow checks, which the real children never reach


def range_controls(img, sets, prim, eofs):
    """Corrupted digest, wrong boundaries, mixed copy sets and out-of-range inputs; each must be rejected."""
    res = []
    bad = bytearray(img.data)
    bad[len(bad) // 2] ^= 1
    try:
        Image(bytes(bad))
        res.append(('digest_flip', False))
    except ValueError:
        res.append(('digest_flip', True))
    for name, thunk in (
            ('start_not_fde', lambda: Fn(img, 'vr', SETS[0]['vr'] + 1)),
            ('wrong_size_kind', lambda: Fn(img, 'seq', SETS[0]['map'])),
            ('wrong_anchor', lambda: Fn(img, 'ext', SETS[1]['ext'], sets[0]['vr'])),
            ('mixed_sets_map', lambda: Machine(img, dict(sets[0], map=sets[1]['map']), prim)),
            ('mixed_sets_vr', lambda: Machine(img, dict(sets[1], vr=sets[2]['vr']), prim)),
            ('sweep_overrun', lambda: sweep(img, sets[0]['vr'].start, sets[0]['vr'].end - 3)),
            ('unmapped_read', lambda: img.read(0x7fff_0000_0000, 4)),
            ('prim_wrong_extent', lambda: sweep(img, PRIM, PRIM + PRIM_SIZE - 2)),
    ):
        try:
            thunk()
            res.append((name, False))
        except (Fault, ValueError):
            res.append((name, True))
    m = Machine(img, sets[0], prim)
    try:
        got = m.run(case(b'', (0xe1, 0), 5))   # disc past the 225-entry table
        res.append(('disc_past_table', got[0] != 'ret'))
    except (Fault, Stop, IndexError, ValueError):
        res.append(('disc_past_table', True))
    got = m.run(case(b'\xdd\xff\xff\xff\xff', None, 5))   # count far past the data: clamped, then EOF
    res.append(('count_past_input', got[0] == 'ret' and got[1][0] == 'err' and got[2][0] == ('alloc', 0x100000)))
    got = m.run(case(b'\x91', None, 0))                    # budget already spent: a panic, not an error value
    res.append(('depth_zero_panics', got[0] == 'unwind:panic_sub:vr'))
    return res


def generate(out_dir, data=None, rows_every=None):
    data = data if data is not None else Path(BINARY).read_bytes()
    img = Image(data)
    sets = load_sets(img)
    prim = Prim(img)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    tsv = {n: [] for n in ('functions', 'call_graph', 'lsda', 'tables', 'coverage', 'cases', 'mutants')}
    tsv['functions'].append('set\tkind\tstart\tsize\tlsda\tinsns\tcalls\tframe\teof_constant')
    tsv['call_graph'].append('set\tcaller\toffset\trole\tcallee\tcallee_start\tin_lsda\tlanding_pad\taction')
    tsv['lsda'].append('set\tkind\tstart\tend\tlanding_pad\taction')
    tsv['tables'].append('set\ttable\tindex\tarm_offset')
    tsv['coverage'].append('kind\toffset\top\tsize\tcovered\tedges')
    tsv['cases'].append('set\tindex\tbuf\tpeek\tdepth\tfail_alloc\toutcome\tresult\tevents\tstate')
    tsv['mutants'].append('kind\tcontrol\tdetected')
    total, mismatches, outcomes, controls = 0, 0, {}, []
    hit, edges = set(), set()
    eofs_of = []
    for si, fns in enumerate(sets):
        eofs_of.append((fns['vr'].eof, fns['ext'].eof))
        for kind, fn in fns.items():
            calls = sum(1 for i in fn.insns if i.op in ('call', 'callr'))
            tsv['functions'].append('\t'.join(map(str, (si, kind, hx(fn.start), KINDS[kind]['size'], hx(fn.lsda),
                                                        len(fn.insns), calls, hx(KINDS[kind]['frame']),
                                                        hx(fn.eof) if fn.eof else '-'))))
            for s, e, lp, a in fn.sites:
                tsv['lsda'].append('%d\t%s\t%s\t%s\t%s\t%s' % (si, kind, hx(s - fn.start), hx(e - fn.start),
                                                                hx(lp - fn.start) if lp else '-', a))
            for name, idx, arm in fn.table_rows(img):
                tsv['tables'].append('%d\t%s\t%d\t%s' % (si, name, idx, hx(arm)))
        for caller, off, role, callee, tgt in closure_rows(img, fns):
            fn = fns[caller]
            site = fn.site_of(fn.start + off)
            tsv['call_graph'].append('%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s' % (
                si, caller, hx(off), role, callee, hx(tgt), int(site is not None),
                hx(site[0] - fn.start) if site and site[0] else '-', site[1] if site else '-'))
    every = rows_every or 8
    for si, fns in enumerate(sets):
        m = Machine(img, fns, prim)
        for idx, c in enumerate(cases(si)):
            got, want = run_case(m, c, eofs_of[si])
            total += 1
            if not same(got, want):
                mismatches += 1
            key = got[0] if got[0] != 'ret' else got[1][0]
            outcomes[key] = outcomes.get(key, 0) + 1
            if si == 0:
                hit |= m.trace
                edges |= m.edges
            if idx % every == si:
                res = got[1] if got[0] == 'ret' else got
                tsv['cases'].append('\t'.join([str(si), str(idx)] + case_row(c) + [
                    key, (doc_text(res[1]) if res[0] == 'ok' else res[1].hex()[:64]) if got[0] == 'ret' else '-',
                    events_text(got[2] if got[0] == 'ret' else got[1])[:200],
                    ','.join(hx(x) for x in got[3]) if got[0] == 'ret' else '-']))
    anchor = sets[0]
    for kind, fn in list(anchor.items()) + [('prim', prim)]:
        for i in fn.insns:
            e = ''
            if i.op == 'j':
                e = ('T' if (i.va, True) in edges else '') + ('N' if (i.va, False) in edges else '')
            tsv['coverage'].append('%s\t%s\t%s\t%d\t%d\t%s' % (kind, hx(i.va - fn.start), i.op, i.size,
                                                               int(i.va in hit), e or '-'))
    # negative controls: wrong models, corrupted images, out-of-range inputs
    allc = list(cases(0))
    sample = [c for j, c in enumerate(allc) if j % 4 == 0] + allc[-2:]   # + the two clamp-overflow cases
    del allc
    m0 = Machine(img, sets[0], prim)
    ran = [(c, run_case(m0, c, eofs_of[0])[0]) for c in sample]
    for v in VARIANTS:
        det = False
        for c, got in ran:
            try:
                want = reconstructed(c, eofs_of[0], v)
            except (IndexError, KeyError, ValueError, struct.error, OverflowError, TypeError):
                want = ('model_fault',)
            if not same(got, want):
                det = True
                break
        controls.append(('model', v, det))
    msample = [c for j, c in enumerate(cases(0)) if j % 9 == 0][:1500]
    for kind, offs in IMAGE_MUTANTS:
        for off in offs:
            controls.append((kind, 'image:+%#x' % off, bool(run_mutant(img, sets[0], prim, kind, off, msample,
                                                                       eofs_of[0]))))
    for name, ok in range_controls(img, sets, prim, eofs_of[0]):
        controls.append(('range', name, ok))
    for kind, name, ok in controls:
        tsv['mutants'].append('%s\t%s\t%d' % (kind, name, int(ok)))
    for name, rows in tsv.items():
        (out / f'{name}.tsv').write_text('\n'.join(rows) + '\n')
    cov = {kind: (sum(1 for i in fn.insns if i.va in hit), len(fn.insns))
           for kind, fn in list(anchor.items()) + [('prim', prim)]}
    summary = {'sha256': SHA256, 'cases': total, 'mismatches': mismatches, 'negative_controls': len(controls),
               'negative_detected': sum(1 for c in controls if c[2]),
               'outcomes': dict(sorted(outcomes.items())),
               'instructions_covered': {k: f'{a}/{b}' for k, (a, b) in cov.items()},
               'case_rows': len(tsv['cases']) - 1}
    (out / 'summary.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
    measure = {'cases': total, 'negative_controls': len(controls),
               'negative_detected': summary['negative_detected'], 'mismatches': mismatches}
    (out / 'measure.json').write_text(json.dumps(measure, indent=1, sort_keys=True) + '\n')
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    s = generate(a.out)
    print(json.dumps(s, sort_keys=True))
    return 0 if s['mismatches'] == 0 and s['negative_controls'] == s['negative_detected'] else 1


if __name__ == '__main__':
    sys.exit(main())
