#!/usr/bin/env python3
"""Reconstruct the node #115 MessagePack value-level `deserialize_any` and prove it.

The action envelope (call at 0x2bd6198) decodes a value through rmp_serde's
`deserialize_any`, compiled into three 2264-byte copies in node #115
(0x1b38990, 0x32a6050, 0x491de60). Unlike the 1769-byte identifier decoder,
each copy returns a 48-byte `Result<T, rmp_serde::decode::Error>` (T is 40
bytes), takes the visitor by pointer (32 bytes, copied to the stack for the
str/bin/ext arms) and a `bool` in cl. It reads one MessagePack marker (or
reuses the peeked one) and routes it:
nil/bool/int/float -> one shared `any` helper; 0xc1 -> TypeMismatch;
fixstr/str8/16/32 -> UTF-8 check -> visit_str, or visit_bytes and a Utf8 error
when the visitor fails; bin8/16/32 -> visit_bytes (cl set) or a byte-sequence
visitor; map/array -> depth-checked visit_map/visit_seq, then a remaining-count
check (LengthMismatch carries the consumed count and drops the value);
ext -> depth-checked ext visitor. This tool:

1. checks the input digest, finds each copy's FDE extent, decodes every
   instruction with a fixed-pattern x86-64 subset decoder and proves the three
   copies are the same shape (only rel32/disp32 fields differ);
2. reads both jump tables (marker tag -> arm, ext tag -> arm) from the bytes;
3. interprets the original bytes of all three copies (the binary is never run;
   callees are contract stubs) over thousands of inputs built from the tables;
4. compares every outcome with a pure reconstruction (`reconstructed_any`):
   result, callee call sequence and arguments, and the deserializer state after
   the call (input position, peek slot, depth);
5. proves instruction coverage up to a named residue (LSDA landing pads, ud2)
   and that wrong reconstructions and corrupted images are rejected.
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
FUNC_SIZE = 2264

COPIES = (
    ('C1', 0x1b38990),
    ('C2', 0x32a6050),
    ('C3', 0x491de60),
)
# Direct call targets in order of first appearance; role names are inferences
# from argument shapes (see README).
ROLES = ('visit_map', 'drop_value', 'visit_seq', 'bytes_seq', 'visit_ext', 'visit_bytes', 'drop_error',
         'visit_str', 'drop_visitor', '_Unwind_Resume')
# GOT slots called through `call *slot(%rip)`; R_X86_64_RELATIVE targets are checked.
SLOTS = {
    0x64e4198: ('any', None),
    0x64dfca8: ('from_utf8', 0x16815e0),
    0x64df520: ('panic_add', 0x1681da0),
    0x64df848: ('panic_sub', 0x1681e40),
    0x64df4c0: ('terminate', 0x1680cab),
}
MARKER_TABLE_LEN = 0xe1   # tags 0x00..0xe0 (Marker niche: 1 = no peeked marker)
EXT_TABLE_LO, EXT_TABLE_LEN = 0xc7, 18
SIMPLE_EOF = 0x2500000003  # io::Error Simple(UnexpectedEof) bit-packed repr
# C1 rodata operands; C2/C3 values are read from the same instruction index.
C1_CONSTS = {'static_eof': 0x641ccb0,  # &'static SimpleMessage stored by the read_exact EOF arms
             'map': 0x641f9f8, 'seq': 0x641f9c8, 'ext': 0x641f9b0,  # depth overflow panic locations
             'map_len': 0x641fa10, 'seq_len': 0x641f9e0}  # consumed-count underflow panic locations

IN_BASE, OUT_BASE, DES_BASE, VIS_BASE = 0x7000_0000_0000, 0x7100_0000_0000, 0x7180_0000_0000, 0x71c0_0000_0000
STACK_TOP = 0x7200_0000_0000
MASK64 = (1 << 64) - 1
STEP_LIMIT = 400
OUT_FILL, STACK_FILL, DES_FILL = 0xaa, 0x5c, 0x3d
VISITOR = hashlib.sha256(b'visitor').digest()  # 32 distinct bytes
OUT_SIZE = 48


def mark(name, knob):
    """48-byte Result a stub writes: Ok = qword 0 + 40 bytes, Err = qword 1 + tag byte + 39 bytes."""
    h = hashlib.sha256(f'{name}:{knob}'.encode()).digest() * 2
    if knob[0] == 'ok':
        return bytes(8) + h[:40]
    return (1).to_bytes(8, 'little') + bytes([knob[1]]) + h[:39]


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
    __slots__ = ('va', 'size', 'op', 'a', 'b', 'w', 'raw', 'rel', 'immlen')


ALU_NAMES = ('add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp')


def decode(img, va):
    """Decode one instruction of the fixed subset used by the decoder copies."""
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
        if reg & 7 != 0 or rm[0] != 'r':
            raise Fault(f'unsupported shift form at {va:#x}')
        ins.op, ins.a, ins.b = 'rol', rm, imm(1)
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
        elif 0xc8 <= op2 <= 0xcf and not W:
            ins.op, ins.a = 'bswap', ('r', (op2 - 0xc8) | B << 3)
        elif op2 == 0x0b:
            ins.op = 'ud2'
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


def shape(ins):
    """Instruction bytes with the rel32/disp32 field zeroed (copies differ only there)."""
    raw = bytearray(ins.raw)
    if ins.rel is not None:
        raw[ins.rel:ins.rel + 4] = bytes(4)
    return bytes(raw)


class Copy:
    """Static facts of one copy, all read from the bytes."""

    def __init__(self, img, label, start):
        self.label, self.start = label, start
        fde = fde_of(img.data, start)
        self.end, self.lsda = fde['end'], fde['lsda']
        if self.end - start != FUNC_SIZE:
            raise Fault(f'{label}: FDE extent is {self.end - start} bytes')
        self.insns = sweep(img, start, self.end)
        self.callees, self.slots = [], []
        for ins in self.insns:
            if ins.op == 'call':
                t = ins.va + ins.size + ins.b
                if t not in self.callees:
                    self.callees.append(t)
            if ins.op == 'callr':
                slot = ins.va + ins.size + ins.a[4]
                if slot not in self.slots:
                    self.slots.append(slot)
        if len(self.callees) != len(ROLES):
            raise Fault(f'{label}: {len(self.callees)} direct callees')
        self.role = dict(zip(self.callees, ROLES))
        self.by_role = dict(zip(ROLES, self.callees))
        if img.plt_symbol(self.by_role['_Unwind_Resume']) != '_Unwind_Resume':
            raise Fault(f'{label}: last callee is not the _Unwind_Resume PLT stub')
        self.slot_targets = {}
        for slot in self.slots:
            want = SLOTS.get(slot)
            got = img.relative.get(slot)
            if want is None or got is None or (want[1] is not None and got != want[1]):
                raise Fault(f'{label}: GOT slot {slot:#x} is not a known RELATIVE target')
            self.slot_targets[slot] = got
        jt = [i for i in self.insns if i.op == 'lea' and i.b[5]]
        tables = [i.va + i.size + i.b[4] for i in jt]
        # The two `lea table(%rip)` + movsxd + add + jmp sequences.
        self.marker_va, self.ext_va = tables[0], tables[1]
        self.marker_arms = img.table(self.marker_va, MARKER_TABLE_LEN)
        self.ext_arms = img.table(self.ext_va, EXT_TABLE_LEN)
        self.sites = img.call_sites(self.lsda, start) if self.lsda else []
        self.pad_lo = min([s[2] for s in self.sites if s[2]] or [self.end])

    def bind_consts(self, base):
        """Rodata operands of this copy at the instruction indices where C1 uses C1_CONSTS."""
        found = {}
        for mine, ref in zip(self.insns, base.insns):
            if ref.op == 'lea' and ref.b[5]:
                rv = ref.va + ref.size + ref.b[4]
                for k, v in C1_CONSTS.items():
                    if rv == v:
                        found.setdefault(k, set()).add(mine.va + mine.size + mine.b[4])
        if sorted(found) != sorted(C1_CONSTS) or any(len(v) != 1 for v in found.values()):
            raise Fault(f'{self.label}: rodata operands do not line up with C1')
        self.consts = {k: v.pop() for k, v in found.items()}


class Machine:
    def __init__(self, img, copy):
        self.img, self.c = img, copy
        self.cache = {i.va: i for i in copy.insns}

    def run(self, case):
        inp, peek, depth, flag, knob = case
        self.inp = bytes(inp)
        self.out = bytearray([OUT_FILL]) * OUT_SIZE
        self.stack = bytearray([STACK_FILL]) * 0x200
        self.vis = bytearray(VISITOR)
        des = bytearray([DES_FILL]) * 0x28
        struct.pack_into('<QQ', des, 0x10, IN_BASE, len(inp))
        des[0x20], des[0x21] = (1, DES_FILL) if peek is None else peek
        struct.pack_into('<H', des, 0x22, depth)
        self.des = des
        self.des0 = bytes(des)
        self.r = [0x1111_0000 + n for n in range(16)]
        self.x = [bytes(16)] * 16
        self.r[7], self.r[6], self.r[2] = OUT_BASE, DES_BASE, VIS_BASE
        self.r[1] = (self.r[1] & ~0xff) | flag
        self.r[4] = STACK_TOP - 8
        self.flags = dict(z=0, c=0, s=0, o=0)
        self.calls, self.trace, self.knob = [], [], knob
        pc = self.c.start
        for _ in range(STEP_LIMIT):
            if not self.c.start <= pc < self.c.end:
                raise Fault(f'left function at {pc:#x}')
            ins = self.cache.get(pc)
            if ins is None:
                raise Fault(f'jump into the middle of an instruction at {pc:#x}')
            self.trace.append(pc)
            nxt = pc + ins.size
            res = self.step(ins, nxt)
            if res == 'ret':
                if self.r[0] != OUT_BASE:
                    raise Fault('rax does not return the out pointer')
                return self.outcome(None)
            if isinstance(res, tuple):
                return self.outcome(res)
            pc = nxt if res is None else res
        raise Fault('step limit')

    def outcome(self, panic):
        des = self.des
        if des[:0x10] != self.des0[:0x10] or des[0x21] != self.des0[0x21] or des[0x24:] != self.des0[0x24:]:
            raise Fault('deserializer bytes outside ptr/len/peek tag/depth changed')
        if bytes(self.vis) != VISITOR:
            raise Fault('caller visitor bytes changed')
        ptr, rem = struct.unpack_from('<QQ', des, 0x10)
        pos = ptr - IN_BASE
        if not 0 <= pos <= len(self.inp) or pos + rem != len(self.inp):
            raise Fault('input cursor is not a suffix of the input')
        state = (pos, des[0x20], struct.unpack_from('<H', des, 0x22)[0])
        return (panic or decode_out(bytes(self.out))), tuple(self.calls), state

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
        for base, buf in ((IN_BASE, self.inp), (OUT_BASE, self.out), (DES_BASE, self.des),
                          (VIS_BASE, self.vis), (STACK_TOP - len(self.stack), self.stack)):
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
        if buf is None or buf is self.inp or buf is self.vis:
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
            self.flags['c'] = c  # inc/dec leave CF unchanged
            self.put(ins.a, w, r, nxt)
        elif op == 'rol':
            v, n = self.get(ins.a, w, nxt), ins.b % w
            r = ((v << n) | (v >> (w - n))) & ((1 << w) - 1)
            self.flags['c'] = r & 1
            self.put(ins.a, w, r, nxt)
        elif op == 'bswap':
            v = self.get(ins.a, 32, nxt)
            self.put(ins.a, 32, int.from_bytes(v.to_bytes(4, 'little'), 'big'), nxt)
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
            if ins.a[0] != 'm':
                raise Fault('register-to-register xmm move not modelled')
            self.store(self.addr(ins.a, nxt), self.x[ins.b])
        elif op == 'ud2':
            raise Fault(f'ud2 reached at {ins.va:#x}')
        else:
            raise Fault(f'no semantics for {op}')
        return None

    def clobber(self):
        for n in (0, 1, 2, 6, 7, 8, 9, 10, 11):
            self.r[n] = 0xdead_0000 + n  # caller-saved registers are clobbered

    def where(self, a):
        """Name a pointer argument: input offset, out, stack temporary, deserializer, visitor."""
        if IN_BASE <= a <= IN_BASE + len(self.inp):
            return a - IN_BASE
        if a == OUT_BASE:
            return 'out'
        if a == DES_BASE:
            return 'des'
        if a == VIS_BASE:
            return 'vis'
        if STACK_TOP - len(self.stack) <= a < STACK_TOP:
            return 'tmp'
        raise Fault(f'unexpected pointer argument {a:#x}')

    def visitor_copy(self, a):
        """A visitor argument is either the caller's visitor or a byte-equal stack copy."""
        w = self.where(a)
        if w == 'vis':
            return 'vis'
        if w == 'tmp' and self.load(a, 32) == VISITOR:
            return 'vis_copy'
        raise Fault('visitor argument is neither the visitor nor a copy of it')

    def call(self, ins, nxt):
        r = self.r
        knob = self.knob
        if ins.op == 'callr':
            slot = self.addr(ins.a, nxt)
            name = SLOTS.get(slot, (None,))[0]
            if name is None or self.c.slot_targets.get(slot) is None:
                raise Fault(f'indirect call through {slot:#x}')
            if name == 'any':
                if (r[7], r[6]) != (OUT_BASE, DES_BASE):
                    raise Fault('any helper is not given (out, deserializer)')
                rec = ('any', self.visitor_copy(r[2]), r[1] & 0xff, r[8] & 0xff)
                self.store(OUT_BASE, mark('any', knob[0]))
            elif name == 'from_utf8':
                at, n = self.where(r[6]), r[2]
                rec = ('from_utf8', at, n)
                res = utf8_result(self.inp[at:at + n])
                if res is None:
                    self.store(r[7], struct.pack('<QQQ', 0, r[6], n))
                else:
                    self.store(r[7], struct.pack('<QQBB6x', 1, res[0], res[1] is not None, res[1] or 0))
            elif name in ('panic_add', 'panic_sub'):
                return (name, r[7])
            else:
                raise Fault(f'{name} called on a normal path')
            self.calls.append(rec)
            self.clobber()
            return None
        target = nxt + ins.b
        role = self.c.role.get(target)
        if role in ('visit_map', 'visit_seq'):
            if self.where(r[7]) != 'tmp':
                raise Fault(f'{role} result is not a stack temporary')
            des, n = struct.unpack('<QI', self.load(r[2], 12))
            if des != DES_BASE:
                raise Fault(f'{role} access does not carry the deserializer')
            self.calls.append((role, self.visitor_copy(r[6]), n))
            self.store(r[7], mark(role, knob[0]))
            if knob[1] is not None:
                self.store(r[2] + 8, struct.pack('<I', knob[1]))
            if knob[2] is not None:
                struct.pack_into('<H', self.des, 0x22, knob[2])
        elif role == 'visit_ext':
            if self.where(r[7]) != 'tmp':
                raise Fault('ext result is not a stack temporary')
            des, n, tail = struct.unpack('<QIB', self.load(r[2], 13))
            if des != DES_BASE:
                raise Fault('ext visitor is not given the deserializer')
            self.calls.append(('visit_ext', self.visitor_copy(r[6]), n, tail))
            self.store(r[7], mark('visit_ext', knob[0]))
            if knob[2] is not None:
                struct.pack_into('<H', self.des, 0x22, knob[2])
        elif role == 'bytes_seq':
            if r[7] != OUT_BASE:
                raise Fault('bytes_seq result is not out')
            a, e, k = struct.unpack('<QQQ', self.load(r[2], 24))
            self.calls.append(('bytes_seq', self.visitor_copy(r[6]), self.where(a), self.where(e), k))
            self.store(OUT_BASE, mark('bytes_seq', knob[0]))
        elif role in ('visit_bytes', 'visit_str'):
            dst = self.where(r[7])
            self.calls.append((role, dst, self.visitor_copy(r[6]), self.where(r[2]), r[1]))
            self.store(r[7], mark(role, knob[0]))
        elif role in ('drop_error', 'drop_value'):
            if self.where(r[7]) != 'tmp':
                raise Fault(f'{role} is not given a stack temporary')
            self.calls.append((role, self.load(r[7], 8).hex()))
        else:
            raise Fault(f'unexpected direct call {target:#x}')
        self.clobber()
        return None


def utf8_result(bs):
    """None when valid; else (valid_up_to, error_len or None) like core::str::Utf8Error."""
    try:
        bytes(bs).decode('utf-8')
        return None
    except UnicodeDecodeError as e:
        return (e.start, None if e.reason == 'unexpected end of data' else e.end - e.start)


CALLEE_NAMES = ('any', 'bytes_seq', 'visit_bytes', 'visit_str', 'visit_ext', 'visit_map', 'visit_seq')
KNOB_RESULTS = (('ok', 0x2a), ('err', 5))


def decode_out(out):
    """Semantic view of the 48-byte Result<T, rmp_serde::decode::Error>."""
    for name in CALLEE_NAMES:
        for knob in KNOB_RESULTS:
            if out == mark(name, knob):
                return ('callee_out', name, knob)
    tag = struct.unpack_from('<Q', out, 0)[0]
    if tag == 0:
        for name in CALLEE_NAMES:
            if out[8:] == mark(name, ('ok', 0x2a))[8:]:
                return ('ok', name)
        raise Fault('Ok payload is no callee value ' + out.hex())
    if tag != 1:
        raise Fault('Result tag is not 0/1 ' + out.hex())
    for name in CALLEE_NAMES:
        if out[8:40] == mark(name, ('err', 5))[8:40]:
            return ('callee_err', name)
    etag = out[8]
    if etag in (0, 1):
        return ('io', etag, struct.unpack_from('<Q', out, 0x10)[0])
    if etag == 2:
        return ('type_mismatch', out[9])
    if etag == 4:
        return ('length_mismatch', struct.unpack_from('<I', out, 0xc)[0])
    if etag == 7:
        up, has, n = struct.unpack_from('<QBB', out, 0x10)  # Utf8Error at error +8
        return ('utf8', up, n if has else None)
    if etag == 8:
        return ('depth',)
    raise Fault('unrecognised output ' + out.hex())


CASE_STRIDE = 5
RARE_KINDS = frozenset(('depth','panic_add', 'panic_sub', 'type_mismatch', 'utf8', 'length_mismatch',
                        'callee_err'))


# reconstruction --------------------------------------------------------------
ANY_TAGS = frozenset([0x00, 0xc0, 0xc2, 0xc3, 0xe0] + list(range(0xca, 0xd4)))
FIXEXT = {0xd4: 1, 0xd5: 2, 0xd6: 4, 0xd7: 8, 0xd8: 16}


def reconstructed_any(inp, peek, depth, flag, knob, consts=C1_CONSTS, variant=None):
    """Pure model: (result, calls, (input position, peek tag, depth)).

    `knob` = (callee result, remaining count written by visit_map/visit_seq or None,
    depth written by a container/ext visitor or None). `variant` names a
    deliberately wrong rule (negative controls only).
    """
    n, calls = len(inp), []
    st = {'pos': 0, 'depth': depth}
    res_knob, rem_knob, depth_knob = knob

    def done(res):
        return res, tuple(calls), (st['pos'], 1, st['depth'])

    def rem():
        return n - st['pos']

    def read_len(k):
        """Big-endian length of k bytes; a short read consumes the rest (read_exact)."""
        if rem() < k:
            if k > 1:
                st['pos'] = n
            return None
        v = int.from_bytes(inp[st['pos']:st['pos'] + k], 'big')
        st['pos'] += k
        return v

    eof_data = ('io', 1, SIMPLE_EOF if variant == 'len_eof_simple' else consts['static_eof'])
    if peek is None:
        if n == 0:
            return done(('io', 1 if variant == 'marker_eof_is_data' else 0, consts['static_eof']))
        b = inp[0]
        st['pos'] = 1
        if b < 0x80:
            tag, pay = 0, b
        elif b >= 0xe0:
            tag, pay = 0xe0, b
        elif b < 0x90:
            tag, pay = 0x80, b & 0x0f
        elif b < 0xa0:
            tag, pay = 0x90, b & 0x0f
        else:
            tag, pay = (0xa0 if b < 0xc0 else b), b & (0x0f if variant == 'fixstr_mask_4bit' else 0x1f)
    else:
        tag, pay = peek

    def restore(kind):
        if st['depth'] == 0xffff:
            return ('panic_add', consts[kind])
        st['depth'] += 1
        return None

    def container(kind, length):
        if st['depth'] == 0:
            return ('panic_sub', consts[kind])
        st['depth'] -= 1
        if st['depth'] == 0 and variant != 'depth_limit_off':
            return ('depth',)
        role = 'visit_map' if kind == 'map' else 'visit_seq'
        calls.append((role, 'vis', length))
        if depth_knob is not None:
            st['depth'] = depth_knob
        if res_knob[0] != 'ok':
            if variant == 'restore_depth_on_error':
                return restore(kind) or ('callee_err', role)
            return ('callee_err', role)
        left = length if rem_knob is None else rem_knob
        if variant == 'ignore_remaining':
            left = 0
        if left == 0:
            out = ('callee_out', role, res_knob)  # the 40-byte Ok value is forwarded unchanged
        else:
            if left > length:
                return ('panic_sub', consts[kind + '_len'])
            consumed = length if variant == 'mismatch_carries_len' else length - left
            out = ('length_mismatch', consumed)
            if variant != 'no_drop_on_mismatch':
                calls.append(('drop_value', mark(role, res_knob)[16:24].hex()))
            if variant == 'mismatch_skips_restore':
                return out
        return restore(kind) or out

    def ext(length):
        if st['depth'] == 0:
            return ('panic_sub', consts['ext'])
        st['depth'] -= 1
        if st['depth'] == 0:
            return ('depth',)
        calls.append(('visit_ext', 'vis_copy', length, 0))
        if depth_knob is not None and variant != 'ext_restore_ignores_callee':
            st['depth'] = depth_knob
        return restore('ext') or ('callee_out', 'visit_ext', res_knob)

    def string(length):
        if rem() < length or (variant == 'str_len_strict' and rem() == length):
            return ('io', 1, SIMPLE_EOF)
        at = st['pos']
        st['pos'] += length
        calls.append(('from_utf8', at, length))
        bad = utf8_result(inp[at:at + length])
        if bad is None:
            calls.append(('visit_str', 'out', 'vis_copy', at, length))
            return ('callee_out', 'visit_str', res_knob)
        if variant == 'no_bytes_fallback':
            return ('utf8', bad[0], bad[1])
        calls.append(('visit_bytes', 'tmp', 'vis_copy', at, length))
        if res_knob[0] == 'ok':
            return ('callee_out', 'visit_bytes', res_knob)
        calls.append(('drop_error', mark('visit_bytes', res_knob)[8:16].hex()))
        return ('utf8', bad[0], bad[1])

    def binary(length):
        if rem() < length:
            return ('io', 1, SIMPLE_EOF)
        at = st['pos']
        st['pos'] += length
        if bool(flag & 0xff) != (variant == 'flag_inverted'):
            calls.append(('visit_bytes', 'out', 'vis_copy', at, length))
            return ('callee_out', 'visit_bytes', res_knob)
        calls.append(('bytes_seq', 'vis', at, at + length, 0))
        return ('callee_out', 'bytes_seq', res_knob)

    if tag in ANY_TAGS or (variant == 'reserved_is_any' and tag == 0xc1):
        calls.append(('any', 'vis', tag, pay & 0xff))
        return done(('callee_out', 'any', res_knob))
    if tag == 0xc1:
        return done(('type_mismatch', 0xc1))
    if tag == 0xa0:
        return done(string(pay))
    if tag in (0xd9, 0xda, 0xdb):
        k = {0xd9: 1, 0xda: 2, 0xdb: 4}[tag]
        v = read_len(k)
        return done(eof_data if v is None else string(v))
    if tag in (0xc4, 0xc5, 0xc6):
        k = {0xc4: 1, 0xc5: 2, 0xc6: 4}[tag]
        v = read_len(k)
        return done(eof_data if v is None else binary(v))
    if tag in (0x80, 0x90):
        return done(container('map' if tag == 0x80 else 'seq', pay))
    if tag in (0xde, 0xdf, 0xdc, 0xdd):
        v = read_len(2 if tag in (0xde, 0xdc) else 4)
        return done(eof_data if v is None else container('map' if tag in (0xde, 0xdf) else 'seq', v))
    if tag in FIXEXT:
        return done(ext(FIXEXT[tag]))
    if tag in (0xc7, 0xc8, 0xc9):
        v = read_len({0xc7: 1, 0xc8: 2, 0xc9: 4}[tag])
        return done(eof_data if v is None else ext(v))
    raise ValueError(f'tag {tag:#x} is not a Marker value')


MODEL_MUTANTS = ('marker_eof_is_data', 'len_eof_simple', 'fixstr_mask_4bit', 'depth_limit_off',
                 'restore_depth_on_error', 'mismatch_carries_len', 'ignore_remaining', 'no_drop_on_mismatch',
                 'mismatch_skips_restore', 'ext_restore_ignores_callee', 'str_len_strict', 'no_bytes_fallback',
                 'flag_inverted', 'reserved_is_any')


# cases -----------------------------------------------------------------------
VALID_TAGS = tuple([0x00, 0x80, 0x90, 0xa0] + list(range(0xc0, 0xe1)))
NAMES = (b'order', b'cancel', b'usdSend', b'vaultTransfer', b'evmUserModify')
BAD = (b'ord\xff', b'\xc3', b'ab\xe2\x82', b'\xed\xa0\x80x', b'\x80')
OK, ERR = ('ok', 0x2a), ('err', 5)
KNOBS = ((OK, None, None), (ERR, None, None), (OK, 0, None), (OK, 1, None), (OK, 0, 0xffff),
         (ERR, None, 7), (OK, 0x10000, None), (OK, 2, 0xfffe))


def bodies():
    """Length/payload tails: every length width short, exact and long."""
    t = [b'', b'\x00', b'\x01', b'\x03']
    for s in NAMES[:3] + BAD[:3]:
        t.append(bytes([len(s)]) + s)
        t.append(bytes([len(s) + 1]) + s)
        t.append(len(s).to_bytes(2, 'big') + s)
        t.append(len(s).to_bytes(4, 'big') + s)
        t.append((len(s) + 1).to_bytes(4, 'big') + s)
    t += [b'\x00\x00', b'\x00\x02', b'\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x05',
          b'\xff\xff', b'\xff\xff\xff\xff', bytes(16), bytes(17)]
    return t


def build_cases():
    cases, seen = [], set()

    def add(inp, peek, depth, flag, knob):
        key = (inp, peek, depth, flag, knob)
        if key not in seen:
            seen.add(key)
            cases.append(key)

    tails = bodies()
    for depth in (0, 2):
        for knob in KNOBS[:2]:
            add(b'', None, depth, 0, knob)
    # every first byte, every tail, both flag values, a normal depth, varied callee knobs
    for b in range(256):
        for j, tail in enumerate(tails):
            for flag in (0, 1):
                add(bytes([b]) + tail, None, 2, flag, KNOBS[(b + j + flag) % 4])
    # fixstr with real names and invalid UTF-8
    for s in NAMES + BAD:
        for k in KNOBS[:2]:
            add(bytes([0xa0 | len(s)]) + s, None, 2, 0, k)
            add(bytes([0xa0 | len(s)]) + s[:-1], None, 2, 0, k)
    # peeked markers: every valid tag x payloads x tails
    for tag in VALID_TAGS:
        for pay in (0, 1, 3, 5, 0x1f):
            for tail in tails[::3]:
                add(tail, (tag, pay), 2, tag & 1, KNOBS[pay % 4])
    # depth, remaining-count and callee-result rules on every container and ext marker
    for first in (b'\x80', b'\x81', b'\x82', b'\x90', b'\x93', b'\xde\x00\x00', b'\xde\x00\x01',
                  b'\xde\xff\xff', b'\xdc\x00\x00', b'\xdc\x00\x02', b'\xdd\x00\x00\x00\x02',
                  b'\xdd\x00\x01\x00\x00', b'\xdf\x00\x00\x00\x00', b'\xdf\xff\xff\xff\xff', b'\xd4\x01\x02',
                  b'\xd8' + bytes(17), b'\xc7\x03\x01abc', b'\xc8\x00\x01\x01a', b'\xc9\x00\x00\x00\x00\x01'):
        for depth in (0, 1, 2, 3, 0xfffe, 0xffff):
            for knob in KNOBS:
                add(first, None, depth, 0, knob)
    # invalid UTF-8 str through every width with both visit_bytes results
    for s in BAD + NAMES:
        for hdr in (bytes([0xd9, len(s)]), b'\xda' + len(s).to_bytes(2, 'big'), b'\xdb' + len(s).to_bytes(4, 'big')):
            for k in KNOBS[:2]:
                add(hdr + s, None, 2, 0, k)
    return cases


def fmt(v):
    if isinstance(v, tuple):
        return '(' + ','.join(fmt(x) for x in v) + ')'
    if isinstance(v, int):
        return hex(v) if v > 9 else str(v)
    if v is None:
        return '-'
    return str(v)


def compare(img, copies, cases, variant=None):
    """Run every case on every copy; return (rows, mismatches, coverage sets)."""
    rows, bad, cover = [], [], {c.label: set() for c in copies}
    machines = [(c, Machine(img, c)) for c in copies]
    for i, case in enumerate(cases):
        want = reconstructed_any(*case, consts=copies[0].consts, variant=variant)
        flags = []
        for c, m in machines:
            try:
                got = m.run(case)
            except Fault as e:
                got = ('fault', str(e))
            cover[c.label].update(m.trace)
            ok = got == reconstructed_any(*case, consts=c.consts, variant=variant)
            flags.append(ok)
            if not ok:
                bad.append((i, c.label, got))
        rows.append((i, case, want, flags))
    return rows, bad, cover


IMM_SITES = {('cmp', 0xdf), ('cmp', 0x90), ('cmp', 0xa0), ('cmp', 0xc0), ('cmp', 0x4), ('cmp', 0x2),
             ('cmp', 0x1), ('cmp', 0x11), ('cmp', 0xffff), ('mov', 0x4), ('mov', 0x8), ('mov', 0x7),
             ('mov', 0x1), ('mov', 0x2), ('mov', 0x10), ('and', 0xf), ('and', 0x1f), ('add', 0xffffff39)}


def image_mutants(img, copy):
    """Single-bit corruptions of copy C1 at the low immediate byte of rule-steering instructions."""
    sites = []
    for ins in copy.insns:
        if not isinstance(ins.b, tuple) or ins.b[0] != 'i' or (ins.op, ins.b[1]) not in IMM_SITES:
            continue
        if ins.va < copy.pad_lo and ins.immlen:  # landing pads are not executed
            sites.append((ins.va + ins.size - ins.immlen, f'{ins.op} imm {ins.b[1]:#x} at {ins.va:#x}'))
    for tag in (0x00, 0x80, 0x90, 0xa0, 0xc1, 0xc4, 0xc5, 0xc6, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xd4, 0xc7):
        sites.append((copy.marker_va + 4 * tag, f'marker table entry {tag:#x}'))
    for t in (0xc7, 0xc8, 0xc9, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8):
        sites.append((copy.ext_va + 4 * (t - EXT_TABLE_LO), f'ext table entry {t:#x}'))
    return sites


def run_mutant(data, img, base, site, cases, rows):
    mut = bytearray(data)
    mut[img.off(site)] ^= 0x01
    mimg = Image(bytes(mut), check=False)
    try:
        mc = Copy(mimg, 'C1', base.start)
        mc.consts = base.consts
        m = Machine(mimg, mc)
    except Fault:
        return 'static'
    for i, case in enumerate(cases):
        try:
            got = m.run(case)
        except Fault:
            got = None
        if got != rows[i][2]:
            return i
    return None


def generate(out_dir, data=None):
    data = data if data is not None else BINARY.read_bytes()
    img = Image(data)
    copies = [Copy(img, label, start) for label, start in COPIES]
    base = copies[0]
    for c in copies:
        c.bind_consts(base)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for c in copies[1:]:
        if [shape(i) for i in c.insns] != [shape(i) for i in base.insns]:
            raise Fault(f'{c.label} is not the same shape as C1')
    any_targets = {c.slot_targets[0x64e4198] for c in copies}

    # copies.tsv ---------------------------------------------------------------
    lines = ['copy\tstart\tend\tbytes\tinsns\tsha256\tmarker_table\text_table\tlsda\tlanding_pads\t'
             + '\t'.join(ROLES) + '\tgot_slots']
    for c in copies:
        raw = img.read(c.start, c.end - c.start)
        pads = sorted({s[2] for s in c.sites if s[2]})
        lines.append('\t'.join([c.label, hex(c.start), hex(c.end), str(c.end - c.start), str(len(c.insns)),
                                hashlib.sha256(raw).hexdigest(), hex(c.marker_va), hex(c.ext_va),
                                hex(c.lsda or 0), ','.join(hex(p) for p in pads)]
                               + [hex(c.by_role[r]) for r in ROLES]
                               + [','.join(f'{s:#x}={SLOTS[s][0]}->{c.slot_targets[s]:#x}' for s in sorted(c.slots))]))
    (out / 'copies.tsv').write_text('\n'.join(lines) + '\n')

    # tables.tsv: marker tag -> arm (offset from function start), per copy ------
    lines = ['table\ttag\t' + '\t'.join(f'{c.label}_arm_off' for c in copies) + '\tsame']
    for t in range(MARKER_TABLE_LEN):
        offs = [c.marker_arms[t] - c.start for c in copies]
        lines.append(f'marker\t{t:#04x}\t' + '\t'.join(hex(o) for o in offs) + f'\t{int(len(set(offs)) == 1)}')
    for t in range(EXT_TABLE_LEN):
        offs = [c.ext_arms[t] - c.start for c in copies]
        lines.append(f'ext\t{t + EXT_TABLE_LO:#04x}\t' + '\t'.join(hex(o) for o in offs)
                     + f'\t{int(len(set(offs)) == 1)}')
    (out / 'tables.tsv').write_text('\n'.join(lines) + '\n')
    ud2 = [i.va - base.start for i in base.insns if i.op == 'ud2']
    arm_groups = {}
    for t in range(MARKER_TABLE_LEN):
        arm_groups.setdefault(base.marker_arms[t] - base.start, []).append(t)
    unreachable_tags = [t for t, a in enumerate(base.marker_arms) if a - base.start in ud2]

    # insns.tsv: C1 listing (shape bytes are shared by C2/C3) --------------------
    lines = ['off\tsize\tbytes\top']
    for ins in base.insns:
        lines.append(f'{ins.va - base.start:#05x}\t{ins.size}\t{ins.raw.hex()}\t{ins.op}')
    (out / 'insns.tsv').write_text('\n'.join(lines) + '\n')

    # cases ---------------------------------------------------------------------
    cases = build_cases()
    rows, bad, cover = compare(img, copies, cases)
    lines = ['case\tinput\tpeek\tdepth\tflag\tcallee_knob\tresult\tcalls\tstate_after\tC1\tC2\tC3']
    kinds, listed = {}, 0
    for i, case, want, got_all in rows:
        inp, peek, depth, flag, knob = case
        kinds[want[0][0]] = kinds.get(want[0][0], 0) + 1
        # Every case is compared; the listing keeps every CASE_STRIDE-th one plus every
        # case whose result kind is rare, to bound the file size.
        if i % CASE_STRIDE and want[0][0] not in RARE_KINDS:
            continue
        listed += 1
        lines.append('\t'.join([str(i), inp.hex() or '-', fmt(peek) if peek else '-', hex(depth), str(flag),
                                fmt(knob), fmt(want[0]), fmt(want[1]) or '-', fmt(want[2])]
                               + ['ok' if g else 'MISMATCH' for g in got_all]))
    (out / 'cases.tsv').write_text('\n'.join(lines) + '\n')

    # coverage --------------------------------------------------------------------
    lines = ['copy\toff\top\treason']
    residue = {}
    for c in copies:
        prev = {b.va: a for a, b in zip(c.insns, c.insns[1:])}
        missed = [i for i in c.insns if i.va not in cover[c.label]]
        for ins in missed:
            if ins.va >= c.pad_lo:
                why = 'landing pad region (LSDA call-site table)'
            elif ins.op == 'ud2':
                why = 'ud2 (table entry for a non-Marker tag)'
            elif ins.op == 'jmp' and ins.va in prev and prev[ins.va].op == 'callr':
                why = 'jmp after a noreturn panic call'
            else:
                why = 'unexplained'
            residue[why] = residue.get(why, 0) + (c.label == 'C1')
            lines.append(f'{c.label}\t{ins.va - c.start:#05x}\t{ins.op}\t{why}')
    (out / 'coverage.tsv').write_text('\n'.join(lines) + '\n')
    covered = {c.label: len([i for i in c.insns if i.va in cover[c.label]]) for c in copies}

    # negative controls --------------------------------------------------------------
    lines = ['kind\tmutant\tkilled\tfirst_case']
    killed = 0
    for v in MODEL_MUTANTS:
        first = next((i for i, case in enumerate(cases)
                      if reconstructed_any(*case, consts=base.consts, variant=v) != rows[i][2]), None)
        killed += first is not None
        lines.append(f'model\t{v}\t{int(first is not None)}\t{first if first is not None else "-"}')
    img_sites = image_mutants(img, base)
    img_killed = 0
    for site, what in img_sites:
        first = run_mutant(data, img, base, site, cases, rows)
        img_killed += first is not None
        lines.append(f'image\t{what} ^0x01\t{int(first is not None)}\t{first if first is not None else "-"}')
    (out / 'mutants.tsv').write_text('\n'.join(lines) + '\n')

    summary = {
        'binary_sha256': SHA256,
        'copies': [hex(c.start) for c in copies],
        'function_bytes': FUNC_SIZE,
        'instructions_per_copy': len(base.insns),
        'copies_same_shape': True,
        'any_helper_targets': sorted(hex(t) for t in any_targets),
        'marker_table_entries': MARKER_TABLE_LEN,
        'marker_arm_groups': len(arm_groups),
        'marker_tags_to_ud2': len(unreachable_tags),
        'ext_table_entries': EXT_TABLE_LEN,
        'cases': len(cases),
        'case_runs': len(cases) * len(copies),
        'cases_listed': listed,
        'mismatches': len(bad),
        'result_kinds': dict(sorted(kinds.items())),
        'covered_instructions': covered,
        'uncovered_residue_C1': dict(sorted(residue.items())),
        'model_mutants_killed': f'{killed}/{len(MODEL_MUTANTS)}',
        'image_mutants_killed': f'{img_killed}/{len(img_sites)}',
        'limitations': 'Callees are contract stubs; their bodies (any helper, map/seq/ext visitors, bytes_seq, '
                       'visit_str/visit_bytes, drops) are not reconstructed here. Landing pads are not executed. '
                       'Role names are inferences from argument shapes and sibling packets.',
    }
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    return summary, bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    s, bad = generate(args.out)
    for b in bad[:5]:
        print('mismatch', b[0], b[1], b[2], file=sys.stderr)
    print(json.dumps({k: s[k] for k in ('cases', 'mismatches', 'covered_instructions', 'uncovered_residue_C1',
                                        'model_mutants_killed', 'image_mutants_killed')}, sort_keys=True))
    return 0 if s['mismatches'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
