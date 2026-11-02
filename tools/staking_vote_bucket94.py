#!/usr/bin/env python3
"""Static evaluator for node 94 validator vote bucket creation and ownership cleanup.

The x86-64 decoder and machine below are adapted from the repository's
staking_stake_accounting.py (MIT, Copyright 2026 Hyperliquid Source
contributors). The license is reproduced at the end of this file.
"""
import argparse
import bisect
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xff, 2: 0xffff, 4: 0xffffffff, 8: 0xffffffffffffffff}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xa5
STACK_TOP = 0x7ff000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x100000
RETURN_SENTINEL = 0xdead0000
POISON = 0xa5a5a5a5a5a5a5a5
STEP_LIMIT = 200000

class EvidenceError(Exception):
    pass

class Halt(Exception):
    pass

class Panicked(Exception):
    pass

class Image:
    def __init__(self, blob):
        self.blob = blob
        self.sections = sections(blob)
        self.mapped = [s for s in self.sections if s['type'] != 8 and s['size']]
        _, fdes = eh_frame_records(blob, self.sections)
        self.fde_ends = {}
        self.fde_records = {}
        for row in fdes:
            if row['start'] in self.fde_ends:
                raise EvidenceError('duplicate FDE start')
            self.fde_ends[row['start']] = row['end']
            self.fde_records[row['start']] = row

    def offset(self, va):
        found = [s for s in self.mapped if s['address'] <= va < s['address'] + s['size']]
        if len(found) != 1:
            raise EvidenceError('address not uniquely file-backed: %#x' % va)
        return found[0]['offset'] + va - found[0]['address']

    def exact_fde(self, va):
        if va not in self.fde_ends:
            raise EvidenceError('not an FDE start: %#x' % va)
        return va, self.fde_ends[va]

    def relative(self):
        matches = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
        if len(matches) != 1 or matches[0]['size'] % 24:
            raise EvidenceError('invalid relocation section')
        rel = matches[0]
        result = {}
        for at in range(rel['offset'], rel['offset'] + rel['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.blob, at)
            if info == 8:
                if slot in result: raise EvidenceError('duplicate relative relocation')
                result[slot] = addend
        return result

def load_image(path=BINARY, expected=SHA256):
    blob = Path(path).read_bytes()
    if hashlib.sha256(blob).hexdigest() != expected:
        raise EvidenceError('binary SHA-256 mismatch')
    return Image(blob)

def fdiv(left, right):
    return left / right

def to_float(bits):
    return struct.unpack('<d', struct.pack('<Q', bits & MASK[8]))[0]

def to_bits(value):
    return struct.unpack('<Q', struct.pack('<d', value))[0]

class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at", "data")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {0: "rol", 1: "ror", 4: "shl", 5: "shr", 7: "sar"}


def decode(read, va):
    """Decode one instruction at va; read(va, n) returns n code bytes."""
    window = read(va, 16)
    pos, rex, opsize, rep, repne = 0, 0, False, False, False
    while True:
        byte = window[pos]
        if byte == 0x66:
            opsize = True
        elif byte == 0xF3:
            rep = True
        elif byte == 0xF2:
            repne = True
        elif byte == 0xF0:
            pass
        elif byte != 0x2E:
            break
        pos += 1
    if 0x40 <= window[pos] <= 0x4F:
        rex = window[pos]
        pos += 1
    wide = bool(rex & 8)
    width = 8 if wide else (2 if opsize else 4)
    byte = window[pos]
    pos += 1
    imm = None
    rip_at = None

    def modrm(vector=False):
        nonlocal pos, rip_at
        mod_rm = window[pos]
        pos += 1
        mod, reg, rm = mod_rm >> 6, ((mod_rm >> 3) & 7) | ((rex & 4) << 1), mod_rm & 7
        if mod == 3:
            return reg, ("x" if vector else "r", rm | ((rex & 1) << 3))
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = window[pos]
            pos += 1
            scale = 1 << (sib >> 6)
            index = ((sib >> 3) & 7) | ((rex & 2) << 2)
            if index == 4:
                index = None
            base = (sib & 7) | ((rex & 1) << 3)
            if sib & 7 == 5 and mod == 0:
                base = None
                disp = struct.unpack_from("<i", window, pos)[0]
                pos += 4
                return reg, ("m", base, index, scale, disp, False)
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | ((rex & 1) << 3)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from("<b", window, pos)[0]
            pos += 1
        elif mod == 2 or rip:
            if rip:
                rip_at = pos
            disp = struct.unpack_from("<i", window, pos)[0]
            pos += 4
        return reg, ("m", base, index, scale, disp, rip)

    def immediate(size):
        nonlocal pos, imm
        value = struct.unpack_from({1: "<b", 2: "<h", 4: "<i", 8: "<q"}[size], window, pos)[0]
        imm = (pos, size)
        pos += size
        return value

    def finish(op, a=None, b=None, w=None, cc=None, target=None):
        size = pos
        if (width if w is None else w) == 1 and not rex:
            if op != "mov" and any(operand and operand[0] == "r" and 4 <= operand[1] <= 7 for operand in (a, b)):
                raise EvidenceError("high byte register at %#x" % va)
            if a and a[0] == "r" and 4 <= a[1] <= 7:
                a = ("h", a[1] - 4)
            if b and b[0] == "r" and 4 <= b[1] <= 7:
                b = ("h", b[1] - 4)

        def fix(operand):
            if operand and operand[0] == "m" and operand[5]:
                return ("m", None, None, 1, va + size + operand[4], False)
            return operand
        return Insn(va, size, op, fix(a), fix(b), width if w is None else w, cc, target, imm, rip_at)

    if 0x50 <= byte <= 0x57:
        return finish("push", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if 0x58 <= byte <= 0x5F:
        return finish("pop", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if byte < 0x40 and byte & 7 < 4:
        name = GROUP1[byte >> 3]
        w = 1 if not byte & 1 else width
        reg, rm = modrm()
        if byte & 2:
            return finish(name, ("r", reg), rm, w)
        return finish(name, rm, ("r", reg), w)
    if byte < 0x40 and byte & 7 in (4, 5):
        w = 1 if byte & 7 == 4 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish(GROUP1[byte >> 3], ("r", RAX), ("i", value), w)
    if byte == 0x63 and wide:
        reg, rm = modrm()
        return finish("movsxd", ("r", reg), rm, 8)
    if 0x70 <= byte <= 0x7F:
        rel = immediate(1)
        return finish("jcc", cc=byte & 15, target=va + pos + rel)
    if byte in (0x80, 0x81, 0x83):
        reg, rm = modrm()
        w = 1 if byte == 0x80 else width
        value = immediate(4 if byte == 0x81 and w != 2 else 2 if byte == 0x81 else 1)
        return finish(GROUP1[reg & 7], rm, ("i", value), w)
    if byte in (0x84, 0x85):
        reg, rm = modrm()
        return finish("test", rm, ("r", reg), 1 if byte == 0x84 else width)
    if byte in (0x88, 0x89, 0x8A, 0x8B):
        reg, rm = modrm()
        w = 1 if not byte & 1 else width
        if byte & 2:
            return finish("mov", ("r", reg), rm, w)
        return finish("mov", rm, ("r", reg), w)
    if byte == 0x8D:
        reg, rm = modrm()
        return finish("lea", ("r", reg), rm, width)
    if byte == 0x90:
        return finish("nop")
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x98:
        return finish("cdqe" if wide else "cwde")
    if byte == 0xA9:
        value = immediate(4)
        return finish("test", ("r", RAX), ("i", value), width)
    if byte == 0xA8:
        value = immediate(1)
        return finish("test", ("r", RAX), ("i", value), 1)
    if 0xB0 <= byte <= 0xB7:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(1)
        return finish("mov", ("r", reg), ("i", value & 0xFF), 1)
    if 0xB8 <= byte <= 0xBF:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(8 if wide else 2 if opsize else 4)
        return finish("mov", ("r", reg), ("i", value & MASK[width]), width)
    if byte == 0x69:
        reg, rm = modrm()
        value = immediate(4)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0x6B:
        reg, rm = modrm()
        value = immediate(1)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0xD3:
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("r", RCX), width)
    if byte in (0xD1, 0xD0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("i", 1), 1 if byte == 0xD0 else width)
    if byte in (0xC1, 0xC0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        value = immediate(1) & 0xFF
        return finish(SHIFTS[reg & 7], rm, ("i", value), 1 if byte == 0xC0 else width)
    if byte == 0xC3:
        return finish("ret")
    if byte == 0xCC:
        return finish("int3")
    if byte in (0xC6, 0xC7):
        reg, rm = modrm()
        w = 1 if byte == 0xC6 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish("mov", rm, ("i", value & MASK[w]), w)
    if byte == 0xE8:
        rel = immediate(4)
        return finish("call", target=va + pos + rel)
    if byte == 0xE9:
        rel = immediate(4)
        return finish("jmp", target=va + pos + rel)
    if byte == 0xEB:
        rel = immediate(1)
        return finish("jmp", target=va + pos + rel)
    if byte in (0xF6, 0xF7):
        reg, rm = modrm()
        w = 1 if byte == 0xF6 else width
        kind = reg & 7
        if kind == 0:
            value = immediate(1 if w == 1 else 4)
            return finish("test", rm, ("i", value), w)
        if kind in (2, 3, 4, 5, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 5: "imul1", 6: "div"}[kind], rm, w=w)
        raise EvidenceError("unsupported group 3 opcode at %#x" % va)
    if byte in (0xFE, 0xFF):
        reg, rm = modrm()
        kind = reg & 7
        w = 1 if byte == 0xFE else width
        if kind in (0, 1):
            return finish("inc" if kind == 0 else "dec", rm, w=w)
        if byte == 0xFF and kind == 2:
            return finish("calli", rm, w=8)
        if byte == 0xFF and kind == 4:
            return finish("jmpi", rm, w=8)
        if byte == 0xFF and kind == 6:
            return finish("pushm", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x87:
        reg, rm = modrm()
        return finish("xchg", rm, ("r", reg), width)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xC6 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufpd", ("x", reg), rm, 16, target=value)
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmppd", ("x", reg), rm, 16, target=value)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x72 and opsize:
            reg, rm = modrm(True)
            if reg & 7 not in (4, 6):
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrad" if reg & 7 == 4 else "pslld", rm, ("i", value), 16)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xAB:
            reg, rm = modrm()
            return finish("btsr", rm, ("r", reg), width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("btr", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two == 0x13:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and rep:
            reg, rm = modrm(True)
            if rm[0] == "x":
                raise EvidenceError("movss between registers at %#x" % va)
            if two == 0x10:
                return finish("movss", ("x", reg), rm, 4)
            return finish("movss", rm, ("x", reg), 4)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0xDF, True): "pandn", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, 8)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x70 and (opsize or repne):
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pshufd" if opsize else "pshuflw", ("x", reg), rm, 16, target=value)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
        if two == 0xBC and rep:
            reg, rm = modrm()
            return finish("tzcnt", ("r", reg), rm, width)
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two == 0x16 and not opsize:
            reg, rm = modrm(True)
            return finish("movhps", ("x", reg), rm, 8)
        if two == 0x12 and not opsize and not rep and not repne:
            reg, rm = modrm(True)
            return finish("movlps", ("x", reg), rm, 8)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movdout", rm, ("x", reg), 4)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x6E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x7E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", rm, ("x", reg), 8)
        if 0x40 <= two <= 0x4F:
            reg, rm = modrm()
            return finish("cmov", ("r", reg), rm, width, cc=two & 15)
        if 0x80 <= two <= 0x8F:
            rel = immediate(4)
            return finish("jcc", cc=two & 15, target=va + pos + rel)
        if 0x90 <= two <= 0x9F:
            _, rm = modrm()
            return finish("set", rm, w=1, cc=two & 15)
        if two == 0xAF:
            reg, rm = modrm()
            return finish("imul2", ("r", reg), rm, width)
        if two == 0xBD:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrd", rm, ("r", reg), width, target=value)
        if two == 0xB1:
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), width)
        if two == 0xAD:
            reg, rm = modrm()
            return finish("shrd", rm, ("r", reg), width)
        if two in (0xB6, 0xB7):
            reg, rm = modrm()
            return finish("movzx", ("r", reg), rm, width, cc=1 if two == 0xB6 else 2)
    raise EvidenceError("undecodable opcode %#x at %#x" % (byte, va))


def decode_range(image, start, end):
    """Decode [start, end) linearly; the last instruction must end exactly at end."""
    base = image.offset(start)
    code = image.blob[base:base + (end - start) + 16]

    def read(va, count):
        return code[va - start:va - start + count]

    rows = []
    va = start
    while va < end:
        row = decode(read, va)
        row.data = bytes(read(va, row.size))
        rows.append(row)
        va = row.next
    if va != end:
        raise EvidenceError("decoder overran FDE end at %#x" % end)
    return rows


class Memory:
    def __init__(self, image):
        self.image = image
        self.stack = bytearray(STACK_SIZE)
        self.heap = bytearray(HEAP_SIZE)
        self.stack_base = STACK_TOP - STACK_SIZE
        self.fresh = (bytes([STACK_MARK]) * STACK_SIZE, bytes([STACK_MARK]) * HEAP_SIZE)
        self.statics = {}

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
        return None, 0

    def read(self, addr, count):
        return int.from_bytes(self.bytes_at(addr, count), "little")

    def write(self, addr, count, value):
        buffer, at = self.locate(addr, count)
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + count] = (value & MASK.get(count, (1 << (8 * count)) - 1)).to_bytes(count, "little")

    def put_bytes(self, addr, data):
        buffer, at = self.locate(addr, len(data))
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + len(data)] = data

    def bytes_at(self, addr, count):
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return self.statics[addr].to_bytes(count, "little")
        try:
            return at(self.image, addr, count)
        except EvidenceError:
            raise Halt("read outside every file-backed mapping: %#x" % addr)

    def copy(self, dst, src, count):
        self.put_bytes(dst, self.bytes_at(src, count))

class Machine:
    def __init__(self, image, patches=None):
        self.image = image
        self.patches = patches or {}
        self.memory = Memory(image)
        self.cache = {}
        self.calls = {}
        self.real = frozenset()
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.branches = set()
        self.current_pc = None
        self.code_window = None
        self.steps = 0
        self.keep_rdx = False
        self.step_limit = STEP_LIMIT
        self.xmm_result = None

    def read_code(self, va, count):
        offset = self.image.offset(va)
        data = bytearray(self.image.blob[offset:offset + count])
        for index in range(count):
            if va + index in self.patches:
                data[index] = self.patches[va + index]
        return data

    def address(self, operand):
        _, base, index, scale, disp, _ = operand
        value = disp
        if base is not None:
            value += self.regs[base]
        if index is not None:
            value += self.regs[index] * scale
        return value & MASK[8]

    def get(self, operand, width):
        kind = operand[0]
        if kind == "r":
            return self.regs[operand[1]] & MASK[width]
        if kind == "h":
            return self.regs[operand[1]] >> 8 & 0xFF
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "h":
            self.regs[operand[1]] = (self.regs[operand[1]] & ~0xFF00) | value << 8
            return
        if operand[0] == "r":
            reg = operand[1]
            if width >= 4:
                self.regs[reg] = value
            else:
                self.regs[reg] = (self.regs[reg] & ~MASK[width]) | value
        else:
            self.memory.write(self.address(operand), width, value)

    def condition(self, code):
        result = {
            0: self.of, 1: self.cf, 2: self.zf, 3: self.cf or self.zf, 4: self.sf,
            5: self.pf, 6: self.sf != self.of, 7: self.zf or self.sf != self.of,
        }[code >> 1]
        return bool(result) != bool(code & 1)

    def set_logic(self, result, width):
        self.cf = self.of = False
        self.zf = result & MASK[width] == 0
        self.sf = bool(result & SIGN[width])

    def add_sub(self, left, right, carry, width, subtract):
        mask = MASK[width]
        if subtract:
            result = (left - right - carry) & mask
            self.cf = left < right + carry
            self.of = bool((left ^ right) & (left ^ result) & SIGN[width])
        else:
            total = left + right + carry
            result = total & mask
            self.cf = total > mask
            self.of = bool(~(left ^ right) & (left ^ result) & SIGN[width])
        self.zf = result == 0
        self.sf = bool(result & SIGN[width])
        return result

    def push(self, value):
        self.regs[RSP] -= 8
        self.memory.write(self.regs[RSP], 8, value)

    def pop(self):
        value = self.memory.read(self.regs[RSP], 8)
        self.regs[RSP] += 8
        return value

    def stub(self, hook):
        self.keep_rdx = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        self.xmm = [POISON | POISON << 64] * 16

    def run(self, entry, args, stack=()):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        for value in reversed(stack):
            self.push(value)
        self.push(RETURN_SENTINEL)
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL:
            if self.code_window is not None and not any(start <= pc < end for start, end in self.code_window):
                raise Halt('control left selected FDE')
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
            self.current_pc = pc
            self.steps += 1
            pc = self.step(row)
        if self.regs[RSP] != top + 8:
            raise Halt("unbalanced stack")
        for reg, value in saved.items():
            if self.regs[reg] != value:
                raise Halt("callee-saved register changed")
        return self.regs[RAX]

    def step(self, row):
        op = row.op
        width = row.width
        if op == "mov":
            self.put(row.a, width, self.get(row.b, width))
        elif op == "jcc":
            taken = self.condition(row.cc)
            self.branches.add((row.va, taken))
            return row.target if taken else row.next
        elif op == "lea":
            self.put(row.a, width, self.address(row.b))
        elif op == "push":
            self.push(self.regs[row.a[1]])
        elif op == "pop":
            self.regs[row.a[1]] = self.pop()
        elif op in ("add", "adc", "sub", "sbb", "cmp"):
            carry = int(self.cf) if op in ("adc", "sbb") else 0
            result = self.add_sub(self.get(row.a, width), self.get(row.b, width), carry, width, op not in ("add", "adc"))
            if op != "cmp":
                self.put(row.a, width, result)
        elif op in ("and", "or", "xor", "test"):
            left, right = self.get(row.a, width), self.get(row.b, width)
            result = left & right if op in ("and", "test") else left | right if op == "or" else left ^ right
            self.set_logic(result, width)
            if op != "test":
                self.put(row.a, width, result)
        elif op == "cmpxchg":
            current = self.get(row.a, width)
            wanted = self.regs[RAX] & MASK[width]
            self.add_sub(wanted, current, 0, width, True)
            if wanted == current:
                self.put(row.a, width, self.get(row.b, width))
            else:
                self.put(("r", RAX), width, current)
        elif op == "xchg":
            first, second = self.get(row.a, width), self.get(row.b, width)
            self.put(row.a, width, second)
            self.put(row.b, width, first)
        elif op == "call":
            self.push(row.next)
            if row.target in self.real:
                return row.target
            hook = self.calls.get(row.target)
            if not hook:
                raise Halt("unmodelled call to %#x at %#x" % (row.target, row.va))
            self.stub(hook)
            return self.pop()
        elif op == "jmp":
            hook = self.calls.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
            return row.target
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "pushm":
            self.push(self.get(row.a, 8))
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
        elif op == "btsr":
            bit = self.get(row.b, width) & (8 * width - 1)
            value = self.get(row.a, width)
            self.cf = bool(value >> bit & 1)
            self.put(row.a, width, value | 1 << bit)
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
        elif op == "movsx":
            value = self.get(row.b, row.cc)
            self.put(row.a, width, value - (1 << (8 * row.cc)) if value & SIGN[row.cc] else value)
        elif op == "ror":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) & MASK[width])
        elif op == "rol":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) & MASK[width])
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (row.b[1] & (8 * width - 1)) & 1)
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.xmm_result = None
            self.stub(hook)
            if self.xmm_result is not None:
                self.xmm[0] = self.xmm_result
        elif op == "ret":
            return self.pop()
        elif op == "movzx":
            self.put(row.a, width, self.get(row.b, row.cc))
        elif op == "set":
            self.put(row.a, 1, int(self.condition(row.cc)))
        elif op == "cmov":
            value = self.get(row.b, width)
            self.put(row.a, width, value if self.condition(row.cc) else self.get(row.a, width))
        elif op in ("inc", "dec"):
            carry = self.cf
            value = self.add_sub(self.get(row.a, width), 1, 0, width, op == "dec")
            self.cf = carry
            self.put(row.a, width, value)
        elif op == "neg":
            value = self.add_sub(0, self.get(row.a, width), 0, width, True)
            self.put(row.a, width, value)
        elif op == "not":
            self.put(row.a, width, ~self.get(row.a, width))
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            left -= (left >> 63) << 64
            right -= (right >> 63) << 64
            product = left * right
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            bits = 8 * width
            left, right = self.get(row.b, width), row.target & MASK[width]
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op in ("shl", "shr", "sar"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "shl":
                result = value << count
            elif op == "shr":
                result = value >> count
            else:
                result = (value - (1 << (8 * width)) if value & SIGN[width] else value) >> count
            if count:
                self.set_logic(result, width)
            self.put(row.a, width, result)
        elif op == "movx":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.vector(row.b)
            elif row.b[0] == "x":
                self.memory.write(self.address(row.a), 16, self.xmm[row.b[1]])
            else:
                raise Halt("unmodelled vector move")
        elif op == "xorps":
            self.xmm[row.a[1]] ^= self.vector(row.b)
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cwde":
            self.regs[RAX] = ((self.regs[RAX] & 0xFFFF) ^ 0x8000) - 0x8000 & MASK[4]
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            bits = 8 * width
            left, right = self.get(row.a, width), self.get(row.b, width)
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd"):
            count = (row.target if row.target is not None else self.regs[RCX]) & 63
            high, low = self.get(row.a, 8), self.get(row.b, 8)
            if op == "shld":
                value = (high << count | low >> (64 - count)) if count else high
            else:
                value = (high >> count | low << (64 - count)) if count else high
            self.put(row.a, 8, value)
        elif op == "div":
            divisor = self.get(row.a, width)
            if divisor == 0:
                raise Halt("division by zero at %#x" % row.va)
            dividend = (self.regs[RDX] & MASK[width]) << (8 * width) | (self.regs[RAX] & MASK[width])
            quotient, remainder = divmod(dividend, divisor)
            if quotient > MASK[width]:
                raise Halt("division overflow at %#x" % row.va)
            self.regs[RAX], self.regs[RDX] = quotient, remainder
        elif op == "movsxd":
            value = self.get(row.b, 4)
            self.put(row.a, 8, value - (1 << 32) if value & SIGN[4] else value)
        else:
            self.step_vector(row, op)
        return row.next

    def low(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]] & MASK[8]
        return self.memory.read(self.address(operand), 8)

    def set_low(self, register, bits):
        self.xmm[register] = (self.xmm[register] & ~MASK[8]) | bits

    def step_vector(self, row, op):
        if op == "movss":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.memory.read(self.address(row.b), 4)
            else:
                self.memory.write(self.address(row.a), 4, self.xmm[row.b[1]] & MASK[4])
            return
        if op == "movsd":
            if row.a[0] == "x":
                if row.b[0] == "x":
                    self.set_low(row.a[1], self.low(row.b))
                else:
                    self.xmm[row.a[1]] = self.low(row.b)
            else:
                self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "movq":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "divsd":
                result = fdiv(left, right)
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "minsd":
                result = left if left < right else right
            else:
                result = left if left > right else right
            self.set_low(row.a[1], to_bits(result))
        elif op == "ucomisd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            unordered = left != left or right != right
            self.of = self.sf = False
            self.pf = unordered
            self.zf = unordered or left == right
            self.cf = unordered or left < right
        elif op == "cvttsd2si":
            value = to_float(self.low(row.b))
            if value != value or not -9223372036854775808.0 <= value < 9223372036854775808.0:
                self.put(row.a, 8, 1 << 63)
            else:
                self.put(row.a, 8, int(value))
        elif op == "cvtsi2sd":
            value = self.get(row.b, 8)
            self.set_low(row.a[1], to_bits(float(value - (1 << 64) if value & SIGN[8] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            self.xmm[row.a[1]] = int.from_bytes(bytes(byte for pair in zip(left[:8], right[:8]) for byte in pair), "little")
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = [(source >> (16 * index)) & 0xFFFF for index in range(4)]
            low = sum(words[(row.target >> (2 * index)) & 3] << (16 * index) for index in range(4))
            self.xmm[row.a[1]] = source >> 64 << 64 | low
        elif op == "pshufd":
            source = self.vector(row.b)
            words = [(source >> (32 * index)) & MASK[4] for index in range(4)]
            self.xmm[row.a[1]] = sum(words[(row.target >> (2 * index)) & 3] << (32 * index) for index in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            lanes = (b"\xff" * size if left[at:at + size] == right[at:at + size] else bytes(size) for at in range(0, 16, size))
            self.xmm[row.a[1]] = int.from_bytes(b"".join(lanes), "little")
        elif op == "pmovmskb":
            data = self.xmm[row.b[1]].to_bytes(16, "little")
            self.put(row.a, 4, sum((byte >> 7) << index for index, byte in enumerate(data)))
        elif op == "tzcnt":
            source = self.get(row.b, row.width)
            count = (source & -source).bit_length() - 1 if source else row.width * 8
            self.cf = source == 0
            self.zf = count == 0
            self.put(row.a, row.width, count)
        elif op == "movhps":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | self.get(row.b, 8) << 64
        elif op == "movlps":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 << 64 | self.get(row.b, 8)
        elif op == "movdout":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op in ("pslld", "psrad"):
            value, lanes = self.xmm[row.a[1]], 0
            for shift in (0, 32, 64, 96):
                lane = (value >> shift) & MASK[4]
                if op == "pslld":
                    lane = (lane << row.b[1]) & MASK[4]
                else:
                    lane = ((lane - (1 << 32) if lane & SIGN[4] else lane) >> row.b[1]) & MASK[4]
                lanes |= lane << shift
            self.xmm[row.a[1]] = lanes
        elif op == "pandn":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] ^ ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "psrlq":
            value = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = ((value & MASK[8]) >> row.b[1]) | (((value >> 64) >> row.b[1]) << 64)
        elif op in ("addpd", "divpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                lanes.append(to_bits(one + two if op == "addpd" else fdiv(one, two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target != 5:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                if not to_float((left >> shift) & MASK[8]) < to_float((right >> shift) & MASK[8]):
                    value |= MASK[8] << shift
            self.xmm[row.a[1]] = value
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



FUNCTIONS = {'inner': 0x2f51d80, 'pair_drop': 0x3376ce0, 'pair_drop_copy': 0x2f07b30, 'promoted_drop': 0x2f07e00, 'option_pair_drop': 0x3999190, 'remaining_drop': 0x3378b40, 'bounded_scan': 0x3bd9ca0}
# External hook: this body was already used by previous work and is not selected.
SET_DROP = 0x33f3a90
SLOT_ALLOC = 0x576dfd8
SLOT_MEMCPY = 0x576dfe0
SLOT_MEMMOVE = 0x576e0e0
STOP_SLOTS = (0x576e470, 0x576e108, 0x576e020, 0x576e2e0, 0x576e010)
MARK_BASE = 0x7700000000
ARENA = HEAP_BASE + 0x10000
ARENA_END = HEAP_BASE + HEAP_SIZE
LAYOUT_INNER = dict(parent=0x210, value=0, width=48, key=0, key_width=0, edge=0x218, count=0x21a, children=0x220, leaf=0x220, internal=0x280)
LAYOUT_STAGE = LAYOUT_INNER

class Fixture:
    """Build and validate a concrete, ordered tree with checked backlinks."""
    def __init__(self, image, patches=None, fail_alloc_at=None, layout=None):
        self.layout = layout or LAYOUT_STAGE
        self.machine = Machine(image, patches)
        self.machine.real = frozenset()
        self.machine.memory.statics = {slot: MARK_BASE + slot for slot in
                                       (SLOT_ALLOC, SLOT_MEMCPY, SLOT_MEMMOVE) + STOP_SLOTS}
        self.machine.slots = {MARK_BASE + SLOT_ALLOC: self.on_alloc,
                              MARK_BASE + SLOT_MEMCPY: self.on_memcpy,
                              MARK_BASE + SLOT_MEMMOVE: self.on_copy}
        for slot in STOP_SLOTS:
            self.machine.slots[MARK_BASE + slot] = self.on_stop
        self.top = ARENA
        self.nodes = {}
        self.allocations = []
        self.fail_alloc_at = fail_alloc_at
        self.serial = 0
        self.keys = []
        self.selected = None
        self.insert_at = None

    def alloc(self, size):
        at = self.top
        self.top += (size + 15) & ~15
        if self.top > ARENA_END: raise Halt('fixture arena full')
        return at

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        if size not in (self.layout['leaf'], self.layout['internal']): raise Halt('unexpected node allocation')
        self.allocations.append(size)
        if self.fail_alloc_at == len(self.allocations):
            machine.regs[RAX] = 0
            return
        ptr = self.alloc(size)
        self.nodes[ptr] = size
        machine.regs[RAX] = ptr

    def on_memcpy(self, machine):
        dst, src, count = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        if count and dst < src + count and src < dst + count:
            raise Halt('overlapping memcpy')
        self.on_copy(machine)

    def on_copy(self, machine):
        count = machine.regs[RDX]
        machine.memory.copy(machine.regs[RDI], machine.regs[RSI], count)
        machine.regs[RAX] = machine.regs[RDI]

    def on_stop(self, machine):
        raise Panicked('failure sink reached at %#x' % machine.current_pc)

    def write(self, at, value, size=8):
        self.machine.memory.write(at, size, value)

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def data(self, at, size):
        return self.machine.memory.bytes_at(at, size)

    def put(self, at, data):
        self.machine.memory.put_bytes(at, data)

def model_insert(tree, path, gap, pair):
    """Independently model insertion, promotion and allocation shape."""
    def step(node, edges):
        old_pairs, old_children = node
        items, children = list(old_pairs), list(old_children)
        if children:
            edge = edges[0]
            promoted, left, right = step(children[edge], edges[1:])
            children[edge] = left
            if promoted is None:
                return None, (tuple(items), tuple(children)), None
            children.insert(edge+1, right)
            index = edge
            item = promoted
        else:
            index, item = gap, pair
        if len(items) < 11:
            items.insert(index, item)
            return None, (tuple(items), tuple(children)), None
        pivot = 4 if index < 5 else 5 if index <= 6 else 6
        promoted = items[pivot]
        items.insert(index, item)
        promoted_index = pivot + int(index <= pivot)
        if items[promoted_index] != promoted:
            raise Halt('invalid model promotion')
        left_children = children[:promoted_index+1] if children else ()
        right_children = children[promoted_index+1:] if children else ()
        left = (tuple(items[:promoted_index]), tuple(left_children))
        right = (tuple(items[promoted_index+1:]), tuple(right_children))
        return promoted, left, right
    promoted, left, right = step(tree, tuple(path))
    return ( (promoted,), (left, right) ) if promoted is not None else left


def model_position(tree, key, path=()):
    pairs, children = tree
    for i, (stored, _) in enumerate(pairs):
        if stored == key: return path, i
        if key < stored:
            return model_position(children[i], key, path+(i,)) if children else None
    return model_position(children[-1], key, path+(len(pairs),)) if children else None


def at(image, va, size):
    off = image.offset(va)
    sec = next(s for s in image.mapped if s['address'] <= va < s['address'] + s['size'])
    if va + size > sec['address'] + sec['size'] or off + size > len(image.blob):
        raise EvidenceError('byte range outside section')
    return image.blob[off:off+size]


def call_target(image, site):
    code = at(image, site, 5)
    if code[0] != 0xe8: raise EvidenceError('not a direct rel32 call')
    return site + 5 + struct.unpack_from('<i', code, 1)[0]


def inner_case(image, n, gap, fail_alloc_at=None, patches=None, corrupt_count=None,
               null_root=False, height_override=None, expect_panic=False):
    """Evaluate a synthetic leaf cursor; multiple elements are adversarial."""
    if not 0 <= n <= 11 or not 0 <= gap <= n:
        raise ValueError('invalid inner cursor')
    layout = LAYOUT_INNER
    f = Fixture(image, patches=patches, fail_alloc_at=fail_alloc_at, layout=layout)
    root = f.alloc(layout['leaf']); f.nodes[root] = layout['leaf']; f.put(root,bytes(layout['leaf']))
    values = [int.from_bytes(bytes(((7*i+j+1) % 256 for j in range(48))), 'little') for i in range(n)]
    for i, value in enumerate(values): f.write(root+48*i,value,48)
    f.write(root+layout['count'],n,2)
    root_desc=f.alloc(24); holder=f.alloc(8); cursor=f.alloc(24); out=f.alloc(24)
    value_ptr=f.alloc(48); depth_ptr=f.alloc(8)
    f.put(root_desc,bytes(24)); f.put(cursor,bytes(24)); f.put(out,bytes(24)); f.put(depth_ptr,bytes(8))
    f.write(root_desc,0 if null_root else root); f.write(root_desc+16,n); f.write(holder,root_desc)
    if height_override is not None: f.write(root_desc+8,height_override)
    f.write(cursor,root); f.write(cursor+16,gap)
    if corrupt_count is not None: f.write(root+layout['count'],corrupt_count,2)
    inserted = int.from_bytes(bytes((255-i for i in range(48))),'little')
    f.write(value_ptr,inserted,48)
    m=f.machine; m.code_window=[image.exact_fde(FUNCTIONS['inner'])]
    try:
        m.run(FUNCTIONS['inner'],{RDI:out,RSI:cursor,RDX:value_ptr,RCX:holder,R8:depth_ptr})
    except Panicked as error:
        if fail_alloc_at is None and not expect_panic: raise
        return {'panic':str(error),'allocations':f.allocations,'seen':m.seen,'branches':m.branches}
    if fail_alloc_at is not None or expect_panic: raise Halt('expected failure boundary')
    root_after, depth = f.read(root_desc), f.read(root_desc+8)
    if depth != int(n==11): raise Halt('inner root depth differs')
    seen_nodes=set(); actual=[]
    def walk(node, level, parent, edge):
        if node in seen_nodes or node not in f.nodes: raise Halt('bad inner node')
        seen_nodes.add(node)
        if f.read(node+layout['parent']) != parent: raise Halt('bad inner parent')
        if parent and f.read(node+layout['edge'],2) != edge: raise Halt('bad inner edge')
        count=f.read(node+layout['count'],2)
        if count>11: raise Halt('overfull inner node')
        for i in range(count+1):
            if level: walk(f.read(node+layout['children']+8*i),level-1,node,i)
            if i<count: actual.append(f.read(node+48*i,48))
    walk(root_after,depth,0,0)
    expected=values[:gap]+[inserted]+values[gap:]
    if actual != expected: raise Halt('inner sequence differs from insertion model')
    if f.read(root_desc+16) != n: raise Halt('helper changed descriptor length')
    node,returned_depth,index=(f.read(out+i*8) for i in range(3))
    if returned_depth or f.read(node+index*48,48) != inserted: raise Halt('inner cursor differs')
    allocations=[layout['leaf'],layout['internal']] if n==11 else []
    if f.allocations != allocations: raise Halt('inner allocation sequence differs')
    pivot=left_count=right_count=None
    if n==11:
        pivot=4 if gap<5 else 5 if gap<=6 else 6
        if f.read(root_after,48)!=values[pivot]: raise Halt('inner promoted element differs')
        left_count=f.read(f.read(root_after+layout['children'])+layout['count'],2)
        right_count=f.read(f.read(root_after+layout['children']+8)+layout['count'],2)
        if (left_count,right_count)!=(pivot+int(gap<=pivot),10-pivot+int(gap>pivot)):
            raise Halt('inner split shape differs')
    return {'count':len(actual),'depth':depth,'allocations':f.allocations,'returned_slot':index,
            'pivot':pivot,'left_count':left_count,'right_count':right_count,
            'seen':m.seen,'branches':m.branches,
            'sequence_sha256':hashlib.sha256(b''.join(v.to_bytes(48,'little') for v in actual)).hexdigest()}


def inner_tree_case(image, counts, edges, gap, corrupt_parent_count=None, expect_panic=False):
    """Exercise multi-level raw inner nodes; fixture reachability is unproven."""
    if not counts or len(counts)!=len(edges) or len(counts)>3:
        raise ValueError('invalid ancestor depth')
    if any(not 1<=n<=11 for n in counts) or any(not 0<=e<=n for e,n in zip(edges,counts)):
        raise ValueError('invalid ancestor shape')
    if not 0<=gap<=11: raise ValueError('invalid gap')
    layout=LAYOUT_INNER
    f=Fixture(image,layout=layout)
    serial=0
    by_value={}
    chosen=None
    def value_for_id(i):
        return int.from_bytes(hashlib.sha384(('inner-%d' % i).encode('ascii')).digest(),'little')
    def make(depth,count,path,parent,edge):
        nonlocal serial,chosen
        node=f.alloc(layout['internal'] if depth else layout['leaf'])
        f.nodes[node]=layout['internal'] if depth else layout['leaf']
        f.put(node,bytes(f.nodes[node])); f.write(node+layout['parent'],parent)
        f.write(node+layout['edge'],edge,2); f.write(node+layout['count'],count,2)
        if not depth and path==():
            if chosen is not None: raise Halt('multiple selected inner leaves')
            chosen=node
        pairs=[]; children=[]
        for i in range(count+1):
            if depth:
                selected=path is not None and path[0]==i
                child_path=path[1:] if selected else None
                child_count=counts[len(counts)-depth+1] if selected and depth>1 else 11 if selected else 5
                child,child_tree=make(depth-1,child_count,child_path,node,i)
                f.write(node+layout['children']+8*i,child); children.append(child_tree)
            if i<count:
                serial+=2; value=value_for_id(serial)
                if value in by_value: raise Halt('fixture value collision')
                by_value[value]=serial
                f.write(node+48*i,value,48); pairs.append((serial,value))
        return node,(tuple(pairs),tuple(children))
    root,initial=make(len(edges),counts[0],tuple(edges),0,0)
    if chosen is None: raise Halt('inner selected leaf missing')
    old_values=[f.read(chosen+48*i,48) for i in range(11)]
    newkey=by_value[old_values[gap]]-1 if gap<11 else by_value[old_values[-1]]+1
    inserted=value_for_id(newkey)
    if inserted in by_value: raise Halt('inner inserted value collision')
    by_value[inserted]=newkey
    expected=model_insert(initial,edges,gap,(newkey,inserted))
    root_desc=f.alloc(24); holder=f.alloc(8); cursor=f.alloc(24); out=f.alloc(24)
    valptr=f.alloc(48); depthptr=f.alloc(8)
    for ptr,size in ((root_desc,24),(holder,8),(cursor,24),(out,24),(depthptr,8)):
        f.put(ptr,bytes(size))
    f.write(root_desc,root); f.write(root_desc+8,len(edges)); f.write(root_desc+16,serial//2)
    f.write(holder,root_desc); f.write(cursor,chosen); f.write(cursor+16,gap); f.write(valptr,inserted,48)
    if corrupt_parent_count is not None:
        parent=f.read(chosen+layout['parent'])
        f.write(parent+layout['count'],corrupt_parent_count,2)
    m=f.machine; m.code_window=[image.exact_fde(FUNCTIONS['inner'])]
    try:
        m.run(FUNCTIONS['inner'],{RDI:out,RSI:cursor,RDX:valptr,RCX:holder,R8:depthptr})
    except Panicked as error:
        if not expect_panic: raise
        return {'panic':str(error),'allocations':f.allocations,'seen':m.seen,'branches':m.branches}
    if expect_panic: raise Halt('expected failure boundary')
    newroot,newdepth=f.read(root_desc),f.read(root_desc+8)
    seen_nodes=set(); positions={}
    def snapshot(node,level,parent,edge,path):
        if node in seen_nodes or node not in f.nodes: raise Halt('invalid inner tree node')
        seen_nodes.add(node)
        if f.nodes[node] != (layout['internal'] if level else layout['leaf']): raise Halt('inner allocation shape')
        if f.read(node+layout['parent'])!=parent: raise Halt('inner parent backlink')
        if parent and f.read(node+layout['edge'],2)!=edge: raise Halt('inner parent edge')
        count=f.read(node+layout['count'],2)
        if count>11: raise Halt('overfull inner node')
        pairs=[]; children=[]
        for i in range(count+1):
            if level:
                children.append(snapshot(f.read(node+layout['children']+8*i),level-1,node,i,path+(i,)))
            if i<count:
                value=f.read(node+48*i,48)
                if value not in by_value or value in positions: raise Halt('missing or duplicate inner payload')
                positions[value]=(node,path,i)
                pairs.append((by_value[value],value))
        return tuple(pairs),tuple(children)
    actual=snapshot(newroot,newdepth,0,0,())
    if actual!=expected: raise Halt('inner tree differs from independent model')
    if f.read(root_desc+16)!=serial//2: raise Halt('helper changed descriptor length')
    node,returned_depth,index=(f.read(out+8*i) for i in range(3))
    stored,path,stored_index=positions[inserted]
    if returned_depth or (node,index)!=(stored,stored_index): raise Halt('inner returned cursor mismatch')
    if (path,index)!=model_position(expected,newkey): raise Halt('inner model position mismatch')
    expected_allocations=[layout['leaf']]
    for count in reversed(counts):
        if count!=11: break
        expected_allocations.append(layout['internal'])
    else:
        expected_allocations.append(layout['internal'])
    if f.allocations!=expected_allocations: raise Halt('inner allocation sequence mismatch')
    if newdepth!=len(edges)+int(all(n==11 for n in counts)): raise Halt('inner height mismatch')
    return {'count':len(positions),'depth':newdepth,'allocations':f.allocations,'returned_slot':index,
            'tree_sha256':hashlib.sha256(repr(actual).encode('ascii')).hexdigest(),
            'seen':m.seen,'branches':m.branches}



def lsda_records(image, role):
    """Decode only zPLR's observed ULEB call-site tables; reject other forms."""
    from fde_extents import uleb
    fde=image.fde_records[FUNCTIONS[role]];start,end=fde['start'],fde['end'];va=fde['lsda']
    if va is None: raise EvidenceError('missing LSDA: '+role)
    matches=[s for s in image.sections if s['name']=='.gcc_except_table' and s['type']!=8]
    if len(matches)!=1:raise EvidenceError('missing exception section')
    sec=matches[0]
    if not sec['address']<=va<sec['address']+sec['size']:raise EvidenceError('LSDA outside section')
    pos=image.offset(va);origin=pos;limit=sec['offset']+sec['size']
    if image.blob[pos] != 0xff: raise EvidenceError('unsupported landing base')
    pos += 1
    type_encoding=image.blob[pos]; pos += 1
    if type_encoding == 0x9b:
        type_offset,pos=uleb(image.blob,pos,limit)
        if pos+type_offset>limit: raise EvidenceError('LSDA type table outside section')
    elif type_encoding != 0xff: raise EvidenceError('unsupported LSDA type encoding')
    if image.blob[pos] != 1: raise EvidenceError('unsupported LSDA call-site encoding')
    pos+=1;length,pos=uleb(image.blob,pos,limit);stop=pos+length
    if stop>limit:raise EvidenceError('LSDA outside section')
    result=[];previous=start
    while pos<stop:
        rowpos=pos
        off,pos=uleb(image.blob,pos,stop);size,pos=uleb(image.blob,pos,stop)
        landing,pos=uleb(image.blob,pos,stop);action,pos=uleb(image.blob,pos,stop)
        a=start+off;b=a+size;target=start+landing if landing else None
        if not start<=a<=b<=end or a<previous or (target is not None and not start<=target<end):
            raise EvidenceError('invalid LSDA call-site range')
        result.append((va+rowpos-origin,image.blob[rowpos:pos].hex(),a,b,target,action));previous=b
    return result


def relocation_records(image, wanted):
    def section(name):
        result=[x for x in image.sections if x['name']==name and x['type']!=8]
        if len(result)!=1:raise EvidenceError('missing or duplicate section '+name)
        return result[0]
    syms=section('.dynsym');strings=section('.dynstr')
    if syms['type']!=11 or strings['type']!=3 or syms['size']%24:
        raise EvidenceError('invalid dynamic symbol table')
    result={}
    for section_name in ('.rela.dyn','.rela.plt'):
        rel=section(section_name)
        if rel['type']!=4 or rel['size']%24:raise EvidenceError('invalid relocation section')
        for off in range(rel['offset'],rel['offset']+rel['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',image.blob,off)
            if slot not in wanted:continue
            if slot in result:raise EvidenceError('duplicate relocation for selected slot')
            kind,index=info&0xffffffff,info>>32;name=''
            if index:
                if index*24+24>syms['size']:raise EvidenceError('symbol out of range')
                noff=struct.unpack_from('<I',image.blob,syms['offset']+index*24)[0]
                if noff>=strings['size']:raise EvidenceError('symbol name out of range')
                begin=strings['offset']+noff;end=image.blob.find(b'\0',begin,strings['offset']+strings['size'])
                if end<0:raise EvidenceError('unterminated symbol')
                name=image.blob[begin:end].decode('ascii')
            result[slot]=(section_name,kind,index,addend,name)
    if set(result)!=set(wanted):raise EvidenceError('selected relocation missing')
    return result


def unwind_slot(image):
    code=at(image,0x5660110,6)
    if code[:2]!=b'\xff\x25':raise EvidenceError('unexpected unwind PLT instruction')
    return 0x5660116+struct.unpack_from('<i',code,2)[0]


def write_tsv(path, columns, rows):
    with path.open('w',encoding='utf-8',newline='') as handle:
        writer=csv.writer(handle,delimiter='\t',lineterminator='\n')
        writer.writerow(columns);writer.writerows(rows)



BODY_HASHES = {
    'bounded_scan': '9a278f6b724a196992150bef844bedb4447d2f62c561bfefc83d8085cf81fb58',
    'inner': '7c32dded53167bde2bff672214b6984cbf6783f3146edc4ac5ed4fee3efd89a9',
    'pair_drop': 'aa8d614e37cdcb71a0ae08fe1a80cab002b54366c38ebbab228fdbcb725deb5a',
    'pair_drop_copy': '1f53bf335488cf46d90155ce06a15baf1669d22e70e9cac872e842e35351a794',
    'promoted_drop': '9b08c3b947e1c270f10499abb81c026c45894f9753dcdc53d3b64b180bdf4f50',
    'option_pair_drop': '4b11b739600f15e79a6d3d32927157ad8f9aa2119fbb61d5ca0028c12a8410ab',
    'remaining_drop': 'ef41931ecee29992eb619a214f4debff02ffba0cb1362dab5c43ac20af88e5d0',
}


CONTEXT_PINS = (
    ('tracker_length_load',0x3946914,'498b442438'),
    ('tracker_threshold',0x3946919,'4883f865'),
    ('skip_below_threshold',0x394691d,'0f82a0000000'),
    ('collector_limit',0x3946984,'48c78424b800000064000000'),
    ('result_capacity_load',0x39469a2,'488bb424e0000000'),
    ('result_nonzero_test',0x39469aa,'4885f6'),
    ('result_pointer_load',0x39469af,'488bbc24e8000000'),
    ('release_byte_count',0x39469b7,'48c1e603'),
    ('vector_release_call',0x39469bd,'ff154d76e201'),
    ('after_scan',0x39469c3,'488b8c2470020000'),
)


def validate_image(image):
    for role,va in FUNCTIONS.items():
        start,end=image.exact_fde(va)
        if hashlib.sha256(at(image,start,end-start)).hexdigest()!=BODY_HASHES[role]:
            raise EvidenceError('body hash mismatch: '+role)
    for name,va,want in CONTEXT_PINS:
        if at(image,va,len(bytes.fromhex(want))).hex()!=want:
            raise EvidenceError('context pin mismatch: '+name)
    for site,target in ((0x33c02b2,FUNCTIONS['inner']),
                        (0x33c03c6,FUNCTIONS['pair_drop']),
                        (0x33f59e1,FUNCTIONS['remaining_drop']),
                        (0x3946a6d,FUNCTIONS['option_pair_drop']),
                        (0x394699d,FUNCTIONS['bounded_scan'])):
        if call_target(image,site)!=target:raise EvidenceError('context transfer mismatch')


class DropHarness:
    """Records calls into an external set destructor; it does not simulate that destructor."""
    def __init__(self,image,patches=None):
        self.m=Machine(image,patches);self.next=ARENA;self.calls=[]
        self.m.calls[SET_DROP]=self.drop
    def alloc(self,size):
        p=self.next;self.next+=(size+15)&~15
        if self.next>ARENA_END:raise Halt('fixture arena full')
        self.m.memory.put_bytes(p,bytes(size));return p
    def w(self,p,size,v):self.m.memory.write(p,size,v)
    def put(self,p,data):self.m.memory.put_bytes(p,data)
    def drop(self,m):
        p=m.regs[RDI]
        self.calls.append((p,m.memory.bytes_at(p,24)))


def descriptor(tag):
    return bytes(((tag*23+i*7+1)&255 for i in range(24)))


def drop_case(image,role,flag=1,patches=None):
    if role not in ('pair_drop','pair_drop_copy','promoted_drop','option_pair_drop'):
        raise ValueError('unknown cleanup role')
    if not 0<=flag<=255:raise ValueError('invalid option tag')
    f=DropHarness(image,patches);option=role=='option_pair_drop'
    obj=f.alloc(56 if option else 48);base=obj+8 if option else obj
    if option:f.w(obj,1,flag)
    f.put(base,descriptor(1));f.put(base+24,descriptor(2))
    m=f.m;m.code_window=[image.exact_fde(FUNCTIONS[role])]
    m.run(FUNCTIONS[role],{RDI:obj})
    observed=[(p-obj,raw) for p,raw in f.calls]
    expected=[] if option and not flag else [(base-obj,descriptor(1)),(base+24-obj,descriptor(2))]
    if observed!=expected:raise Halt('pair cleanup arguments or order differ')
    return dict(role=role,flag=flag,offsets=','.join(str(p) for p,_ in observed),
                calls=len(observed),seen=m.seen,branches=m.branches)


def remaining_case(image,row_count,patches=None):
    if not 0<=row_count<=16:raise ValueError('invalid synthetic row count')
    f=DropHarness(image,patches);iterator=f.alloc(8);rows=f.alloc(max(1,row_count)*48)
    for i in range(row_count):
        f.put(rows+48*i,descriptor(2*i+1));f.put(rows+48*i+24,descriptor(2*i+2))
    cursor=[0];fetches=[0]
    def next_row(m):
        if m.regs[RSI]!=iterator:raise Halt('wrong iterator argument')
        out=m.regs[RDI];fetches[0]+=1
        if cursor[0]<row_count:
            m.memory.write(out,8,rows);m.memory.write(out+16,8,cursor[0]);cursor[0]+=1
        else:m.memory.write(out,8,0)
    m=f.m;m.calls[0x33ae610]=next_row
    m.code_window=[image.exact_fde(FUNCTIONS['remaining_drop'])]
    m.run(FUNCTIONS['remaining_drop'],{RDI:iterator})
    expected=[(rows+48*i+24*j,descriptor(2*i+j+1)) for i in range(row_count) for j in range(2)]
    if f.calls!=expected:raise Halt('remaining-row destructor arguments or order differ')
    if fetches[0]!=row_count+1:raise Halt('wrong iterator fetch count')
    return dict(rows=row_count,fetches=fetches[0],calls=len(f.calls),seen=m.seen,branches=m.branches)


def chain_case(image,n,gap):
    """Project removal after insertion and run the two-descriptor cleanup wrapper."""
    if not 0<=n<=11 or not 0<=gap<=n:raise ValueError('invalid chain cursor')
    f=Fixture(image,layout=LAYOUT_INNER)
    root=f.alloc(0x220);f.nodes[root]=0x220;f.put(root,bytes(0x220));f.write(root+0x21a,n,2)
    # Old rows are opaque here; the inserted pair has independently marked fields.
    for i in range(n):f.put(root+48*i,bytes([i+1])*48)
    desc=f.alloc(24);holder=f.alloc(8);cursor=f.alloc(24);out=f.alloc(24);value=f.alloc(48);depthptr=f.alloc(8)
    for p,size in ((desc,24),(holder,8),(cursor,24),(out,24),(depthptr,8)):f.put(p,bytes(size))
    f.write(desc,root);f.write(desc+16,n);f.write(holder,desc);f.write(cursor,root);f.write(cursor+16,gap)
    payload=descriptor(1)+descriptor(2);f.put(value,payload)
    m=f.machine;m.code_window=[image.exact_fde(FUNCTIONS['inner'])]
    m.run(FUNCTIONS['inner'],{RDI:out,RSI:cursor,RDX:value,RCX:holder,R8:depthptr})
    node,level,index=(f.read(out+8*j) for j in range(3));pair=node+index*48
    if level or f.data(pair,48)!=payload:raise Halt('returned payload mismatch')
    if f.read(desc+16)!=n:raise Halt('inner helper changed map length')
    calls=[]
    def drop(machine):
        p=machine.regs[RDI];calls.append((p,machine.memory.bytes_at(p,24)))
    m.calls[SET_DROP]=drop;m.code_window=[image.exact_fde(FUNCTIONS['pair_drop'])]
    m.run(FUNCTIONS['pair_drop'],{RDI:pair})
    if calls!=[(pair,descriptor(1)),(pair+24,descriptor(2))]:
        raise Halt('projected cleanup lost descriptor ownership')
    return dict(count=n,gap=gap,height=f.read(desc+8),slot=index,
                allocations=f.allocations,calls=len(calls),seen=m.seen,branches=m.branches)


class ResumeObserved(Exception):
    pass


def landing_case(image,role):
    """Enter a call-site-table landing with projected registers and stubbed set drops."""
    configuration={
        'inner': (0x2f527fa,0x2f52894,'both',R12),
        'pair_drop': (0x3376ce7,0x3376cff,'second',RBX),
        'pair_drop_copy': (0x2f07b37,0x2f07b4f,'second',RBX),
        'promoted_drop': (0x2f07e07,0x2f07e1f,'second',RBX),
        'option_pair_drop': (0x39991a0,0x39991c0,'second_option',RBX),
        'remaining_drop': (0x3378b83,0x3378bb3,'second',R15),
    }
    if role not in configuration:raise ValueError('unknown landing')
    failure,landing,operation,reg=configuration[role]
    matches=[r for r in lsda_records(image,role) if r[2]<=failure<r[3]]
    if len(matches)!=1 or matches[0][4]!=landing or matches[0][5]!=0:
        raise EvidenceError('landing not bound by LSDA')
    f=DropHarness(image);obj=f.alloc(56 if operation=='second_option' else 48)
    base=obj+8 if operation=='second_option' else obj
    f.put(base,descriptor(1));f.put(base+24,descriptor(2));m=f.m;token=0x334455667788
    m.regs=[0]*16;m.regs[RSP]=STACK_TOP-0x400;m.regs[reg]=obj;m.regs[RAX]=token
    def resume(machine):
        if machine.regs[RDI]!=token:raise Halt('exception token not forwarded')
        raise ResumeObserved()
    m.calls[0x5660110]=resume
    m.real=frozenset(FUNCTIONS[x] for x in ('pair_drop','pair_drop_copy','promoted_drop'))
    windows=[image.exact_fde(FUNCTIONS[k]) for k in (role,'pair_drop','pair_drop_copy','promoted_drop')]
    pc=landing
    for _ in range(10000):
        if not any(a<=pc<b for a,b in windows):raise Halt('landing left selected functions')
        row=decode(m.read_code,pc);m.current_pc=pc;m.seen.add(pc)
        try:pc=m.step(row)
        except ResumeObserved:break
    else:raise Halt('landing step limit')
    expected=([(base,descriptor(1))] if operation=='both' else [])+[(base+24,descriptor(2))]
    if f.calls!=expected:raise Halt('landing destructor arguments or order differ')
    return dict(role=role,failure=failure,landing=landing,calls=len(f.calls),
                offsets=','.join(str(p-obj) for p,_ in f.calls),seen=m.seen,branches=m.branches)


def scan_case(image, node_count, depth, limit, declared=None, allocation_failure=False, patches=None, extra=0):
    """Interpret the capped pointer collector on a synthetic zero-key tree."""
    if not 0<=node_count<=11 or depth not in (0,1) or not 0<=limit<=((1<<64)-1):
        raise ValueError('invalid scan fixture')
    if depth and not node_count: raise ValueError('empty internal fixture')
    if extra not in (0,1,2) or (extra and (depth!=1 or node_count+extra>11)):
        raise ValueError('invalid extra leaf values')
    f=DropHarness(image,patches);m=f.m;out=f.alloc(24);iterator=f.alloc(80);expected=[]
    def node(level,parent,edge):
        p=f.alloc(0x1d0 if level else 0x170)
        count=node_count+(extra if not level and edge==0 and depth else 0)
        f.w(p+0x160,8,parent);f.w(p+0x168,2,edge);f.w(p+0x16a,2,count)
        for j in range(count+1):
            if level:
                child=node(level-1,p,j);f.w(p+0x170+8*j,8,child)
            if j<count:expected.append(p+0x16c)
        return p
    root=node(depth,0,0) if node_count else 0
    actual=len(expected);amount=actual if declared is None else declared
    if not 0<=amount<=((1<<64)-1):raise ValueError('invalid declared length')
    f.w(iterator,8,int(bool(root)));f.w(iterator+0x10,8,root);f.w(iterator+0x18,8,depth)
    f.w(iterator+0x20,8,int(bool(root)));f.w(iterator+0x30,8,root);f.w(iterator+0x38,8,depth)
    f.w(iterator+0x40,8,amount);f.w(iterator+0x48,8,limit)
    allocations=[]
    def alloc(machine):
        size=machine.regs[RDI];allocations.append(size)
        machine.regs[RAX]=0 if allocation_failure else f.alloc(size)
    def stop(machine):raise Panicked('failure sink reached at %#x'%machine.current_pc)
    m.memory.statics.update({0x576dfd8:MARK_BASE+0x576dfd8,0x576dfb8:MARK_BASE+0x576dfb8,
                             0x576e470:MARK_BASE+0x576e470})
    m.slots.update({MARK_BASE+0x576dfd8:alloc,MARK_BASE+0x576dfb8:stop,MARK_BASE+0x576e470:stop})
    m.code_window=[image.exact_fde(FUNCTIONS['bounded_scan'])]
    try:m.run(FUNCTIONS['bounded_scan'],{RDI:out,RSI:iterator})
    except Panicked as exc:
        if not allocation_failure and declared is None:raise
        return dict(panic=str(exc),allocations=allocations,seen=m.seen,branches=m.branches)
    if allocation_failure:raise Halt('scan allocation failure did not reach boundary')
    capacity=m.memory.read(out,8);ptr=m.memory.read(out+8,8);length=m.memory.read(out+16,8)
    # Comparison uses actual tree order, not the collector's output bytes.
    if declared is None:
        count=min(actual,limit)
        if capacity!=count or length!=count:raise Halt('scan length or capacity differs')
        values=[m.memory.read(ptr+8*j,8) for j in range(length)]
        if values!=expected[:count]:raise Halt('scan pointer order differs')
        expected_alloc=[] if not count else [8*count]
        if allocations!=expected_alloc:raise Halt('scan allocation size differs')
    return dict(rows=actual,limit=limit,capacity=capacity,length=length,allocations=allocations,
                seen=m.seen,branches=m.branches)


def observe_controls(image):
    controls=(
        ('split_capacity_11_to_10',lambda:inner_case(image,10,5,patches={0x2f51da1:10})),
        ('pair_second_offset_24_to_16',lambda:drop_case(image,'pair_drop',patches={0x3376cef:16})),
        ('option_zero_branch_inverted',lambda:drop_case(image,'option_pair_drop',flag=0,patches={0x3999197:0x75})),
        ('remaining_row_stride_changed',lambda:remaining_case(image,2,patches={0x3378b7c:3})),
        ('scan_minimum_inverted',lambda:scan_case(image,10,1,100,patches={0x3bd9cbb:0x47})),
        ('scan_pointer_offset_changed',lambda:scan_case(image,10,1,100,patches={0x3bd9d5c:0x6d})),
    )
    rows=[]
    for name,case in controls:
        try:case()
        except (Halt,Panicked,EvidenceError) as exc:rows.append((name,'rejected',str(exc)))
        else:raise Halt('mutation survived: '+name)
    return rows


def generate(image,out):
    validate_image(image);out.mkdir(parents=True,exist_ok=True)
    reached=set();outcomes=set()
    def record(result):
        reached.update(result.pop('seen'));outcomes.update(result.pop('branches'));return result
    funcs=[];instructions=[];branches=[];transfers=[];lsdas=[];decoded_by_role={}
    for role,va in FUNCTIONS.items():
        start,end=image.exact_fde(va);fde=image.fde_records[va];raw=at(image,start,end-start)
        rows=decode_range(image,start,end);decoded_by_role[role]=rows
        funcs.append((role,hex(start),hex(end),hex(image.offset(start)),len(raw),hex(fde['fde']),hex(fde['cie']),hex(fde['lsda']),hashlib.sha256(raw).hexdigest()))
        for row in rows:
            instructions.append((role,hex(row.va),row.data.hex(),row.op))
            if row.op=='jcc':branches.append((role,hex(row.va),row.data.hex(),row.cc,hex(row.target),hex(row.next)))
            if row.op in ('call','calli','jmp','jmpi'):
                target=hex(row.target) if row.target is not None else '';operand=''
                if row.target is None and row.a:
                    if row.a[0]=='m' and row.a[1] is None and row.a[2] is None:operand=hex(row.a[4])
                    elif row.a[0]=='r':operand='register-%d'%row.a[1]
                    else:operand='other-memory'
                transfers.append((role,hex(row.va),row.data.hex(),row.op,target,operand))
        for pos,raw_bytes,begin,end_,landing,action in lsda_records(image,role):
            lsdas.append((role,hex(pos),raw_bytes,hex(begin),hex(end_),hex(landing) if landing else '',action))
    contexts=[]
    for name,site in (('vote_store_to_adapter',0x394669f),('vote_bucket_insert',0x33c02b2),('adapter_failure_pair',0x33c03c6),('bucket_cleanup_remaining',0x33f59e1),('vote_unwind_pair',0x3946a6d),('bounded_scan',0x394699d)):
        contexts.append((name,hex(site),hex(image.offset(site)),at(image,site,5).hex(),hex(call_target(image,site))))
    leaf_rows=[];deep_rows=[];drop_rows=[];remaining_rows=[];chain_rows=[];landing_rows=[];failure_rows=[];scan_rows=[];scan_failure_rows=[]
    for n in range(12):
        for gap in range(n+1):
            r=record(inner_case(image,n,gap))
            leaf_rows.append((n,gap,r['depth'],','.join(map(str,r['allocations'])),r['returned_slot'],
                              '' if r['pivot'] is None else r['pivot'],'' if r['left_count'] is None else r['left_count'],
                              '' if r['right_count'] is None else r['right_count'],r['sequence_sha256']))
            r=record(chain_case(image,n,gap))
            chain_rows.append((n,gap,r['height'],','.join(map(str,r['allocations'])),r['slot'],r['calls']))
    for n in (1,5,10,11):
        for edge in range(n+1):
            for gap in range(12):
                r=record(inner_tree_case(image,[n],[edge],gap))
                deep_rows.append((str(n),str(edge),gap,r['depth'],','.join(map(str,r['allocations'])),r['returned_slot'],r['tree_sha256']))
    for upper in (0,5,11):
        for lower in (0,5,11):
            for gap in range(12):
                r=record(inner_tree_case(image,[11,11],[upper,lower],gap))
                deep_rows.append(('11,11','%d,%d'%(upper,lower),gap,r['depth'],','.join(map(str,r['allocations'])),r['returned_slot'],r['tree_sha256']))
    for role in ('pair_drop','pair_drop_copy','promoted_drop','option_pair_drop'):
        for flag in ((0,1,2,255) if role=='option_pair_drop' else (1,)):
            r=record(drop_case(image,role,flag))
            drop_rows.append((role,flag,r['calls'],r['offsets']))
    for count in (0,1,2,5,11):
        r=record(remaining_case(image,count));remaining_rows.append((count,r['fetches'],r['calls']))
    for role in ('inner','pair_drop','pair_drop_copy','promoted_drop','option_pair_drop','remaining_drop'):
        r=record(landing_case(image,role))
        landing_rows.append((role,hex(r['failure']),hex(r['landing']),r['calls'],r['offsets']))
    for label,fn in (
        ('split_leaf_allocation',lambda:inner_case(image,11,5,fail_alloc_at=1)),
        ('split_root_allocation',lambda:inner_case(image,11,5,fail_alloc_at=2)),
        ('null_root_descriptor',lambda:inner_case(image,11,5,null_root=True,expect_panic=True)),
        ('height_overflow',lambda:inner_case(image,11,5,height_override=(1<<64)-1,expect_panic=True))):
        r=record(fn());site=int(r['panic'].rsplit(' ',1)[1],16)
        matching=[x for x in lsda_records(image,'inner') if x[2]<=site<x[3]]
        if len(matching)!=1:raise EvidenceError('failure not uniquely described by LSDA')
        match=matching[0]
        failure_rows.append((label,hex(site),hex(match[4]) if match[4] else '',match[5],','.join(map(str,r['allocations']))))
    for n,depth,extra in ((0,0,0),(1,0,0),(2,0,0),(9,1,0),(9,1,1),(9,1,2),(10,1,0),(11,1,0)):
        for limit in (0,1,99,100,101,200):
            r=record(scan_case(image,n,depth,limit,extra=extra))
            scan_rows.append((n,depth,extra,r['rows'],limit,r['capacity'],r['length'],','.join(map(str,r['allocations']))))
    for name,kw,limit in (('allocation_failure',{'allocation_failure':True},100),
                          ('inconsistent_length',{'declared':1000},100),
                          ('capacity_overflow',{'declared':1<<63},1<<63)):
        r=record(scan_case(image,1,0,limit,**kw))
        if 'panic' not in r:raise Halt('scan failure boundary was not reached')
        site=int(r['panic'].rsplit(' ',1)[1],16)
        matching=[x for x in lsda_records(image,'bounded_scan') if x[2]<=site<x[3]]
        if len(matching)!=1:raise EvidenceError('scan failure not uniquely covered')
        scan_failure_rows.append((name,hex(site),hex(matching[0][4]) if matching[0][4] else '',matching[0][5],','.join(map(str,r['allocations']))))
    pins=[]
    for name,va,want in CONTEXT_PINS:
        raw=at(image,va,len(bytes.fromhex(want)))
        pins.append((name,hex(va),hex(image.offset(va)),raw.hex()))
    controls=observe_controls(image);coverage=[]
    for role,rows in decoded_by_role.items():
        cond=[r for r in rows if r.op=='jcc']
        coverage.append((role,len(rows),sum(r.va in reached for r in rows),len(cond),
                         sum(any((r.va,t) in outcomes for t in (False,True)) for r in cond),
                         sum(all((r.va,t) in outcomes for t in (False,True)) for r in cond)))
    slot=unwind_slot(image)
    wanted=(SLOT_ALLOC,SLOT_MEMCPY,SLOT_MEMMOVE,0x576e010,0x576e020,0x576e108,0x576e128,0x576e2e0,0x576e470,0x576dfb8,slot)
    rel=relocation_records(image,wanted)
    if rel[slot][4]!='_Unwind_Resume':raise EvidenceError('wrong unwind relocation')
    if rel[SLOT_MEMCPY][4]!='memcpy' or rel[SLOT_MEMMOVE][4]!='memmove':raise EvidenceError('wrong copy relocations')
    write_tsv(out/'functions.tsv',('role','start_va','end_va_exclusive','file_offset','bytes','fde_va','cie_va','lsda_va','sha256'),funcs)
    write_tsv(out/'instructions.tsv',('role','va','bytes','decoded_operation'),instructions)
    write_tsv(out/'branches.tsv',('role','va','bytes','condition_code','taken_va','fallthrough_va'),branches)
    write_tsv(out/'transfers.tsv',('role','va','bytes','operation','target_va','indirect_operand'),transfers)
    write_tsv(out/'pins.tsv',('role','va','file_offset','bytes'),pins)
    write_tsv(out/'scan-cases.tsv',('node_count','depth','extra','rows','limit','capacity','length','alloc_sizes'),scan_rows)
    write_tsv(out/'scan-failures.tsv',('case','failure_site','lsda_landing','action','alloc_sizes'),scan_failure_rows)
    write_tsv(out/'context.tsv',('role','call_va','file_offset','bytes','target_va'),contexts)
    write_tsv(out/'lsda.tsv',('role','record_va','bytes','start_va','end_va_exclusive','landing_va','action'),lsdas)
    write_tsv(out/'relocations.tsv',('slot_va','section','type','symbol_index','addend','symbol'),[(hex(k),*rel[k]) for k in sorted(rel)])
    write_tsv(out/'leaf-cases.tsv',('old_count','gap','height','alloc_sizes','returned_slot','promoted_old_slot','left_count','right_count','value_sequence_sha256'),leaf_rows)
    write_tsv(out/'deep-cases.tsv',('parent_counts','parent_edges','leaf_gap','height','alloc_sizes','returned_slot','tree_sha256'),deep_rows)
    write_tsv(out/'chain-cases.tsv',('old_count','gap','outer_height','alloc_sizes','returned_slot','external_drop_calls'),chain_rows)
    write_tsv(out/'drop-cases.tsv',('role','option_tag','external_drop_calls','argument_offsets'),drop_rows)
    write_tsv(out/'remaining-cases.tsv',('rows','iterator_calls','external_drop_calls'),remaining_rows)
    write_tsv(out/'landing-cases.tsv',('role','failure_site','landing_va','external_drop_calls','argument_offsets'),landing_rows)
    write_tsv(out/'failure-cases.tsv',('case','failure_site','lsda_landing','action','alloc_sizes'),failure_rows)
    write_tsv(out/'mutations.tsv',('case','outcome','reason'),controls)
    write_tsv(out/'coverage.tsv',('role','linear_instructions','reached_instructions','linear_conditional_sites','reached_conditional_sites','both_outcomes'),coverage)
    summary={'target_sha256':SHA256,'functions':len(funcs),'linear_instructions':len(instructions),
             'conditional_sites':len(branches),'lsda_records':len(lsdas),'leaf_cases':len(leaf_rows),
             'deep_cases':len(deep_rows),'chain_cases':len(chain_rows),'drop_cases':len(drop_rows),
             'remaining_cases':len(remaining_rows),'landing_cases':len(landing_rows),'failure_cases':len(failure_rows),
             'mutations_rejected':len(controls),'relocations':len(rel),'context_edges':len(contexts),
             'scan_cases':len(scan_rows),'scan_failure_cases':len(scan_failure_rows),'context_pins':len(pins)}
    (out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(generate(load_image(),args.out),sort_keys=True))


if __name__=='__main__':
    try:main()
    except (EvidenceError,Halt,Panicked,OSError,ValueError,struct.error) as error:
        print('staking_vote_bucket94: '+str(error),file=sys.stderr)
        sys.exit(1)

# MIT License
#
# Copyright (c) 2026 Hyperliquid Source contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
