#!/usr/bin/env python3
"""Static evaluator for the node 94 vote-jail tracker insertion path.

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
            if self.code_window is not None and not self.code_window[0] <= pc < self.code_window[1]:
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



FUNCTIONS = {'outer': 0x2f3d5c0, 'inner': 0x2f9cc50}
SLOT_ALLOC = 0x576dfd8
SLOT_MEMCPY = 0x576dfe0
SLOT_MEMMOVE = 0x576e0e0
STOP_SLOTS = (0x576e470, 0x576e108, 0x576e020, 0x576e2e0, 0x576e010)
MARK_BASE = 0x7700000000
ARENA = HEAP_BASE + 0x10000
ARENA_END = HEAP_BASE + HEAP_SIZE
LAYOUT_OUTER = dict(parent=0x160, value=0, width=32, key=0x168, key_width=20, edge=0x244, count=0x246, children=0x248, leaf=0x248, internal=0x2a8)
LAYOUT_INNER = dict(parent=0x210, value=0, width=48, key=0, key_width=0, edge=0x218, count=0x21a, children=0x220, leaf=0x220, internal=0x280)
LAYOUT_STAGE = LAYOUT_OUTER

def value_for_key(key, width):
    return (key * 13 + 0x1122334455667788) & ((1 << (width * 8)) - 1)


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

    def key(self, at):
        return int.from_bytes(self.data(at, self.layout['key_width']), 'big')

    def build(self, internal_counts, edges, leaf_count, leaf_slot):
        # Separate selected path is marked by assigning tuples; ordinary
        # branches use None.  A leaf with path == () is the selected leaf.
        if len(internal_counts) != len(edges) or len(edges) > 3:
            raise ValueError('invalid depth')
        if not 0 <= leaf_count <= 11 or not 0 <= leaf_slot <= leaf_count:
            raise ValueError('invalid leaf position')
        if any(not 1 <= n <= 11 for n in internal_counts):
            raise ValueError('invalid internal count')
        if any(not 0 <= edge <= n for edge, n in zip(edges, internal_counts)):
            raise ValueError('invalid child index')
        self.expected_count = 0
        self.selected = None
        def make(depth, count, remaining_edges, parent=0, edge=0):
            ptr = self.alloc(self.layout['internal'] if depth else self.layout['leaf'])
            self.nodes[ptr] = self.layout['internal'] if depth else self.layout['leaf']
            self.put(ptr, bytes(self.nodes[ptr]))
            self.write(ptr+self.layout['parent'], parent)
            self.write(ptr+self.layout['edge'], edge, 2)
            self.write(ptr+self.layout['count'], count, 2)
            is_target_leaf = depth == 0 and remaining_edges == ()
            if is_target_leaf:
                if self.selected is not None: raise Halt('multiple target leaves')
                self.selected = ptr
            for i in range(count+1):
                if depth:
                    match = remaining_edges is not None and remaining_edges[0] == i
                    child_path = remaining_edges[1:] if match else None
                    child_count = (internal_counts[len(internal_counts)-depth+1]
                                   if match and depth > 1 else leaf_count if match else 5)
                    child = make(depth-1, child_count, child_path, ptr, i)
                    self.write(ptr+self.layout['children']+8*i, child)
                if i < count:
                    self.serial += 2
                    if self.layout['key_width'] == 21:
                        key = ((int.from_bytes(bytes(range(1, 21)), 'big') + self.serial) << 8)
                    else:
                        key = int.from_bytes(bytes(range(1, 21)), 'big') + self.serial
                    self.put(ptr+self.layout['key']+self.layout['key_width']*i, key.to_bytes(self.layout['key_width'], 'big'))
                    self.write(ptr+self.layout['value']+self.layout['width']*i, value_for_key(key, self.layout['width']), self.layout['width'])
                    self.expected_count += 1
            return ptr
        depth = len(edges)
        root = make(depth, internal_counts[0] if depth else leaf_count, tuple(edges))
        if self.selected is None: raise Halt('selected leaf missing')
        # Sorted interleaving has even keys, leaving a free odd key at every edge.
        keys, _ = self.inspect(root, depth)
        leaf_keys = [self.key(self.selected+self.layout['key']+self.layout['key_width']*i) for i in range(leaf_count)]
        if leaf_slot < leaf_count:
            insertion_key = leaf_keys[leaf_slot] - (256 if self.layout['key_width'] == 21 else 1)
        elif leaf_count:
            insertion_key = leaf_keys[-1] + (256 if self.layout['key_width'] == 21 else 1)
        else:
            insertion_key = int.from_bytes(bytes(range(1, 21)), 'big') + 1
            if self.layout['key_width'] == 21: insertion_key <<= 8
        if insertion_key in keys: raise Halt('fixture key collision')
        return root, insertion_key

    def inspect(self, root, depth):
        seen = set()
        keys, values = [], []
        def walk(ptr, level, parent, edge):
            if ptr in seen or ptr not in self.nodes: raise Halt('invalid child pointer')
            seen.add(ptr)
            if self.nodes[ptr] != (self.layout['internal'] if level else self.layout['leaf']): raise Halt('bad node size')
            if self.read(ptr+self.layout['parent']) != parent: raise Halt('bad parent backlink')
            if parent and self.read(ptr+self.layout['edge'], 2) != edge: raise Halt('bad parent edge')
            n = self.read(ptr+self.layout['count'], 2)
            if n > 11: raise Halt('overfull node')
            for i in range(n+1):
                if level: walk(self.read(ptr+self.layout['children']+8*i), level-1, ptr, i)
                if i < n:
                    keys.append(self.key(ptr+self.layout['key']+self.layout['key_width']*i))
                    values.append(self.read(ptr+self.layout['value']+self.layout['width']*i, self.layout['width']))
        walk(root, depth, 0, 0)
        if keys != sorted(keys) or len(keys) != len(set(keys)): raise Halt('key order')
        return keys, values



def snapshot_tree(fixture, root, depth):
    """Capture all logical keys, values and child shapes from a verified tree."""
    count = fixture.read(root + fixture.layout['count'], 2)
    pairs = tuple((fixture.key(root + fixture.layout['key'] + fixture.layout['key_width']*i),
                   fixture.read(root + fixture.layout['value'] + fixture.layout['width']*i, fixture.layout['width'])) for i in range(count))
    children = tuple(snapshot_tree(fixture, fixture.read(root + fixture.layout['children'] + 8*i), depth-1)
                     for i in range(count+1)) if depth else ()
    return pairs, children


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


def physical_position(fixture, root, depth, key):
    node, path = root, ()
    while True:
        n = fixture.read(node+fixture.layout['count'], 2)
        i = 0
        while i < n and fixture.key(node+fixture.layout['key']+fixture.layout['key_width']*i) < key:
            i += 1
        if i < n and fixture.key(node+fixture.layout['key']+fixture.layout['key_width']*i) == key:
            return node, path, i
        if not depth: return None
        node = fixture.read(node+fixture.layout['children']+8*i)
        path += (i,)
        depth -= 1

def evaluate(image, function, counts, edges, leaf_count, leaf_slot, patches=None,
             fail_alloc_at=None, bad_cursor_depth=False, null_root=False, expect_panic=False,
             corrupt_leaf_count=None, corrupt_parent_count=None, root_height_override=None,
             kind=0, inserted_value=None, same_address=False):
    layout = LAYOUT_OUTER
    f = Fixture(image, patches, fail_alloc_at, layout)
    root, key = f.build(counts, edges, leaf_count, leaf_slot)
    related = None
    before_keys, before_values = f.inspect(root, len(edges))
    original_root_keys = [f.key(root+layout['key']+layout['key_width']*i)
                          for i in range(f.read(root+layout['count'],2))]
    expected = list(zip(before_keys, before_values))
    before_tree = snapshot_tree(f, root, len(edges))
    new_value = ((value_for_key(key, layout['width']) + 1) & ((1 << (8*layout['width']))-1)) if inserted_value is None else inserted_value
    if not 0 <= new_value < (1 << (8*layout['width'])): raise ValueError('invalid value')
    expected_tree = model_insert(before_tree, edges, leaf_slot, (key, new_value))
    expected.append((key, new_value))
    expected.sort()
    root_desc = f.alloc(24); holder = f.alloc(8); cursor = f.alloc(24)
    out = f.alloc(24); key_ptr = f.alloc(layout['key_width']); val_ptr = f.alloc(layout['width']); depth_ptr = f.alloc(8)
    f.write(root_desc, 0 if null_root else root)
    f.write(root_desc+8, len(edges))
    f.write(root_desc+16, len(before_keys))
    f.write(holder, root_desc)
    f.write(cursor, f.selected); f.write(cursor+8, 0); f.write(cursor+16, leaf_slot)
    f.put(key_ptr, key.to_bytes(layout['key_width'], 'big')); f.write(val_ptr, new_value, layout['width'])
    f.write(depth_ptr, 0, 4)
    if bad_cursor_depth: f.write(cursor+8, 1)
    if corrupt_leaf_count is not None: f.write(f.selected+layout['count'], corrupt_leaf_count, 2)
    if corrupt_parent_count is not None:
        parent = f.read(f.selected+layout['parent'])
        if not parent: raise ValueError('parent required for count corruption')
        f.write(parent+layout['count'], corrupt_parent_count, 2)
    if root_height_override is not None: f.write(root_desc+8, root_height_override)
    m = f.machine
    m.code_window = image.exact_fde(function)
    args = {RDI: out, RSI: cursor, RDX: key_ptr, RCX: val_ptr, R8: holder, R9: depth_ptr}
    try:
        m.run(function, args)
    except Panicked as exc:
        if not expect_panic: raise
        return dict(panic=str(exc), allocations=f.allocations, seen=m.seen, branches=m.branches)
    if expect_panic: raise Halt('expected failure sink was not reached')
    root_after, depth_after = f.read(root_desc), f.read(root_desc+8)
    keys_after, vals_after = f.inspect(root_after, depth_after)
    root_split = leaf_count == 11 and all(n == 11 for n in counts)
    if depth_after != len(edges) + int(root_split): raise Halt('unexpected root height')
    pivot_key = pivot_index = left_count = right_count = None
    if root_split:
        position = edges[0] if edges else leaf_slot
        pivot = 4 if position < 5 else 5 if position <= 6 else 6
        pivot_key = f.key(root_after+layout['key'])
        pivot_index = original_root_keys.index(pivot_key) if pivot_key in original_root_keys else None
        left_count = f.read(f.read(root_after+layout['children'])+layout['count'],2)
        right_count = f.read(f.read(root_after+layout['children']+8)+layout['count'],2)
        if pivot_key != original_root_keys[pivot]: raise Halt('wrong promoted root key')
        if (left_count, right_count) != (pivot+int(position <= pivot),
                                           10-pivot+int(position > pivot)):
            raise Halt('wrong root split counts')
    if list(zip(keys_after, vals_after)) != expected: raise Halt('tree differs from ordered insertion')
    actual_tree = snapshot_tree(f, root_after, depth_after)
    if actual_tree != expected_tree: raise Halt('tree shape differs from independent model')
    expected_allocations = []
    if leaf_count == 11:
        expected_allocations.append(layout['leaf'])
        for n in reversed(counts):
            if n != 11: break
            expected_allocations.append(layout['internal'])
        else:
            expected_allocations.append(layout['internal'])
    if f.allocations != expected_allocations: raise Halt('allocation sequence differs from model')
    if f.read(root_desc+16) != len(before_keys): raise Halt('helper unexpectedly changed map length')
    returned, returned_depth, returned_slot = (f.read(out+i*8) for i in range(3))
    physical_node, physical_path, physical_slot = physical_position(f, root_after, depth_after, key)
    if (physical_path, physical_slot) != model_position(expected_tree, key):
        raise Halt('returned logical position differs from model')
    if returned != physical_node or returned_slot != physical_slot:
        raise Halt('returned physical position differs from traversal')
    if returned_depth != 0 or f.key(returned+layout['key']+returned_slot*layout['key_width']) != key:
        raise Halt('returned cursor does not identify inserted key')
    if f.read(returned+layout['value']+returned_slot*layout['width'], layout['width']) != new_value:
        raise Halt('returned cursor does not identify inserted value')
    return dict(keys=len(keys_after), depth=depth_after,
                inserted_key=key.to_bytes(layout['key_width'], 'big').hex(),
                related_existing='' if related is None else related.to_bytes(layout['key_width'], 'big').hex(),
                allocations=f.allocations, returned_slot=returned_slot,
                pivot=pivot_index, left_count=left_count, right_count=right_count,
                tree_hash=hashlib.sha256(repr(actual_tree).encode('ascii')).hexdigest(),
                visited=len(m.seen), seen=m.seen, branches=m.branches)


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


def unique_section(image, name):
    found = [s for s in image.sections if s['name'] == name and s['type'] != 8]
    if len(found) != 1: raise EvidenceError('missing or ambiguous section: ' + name)
    return found[0]


def relocation_records(image):
    rel = unique_section(image, '.rela.dyn')
    syms = unique_section(image, '.dynsym')
    strings = unique_section(image, '.dynstr')
    if (rel['type'], syms['type'], strings['type']) != (4,11,3):
        raise EvidenceError('invalid ELF relocation or symbol section type')
    if rel['size'] % 24 or syms['size'] % 24: raise EvidenceError('invalid ELF record size')
    wanted = set((SLOT_ALLOC, SLOT_MEMCPY, SLOT_MEMMOVE) + STOP_SLOTS)
    records = {}
    for off in range(rel['offset'], rel['offset']+rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.blob, off)
        if slot not in wanted: continue
        if slot in records: raise EvidenceError('duplicate relocation')
        kind, index = info & 0xffffffff, info >> 32
        name = ''
        if index:
            if index*24 + 24 > syms['size']: raise EvidenceError('symbol index outside table')
            name_offset = struct.unpack_from('<I', image.blob, syms['offset']+index*24)[0]
            if name_offset >= strings['size']: raise EvidenceError('symbol name outside string table')
            pos = strings['offset'] + name_offset
            end = image.blob.find(b'\0', pos, strings['offset']+strings['size'])
            if end < 0: raise EvidenceError('unterminated symbol name')
            name = image.blob[pos:end].decode('ascii')
        records[slot] = (kind,index,addend,name)
    if set(records) != wanted: raise EvidenceError('missing relocation')
    if records[SLOT_MEMCPY][3] != 'memcpy' or records[SLOT_MEMMOVE][3] != 'memmove':
        raise EvidenceError('unexpected copy symbol')
    if any(records[x][0] != 8 for x in (SLOT_ALLOC,) + STOP_SLOTS):
        raise EvidenceError('unexpected boundary relocation type')
    return records


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

# Context and executable-slice checks for the two vote-tracker entry adapters.
WINDOWS = {
    'outer': (0x2f3d5c0, 0x2f3e68e, 'bdae41ccb8d23e10c94077d9cbcb2965b7916f362c50f65d7e95cbe0222a6e2b'),
    'inner': (0x2f9cc50, 0x2f9d814, 'f556060bd2d12a9399698d5436f4b7bde367e30a3ff1bf887d58a96726f64ae9'),
}
CALLS = ((0x33c21eb, 'outer'), (0x33c24d2, 'inner'))


def validate_image(image):
    for name, (start, end, digest) in WINDOWS.items():
        if image.exact_fde(start) != (start, end):
            raise EvidenceError('unexpected FDE: '+name)
        if hashlib.sha256(at(image, start, end-start)).hexdigest() != digest:
            raise EvidenceError('unexpected function body: '+name)
        if not any(s['flags'] & 4 and s['address'] <= start and end <= s['address']+s['size'] for s in image.mapped):
            raise EvidenceError('function not in executable file-backed section')
    for site, target in CALLS:
        if call_target(image, site) != FUNCTIONS[target]:
            raise EvidenceError('unexpected call target')
    relocation_records(image)


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
    m=f.machine; m.code_window=image.exact_fde(FUNCTIONS['inner'])
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
    m=f.machine; m.code_window=image.exact_fde(FUNCTIONS['inner'])
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


def nested_helper_case(image, counts, edges, leaf_count, slot):
    """Compose the two selected bodies around a harness-provided empty inner leaf."""
    f=Fixture(image,layout=LAYOUT_OUTER)
    root,key=f.build(counts,edges,leaf_count,slot)
    keys,values=f.inspect(root,len(edges))
    initial=snapshot_tree(f,root,len(edges))
    payload=bytes(24)+bytes((0,1))+bytes(6)
    expected=model_insert(initial,edges,slot,(key,int.from_bytes(payload,'little')))
    root_desc=f.alloc(24); holder=f.alloc(8); cursor=f.alloc(24); out=f.alloc(24)
    keyptr=f.alloc(20); value=f.alloc(32); depthptr=f.alloc(8)
    for ptr,size in ((root_desc,24),(holder,8),(cursor,24),(out,24),(depthptr,8)):
        f.put(ptr,bytes(size))
    f.write(root_desc,root); f.write(root_desc+8,len(edges)); f.write(root_desc+16,len(keys))
    f.write(holder,root_desc); f.write(cursor,f.selected); f.write(cursor+16,slot)
    f.put(keyptr,key.to_bytes(20,'big')); f.put(value,payload)
    m=f.machine; m.code_window=image.exact_fde(FUNCTIONS['outer'])
    m.run(FUNCTIONS['outer'],{RDI:out,RSI:cursor,RDX:keyptr,RCX:value,R8:holder,R9:depthptr})
    root_after,depth=f.read(root_desc),f.read(root_desc+8)
    if snapshot_tree(f,root_after,depth)!=expected: raise Halt('outer model mismatch')
    actual_keys,actual_values=f.inspect(root_after,depth)
    if list(zip(actual_keys,actual_values))!=sorted(list(zip(keys,values))+[(key,int.from_bytes(payload,'little'))]):
        raise Halt('outer ordered pairs mismatch')
    node,height,index=(f.read(out+8*i) for i in range(3))
    pos=physical_position(f,root_after,depth,key)
    if height or (node,index)!=(pos[0],pos[2]): raise Halt('outer cursor mismatch')
    inner_desc=node+32*index
    if f.data(inner_desc,32)!=payload: raise Halt('outer initial payload mismatch')
    # The caller and root setup are explicit fixture operations, not evaluated code.
    f.layout=LAYOUT_INNER
    inner_node=f.alloc(LAYOUT_INNER['leaf']); f.nodes[inner_node]=LAYOUT_INNER['leaf']
    f.put(inner_node,bytes(LAYOUT_INNER['leaf'])); f.write(inner_desc,inner_node)
    inner_holder=f.alloc(8); inner_cursor=f.alloc(24); inner_out=f.alloc(24)
    inner_value=f.alloc(48); inner_depth=f.alloc(8)
    for ptr,size in ((inner_cursor,24),(inner_out,24),(inner_value,48),(inner_depth,8)):
        f.put(ptr,bytes(size))
    f.write(inner_holder,inner_desc); f.write(inner_cursor,inner_node)
    m.code_window=image.exact_fde(FUNCTIONS['inner'])
    m.run(FUNCTIONS['inner'],{RDI:inner_out,RSI:inner_cursor,RDX:inner_value,RCX:inner_holder,R8:inner_depth})
    got_node,got_depth,got_index=(f.read(inner_out+8*i) for i in range(3))
    if (got_node,got_depth,got_index)!=(inner_node,0,0): raise Halt('inner cursor mismatch')
    if f.read(inner_node+LAYOUT_INNER['count'],2)!=1 or f.data(inner_node,48)!=bytes(48):
        raise Halt('inner inserted payload mismatch')
    if f.read(root_desc+16)!=len(keys) or f.read(inner_desc+16)!=0:
        raise Halt('helper changed descriptor length')
    if f.data(inner_desc+24,2)!=b'\x00\x01': raise Halt('outer flags changed')
    return {'outer_count':len(actual_keys),'outer_depth':depth,'inner_count':1,
            'allocations':f.allocations,'seen':m.seen,'branches':m.branches}


def outer_cases():
    for n in range(12):
        for i in range(n+1):
            yield 'leaf', (), (), n, i
    for n in (1, 5, 10, 11):
        for edge in range(n+1):
            for i in range(12):
                yield 'parent', (n,), (edge,), 11, i
    for counts, edges in (((1,11),(0,0)), ((5,11),(5,11)), ((11,5),(6,5)),
                          ((11,11),(0,5)), ((11,11),(11,6)),
                          ((11,11,11),(0,5,11)), ((11,11,11),(11,6,0))):
        for i in (0,4,5,6,7,11):
            yield 'cascade', counts, edges, 11, i


def tsv(path, columns, rows):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
        writer.writerow(columns)
        writer.writerows(rows)


def seq(values):
    return ','.join(str(v) for v in values)


def generate(image, out):
    validate_image(image)
    out.mkdir(parents=True, exist_ok=True)
    function_rows = []
    for role, (start, end, _) in WINDOWS.items():
        function_rows.append((role, hex(start), hex(end), end-start, hex(image.offset(start)),
                              hashlib.sha256(at(image,start,end-start)).hexdigest(),
                              len(decode_range(image,start,end))))
    tsv(out/'functions.tsv', ('role','start_va','end_va_exclusive','size','file_offset','sha256','decoded_instructions'), function_rows)
    tsv(out/'calls.tsv', ('caller_site_va','site_file_offset','call_bytes','target_va','target_role'),
        [(hex(site),hex(image.offset(site)),at(image,site,5).hex(),hex(call_target(image,site)),role) for site,role in CALLS])
    # E8 is scanned byte by byte, so these are candidates, not established
    # instruction boundaries except at the two separately validated sites.
    candidates=[]
    by_target={start:role for role,start in FUNCTIONS.items()}
    for sec in image.mapped:
        if not sec['flags'] & 4: continue
        begin,end=sec['offset'],sec['offset']+sec['size']
        if end>len(image.blob): raise EvidenceError('executable section exceeds file')
        i=image.blob.find(b'\xe8',begin,end)
        while i>=0:
            va=sec['address']+i-begin
            if i+5<=end:
                target=va+5+int.from_bytes(image.blob[i+1:i+5],'little',signed=True)
                if target in by_target:
                    candidates.append((va,i,image.blob[i:i+5].hex(),target,by_target[target]))
            i=image.blob.find(b'\xe8',i+1,end)
    candidates.sort()
    tsv(out/'call-candidates.tsv',('site_va','file_offset','bytes','target_va','target_role'),
        [(hex(va),hex(off),raw,hex(target),role) for va,off,raw,target,role in candidates])
    anchor_sites=(('outer_capacity',0x2f3d5fc),('outer_pivot_five',0x2f3d60b),
                  ('outer_pivot_six',0x2f3d678),('outer_move_keys',0x2f3d6d0),
                  ('inner_capacity',0x2f9cc6e),('inner_pivot_five',0x2f9cc78),
                  ('inner_pivot_six',0x2f9cd31),('inner_move_payload',0x2f9cce2),
                  ('inner_write_count',0x2f9cd1f))
    decoder=Machine(image)
    anchors=[]
    for label,va in anchor_sites:
        row=decode(decoder.read_code,va)
        anchors.append((label,hex(va),hex(image.offset(va)),at(image,va,row.next-va).hex()))
    tsv(out/'anchors.tsv',('observation','site_va','file_offset','bytes'),anchors)
    branch_counts = {}
    reached = set()
    def record(result):
        reached.update(result['seen'])
        for branch in result['branches']:
            branch_counts[branch] = branch_counts.get(branch,0)+1
    outer_rows = []
    for group, counts, edges, n, gap in outer_cases():
        r = evaluate(image, FUNCTIONS['outer'], counts, edges, n, gap)
        record(r)
        outer_rows.append((group,seq(counts),seq(edges),n,gap,r['keys'],r['depth'],
                           '' if r['pivot'] is None else r['pivot'],
                           '' if r['left_count'] is None else r['left_count'],
                           '' if r['right_count'] is None else r['right_count'],
                           seq(r['allocations']),r['returned_slot'],r['tree_hash'],r['visited']))
    tsv(out/'outer-cases.tsv', ('group','ancestor_counts','selected_edges','leaf_count','gap','result_keys',
        'result_depth','root_original_pivot','root_left_count','root_right_count','allocation_sizes',
        'returned_slot','tree_sha256','visited_instruction_starts'),outer_rows)
    inner_rows=[]
    for n in range(12):
        for gap in range(n+1):
            r=inner_case(image,n,gap)
            record(r)
            inner_rows.append(('empty_leaf' if n==0 else 'synthetic_nonempty',n,gap,r['count'],r['depth'],
                               '' if r['pivot'] is None else r['pivot'],
                               '' if r['left_count'] is None else r['left_count'],
                               '' if r['right_count'] is None else r['right_count'],seq(r['allocations']),
                               r['returned_slot'],r['sequence_sha256'],len(r['seen'])))
    tsv(out/'inner-cases.tsv',('fixture','leaf_count','gap','result_count','result_depth','root_original_pivot',
        'root_left_count','root_right_count','allocation_sizes','returned_slot','sequence_sha256',
        'visited_instruction_starts'),inner_rows)
    inner_tree_rows=[]
    for group,counts,edges,n,gap in outer_cases():
        if group=='leaf': continue
        r=inner_tree_case(image,counts,edges,gap)
        record(r)
        inner_tree_rows.append((group,seq(counts),seq(edges),n,gap,r['count'],r['depth'],
                                seq(r['allocations']),r['returned_slot'],r['tree_sha256'],len(r['seen'])))
    tsv(out/'inner-tree-cases.tsv',('group','ancestor_counts','selected_edges','leaf_count','gap',
        'result_count','result_depth','allocation_sizes','returned_slot','tree_sha256',
        'visited_instruction_starts'),inner_tree_rows)
    nested_rows=[]
    for group,counts,edges,n,gap in outer_cases():
        if group=='leaf' or (group=='parent' and edges[0] in (0,counts[0]) and gap in (0,5,6,11)):
            r=nested_helper_case(image,counts,edges,n,gap)
            record(r)
            nested_rows.append((group,seq(counts),seq(edges),n,gap,r['outer_count'],r['outer_depth'],
                                r['inner_count'],seq(r['allocations']),len(r['seen'])))
    tsv(out/'nested-cases.tsv',('group','ancestor_counts','selected_edges','leaf_count','gap',
        'outer_count','outer_depth','inner_count','allocation_sizes','visited_instruction_starts'),nested_rows)
    controls=[]
    for role in ('outer','inner'):
        for fail in (1,2):
            r=(evaluate(image,FUNCTIONS['outer'],(),(),11,5,fail_alloc_at=fail,expect_panic=True)
               if role=='outer' else inner_case(image,11,5,fail_alloc_at=fail))
            record(r)
            controls.append(('allocation_'+role,str(fail),r['panic'],seq(r['allocations'])))
    for name,kw,counts,edges in (
        ('leaf_count_22',{'corrupt_leaf_count':22},(),()),
        ('null_root',{'null_root':True},(),()),
        ('height_max',{'root_height_override':MASK[8]},(),()),
        ('height_one',{'root_height_override':1},(),()),
        ('parent_count_22',{'corrupt_parent_count':22},(11,),(0,))):
        r=evaluate(image,FUNCTIONS['outer'],counts,edges,11,5,expect_panic=True,**kw)
        record(r)
        controls.append(('corruption',name,r['panic'],seq(r['allocations'])))
    for name,kw in (('leaf_count_22',{'corrupt_count':22}),('null_root',{'null_root':True}),
                    ('height_max',{'height_override':MASK[8]}),('height_one',{'height_override':1})):
        r=inner_case(image,11,5,expect_panic=True,**kw)
        record(r)
        controls.append(('inner_corruption',name,r['panic'],seq(r['allocations'])))
    r=inner_tree_case(image,(11,),(0,),5,corrupt_parent_count=22,expect_panic=True)
    record(r)
    controls.append(('inner_corruption','parent_count_22',r['panic'],seq(r['allocations'])))
    tsv(out/'controls.tsv',('kind','case','result','allocation_sizes'),controls)
    decoder = Machine(image)
    branch_rows = []
    for va in sorted({va for va,_ in branch_counts}):
        insn=decode(decoder.read_code,va)
        if insn.op != 'jcc': raise Halt('branch counter does not identify a conditional jump')
        branch_rows.append((hex(va),hex(image.offset(va)),at(image,va,insn.next-va).hex(),hex(insn.target),
                            branch_counts.get((va,False),0),branch_counts.get((va,True),0)))
    tsv(out/'branches.tsv',('site_va','file_offset','instruction_bytes','taken_target_va','not_taken_cases','taken_cases'),branch_rows)
    coverage=[]
    for role,(start,end,_) in WINDOWS.items():
        decoded=decode_range(image,start,end)
        conds=[row.va for row in decoded if row.op=='jcc']
        coverage.append((role,len(decoded),sum(row.va in reached for row in decoded),len(conds),
                         sum(any((va,t) in branch_counts for t in (False,True)) for va in conds),
                         sum(all((va,t) in branch_counts for t in (False,True)) for va in conds)))
    tsv(out/'coverage.tsv',('role','linear_decoded_instructions','reached_instruction_starts',
        'linear_conditional_sites','reached_conditional_sites','sites_with_both_outcomes'),coverage)
    rel=relocation_records(image)
    tsv(out/'relocations.tsv',('slot_va','relocation_type','symbol_index','addend','symbol'),
        [(hex(slot),kind,index,addend,name) for slot,(kind,index,addend,name) in sorted(rel.items())])
    return {'functions':len(function_rows),'calls':len(CALLS),'byte_call_candidates':len(candidates),'outer_cases':len(outer_rows),
            'inner_cases':len(inner_rows),'inner_tree_cases':len(inner_tree_rows),'nested_cases':len(nested_rows),'controls':len(controls),'conditional_sites':len(branch_rows)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(generate(load_image(),args.out),sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError,Halt,Panicked,OSError,ValueError,struct.error) as error:
        print('staking_vote_jail_insert94: '+str(error),file=sys.stderr)
        sys.exit(1)
