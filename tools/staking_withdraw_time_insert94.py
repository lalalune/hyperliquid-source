#!/usr/bin/env python3
"""Static evaluator for the node 94 withdrawal time-queue insertion path.

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
from fde_extents import eh_frame_records, uleb

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
        for row in fdes:
            if row['start'] in self.fde_ends:
                raise EvidenceError('duplicate FDE start')
            self.fde_ends[row['start']] = row['end']

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
            offset = self.image.offset(addr)
        except EvidenceError:
            raise Halt("read outside every mapping: %#x" % addr)
        return bytes(self.image.blob[offset:offset + count])

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



SLOT_ALLOC = 0x576dfd8
SLOT_MEMCPY = 0x576dfe0
SLOT_MEMMOVE = 0x576e0e0
STOP_SLOTS = (0x576e470, 0x576e108, 0x576e020, 0x576e2e0, 0x576e010)
MARK_BASE = 0x7700000000
ARENA = HEAP_BASE + 0x10000
ARENA_END = HEAP_BASE + HEAP_SIZE
KEY_BASE = (1 << 95) + (1 << 64) + (1000 << 32)
LAYOUT_STANDARD = dict(parent=0, value=8, width=24, key=0x110, edge=0x194,
                       count=0x196, children=0x198, leaf=0x198, internal=0x1f8)


def value_for_key(key, width):
    if width != 24: raise ValueError('fixture expects a three-word vector descriptor')
    capacity = (key & 0xffffffff) % 6
    pointer = 8 if not capacity else 0x710000000 + (key & 0xffffffff)*32
    length = (key & 0xffffffff) % (capacity+1)
    return capacity | pointer << 64 | length << 128



class Fixture:
    """Build and validate a concrete, ordered tree with checked backlinks."""
    def __init__(self, image, patches=None, fail_alloc_at=None, layout=None):
        self.layout = layout or LAYOUT_STANDARD
        self.machine = Machine(image, patches)
        self.machine.real = frozenset()
        self.machine.memory.statics = {slot: MARK_BASE + slot for slot in
                                       (SLOT_ALLOC, SLOT_MEMCPY, SLOT_MEMMOVE) + STOP_SLOTS}
        self.machine.slots = {MARK_BASE + SLOT_ALLOC: self.on_alloc,
                              MARK_BASE + SLOT_MEMCPY: self.on_copy,
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
        date, sec, nanos = struct.unpack('<iII', self.data(at, 12))
        return ((date + (1 << 31)) << 64) | (sec << 32) | nanos

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
                    key = KEY_BASE + self.serial
                    self.put(ptr+self.layout['key']+12*i, struct.pack('<iII', (key >> 64) - (1 << 31), (key >> 32) & 0xffffffff, key & 0xffffffff))
                    self.write(ptr+self.layout['value']+self.layout['width']*i, value_for_key(key, self.layout['width']), self.layout['width'])
                    self.expected_count += 1
            return ptr
        depth = len(edges)
        root = make(depth, internal_counts[0] if depth else leaf_count, tuple(edges))
        if self.selected is None: raise Halt('selected leaf missing')
        # Sorted interleaving has even keys, leaving a free odd key at every edge.
        keys, _ = self.inspect(root, depth)
        leaf_keys = [self.key(self.selected+self.layout['key']+12*i) for i in range(leaf_count)]
        if leaf_slot < leaf_count:
            insertion_key = leaf_keys[leaf_slot] - 1
        elif leaf_count:
            insertion_key = leaf_keys[-1] + 1
        else:
            insertion_key = KEY_BASE + 1
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
                    keys.append(self.key(ptr+self.layout['key']+12*i))
                    values.append(self.read(ptr+self.layout['value']+self.layout['width']*i, self.layout['width']))
        walk(root, depth, 0, 0)
        if keys != sorted(keys) or len(keys) != len(set(keys)): raise Halt('key order')
        return keys, values



def snapshot_tree(fixture, root, depth):
    """Capture all logical keys, values and child shapes from a verified tree."""
    count = fixture.read(root + fixture.layout['count'], 2)
    pairs = tuple((fixture.key(root + fixture.layout['key'] + 12*i),
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
        while i < n and fixture.key(node+fixture.layout['key']+12*i) < key:
            i += 1
        if i < n and fixture.key(node+fixture.layout['key']+12*i) == key:
            return node, path, i
        if not depth: return None
        node = fixture.read(node+fixture.layout['children']+8*i)
        path += (i,)
        depth -= 1

def evaluate(image, function, counts, edges, leaf_count, leaf_slot, patches=None,
             fail_alloc_at=None, bad_cursor_depth=False, null_root=False, expect_panic=False,
             corrupt_leaf_count=None, corrupt_parent_count=None, root_height_override=None):
    layout = LAYOUT_STANDARD
    f = Fixture(image, patches, fail_alloc_at, layout)
    root, key = f.build(counts, edges, leaf_count, leaf_slot)
    before_keys, before_values = f.inspect(root, len(edges))
    original_root_keys = [f.key(root+layout['key']+12*i)
                          for i in range(f.read(root+layout['count'],2))]
    expected = list(zip(before_keys, before_values))
    before_tree = snapshot_tree(f, root, len(edges))
    new_value = value_for_key(key, layout['width'])
    expected_tree = model_insert(before_tree, edges, leaf_slot, (key, new_value))
    expected.append((key, new_value))
    expected.sort()
    root_desc = f.alloc(24); holder = f.alloc(8); cursor = f.alloc(24)
    out = f.alloc(24); key_ptr = f.alloc(12); val_ptr = f.alloc(layout['width']); depth_ptr = f.alloc(8)
    f.write(root_desc, 0 if null_root else root)
    f.write(root_desc+8, len(edges))
    f.write(root_desc+16, len(before_keys))
    f.write(holder, root_desc)
    f.write(cursor, f.selected); f.write(cursor+8, 0); f.write(cursor+16, leaf_slot)
    f.put(key_ptr, struct.pack('<iII', (key >> 64) - (1 << 31), (key >> 32) & 0xffffffff, key & 0xffffffff)); f.write(val_ptr, new_value, layout['width'])
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
        return dict(panic=str(exc), panic_va=m.current_pc, allocations=f.allocations, seen=m.seen, branches=m.branches)
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
    if returned_depth != 0 or f.key(returned+layout['key']+returned_slot*12) != key:
        raise Halt('returned cursor does not identify inserted key')
    if f.read(returned+layout['value']+returned_slot*layout['width'], layout['width']) != new_value:
        raise Halt('returned cursor does not identify inserted value')
    return dict(keys=len(keys_after), depth=depth_after,
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


def cases():
    # All insertions into a single leaf, including all twelve full-leaf gaps.
    for n in range(12):
        for i in range(n+1):
            yield ('leaf', (), (), n, i)
    # Every child and leaf gap for full-parent and near-full-parent propagation.
    for n in (1, 5, 10, 11):
        for edge in range(n+1):
            for i in range(12):
                yield ('parent', (n,), (edge,), 11, i)
    # Three levels, covering the pivot boundaries at both internal levels.
    for counts in ((1,11), (5,11), (11,5), (11,11)):
        choices = [sorted(set(x for x in (0, 4, 5, 6, 7, n) if x <= n)) for n in counts]
        for outer in choices[0]:
            for inner in choices[1]:
                for i in (0, 4, 5, 6, 7, 11):
                    yield ('cascade', counts, (outer,inner), 11, i)
    # A fourth level exercises repeated propagation past the earlier depth bound.
    for counts, edges in (((11,11,11),(0,5,11)), ((11,11,11),(11,6,0)),
                          ((11,11,5),(6,5,5)), ((1,11,11),(0,11,6))):
        for i in (0,4,5,6,11):
            yield ('deep_cascade', counts, edges, 11, i)


def to_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as stream:
        w = csv.writer(stream, delimiter='\t', lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)



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

def rank_time(date, seconds, nanos):
    if not -(1 << 31) <= date < (1 << 31) or not 0 <= seconds < (1 << 32) or not 0 <= nanos < (1 << 32):
        raise ValueError('time component outside encoded width')
    return ((date + (1 << 31)) << 64) | (seconds << 32) | nanos


def varied_times():
    raw = [(-(1 << 31),0,0), (-(1 << 31),0,1), (-2,3,2), (-1,0,0),
           (-1,0,1), (-1,1,0), (-1,0xffffffff,0xffffffff), (0,0,0),
           (0,0,1), (0,1,0), (0,0xffffffff,0xffffffff), (1,0,0),
           (1,0,1), (1,1,0), ((1 << 31)-1,0,0), ((1 << 31)-1,0xffffffff,0xffffffff)]
    return [raw[index] for i in range(8) for index in (15-i,i)]


def sequence(image, order):
    f = Fixture(image)
    root, _ = f.build((), (), 0, 0)
    layout = f.layout
    desc=f.alloc(24); holder=f.alloc(8); cursor=f.alloc(24); out=f.alloc(24)
    key_ptr=f.alloc(12); val_ptr=f.alloc(24); depth_ptr=f.alloc(8)
    f.write(desc,root); f.write(desc+8,0); f.write(desc+16,0);f.write(holder,desc)
    f.machine.code_window = image.exact_fde(0x2f504e0)
    expected={}
    for key in order:
        root=f.read(desc); depth=f.read(desc+8); node=root; remain=depth; path=[]
        while True:
            n=f.read(node+layout['count'],2); i=0
            while i<n and f.key(node+layout['key']+12*i)<key: i+=1
            if i<n and f.key(node+layout['key']+12*i)==key: raise ValueError('duplicate key')
            if not remain: break
            path.append(i);node=f.read(node+layout['children']+8*i);remain-=1
        model=model_insert(snapshot_tree(f,root,depth),path,i,(key,value_for_key(key,24)))
        f.write(cursor,node);f.write(cursor+8,0);f.write(cursor+16,i)
        f.put(key_ptr,struct.pack('<iII',(key>>64)-(1<<31),(key>>32)&0xffffffff,key&0xffffffff));f.write(val_ptr,value_for_key(key,24),24);f.write(depth_ptr,0,4)
        f.machine.run(0x2f504e0,{RDI:out,RSI:cursor,RDX:key_ptr,RCX:val_ptr,R8:holder,R9:depth_ptr})
        if f.read(desc+16)!=len(expected):raise Halt('unexpected map count')
        f.write(desc+16,len(expected)+1)
        expected[key]=value_for_key(key,24)
        root=f.read(desc); depth=f.read(desc+8)
        keys,vals=f.inspect(root,depth)
        if list(zip(keys,vals))!=sorted(expected.items()):raise Halt('sequence payload mismatch')
        if snapshot_tree(f,root,depth)!=model:raise Halt('sequence tree shape mismatch')
        returned=f.read(out); slot=f.read(out+16)
        if f.key(returned+layout['key']+12*slot)!=key:raise Halt('sequence cursor mismatch')
    return len(expected),f.read(desc+8),len(f.allocations),len(f.machine.seen),len(f.machine.branches)


class ResumeUnwind(Exception):
    pass
class ModeledTrap(Exception):
    pass

def cleanup_case(image, entry, cap, extra):
    f = Fixture(image)
    m = f.machine
    slot=0x576e010
    events=[]
    marker=MARK_BASE+slot
    def release(machine):
        events.append((machine.regs[RDI],machine.regs[RSI]))
    def resume(machine):
        events.append(('resume',machine.regs[RDI]));raise ResumeUnwind
    m.slots[marker]=release;m.memory.statics[slot]=marker;m.calls[0x5660110]=resume
    stack=STACK_TOP-0x200
    mainptr,extraptr,node1,node2,exc=0x77700010,0x77700020,0x77700030,0x77700040,0x77700050
    f.write(stack,cap);f.write(stack+0x18,mainptr);f.write(stack+0x28,extraptr)
    m.regs=[POISON]*16
    for r,v in {RSP:stack,RAX:exc,R12:extra,R14:extra,R15:cap,RBX:node1,RBP:node2}.items():m.regs[r]=v
    expected=[]
    if entry in (0x2f51332,0x2f51365,0x2f51374) and extra:expected.append((extraptr,extra*32))
    if entry==0x2f51332:expected.append((node1,0x198))
    if entry in (0x2f51365,0x2f51374):expected.append((node2,0x1f8))
    if entry==0x2f512fe:expected.append((node1,0x1f8))
    if entry != 0x2f512fe and entry != 0x2f51310:
        if cap:expected.append((extraptr if entry in (0x2f51312,0x2f51323) else mainptr,cap*32))
        expected.append(('resume',exc))
    pc=entry
    try:
        for step in range(500):
            if not 0x2f504e0<=pc<0x2f513c5:raise Halt('cleanup outside FDE')
            row=decode(m.read_code,pc);m.current_pc=pc
            if row.op=='ud2':raise ModeledTrap
            pc=m.step(row)
        raise Halt('cleanup step limit')
    except ResumeUnwind:
        terminal='resume'
    except ModeledTrap:
        terminal='trap'
    if events!=expected:raise Halt('cleanup events differ: '+repr((events,expected)))
    if terminal!=('trap' if entry in (0x2f512fe,0x2f51310) else 'resume'):raise Halt('wrong cleanup terminal')
    return terminal,events


SUBJECT = 0x2f504e0
END = 0x2f513c5
BODY_SHA256 = 'a99374968cac99842de083207459dde814a37dea5aa12b85ee3dc22e482fce3e'
PINS = (
    ('leaf_count', 0x2f504fe, '450fb7ba96010000'),
    ('capacity_eleven', 0x2f50506, '4983ff0b'),
    ('low_gap', 0x2f50521, '4c8b66104983fc05'),
    ('left_pivot', 0x2f50530, '41bf04000000'),
    ('gap_six', 0x2f50589, '4983fc060f851f010000'),
    ('leaf_allocation', 0x2f506e0, 'bf98010000'),
    ('internal_allocation', 0x2f510db, 'bff8010000'),
    ('vacant_adapter_call', 0x33bffcd, 'e80e05b9ff'),
    ('enqueue_adapter_call', 0x3c13327, 'e844cc7aff'),
    ('adapter_count_increment', 0x33c006a, '48ff4510'),
    ('context_date_and_seconds_compare', 0x3c13248, '428b9c181001000039de400f9cc50f9fc375d5428bac1814010000'),
    ('context_nanos_compare', 0x3c1326f, '423b8c18180100000f97c380db00'),
    ('context_equal_branch', 0x3c13280, '440fb6cb4585c90f84bb000000'),
    ('context_empty_vector', 0x3c132eb, '48c78424800000000000000048c78424880000000800000048c784249000000000000000'),
    ('context_append_row', 0x3c13366, '4c892408410f10070f11440808418b57108954081848ffc349895d1066'),
    ('append_after_lookup', 0x3c13344, '4983c508498b5d10493b5d0075094c89efff157511b601498b45084889d948c1e1054c892408410f1007'),
)


def unwind_symbol(image):
    plt = 0x5660110
    stub = at(image, plt, 6)
    if stub[:2] != b'\xff\x25': raise EvidenceError('unexpected unwind PLT stub')
    slot = plt + 6 + struct.unpack_from('<i', stub, 2)[0]
    if call_target(image, 0x2f513c0) != plt:
        raise EvidenceError('landing does not call the expected PLT stub')
    rela = unique_section(image, '.rela.plt')
    syms = unique_section(image, '.dynsym')
    strings = unique_section(image, '.dynstr')
    if (rela['type'], syms['type'], strings['type']) != (4, 11, 3) or rela['size'] % 24:
        raise EvidenceError('invalid unwind relocation tables')
    found = []
    for offset in range(rela['offset'], rela['offset']+rela['size'], 24):
        address, info, addend = struct.unpack_from('<QQq',image.blob,offset)
        if address != slot: continue
        kind, index = info & 0xffffffff, info >> 32
        if index*24 + 24 > syms['size']: raise EvidenceError('unwind symbol outside table')
        nameoff = struct.unpack_from('<I',image.blob,syms['offset']+index*24)[0]
        if nameoff >= strings['size']: raise EvidenceError('unwind name outside table')
        namepos = strings['offset'] + nameoff
        end = image.blob.find(b'\0', namepos, strings['offset']+strings['size'])
        if end < 0: raise EvidenceError('unterminated unwind symbol')
        found.append((kind,index,addend,bytes(image.blob[namepos:end]).decode('ascii')))
    if len(found) != 1 or found[0][0] != 7 or found[0][3] != '_Unwind_Resume':
        raise EvidenceError('unexpected unwind relocation')
    return plt,stub,slot,*found[0]


def lsda_records(image):
    fdes = [f for f in eh_frame_records(image.blob, image.sections)[1] if f['start'] == SUBJECT]
    if len(fdes) != 1 or fdes[0]['lsda'] is None: raise EvidenceError('missing subject LSDA')
    sec = unique_section(image, '.gcc_except_table')
    if sec['type'] == 8: raise EvidenceError('LSDA section not file-backed')
    va = fdes[0]['lsda']
    if not sec['address'] <= va < sec['address'] + sec['size']: raise EvidenceError('LSDA outside exception table')
    pos = image.offset(va)
    limit = sec['offset'] + sec['size']
    if image.blob[pos:pos+3] != b'\xff\xff\x01':
        raise EvidenceError('unsupported LSDA encodings')
    pos += 3
    length, pos = uleb(image.blob, pos, limit)
    end = pos + length
    if end > limit: raise EvidenceError('LSDA call-site table outside section')
    records, prior_end = [], SUBJECT
    while pos < end:
        at_start = pos
        start, pos = uleb(image.blob, pos, end)
        size, pos = uleb(image.blob, pos, end)
        landing, pos = uleb(image.blob, pos, end)
        action, pos = uleb(image.blob, pos, end)
        begin, finish = SUBJECT + start, SUBJECT + start + size
        target = SUBJECT + landing if landing else None
        if not SUBJECT <= begin <= finish <= END or begin < prior_end:
            raise EvidenceError('invalid LSDA call-site range')
        if target is not None and not SUBJECT <= target < END:
            raise EvidenceError('LSDA landing outside FDE')
        if action != 0: raise EvidenceError('unsupported LSDA action')
        records.append((va + at_start-image.offset(va), bytes(image.blob[at_start:pos]), begin, finish, target, action))
        prior_end = finish
    if pos != end: raise EvidenceError('LSDA call-site table overrun')
    return records


def validate_image(image):
    start, end = image.exact_fde(SUBJECT)
    if (start, end) != (SUBJECT, END):
        raise EvidenceError('unexpected FDE bounds')
    if hashlib.sha256(at(image, start, end-start)).hexdigest() != BODY_SHA256:
        raise EvidenceError('unexpected function body')
    executable = [s for s in image.mapped if s['flags'] & 4 and
                  s['address'] <= start and end <= s['address'] + s['size']]
    if len(executable) != 1:
        raise EvidenceError('not uniquely executable and file-backed')
    for name, va, pattern in PINS:
        if at(image, va, len(bytes.fromhex(pattern))) != bytes.fromhex(pattern):
            raise EvidenceError('anchor mismatch: ' + name)
    if call_target(image, 0x33bffcd) != SUBJECT:
        raise EvidenceError('vacant adapter call target changed')
    if call_target(image, 0x3c13327) != 0x33bff70:
        raise EvidenceError('enqueue adapter call target changed')
    relocation_records(image)
    unwind_symbol(image)
    rows = decode_range(image, start, end)
    starts = {row.va for row in rows}
    for _, _, _, _, landing, _ in lsda_records(image):
        if landing is not None and landing not in starts: raise EvidenceError('LSDA landing inside an instruction')
    for row in rows:
        if row.op in ('jmp', 'jcc') and row.target is not None and start <= row.target < end and row.target not in starts:
            raise EvidenceError('branch inside an instruction')
    return rows


def generate(image, out):
    rows = validate_image(image)
    lsda = lsda_records(image)
    out.mkdir(parents=True, exist_ok=True)
    seen, branches, scenario_rows = set(), set(), []
    witnesses = {}
    for index, (group, counts, edges, length, gap) in enumerate(cases()):
        result = evaluate(image, SUBJECT, counts, edges, length, gap)
        seen.update(result['seen'])
        branches.update(result['branches'])
        for branch in sorted(result['branches']):
            group_witnesses = witnesses.setdefault(branch, [])
            if len(group_witnesses) < 2:
                group_witnesses.append((counts, edges, length, gap))
        scenario_rows.append((group, index, ','.join(map(str, counts)), ','.join(map(str, edges)),
                              length, gap, result['keys'], result['depth'],
                              ','.join(map(str, result['allocations'])), result['returned_slot'],
                              '' if result['pivot'] is None else result['pivot'],
                              '' if result['left_count'] is None else result['left_count'],
                              '' if result['right_count'] is None else result['right_count'],
                              result['visited'], result['tree_hash']))
    sequences = []
    nums = list(range(1, 181))
    orders = (('ascending', nums), ('descending', nums[::-1]),
              ('alternating', [x for i in range(90) for x in (nums[i], nums[-1-i])]))
    for name, order in orders:
        count, height, allocations, reached, observed = sequence(image, [KEY_BASE + 2*x for x in order])
        sequences.append((name,count,height,allocations,reached,observed))
    varied = varied_times()
    varied_result = sequence(image, [rank_time(*row) for row in varied])
    if varied_result[0] != len(varied): raise EvidenceError('mixed-width sequence length mismatch')
    controls = []
    failures = []
    failed = (
        ('leaf_allocation', (), (), dict(fail_alloc_at=1)),
        ('new_root_allocation', (), (), dict(fail_alloc_at=2)),
        ('internal_allocation', (11,), (6,), dict(fail_alloc_at=2)),
        ('cascade_root_allocation', (11,), (6,), dict(fail_alloc_at=3)),
        ('bad_cursor_height', (1,), (0,), dict(bad_cursor_depth=True)),
        ('missing_root', (), (), dict(null_root=True)),
        ('corrupt_leaf_count', (), (), dict(corrupt_leaf_count=22)),
        ('corrupt_parent_count', (11,), (0,), dict(corrupt_parent_count=22)),
        ('height_overflow', (), (), dict(root_height_override=MASK[8])),
        ('height_mismatch', (), (), dict(root_height_override=1)),
    )
    for label, counts, edges, options in failed:
        result = evaluate(image, SUBJECT, counts, edges, 11, 5, expect_panic=True, **options)
        match = [record for record in lsda if record[2] <= result['panic_va'] < record[3]]
        if len(match) != 1: raise EvidenceError('failure boundary has no unique LSDA record')
        landing = match[0][4]
        controls.append((label, 'modeled failure boundary', result['panic'],
                         ','.join(map(str, result['allocations']))))
        failures.append((label,hex(result['panic_va']),hex(landing) if landing is not None else ''))
    mutants = (('capacity_11_to_10', 0x29, 10, 10, 5),
               ('pivot_4_to_3', 0x52, 3, 11, 0),
               ('key_tail_offset_8_to_9', 0x82, 9, 4, 4),
               ('full_branch_inverted', 0x3f, 0x73, 10, 5))
    for label, offset, replacement, count, gap in mutants:
        try:
            evaluate(image, SUBJECT, (), (), count, gap, patches={SUBJECT+offset: replacement})
        except (Halt, Panicked, EvidenceError) as error:
            controls.append((label, type(error).__name__, str(error), ''))
        else:
            raise EvidenceError('mutation was not detected: ' + label)
    jump = b'\xe9' + struct.pack('<i', END + 16 - (SUBJECT + 5))
    try:
        evaluate(image, SUBJECT, (), (), 0, 0, patches={SUBJECT+i: v for i, v in enumerate(jump)})
    except Halt as error:
        if str(error) != 'control left selected FDE': raise
        controls.append(('jump_outside_fde', 'Halt', str(error), ''))
    else:
        raise EvidenceError('out-of-window jump accepted')

    cleanup = []
    entries = (0x2f51312, 0x2f51321, 0x2f51323, 0x2f51332, 0x2f5135c, 0x2f51365,
               0x2f5136f, 0x2f51374, 0x2f512fe, 0x2f51310)
    labels = {0x77700010:'main', 0x77700020:'extra', 0x77700030:'leaf', 0x77700040:'internal', 0x77700050:'exception'}
    for entry in entries:
        for cap in (0,2):
            for extra in (0,3):
                terminal, events = cleanup_case(image,entry,cap,extra)
                event_text = ','.join(('resume:'+labels[value] if name == 'resume' else 'free:'+labels[name]+':'+str(value)) for name,value in events)
                cleanup.append((hex(entry),cap,extra,terminal,event_text))
    mutation_rows = []
    for row in (r for r in rows if r.op == 'jcc'):
        if 0x70 <= row.data[0] <= 0x7f:
            address, replacement = row.va, row.data[0] ^ 1
        elif row.data[0] == 0x0f and 0x80 <= row.data[1] <= 0x8f:
            address, replacement = row.va + 1, row.data[1] ^ 1
        else:
            raise EvidenceError('unsupported conditional encoding')
        inputs = witnesses.get((row.va, False), []) + witnesses.get((row.va, True), [])
        outcomes = []
        for counts, edges, count, gap in inputs:
            try:
                evaluate(image, SUBJECT, counts, edges, count, gap, patches={address: replacement})
            except Panicked:
                outcomes.append('modeled_failure_boundary')
            except (Halt, EvidenceError) as error:
                text = str(error)
                prefixes = ('unexpected root height', 'wrong promoted', 'wrong root split',
                            'tree differs', 'tree shape differs', 'allocation sequence differs',
                            'returned physical', 'returned logical', 'returned cursor',
                            'helper unexpectedly changed', 'bad parent backlink', 'bad parent edge',
                            'key order', 'overfull node')
                outcomes.append('model_difference' if text.startswith(prefixes) else 'interpreter_fault')
            else:
                outcomes.append('survived')
        if 'model_difference' in outcomes: classification = 'model_difference'
        elif 'modeled_failure_boundary' in outcomes: classification = 'modeled_failure_boundary'
        elif 'interpreter_fault' in outcomes: classification = 'interpreter_fault'
        elif outcomes: classification = 'survived'
        else: classification = 'unreached'
        mutation_rows.append((hex(row.va),row.data.hex(),len(inputs),classification,','.join(outcomes)))
    branch_rows = [(hex(r.va), r.data.hex(), r.cc, hex(r.target),
                    int((r.va, False) in branches), int((r.va, True) in branches))
                   for r in rows if r.op == 'jcc']
    conditionals = [r for r in rows if r.op == 'jcc']
    coverage = dict(instructions_total=len(rows), instructions_reached=sum(r.va in seen for r in rows),
                    conditional_total=len(conditionals),
                    conditionals_both=sum((r.va, False) in branches and (r.va, True) in branches for r in conditionals),
                    conditionals_neither=sum(r.va not in seen for r in conditionals))
    fde = next(f for f in eh_frame_records(image.blob, image.sections)[1] if f['start'] == SUBJECT)
    to_tsv(out/'function.tsv', ('start_va','end_va_exclusive','file_offset','bytes','fde_va','cie_va','lsda_va','sha256'),
           [(hex(SUBJECT), hex(END), hex(image.offset(SUBJECT)), END-SUBJECT,
             hex(fde['fde']), hex(fde['cie']), hex(fde['lsda']) if fde['lsda'] is not None else '', BODY_SHA256)])
    to_tsv(out/'instructions.tsv', ('va','bytes','operation','width','operand_a','operand_b','condition','target'),
           [(hex(r.va),r.data.hex(),r.op,r.width,repr(r.a) if r.a is not None else '',
             repr(r.b) if r.b is not None else '', '' if r.cc is None else r.cc,
             '' if r.target is None else hex(r.target & MASK[8])) for r in rows])
    to_tsv(out/'branch-mutations.tsv', ('va','original_bytes','witnesses','classification','outcomes'), mutation_rows)
    to_tsv(out/'branches.tsv', ('va','bytes','condition','target','fallthrough_seen','taken_seen'), branch_rows)
    to_tsv(out/'anchors.tsv', ('name','va','bytes'), [(name,hex(va),at(image,va,len(bytes.fromhex(p))).hex()) for name,va,p in PINS])
    to_tsv(out/'cases.tsv', ('group','case','internal_counts','edges','leaf_count','leaf_gap','keys_after','height_after','alloc_sizes','returned_slot','promoted_old_slot','left_count','right_count','visited_instructions','tree_sha256'),scenario_rows)
    to_tsv(out/'key-boundaries.tsv', ('insertion_order','date_i32','seconds_u32','nanos_u32','input_bytes','result'),
           [(i,date,seconds,nanos,struct.pack('<iII',date,seconds,nanos).hex(),'matched') for i,(date,seconds,nanos) in enumerate(varied)])
    to_tsv(out/'sequences.tsv', ('order','insertions','final_height','allocations','reached_instructions','observed_branch_edges'), sequences)
    to_tsv(out/'failure-landings.tsv', ('fixture','failure_call_va','lsda_landing_va'), failures)
    to_tsv(out/'cleanup-cases.tsv', ('entry_va','main_capacity','extra_capacity','terminal','ordered_hook_events'), cleanup)
    to_tsv(out/'lsda-call-sites.tsv', ('record_va','raw_bytes','start_va','end_va_exclusive','landing_va','action'),
           [(hex(at_va),raw.hex(),hex(begin),hex(end),hex(landing) if landing is not None else '',action) for at_va,raw,begin,end,landing,action in lsda])
    to_tsv(out/'controls.tsv', ('case','result','detail','alloc_sizes'),controls)
    relocs = relocation_records(image)
    plt, stub, slot, kind, index, addend, symbol = unwind_symbol(image)
    to_tsv(out/'unwind-symbol.tsv', ('call_site_va','plt_va','plt_bytes','slot_va','type','symbol_index','addend','symbol'),
           [(hex(0x2f513c0),hex(plt),stub.hex(),hex(slot),kind,index,hex(addend),symbol)])
    to_tsv(out/'relocations.tsv', ('slot_va','type','symbol_index','addend','symbol'),
           [(hex(slot),kind,index,hex(addend),name) for slot,(kind,index,addend,name) in sorted(relocs.items())])
    summary = dict(binary_sha256=SHA256, normal_cases=len(scenario_rows), negative_controls=len(controls),
                   fde_windows=1, sequence_cases=len(sequences), sequence_insertions=sum(r[1] for r in sequences), coverage=coverage,
                   lsda_records=len(lsda), landing_fixtures=len(cleanup), mixed_width_insertions=varied_result[0], mixed_width_height=varied_result[1],
                   branch_mutations={kind:sum(row[3] == kind for row in mutation_rows) for kind in sorted({row[3] for row in mutation_rows})},
                   limitations='Finite synthetic trees, modeled external boundaries, no target execution; FDE ranges are unwind extents.')
    (out/'summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2)+'\n',encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(generate(load_image(), args.out), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, Halt, Panicked, OSError, ValueError, struct.error) as error:
        print('staking_withdraw_time_insert94: ' + str(error), file=sys.stderr)
        sys.exit(1)
