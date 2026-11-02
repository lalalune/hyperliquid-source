#!/usr/bin/env python3
"""Static evaluator for the node 94 staking address-map insertion path.

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
        self.allowed_windows = None
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
            if self.allowed_windows is not None and not any(a <= pc < b for a,b in self.allowed_windows):
                raise Halt('control left selected FDEs')
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



# Only the allocation and byte-copy boundaries are simulated. The four body
# windows below are decoded from the checked image on every fresh machine.
FUNCTIONS = {'stake_insert': 0x2f54330, 'stake_entry': 0x33bede0}
SLOT_ALLOC = 0x576dfd8
SLOT_MEMCPY = 0x576dfe0
SLOT_MEMMOVE = 0x576e0e0
STOP_SLOTS = (0x576e470, 0x576e108, 0x576e020, 0x576e2e0, 0x576e010)
MARK_BASE = 0x7700000000
ARENA = HEAP_BASE + 0x10000
ARENA_END = HEAP_BASE + HEAP_SIZE
KEY_BASE = int.from_bytes(bytes(range(1, 21)), 'big')
LAYOUT_STANDARD = dict(parent=0xb0, value=0, width=16, key=0xb8, edge=0x194,
                       count=0x196, children=0x198, leaf=0x198, internal=0x1f8)



def value_for_key(key, width):
    base = int.from_bytes(bytes(range(1, width+1)), 'big')
    return (base + key * 13) & ((1 << (8 * width)) - 1)


class Fixture:
    """Build and validate a concrete, ordered tree with checked backlinks."""
    def __init__(self, image, patches=None, fail_alloc_at=None, layout=None):
        self.layout = layout or LAYOUT_STANDARD
        self.machine = Machine(image, patches)
        self.machine.real = frozenset((FUNCTIONS['stake_insert'],))
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
        return int.from_bytes(self.data(at, 20), 'big')

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
                    self.put(ptr+self.layout['key']+20*i, key.to_bytes(20, 'big'))
                    self.write(ptr+self.layout['value']+self.layout['width']*i, value_for_key(key, self.layout['width']), self.layout['width'])
                    self.expected_count += 1
            return ptr
        depth = len(edges)
        root = make(depth, internal_counts[0] if depth else leaf_count, tuple(edges))
        if self.selected is None: raise Halt('selected leaf missing')
        # Sorted interleaving has even keys, leaving a free odd key at every edge.
        keys, _ = self.inspect(root, depth)
        leaf_keys = [self.key(self.selected+self.layout['key']+20*i) for i in range(leaf_count)]
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
                    keys.append(self.key(ptr+self.layout['key']+20*i))
                    values.append(self.read(ptr+self.layout['value']+self.layout['width']*i, self.layout['width']))
        walk(root, depth, 0, 0)
        if keys != sorted(keys) or len(keys) != len(set(keys)): raise Halt('key order')
        return keys, values



def snapshot_tree(fixture, root, depth):
    """Capture all logical keys, values and child shapes from a verified tree."""
    count = fixture.read(root + fixture.layout['count'], 2)
    pairs = tuple((fixture.key(root + fixture.layout['key'] + 20*i),
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
        while i < n and fixture.key(node+fixture.layout['key']+20*i) < key:
            i += 1
        if i < n and fixture.key(node+fixture.layout['key']+20*i) == key:
            return node, path, i
        if not depth: return None
        node = fixture.read(node+fixture.layout['children']+8*i)
        path += (i,)
        depth -= 1

def evaluate(image, function, counts, edges, leaf_count, leaf_slot, patches=None,
             fail_alloc_at=None, bad_cursor_depth=False, null_root=False, expect_panic=False,
             corrupt_leaf_count=None, corrupt_parent_count=None, root_height_override=None, step_limit=None):
    layout = LAYOUT_STANDARD
    f = Fixture(image, patches, fail_alloc_at, layout)
    root, key = f.build(counts, edges, leaf_count, leaf_slot)
    before_keys, before_values = f.inspect(root, len(edges))
    original_root_keys = [f.key(root+layout['key']+20*i)
                          for i in range(f.read(root+layout['count'],2))]
    expected = list(zip(before_keys, before_values))
    before_tree = snapshot_tree(f, root, len(edges))
    new_value = value_for_key(key, layout['width']) + 1
    expected_tree = model_insert(before_tree, edges, leaf_slot, (key, new_value))
    expected.append((key, new_value))
    expected.sort()
    root_desc = f.alloc(24); holder = f.alloc(8); cursor = f.alloc(24)
    out = f.alloc(24); key_ptr = f.alloc(20); val_ptr = f.alloc(layout['width']); depth_ptr = f.alloc(8)
    f.write(root_desc, 0 if null_root else root)
    f.write(root_desc+8, len(edges))
    f.write(root_desc+16, len(before_keys))
    f.write(holder, root_desc)
    f.write(cursor, f.selected); f.write(cursor+8, 0); f.write(cursor+16, leaf_slot)
    f.put(key_ptr, key.to_bytes(20, 'big')); f.write(val_ptr, new_value, layout['width'])
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
    if step_limit is not None: m.step_limit=step_limit
    args = {RDI: out, RSI: cursor, RDX: key_ptr, RCX: new_value & MASK[8], R8: new_value >> 64, R9: holder}
    try:
        m.run(function, args, stack=(depth_ptr,))
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
    if returned_depth != 0 or f.key(returned+layout['key']+returned_slot*20) != key:
        raise Halt('returned cursor does not identify inserted key')
    if f.read(returned+layout['value']+returned_slot*layout['width'], layout['width']) != new_value:
        raise Halt('returned cursor does not identify inserted value')
    return dict(keys=len(keys_after), depth=depth_after,
                allocations=f.allocations, returned_slot=returned_slot,
                pivot=pivot_index, left_count=left_count, right_count=right_count,
                tree_hash=hashlib.sha256(repr(actual_tree).encode('ascii')).hexdigest(),
                visited=len(m.seen), seen=m.seen, branches=m.branches)


def adapter_case(image, n, slot, empty=False, fail_alloc_at=None, value_override=None, patches=None, counts=(), edges=(), catch_failure=False):
    f=Fixture(image, patches=patches, fail_alloc_at=fail_alloc_at)
    f.machine.real=frozenset((FUNCTIONS['stake_insert'],))
    f.machine.allowed_windows=tuple(image.exact_fde(start) for start in FUNCTIONS.values())
    if empty:
        if n != 0 or slot != 0 or counts or edges: raise ValueError('invalid empty fixture')
        root=0; key=KEY_BASE+1; before=[]; before_tree=((),())
    else:
        root,key=f.build(counts,edges,n,slot)
        before=list(zip(*f.inspect(root,len(edges))))
        before_tree=snapshot_tree(f,root,len(edges))
    mp, desc, out=(f.alloc(x) for x in (24,0x40,32))
    f.put(mp, bytes(24)); f.put(desc,bytes(0x40)); f.put(out,bytes(32))
    f.write(mp,root);f.write(mp+8,len(edges));f.write(mp+16,len(before))
    f.write(desc,mp);f.write(desc+8,0 if empty else f.selected);f.write(desc+16,0);f.write(desc+24,slot)
    f.put(desc+32,key.to_bytes(20,'big'))
    value=value_for_key(key,16)+1 if value_override is None else value_override
    try:
        f.machine.run(FUNCTIONS['stake_entry'],{RDI:out,RSI:desc,RDX:value & MASK[8],RCX:value >> 64})
    except Panicked as e:
        if not catch_failure: raise
        return dict(panic=str(e),allocations=f.allocations,seen=f.machine.seen,branches=f.machine.branches)
    if catch_failure: raise Halt('expected entry failure sink was not reached')
    r=f.read(mp); height=f.read(mp+8)
    keys, vals=f.inspect(r,height)
    expected=sorted(before+[(key,value)])
    if list(zip(keys,vals))!=expected or f.read(mp+16)!=len(expected):raise Halt('adapter content or map count mismatch')
    expected_tree=model_insert(before_tree,edges,slot,(key,value))
    if snapshot_tree(f,r,height)!=expected_tree: raise Halt('adapter shape differs from independent model')
    alloc_expected=[]
    if empty: alloc_expected.append(f.layout['leaf'])
    elif n==11:
        alloc_expected.append(f.layout['leaf'])
        for count in reversed(counts):
            if count!=11: break
            alloc_expected.append(f.layout['internal'])
        else: alloc_expected.append(f.layout['internal'])
    if f.allocations!=alloc_expected: raise Halt('adapter allocation order mismatch')
    pos=physical_position(f,r,height,key)
    if (f.read(out),f.read(out+8),f.read(out+16),f.read(out+24)) != (pos[0],height-len(pos[1]),pos[2],mp):
        raise Halt('adapter returned cursor mismatch')
    return dict(empty=empty,n=n,slot=slot,height=height,allocated=f.allocations,seen=f.machine.seen,branches=f.machine.branches)

# Fixed, manually inspected instruction witnesses. Lists and quantities in
# generated records come from the authenticated ELF and the exercised model.
WINDOWS = {
    'stake_insert': (0x2f54f90, '3ae32af0d7f05d55cd3771ee50b7ea58ead746c9ddd4606ecdd65bb8915885ce'),
    'stake_entry': (0x33bef2a, 'b3ebb5a3a786760ceff646c244d87981a1d659c4194926d0477ee0e08bd0cb6a'),
}
PINS = (
    ('profile_gate_call',0x3995372,'e8f9cbffff'),
    ('profile_gate_ok',0x399537f,'3d86010000'),
    ('profile_gate_failure',0x3995384,'0f85b4010000'),
    ('host_map_root',0x3995402,'4d8b7f10'),
    ('host_empty_root',0x3995416,'0f8485020000'),
    ('host_compare_slot',0x399542a,'4c8b255790dd01'),
    ('host_node_count',0x3995431,'410fb78796010000'),
    ('host_key_base',0x3995453,'bbb8000000'),
    ('host_compare_size',0x3995470,'ba14000000'),
    ('host_compare_call',0x3995478,'41ffd4'),
    ('host_equal_result',0x3995493,'0fb6c0'),
    ('host_equal_flags',0x3995496,'85c0'),
    ('host_equal_test',0x3995498,'750a'),
    ('host_equal_exit',0x399549a,'e9bc010000'),
    ('host_height_decrement',0x39954a9,'4883e801'),
    ('host_leaf_gap',0x39954ad,'0f820c0b0000'),
    ('host_child_array',0x39954b8,'4f8bbcef98010000'),
    ('host_duplicate_status',0x3995660,'66c745009300'),
    ('host_gap_to_insert',0x3995fce,'e9d1f6ffff'),
    ('stake_map_arg',0x39956a9,'488d4310'),
    ('user_first_word',0x39956ad,'498b0e'),
    ('user_second_word',0x39956b0,'498b5608'),
    ('register_zero_values',0x3995703,'31d231c9'),
    ('entry_call',0x3995707,'e8d496a2ff'),
    ('entry_insert_call',0x33bee47,'e8e454b9ff'),
    ('entry_map_increment',0x33beeda,'49ff4510'),
    ('entry_key_offset',0x33beeb6,'89b490c8000000'),
    ('entry_value_low',0x33beecf,'4c892410'),
    ('entry_value_high',0x33beed3,'4c897c1008'),
    ('node_count',0x2f5434d,'450fb7a596010000'),
    ('capacity',0x2f54355,'4983fc0b732f'),
    ('pivot_low',0x2f54393,'4983fc05'),
    ('pivot_high',0x2f54475,'4983fc06'),
    ('key_stride',0x2f54363,'488d0492'),
    ('key_base',0x2f54367,'488d1c85b8000000'),
    ('leaf_alloc_size',0x2f544af,'bf98010000'),
    ('leaf_count_write',0x2f54462,'664589a596010000'),
)


def at(image, va, size):
    if size < 0:
        raise EvidenceError('negative range')
    matches=[s for s in image.sections if s['type'] != 8 and s['size']
             and s['address'] <= va and va+size <= s['address']+s['size']]
    if len(matches)!=1:
        raise EvidenceError('range is not uniquely file-backed')
    section=matches[0]; offset=section['offset']+va-section['address']
    return bytes(image.blob[offset:offset+size])


def checked_call(image, site, target):
    data=at(image,site,5)
    if data[0]!=0xe8 or site+5+struct.unpack_from('<i',data,1)[0]!=target:
        raise EvidenceError('direct call mismatch')
    return data


def validate(image):
    for name,start in FUNCTIONS.items():
        end,digest=WINDOWS[name]
        if image.exact_fde(start)!=(start,end): raise EvidenceError('unexpected FDE extent')
        if hashlib.sha256(at(image,start,end-start)).hexdigest()!=digest:
            raise EvidenceError('function bytes mismatch: '+name)
    for name,va,expected in PINS:
        if at(image,va,len(bytes.fromhex(expected))).hex()!=expected:
            raise EvidenceError('witness mismatch: '+name)
    checked_call(image,0x3995707,FUNCTIONS['stake_entry'])
    checked_call(image,0x33bee47,FUNCTIONS['stake_insert'])


def case_specs():
    for n in range(12):
        for gap in range(n+1): yield ('leaf',(),(),n,gap)
    for n in (1,5,10,11):
        for edge in range(n+1):
            for gap in range(12): yield ('parent',(n,),(edge,),11,gap)
    for counts in ((1,11),(5,11),(11,5),(11,11)):
        choices=[sorted(set(x for x in (0,4,5,6,7,n) if x<=n)) for n in counts]
        for outer in choices[0]:
            for inner in choices[1]:
                for gap in (0,4,5,6,7,11): yield ('cascade',counts,(outer,inner),11,gap)
    for counts,edges in (((11,11,11),(0,5,11)),((11,11,11),(11,6,0)),
                         ((11,11,5),(6,5,5)),((1,11,11),(0,11,6))):
        for gap in (0,4,5,6,11): yield ('deep',counts,edges,11,gap)


def tsv(path, headings, rows):
    with path.open('w',encoding='utf-8',newline='') as f:
        writer=csv.writer(f,delimiter='\t',lineterminator='\n')
        writer.writerow(headings); writer.writerows(rows)


def mutation_results(image):
    controls=[]
    mutations=(('capacity',0x2f54358,10,10,5),('pivot',0x2f543b5,3,11,0),
               ('full_branch',0x2f54359,0x72,10,5),('key_tail',0x2f5437d,0x11,4,4),
               ('second_word_offset',0x2f54461,0,5,2))
    for label,addr,edit,n,gap in mutations:
        old=at(image,addr,1)[0]
        if old==edit: raise EvidenceError('mutation unchanged')
        evaluate(image,FUNCTIONS['stake_insert'],(),(),n,gap)
        try: evaluate(image,FUNCTIONS['stake_insert'],(),(),n,gap,patches={addr:edit})
        except (Halt,Panicked,EvidenceError) as e:
            if any(word in str(e) for word in ('step limit','unmodelled','undecodable')): raise
            controls.append((label,hex(addr),f'{old:02x}',f'{edit:02x}',type(e).__name__,str(e)))
        else: raise EvidenceError('undetected mutation: '+label)
    address=0x33beedd; old=at(image,address,1)[0]
    adapter_case(image,5,2,value_override=0)
    try: adapter_case(image,5,2,value_override=0,patches={address:8})
    except (Halt,Panicked,EvidenceError) as e:
        if any(word in str(e) for word in ('step limit','unmodelled','undecodable')): raise
        controls.append(('map_count_offset',hex(address),f'{old:02x}','08',type(e).__name__,str(e)))
    else: raise EvidenceError('undetected adapter mutation')
    return controls


def relocation_records(image):
    def section(name):
        rows=[s for s in image.sections if s['name']==name and s['type']!=8]
        if len(rows)!=1: raise EvidenceError('ambiguous relocation input')
        return rows[0]
    rel,syms,strings=(section(n) for n in ('.rela.dyn','.dynsym','.dynstr'))
    if (rel['type'],syms['type'],strings['type'])!=(4,11,3) or rel['size']%24 or syms['size']%24:
        raise EvidenceError('invalid relocation input')
    wanted=set((SLOT_ALLOC,SLOT_MEMCPY,SLOT_MEMMOVE,0x576e488)+STOP_SLOTS)
    result={}
    for off in range(rel['offset'],rel['offset']+rel['size'],24):
        slot,info,addend=struct.unpack_from('<QQq',image.blob,off)
        if slot not in wanted: continue
        if slot in result: raise EvidenceError('duplicate relocation')
        kind,index=info & 0xffffffff,info>>32; name=''
        if index:
            if index*24+24>syms['size']: raise EvidenceError('invalid symbol index')
            name_off=struct.unpack_from('<I',image.blob,syms['offset']+index*24)[0]
            if name_off>=strings['size']: raise EvidenceError('invalid name index')
            pos=strings['offset']+name_off
            end=image.blob.find(b'\0',pos,strings['offset']+strings['size'])
            if end<0: raise EvidenceError('unterminated symbol')
            name=image.blob[pos:end].decode('ascii')
        result[slot]=(kind,index,addend,name)
    if set(result)!=wanted: raise EvidenceError('missing relocation')
    for slot,symbol in ((SLOT_MEMCPY,'memcpy'),(SLOT_MEMMOVE,'memmove'),(0x576e488,'memcmp')):
        if result[slot][3]!=symbol: raise EvidenceError('unexpected import')
    return result


def generate(image,out):
    validate(image)
    out.mkdir(parents=True,exist_ok=True)
    decoded={}; functions=[]; insns=[]
    _,fdes=eh_frame_records(image.blob,image.sections)
    records={r['start']:r for r in fdes if r['start'] in FUNCTIONS.values()}
    for name,start in FUNCTIONS.items():
        end=WINDOWS[name][0]; rows=decode_range(image,start,end);decoded[name]=rows
        record=records[start]
        functions.append((name,hex(start),hex(end),hex(image.offset(start)),end-start,
                          hex(record['fde']),hex(record['cie']),WINDOWS[name][1],len(rows)))
        boundaries={r.va for r in rows}
        for r in rows:
            if r.op in ('jmp','jcc') and r.target not in boundaries:
                raise EvidenceError('branch target outside decoded boundaries')
            insns.append((name,hex(r.va),r.data.hex(),r.op,r.width,
                          repr(r.a) if r.a is not None else '',repr(r.b) if r.b is not None else '',
                          '' if r.cc is None else r.cc,'' if r.target is None else hex(r.target & MASK[8])))
    seen=set(); branch_seen=set(); scenarios=[]; branch_samples={}
    for idx,(group,counts,edges,n,gap) in enumerate(case_specs()):
        res=evaluate(image,FUNCTIONS['stake_insert'],counts,edges,n,gap)
        seen.update(res['seen']);branch_seen.update(res['branches'])
        for branch in res['branches']:
            branch_samples.setdefault(branch,(counts,edges,n,gap))
        scenarios.append((idx,group,','.join(map(str,counts)),','.join(map(str,edges)),n,gap,
                          res['keys'],res['depth'],','.join(map(str,res['allocations'])),
                          res['returned_slot'],'' if res['pivot'] is None else res['pivot'],
                          '' if res['left_count'] is None else res['left_count'],
                          '' if res['right_count'] is None else res['right_count'],res['visited'],res['tree_hash']))
    adapters=[]
    for empty,n,gap in [(True,0,0)]+[(False,n,g) for n in (0,1,5,10,11) for g in range(n+1)]:
        for value in (0,1,1<<64,(1<<128)-1):
            res=adapter_case(image,n,gap,empty,value_override=value)
            seen.update(res['seen']);branch_seen.update(res['branches'])
            adapters.append((int(empty),'','',n,gap,f'{value:032x}',res['height'],','.join(map(str,res['allocated']))))
    for counts,edges in (((1,),(0,)),((5,),(3,)),((11,),(5,)),((11,11),(6,5))):
        for gap in (0,4,5,6,7,11):
            for value in (0,(1<<128)-1):
                res=adapter_case(image,11,gap,value_override=value,counts=counts,edges=edges)
                seen.update(res['seen']);branch_seen.update(res['branches'])
                adapters.append((0,','.join(map(str,counts)),','.join(map(str,edges)),11,gap,
                                 f'{value:032x}',res['height'],','.join(map(str,res['allocated']))))
    controls=mutation_results(image)
    failures=[]; failure_seen=set(); failure_branches=set(); failure_edges=[]
    decoded_by_va={row.va:row for rows in decoded.values() for row in rows}
    def retain_failure_edges(label,result):
        for va,taken in sorted(result['branches']):
            row=decoded_by_va[va]
            failure_edges.append((label,hex(va),row.data.hex(),int(taken),
                                  hex(row.target if taken else row.next)))
    expected_failure={'first_leaf_allocation':0x2f54eef,'new_root_allocation':0x2f54f0c,
                      'parent_allocation':0x2f54eab,'cascade_root_allocation':0x2f54f0c,
                      'null_root':0x2f54efc,'invalid_leaf_count':0x2f54edd,
                      'invalid_parent_count':0x2f54e61,'height_overflow':0x2f54f1b,
                      'height_mismatch':0x2f54f36}
    for label,counts,edges,options in (
        ('first_leaf_allocation',(),(),dict(fail_alloc_at=1)),
        ('new_root_allocation',(),(),dict(fail_alloc_at=2)),
        ('parent_allocation',(11,),(6,),dict(fail_alloc_at=2)),
        ('cascade_root_allocation',(11,),(6,),dict(fail_alloc_at=3)),
        ('null_root',(),(),dict(null_root=True)),
        ('invalid_leaf_count',(),(),dict(corrupt_leaf_count=22)),
        ('invalid_parent_count',(11,),(0,),dict(corrupt_parent_count=22)),
        ('height_overflow',(),(),dict(root_height_override=MASK[8])),
        ('height_mismatch',(),(),dict(root_height_override=1))):
        result=evaluate(image,FUNCTIONS['stake_insert'],counts,edges,11,5,expect_panic=True,**options)
        if result['panic'] != 'failure sink reached at %#x' % expected_failure[label]:
            raise EvidenceError('wrong modeled failure boundary: '+label)
        failure_seen.update(result['seen']); failure_branches.update(result['branches'])
        retain_failure_edges(label,result)
        failures.append((label,result['panic'],','.join(map(str,result['allocations']))))
    result=adapter_case(image,0,0,True,fail_alloc_at=1,value_override=0,catch_failure=True)
    if result['panic']!='failure sink reached at 0x33bef0b': raise EvidenceError('wrong entry failure boundary')
    failure_seen.update(result['seen']); failure_branches.update(result['branches'])
    retain_failure_edges('entry_allocation',result)
    failures.append(('entry_allocation',result['panic'],','.join(map(str,result['allocations']))))
    branch_mutants=[]
    for row in decoded['stake_insert']:
        if row.op!='jcc': continue
        if 0x70<=row.data[0]<=0x7f: address=row.va
        elif row.data[0]==0x0f and 0x80<=row.data[1]<=0x8f: address=row.va+1
        else: raise EvidenceError('unsupported conditional encoding')
        old=at(image,address,1)[0]
        for taken in (False,True):
            spec=branch_samples.get((row.va,taken))
            if spec is None: continue
            counts,edges,n,gap=spec
            evaluate(image,FUNCTIONS['stake_insert'],counts,edges,n,gap,step_limit=50000)
            try:
                evaluate(image,FUNCTIONS['stake_insert'],counts,edges,n,gap,
                         patches={address:old^1},step_limit=50000)
            except (Halt,Panicked,EvidenceError) as e:
                status=type(e).__name__; detail=str(e)
            else: status='matches_model'; detail=''
            branch_mutants.append((hex(row.va),int(taken),hex(address),f'{old:02x}',f'{old^1:02x}',
                                   ','.join(map(str,counts)),','.join(map(str,edges)),n,gap,status,detail))
    branches=[]; coverage={} 
    for name,rows in decoded.items():
        js=[r for r in rows if r.op=='jcc']
        for r in js: branches.append((name,hex(r.va),r.data.hex(),r.cc,hex(r.target),int((r.va,False) in branch_seen),int((r.va,True) in branch_seen),int((r.va,False) in failure_branches),int((r.va,True) in failure_branches)))
        coverage[name]={'decoded':len(rows),'reached':sum(r.va in seen for r in rows),
                        'conditional':len(js),'both':sum((r.va,False) in branch_seen and (r.va,True) in branch_seen for r in js)}
    tsv(out/'functions.tsv',('role','start_va','end_va','file_offset','size','fde_va','cie_va','sha256','decoded_instructions'),functions)
    tsv(out/'instructions.tsv',('role','va','bytes','operation','width','operand_a','operand_b','cc','target'),insns)
    tsv(out/'anchors.tsv',('name','va','file_offset','bytes'),[(n,hex(a),hex(image.offset(a)),at(image,a,len(bytes.fromhex(b))).hex()) for n,a,b in PINS])
    tsv(out/'cases.tsv',('id','family','parent_counts','child_edges','leaf_count','gap','rows_after','height_after','allocation_sizes','returned_slot','promoted_slot','left_count','right_count','reached','tree_sha256'),scenarios)
    tsv(out/'adapter-cases.tsv',('empty_map','parent_counts','child_edges','leaf_count','gap','value_hex','height_after','allocation_sizes'),adapters)
    tsv(out/'branches.tsv',('role','va','bytes','cc','target','normal_fallthrough','normal_taken','failure_fallthrough','failure_taken'),branches)
    tsv(out/'branch-mutations.tsv',('va','normal_taken','edited_va','original','replacement','parent_counts','child_edges','leaf_count','gap','result','detail'),branch_mutants)
    relocs=relocation_records(image)
    tsv(out/'relocations.tsv',('slot_va','type','symbol_index','addend','symbol'),
        [(hex(slot),kind,index,hex(addend),name) for slot,(kind,index,addend,name) in sorted(relocs.items())])
    tsv(out/'mutations.tsv',('case','va','original','replacement','result','detail'),controls)
    tsv(out/'failure-cases.tsv',('case','boundary','allocations'),failures)
    tsv(out/'failure-edges.tsv',('case','va','bytes','taken','next_va'),failure_edges)
    summary={'binary_sha256':SHA256,'function_count':len(FUNCTIONS),'insertion_cases':len(scenarios),
             'adapter_cases':len(adapters),'targeted_mutations_detected':len(controls),
             'branch_mutation_samples':len(branch_mutants),
             'branch_mutation_outcomes':{k:sum(r[-2]==k for r in branch_mutants) for k in sorted({r[-2] for r in branch_mutants})},
             'modeled_failure_cases':len(failures),'coverage':coverage,
             'limits':'Synthetic trees and modeled allocation/copy boundaries; no target execution or component coverage claim.'}
    (out/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(generate(load_image(),args.out),sort_keys=True))

if __name__=='__main__':
    try: main()
    except (EvidenceError,Halt,Panicked,OSError,ValueError,struct.error) as error:
        print('staking_register_stake_map94: '+str(error),file=sys.stderr)
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
