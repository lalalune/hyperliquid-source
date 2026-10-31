#!/usr/bin/env python3
"""Pin the node #94 outcome deploy mark price and the source of its one input from ELF bytes.

Functions 0x274c9f0, 0x4d6c760 and 0x4d6d570 deploy one outcome market. For each side they read a u64
value v from the outcome record, convert it to f64, multiply by 0.5, round, floor at 1 and store the
result at table row +0x78. The value comes from 0x3c014b0, which writes the constant 100000000. The
real bytes run over real table layouts with only the calls stubbed, a separately written
specification predicts every run, and the chain after the round call is proved for all 2^64 f64 bit
patterns. No objdump or readelf output is parsed, and the binary is never executed. Standard library
only.

    python3 tools/outcome_deploy_mark.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
import hashlib
import json
import math
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x40000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 6000


class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class Image:
    """Section, relocation and FDE views of one ELF byte string, through the shared parsers."""

    def __init__(self, blob):
        self.blob = blob
        self.relative_map = None
        self.sections = sections(blob)
        # SHT_NOBITS sections have no file bytes, so they never resolve an address.
        self.mapped = sorted((s for s in self.sections if s["type"] != 8 and s["address"] and s["size"]),
                             key=lambda s: s["address"])
        self.named = {s["name"]: s for s in self.sections}
        _, fdes = eh_frame_records(blob, self.sections)
        ends = {}
        for row in fdes:
            ends[row["start"]] = max(ends.get(row["start"], 0), row["end"])
        self.fde_ends = ends
        self.starts = sorted(ends)

    def offset(self, va):
        for section in self.mapped:
            if section["address"] <= va < section["address"] + section["size"]:
                return va - section["address"] + section["offset"]
        raise EvidenceError("address outside file-backed sections: %#x" % va)

    def fde(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index < 0 or va >= self.fde_ends[self.starts[index]]:
            raise EvidenceError("address outside every FDE: %#x" % va)
        return self.starts[index], self.fde_ends[self.starts[index]]

    def exact_fde(self, va):
        start, end = self.fde(va)
        if start != va:
            raise EvidenceError("not an FDE start: %#x" % va)
        return start, end

    def text_bytes(self):
        text = self.named[".text"]
        return text["address"], bytes(self.blob[text["offset"]:text["offset"] + text["size"]])

    def relocations(self):
        """Yield (slot, type, addend, symbol index) for .rela.dyn."""
        rela = self.named[".rela.dyn"]
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", self.blob, at)
            yield slot, info & 0xFFFFFFFF, addend, info >> 32

    def relative(self):
        if self.relative_map is None:
            self.relative_map = {slot: addend for slot, kind, addend, _ in self.relocations() if kind == 8}
        return self.relative_map

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/"):
            if marker in path:
                path = path[path.rindex(marker) + 1:]
                break
        return path, line, column


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


def to_float(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & MASK[8]))[0]


def to_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {4: "shl", 5: "shr", 7: "sar"}


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
            for operand in (a, b):
                if operand and operand[0] == "r" and 4 <= operand[1] <= 7:
                    raise EvidenceError("high byte register at %#x" % va)

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
    if byte == 0x98 and wide:
        return finish("cdqe")
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
        if kind in (2, 3, 4, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 6: "div"}[kind], rm, w=w)
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
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
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
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
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

    def run(self, entry, args):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        self.push(RETURN_SENTINEL)
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
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
            return row.target if self.condition(row.cc) else row.next
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
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            self.put(row.a, width, self.get(row.b, width) * row.target)
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
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
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
            count = (row.target if op == "shld" else self.regs[RCX]) & 63
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
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
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






# ---- targets ----

COPIES = (0x274C9F0, 0x4D6C760, 0x4D6D570)
SIDE_BUILDER = 0x3C014B0
VALIDATOR = 0x3728D20
RESOLVER = 0x37288B0
VALUE_LOOKUP = 0x372B4B0
ROUND = 0x565F410
HASH = 0x399C4A0
RECORDER = 0x358DCD0
FLOAT_DECIMAL = 0x3790B60
SLOT_VALIDATOR = 0x5774C78
SLOT_RESOLVER = 0x5774C80
SLOT_LOOKUP = 0x5774788
SLOT_ROUND = 0x576F6D8
SLOT_FLOAT_DECIMAL = 0x5774C20
SLOT_RECORDER = 0x5773190
SLOT_COPY = 0x576DFE0
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576DFC8
SLOT_BTREE = 0x5773170
SLOT_QUOTE_OK = 0x5775E58
DECIMAL_NEW = 0x4EAC740
DECIMAL_DROP = 0x3762510
WEI_LOCATION = 0x56DFD90
PAIR_LOCATION = 0x56F1FD8

# Calls that differ by copy, read from the rows of each function.
EDGES = {
    0x274C9F0: dict(marks=0x3388, users=0x8B8, insert=0x284F810, deploy=0x2748310, liquidity=0x274FD60,
                    batch_a=0x24FDED0, batch_b=0x24FC8A0, drop=0x277EBA0, clone=None, rounds=(0x274D03E, 0x274D1A3), dirty=0x56BD990),
    0x4D6C760: dict(marks=0x3388, users=0x8B8, insert=0x4941FE0, deploy=0x4D63BE0, liquidity=0x4D73550,
                    batch_a=0x432BF70, batch_b=0x432B440, drop=0x4DAF4A0, clone=0x4DF98D0, rounds=(0x4D6CB65, 0x4D6CCC2), dirty=0x5744598),
    0x4D6D570: dict(marks=0x3E08, users=0x1338, insert=0x4941FE0, deploy=0x4D642F0, liquidity=0x4D72A80,
                    batch_a=0x432BF70, batch_b=0x432A990, drop=0x4DAF4A0, clone=0x4DF98D0, rounds=(0x4D6D975, 0x4D6DAD2), dirty=0x5744598),
}

OK = 0x186
FAILED = 0x140
INVALID_TOKEN = 0xEA
INVALID_QUOTE = 0xEF
LENGTH = 0x143
TEXT = 0x17B
WHOLE_UNIT = 100000000
TICK_WORD = 1000
MAX_OUTCOME = 19999
SIDE_NAME_LIMIT = 100
ERROR_NICHE = 1 << 63
ONE_POINT_ZERO = b"1.0"
U64_MAX = MASK[8]
TWO_64 = 18446744073709551616.0

TEXTS = {
    "decimals": (0x5B8E9A, 30, b"outcome token invalid decimals"),
    "not_outcome": (0x5B8EB8, 26, b"token is not outcome token"),
    "deployed": (0x5B8EE4, 30, b"outcome token already deployed"),
    "not_valid": (0x5B8ED2, 18, b"token is not valid"),
    "distinct": (0x599359, 31, b"outcome tokens must be distinct"),
    "limit": (0x59934B, 14, b"limit exceeded"),
    "unexpected": (0x599339, 18, b"outcome unexpected"),
}
CONSTANTS = {
    0x20A940: ("one half", 0x3FE0000000000000),
    0x20A4B0: ("infinity", 0x7FF0000000000000),
    0x20A510: ("2^64", 0x43F0000000000000),
    0x20A218: ("largest f64 below 2^64", 0x43EFFFFFFFFFFFFF),
    0x20A7F0: ("2^63", 0x43E0000000000000),
    0x203E80: ("exponent words 0x43300000 0x45300000", 0x4530000043300000),
    0x202EA0: ("2^52", 0x4330000000000000),
    0x202EA8: ("2^84", 0x4530000000000000),
}

STATE = HEAP_BASE + 0x1000
META = STATE + 0x90
SPOT = STATE + 0x80
TOKENS = HEAP_BASE + 0x10000
LISTS = HEAP_BASE + 0x12000
PAIRS = HEAP_BASE + 0x13000
MARKS = HEAP_BASE + 0x14000
OUT = HEAP_BASE + 0x200
USER = HEAP_BASE + 0x300
PARAM_A = HEAP_BASE + 0x340
PARAM_B = HEAP_BASE + 0x380
CONTEXT = HEAP_BASE + 0x400
SIDE = HEAP_BASE + 0x440
QUOTE_WORD = HEAP_BASE + 0x480
BTREE_HEAD = HEAP_BASE + 0x4C0
NODES = HEAP_BASE + 0x15000
ROOTS = HEAP_BASE + 0x16000
TABLES = HEAP_BASE + 0x18000
BRK = HEAP_BASE + 0x30000
USED = 0x31000
TOKEN_STRIDE = 0xE8
PAIR_STRIDE = 0x20
MARK_STRIDE = 0xD8
MARK_FIELD = 0x78
MARK_ROWS = 16
RECORD_STRIDE = 0x90
BUCKETS = 128
IMPORT_MARK = 0xF00000000000
USER_BYTES = bytes(range(0x31, 0x45))
DECIMAL_BYTES = bytes(range(0x50, 0x60))
FILL = 0x77


def fdiv(left, right):
    if right == 0.0:
        return math.nan if left == 0.0 or left != left else math.copysign(math.inf, left) * math.copysign(1.0, right)
    return left / right


# ---- the specification, written from the claim and not from the evaluator ----

def round_half_away(value):
    if value != value or math.isinf(value):
        return value
    magnitude = fractions.Fraction(abs(value))
    return math.copysign(float(math.floor(magnitude + fractions.Fraction(1, 2))), value)


def spec_tail(y):
    """The chain after the round call, for any f64 y."""
    if y != y or y <= 0.0 or math.isinf(y):
        return 1
    if y >= TWO_64:
        return U64_MAX
    return max(1, int(y))


def spec_mark(v):
    return spec_tail(round_half_away(float(v) * 0.5))


def closed_mark(v):
    """Same value in integers: F is v after correct rounding to f64."""
    whole = int(float(v))
    return max(1, (whole + 1) >> 1)


def reference_formula(low, high):
    """OutcomeScalar::rounded_mid_mark as the reference writes it."""
    mid = max(round_half_away((float(low) + float(high)) * 0.5), 0.0)
    raw = int(min(mid, float(U64_MAX)))
    return 1 if raw == 0 else min(raw, U64_MAX)


class Deploy:
    """One call of a deploy copy; everything the stubs answer is a field."""

    def __init__(self, **fields):
        self.validate_error = None
        self.outcome = 41
        self.resolve_fail = False
        self.primary, self.linked = 2, 3
        self.token_rows = 9
        self.lists = {2: [4], 3: [5]}
        self.pairs = {4: (7, 11), 5: (8, 11)}
        self.pair_rows = 12
        self.mark_rows = MARK_ROWS
        self.quote = 11
        self.user = USER_BYTES
        self.values = {4: WHOLE_UNIT, 5: WHOLE_UNIT}
        self.deployed = {}
        self.liquidity = {}
        self.first_decimal_ok = True
        self.second_decimal_tag = OK
        self.bare_record = False
        self.__dict__.update(fields)


RECORD_CAPACITIES = (0x10, 0x38, 0x60, 0x78)


def spec_deploy(case, entry=None):
    events = [("validate", case.quote)]
    if case.validate_error is not None:
        events_out = ("error", case.validate_error)
        return dict(events=events, out=events_out, marks={}, dirty=0)
    events.append(("resolve", case.outcome))
    marks = {}
    state = dict(events=events, marks=marks, dirty=0, out=None)

    def fail(result_tag=None):
        if result_tag is not None:
            events.append(("drop", result_tag))
        state["dirty"] = 1
        events.append(("recorder", 4, EDGES[entry or COPIES[1]]["dirty"]))
        if any(case.user):
            events.append(("insert", case.user))
        state["out"] = ("tag", FAILED, None)
        if not case.bare_record:
            events.extend(("free", capacity) for capacity in RECORD_CAPACITIES)
        return state

    if case.resolve_fail:
        return fail()
    for side, row in enumerate((case.primary, case.linked)):
        if row >= case.token_rows:
            state["out"] = ("panic", PANIC_TABLE[0])
            return state
        entries = case.lists.get(row, [])
        if entries:
            pair = entries[0]
            if pair >= case.pair_rows:
                state["out"] = ("bounds", pair)
                return state
            if case.pairs.get(pair, (0, 0))[1] != case.quote:
                return fail(INVALID_TOKEN)
        else:
            if side == 0 and not case.first_decimal_ok:
                return fail(0xAC)
            if side == 1 and case.second_decimal_tag != OK:
                return fail(case.second_decimal_tag)
            events.append(("deploy", row, case.quote))
            answer = case.deployed.get(row, ("ok", 6))
            if answer[0] != "ok":
                return fail(answer[1])
            pair = answer[1]
            events.append(("liquidity", pair))
            tag = case.liquidity.get(pair, OK)
            if tag != OK:
                events.extend((("free", 3), ("free", 3)))
                return fail(tag)
            events.extend((("free", 3), ("free", 3)))
        events.append(("lookup", pair))
        value = case.values.get(pair, WHOLE_UNIT)
        if value is None:
            return fail()
        if pair >= case.mark_rows:
            state["out"] = ("panic", PANIC_TABLE[1 + side])
            return state
        marks[pair] = spec_mark(value)
    events.append(("batch_a",))
    events.append(("batch_b",))
    state["out"] = ("tag", OK, case.outcome)
    return state


class Side:
    """One side record for the builder."""

    def __init__(self, **fields):
        self.token = 7
        self.capacity = 16
        self.name_length = 3
        self.token_rows = 9
        self.decimals = (0, 5)
        self.registered = True
        self.deployed = False
        self.balance = (U64_MAX, 0)
        self.height = 0
        self.other_keys = ()
        self.quote_ok = True
        self.collide = False
        self.full = False
        self.__dict__.update(fields)


def spec_side(side):
    """(tag, payload words, frees, recorder calls)"""
    name = (side.capacity, name_pointer(side), side.name_length)
    freed = [("free", name_pointer(side), side.capacity)] if side.capacity else []
    if side.token >= side.token_rows:
        return dict(tag=INVALID_TOKEN, words=None, freed=freed, recorded=[])
    if side.name_length > SIDE_NAME_LIMIT:
        return dict(tag=LENGTH, words=(None, None, side.name_length), freed=freed, recorded=[])

    def text(key):
        return dict(tag=TEXT, words=(TEXTS[key][0], TEXTS[key][1]), freed=freed, recorded=[])

    if side.decimals != (0, 5):
        return text("decimals")
    if not side.registered:
        return text("not_outcome")
    if side.deployed:
        return text("deployed")
    held = side.balance
    if held is None:
        return text("not_valid")
    total, reserved = held
    if total < reserved:
        answer = text("not_valid")
        answer["recorded"] = [(0, WEI_LOCATION)]
        return answer
    if total - reserved != U64_MAX:
        return text("not_valid")
    if not side.quote_ok:
        return dict(tag=INVALID_QUOTE, words=None, freed=freed, recorded=[])
    return dict(tag=OK, words=name + (WHOLE_UNIT, side.token), freed=[], recorded=[])


def name_pointer(side):
    return HEAP_BASE + 0x500 + (side.token & 0xFFFF) * 0x10


class Validate:
    """One call of the validator with the real side builder inside."""

    def __init__(self, **fields):
        self.first = Side(token=7)
        self.second = Side(token=8)
        self.quote_entry = 1
        self.quote = 11
        self.counter = 40
        self.outcome_taken = False
        self.quote_height = 0
        self.extra_capacity = (0x31, 0x51)
        self.__dict__.update(fields)


def extra_freed(case):
    rows = zip(case.extra_capacity, (0x1111, 0x2222))
    return [("free", pointer, capacity) for capacity, pointer in rows if capacity]


def spec_validate(case):
    """(end, tag or id, payload or record words, frees)"""
    extra = extra_freed(case)

    def owned(*sides):
        return [("free", name_pointer(side), side.capacity) for side in sides if side.capacity]

    def done(end, code, words, freed):
        return (end, code, words, sorted(freed))

    if case.quote_entry != 1:
        return done("error", INVALID_QUOTE, None, owned(case.first, case.second) + extra)
    first, second = spec_side(case.first), spec_side(case.second)
    if first["tag"] != OK:
        keep = owned(case.second) if second["tag"] == OK else second["freed"]
        return done("error", first["tag"], first["words"], first["freed"] + keep + extra)
    if second["tag"] != OK:
        return done("error", second["tag"], second["words"], second["freed"] + owned(case.first) + extra)
    for broken, key in ((case.first.token == case.second.token, "distinct"), (case.counter > MAX_OUTCOME, "limit"),
                        (case.outcome_taken, "unexpected")):
        if broken:
            return done("error", TEXT, (TEXTS[key][0], TEXTS[key][1]), owned(case.first, case.second) + extra)
    words = (case.counter, case.first.capacity, name_pointer(case.first), case.first.name_length, WHOLE_UNIT, case.first.token,
             case.second.capacity, name_pointer(case.second), case.second.name_length, WHOLE_UNIT, case.second.token,
             case.extra_capacity[0], 0x1111, 0x41, case.extra_capacity[1], 0x2222, 0x61, TICK_WORD)
    return done("record", case.counter, words, [])


class Lookup:
    """One call of the value lookup."""

    def __init__(self, **fields):
        self.pair = 4
        self.pair_rows = 12
        self.token = 7
        self.outcome = 41
        self.first_token, self.first_value = 7, 111
        self.second_token, self.second_value = 8, 222
        self.has_outcome = True
        self.has_record = True
        self.empty_first = self.empty_second = False
        self.collide = False
        self.full = False
        self.__dict__.update(fields)


def spec_lookup(case):
    if case.pair >= case.pair_rows:
        return ("bounds", case.pair, PAIR_LOCATION)
    if case.empty_first or not case.has_outcome:
        return ("error", 3)
    if case.empty_second or not case.has_record:
        return ("error", 4)
    if case.first_token == case.token:
        return ("value", case.first_value)
    if case.second_token == case.token:
        return ("value", case.second_value)
    return ("error", 2)


PANIC_TABLE = (0x56F21F0, 0x5742338, 0x5742338)


# ---- harness ----

def hash_of(key):
    return (key * 0x9E3779B97F4A7C15 + 0x1234) & U64_MAX


class Harness:
    def __init__(self, image, patches=None, constants=None):
        self.image = image
        self.machine = Machine(image, patches)
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        self.relative = relative
        slots = (SLOT_VALIDATOR, SLOT_RESOLVER, SLOT_LOOKUP, SLOT_ROUND, SLOT_FLOAT_DECIMAL, SLOT_RECORDER, SLOT_COPY,
                 SLOT_ALLOC, SLOT_FREE, SLOT_PANIC, SLOT_BOUNDS, SLOT_BTREE, SLOT_QUOTE_OK)
        target = {slot: relative.get(slot, IMPORT_MARK + slot) for slot in slots}
        self.target = target
        machine.memory.statics.update(target)
        machine.memory.statics.update(constants or {})
        self.common = {target[SLOT_VALIDATOR]: self.on_validate, target[SLOT_RESOLVER]: self.on_resolve,
                       target[SLOT_LOOKUP]: self.on_lookup, target[SLOT_FLOAT_DECIMAL]: self.on_float_decimal,
                       target[SLOT_RECORDER]: self.on_recorder, target[SLOT_COPY]: self.on_copy,
                       target[SLOT_ALLOC]: self.on_alloc, target[SLOT_FREE]: self.on_free,
                       target[SLOT_PANIC]: self.on_panic, target[SLOT_BOUNDS]: self.on_bounds,
                       target[SLOT_BTREE]: self.on_btree, target[SLOT_QUOTE_OK]: self.on_quote_ok}
        machine.slots = dict(self.common)
        machine.real = frozenset((ROUND, SIDE_BUILDER))
        self.frees = []
        self.recorded = []

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def bytes_at(self, at, count):
        return self.machine.memory.bytes_at(at, count)

    # stubs shared by the runs

    def on_copy(self, machine):
        regs = machine.regs
        if regs[RDX]:
            machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_alloc(self, machine):
        if machine.regs[RDI] != 3:
            raise Halt("allocation size")
        machine.regs[RAX] = self.brk
        self.brk += (machine.regs[RDI] + 15) & ~15

    def on_free(self, machine):
        self.frees.append(("free", machine.regs[RDI], machine.regs[RSI]))
        self.events.append(("free", machine.regs[RSI]))

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_bounds(self, machine):
        raise Panicked(("bounds", machine.regs[RDI], machine.regs[RDX]))

    def on_recorder(self, machine):
        self.recorded.append((machine.regs[RDI], machine.regs[RSI]))
        self.events.append(("recorder", machine.regs[RDI], machine.regs[RSI]))

    def on_hash(self, machine):
        if machine.regs[RDI] not in self.hashers:
            raise Halt("hash of an unexpected table")
        machine.regs[RAX] = hash_of(self.read(machine.regs[RSI]))

    # deploy copy stubs

    def on_validate(self, machine):
        regs = machine.regs
        case = self.case
        frame = regs[RSP]
        if regs[RSI] != META or self.read(frame) != SPOT or regs[R8] != case.quote:
            raise Halt("validator arguments")
        if self.bytes_at(regs[RDX], 20) != case.user:
            raise Halt("validator user")
        for index in range(8):
            if self.read(regs[RCX] + index * 8) != 0x1001 + index:
                raise Halt("validator parameters")
        for index in range(6):
            if self.read(regs[R9] + index * 8) != 0x2001 + index:
                raise Halt("validator parameters")
        self.events.append(("validate", regs[R8]))
        out = regs[RDI]
        if case.validate_error is not None:
            for index in range(0x12):
                self.word(out + index * 8, 0xC0C0000000000000 + index)
            self.word(out + 8, ERROR_NICHE)
            self.word(out + 0x10, case.validate_error, 2)
            return
        for index in range(0x12):
            self.word(out + index * 8, 0xB0B0000000000000 + index)
        self.word(out, case.outcome)
        for at in (0x18, 0x40, 0x68, 0x80):
            self.word(out + at, 0)
        for at in (0x08, 0x30, 0x58, 0x70):
            self.word(out + at, 0 if case.bare_record else at + 8)
        self.record = self.bytes_at(out + 8, 0x88)

    def on_clone(self, machine):
        machine.memory.copy(machine.regs[RDI], machine.regs[RSI], 0x90)

    def on_resolve(self, machine):
        regs = machine.regs
        case = self.case
        if regs[RSI] != META or regs[RCX] != case.outcome or self.bytes_at(regs[RDX], 20) != case.user:
            raise Halt("resolver arguments")
        self.events.append(("resolve", regs[RCX]))
        self.word(regs[RDI], 1 if case.resolve_fail else 0, 1)
        self.word(regs[RDI] + 8, case.primary)
        self.word(regs[RDI] + 16, case.linked)

    def on_lookup(self, machine):
        regs = machine.regs
        if regs[RSI] != META or regs[RCX] != META:
            raise Halt("lookup arguments")
        self.events.append(("lookup", regs[RDX]))
        value = self.case.values.get(regs[RDX], WHOLE_UNIT)
        self.word(regs[RDI], 1 if value is None else 0, 1)
        self.word(regs[RDI] + 8, 0xDEAD if value is None else value)

    def on_decimal_new(self, machine):
        regs = machine.regs
        if self.read(regs[RSI]) != 1 << 52 or self.read(regs[RSI] + 8, 4) != 0 or regs[RDX] & MASK[4] != 0xFFFFFFCB:
            raise Halt("decimal arguments")
        if (regs[RCX] & MASK[4], regs[R8] & MASK[4], regs[R9] & MASK[4]) != (1, 1, 1):
            raise Halt("decimal flags")
        self.word(regs[RDI], 1 if self.case.first_decimal_ok else 0, 4)
        machine.memory.put_bytes(regs[RDI] + 4, DECIMAL_BYTES)

    def on_float_decimal(self, machine):
        regs = machine.regs
        if machine.xmm[0] & MASK[8] != to_bits(0.5):
            raise Halt("float argument")
        tag = self.case.second_decimal_tag
        self.word(regs[RDI], tag, 2)
        if tag == OK:
            machine.memory.put_bytes(regs[RDI] + 4, DECIMAL_BYTES)

    def on_deploy(self, machine):
        regs = machine.regs
        case = self.case
        row, quote = self.read(regs[RCX]), self.read(regs[RCX] + 8)
        if regs[RSI] != STATE or self.bytes_at(regs[RDX], 20) != case.user:
            raise Halt("deploy arguments")
        if self.bytes_at(regs[R8], 16) != DECIMAL_BYTES:
            raise Halt("deploy decimal")
        self.events.append(("deploy", row, quote))
        answer = case.deployed.get(row, ("ok", 6))
        self.word(regs[RDI], OK if answer[0] == "ok" else answer[1], 2)
        self.word(regs[RDI] + 8, answer[1])

    def on_liquidity(self, machine):
        regs = machine.regs
        for at in (regs[R8], regs[R9]):
            pointer, length = self.read(at + 8), self.read(at + 16)
            if length != 3 or self.read(at) != 3 or self.bytes_at(pointer, 3) != ONE_POINT_ZERO:
                raise Halt("liquidity text")
        if regs[RSI] != STATE or self.bytes_at(regs[RDX], 20) != self.case.user:
            raise Halt("liquidity arguments")
        if self.read(regs[RSP] + 8) != 0 or self.read(regs[RSP] + 16) != 0:
            raise Halt("liquidity stack arguments")
        self.events.append(("liquidity", regs[RCX]))
        self.word(regs[RDI], self.case.liquidity.get(regs[RCX], OK), 2)

    def on_drop(self, machine):
        self.events.append(("drop", self.read(machine.regs[RDI], 2)))

    def on_insert(self, machine):
        if machine.regs[RDI] != STATE + self.edges["users"]:
            raise Halt("insert set")
        self.events.append(("insert", self.bytes_at(machine.regs[RSI], 20)))

    def on_batch_a(self, machine):
        regs = machine.regs
        at = regs[RSI]
        if self.read(at) != 0 or self.read(at + 8) != 1 or self.read(at + 0x98) != self.case.outcome:
            raise Halt("batch item")
        if self.bytes_at(at + 0x10, 0x88) != self.record:
            raise Halt("batch record")
        if tuple(self.read(regs[RDI] + o) for o in (0, 8, 16)) != (0, 8, 0):
            raise Halt("batch list")
        self.word(regs[RDI], 1)
        self.word(regs[RDI] + 8, 0x4444)
        self.word(regs[RDI] + 16, 1)
        self.events.append(("batch_a",))

    def on_batch_b(self, machine):
        regs = machine.regs
        if regs[RSI] != STATE or tuple(self.read(regs[RDI] + o) for o in (0, 8, 16)) != (1, 0x4444, 1):
            raise Halt("batch state")
        self.events.append(("batch_b",))

    def on_decimal_drop(self, machine):
        if self.read(machine.regs[RDI], 2) != 0xAC:
            raise Halt("decimal drop tag")

    def install_deploy(self, case, entry):
        memory = self.machine.memory
        memory.reset(USED)
        self.case = case
        self.edges = edges = EDGES[entry]
        self.events = []
        self.frees = []
        self.recorded = []
        self.brk = BRK
        self.machine.calls = {DECIMAL_NEW: self.on_decimal_new, DECIMAL_DROP: self.on_decimal_drop, edges["insert"]: self.on_insert,
                              edges["deploy"]: self.on_deploy, edges["liquidity"]: self.on_liquidity,
                              edges["batch_a"]: self.on_batch_a, edges["batch_b"]: self.on_batch_b, edges["drop"]: self.on_drop}
        if edges["clone"]:
            self.machine.calls[edges["clone"]] = self.on_clone
        memory.put_bytes(USER, case.user)
        for index in range(8):
            self.word(PARAM_A + index * 8, 0x1001 + index)
        for index in range(6):
            self.word(PARAM_B + index * 8, 0x2001 + index)
        self.word(STATE + 0x1E8, 0, 1)
        self.word(STATE + 0x1F8, PAIRS)
        self.word(STATE + 0x200, case.pair_rows)
        self.word(STATE + 0x208, 0)
        self.word(STATE + 0x210, TOKENS)
        self.word(STATE + 0x218, case.token_rows)
        self.word(STATE + 0x220, 0)
        self.word(STATE + edges["marks"], MARKS)
        self.word(STATE + edges["marks"] + 8, case.mark_rows)
        self.word(STATE + edges["marks"] + 0x10, 0)
        at = LISTS
        for row in range(16):
            entries = case.lists.get(row, [])
            self.word(TOKENS + row * TOKEN_STRIDE + 0x58, at)
            self.word(TOKENS + row * TOKEN_STRIDE + 0x60, len(entries))
            for item in entries:
                self.word(at, item)
                at += 8
        for pair in range(32):
            token, quote = case.pairs.get(pair, (0, 0))
            self.word(PAIRS + pair * PAIR_STRIDE, token)
            self.word(PAIRS + pair * PAIR_STRIDE + 8, quote)
        for row in range(MARK_ROWS):
            for at in range(0, MARK_STRIDE, 8):
                self.word(MARKS + row * MARK_STRIDE + at, 0x5151000000000000 + row * 0x1000 + at)

    def run_deploy(self, entry, case):
        self.install_deploy(case, entry)
        machine = self.machine
        try:
            value = machine.run(entry, {RDI: OUT, RSI: STATE, RDX: USER, RCX: PARAM_A, R8: case.quote, R9: PARAM_B})
        except Panicked as stop:
            detail = stop.args[0]
            out = ("panic", detail[1]) if detail[0] == "panic" else ("bounds", detail[1])
            return self.deploy_state(out)
        if value not in (OUT, machine.regs[RAX]):
            raise Halt("return value")
        if case.validate_error is not None:
            if self.read(OUT, 2) != case.validate_error:
                raise Halt("error tag was not copied")
            for index in range(1, 0xC):
                if self.read(OUT + index * 8) != 0xC0C0000000000000 + index + 2:
                    raise Halt("error payload was not copied")
            out = ("error", case.validate_error)
        else:
            tag = self.read(OUT, 2)
            out = ("tag", tag, self.read(OUT + 8) if tag == OK else None)
        return self.deploy_state(out)

    def deploy_state(self, out):
        marks = {}
        for row in range(MARK_ROWS):
            for at in range(0, MARK_STRIDE, 8):
                word = self.read(MARKS + row * MARK_STRIDE + at)
                if word != 0x5151000000000000 + row * 0x1000 + at:
                    if at != MARK_FIELD:
                        raise Halt("write beside the mark field")
                    marks[row] = word
        return dict(events=self.events, out=out, marks=marks, dirty=self.read(STATE + 0x1E8, 1))

    # real side builder, validator and lookup

    def swiss(self, base, stride, rows, offset_key=0, collide=False, full=False):
        """Lay out one hash table: control bytes at base, entries below it, as the probes read them."""
        memory = self.machine.memory
        memory.put_bytes(base, b"\xff" * (BUCKETS + 16))
        for key, payload in rows.items():
            value = hash_of(key)
            position = value & (BUCKETS - 1)
            top = value >> 57
            place = position
            if full:
                for index in range(48):
                    self.fill_slot(base, stride, (position + index) & (BUCKETS - 1), top ^ 1, key ^ 0x7777, payload)
                place = (position + 48) & (BUCKETS - 1)
            if collide:
                self.fill_slot(base, stride, place, top, key ^ 0x5A5A, payload)
                self.fill_slot(base, stride, (place + 1) & (BUCKETS - 1), top, key ^ 0x5A5B, payload)
                place = (place + 3) & (BUCKETS - 1)
            self.fill_slot(base, stride, place, top, key, payload)

    def fill_slot(self, base, stride, place, top, key, payload):
        memory = self.machine.memory
        memory.write(base + place, 1, top)
        if place < 16:
            memory.write(base + BUCKETS + place, 1, top)
        at = base - (place + 1) * stride
        memory.put_bytes(at, b"\xcd" * stride)
        self.word(at, key)
        memory.put_bytes(at + 8, payload)

    def table(self, holder, ctrl, count, base_of_hasher):
        self.word(holder, ctrl)
        self.word(holder + 8, BUCKETS - 1)
        self.word(holder + 0x10, 0)
        self.word(holder + 0x18, count)
        self.hashers.add(base_of_hasher)

    def install_sides(self, sides):
        memory = self.machine.memory
        self.word(STATE + 0x210, TOKENS)
        rows = max(side.token_rows for side in sides)
        self.word(STATE + 0x218, rows)
        for side in sides:
            if side.token < 16:
                row = TOKENS + side.token * TOKEN_STRIDE
                self.word(row + 0x48, side.decimals[0], 1)
                self.word(row + 0x49, side.decimals[1], 1)
        registered = {side.token: b"\x00" * 0x18 for side in sides if side.registered}
        deployed = {side.token: b"\x00" * 8 for side in sides if side.deployed}
        collide = any(side.collide for side in sides)
        full = any(side.full for side in sides)
        ctrl = TABLES + 0x1000
        self.swiss(ctrl, 0x20, registered, collide=collide, full=full)
        self.table(META + 0x40, ctrl, len(registered), META + 0x60)
        ctrl = TABLES + 0x2000
        self.swiss(ctrl, 0x10, deployed, collide=collide, full=full)
        self.table(META + 0x70, ctrl, len(deployed), META + 0x90)
        self.balances = {}
        for side in sides:
            self.balances[side.token] = side

    def on_btree(self, machine):
        regs = machine.regs
        if regs[RDI] != SPOT:
            raise Halt("balance table owner")
        raw = self.bytes_at(regs[RSI], 20)
        if raw[:12] != b"\x32" + bytes(11):
            raise Halt("system address prefix")
        token = int.from_bytes(raw[12:], "big")
        side = self.balances[token]
        self.leaf_for(side)
        regs[RAX] = BTREE_HEAD

    def leaf_for(self, side):
        memory = self.machine.memory
        self.word(BTREE_HEAD + 0x10, 0)
        self.word(BTREE_HEAD + 0x18, 0)
        if side.balance is None and not side.other_keys:
            return
        keys = sorted(set(side.other_keys) | ({side.token} if side.balance is not None else set()))
        memory.put_bytes(NODES, bytes(0x1D0))

        def leaf(at, items):
            self.word(at + 0x16A, len(items), 2)
            for index, key in enumerate(items):
                self.word(at + 8 + index * 8, key)
                total, reserved = side.balance if key == side.token else (0x99, 0x11)
                self.word(at + 0x60 + index * 0x18, total)
                self.word(at + 0x68 + index * 0x18, reserved)
            for index in range(len(items), 11):
                self.word(at + 8 + index * 8, side.token)
                self.word(at + 0x60 + index * 0x18, U64_MAX)
                self.word(at + 0x68 + index * 0x18, 0)

        if side.height == 0:
            leaf(NODES, keys)
            self.word(BTREE_HEAD + 0x10, NODES)
            return
        pivot = len(keys) // 2
        left, right = NODES + 0x200, NODES + 0x400
        leaf(NODES, [keys[pivot]])
        self.word(NODES + 0x170, left)
        self.word(NODES + 0x178, right)
        leaf(left, keys[:pivot])
        leaf(right, keys[pivot + 1:])
        self.word(BTREE_HEAD + 0x10, NODES)
        self.word(BTREE_HEAD + 0x18, side.height)

    def on_quote_ok(self, machine):
        regs = machine.regs
        if regs[RDI] != META or regs[RDX] != self.quote:
            raise Halt("quote predicate arguments")
        side = self.balances[regs[RSI]]
        regs[RAX] = int(side.quote_ok)

    def write_side(self, at, side):
        self.word(at, side.token)
        self.word(at + 8, side.capacity)
        self.word(at + 0x10, name_pointer(side))
        self.word(at + 0x18, side.name_length)

    def run_side(self, side):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        self.events = []
        self.frees = []
        self.recorded = []
        self.brk = BRK
        self.hashers = set()
        self.quote = 11
        machine.calls = {HASH: self.on_hash}
        self.install_sides([side])
        self.word(SIDE, 0)
        self.write_side(SIDE, side)
        self.word(QUOTE_WORD, 11)
        self.word(CONTEXT, META)
        self.word(CONTEXT + 8, USER)
        self.word(CONTEXT + 0x10, META)
        self.word(CONTEXT + 0x18, SPOT)
        self.word(CONTEXT + 0x20, QUOTE_WORD)
        for at in range(0, 0x30, 8):
            self.word(OUT + at, 0xE0E0E0E0E0E0E0E0)
        machine.run(SIDE_BUILDER, {RDI: OUT, RSI: CONTEXT, RDX: SIDE})
        tag = self.read(OUT, 2)
        answer = dict(tag=tag, freed=list(self.frees), recorded=list(self.recorded), words=None)
        if tag == OK:
            answer["words"] = tuple(self.read(OUT + at) for at in (8, 0x10, 0x18, 0x20, 0x28))
        elif tag == TEXT:
            answer["words"] = (self.read(OUT + 8), self.read(OUT + 0x10))
        elif tag == LENGTH:
            answer["words"] = (None, None, self.read(OUT + 0x18))
        return answer

    def quote_tree(self, case):
        """Node shape read by the validator: keys at +8, length at +0x62, flag bytes at +0x64, edges at +0x70."""
        node = NODES + 0x600
        if case.quote_height:
            self.word(node + 0x62, 1, 2)
            self.word(node + 8, case.quote + 50)
            self.word(node + 0x64, 1, 1)
            self.word(node + 0x70, NODES + 0x800)
            self.word(node + 0x78, 0xBAD)
            node = NODES + 0x800
        self.word(node + 0x62, 3, 2)
        keys = {0: (5, case.quote + 1, 90), 1: (5, case.quote, 90), 2: (5, case.quote, 90), 3: (1, 2, 3)}[case.quote_entry]
        for index, key in enumerate(keys):
            self.word(node + 8 + index * 8, key)
            self.word(node + 0x64 + index, int(case.quote_entry != 2) if index != 1 else int(case.quote_entry == 2), 1)
        for index in range(3, 11):
            self.word(node + 8 + index * 8, case.quote)
            self.word(node + 0x64 + index, 0, 1)

    def on_second_error(self, machine):
        """Drop of the second side's error when the first also failed; builder frees were already made."""
        if self.read(machine.regs[RDI], 2) == OK:
            raise Halt("drop of a good side")

    def run_validate(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        self.events = []
        self.frees = []
        self.recorded = []
        self.brk = BRK
        self.hashers = set()
        self.quote = case.quote
        machine.calls = {HASH: self.on_hash, 0x3C1ADA0: self.on_second_error}
        self.install_sides([case.first, case.second])
        self.word(SPOT + 0x260, NODES + 0x600)
        self.word(SPOT + 0x268, case.quote_height)
        self.quote_tree(case)
        memory.put_bytes(USER, USER_BYTES)
        self.write_side(PARAM_A, case.first)
        self.write_side(PARAM_A + 0x20, case.second)
        for index, word in enumerate((case.extra_capacity[0], 0x1111, 0x41, case.extra_capacity[1], 0x2222, 0x61)):
            self.word(PARAM_B + index * 8, word)
        self.word(META + 0x130, case.counter)
        taken = {case.counter: b"\x00" * 0x88} if case.outcome_taken else {}
        ctrl = TABLES + 0x7000
        self.swiss(ctrl, RECORD_STRIDE, taken)
        self.table(META + 0xD0, ctrl, len(taken), META + 0xF0)
        for at in range(0, 0x90, 8):
            self.word(OUT + at, 0xE0E0E0E0E0E0E0E0)
        # The seventh argument sits just above the return address pushed by run().
        self.word(STACK_TOP - 0x100, SPOT)
        machine.run(VALIDATOR, {RDI: OUT, RSI: META, RDX: USER, RCX: PARAM_A, R8: case.quote, R9: PARAM_B})
        freed = sorted(self.frees)
        if self.read(OUT + 8) == ERROR_NICHE:
            tag = self.read(OUT + 0x10, 2)
            if tag == TEXT:
                words = (self.read(OUT + 0x18), self.read(OUT + 0x20))
            elif tag == LENGTH:
                words = (None, None, self.read(OUT + 0x28))
            else:
                words = None
            return ("error", tag, words, freed)
        words = tuple(self.read(OUT + at) for at in range(0, 0x90, 8))
        return ("record", self.read(OUT), words, freed)

    def run_lookup(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        self.events = []
        self.hashers = set()
        machine.calls = {HASH: self.on_hash}
        self.word(META + 0x168, PAIRS)
        self.word(META + 0x170, case.pair_rows)
        for pair in range(16):
            self.word(PAIRS + pair * PAIR_STRIDE, 0xABAB)
        self.word(PAIRS + case.pair * PAIR_STRIDE if case.pair < 16 else PAIRS, case.token)
        first = {} if not case.has_outcome else {case.token: case.outcome.to_bytes(8, "little")}
        ctrl = TABLES + 0x2000
        self.swiss(ctrl, 0x10, first, collide=case.collide, full=case.full)
        self.table(META + 0x70, ctrl, 0 if case.empty_first else 1, META + 0x90)
        record = bytearray(b"\xcd" * 0x88)
        for at, word in ((0x20, case.first_value), (0x28, case.first_token), (0x48, case.second_value), (0x50, case.second_token)):
            record[at - 8:at] = word.to_bytes(8, "little")
        second = {} if not case.has_record else {case.outcome: bytes(record)}
        ctrl = TABLES + 0x7000
        self.swiss(ctrl, RECORD_STRIDE, second, collide=case.collide, full=case.full)
        self.table(META + 0xD0, ctrl, 0 if case.empty_second else 1, META + 0xF0)
        for at in (0, 8):
            self.word(OUT + at, 0xE0E0E0E0E0E0E0E0)
        try:
            machine.run(VALUE_LOOKUP, {RDI: OUT, RSI: META, RDX: case.pair, RCX: META})
        except Panicked as stop:
            return stop.args[0]
        if self.read(OUT, 1) == 1:
            return ("error", self.read(OUT + 1, 1))
        if self.read(OUT, 1) != 0:
            raise Halt("lookup tag")
        return ("value", self.read(OUT + 8))


# ---- the conversion, for all u64 values ----

class Traced(Harness):
    """Runs one deploy copy with the chosen round call answering a chosen bit pattern."""

    def run_tail(self, entry, site, bits):
        machine = self.machine
        round_at = EDGES[entry]["rounds"][site]
        start = round_at + 6
        end = self.store_after(entry, site) + 1
        trace = []
        original = machine.step

        def step(row):
            if row.va == round_at:
                self.machine.regs[RSP] = self.machine.regs[RSP]
                machine.xmm[0] = bits
                return row.next
            if start <= row.va < end:
                if row.op in ("jcc", "cmov"):
                    trace.append((row.va, machine.condition(row.cc)))
                following = original(row)
                if row.op in ("ucomisd", "cmp"):
                    trace.append((row.va, machine.cf, machine.zf, machine.pf))
                elif row.op == "cvttsd2si":
                    trace.append((row.va, machine.regs[row.a[1]] == 1 << 63))
                elif row.op == "maxsd":
                    trace.append((row.va, machine.xmm[row.a[1]] & MASK[8] == 0))
                return following
            return original(row)

        machine.step = step
        try:
            got = self.run_deploy(entry, TAIL_CASE)
        finally:
            del machine.step
        return tuple(trace), got["marks"][5 if site else 4]

    def store_after(self, entry, site):
        key = (entry, site)
        if key not in self.stores:
            self.stores[key] = find_store(self.image, EDGES[entry]["rounds"][site])
        return self.stores[key]

    stores = {}


TAIL_CASE = Deploy()


def find_store(image, round_at):
    """First write of a mark after one round call, by decoded row."""
    base = image.offset(round_at)

    def read(va, count):
        return image.blob[base + va - round_at:base + va - round_at + count]

    jumps = 0
    va = round_at
    for _ in range(60):
        row = decode(read, va)
        if row.op == "mov" and row.a[0] == "m" and row.a[4] == MARK_FIELD and row.a[3] == 1 and row.a[2] is not None:
            return row.va
        va = row.next
    raise EvidenceError("no mark store after %#x" % round_at)


FLOAT_SEEDS = ((0, 0x7FEFFFFFFFFFFFFF), (0x7FF0000000000000, 0x7FF0000000000000), (0x7FF0000000000001, (1 << 63) - 1),
               (1 << 63, (1 << 63) | 0x7FEFFFFFFFFFFFFF), ((1 << 63) | 0x7FF0000000000000, (1 << 63) | 0x7FF0000000000000),
               ((1 << 63) | 0x7FF0000000000001, MASK[8]))
INTERIOR_POINTS = 8


def interior(lo, hi):
    return [lo + (hi - lo) * index // (INTERIOR_POINTS + 1) for index in range(1, INTERIOR_POINTS + 1)]


def refine_tail(harness, entry, site):
    """Split the f64 bit patterns until each piece has one decision record; check the closed form."""
    pieces = []
    runs = 0
    for seed in FLOAT_SEEDS:
        stack = [seed]
        found = []
        while stack:
            lo, hi = stack.pop()
            first = harness.run_tail(entry, site, lo)
            last = harness.run_tail(entry, site, hi) if hi != lo else first
            runs += 2
            if first[0] == last[0]:
                found.append((lo, hi, first[0]))
                continue
            middle = (lo + hi) // 2
            stack.append((middle + 1, hi))
            stack.append((lo, middle))
        found.sort(key=lambda row: row[0])
        merged = []
        for lo, hi, trace in found:
            if merged and merged[-1][2] == trace and merged[-1][1] + 1 == lo:
                merged[-1] = (merged[-1][0], hi, trace)
            else:
                merged.append((lo, hi, trace))
        pieces.extend(merged)
    rows = []
    for lo, hi, trace in pieces:
        for bits in [lo, hi] + (interior(lo, hi) if hi > lo else []):
            out = harness.run_tail(entry, site, bits)
            if out[0] != trace:
                raise EvidenceError("interior point left its piece: %#x" % bits)
            if out[1] != spec_tail(to_float(bits)):
                raise EvidenceError("tail mismatch at %#x: %#x" % (bits, out[1]))
        rows.append((lo, hi, harness.run_tail(entry, site, lo)[1], harness.run_tail(entry, site, hi)[1], len(trace)))
    return rows, runs


def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 0xD1342543DE82EF95 + 1) & MASK[8]
        yield state >> 3 ^ state


def value_vectors(count=400):
    values = {0, 1, 2, 3, 4, 5, 99, 100, 101, WHOLE_UNIT, WHOLE_UNIT - 1, WHOLE_UNIT + 1, U64_MAX, U64_MAX - 1}
    for bit in range(64):
        for delta in (-1, 0, 1, 2):
            values.add(((1 << bit) + delta) & U64_MAX)
    for bit in range(53, 64):
        step = 1 << (bit - 52)
        for multiple in (1, 3, 5, 0x10000000000001):
            base = (1 << bit) + multiple * step
            for delta in (-step // 2 - 1, -step // 2, -step // 2 + 1, step // 2 - 1, step // 2, step // 2 + 1):
                if 0 <= base + delta <= U64_MAX:
                    values.add(base + delta)
    stream = lcg(0x5EED)
    for _ in range(count):
        word = next(stream)
        values.add(word >> (next(stream) & 63))
    return sorted(values)


# ---- named cases ----

def deploy_cases():
    new_primary = dict(lists={3: [5]}, deployed={2: ("ok", 6)}, values={5: WHOLE_UNIT, 6: 300})
    new_linked = dict(lists={2: [4]}, deployed={3: ("ok", 6)}, values={4: 7, 6: WHOLE_UNIT})
    both_new = dict(lists={}, deployed={2: ("ok", 6), 3: ("ok", 7)}, values={6: 9, 7: 11})
    cases = [("both sides exist", Deploy()),
             ("validator refuses", Deploy(validate_error=0xEF)),
             ("validator text error", Deploy(validate_error=TEXT)),
             ("resolver refuses", Deploy(resolve_fail=True)),
             ("resolver refuses, zero user", Deploy(resolve_fail=True, user=bytes(20))),
             ("resolver refuses, last user byte only", Deploy(resolve_fail=True, user=bytes(19) + b"\x01")),
             ("resolver refuses, first user byte only", Deploy(resolve_fail=True, user=b"\x01" + bytes(19))),
             ("primary row at table end", Deploy(primary=9)),
             ("primary row past table", Deploy(primary=1 << 40)),
             ("linked row at table end", Deploy(linked=9)),
             ("primary pair at pair end", Deploy(lists={2: [12], 3: [5]})),
             ("linked pair at pair end", Deploy(lists={2: [4], 3: [12]})),
             ("primary quote differs", Deploy(pairs={4: (7, 12), 5: (8, 11)})),
             ("linked quote differs", Deploy(pairs={4: (7, 11), 5: (8, 12)})),
             ("linked quote differs, zero user", Deploy(pairs={4: (7, 11), 5: (8, 12)}, user=bytes(20))),
             ("only the first list entry counts", Deploy(lists={2: [4, 9], 3: [5, 9]}, pairs={4: (7, 11), 5: (8, 11), 9: (1, 99)})),
             ("primary lookup fails", Deploy(values={4: None, 5: 8})),
             ("linked lookup fails after primary stored", Deploy(values={4: 8, 5: None})),
             ("primary mark row at end", Deploy(lists={2: [14], 3: [5]}, pairs={14: (7, 11), 5: (8, 11)}, mark_rows=14)),
             ("linked mark row at end", Deploy(lists={2: [4], 3: [14]}, pairs={4: (7, 11), 14: (8, 11)}, mark_rows=14)),
             ("primary deployed new", Deploy(**new_primary)),
             ("linked deployed new", Deploy(**new_linked)),
             ("both deployed new", Deploy(**both_new)),
             ("new primary, decimal fails", Deploy(first_decimal_ok=False, **new_primary)),
             ("new primary, deploy fails", Deploy(**dict(new_primary, deployed={2: ("err", 0x1F)}))),
             ("new primary, liquidity fails", Deploy(liquidity={6: 0x2B}, **new_primary)),
             ("new primary, lookup fails", Deploy(**dict(new_primary, values={6: None}))),
             ("new linked, decimal fails", Deploy(second_decimal_tag=0xAC, **new_linked)),
             ("new linked, deploy fails", Deploy(**dict(new_linked, deployed={3: ("err", 0x1F)}))),
             ("new linked, liquidity fails", Deploy(liquidity={6: 0x2B}, **new_linked)),
             ("new primary skips the quote test", Deploy(**dict(new_primary, pairs={6: (1, 99), 5: (8, 11)}))),
             ("new linked skips the quote test", Deploy(**dict(new_linked, pairs={4: (7, 11), 6: (1, 99)}))),
             ("outcome id zero", Deploy(outcome=0)),
             ("record strings have no capacity, refused", Deploy(bare_record=True, resolve_fail=True)),
             ("record strings have no capacity, accepted", Deploy(bare_record=True)),
             ("value zero", Deploy(values={4: 0, 5: 1})),
             ("value one and two", Deploy(values={4: 1, 5: 2})),
             ("value three", Deploy(values={4: 3, 5: 5})),
             ("value MAX", Deploy(values={4: U64_MAX, 5: 1 << 63})),
             ("value above 2^53", Deploy(values={4: (1 << 53) + 1, 5: (1 << 53) + 3}))]
    return cases


def value_cases(values):
    return [Deploy(values={4: value, 5: values[-1 - index]}) for index, value in enumerate(values)]


def side_cases():
    near = (6, 8, 9, 12)
    return [("accepted", Side()),
            ("accepted, no capacity", Side(capacity=0)),
            ("accepted at name limit", Side(name_length=100)),
            ("accepted, empty name", Side(name_length=0)),
            ("name past limit", Side(name_length=101)),
            ("name past limit, no capacity", Side(name_length=101, capacity=0)),
            ("token at table end", Side(token=9, token_rows=9)),
            ("token past table", Side(token=1 << 40)),
            ("token at table end, no capacity", Side(token=9, token_rows=9, capacity=0)),
            ("token and name both bad", Side(token=9, token_rows=9, name_length=500)),
            ("size decimals 1", Side(decimals=(1, 5))),
            ("wei decimals 4", Side(decimals=(0, 4))),
            ("wei decimals 6", Side(decimals=(0, 6))),
            ("wei decimals 5 at high bit", Side(decimals=(0, 0x85))),
            ("decimals fail, no capacity", Side(decimals=(1, 5), capacity=0)),
            ("not registered", Side(registered=False)),
            ("not registered, no capacity", Side(registered=False, capacity=0)),
            ("already deployed", Side(deployed=True)),
            ("already deployed, no capacity", Side(deployed=True, capacity=0)),
            ("registered behind a tag collision", Side(collide=True)),
            ("deployed behind a tag collision", Side(deployed=True, collide=True)),
            ("registered past two full groups", Side(full=True)),
            ("deployed past two full groups", Side(full=True, deployed=True)),
            ("unknown behind two full groups", Side(full=True, registered=False)),
            ("no balance row", Side(balance=None)),
            ("no balance row, other keys", Side(balance=None, other_keys=near)),
            ("no balance row, no capacity", Side(balance=None, capacity=0)),
            ("balance one short", Side(balance=(U64_MAX - 1, 0))),
            ("balance MAX with one reserved", Side(balance=(U64_MAX, 1))),
            ("balance zero", Side(balance=(0, 0))),
            ("reserved above total", Side(balance=(1, 2))),
            ("reserved MAX", Side(balance=(0, U64_MAX))),
            ("balance row beside others", Side(other_keys=near)),
            ("balance row last of 11", Side(other_keys=(1, 2, 3, 4, 5, 6))),
            ("balance row in left child", Side(other_keys=(9, 10, 11), height=1)),
            ("balance row in right child", Side(token=11, other_keys=(5, 7, 9), height=1, token_rows=16)),
            ("balance row in the root", Side(other_keys=(3, 12), height=1)),
            ("quote predicate refuses", Side(quote_ok=False)),
            ("quote predicate refuses, no capacity", Side(quote_ok=False, capacity=0))]


def validate_cases():
    both = lambda **fields: Validate(**fields)
    return [("accepted", both()),
            ("accepted at the last id", both(counter=MAX_OUTCOME)),
            ("id past the limit", both(counter=MAX_OUTCOME + 1)),
            ("id far past the limit", both(counter=1 << 40)),
            ("id already used", both(outcome_taken=True)),
            ("quote missing", both(quote_entry=0)),
            ("quote flagged", both(quote_entry=2)),
            ("quote above every key", both(quote_entry=3)),
            ("tokens equal", both(second=Side(token=7))),
            ("first side refused", both(first=Side(token=7, decimals=(1, 5)))),
            ("second side refused", both(second=Side(token=8, deployed=True))),
            ("both sides refused, first wins", both(first=Side(token=7, name_length=200), second=Side(token=8, registered=False))),
            ("first length error keeps its length", both(first=Side(token=7, name_length=101))),
            ("second length error keeps its length", both(second=Side(token=8, name_length=102))),
            ("second token bad", both(second=Side(token=20, token_rows=9))),
            ("first refused, second has no capacity", both(first=Side(token=7, registered=False), second=Side(token=8, capacity=0))),
            ("second refused, first has no capacity", both(first=Side(token=7, capacity=0), second=Side(token=8, registered=False))),
            ("both refused, no capacity", both(first=Side(token=7, registered=False, capacity=0), second=Side(token=8, registered=False, capacity=0))),
            ("tokens equal, no capacity", both(first=Side(token=7, capacity=0), second=Side(token=7, capacity=0))),
            ("limit, no capacity", both(counter=MAX_OUTCOME + 1, first=Side(token=7, capacity=0), second=Side(token=8, capacity=0))),
            ("quote missing, no capacity", both(quote_entry=0, first=Side(token=7, capacity=0), second=Side(token=8, capacity=0), extra_capacity=(0, 0))),
            ("quote missing, first capacity only", both(quote_entry=0, second=Side(token=8, capacity=0), extra_capacity=(0, 0))),
            ("quote missing, second capacity only", both(quote_entry=0, first=Side(token=7, capacity=0), extra_capacity=(0, 0))),
            ("quote missing, first extra only", both(quote_entry=0, first=Side(token=7, capacity=0), second=Side(token=8, capacity=0), extra_capacity=(0x31, 0))),
            ("quote missing, second extra only", both(quote_entry=0, first=Side(token=7, capacity=0), second=Side(token=8, capacity=0), extra_capacity=(0, 0x51))),
            ("limit, no extra capacity", both(counter=MAX_OUTCOME + 1, extra_capacity=(0, 0))),
            ("limit, first extra only", both(counter=MAX_OUTCOME + 1, extra_capacity=(0x31, 0))),
            ("limit, second extra only", both(counter=MAX_OUTCOME + 1, extra_capacity=(0, 0x51))),
            ("tokens equal, no extra capacity", both(second=Side(token=7), extra_capacity=(0, 0))),
            ("tokens equal, first side capacity only", both(first=Side(token=7), second=Side(token=7, capacity=0))),
            ("accepted with no extra capacity", both(extra_capacity=(0, 0))),
            ("quote one level down", both(quote_height=1)),
            ("quote missing one level down", both(quote_height=1, quote_entry=0)),
            ("quote flagged one level down", both(quote_height=1, quote_entry=2))]


def lookup_cases():
    return [("first side", Lookup()), ("second side", Lookup(token=8)), ("both sides equal, first wins", Lookup(first_token=7, second_token=7)),
            ("token on neither side", Lookup(token=9)), ("pair at end", Lookup(pair=12)), ("pair past end", Lookup(pair=1 << 33)),
            ("no outcome entry", Lookup(has_outcome=False)), ("first table empty", Lookup(empty_first=True)),
            ("no record", Lookup(has_record=False)), ("second table empty", Lookup(empty_second=True)),
            ("tag collision in both tables", Lookup(collide=True)), ("tag collision, second side", Lookup(collide=True, token=8)),
            ("full group in both tables", Lookup(full=True)), ("full groups, second side", Lookup(full=True, token=8)),
            ("full groups, no outcome", Lookup(full=True, has_outcome=False)), ("last pair", Lookup(pair=11)),
            ("full groups, no record", Lookup(full=True, has_record=False))]


# ---- static facts ----

def direct_calls(image, targets):
    base, text = image.text_bytes()
    found = collections.defaultdict(list)
    at = text.find(b"\xe8")
    while 0 <= at <= len(text) - 5:
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in targets:
            found[target].append(base + at)
        at = text.find(b"\xe8", at + 1)
    return found


def slot_calls(image, slot):
    base, text = image.text_bytes()
    found = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            found.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return found


def table_uses(image, displacement):
    """Loads of a 64-bit field at one state displacement, by exact opcode bytes."""
    base, text = image.text_bytes()
    pattern = re.compile(rb"[\x48\x49\x4c\x4d]\x8b[\x80-\xbf&&[^\x84\x8c\x94\x9c\xa4\xac\xb4\xbc]]" .replace(b"&&[^\x84\x8c\x94\x9c\xa4\xac\xb4\xbc]", b"") + re.escape(struct.pack("<i", displacement)))
    return [base + match.start() for match in pattern.finditer(text)]


def head_shape(image, round_at):
    """The eight rows from the value load to the round call, by exact bytes."""
    start = round_at - 44
    base = image.offset(start)
    code = image.blob[base:base + 44 + 22]

    def read(va, count):
        return code[va - start:va - start + count]

    rows = []
    va = start
    while va <= round_at:
        rows.append(decode(read, va))
        va = rows[-1].next
    names = [row.op for row in rows]
    if names != ["movsd", "punpckldq", "subpd", "movx", "unpckhpd", "addsd", "mulsd", "calli"]:
        raise EvidenceError("unexpected head at %#x: %s" % (round_at, names))
    first = rows[0]
    if first.a != ("x", 1) or first.b[1] != RSP:
        raise EvidenceError("value load at %#x" % start)
    absolute = (rows[1].b[4], rows[2].b[4], rows[6].b[4], rows[7].a[4])
    if absolute != (0x203E80, 0x202EA0, 0x20A940, SLOT_ROUND):
        raise EvidenceError("head constants at %#x: %s" % (round_at, absolute))
    if (rows[3].a, rows[3].b, rows[4].a, rows[4].b, rows[5].a, rows[5].b, rows[6].a) != (
            ("x", 0), ("x", 1), ("x", 0), ("x", 1), ("x", 0), ("x", 1), ("x", 0)):
        raise EvidenceError("head registers at %#x" % round_at)
    return first.b[4]


def run_head(harness, round_at, value):
    """Run the real load-to-round rows with the value in a stack slot; return the bits given to round."""
    machine = harness.machine
    start = round_at - 44
    machine.regs = [POISON] * 16
    machine.regs[RSP] = STACK_TOP - 0x1000
    displacement = head_shape(harness.image, round_at)
    machine.memory.write(machine.regs[RSP] + displacement, 8, value)
    pc = start
    while pc != round_at:
        row = machine.cache.get(pc)
        if row is None:
            row = decode(machine.read_code, pc)
            machine.cache[pc] = row
        pc = machine.step(row)
    return machine.xmm[0] & MASK[8]


def copies_match(image):
    """Copy 2 against copy 3: rows at the same offsets, listing what differs."""
    first, second = COPIES[1], COPIES[2]
    low, end = image.exact_fde(first)
    other, other_end = image.exact_fde(second)
    if end - low != other_end - other:
        raise EvidenceError("copies differ in size")
    left, right = decode_range(image, low, end), decode_range(image, other, other_end)
    if [row.va - low for row in left] != [row.va - other for row in right]:
        raise EvidenceError("copies differ in instruction boundaries")

    def shape(row, start, stop):
        target = row.target
        if target is not None and start <= target < stop:
            target = target - start
        elif row.op in ("call", "calli") or row.rip_at is not None:
            target = None
        return (row.op, row.width, row.cc, row.a if row.rip_at is None else None, row.b if row.rip_at is None else None, target)

    rows = []
    for one, two in zip(left, right):
        if shape(one, low, end) != shape(two, other, other_end):
            rows.append((one.va - low, one.a, one.b, two.a, two.b))
    return len(left), rows


def text_rows(image):
    rows = []
    for name, (address, size, want) in sorted(TEXTS.items()):
        data = bytes(image.blob[image.offset(address):image.offset(address) + size])
        if data != want:
            raise EvidenceError("text moved: %s" % name)
        rows.append((name, address, size, data.decode()))
    return rows


def constant_rows(image):
    rows = []
    for address, (name, want) in sorted(CONSTANTS.items()):
        bits = struct.unpack_from("<Q", image.blob, image.offset(address))[0]
        if bits != want:
            raise EvidenceError("constant moved: %#x" % address)
        rows.append((address, name, bits))
    return rows


def tag_text(image, tag):
    """Text of one error tag through the Display jump table."""
    table = 0x59A8D0
    relative = struct.unpack_from("<i", image.blob, image.offset(table) + 4 * tag)[0]
    arm = table + relative
    code = bytes(image.blob[image.offset(arm):image.offset(arm) + 40])
    at = code.find(b"\x48\x8d\x35")
    target = arm + at + 7 + struct.unpack_from("<i", code, at + 3)[0]
    size = struct.unpack_from("<I", code, at + 8)[0]
    return bytes(image.blob[image.offset(target):image.offset(target) + size]).decode()


def site_rows(image):
    rows = []
    for entry in COPIES:
        for site, round_at in enumerate(EDGES[entry]["rounds"]):
            load = head_shape(image, round_at)
            rows.append((entry, "primary" if site == 0 else "linked", round_at - 44, load, round_at, find_store(image, round_at)))
    return rows


def state_rows(image):
    rows = []
    for entry in COPIES:
        low, end = image.exact_fde(entry)
        pointer, length = EDGES[entry]["marks"], EDGES[entry]["marks"] + 8
        users = EDGES[entry]["users"]
        counts = collections.Counter()
        for row in decode_range(image, low, end):
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[4] in (pointer, length, users, 0x1E8):
                    counts[operand[4]] += 1
        rows.append((entry, end - low, pointer, counts[pointer], length, counts[length], users, counts[users], counts[0x1E8]))
    return rows


# ---- mutation controls ----

UNSET = "copies a payload word this error never sets, so both sources hold the same fill"
EXPECTED_SURVIVORS = {
    (0x20A510, "constant"): "a raised bound changes nothing: values at or above 2^64 still saturate at the compare with the largest f64",
    (0x3728E68, "displacement"): "pointer pair kept for the landing pad, read on no normal path",
    (0x3728E6C, "displacement"): "pointer pair kept for the landing pad, read on no normal path",
    (0x3729345, "displacement"): UNSET, (0x372934D, "displacement"): UNSET, (0x372938E, "displacement"): UNSET,
    (0x3729397, "displacement"): UNSET, (0x37293A0, "displacement"): UNSET, (0x37293AD, "displacement"): UNSET,
    (0x37293B7, "displacement"): UNSET, (0x37293C0, "displacement"): UNSET,
    (0x3C01712, "immediate"): "the next movq at +0x25 rewrites this byte at +0x2c",
    (0x4D6C9ED, "immediate"): "stack flag beside the user copy, read by no modelled path",
    (0x4D6CBB4, "immediate"): "sar by 62 keeps all but bit 0, doubles at or above 2^63 are multiples of 2048",
    (0x4D6CD14, "immediate"): "sar by 62 keeps all but bit 0, doubles at or above 2^63 are multiples of 2048",
    (0x4D6CD7B, "immediate"): "the extra byte lands at item +0x98, which the next store rewrites with the outcome id",
}


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    # A renamed stack slot says little: one half of a spill can move and still agree with the other.
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def mutation_targets(image, entry, seen):
    edits = []
    low, high = image.exact_fde(entry)
    for row in decode_range(image, low, high):
        if row.va not in seen or row.rip_at is not None:
            continue
        data = image.blob[image.offset(row.va):image.offset(row.va) + row.size]
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp", "pshufd", "pshuflw"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def first_failure(harness, sets):
    catch = (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError, OverflowError, struct.error, AttributeError, TypeError)
    for name, kind, case in sets:
        try:
            got = run_one(harness, kind, case)
        except catch as error:
            return "%s: %s" % (name, type(error).__name__)
        if got != want_one(kind, case):
            return "%s: differs" % name
    return None


def run_one(harness, kind, case):
    if kind == "side":
        return harness.run_side(case)
    if kind == "validate":
        return harness.run_validate(case)
    if kind == "lookup":
        return harness.run_lookup(case)
    return harness.run_deploy(kind, case)


def want_one(kind, case):
    if kind == "side":
        return spec_side(case)
    if kind == "validate":
        return spec_validate(case)
    if kind == "lookup":
        return spec_lookup(case)
    return spec_deploy(case, kind)


def case_sets(values):
    deploy = [(name, COPIES[1], case) for name, case in deploy_cases()]
    deploy += [("value %d" % index, COPIES[1], case) for index, case in enumerate(value_cases(values[:40] + values[-40:]))]
    side = [(name, "side", case) for name, case in side_cases()]
    validate = [(name, "validate", case) for name, case in validate_cases()]
    lookup = [(name, "lookup", case) for name, case in lookup_cases()]
    return {COPIES[1]: deploy, SIDE_BUILDER: side, VALIDATOR: validate + side[:0], VALUE_LOOKUP: lookup}


TAIL_POINTS = (0, 1, to_bits(0.5), to_bits(1.0), to_bits(1.5), to_bits(2.0), to_bits(3.0), 1 << 63, to_bits(-1.0), to_bits(-5e-324),
               to_bits(2.0 ** 52), to_bits(2.0 ** 63) - 1, to_bits(2.0 ** 63), to_bits(2.0 ** 63) + 1, to_bits(2.0 ** 64) - 2,
               to_bits(2.0 ** 64) - 1, to_bits(2.0 ** 64), to_bits(2.0 ** 64) + 1, to_bits(1e300), 0x7FF0000000000000,
               0x7FF0000000000001, 0x7FF8000000000000, 0xFFF0000000000000, 0xFFF8000000000000)


def tail_window(site):
    round_at = EDGES[COPIES[1]]["rounds"][site]
    return round_at, round_at + 0xB0


def tail_points_reason(image, patch, constants):
    """A fixed list of bit patterns through both sites; mutants of the tail are one-point changes."""
    harness = Traced(image, patch, constants)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    for site in (0, 1):
        for bits in TAIL_POINTS:
            try:
                if harness.run_tail(COPIES[1], site, bits)[1] != spec_tail(to_float(bits)):
                    return "tail point %#x" % bits
            except (Halt, EvidenceError, KeyError, Panicked) as error:
                return "tail point %#x: %s" % (bits, type(error).__name__)
    return None


LANE_CONSTANTS = (("lane constant 2^52", 0x202EA0, 0x4330000000000000 ^ 1 << 49 | 0x4530000000000000 << 64),
                  ("lane constant 2^84", 0x202EA0, 0x4330000000000000 | (0x4530000000000000 ^ 1 << 49) << 64),
                  ("exponent word 0x43300000", 0x203E80, 0x4530000043300000 ^ 1 << 20),
                  ("exponent word 0x45300000", 0x203E80, 0x4530000043300000 ^ 1 << 52))


def run_mutants(image, seen, values):
    rows = []
    sets = case_sets(values)
    windows = (tail_window(0), tail_window(1))
    for entry, group in sets.items():
        for va, kind, patch in mutation_targets(image, entry, seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            reason = first_failure(harness, group)
            if reason is None and entry == COPIES[1] and any(low < va < high for low, high in windows):
                reason = tail_points_reason(image, patch, None)
            rows.append((va, kind, "killed" if reason else "survived", reason or EXPECTED_SURVIVORS.get((va, kind), "")))
    for address, (name, bits) in sorted(CONSTANTS.items()):
        if address in (0x202EA0, 0x202EA8, 0x203E80):
            continue
        statics = {address: bits ^ (1 << 49)}
        harness = Harness(image, None, statics)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        reason = first_failure(harness, sets[COPIES[1]]) or tail_points_reason(image, None, statics)
        rows.append((address, "constant", "killed" if reason else "survived", reason or EXPECTED_SURVIVORS.get((address, "constant"), "")))
    for name, address, value in LANE_CONSTANTS:
        harness = Harness(image, None, {address: value})
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        reason = first_failure(harness, sets[COPIES[1]])
        rows.append((address, "constant:" + name, "killed" if reason else "survived", reason or EXPECTED_SURVIVORS.get((address, "constant:" + name), "")))
    survivors = sorted((row[0], row[1]) for row in rows if row[2] == "survived")
    if survivors != sorted(EXPECTED_SURVIVORS):
        raise EvidenceError("survivor list changed: %s" % " ".join("%#x/%s" % row for row in survivors))
    return rows


# ---- analysis ----

def analyse(image, full=True):
    copies, differences = copies_match(image)
    harness = Traced(image)
    Traced.stores = {}
    values = value_vectors()
    outcome_rows = []
    for name, case in deploy_cases():
        for entry in COPIES:
            got, want = harness.run_deploy(entry, case), spec_deploy(case, entry)
            if got != want:
                raise EvidenceError("%#x %s: %r != %r" % (entry, name, got, want))
        outcome_rows.append((name, want["out"][0], "%#x" % want["out"][1] if want["out"][0] != "error" else "%#x" % want["out"][1],
                             " ".join("%d=%d" % item for item in sorted(want["marks"].items())), want["dirty"],
                             " ".join(event[0] for event in want["events"])))
    value_rows = value_cases(values)
    for case in value_rows:
        for entry in COPIES:
            if harness.run_deploy(entry, case) != spec_deploy(case, entry):
                raise EvidenceError("value mismatch at %#x" % entry)
    head_total = 0
    for entry in COPIES:
        for round_at in EDGES[entry]["rounds"]:
            for value in values:
                if run_head(harness, round_at, value) != to_bits(float(value) * 0.5):
                    raise EvidenceError("head mismatch at %#x for %#x" % (round_at, value))
                head_total += 1
    for value in values:
        if spec_mark(value) != closed_mark(value):
            raise EvidenceError("closed form at %#x" % value)
    side_rows = []
    for name, side in side_cases():
        got, want = harness.run_side(side), spec_side(side)
        if got != want:
            raise EvidenceError("side %s: %r != %r" % (name, got, want))
        side_rows.append((name, "%#x" % want["tag"], tag_label(image, want), len(want["freed"]), len(want["recorded"])))
    validate_rows = []
    for name, case in validate_cases():
        got, want = harness.run_validate(case), spec_validate(case)
        if got != want:
            raise EvidenceError("validate %s: %r != %r" % (name, got, want))
        validate_rows.append((name, want[0], "%#x" % want[1], " ".join("%#x" % w for w in want[2]) if want[0] == "record" else "", len(want[3])))
    lookup_rows = []
    for name, case in lookup_cases():
        got, want = harness.run_lookup(case), spec_lookup(case)
        if got != want:
            raise EvidenceError("lookup %s: %r != %r" % (name, got, want))
        lookup_rows.append((name, want[0], "%#x" % want[1]))
    tails = {}
    runs = 0
    for entry in COPIES:
        for site in (0, 1):
            tails[(entry, site)], used = refine_tail(harness, entry, site)
            runs += used
    sites = direct_calls(image, set(COPIES) | {SIDE_BUILDER})
    examples = []
    for v in (0, 1, 2, 3, 99, 100, 101, 1000, WHOLE_UNIT - 1, WHOLE_UNIT, WHOLE_UNIT + 1, 1 << 53, (1 << 53) + 1, (1 << 53) + 2, (1 << 53) + 3,
              (1 << 63) - 1, 1 << 63, U64_MAX):
        examples.append((v, float(v).hex(), spec_mark(v), harness.run_deploy(COPIES[1], Deploy(values={4: v, 5: v}))["marks"][4],
                         reference_formula(v & MASK[4], v >> 32 << 32)))
    result = {
        "copies": copies, "differences": differences, "outcomes": outcome_rows, "value_vectors": len(values),
        "value_runs": len(value_rows) * len(COPIES), "head_runs": head_total, "sides": side_rows, "validates": validate_rows,
        "lookups": lookup_rows, "tails": tails, "tail_runs": runs, "examples": examples,
        "sites": site_rows(image), "states": state_rows(image), "constants": constant_rows(image), "texts": text_rows(image),
        "copy_callers": {entry: sites.get(entry, []) for entry in COPIES}, "builder_callers": sites.get(SIDE_BUILDER, []),
        "slots": {slot: harness.relative[slot] for slot in (SLOT_VALIDATOR, SLOT_RESOLVER, SLOT_LOOKUP, SLOT_ROUND, SLOT_FLOAT_DECIMAL)},
        "slot_calls": {slot: len(slot_calls(image, slot)) for slot in (SLOT_VALIDATOR, SLOT_RESOLVER, SLOT_LOOKUP)},
        "fde": {entry: image.exact_fde(entry) for entry in COPIES + (SIDE_BUILDER, VALIDATOR, RESOLVER, VALUE_LOOKUP)},
        "tags": {tag: tag_text(image, tag) for tag in (FAILED, INVALID_TOKEN, INVALID_QUOTE, LENGTH)},
        "locations": {va: image.location(va, harness.relative) for va in sorted({EDGES[e]["dirty"] for e in COPIES} | set(PANIC_TABLE) | {WEI_LOCATION, PAIR_LOCATION})},
    }
    if full:
        result["mutations"] = run_mutants(image, set(harness.machine.seen), values)
    return result


def tag_label(image, want):
    if want["tag"] == TEXT:
        return next(name for name, row in TEXTS.items() if row[0] == want["words"][0])
    if want["tag"] == OK:
        return "accepted, value %#x" % want["words"][3]
    return tag_text(image, want["tag"])


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("deploy-outcomes.tsv", ("case", "end", "code", "marks_written", "dirty", "calls_in_order"), result["outcomes"])
    tsv("side-outcomes.tsv", ("case", "tag", "meaning", "frees", "recorder_calls"), result["sides"])
    tsv("validator-outcomes.tsv", ("case", "end", "code", "record_words", "frees"), result["validates"])
    tsv("lookup-outcomes.tsv", ("case", "end", "value_or_code"), result["lookups"])
    tsv("mark-sites.tsv", ("function", "side", "load_at", "stack_slot", "round_call", "store"),
        [("%#x" % a, b, "%#x" % c, "%#x" % d, "%#x" % e, "%#x" % f) for a, b, c, d, e, f in result["sites"]])
    tsv("tail-pieces.tsv", ("function", "side", "bits_lo", "bits_hi", "mark_at_lo", "mark_at_hi", "decisions"),
        [("%#x" % entry, site, "%#x" % lo, "%#x" % hi, "%#x" % a, "%#x" % b, n)
         for (entry, site), rows in sorted(result["tails"].items()) for lo, hi, a, b, n in rows])
    tsv("mark-examples.tsv", ("v", "v_as_f64", "mark_specification", "mark_real_bytes", "reference_formula_on_the_two_words"),
        [("%#x" % a, b, "%#x" % c, "%#x" % d, "%#x" % e) for a, b, c, d, e in result["examples"]])
    tsv("copy-differences.tsv", ("offset", "second_copy_a", "second_copy_b", "third_copy_a", "third_copy_b"),
        [("%#x" % o, a, b, c, d) for o, a, b, c, d in result["differences"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"),
            [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "copies": ["%#x" % entry for entry in COPIES],
        "fde": {"%#x" % k: ["%#x" % v[0], "%#x" % v[1], v[1] - v[0]] for k, v in result["fde"].items()},
        "instructions_second_copy": result["copies"], "second_third_copy_differences": len(result["differences"]),
        "copy_callers": {"%#x" % k: ["%#x" % s for s in v] for k, v in result["copy_callers"].items()},
        "side_builder_callers": ["%#x" % s for s in result["builder_callers"]],
        "slots": {"%#x" % k: "%#x" % v for k, v in result["slots"].items()},
        "slot_calls": {"%#x" % k: v for k, v in result["slot_calls"].items()},
        "state_fields": [dict(zip(("function", "size", "marks", "marks_uses", "marks_len", "marks_len_uses", "users", "users_uses", "dirty_uses"),
                                  ["%#x" % row[0], row[1], "%#x" % row[2], row[3], "%#x" % row[4], row[5], "%#x" % row[6], row[7], row[8]]))
                         for row in result["states"]],
        "constants": [{"address": "%#x" % a, "name": n, "bits": "%#x" % b} for a, n, b in result["constants"]],
        "texts": [{"name": n, "address": "%#x" % a, "size": s, "text": t} for n, a, s, t in result["texts"]],
        "tags": {"%#x" % k: v for k, v in result["tags"].items()},
        "locations": {"%#x" % k: "%s:%d:%d" % v for k, v in result["locations"].items()},
        "value_vectors": result["value_vectors"], "value_runs": result["value_runs"], "head_runs": result["head_runs"],
        "tail_pieces": {"%#x/%d" % k: len(v) for k, v in sorted(result["tails"].items())}, "tail_runs": result["tail_runs"],
        "named_cases": {"deploy": len(result["outcomes"]), "side": len(result["sides"]), "validator": len(result["validates"]),
                        "lookup": len(result["lookups"])},
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"),
                                "survived": sum(1 for r in rows if r[2] == "survived")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    result = analyse(image)
    files = render(result)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files), "tail_pieces": {"%#x/%d" % k: len(v) for k, v in sorted(result["tails"].items())}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
