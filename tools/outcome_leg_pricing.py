#!/usr/bin/env python3
"""Pin the node #94 outcome leg pricing functions 0x4d17fa0 and 0x4d18dc0 from ELF bytes.

The functions walk two lists of legs behind the OutcomeDeploy handlers. Legs whose token differs from
the shared parent word are counted as n. The leg amount is amount * (1/n) truncated in f64, the leg
price is max(1, round(value * ((1/n - 1) + 1))), and a row is written only if price * quote stays at or
below 0x7ffffffffffffffe; otherwise the leg goes on with cost 0 and no error. The real bytes run over
real table layouts, a separately written specification predicts every run, and the rows after each
float multiply are split over all 2^64 f64 bit patterns. No objdump or readelf output is parsed and the
binary is never executed. Standard library only.

    python3 tools/outcome_leg_pricing.py --out <dir>
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
HEAP_SIZE = 0x20000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 80000


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
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at", "data")

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
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
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
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
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








FILL = 0xCC

TARGETS = (0x4D17FA0, 0x4D18DC0)
WRAPPERS = (0x4C34BC0, 0x4C34A30)
APPLIERS = (0x432A990, 0x432B440)
FLAG_FIELD = (0x1372, 0x8F2)
COPY_SHIFT = TARGETS[1] - TARGETS[0]
REAL_HELPER = 0x3C18FB0
SUCCESS = 0x27
MAX_SAFE = 0x7FFFFFFFFFFFFFFE
MAX_I64 = (1 << 63) - 1
MAX_U64 = MASK[8]
ROW_SIZE = 0x268
ROW_TAG = 10
MARK_BASE = 0x7700000000

ROLES_DIRECT = {0x399C4A0: "hash", 0x4A03180: "side", 0x3281190: "cost", 0x3987CB0: "flagged", 0x4D11B70: "leg", 0x445D4A0: "final"}
ROLES_SLOT = {0x576F6D8: "round", 0x5774548: "default", 0x5774790: "validate", 0x5774A80: "quote", 0x5773170: "holder", 0x576DFE0: "memcpy",
              0x5773D50: "grow", 0x576E010: "free", 0x576E470: "panic_rdi", 0x576DFC8: "panic_rdx", 0x576E048: "panic_r8", 0x576E128: "abort"}

LOC_SPOT_TABLE = 0x56F21F0
LOC_TOKEN_TABLE = 0x56F1FD8
LOC_HELPER_TOKEN = 0x5714C70
LOC_UNWRAP = 0x5714C10

PAYLOAD = HEAP_BASE + 0x400
OUTVEC = HEAP_BASE + 0x600
USER = HEAP_BASE + 0x700
MAP2 = HEAP_BASE + 0x780
STATE = HEAP_BASE + 0x1000
ENTRIES_LOW = HEAP_BASE + 0x3C00
CTRL = HEAP_BASE + 0x6000
SPOTS = HEAP_BASE + 0x7000
SPOT_WORDS = HEAP_BASE + 0xA000
TOKENS = HEAP_BASE + 0xA400
LEGS = HEAP_BASE + 0xB000
NODES = HEAP_BASE + 0xC000
ROWS = HEAP_BASE + 0x10000
USED = HEAP_BASE + 0x18000 - HEAP_BASE
BUCKETS = 64
ENTRY_STRIDE = 0x90
SPOT_STRIDE = 0xE8
TOKEN_STRIDE = 0x20
SPOT_ROWS = 40
TOKEN_ROWS = 40
OUT_CAP = 8
USER_BYTES = bytes(range(0x51, 0x65))
STATE_60 = bytes(range(0xB0, 0xBC))
HASH_FACTOR = 0x9E3779B97F4A7C15
SIDE_SIZE = 0xF8
UNDEFINED_ROW = (0x225, 0x226, 0x227, 0x264, 0x265, 0x266, 0x267)


def hash_of(key):
    return (key * HASH_FACTOR) & MASK[8]


def pattern(index):
    return bytes((0x30 + index * 0x40 + at * 7) & 0xFF for at in range(SIDE_SIZE))


def flagged_bytes(flag, first, second):
    return struct.pack("<QQQQ", first ^ 0x0101010101010101, second ^ 0x0202020202020202, flag * 0x1111, first + second)


def spec_round(value):
    """f64::round: halves away from zero."""
    if value != value or abs(value) == math.inf or abs(value) >= 2.0 ** 52:
        return value
    whole = float(math.trunc(value))
    if abs(value - whole) >= 0.5:
        whole += math.copysign(1.0, value)
    return math.copysign(whole, value)


def spec_amount_tail(value):
    """Rows after the amount multiply: non-finite 0, floor at 0, ceiling i64::MAX."""
    if value != value or value == math.inf or value == -math.inf or value <= 0:
        return 0
    if value > 9223372036854774784.0:
        return MAX_I64
    return int(value)


def spec_px_tail(value):
    """Rows after round: NaN, zero, negative and +inf give 1; above the last double below 2^64 gives u64::MAX."""
    if value != value or value <= 0 or value == math.inf:
        return 1
    if value > 18446744073709549568.0:
        return MAX_U64
    return max(1, int(value))


def fdiv(left, right):
    if right == 0:
        return math.copysign(math.inf, left)
    return left / right


def leg_factor(count):
    return (fdiv(1.0, float(count)) + -1.0) + 1.0


def leg_px(value, count):
    return spec_px_tail(spec_round(float(value) * leg_factor(count)))


def share_amount(amount, count):
    return spec_amount_tail(float(amount) * fdiv(1.0, float(count)))


class SpecPanic(Exception):
    pass


class Case:
    """One call: the two leg lists, the outcome entries, table contents and stub answers."""

    def __init__(self, name="", **fields):
        self.name = name
        self.lists = (((7, 11, 1000), (8, 13, 2000), (9, 15, 3000)), ())
        self.entries = {7: (11, 100000000, 12, 90000000), 8: (13, 100000000, 14, 80000000), 9: (15, 70000000, 16, 60000000)}
        self.spot_lens = {}
        self.spot_tokens = {}
        self.parents = {}
        self.spot_count = SPOT_ROWS
        self.token_count = TOKEN_ROWS
        self.map_empty = False
        self.word8 = 0
        self.word30 = 1
        self.head = 0x4141414142424242
        self.first = 0x1111
        self.second = 0x2222
        self.amount = 900000
        self.p60 = 0x6060
        self.p68 = 0x6868
        self.flag_a0 = 1
        self.word0 = 1
        self.statuses = {}
        self.scales = {}
        self.default_scale = 0x5A5A
        self.holders = {}
        self.state0 = 1
        self.state_words = (0xABCD, 0xDCBA)
        self.flag = 0x37
        self.cost = None
        self.quote = None
        self.cap = OUT_CAP
        self.shape = "leaf"
        self.__dict__.update(fields)

    def parent(self, token):
        return self.parents.get(token, 3)

    def spot_token(self, tok):
        return self.spot_tokens.get(tok, tok)

    def side(self, tok):
        """The two-sided helper, one side: (error, parent word)."""
        if tok >= self.spot_count:
            raise SpecPanic(LOC_SPOT_TABLE)
        if self.spot_lens.get(tok, 1) != 1:
            return (True, None)
        token = self.spot_token(tok)
        if token >= self.token_count:
            raise SpecPanic(LOC_HELPER_TOKEN)
        return (False, self.parent(token))

    def cost_of(self, px):
        return (px + 5) & MAX_U64 if self.cost is None else self.cost

    def quote_of(self, size):
        return (size * 3) & MAX_U64 if self.quote is None else self.quote


def spec_record(case, count, flag):
    if case.word8 == 2 or flag or count == 0:
        return None
    if case.amount >> 63:
        raise SpecPanic(LOC_UNWRAP)
    first = (case.first, ADDRESS_A) if case.word8 & MASK[4] == 1 else None
    second = (case.second, ADDRESS_B) if case.word30 & MASK[4] == 1 else None
    return (first, second, share_amount(case.amount, count), case.p60, case.p68)


def spec_row(case, spot, px, quote, product, held, flag):
    row = bytearray(ROW_SIZE)
    side = bytearray(pattern(0))
    side[0:8] = struct.pack("<Q", case.word0)
    side[8] = 0x41
    row[0:SIDE_SIZE] = side
    row[SIDE_SIZE:2 * SIDE_SIZE] = pattern(1)
    struct.pack_into("<QQQQQ", row, 0x1F0, spot, px, quote, product, 0)
    row[0x218:0x224] = STATE_60
    row[0x224] = flag
    struct.pack_into("<QQQ", row, 0x228, 1, held, px)
    row[0x240:0x244] = bytes((ROW_TAG, case.flag_a0, flag, 1))
    if case.state0 == 1:
        row[0x244:0x264] = flagged_bytes(case.flag, case.state_words[0], case.state_words[1])
    return bytes(row)


def spec_body(case, events, rows):
    legs_done = 0
    for index, flag in ((0, 0), (1, 1)):
        count = 0
        for ident, tok, _size in case.lists[index]:
            if case.map_empty or ident not in case.entries:
                return 4
            entry = case.entries[ident]
            first = case.side(entry[0])
            second = case.side(entry[2])
            if first[0] or second[0]:
                return 0
            if first[1] != second[1]:
                return 0xF
            if first[1] != tok:
                count = min(count + 1, MAX_U64)
        record = spec_record(case, count, flag)
        factor = leg_factor(count) if count else None
        for ident, tok, size in case.lists[index]:
            cost = 0
            entry = case.entries[ident]
            parent = case.side(entry[0])[1]
            picked = None
            if parent != tok:
                picked = 1 if entry[0] == tok else 3 if entry[2] == tok else None
            if picked is not None:
                value = entry[picked]
                rounded = spec_round(float(value) * factor)
                events.append(("round", to_bits(rounded)))
                px = spec_px_tail(rounded)
                if tok >= case.spot_count:
                    raise SpecPanic(LOC_SPOT_TABLE)
                if case.spot_lens.get(tok, 1) == 1:
                    spot = case.spot_token(tok)
                    if spot >= case.token_count:
                        raise SpecPanic(LOC_TOKEN_TABLE)
                    word = case.parent(spot)
                    scale = case.scales.get(word)
                    if scale is None:
                        events.append(("default", word))
                        scale = case.default_scale
                    charge = case.cost_of(px)
                    events.append(("cost", scale, px, spot))
                    if charge:
                        events.append(("validate", size, tok))
                        quote = case.quote_of(size)
                        events.append(("quote", spot, size, px))
                        for side in (0, 1):
                            events.append(("side", side, flag ^ 1, spot, tok, size, record))
                        events.append(("holder", USER_BYTES))
                        held = case.holders.get(0x1000 + spot, 0)
                        product = px * quote
                        if product <= MAX_SAFE and case.word0 != 2:
                            if case.state0 == 1:
                                events.append(("flagged", case.flag, case.state_words[0], case.state_words[1]))
                            if len(rows) == case.cap:
                                events.append(("grow",))
                            rows.append(spec_row(case, spot, px, quote, product, held, flag ^ 1))
                            cost = charge
            events.append(("leg", ident, flag, tok, size, 2, cost))
            status = case.statuses.get(legs_done, SUCCESS)
            legs_done += 1
            if status != SUCCESS:
                return status
    if case.word8 == 2:
        return SUCCESS
    events.append(("final", case.head, case.amount))
    return SUCCESS


def spec_run(case):
    events = []
    rows = []
    try:
        status = spec_body(case, events, rows)
    except SpecPanic as error:
        return ("panic", error.args[0], tuple(events), tuple(rows))
    for index in (0, 1):
        if len(case.lists[index]) + 2:
            events.append(("free", LEG_BASE[index], (len(case.lists[index]) + 2) * 24))
    return ("value", status, tuple(events), tuple(rows))


ADDRESS_A = bytes(range(0x71, 0x85))
ADDRESS_B = bytes(range(0x91, 0xA5))
LEG_BASE = (LEGS, LEGS + 0x800)


def reference_outcome(px, quote):
    """The published reference rule, written from its text: a product above the bound is status 18."""
    return "ok" if px * quote <= MAX_SAFE else "status_18"


def role_maps(image, target):
    """Direct targets and slots for one copy, in row order, joined to the first copy's roles."""
    def listing(start):
        rows = decode_range(image, *image.exact_fde(start))
        direct = [row.target for row in rows if row.op == "call"]
        slots = [row.va + row.size + struct.unpack_from("<i", row.data, row.rip_at)[0] for row in rows if row.op == "calli" and row.rip_at is not None]
        return direct, slots

    first = listing(TARGETS[0])
    here = listing(target)
    if len(first[0]) != len(here[0]) or len(first[1]) != len(here[1]):
        raise EvidenceError("the copies call in different numbers")
    direct = {}
    slots = {}
    for a, b in zip(*(first[0], here[0])):
        if a in ROLES_DIRECT:
            direct[b] = ROLES_DIRECT[a]
    for a, b in zip(*(first[1], here[1])):
        if a in ROLES_SLOT:
            slots[b] = ROLES_SLOT[a]
    return direct, slots


class Harness:
    def __init__(self, image, copy=0, patches=None):
        self.image = image
        self.copy = copy
        self.target = TARGETS[copy]
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((REAL_HELPER,))
        direct, slots = role_maps(image, self.target)
        machine.calls = {va: getattr(self, "on_" + role) for va, role in direct.items()}
        machine.slots = {}
        for slot, role in slots.items():
            marker = MARK_BASE + slot
            machine.memory.statics[slot] = marker
            machine.slots[marker] = getattr(self, "on_" + role)
        self.events = []
        self.case = None

    # Stubs: each checks what it is given and records it.
    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def read(self, addr, size=8):
        return self.machine.memory.read(addr, size)

    def on_hash(self, machine):
        self.expect(machine.regs[RDI] == STATE + 0x180, "hash table")
        machine.regs[RAX] = self.hash_of(self.read(machine.regs[RSI]))

    hash_of = staticmethod(hash_of)

    def on_round(self, machine):
        value = to_float(machine.xmm[0] & MASK[8])
        result = spec_round(value)
        self.events.append(("round", to_bits(result)))
        machine.xmm_result = to_bits(result)

    def on_default(self, machine):
        self.expect(machine.regs[RDI] == STATE + 0x90, "default context")
        self.events.append(("default", machine.regs[RSI]))
        machine.regs[RAX] = self.case.default_scale

    def on_cost(self, machine):
        self.expect(machine.regs[RCX] == STATE + 0x90, "cost context")
        self.events.append(("cost", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = self.case.cost_of(machine.regs[RSI])

    def on_validate(self, machine):
        self.expect(machine.regs[RDX] == STATE + 0x90, "validate context")
        self.events.append(("validate", machine.regs[RDI], machine.regs[RSI]))

    def on_quote(self, machine):
        self.expect(machine.regs[RCX] == STATE + 0x90, "quote context")
        self.events.append(("quote", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = self.case.quote_of(machine.regs[RSI])

    def on_side(self, machine):
        closure = machine.regs[RSI]
        memory = machine.memory
        index = machine.regs[RDX]
        self.expect(self.read(closure) == STATE and self.read(closure + 8) == STATE + 0x80, "side closure state")
        self.expect(memory.bytes_at(self.read(closure + 24), 20) == USER_BYTES, "side closure user")
        flag = self.read(self.read(closure + 16), 1)
        spot = self.read(self.read(closure + 32))
        tok_at = self.read(closure + 48)
        record = self.read(self.read(closure + 40))
        if record == 0:
            shown = None
        else:
            first = second = None
            if self.read(record) == 1:
                first = (self.read(record + 8), memory.bytes_at(record + 0x10, 20))
            else:
                self.expect(self.read(record) == 0, "first option word")
            if self.read(record + 0x28) == 1:
                second = (self.read(record + 0x30), memory.bytes_at(record + 0x38, 20))
            else:
                self.expect(self.read(record + 0x28) == 0, "second option word")
            shown = (first, second, self.read(record + 0x50), self.read(record + 0x58), self.read(record + 0x60))
        self.events.append(("side", index, flag, spot, self.read(tok_at), self.read(tok_at + 8), shown))
        data = bytearray(pattern(index))
        if index == 0:
            data[0:8] = struct.pack("<Q", self.case.word0)
            data[8] = 0x41
        memory.put_bytes(machine.regs[RDI], bytes(data))

    def on_holder(self, machine):
        self.expect(machine.regs[RDI] == STATE + 0x80, "holder map")
        self.events.append(("holder", machine.memory.bytes_at(machine.regs[RSI], 20)))
        machine.regs[RAX] = MAP2

    def on_flagged(self, machine):
        self.expect(machine.regs[RDI] == machine.regs[RSP] + 8 + 0xD0 and machine.regs[R8] == 0, "flagged arguments")
        self.events.append(("flagged", machine.regs[RSI] & 0xFF, machine.regs[RCX], machine.regs[RDX]))
        machine.memory.put_bytes(machine.regs[RDI], flagged_bytes(machine.regs[RSI] & 0xFF, machine.regs[RCX], machine.regs[RDX]))

    def on_leg(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE, "leg state")
        self.expect(machine.memory.bytes_at(regs[RSI], 20) == USER_BYTES, "leg user")
        self.events.append(("leg", regs[RDX], regs[RCX] & 0xFF, regs[R8], regs[R9], self.read(regs[RSP] + 8), self.read(regs[RSP] + 16)))
        status = self.case.statuses.get(self.legs_done, SUCCESS)
        self.legs_done += 1
        regs[RAX] = status

    def on_final(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + 0x80 and regs[R8] == PAYLOAD and regs[RSI] == USER, "final arguments")
        self.events.append(("final", regs[RDX], regs[RCX]))

    def on_memcpy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_grow(self, machine):
        self.expect(machine.regs[RDI] == OUTVEC, "grow vector")
        self.events.append(("grow",))
        self.word(OUTVEC, OUT_CAP * 2)

    def on_free(self, machine):
        self.expect(machine.regs[RDX] == 0, "free align")
        self.events.append(("free", machine.regs[RDI], machine.regs[RSI]))

    def on_panic_rdi(self, machine):
        raise Panicked(machine.regs[RDI])

    def on_panic_rdx(self, machine):
        raise Panicked(machine.regs[RDX])

    def on_panic_r8(self, machine):
        raise Panicked(machine.regs[R8])

    def on_abort(self, machine):
        raise Halt("abort stub")

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def install_map(self, case):
        memory = self.machine.memory
        memory.put_bytes(ENTRIES_LOW, bytes([FILL]) * (CTRL - ENTRIES_LOW))
        control = bytearray([0xFF]) * (BUCKETS + 16)
        for key in sorted(case.entries, reverse=True):
            digest = self.hash_of(key)
            at = digest & (BUCKETS - 1)
            while control[at] != 0xFF:
                at = (at + 1) % BUCKETS
            control[at] = digest >> 57
            if at < 16:
                control[BUCKETS + at] = digest >> 57
            entry = CTRL - ENTRY_STRIDE * (at + 1)
            a_tok, a_value, b_tok, b_value = case.entries[key]
            self.word(entry, key)
            self.word(entry + 0x20, a_value)
            self.word(entry + 0x28, a_tok)
            self.word(entry + 0x48, b_value)
            self.word(entry + 0x50, b_tok)
        memory.put_bytes(CTRL, bytes(control))

    def node(self, keys, children, base, value_at, stride, values, len_at, edges_at, size, stale):
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * size)
        for slot in range(11):
            self.word(base + 8 + 8 * slot, keys[slot] if slot < len(keys) else stale)
            self.word(base + value_at + stride * slot, values.get(keys[slot], 0xBAD0 + slot) if slot < len(keys) else 0xBAD0 + slot)
        self.word(base + len_at, len(keys), 2)
        for slot, child in enumerate(children or ()):
            self.word(base + edges_at + 8 * slot, child)

    def tree(self, values, base, value_at, stride, len_at, edges_at, size, stale):
        keys = tuple(sorted(values))
        if self.case.shape == "two" and len(keys) >= 3:
            cut = len(keys) // 2
            left = base + size + 0x100
            right = left + size + 0x100
            self.node(keys[:cut], None, left, value_at, stride, values, len_at, edges_at, size, stale)
            self.node(keys[cut + 1:], None, right, value_at, stride, values, len_at, edges_at, size, stale)
            self.node((keys[cut],), (left, right), base, value_at, stride, values, len_at, edges_at, size + 0x70, stale)
            return base, 1
        self.node(keys, None, base, value_at, stride, values, len_at, edges_at, size, stale)
        return base, 0

    def install(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        self.case = case
        self.events = []
        self.legs_done = 0
        memory.put_bytes(STATE, bytes([FILL]) * 0x2000)
        memory.put_bytes(USER, USER_BYTES)
        memory.put_bytes(STATE + 0x60, STATE_60)
        self.word(STATE, case.state0)
        self.word(STATE + 8, case.state_words[0])
        self.word(STATE + 0x28, case.state_words[1])
        for offset in (FLAG_FIELD[self.copy], FLAG_FIELD[1 - self.copy]):
            self.word(STATE + offset, case.flag if offset == FLAG_FIELD[self.copy] else case.flag ^ 0xFF, 1)
        self.word(STATE + 0x160, CTRL)
        self.word(STATE + 0x168, BUCKETS - 1)
        self.word(STATE + 0x178, 0 if case.map_empty else 5)
        self.install_map(case)
        self.word(STATE + 0x210, SPOTS)
        self.word(STATE + 0x218, case.spot_count)
        self.word(STATE + 0x1F8, TOKENS)
        self.word(STATE + 0x200, case.token_count)
        for tok in range(SPOT_ROWS):
            row = SPOTS + tok * SPOT_STRIDE
            self.word(row + 0x58, SPOT_WORDS + 8 * tok)
            self.word(row + 0x60, case.spot_lens.get(tok, 1))
            self.word(SPOT_WORDS + 8 * tok, case.spot_token(tok))
        for token in range(TOKEN_ROWS):
            row = TOKENS + token * TOKEN_STRIDE
            self.word(row, 0x1000 + token)
            self.word(row + 8, case.parent(token))
        stale = 0
        root, height = self.tree(dict(case.scales), NODES, 0x60, 8, 0xBA, 0xC0, 0xC0, stale) if case.scales else (0, 0)
        self.word(STATE + 0x250, root)
        self.word(STATE + 0x258, height)
        if case.holders:
            root, height = self.tree(dict(case.holders), NODES + 0x1000, 0x70, 24, 0x16A, 0x170, 0x170, stale)
        else:
            root, height = 0, 0
        self.word(MAP2 + 0x10, root)
        self.word(MAP2 + 0x18, height)
        self.word(PAYLOAD, case.head)
        self.word(PAYLOAD + 8, case.word8)
        self.word(PAYLOAD + 0x10, case.first)
        memory.put_bytes(PAYLOAD + 0x18, ADDRESS_A)
        self.word(PAYLOAD + 0x30, case.word30)
        self.word(PAYLOAD + 0x38, case.second)
        memory.put_bytes(PAYLOAD + 0x40, ADDRESS_B)
        self.word(PAYLOAD + 0x58, case.amount)
        self.word(PAYLOAD + 0x60, case.p60)
        self.word(PAYLOAD + 0x68, case.p68)
        self.word(PAYLOAD + 0xA0, case.flag_a0, 1)
        for index in (0, 1):
            legs = case.lists[index]
            at = 0x70 + 0x18 * index
            self.word(PAYLOAD + at, len(legs) + 2)
            self.word(PAYLOAD + at + 8, LEG_BASE[index])
            self.word(PAYLOAD + at + 16, len(legs))
            for slot, (ident, tok, size) in enumerate(legs):
                self.word(LEG_BASE[index] + 24 * slot, ident)
                self.word(LEG_BASE[index] + 24 * slot + 8, tok)
                self.word(LEG_BASE[index] + 24 * slot + 16, size)
            # A sentinel past the end of each list.
            self.word(LEG_BASE[index] + 24 * len(legs), 0x7777)
        memory.put_bytes(ROWS, bytes([FILL]) * (USED - (ROWS - HEAP_BASE)))
        self.word(OUTVEC, case.cap)
        self.word(OUTVEC + 8, ROWS)
        self.word(OUTVEC + 16, 0)

    def rows(self):
        count = self.read(OUTVEC + 16)
        found = []
        for index in range(count):
            data = bytearray(self.machine.memory.bytes_at(ROWS + index * ROW_SIZE, ROW_SIZE))
            for at in UNDEFINED_ROW:
                data[at] = 0
            found.append(bytes(data))
        return tuple(found)

    def run(self, case):
        self.install(case)
        try:
            value = self.machine.run(self.target, {RDI: STATE, RSI: USER, RDX: PAYLOAD, RCX: OUTVEC})
        except Panicked as error:
            return ("panic", error.args[0], tuple(self.events), self.rows())
        if self.read(ROWS + self.read(OUTVEC + 16) * ROW_SIZE, 1) != FILL:
            raise Halt("write past the last row")
        return ("value", value & 0xFF, tuple(self.events), self.rows())

    def tail(self, start, end, result, bits):
        """Run a row window on one bit pattern; return the decision record and the result register."""
        machine = self.machine
        machine.regs = [POISON] * 16
        machine.xmm = [POISON | POISON << 64] * 16
        machine.xmm[0] = bits | POISON << 64
        machine.regs[RBP] = PAYLOAD
        machine.regs[RSP] = STACK_TOP - 0x4000
        pc = start
        trace = []
        for _ in range(100):
            if pc == end:
                return tuple(trace), machine.regs[result]
            row = machine.cache.get(pc)
            if row is None:
                row = decode(machine.read_code, pc)
                machine.cache[pc] = row
            machine.seen.add(pc)
            if row.op in ("jcc", "cmov"):
                trace.append((row.va, machine.condition(row.cc)))
            pc = machine.step(row)
            if row.op == "ucomisd":
                trace.append((row.va, machine.cf, machine.zf, machine.pf))
            elif row.op == "cvttsd2si":
                trace.append((row.va, machine.regs[row.a[1]] == 1 << 63))
        raise Halt("tail did not end")


AMOUNT_WINDOW = (0x4D18356, 0x4D183CA, RDI)
PX_WINDOW = (0x4D18694, 0x4D18722, RBP)


FLOAT_SEEDS = ((0, 0x7FEFFFFFFFFFFFFF), (0x7FF0000000000000, 0x7FF0000000000000), (0x7FF0000000000001, (1 << 63) - 1),
               (1 << 63, (1 << 63) | 0x7FEFFFFFFFFFFFFF), ((1 << 63) | 0x7FF0000000000000, (1 << 63) | 0x7FF0000000000000),
               ((1 << 63) | 0x7FF0000000000001, MASK[8]))
INTERIOR_POINTS = 8


def interior(lo, hi):
    return [lo + (hi - lo) * index // (INTERIOR_POINTS + 1) for index in range(1, INTERIOR_POINTS + 1)]


def merge(found):
    found.sort(key=lambda row: row[0])
    merged = []
    for lo, hi, trace in found:
        if merged and merged[-1][2] == trace and merged[-1][1] + 1 == lo:
            merged[-1] = (merged[-1][0], hi, trace)
        else:
            merged.append((lo, hi, trace))
    return merged


def split(run, seed):
    """Halve a range until both ends share one decision record."""
    stack = [seed]
    found = []
    runs = 0
    while stack:
        lo, hi = stack.pop()
        first = run(lo)
        last = run(hi) if hi != lo else first
        runs += 2
        if first == last:
            found.append((lo, hi, first))
            continue
        middle = (lo + hi) // 2
        stack.append((middle + 1, hi))
        stack.append((lo, middle))
    return merge(found), runs


def refine_window(harness, window, spec):
    start, end, result = window
    shift = TARGETS[harness.copy] - TARGETS[0]
    rows = []
    runs = 0
    for seed in FLOAT_SEEDS:
        pieces, count = split(lambda bits: harness.tail(start + shift, end + shift, result, bits)[0], seed)
        runs += count
        for lo, hi, trace in pieces:
            for bits in [lo, hi] + (interior(lo, hi) if hi > lo else []):
                got = harness.tail(start + shift, end + shift, result, bits)
                if got[0] != trace:
                    raise EvidenceError("interior point left its piece: %#x" % bits)
                if got[1] != spec(to_float(bits)):
                    raise EvidenceError("window mismatch at %#x: %#x" % (bits, got[1]))
            rows.append((lo, hi, harness.tail(start + shift, end + shift, result, lo)[1], harness.tail(start + shift, end + shift, result, hi)[1], len(trace)))
    return rows, runs


def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state


def crowded():
    """Twenty ids that start probing at the bucket of id 7, one sharing its seven hash bits, so id 7 sits past the first group."""
    home = Harness.hash_of(7)
    near = []
    twin = None
    key = 1000
    while len(near) < 20 or twin is None:
        digest = Harness.hash_of(key)
        if digest & (BUCKETS - 1) == home & (BUCKETS - 1):
            if digest >> 57 == home >> 57:
                twin = twin or key
            else:
                near.append(key)
        key += 1
    entries = dict(Case().entries)
    for other in near[:20] + [twin]:
        entries[other] = (1, 1, 2, 1)
    return entries


ONE_LEG = ((7, 11, 1000),)
TWO_LEGS = ((7, 11, 1000), (8, 13, 2000))
FORTY_NINE = tuple((7, 11, 1 + slot) for slot in range(49))
NAMED = (
    Case("three legs, list 0: record present"),
    Case("three legs in list 1: no record", lists=((), ((7, 11, 1000), (8, 13, 2000), (9, 15, 3000)))),
    Case("legs in both lists", lists=(TWO_LEGS, ((9, 15, 3000),))),
    Case("no legs at all", lists=((), ())),
    Case("one leg: factor 1, px = value", lists=(ONE_LEG, ())),
    Case("two legs: factor 1/2", lists=(TWO_LEGS, ())),
    Case("leg on side B of its entry", lists=(((7, 12, 500),), ())),
    Case("side B value odd", lists=(((7, 12, 500), (8, 14, 7)), ()), entries={7: (11, 1, 12, 3), 8: (13, 5, 14, 1)}),
    Case("leg token equals the parent word: cost 0, not counted", lists=(((7, 3, 500), (8, 13, 7)), ())),
    Case("only parent legs: count 0, no record, cost 0", lists=(((7, 3, 500), (8, 3, 7)), ())),
    Case("leg token on neither side: counted, cost 0", lists=(((7, 20, 500), (8, 13, 7)), ())),
    Case("empty map field: status 4", map_empty=True),
    Case("unknown id: status 4", lists=(((77, 11, 1),), ())),
    Case("unknown id in the second list after the first", lists=(ONE_LEG, ((77, 11, 1),))),
    Case("sides with different parents: status 15", parents={12: 4}),
    Case("side A token vector length 2: status 0", spot_lens={11: 2}),
    Case("side B token vector length 0: status 0", spot_lens={12: 0}),
    Case("side A spot index one past the table", entries={7: (40, 1, 12, 1)}, lists=(((7, 11, 1),), ())),
    Case("side B spot index one past the table", entries={7: (11, 1, 40, 1)}, lists=(((7, 11, 1),), ())),
    Case("side A spot index past a short table", spot_count=11),
    Case("side B token index one past the table", spot_tokens={12: 40}),
    Case("side A token index past a short table", token_count=11),
    Case("spot table count 12: leg index 11 still inside", spot_count=13, lists=(ONE_LEG, ())),
    Case("option words 2: no record, no final", word8=2),
    Case("option word 3: record with no first", word8=3),
    Case("option low dword 1 only", word8=0x100000001),
    Case("first option present", word8=1),
    Case("second option absent", word30=0),
    Case("second option high dword set", word30=0x100000001),
    Case("second option 2: absent", word30=2),
    Case("amount 0", amount=0),
    Case("amount 1, three legs: truncates to 0", amount=1),
    Case("amount 3, three legs", amount=3),
    Case("amount 2^63 - 1 one leg: f64 2^63, cap i64::MAX", amount=MAX_I64, lists=(ONE_LEG, ())),
    Case("amount 2^63 - 512 one leg", amount=(1 << 63) - 512, lists=(ONE_LEG, ())),
    Case("amount 2^63 - 513 one leg", amount=(1 << 63) - 513, lists=(ONE_LEG, ())),
    Case("amount 2^63 panics in list 0", amount=1 << 63),
    Case("amount 2^63 in list 1 only: no conversion", amount=1 << 63, lists=((), TWO_LEGS)),
    Case("amount 2^63 with no counted legs: no conversion", amount=1 << 63, lists=(((7, 3, 1),), ())),
    Case("amount 2^63 with word 2: no conversion", amount=1 << 63, word8=2),
    Case("forty-nine legs, amount 49: 49 * (1/49) truncates to 0", amount=49, lists=(FORTY_NINE, ()), cap=60),
    Case("value 0: px floor 1", entries={7: (11, 0, 12, 0)}, lists=(ONE_LEG, ())),
    Case("value 1, two legs: round(0.5) is 1", entries={7: (11, 1, 12, 0), 8: (13, 1, 14, 0)}, lists=(TWO_LEGS, ())),
    Case("value 2, three legs", entries={7: (11, 2, 12, 0), 8: (13, 2, 14, 0), 9: (15, 2, 16, 0)}),
    Case("value u64 max, one leg", entries={7: (11, MAX_U64, 12, 0)}, lists=(ONE_LEG, ())),
    Case("value 2^63, one leg", entries={7: (11, 1 << 63, 12, 0)}, lists=(ONE_LEG, ())),
    Case("value u64 max, two legs", entries={7: (11, MAX_U64, 12, 0), 8: (13, MAX_U64, 14, 0)}, lists=(TWO_LEGS, ())),
    Case("leg spot vector length 2 in the second pass only: parent side untouched", lists=(((7, 12, 5),), ()), spot_lens={}),
    Case("scale from the map, leaf", scales={3: 0x7777, 5: 0x8888, 9: 0x9999}),
    Case("scale absent, map non-empty", scales={2: 0x7777, 5: 0x8888}),
    Case("scale from the map, two levels", scales={1: 0x1, 2: 0x2, 3: 0x3, 4: 0x4, 5: 0x5, 6: 0x6, 7: 0x7}, shape="two"),
    Case("scale right of a two-level root", scales={0: 0x1, 1: 0x2, 2: 0x3}, shape="two"),
    Case("scale between keys of a two-level root", scales={0: 0x1, 1: 0x2, 5: 0x3, 6: 0x4, 7: 0x5}, shape="two"),
    Case("cost 0: no row, leg cost 0", cost=0),
    Case("cost u64 max", cost=MAX_U64),
    Case("holder value present", holders={0x100B: 0x4444, 0x100C: 1, 0x1000: 2}),
    Case("holder value absent", holders={0x1001: 1, 0x1002: 2}),
    Case("holder value two levels", holders={0x1001: 1, 0x1003: 2, 0x100B: 3, 0x100D: 4, 0x1020: 5}, shape="two"),
    Case("holder value at the root key", holders={0x1001: 1, 0x100B: 2, 0x1020: 3}, shape="two", lists=(ONE_LEG, ())),
    Case("holder above the root key", holders={0x1001: 1, 0x1002: 2, 0x1003: 3}, shape="two", lists=(ONE_LEG, ())),
    Case("side word 2: no row, leg cost 0", word0=2),
    Case("side word 0", word0=0),
    Case("side word 3", word0=3),
    Case("product exactly the bound: admitted", lists=(ONE_LEG, ()), entries={7: (11, 2, 12, 0)}, quote=(MAX_SAFE // 2)),
    Case("product bound plus one, odd: refused", lists=(ONE_LEG, ()), entries={7: (11, 1, 12, 0)}, quote=MAX_SAFE + 1),
    Case("product bound with px 1: admitted", lists=(ONE_LEG, ()), entries={7: (11, 1, 12, 0)}, quote=MAX_SAFE),
    Case("product 2^64 exactly: low word 0, refused by overflow", lists=(ONE_LEG, ()), entries={7: (11, 1 << 32, 12, 0)}, quote=1 << 32),
    Case("product above 2^64 with low word small", lists=(ONE_LEG, ()), entries={7: (11, 1 << 33, 12, 0)}, quote=(1 << 31) + 1),
    Case("quote 0: product 0, admitted", quote=0),
    Case("px 3 and quote 2^62: above the bound", lists=(ONE_LEG, ()), entries={7: (11, 3, 12, 0)}, quote=1 << 62),
    Case("state word 0: no extra call", state0=0),
    Case("state word 2: no extra call", state0=2),
    Case("flag byte differs", flag=0xC9),
    Case("flag byte a0 is 0", flag_a0=0),
    Case("flag byte a0 is 7", flag_a0=7),
    Case("first leg status 5: stops", statuses={0: 5}),
    Case("second leg status 0: stops", statuses={1: 0}),
    Case("last leg of list 1 status 9", lists=(ONE_LEG, ((9, 15, 3),)), statuses={1: 9}),
    Case("grow at cap 0", cap=0),
    Case("grow at cap 1", cap=1),
    Case("id 7 past a full probe group, with a hash twin", entries=crowded()),
    Case("unknown id over a crowded table: status 4", entries=crowded(), lists=(((77, 11, 1),), ())),
    Case("spot length 2 on the leg side after the check passes", lists=(((7, 20, 5), (8, 13, 7)), ()), spot_lens={20: 2}),
)


def vector_cases(count):
    random = lcg(0x4D17FA0)
    cases = []
    values = (0, 1, 2, 3, 99, 100, 101, 12345, 100000000, 99999999, 1 << 52, (1 << 53) + 1, 1 << 63, MAX_U64)
    amounts = (0, 1, 2, 3, 7, 49, 98, 1000, 900000, 1 << 40, (1 << 53) + 1, 1 << 62, MAX_I64)
    for _ in range(count):
        entries = {}
        for ident in (7, 8, 9, 10):
            pick = next(random)
            first = values[next(random) % len(values)] if pick & 1 else next(random) >> (next(random) % 64)
            second = values[next(random) % len(values)] if pick & 2 else next(random) >> (next(random) % 64)
            entries[ident] = (11 + (ident - 7) * 2, first, 12 + (ident - 7) * 2, second)
        legs = ([], [])
        for slot in range(next(random) % 7):
            ident = 7 + next(random) % 4
            tok = entries[ident][next(random) % 3 and 0 or 2] if next(random) % 5 else 3
            legs[next(random) % 3 == 0].append((ident, tok, next(random) >> (next(random) % 64)))
        amount = amounts[next(random) % len(amounts)]
        quote = None if next(random) % 3 else next(random) >> (next(random) % 64)
        cost = None if next(random) % 5 else 0
        word = next(random) % 6
        cases.append(Case(entries=entries, lists=(tuple(legs[0]), tuple(legs[1])), amount=amount, quote=quote, cost=cost, word8=word % 3,
                          word30=word % 2, state0=next(random) % 3, word0=next(random) % 4, flag=next(random) & 0xFF, flag_a0=next(random) & 0xFF))
    return cases


def check_cases(harness, cases):
    rows = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("mismatch for %s" % (case.name or (case.lists, case.entries, case.amount)))
        rows.append(got)
    return rows


def copy_diff(image):
    """Rows of the two copies, joined by position; rip displacements are compared as absolute targets, call targets are listed."""
    first = decode_range(image, *image.exact_fde(TARGETS[0]))
    second = decode_range(image, *image.exact_fde(TARGETS[1]))
    if len(first) != len(second):
        raise EvidenceError("copy row counts differ")
    differ = []
    calls = []
    for a, b in zip(first, second):
        if b.va - a.va != COPY_SHIFT or a.size != b.size or a.op != b.op:
            raise EvidenceError("copies do not line up at %#x" % a.va)
        left, right = a.data, b.data
        if a.rip_at is not None:
            target_a = a.va + a.size + struct.unpack_from("<i", left, a.rip_at)[0]
            target_b = b.va + b.size + struct.unpack_from("<i", right, b.rip_at)[0]
            if a.op == "calli" or target_a != target_b:
                calls.append(("slot" if a.op == "calli" else "rip", a.va, b.va, target_a, target_b))
            left = left[:a.rip_at] + left[a.rip_at + 4:]
            right = right[:b.rip_at] + right[b.rip_at + 4:]
        elif a.op == "call":
            calls.append(("direct", a.va, b.va, a.target, b.target))
            continue
        if left != right:
            differ.append((a.va, b.va, a.data.hex(), b.data.hex()))
    return len(first), differ, calls


def constant_rows(image):
    rows = []
    for va, name in ((0x20A278, "-1.0"), (0x20A730, "1.0"), (0x20A4B0, "+inf"), (0x20ACB8, "-2^63"), (0x20A7F0, "2^63"), (0x20A2C8, "largest double below 2^63"),
                     (0x20A510, "2^64"), (0x20A218, "largest double below 2^64")):
        rows.append(("%#x" % va, name, bytes(image.blob[image.offset(va):image.offset(va) + 8]).hex()))
    return rows


def constant_census(image):
    """Every movabs of the product bound in the two functions."""
    needle = struct.pack("<Q", MAX_SAFE)
    found = []
    for target in TARGETS:
        low, high = image.exact_fde(target)
        data = bytes(image.blob[image.offset(low):image.offset(high)])
        at = data.find(needle)
        while at >= 0:
            found.append("%#x" % (low + at - 2))
            at = data.find(needle, at + 1)
    return found


def bound_in(image, starts):
    """Bytes of the product bound inside whole functions, by FDE."""
    needle = struct.pack("<Q", MAX_SAFE)
    rows = []
    for start in starts:
        low, high = image.exact_fde(start)
        rows.append(("%#x" % low, "%#x" % high, bytes(image.blob[image.offset(low):image.offset(high)]).count(needle)))
    return rows


def factor_rows():
    """Factor against 1/n, and the price each gives for value 1e8; pure float arithmetic, the rows are checked against real bytes by the vectors."""
    rows = []
    for count in list(range(1, 33)) + [49, 64, 100, 1000]:
        share = fdiv(1.0, float(count))
        factor = leg_factor(count)
        px = leg_px(100000000, count)
        plain = spec_px_tail(spec_round(1e8 * share))
        rows.append((count, share.hex(), factor.hex(), "same" if share == factor else "differs", px, plain, px * count - 100000000))
    return rows


def factor_census(limit=1 << 16):
    differ = same_px = other_px = 0
    first = None
    for count in range(1, limit + 1):
        share = 1.0 / count
        factor = (share + -1.0) + 1.0
        if share != factor:
            differ += 1
            a = spec_px_tail(spec_round(1e8 * factor))
            b = spec_px_tail(spec_round(1e8 * share))
            if a == b:
                same_px += 1
            else:
                other_px += 1
                first = first or (count, a, b)
    return dict(limit=limit, factor_differs=differ, same_price=same_px, other_price=other_px, first_other=first)


def even_share_rows(limit=1000):
    """Exact multiples amount = n*k where the f64 share truncates below k."""
    rows = []
    for count in range(2, limit + 1):
        for whole in (1, 2, 3, 1000):
            got = share_amount(count * whole, count)
            if got != whole:
                rows.append((count, whole, count * whole, got))
    return rows


def reference_rows():
    return [(px, quote, px * quote, reference_outcome(px, quote), "admitted" if px * quote <= MAX_SAFE else "row skipped, leg cost 0")
            for px, quote in ((1, MAX_SAFE), (2, MAX_SAFE // 2), (1, MAX_SAFE + 1), (1 << 32, 1 << 32), (3, 1 << 62))]


WINDOWS = ((0x4D181F9, 0x4D18237), (0x4D1824D, 0x4D18459), (0x4D1860C, 0x4D18826), (0x4D18A18, 0x4D18A40), (0x4D18B8A, 0x4D18C46))


def edits_for(image, rows, seen):
    edits = []
    for row in rows:
        if row.va not in seen or not any(lo <= row.va < hi for lo, hi in WINDOWS):
            continue
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("addsd", "mulsd", "divsd", "subsd"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            other = {0x58: 0x5C, 0x5C: 0x58, 0x59: 0x5E, 0x5E: 0x59}[data[at]]
            edits.append((row.va, "operation", {row.va + at: other}))
        if row.rip_at is not None and row.op not in ("calli", "lea"):
            edits.append((row.va, "constant", {row.va + row.rip_at: data[row.rip_at] ^ 8}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def first_failure(harness, cases):
    for case in cases:
        try:
            if harness.run(case) != spec_run(case):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError):
            return case
    return None


def tail_killed(harness, va):
    for (start, end, result), spec in ((AMOUNT_WINDOW, spec_amount_tail), (PX_WINDOW, spec_px_tail)):
        if not start <= va < end:
            continue
        for bits in (0, 1, to_bits(0.5), to_bits(1.0), to_bits(2.0 ** 63), to_bits(2.0 ** 63 - 1024), to_bits(2.0 ** 64), to_bits(2.0 ** 64 - 2048), to_bits(2.0 ** 65), 0x7FEFFFFFFFFFFFFF, 0x7FEFFFFFFFFFFFFE,
                     to_bits(math.inf), to_bits(-math.inf), to_bits(-1.0), to_bits(-1e300), 0x7FF8000000000000, to_bits(1e300), 1 << 63):
            try:
                if harness.tail(start, end, result, bits)[1] != spec(to_float(bits)):
                    return True
            except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError):
                return True
    return False


NO_NEGATIVE = "every negative value ends at 0 at the cmovle whatever this row does"
NO_CLAMP = "the upper clamp is redundant: without it cvttsd2si gives the indefinite value and the cmova after it still gives i64::MAX"
SHADOWED = "shadowed: the helper in the first pass panics on the same index, so this second bound cannot fire"
EXPECTED_SURVIVORS = {
    (0x4D1821C, "immediate"): "the count saturation value needs 2^64 counted legs",
    (0x4D182FB, "immediate"): "count 0 means every leg holds the parent word, so no later row reads the record",
    (0x4D18360, "constant"): NO_NEGATIVE,
    (0x4D1836C, "condition"): NO_NEGATIVE,
    (0x4D1836E, "constant"): NO_CLAMP,
    (0x4D18376, "condition"): NO_CLAMP,
    (0x4D18384, "constant"): NO_CLAMP,
    (0x4D1861F, "immediate"): "the zero written here is read only on a branch the first pass already returned from with status 15",
    (0x4D186A1, "immediate"): "mask bit 0 cannot change a compare against 0x7fefffffffffffff for any value that reaches it, and the masked word is not used again",
    (0x4D186DB, "immediate"): "sign mask 62 instead of 63: the two lanes differ only in bit 0, which is clear for every value at or above 2^62",
    (0x4D186FE, "immediate"): "the value here is never kept: it is above or equal to 0 and never NaN, so the cmovae always replaces it",
    (0x4D1872B, "displacement"): SHADOWED,
    (0x4D18768, "displacement"): SHADOWED,
}


def run_mutants(image, rows, seen):
    results = []
    cases = list(NAMED)
    control = Harness(image, 0)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    for va, kind, patch in edits_for(image, rows, seen):
        harness = Harness(image, 0, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        if first_failure(harness, cases) is not None:
            results.append((va, kind, "killed", "whole run"))
        elif tail_killed(harness, va):
            results.append((va, kind, "killed", "bit pattern window"))
        else:
            results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def slot_rows(image, relative):
    rows = []
    for slot, role in sorted(ROLES_SLOT.items()):
        rows.append(("%#x" % slot, role, "%#x" % relative[slot] if slot in relative else "filled by the loader"))
    return rows


def location_rows(image, relative):
    rows = []
    for va in (LOC_SPOT_TABLE, LOC_TOKEN_TABLE, LOC_HELPER_TOKEN, LOC_UNWRAP):
        rows.append(("%#x" % va,) + tuple(image.location(va, relative)))
    return rows


def wrapper_rows(image):
    rows = []
    for target, wrapper in zip(TARGETS, WRAPPERS):
        rows.append(("%#x" % target, "%#x" % wrapper, ",".join("%#x" % va for va in direct_to(image, target))))
    return rows


def direct_to(image, target):
    low, data = image.text_bytes()
    found = []
    at = data.find(b"\xE8")
    while at >= 0:
        if at + 5 <= len(data) and low + at + 5 + struct.unpack_from("<i", data, at + 1)[0] == target:
            found.append(low + at)
        at = data.find(b"\xE8", at + 1)
    return found


def analyse(image, mutate=True, vectors=400):
    result = {}
    relative = image.relative()
    harnesses = [Harness(image, 0), Harness(image, 1)]
    named = list(NAMED)
    outcomes = []
    for harness in harnesses:
        outcomes.append(check_cases(harness, named))
        check_cases(harness, vector_cases(vectors))
    fde = [image.exact_fde(target) for target in TARGETS]
    rows = decode_range(image, *fde[0])
    amount_rows, amount_runs = refine_window(harnesses[0], AMOUNT_WINDOW, spec_amount_tail)
    px_rows, px_runs = refine_window(harnesses[0], PX_WINDOW, spec_px_tail)
    seen = set(harnesses[0].machine.seen)
    unreached = [row.va for row in rows if row.va not in seen and row.op not in ("int3", "nop")]
    result.update(fde=fde, rows=rows, named=named, outcomes=outcomes[0], vector_count=vectors * 2, amount=amount_rows, amount_runs=amount_runs, px=px_rows, px_runs=px_runs,
                  unreached=unreached, copy=copy_diff(image), constants=constant_rows(image), census=constant_census(image), appliers=bound_in(image, APPLIERS), factors=factor_rows(),
                  factor_census=factor_census(), even=even_share_rows(), reference=reference_rows(), slots=slot_rows(image, relative),
                  locations=location_rows(image, relative), wrappers=wrapper_rows(image))
    if outcomes[0] != outcomes[1]:
        raise EvidenceError("the copies differ on a named case")
    if mutate:
        result["mutations"] = run_mutants(image, rows, seen)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(outcome):
    kind, value, events, rows = outcome
    legs = [event for event in events if event[0] == "leg"]
    return (kind, "%#x" % value, len(legs), ",".join(str(event[6]) for event in legs), len(rows),
            ",".join(str(struct.unpack_from("<Q", row, 0x1F8)[0]) for row in rows),
            ",".join(str(struct.unpack_from("<Q", row, 0x208)[0]) for row in rows),
            ",".join(event[0] for event in events if event[0] in ("final", "grow")))


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("address", "size", "bytes", "operation"), [("%#x" % row.va, row.size, row.data.hex(), row.op) for row in result["rows"]])
    tsv("constants.tsv", ("address", "name", "bytes"), result["constants"])
    tsv("slots.tsv", ("slot", "role_in_harness", "relative_target"), result["slots"])
    tsv("locations.tsv", ("record", "path", "line", "column"), result["locations"])
    tsv("outcomes.tsv", ("case", "end", "value", "legs", "leg_costs", "rows", "row_px", "row_product", "other_events"),
        [(case.name,) + describe(outcome) for case, outcome in zip(result["named"], result["outcomes"])])
    tsv("amount-pieces.tsv", ("bits_lo", "bits_hi", "result_at_lo", "result_at_hi", "decisions"),
        [("%#x" % lo, "%#x" % hi, "%#x" % a, "%#x" % b, n) for lo, hi, a, b, n in result["amount"]])
    tsv("px-pieces.tsv", ("bits_lo", "bits_hi", "result_at_lo", "result_at_hi", "decisions"),
        [("%#x" % lo, "%#x" % hi, "%#x" % a, "%#x" % b, n) for lo, hi, a, b, n in result["px"]])
    tsv("factor.tsv", ("legs", "one_over_n", "factor", "against_one_over_n", "px_for_1e8", "px_with_plain_one_over_n", "px_times_n_minus_1e8"), result["factors"])
    tsv("even-share.tsv", ("legs", "exact_share", "amount", "share_real_rule"), result["even"])
    tsv("reference-compare.tsv", ("px", "quote", "product", "reference_rule", "bytes"), result["reference"])
    total, differ, calls = result["copy"]
    tsv("copy-diff.tsv", ("row_first", "row_second", "bytes_first", "bytes_second"), [("%#x" % a, "%#x" % b, c, d) for a, b, c, d in differ])
    tsv("copy-calls.tsv", ("kind", "row_first", "row_second", "target_first", "target_second"),
        [(k, "%#x" % a, "%#x" % b, "%#x" % c, "%#x" % d) for k, a, b, c, d in calls])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": ["%#x" % target for target in TARGETS],
        "fde": [["%#x" % low, "%#x" % high, high - low] for low, high in result["fde"]],
        "instructions": len(result["rows"]), "unreached_rows": ["%#x" % va for va in result["unreached"]],
        "wrappers": result["wrappers"], "bound_movabs": result["census"], "bound_in_row_appliers": result["appliers"], "copy_rows": total, "copy_rows_differing": len(differ),
        "named_cases": len(result["named"]), "vector_cases": result["vector_count"],
        "amount_pieces": len(result["amount"]), "amount_runs": result["amount_runs"], "px_pieces": len(result["px"]), "px_runs": result["px_runs"],
        "factor_census": result["factor_census"], "even_share_misses": len(result["even"]),
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
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
