#!/usr/bin/env python3
"""Pin node #94 L1 to EVM transfer fee: EIP-1559 next base fee, 1e8 floor, ceil divide by 1e10, cap.

The real instructions of 0x1359660, 0x342a1b0 and 0x37325d0 run on named and generated inputs against closed forms
kept apart from the evaluator, a path walker reads the same rows with symbolic inputs so the result covers every
input, and every reached conditional row, immediate and field offset is mutated. Sites come from .text bytes.
No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/l1_evm_transfer_fee.py --out <dir>
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
MUTANT_STEP_LIMIT = 20000


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
SHIFTS = {1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrdi", rm, ("r", reg), width, target=value)
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
        elif op in ("shld", "shrd", "shrdi"):
            bits = 8 * width
            count = (self.regs[RCX] if op == "shrd" else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op == "shld":
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
        elif op == "ror":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) if count else value)
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


BASE_FEE = 0x1359660
PRICE = 0x342A1B0
FEE = 0x37325D0
UDIVTI3 = 0x565F5A0
SLOT_BASE = 0x576E198
SLOT_PRICE = 0x5774A30
SLOT_FEE = 0x5774A38
SLOT_UDIV = 0x576E1A8
SLOT_DIV_ZERO = 0x576E1B8
SLOT_SUB = 0x576E150
SLOT_MUL = 0x576E1B0
SLOT_ADD = 0x576E118
PANIC_SLOTS = {SLOT_DIV_ZERO: "div_by_zero", SLOT_SUB: "sub_overflow", SLOT_MUL: "mul_overflow", SLOT_ADD: "add_overflow"}
PANIC_TARGETS = {SLOT_DIV_ZERO: 0x157B440, SLOT_SUB: 0x157B520, SLOT_MUL: 0x157B4A0, SLOT_ADD: 0x157B480}
LOCATIONS = (0x5663EE8, 0x5663F00, 0x5663F18, 0x5663F30, 0x5663F48, 0x5663F60, 0x5663F78, 0x5663F90)
CRATE = "alloy-eips-0.9.2/src/eip1559/helpers.rs"
ERROR_DROP = 0x3762510
TOP = MASK[8]
FLOOR = 100000000
DEFAULT_GAS = 200000
SCALE = 10000000000
CAP = 0x0CCCCCCCCCCCCCCB
TAG_FEE = 0x14D
TAG_QUEUE = 0x14C
TAG_OK = 0x186
DENOMINATOR = 8
ELASTICITY = 2
HEADER = HEAP_BASE + 0x400
OUT = HEAP_BASE + 0x200
USED = 0x1000
MARK_BASE = 0x7700000000
MARK_UDIV = MARK_BASE + 1
MARK_NEXT = MARK_BASE + 2
FILL = 0x5A5A5A5A5A5A5A5A
EXPECTED_BASE_SITES = 6
EXPECTED_FEE_SITES = 3


class Case:
    __slots__ = ("name", "args")

    def __init__(self, name, *args):
        self.name, self.args = name, args


def next_base_fee_model(used, limit, base, denominator, elasticity):
    """Closed form of 0x1359660; a panic is returned as (line, column) of its Location."""
    if elasticity == 0:
        return ("panic", 33, 22)
    target = limit // elasticity
    if used == target:
        return ("value", base)
    above = used > target
    delta = used - target if above else target - used
    divisor = target * denominator
    if divisor >> 128:
        return ("panic", 48, 27) if above else ("panic", 57, 23)
    if divisor == 0:
        return ("panic", 47, 21) if above else ("panic", 56, 17)
    quotient = delta * base // divisor
    if above:
        step = (quotient & TOP) if quotient >> 64 else max(1, quotient)
        if base + step > TOP:
            return ("panic", 43, 13)
        return ("value", base + step)
    return ("value", max(base - (quotient & TOP), 0))


def price_model(tag, next_fee):
    """Closed form of 0x342a1b0 for the two tags the callers can pass."""
    if tag == 1:
        return max(next_fee, FLOOR)
    return FLOOR


def fee_model(price, flag, gas):
    """Closed form of 0x37325d0: (status, value)."""
    units = gas if flag & 1 else DEFAULT_GAS
    value = -(-(units * price) // SCALE)
    if value > CAP:
        return (TAG_FEE, None)
    return (TAG_OK, value)


class Harness:
    def __init__(self, image, patches=None):
        self.machine = Machine(image, patches)
        self.image = image
        self.machine.memory.statics.update({SLOT_UDIV: UDIVTI3, SLOT_BASE: BASE_FEE})
        for slot, target in PANIC_TARGETS.items():
            self.machine.memory.statics[slot] = target
            self.machine.slots[target] = self.panic_hook(slot)
        self.machine.real = frozenset((UDIVTI3, BASE_FEE))
        self.machine.calls[ERROR_DROP] = self.error_drop
        self.relative = image.relative()
        self.drops = 0
        self.stub_log = []
        self.stub_value = None

    def panic_hook(self, slot):
        def hook(machine):
            line = self.panic_line(machine.regs[RDI])
            raise Panicked((PANIC_SLOTS[slot], line[0], line[1]))
        return hook

    def panic_line(self, slot):
        path, line, column = self.image.location(slot, self.relative)
        if not path.endswith(CRATE):
            raise Halt("panic outside the helper file")
        return line, column

    def error_drop(self, machine):
        if machine.regs[RDI] != machine.regs[RSP] + 8 or machine.memory.read(machine.regs[RDI], 2) != TAG_FEE:
            raise Halt("error word differs at the drop")
        self.drops += 1
        machine.regs[RAX] = POISON

    def next_stub(self, machine):
        machine.regs[RAX] = self.stub_value
        top = machine.regs[RSP]
        self.stub_log.append((machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX], machine.regs[R8], machine.memory.read(top + 0, 8), machine.memory.read(top + 8, 8)))

    def reset(self):
        self.machine.memory.reset(USED)
        self.drops = 0
        self.stub_log = []

    def run_base(self, used, limit, base, denominator, elasticity):
        self.reset()
        entry_top = STACK_TOP - 0x100
        self.machine.memory.write(entry_top, 8, elasticity)
        self.machine.memory.write(entry_top + 8, 8, 0x77777777)
        try:
            value = self.machine.run(BASE_FEE, {RDI: used, RSI: limit, RDX: base, RCX: denominator & TOP, R8: denominator >> 64})
        except Panicked as signal:
            return ("panic", signal.args[0][1], signal.args[0][2], signal.args[0][0])
        return ("value", value)

    def fill_header(self, tag, base, limit, used):
        memory = self.machine.memory
        for at in range(0, 0x240, 8):
            memory.write(HEADER + at, 8, FILL + at)
        memory.write(HEADER, 8, tag)
        memory.write(HEADER + 8, 8, base)
        memory.write(HEADER + 0x218, 8, limit)
        memory.write(HEADER + 0x220, 8, used)

    def run_price(self, tag, base, limit, used, stale, next_fee=None):
        self.reset()
        self.fill_header(tag, base, limit, used)
        statics = self.machine.memory.statics
        if next_fee is None:
            statics[SLOT_BASE] = BASE_FEE
        else:
            statics[SLOT_BASE] = MARK_NEXT
            self.machine.slots[MARK_NEXT] = self.next_stub
            self.stub_value = next_fee
        try:
            value = self.machine.run(PRICE, {RDI: HEADER, RAX: stale})
        except Panicked as signal:
            return ("panic", signal.args[0][1], signal.args[0][2], signal.args[0][0])
        finally:
            statics[SLOT_BASE] = BASE_FEE
        return ("value", value, tuple(self.stub_log))

    def run_fee(self, price, flag, gas):
        self.reset()
        memory = self.machine.memory
        memory.write(OUT, 8, FILL)
        memory.write(OUT + 8, 8, FILL)
        memory.write(OUT + 16, 8, FILL)
        value = self.machine.run(FEE, {RDI: OUT, RSI: price, RDX: 0x4444, RCX: 0xABCDEF00 | flag, R8: gas})
        if value != OUT:
            raise Halt("result pointer differs")
        status = memory.read(OUT, 2)
        if self.drops != 1 or memory.read(OUT + 16, 8) != FILL or memory.read(OUT + 2, 6) != FILL >> 16:
            raise Halt("fee frame differs")
        return (status, memory.read(OUT + 8, 8))


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & TOP
        yield state


def shaped(source):
    """Words with short, long and edge shapes, so every branch side is reached."""
    word = next(source)
    kind = word & 7
    body = next(source)
    if kind == 0:
        return body & 0xFF
    if kind == 1:
        return body & 0xFFFFFFFF
    if kind == 2:
        return TOP - (body & 0xFF)
    if kind == 3:
        return 1 << (body & 63)
    if kind == 4:
        return (1 << (body & 63)) - 1
    if kind == 5:
        return body >> 20
    return body


def base_cases(count):
    edge = [0, 1, 2, 7, 8, 9, 0xFFFFFFFF, 0x100000000, 0x100000001, 1 << 63, TOP - 1, TOP]
    cases = [
        Case("eq target", 15000000, 30000000, 100000000, 8, 2),
        Case("full block rises 1/8", 30000000, 30000000, 100000000, 8, 2),
        Case("empty block falls 1/8", 0, 30000000, 100000000, 8, 2),
        Case("one over, floor 1", 15000001, 30000000, 1000, 8, 2),
        Case("one under, quotient 0", 14999999, 30000000, 1000, 8, 2),
        Case("elasticity zero", 5, 6, 7, 8, 0),
        Case("limit one target zero above", 1, 1, 7, 8, 2),
        Case("limit zero used zero", 0, 0, 7, 8, 2),
        Case("denominator zero above", 9, 8, 7, 0, 2),
        Case("denominator zero below", 1, 8, 7, 0, 2),
        Case("denominator high above overflow", TOP, TOP, 7, TOP << 64, 2),
        Case("denominator high below overflow", 0, TOP, 7, TOP << 64, 2),
        Case("target times low carries above", TOP, TOP, 7, (1 << 66) + TOP, 2),
        Case("target times low carries below", 0, TOP, 7, (1 << 66) + TOP, 2),
        Case("high word only above", 9, 8, 7, 1 << 64, 2),
        Case("high word only below", 1, 8, 7, 1 << 64, 2),
        Case("add overflow", TOP, 2, TOP, 1, 2),
        Case("add to exact max", 2, 2, TOP - 1, 1, 2),
        Case("floor one then overflow", 1, 0x40000000, TOP, 8, 2),
        Case("quotient above 64 bits above", TOP, 2, TOP, 1, 2),
        Case("quotient above 64 bits step low", TOP, 4, 0x8000000000000000, 1, 4),
        Case("quotient high word set low word zero above", TOP, 1 << 32, 1 << 62, 1 << 32, 1 << 32),
        Case("saturates to zero", 0, 30000000, 7, 1, 2),
        Case("quotient above 64 bits below", 0, TOP, TOP, 1, 2),
        Case("thirty two bit path", 3, 40, 5, 8, 2),
        Case("sixty four bit limit small e", 3, 1 << 32, 5, 8, 2),
        Case("sixty four bit e", 3, 40, 5, 8, 1 << 32),
        Case("elasticity one", 41, 40, 9000, 8, 1),
        Case("elasticity three", 41, 40, 9000, 8, 3),
    ]
    for used in (0, 1, 7, 8, 9, 0xFFFFFFFF, TOP):
        for limit in (0, 1, 2, 16, 18, 0x100000000, TOP):
            cases.append(Case("grid", used, limit, 100000000, 8, 2))
    source = lcg(0x1559)
    for _ in range(count):
        high = shaped(source) if next(source) & 15 == 0 else 0
        low = shaped(source)
        elasticity = shaped(source) if next(source) & 7 == 0 else 1 + (next(source) & 3)
        cases.append(Case("vector", shaped(source), shaped(source), shaped(source), high << 64 | low, elasticity))
    for value in edge:
        cases.append(Case("edge", value, value, value, value, 2))
    return cases


def price_cases(count):
    cases = [Case("absent base fee", 0, 5, 30000000, 15000000, 0x1234, None), Case("floor below", 1, 7, 30000000, 15000000, 0x1234, None), Case("exact floor", 1, FLOOR, 30000000, 15000000, 0x1234, None),
             Case("floor plus one", 1, FLOOR + 1, 30000000, 15000000, 0x1234, None), Case("full block above floor", 1, FLOOR, 30000000, 30000000, 0x1234, None), Case("empty block floors", 1, FLOOR, 30000000, 0, 0x1234, None),
             Case("stale above floor tag 0", 0, 5, 30000000, 0, FLOOR + 5, None), Case("stub at floor", 1, 1, 2, 3, 0x1234, FLOOR), Case("stub above floor", 1, 1, 2, 3, 0x1234, FLOOR + 1), Case("stub below", 1, 1, 2, 3, 0x1234, FLOOR - 1),
             Case("stub zero", 1, 11, 22, 33, 0x1234, 0), Case("stub top", 1, 11, 22, 33, 0x1234, TOP), Case("tag high bits 0x100 keep floor", 0x100, 1, 2, 3, 0x1234, 7), Case("tag 3 outside the enum", 3, 1, 2, 3, FLOOR + 9, None)]
    source = lcg(0x342A)
    for _ in range(count):
        cases.append(Case("vector", next(source) & 1, shaped(source), shaped(source), shaped(source), shaped(source), shaped(source) if next(source) & 1 else None))
    return cases


def fee_cases(count):
    cases = [Case("default gas at floor", FLOOR, 0, 12345), Case("set flag uses gas", FLOOR, 1, 12345), Case("exact divide", SCALE, 1, 7), Case("one above exact", SCALE + 1, 1, 7), Case("one below exact", SCALE - 1, 1, 7),
             Case("zero price", 0, 1, TOP), Case("zero gas", TOP, 1, 0), Case("tiny rounds to 1", 1, 1, 1), Case("at cap", CAP * SCALE, 1, 1) if CAP * SCALE <= TOP else Case("at cap", 1 << 62, 1, 2000000000),
             Case("value exactly at the cap", CAP, 1, SCALE), Case("value one past the cap", CAP + 1, 1, SCALE), Case("max product", TOP, 1, TOP), Case("default gas top price", TOP, 0, 0), Case("flag bit 0 only", FLOOR, 2, 12345)]
    bound = CAP * SCALE
    high = bound >> 64
    # Words whose product sits on both sides of the cap edge.
    for delta in (0, 1, SCALE - 1, SCALE, SCALE + 1):
        for target in (bound - delta, bound + delta):
            first = 0x40000000000
            second = target // first
            cases.append(Case("cap edge", second, 1, first))
            cases.append(Case("cap edge plus", second + 1, 1, first))
    # A product with a high quotient word above zero and a low quotient word below the cap.
    cases.append(Case("high quotient word", 1 << 42, 1, 1 << 63))
    cases.append(Case("quotient low word small", (1 << 54) * 5 ** 10 // (1 << 32) * 1, 1, 1 << 42))
    factor = (1 << 64) * SCALE // (1 << 63)
    cases.append(Case("quotient exactly 2^64", factor, 1, 1 << 63))
    cases.append(Case("quotient 2^64 plus remainder", factor + 1, 1, 1 << 63))
    source = lcg(0x14D)
    for _ in range(count):
        cases.append(Case("vector", shaped(source), next(source) & 3, shaped(source)))
    return cases


def same_base(got, want):
    return got[:3] == want[:3] if want[0] == "panic" else got == want


def check_base(harness, cases):
    counts = collections.Counter()
    for case in cases:
        got = harness.run_base(*case.args)
        want = next_base_fee_model(*case.args)
        if not same_base(got, want):
            raise EvidenceError("%s: got %s want %s" % (case.name, got, want))
        counts["panic %d:%d" % want[1:] if want[0] == "panic" else "value"] += 1
    return counts


def expected_price(case):
    tag, base, limit, used, stale, stub = case.args
    if tag == 1:
        if stub is None:
            outcome = next_base_fee_model(used, limit, base, DENOMINATOR, ELASTICITY)
            if outcome[0] == "panic":
                return outcome
            return ("value", price_model(1, outcome[1]), ())
        return ("value", price_model(1, stub), ((used, limit, base, DENOMINATOR, 0, ELASTICITY, 0),))
    if tag & 0xFF == 0:
        return ("value", FLOOR, ())
    return ("value", max(stale, FLOOR), ())


def check_price(harness, cases):
    counts = collections.Counter()
    for case in cases:
        got = harness.run_price(*case.args)
        want = expected_price(case)
        if not same_base(got, want):
            raise EvidenceError("%s: got %s want %s" % (case.name, got, want))
        counts[want[0]] += 1
    return counts


def check_fee(harness, cases):
    counts = collections.Counter()
    for case in cases:
        status, word = harness.run_fee(*case.args)
        want, value = fee_model(*case.args)
        if status != want or (want == TAG_OK and word != value) or (want != TAG_OK and word != FILL):
            raise EvidenceError("%s: got %s want %s" % (case.name, (status, word), (want, value)))
        counts[want] += 1
    return counts


class Unsupported(Exception):
    pass


class Fork(Exception):
    def __init__(self, key, options):
        self.key, self.options = key, options


def show(value):
    if isinstance(value, int):
        return hex(value) if value > 9 else str(value)
    if value is None:
        return "poison"
    head = value[0]
    if head == "a":
        return value[1]
    return "%s(%s)" % (head, ",".join(show(item) for item in value[1:]))


def ev(value, env):
    """Exact integer value of a symbolic word under named inputs."""
    if isinstance(value, int):
        return value
    head = value[0]
    if head == "a":
        return env[value[1]]
    args = [ev(item, env) for item in value[1:]]
    if head == "lo":
        return args[0] & TOP
    if head == "hi":
        return args[0] >> 64
    if head == "mul":
        return args[0] * args[1]
    if head == "add":
        return args[0] + args[1]
    if head == "sub":
        return args[0] - args[1]
    if head == "or":
        return args[0] | args[1]
    if head == "shr32":
        return args[0] >> 32
    if head == "fdiv":
        return args[0] // args[1]
    if head == "pair":
        return args[0] << 64 | args[1]
    if head == "udiv":
        return args[0] // args[1]
    if head == "ne0":
        return int(args[0] != 0)
    if head == "rem":
        return args[0] % args[1]
    if head == "bit0":
        return args[0] & 1
    if head == "low8":
        return args[0] & 0xFF
    if head == "ceil":
        return args[0] + args[1]
    raise Unsupported(head)


class Path:
    def __init__(self):
        self.regs = {}
        self.mem = {}
        self.fields = {}
        self.writes = {}
        self.facts = {}
        self.cf = self.zf = None
        self.of = None
        self.pc = None
        self.steps = 0

    def clone(self):
        other = Path.__new__(Path)
        other.__dict__.update(self.__dict__)
        other.regs, other.mem, other.writes, other.facts = dict(self.regs), dict(self.mem), dict(self.writes), dict(self.facts)
        return other


def compare(path, left, right):
    """Three way order of two words: -1, 0 or 1, forking when no fact settles it."""
    if isinstance(left, tuple) and left[0] == "low8":
        known = known_word(path, left[1])
        if known is not None:
            left = known & 0xFF
    if isinstance(left, int) and isinstance(right, int):
        return (left > right) - (left < right)
    if left == right:
        return 0
    if ("cmp", left, right) in path.facts:
        return path.facts[("cmp", left, right)]
    if ("cmp", right, left) in path.facts:
        return -path.facts[("cmp", right, left)]
    if right == 0:
        raise Fork(("cmp", left, right), (0, 1))
    if left == 0:
        raise Fork(("cmp", left, right), (0, -1))
    raise Fork(("cmp", left, right), (-1, 0, 1))


def known_word(path, value):
    """The constant a word equals under the path facts, if any."""
    for key, order in path.facts.items():
        if key[0] == "cmp" and key[1] == value and isinstance(key[2], int):
            if order == 0:
                return key[2]
            if order < 0 and key[2] == 1:
                return 0
    return None


def carry(path, key):
    if key not in path.facts:
        raise Fork(key, (False, True))
    return path.facts[key]


def flag_cf(path):
    value = path.cf
    if isinstance(value, bool):
        return value
    if value[0] == "lt":
        return compare(path, value[1], value[2]) < 0
    if value[0] == "carry":
        return carry(path, value)
    if value[0] == "nonzero":
        return compare(path, value[1], 0) != 0
    raise Unsupported("cf")


def flag_zf(path):
    value = path.zf
    if isinstance(value, bool):
        return value
    if value[0] == "eq":
        return compare(path, value[1], value[2]) == 0
    if value[0] == "zero":
        return compare(path, value[1], 0) == 0
    raise Unsupported("zf")


def flag_of(path):
    return compare(path, path.of, 0) != 0


def condition(path, code):
    base = code >> 1
    if base == 0:
        result = flag_of(path)
    elif base == 1:
        result = flag_cf(path)
    elif base == 2:
        result = flag_zf(path)
    elif base == 3:
        result = flag_cf(path) or flag_zf(path)
    else:
        raise Unsupported("condition %d" % code)
    return result != bool(code & 1)


def read_operand(path, operand, width):
    kind = operand[0]
    if kind == "i":
        return operand[1] & MASK[width]
    if kind == "r":
        value = path.regs.get(operand[1])
    else:
        value = read_memory(path, operand, width)
    if value is None:
        raise Unsupported("poison read")
    if width == 8 or isinstance(value, int):
        return value & MASK[width] if isinstance(value, int) else value
    if width == 4:
        return narrow(path, value)
    if width == 1:
        return ("low8", value)
    raise Unsupported("narrow read")


def narrow(path, value):
    """A 32 bit read keeps a symbolic word only under a fact that it fits."""
    for key, known in path.facts.items():
        if known == 0 and key[0] == "cmp" and key[2] == 0 and isinstance(key[1], tuple) and key[1][0] == "shr32":
            pair = key[1][1][1:]
            if value in pair or (isinstance(value, tuple) and value[0] == "fdiv" and value[1] in pair):
                return value
    raise Unsupported("32 bit read of a wide word")


def effective(path, operand):
    _, base, index, scale, disp, rip = operand
    if rip or base is None:
        return disp
    if index is not None:
        raise Unsupported("index")
    root = path.regs.get(base)
    if isinstance(root, int):
        return root + disp
    if root is None:
        raise Unsupported("poison base")
    return (root, disp)


def read_memory(path, operand, width):
    place = effective(path, operand)
    if isinstance(place, tuple):
        key = (place[0], place[1])
        if key in path.fields:
            return path.fields[key]
        raise Unsupported("field read")
    return path.mem.get(place)


def write_operand(path, operand, width, value):
    if operand[0] == "r":
        if width == 8 or (width == 4):
            path.regs[operand[1]] = value
        else:
            path.regs[operand[1]] = value if isinstance(value, int) else None
        return
    place = effective(path, operand)
    if isinstance(place, tuple):
        path.writes[(show(place[0]), place[1], width)] = value
    else:
        path.mem[place] = value


def do_call(path, row, slot):
    regs = path.regs
    if slot in PANIC_SLOTS:
        return ("panic", PANIC_SLOTS[slot], regs.get(RDI))
    if slot == SLOT_UDIV:
        low, high, dlow, dhigh = regs.get(RDI), regs.get(RSI), regs.get(RDX), regs.get(RCX)
        if not (isinstance(low, tuple) and low[0] == "lo" and high == ("hi", low[1])):
            raise Unsupported("dividend pair")
        if dhigh == 0:
            divisor = dlow
            if compare(path, divisor, 0) == 0:
                raise Unsupported("zero divisor reaches the divide")
        else:
            divisor = ("pair", dhigh, dlow)
            if path.facts.get(("cmp", ("or", dlow, dhigh), 0)) != 1:
                raise Unsupported("divisor not tested")
        quotient = ("udiv", low[1], divisor)
        clobber(path)
        regs[RAX] = ("lo", quotient)
        regs[RDX] = ("hi", quotient)
        return None
    if slot == SLOT_BASE:
        args = (regs.get(RDI), regs.get(RSI), regs.get(RDX), regs.get(RCX), regs.get(R8), path.mem.get(regs[RSP]), path.mem.get(regs[RSP] + 8))
        if args != (("a", "used"), ("a", "limit"), ("a", "base"), DENOMINATOR, 0, ELASTICITY, 0):
            raise Unsupported("next base fee arguments")
        clobber(path)
        regs[RAX] = ("a", "next")
        return None
    raise Unsupported("indirect call %#x" % slot)


def clobber(path):
    for reg in VOLATILE + (RAX, RDX):
        path.regs[reg] = None


def do_step(path, row):
    op, width = row.op, row.width
    regs = path.regs
    if op == "mov":
        if width < 4 and row.a[0] == "r":
            regs[row.a[1]] = row.b[1] if row.b[0] == "i" else None
        else:
            value = read_operand(path, row.b, width)
            write_operand(path, row.a, width, value)
    elif op == "lea":
        place = effective(path, row.b)
        if isinstance(place, tuple):
            raise Unsupported("symbolic lea")
        regs[row.a[1]] = place
    elif op == "push":
        regs[RSP] -= 8
        path.mem[regs[RSP]] = regs.get(row.a[1])
    elif op == "pushi":
        regs[RSP] -= 8
        path.mem[regs[RSP]] = row.a[1] & TOP
    elif op == "pop":
        regs[row.a[1]] = path.mem[regs[RSP]]
        regs[RSP] += 8
    elif op == "jcc":
        return row.target if condition(path, row.cc) else row.next
    elif op == "jmp":
        return row.target
    elif op == "ret":
        return "ret"
    elif op == "set":
        regs[row.a[1]] = ("ne0", path.zf[1]) if row.cc == 5 and isinstance(path.zf, tuple) and path.zf[0] == "zero" and isinstance(path.zf[1], tuple) and path.zf[1][0] == "rem" else int(condition(path, row.cc))
    elif op == "cmov":
        if condition(path, row.cc):
            regs[row.a[1]] = regs.get(row.b[1])
    elif op == "movzx":
        value = regs.get(row.b[1]) if row.b[0] == "r" else None
        if not isinstance(value, int):
            raise Unsupported("movzx")
        regs[row.a[1]] = value & 0xFF
    elif op == "xor":
        if row.a == row.b:
            regs[row.a[1]] = 0
            path.cf, path.zf = False, True
        else:
            raise Unsupported("xor")
    elif op == "test":
        left, right = read_operand(path, row.a, width), read_operand(path, row.b, width)
        if left == right:
            path.zf = ("zero", left)
        elif right == 1 and width == 1:
            path.zf = ("zero", ("bit0", left[1] if isinstance(left, tuple) and left[0] == "low8" else left))
        else:
            raise Unsupported("test")
        path.cf = False
    elif op == "or":
        left, right = read_operand(path, row.a, width), read_operand(path, row.b, width)
        if isinstance(left, int) and isinstance(right, int):
            result = left | right
        elif isinstance(left, tuple) and left[0] == "remhi" and right == ("remlo",) + left[1:]:
            result = ("rem",) + left[1:]
        elif isinstance(right, tuple) and right[0] == "remhi" and left == ("remlo",) + right[1:]:
            result = ("rem",) + right[1:]
        else:
            result = ("or", left, right)
        write_operand(path, row.a, width, result)
        path.cf, path.zf = False, (result == 0 if isinstance(result, int) else ("zero", result))
    elif op == "shr":
        value = regs.get(row.a[1])
        count = row.b[1]
        if isinstance(value, int):
            result = value >> count
        elif count == 32 and value[0] == "or":
            result = ("shr32", value)
        else:
            raise Unsupported("shr")
        regs[row.a[1]] = result
        path.zf = result == 0 if isinstance(result, int) else ("zero", result)
    elif op == "cmp":
        left, right = read_operand(path, row.a, width), read_operand(path, row.b, width)
        path.cf, path.zf = ("lt", left, right), ("eq", left, right)
    elif op == "add":
        step_add(path, row)
    elif op == "adc":
        step_adc(path, row)
    elif op == "sub":
        step_sub(path, row)
    elif op == "sbb":
        step_sbb(path, row)
    elif op == "mul":
        left, right = regs.get(RAX), read_operand(path, row.a, 8)
        if left is None:
            raise Unsupported("mul poison")
        product = ("mul", left, right)
        regs[RAX], regs[RDX] = ("lo", product), ("hi", product)
        path.of = ("hi", product)
        path.cf = ("nonzero", ("hi", product))
    elif op == "imul2":
        left, right = read_operand(path, row.a, 8), read_operand(path, row.b, 8)
        regs[row.a[1]] = ("lo", ("mul", left, right))
    elif op == "div":
        divisor = read_operand(path, row.a, width)
        dividend = regs.get(RAX)
        if regs.get(RDX) != 0 or compare(path, divisor, 0) <= 0:
            raise Unsupported("div")
        regs[RAX], regs[RDX] = ("fdiv", dividend, divisor), None
    elif op == "nop":
        pass
    elif op == "call":
        if row.target != ERROR_DROP or path.mem.get(regs[RDI]) != TAG_FEE or regs[RDI] != regs[RSP]:
            raise Unsupported("direct call")
        clobber(path)
    else:
        raise Unsupported(op)
    return row.next


def step_add(path, row):
    width = row.width
    left, right = read_operand(path, row.a, width), read_operand(path, row.b, width)
    if isinstance(left, int) and isinstance(right, int):
        total = left + right
        write_operand(path, row.a, width, total & MASK[width])
        path.cf, path.zf = total > MASK[width], total & MASK[width] == 0
        return
    # The low half of ceil: quotient word plus the remainder bit, carried by an adc on the high half.
    if isinstance(left, tuple) and left[0] == "ne0" and isinstance(right, tuple) and right[0] == "lo":
        left, right = right, left
    if isinstance(left, tuple) and left[0] == "lo" and isinstance(right, tuple) and right[0] == "ne0":
        sum_word = ("ceil", left[1], right)
        write_operand(path, row.a, width, ("lo", sum_word))
        path.cf = ("ceilcarry", left[1], sum_word)
        return
    write_operand(path, row.a, width, ("add", left, right))
    path.cf = ("carry", left, right)
    path.zf = None


def step_adc(path, row):
    if row.b != ("i", 0) and row.b[1] != 0:
        raise Unsupported("adc")
    value = read_operand(path, row.a, row.width)
    if isinstance(path.cf, tuple) and path.cf[0] == "ceilcarry" and value == ("hi", path.cf[1]):
        write_operand(path, row.a, row.width, ("hi", path.cf[2]))
        path.cf = False
        return
    if isinstance(value, int):
        write_operand(path, row.a, row.width, (value + int(flag_cf(path))) & MASK[row.width])
        return
    if flag_cf(path):
        write_operand(path, row.a, row.width, ("add", value, 1))
        path.cf = ("carry", value, 1)
    else:
        path.cf = False


def step_sub(path, row):
    width = row.width
    left, right = read_operand(path, row.a, width), read_operand(path, row.b, width)
    if isinstance(left, int) and isinstance(right, int):
        write_operand(path, row.a, width, (left - right) & MASK[width])
        path.cf, path.zf = left < right, left == right
        return
    # Second half of `P - Q * k`: left = lo(P), right = lo(lo(Q) * k).
    if isinstance(right, tuple) and right[0] == "lo" and isinstance(right[1], tuple) and right[1][0] == "mul" and isinstance(right[1][1], tuple) and right[1][1][0] == "lo" and isinstance(left, tuple) and left[0] == "lo":
        quotient = right[1][1][1]
        factor = right[1][2]
        if quotient == ("udiv", left[1], factor):
            write_operand(path, row.a, width, ("remlo", left[1], factor))
            path.cf = ("remborrow", left[1], factor, quotient)
            return
    order = compare(path, left, right)
    if order < 0:
        write_operand(path, row.a, width, None)
        path.cf, path.zf = True, False
    else:
        write_operand(path, row.a, width, 0 if order == 0 else ("sub", left, right))
        path.cf, path.zf = False, order == 0


def step_sbb(path, row):
    width = row.width
    left, right = read_operand(path, row.a, width), read_operand(path, row.b, width)
    if isinstance(path.cf, tuple) and path.cf[0] == "remborrow":
        _, dividend, factor, quotient = path.cf
        wanted = ("add", ("hi", ("mul", ("lo", quotient), factor)), ("lo", ("mul", ("hi", quotient), factor)))
        if left != ("hi", dividend) or right not in (wanted, ("add", wanted[2], wanted[1])):
            raise Unsupported("sbb shape")
        write_operand(path, row.a, width, ("remhi", dividend, factor))
        path.cf = False
        return
    borrow = flag_cf(path)
    if isinstance(left, int) and isinstance(right, int):
        write_operand(path, row.a, width, (left - right - borrow) & MASK[width])
        path.cf, path.zf = left < right + borrow, (left - right - borrow) & MASK[width] == 0
        return
    if left == 0 and row.a[0] == "r":
        order = compare(path, right, 0)
        write_operand(path, row.a, width, None)
        path.cf = bool(borrow or order > 0)
        return
    raise Unsupported("sbb")


def seed_base():
    path = Path()
    rsp = STACK_TOP - 0x108
    path.regs = {RSP: rsp, RDI: ("a", "used"), RSI: ("a", "limit"), RDX: ("a", "base"), RCX: ("a", "dlow"), R8: ("a", "dhigh"), RBX: ("a", "rbx")}
    path.mem = {rsp + 8: ("a", "e")}
    return path


def seed_price():
    path = Path()
    rsp = STACK_TOP - 0x108
    root = ("a", "header")
    path.regs = {RSP: rsp, RDI: root, RAX: ("a", "stale"), RBX: ("a", "rbx")}
    path.fields = {(root, 0): ("a", "tag"), (root, 8): ("a", "base"), (root, 0x218): ("a", "limit"), (root, 0x220): ("a", "used")}
    return path


def seed_fee():
    path = Path()
    rsp = STACK_TOP - 0x108
    path.regs = {RSP: rsp, RDI: ("a", "out"), RSI: ("a", "price"), RDX: ("a", "unused"), RCX: ("a", "flag"), R8: ("a", "gas")}
    for reg in (RBX, RBP, R12, R13, R14, R15):
        path.regs[reg] = ("a", "saved%d" % reg)
    return path


def rows_of(image, start, end, patches=None):
    if not patches:
        return {row.va: row for row in decode_range(image, start, end)}
    base = image.offset(start)
    code = bytearray(image.blob[base:base + (end - start) + 16])
    for va, value in patches.items():
        code[va - start] = value

    def read(va, count):
        return code[va - start:va - start + count]

    rows = {}
    va = start
    while va < end:
        row = decode(read, va)
        row.data = bytes(read(va, row.size))
        rows[va] = row
        va = row.next
    return rows


def walk(rows, seed, entry, limit=4000):
    """Every feasible path of the bytes over all inputs; each leaf is (facts, result)."""
    leaves = []
    seed.pc = entry
    work = [seed]
    forks = 0
    while work:
        path = work.pop()
        while True:
            path.steps += 1
            if path.steps > 2000:
                raise Unsupported("path too long")
            row = rows.get(path.pc)
            if row is None:
                raise Unsupported("left the function at %#x" % path.pc)
            try:
                if row.op == "calli":
                    slot = row.rip_at if row.rip_at is not None else row.a[4]
                    slot = row.a[4] if row.a[0] == "m" else slot
                    outcome = do_call(path, row, slot)
                    if outcome is not None:
                        leaves.append((path.facts, outcome, dict(path.writes), path))
                        break
                    path.pc = row.next
                    continue
                step = do_step(path, row)
            except Fork as fork:
                forks += 1
                if forks > limit:
                    raise Unsupported("fork budget")
                for option in fork.options:
                    other = path.clone()
                    other.facts[fork.key] = option
                    work.append(other)
                break
            if step == "ret":
                leaves.append((path.facts, ("ret", path.regs.get(RAX)), dict(path.writes), path))
                break
            path.pc = step
    return leaves


ABBREVIATIONS = (
    ("fdiv(limit,e)", "T"),
    ("pair(add(hi(mul(T,dlow)),lo(mul(dhigh,T))),lo(mul(T,dlow)))", "D"),
    ("or(lo(mul(T,dlow)),add(hi(mul(T,dlow)),lo(mul(dhigh,T))))", "D_or"),
    ("udiv(mul(sub(used,T),base),D)", "Q_up"),
    ("udiv(mul(sub(T,used),base),D)", "Q_down"),
    ("ceil(udiv(mul(gas,price),0x2540be400),ne0(rem(mul(gas,price),0x2540be400)))", "C_gas"),
    ("ceil(udiv(mul(0x30d40,price),0x2540be400),ne0(rem(mul(0x30d40,price),0x2540be400)))", "C_default"),
)
EXPECTED_RESULTS = {
    "next_base_fee": {"return base", "return add(base,lo(Q_up))", "return add(base,add(lo(Q_up),1))", "return sub(base,lo(Q_down))", "return 0", "panic div_by_zero 33:22", "panic div_by_zero 47:21", "panic div_by_zero 56:17",
                      "panic mul_overflow 48:27", "panic mul_overflow 57:23", "panic add_overflow 43:13"},
    "price": {"return 0x5f5e100", "return next", "return stale"},
    "fee": {"return out [out+0:2]=0x14d", "return out [out+0:2]=0x186 [out+8:8]=lo(C_gas)", "return out [out+0:2]=0x186 [out+8:8]=lo(C_default)"},
}


def abbreviate(text):
    for long, short in ABBREVIATIONS:
        text = text.replace(long, short)
    return text


def options_of(key):
    if key[0] == "carry":
        return frozenset((False, True))
    if key[2] == 0:
        return frozenset((0, 1))
    if key[1] == 0:
        return frozenset((0, -1))
    return frozenset((-1, 0, 1))


def result_text(image, relative, leaf):
    outcome, writes = leaf[1], leaf[2]
    if outcome[0] == "panic":
        path, line, column = image.location(outcome[2], relative)
        if not path.endswith(CRATE):
            raise EvidenceError("panic Location outside the helper file")
        return "panic %s %d:%d" % (outcome[1], line, column)
    text = "return " + show(outcome[1])
    for key in sorted(writes):
        text += " [%s+%d:%d]=%s" % (key[0], key[1], key[2], show(writes[key]))
    return text


def merged(image, leaves):
    """Join leaves that differ in one fact, so a split with no effect leaves no row."""
    relative = image.relative()
    unique = {}
    for leaf in leaves:
        facts = {key: frozenset((value,)) for key, value in leaf[0].items() if not (key[0] == "cmp" and isinstance(key[1], tuple) and key[1][0] == "shr32")}
        text = result_text(image, relative, leaf)
        unique.setdefault((frozenset(facts.items()), text), (facts, text, leaf))
    rows = list(unique.values())
    changed = True
    while changed:
        changed = False
        for one in range(len(rows)):
            for two in range(one + 1, len(rows)):
                left, right = rows[one], rows[two]
                if left[1] != right[1] or set(left[0]) != set(right[0]):
                    continue
                differ = [key for key in left[0] if left[0][key] != right[0][key]]
                if len(differ) > 1:
                    continue
                facts = dict(left[0])
                if differ:
                    key = differ[0]
                    facts[key] = left[0][key] | right[0][key]
                    if facts[key] == options_of(key):
                        del facts[key]
                rows[one] = (facts, left[1], left[2])
                del rows[two]
                changed = True
                break
            if changed:
                break
    return rows


def fact_text(key, values):
    if key[0] == "carry":
        return "%s + %s %s" % (show(key[1]), show(key[2]), "carries" if True in values and len(values) == 1 else "fits")
    words = {-1: "<", 0: "==", 1: ">"}
    if len(values) == 2:
        word = {frozenset((-1, 0)): "<=", frozenset((0, 1)): ">=", frozenset((-1, 1)): "!="}[values]
    else:
        word = words[next(iter(values))]
    return "%s %s %s" % (show(key[1]), word, show(key[2]))


def leaf_lines(rows):
    return sorted((abbreviate(" & ".join(sorted(fact_text(key, facts[key]) for key in facts))) or "always", abbreviate(result)) for facts, result, _ in rows)


def holds(facts, env):
    for key, values in facts.items():
        try:
            if key[0] == "carry":
                actual = ev(key[1], env) + ev(key[2], env) > TOP
            else:
                left, right = ev(key[1], env), ev(key[2], env)
                actual = (left > right) - (left < right)
        except ZeroDivisionError:
            return False
        if actual not in values:
            return False
    return True


def match_one(rows, env):
    hits = [row for row in rows if holds(row[0], env)]
    if len(hits) != 1:
        raise EvidenceError("%d leaves match one input" % len(hits))
    return hits[0]


def base_env(case):
    used, limit, base, denominator, elasticity = case.args
    return dict(used=used, limit=limit, base=base, dlow=denominator & TOP, dhigh=denominator >> 64, e=elasticity)


def check_base_leaves(rows, cases):
    hit = set()
    for case in cases:
        row = match_one(rows, base_env(case))
        hit.add(row[1])
        want = next_base_fee_model(*case.args)
        leaf = row[2]
        if leaf[1][0] == "panic":
            if want[0] != "panic" or row[1].rsplit(" ", 1)[1] != "%d:%d" % want[1:]:
                raise EvidenceError("%s: leaf %s model %s" % (case.name, row[1], want))
        elif want != ("value", ev(leaf[1][1], base_env(case))):
            raise EvidenceError("%s: leaf %s model %s" % (case.name, row[1], want))
    return hit


def check_fee_leaves(rows, cases):
    hit = set()
    for case in cases:
        price, flag, gas = case.args
        row = match_one(rows, dict(price=price, flag=flag, gas=gas))
        hit.add(row[1])
        status, value = fee_model(*case.args)
        writes = row[2][2]
        if writes[("out", 0, 2)] != status:
            raise EvidenceError("%s: status differs" % case.name)
        if status == TAG_OK and ev(writes[("out", 8, 8)], dict(price=price, flag=flag, gas=gas)) != value:
            raise EvidenceError("%s: value differs" % case.name)
    return hit


def check_price_leaves(rows, cases):
    hit = set()
    for case in cases:
        tag, base, limit, used, stale, stub = case.args
        step = stub
        if stub is None:
            outcome = next_base_fee_model(used, limit, base, DENOMINATOR, ELASTICITY)
            if tag != 1 or outcome[0] == "panic":
                step = 0
            else:
                step = outcome[1]
        env = dict(tag=tag, base=base, limit=limit, used=used, stale=stale, next=step)
        row = match_one(rows, env)
        hit.add(row[1])
        if tag in (0, 1) and ev(row[2][1][1], env) != price_model(tag, step):
            raise EvidenceError("%s: price differs" % case.name)
    return hit


SEEDS = {"next_base_fee": (BASE_FEE, seed_base), "price": (PRICE, seed_price), "fee": (FEE, seed_fee)}


def walked(image, name, patches=None):
    start, seed = SEEDS[name]
    end = image.exact_fde(start)[1]
    rows = rows_of(image, start, end, patches)
    leaves = walk(rows, seed(), start)
    return rows, merged(image, leaves), {leaf[3].pc for leaf in leaves}


def walk_table(image):
    tables = {}
    for name in SEEDS:
        rows, table, _ = walked(image, name)
        results = {abbreviate(row[1]) for row in table}
        if results != EXPECTED_RESULTS[name]:
            raise EvidenceError("%s: leaf results differ: %s" % (name, sorted(results ^ EXPECTED_RESULTS[name])))
        tables[name] = (len(rows), table)
    return tables


def edits_for(image, rows, seen):
    edits = []
    for row in rows:
        if row.va not in seen:
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


FAILURES = (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError, OverflowError, struct.error, ZeroDivisionError)
CHECKS = {"next_base_fee": check_base, "price": check_price, "fee": check_fee}
EXPECTED_SURVIVORS = {(0x1359713, "immediate"): "equivalent: the two cmov rows after it always replace rdx, the value 1 is never read"}


def first_failure(check, harness, cases):
    for case in cases:
        try:
            check(harness, [case])
        except FAILURES:
            return case
    return None


def run_mutants(image, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    for name, (start, _) in SEEDS.items():
        if first_failure(CHECKS[name], control, cases[name]) is not None:
            raise EvidenceError("an unedited image fails under the mutant step limit")
    baseline = {name: leaf_lines(walked(image, name)[1]) for name in SEEDS}
    for name, (start, _) in SEEDS.items():
        end = image.exact_fde(start)[1]
        for va, kind, patch in edits_for(image, decode_range(image, start, end), seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            hit = first_failure(CHECKS[name], harness, cases[name])
            if hit is not None:
                results.append((name, va, kind, "killed", hit.name))
                continue
            try:
                table = leaf_lines(walked(image, name, patch)[1])
            except (Unsupported, KeyError, IndexError, TypeError, ValueError, EvidenceError):
                table = None
            if table != baseline[name]:
                results.append((name, va, kind, "killed", "path walker"))
            else:
                results.append((name, va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def call_sites(image):
    """Every `call *slot(%rip)` of the three slots, from .text bytes."""
    base, text = image.text_bytes()
    sites = {SLOT_BASE: [], SLOT_PRICE: [], SLOT_FEE: []}
    for match in re.finditer(rb"\xff\x15", text):
        at = match.start()
        slot = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if slot in sites:
            sites[slot].append(base + at)
    return sites


def base_site_rows(image, sites):
    rows = []
    for site in sites[SLOT_BASE]:
        before = bytes(image.blob[image.offset(site - 12):image.offset(site)])
        after = bytes(image.blob[image.offset(site + 6):image.offset(site + 40)])
        fixed = before == bytes.fromhex("b9080000004531c06a006a02")
        floor = struct.pack("<I", FLOOR + 1) in after
        rows.append((site, "8, 2" if fixed else "read at run time", "yes" if floor else "no"))
    return rows


def fee_site_rows(image, sites):
    rows = []
    if len(sites[SLOT_FEE]) != EXPECTED_FEE_SITES or len(sites[SLOT_PRICE]) != EXPECTED_FEE_SITES:
        raise EvidenceError("fee site count differs")
    for price_site, fee_site in zip(sites[SLOT_PRICE], sites[SLOT_FEE]):
        if not 0 < fee_site - price_site < 0x40 or image.fde(price_site) != image.fde(fee_site):
            raise EvidenceError("price and fee sites are not one pair")
        window = bytes(image.blob[image.offset(fee_site - 0x60):image.offset(fee_site)])
        queue = re.search(rb"\x66\xb8\x4c\x01.{0,8}\x48\x83\xb9(....)\x09", window, re.S)
        header = re.search(rb"\xbe\x00\xe1\xf5\x05\x83\xb9(....)\x02", window, re.S)
        flag = re.search(rb"\x48\x83\xbc\x24(....)\x00\x0f\x95\xc1", window, re.S)
        gas = re.search(rb"\x4c\x8b\x84\x24(....)", window, re.S)
        if not (queue and header and flag and gas):
            raise EvidenceError("fee site shape differs at %#x" % fee_site)
        rows.append((price_site, fee_site, struct.unpack("<I", queue[1])[0], struct.unpack("<I", header[1])[0], struct.unpack("<I", flag[1])[0], struct.unpack("<I", gas[1])[0]))
    return rows


def tag_text(image, tag):
    table = 0x59A8D0
    relative = struct.unpack_from("<i", image.blob, table + 4 * tag)[0]
    code = bytes(image.blob[image.offset(table + relative):image.offset(table + relative) + 64])
    at = code.find(b"\x48\x8d\x35")
    if at < 0 or code[at + 7] != 0xBA:
        raise EvidenceError("tag arm shape differs")
    start = table + relative + at + 7 + struct.unpack_from("<i", code, at + 3)[0]
    size = struct.unpack_from("<I", code, at + 8)[0]
    return bytes(image.blob[image.offset(start):image.offset(start) + size]).decode()


CONSTANTS = (
    ("price floor test", 0x342A1E2, 2, 4, FLOOR + 1), ("price floor value", 0x342A1E8, 1, 4, FLOOR), ("denominator", 0x342A1CC, 1, 4, DENOMINATOR), ("elasticity", 0x342A1D6, 1, 1, ELASTICITY),
    ("default gas", 0x37325E0, 1, 4, DEFAULT_GAS), ("divisor", 0x3732606, 2, 8, SCALE), ("largest fee", 0x373264D, 2, 8, CAP), ("error tag", 0x3732649, 2, 2, TAG_FEE), ("success tag", 0x3732663, 2, 2, TAG_OK),
)


def constant_rows(image):
    rows = []
    for name, va, skip, size, want in CONSTANTS:
        got = int.from_bytes(image.blob[image.offset(va + skip):image.offset(va + skip) + size], "little")
        if got != want:
            raise EvidenceError("%s differs at %#x" % (name, va))
        rows.append((name, va, got))
    return rows


def location_rows(image):
    relative = image.relative()
    rows = []
    for slot in LOCATIONS:
        path, line, column = image.location(slot, relative)
        if not path.endswith(CRATE):
            raise EvidenceError("Location outside the helper file")
        rows.append((slot, CRATE, line, column))
    return rows


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, target in ((SLOT_BASE, BASE_FEE), (SLOT_PRICE, PRICE), (SLOT_FEE, FEE), (SLOT_UDIV, UDIVTI3)) + tuple(PANIC_TARGETS.items()):
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x differs" % slot)
        rows.append((slot, target))
    return rows


EXAMPLES = (
    ("header absent", 2, 0, 0, 0, 0, 0), ("no base fee word", 0, 0, 30000000, 0, 0, 0), ("at floor, half full", 1, FLOOR, 30000000, 15000000, 0, 0), ("at floor, empty", 1, FLOOR, 30000000, 0, 0, 0),
    ("at floor, full", 1, FLOOR, 30000000, 30000000, 0, 0), ("1 gwei, half full", 1, 1000000000, 30000000, 15000000, 0, 0), ("1 gwei, full", 1, 1000000000, 30000000, 30000000, 0, 0), ("1 gwei, empty", 1, 1000000000, 30000000, 0, 0, 0),
    ("1 gwei, half full, gas 1000000", 1, 1000000000, 30000000, 15000000, 1, 1000000), ("1 gwei, half full, gas 1", 1, 1000000000, 30000000, 15000000, 1, 1), ("floor, half full, gas 99", 1, FLOOR, 30000000, 15000000, 1, 99),
)


def example_rows(harness):
    rows = []
    for name, tag, base, limit, used, flag, gas in EXAMPLES:
        price = FLOOR if tag == 2 else harness.run_price(tag, base, limit, used, 0)[1]
        status, value = harness.run_fee(price, flag, gas)
        rows.append((name, tag, base, limit, used, flag, gas, price, status, value))
    return rows


def analyse(image, mutate=True, vectors=1500):
    tables = walk_table(image)
    harness = Harness(image)
    cases = {"next_base_fee": base_cases(vectors), "price": price_cases(vectors // 3), "fee": fee_cases(vectors // 3)}
    counts = {name: CHECKS[name](harness, cases[name]) for name in SEEDS}
    hits = {"next_base_fee": check_base_leaves(tables["next_base_fee"][1], cases["next_base_fee"]), "price": check_price_leaves(tables["price"][1], cases["price"]), "fee": check_fee_leaves(tables["fee"][1], cases["fee"])}
    sites = call_sites(image)
    if len(sites[SLOT_BASE]) != EXPECTED_BASE_SITES:
        raise EvidenceError("base fee site count differs")
    reached = {}
    for name, (start, _) in SEEDS.items():
        end = image.exact_fde(start)[1]
        reached[name] = sum(1 for row in decode_range(image, start, end) if row.va in harness.machine.seen)
    result = dict(tables=tables, counts=counts, hits=hits, cases=cases, sites=sites, base_sites=base_site_rows(image, sites), fee_sites=fee_site_rows(image, sites), constants=constant_rows(image), locations=location_rows(image),
                  slots=slot_rows(image), examples=example_rows(harness), reached=reached, tag_fee=tag_text(image, TAG_FEE), tag_queue=tag_text(image, TAG_QUEUE), bounds={name: image.exact_fde(SEEDS[name][0]) for name in SEEDS})
    if mutate:
        small = {name: cases[name][:220] for name in cases}
        result["mutations"] = run_mutants(image, set(harness.machine.seen), small)
        unexplained = [row for row in result["mutations"] if row[4] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[1]), row[2]) for row in unexplained])
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("functions.tsv", ("function", "start", "end", "rows", "rows_reached_by_vectors", "merged_leaves"), [(name, "%#x" % result["bounds"][name][0], "%#x" % result["bounds"][name][1], result["tables"][name][0], result["reached"][name], len(result["tables"][name][1])) for name in SEEDS])
    tsv("leaves.tsv", ("function", "conditions", "result"), [(name, condition_text, outcome) for name in SEEDS for condition_text, outcome in leaf_lines(result["tables"][name][1])])
    tsv("panic-locations.tsv", ("record", "file", "line", "column"), [("%#x" % slot, path, line, column) for slot, path, line, column in result["locations"]])
    tsv("slots.tsv", ("slot", "relative_target"), [("%#x" % slot, "%#x" % target) for slot, target in result["slots"]])
    tsv("constants.tsv", ("name", "row", "value"), [(name, "%#x" % va, value) for name, va, value in result["constants"]])
    tsv("base-fee-sites.tsv", ("call_site", "denominator_elasticity", "1e8_floor_after_call"), [("%#x" % site, form, floor) for site, form, floor in result["base_sites"]])
    tsv("fee-sites.tsv", ("price_call", "fee_call", "queue_count_field", "header_field", "flag_frame_slot", "gas_frame_slot"), [("%#x" % row[0], "%#x" % row[1]) + tuple("%#x" % cell for cell in row[2:]) for row in result["fee_sites"]])
    tsv("examples.tsv", ("name", "tag", "base_fee", "gas_limit", "gas_used", "flag", "gas", "price", "status", "fee"), result["examples"])
    if "mutations" in result:
        tsv("mutations.tsv", ("function", "address", "kind", "outcome", "detail"), [(name, "%#x" % va, kind, outcome, detail) for name, va, kind, outcome, detail in result["mutations"]])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "cases": {name: len(result["cases"][name]) for name in SEEDS}, "base_fee_outcomes": dict(sorted(result["counts"]["next_base_fee"].items())),
               "fee_outcomes": {str(key): value for key, value in sorted(result["counts"]["fee"].items())}, "price_outcomes": dict(sorted(result["counts"]["price"].items())), "tag_0x14d": result["tag_fee"], "tag_0x14c": result["tag_queue"],
               "leaves_hit_by_vectors": {name: len(result["hits"][name]) for name in SEEDS}, "leaf_results": {name: len(EXPECTED_RESULTS[name]) for name in SEEDS}}
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[3] == "killed"), "killed_by_walker_only": sum(1 for r in rows if r[4] == "path walker"), "survived": sum(1 for r in rows if r[3] == "survived")}
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
