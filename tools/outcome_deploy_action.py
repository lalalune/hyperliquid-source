#!/usr/bin/env python3
"""Pin node #94 OutcomeDeploy: the ten action arms, their count and length gates, and the settlement fraction rules.

The real bytes run under recording stubs with real B-tree and hash table layouts. A separately written rule list
predicts the heap and events of every run, and every reached conditional row, immediate and field offset is mutated.
No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/outcome_deploy_action.py --out <dir>
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
            return finish("cvtsi2sd", ("x", reg), rm, width)
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
            value = self.get(row.b, row.width)
            self.set_low(row.a[1], to_bits(float(value - (1 << (8 * row.width)) if value & SIGN[row.width] else value)))
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


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right



HANDLER = 0x2749880
HANDLER_A = 0x4D66400
HANDLER_B = 0x4D67E10
WRAP = 0x274B290
WRAP_A = 0x4D69820
WRAP_B = 0x4D69AE0
GATE = 0x3729DF0
NAME = 0x3C00F50
DESC_Q = 0x3729CA0
DESC_O = 0x3729830
QBUILD = 0x3729990
OPEN = 0x3719210
QINSERT = 0x3728C20
YESNO = 0x398CB60
DUP_Q = 0x372A910
DUP_O = 0x372AEA0
HANDLERS = {HANDLER: dict(chain=0x8F2, table=0x3EDD50, limit=0x3F0121), HANDLER_A: dict(chain=0x1372, table=0x712C4C, limit=0x715522), HANDLER_B: dict(chain=0x8F2, table=0x712C74, limit=0x715522)}
WRAPS = {WRAP: dict(settle=0x2717ED0, location=0x56BD990, insert=0x284F810, set_at=0x8B8, text=0x3EFE9A),
         WRAP_A: dict(settle=0x4D10A80, location=0x5744598, insert=0x4941FE0, set_at=0x1338, text=0x71529B),
         WRAP_B: dict(settle=0x4D0FE80, location=0x5744598, insert=0x4941FE0, set_at=0x8B8, text=0x71529B)}
NAMES = {HANDLER: "outcome_deploy", HANDLER_A: "outcome_deploy_shifted", HANDLER_B: "outcome_deploy_copy", WRAP: "settle_outcome", WRAP_A: "settle_outcome_shifted", WRAP_B: "settle_outcome_copy",
         GATE: "settle_gate", NAME: "name_lengths", DESC_Q: "change_question_text", DESC_O: "change_outcome_text", QBUILD: "question_record", OPEN: "side_circulation", QINSERT: "question_insert",
         YESNO: "default_side_names", DUP_Q: "duplicate_question", DUP_O: "duplicate_standalone"}
TARGETS = tuple(sorted(NAMES))
HASH = 0x399C4A0
C_TOKEN = 0x274C600
C_CLONE = 0x26BA7A0
C_SIDES2 = 0x2786600
C_SIDES3 = 0x2786700
C_DEPLOY = 0x27513C0
C_MARKET = 0x274C9F0
C_QUESTION = 0x274E1C0
C_NAMED = 0x2719BD0
C_COLLECT = 0x2511DD0
C_SETTLEQ = 0x274BC20
C_MAPND = 0x2511FB0
C_OUTCOMES = 0x2512FE0
C_DROP_A = 0x27794D0
C_DROP_B = 0x277CCD0
C_DROP_C = 0x277A8F0
SLOT_NAME = 0x5774C38
SLOT_DUP_O = 0x5774C40
SLOT_DESC_Q = 0x5774C48
SLOT_DESC_O = 0x5774C50
SLOT_DUP_Q = 0x5774C58
SLOT_YESNO = 0x5774C60
SLOT_GATE = 0x5774C68
SLOT_PARSE = 0x5773328
SLOT_FIND = 0x5773838
SLOT_STR = 0x576E0D0
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_BCMP = 0x576E378
SLOT_COPY = 0x576DFE0
SLOT_RECORD = 0x5773190
SLOT_SPOT_USER = 0x5773170
SLOT_UNWIND = 0x576E128
COLLECT_SET = 0x3BAE4B0
KEYS_Q = 0x3BB61E0
KEYS_O = 0x3BB5BC0
DROP_KEYS_Q = 0x33F4320
NEXT_KEY = 0x33B9210
Q_CLONE = 0x3799710
Q_INSERT = 0x379D820
Q_DROP = 0x3765030
L_INSERT = 0x379D690
Q_DROP_ND = 0x3761B80
MARK_BASE = 0x7700000000
OK = 0x186
TAG_TEXT = 0x17B
TAG_STATUS = 0x17D
TAG_LEN = 0x143
TAG_NUM = 0x13F
TAG_OUTCOME = 0xEC
TAG_QUESTION = 0xED
TAG_TOKEN = 0xEA
TAG_CHAIN = 0x8E
TAG_INPUT = 0x140
TOP = MASK[8]
CAP = 0x0CCCCCCCCCCCCCCC
SETTLED = 0x27
ONE = 0x3FF0000000000000
TEXT_TABLE = 0x59A8D0
STATUS_TABLE = 0x59B088
TEXTS = {"daily": (0x20C9A0, 0x20), "limit": (0x3F0121, 0x0E), "limit2": (0x59934B, 0x0E), "fallback": (0x5993FF, 0x1E), "exact": (0x599390, 0x33), "others": (0x5993C3, 0x3C),
         "question": (0x2094C0, 0x10), "bad fallback": (0x599378, 0x18), "dup q": (0x5994A2, 0x12), "dup o": (0x5994B4, 0x1C)}
OUT = HEAP_BASE + 0x100
USER_AT = HEAP_BASE + 0x200
ACTION = HEAP_BASE + 0x240
DETAILS = HEAP_BASE + 0x2F0
ND_IN = HEAP_BASE + 0x320
RECORD = HEAP_BASE + 0x360
SPOT_REC = HEAP_BASE + 0x3E0
IDS = HEAP_BASE + 0x400
VEC_AT = HEAP_BASE + 0x480
ALLOC_AT = HEAP_BASE + 0x4C0
STRS = HEAP_BASE + 0x600
S = HEAP_BASE + 0x1000
SP = S + 0x80
T = S + 0x90
NODES = HEAP_BASE + 0x2800
BUCKETS = 64
OUT_CTRL = HEAP_BASE + 0x8000
Q_CTRL = HEAP_BASE + 0xA000
L_CTRL = HEAP_BASE + 0xA800
USED = 0xB000
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(USED))
USER = 0x1234567890ABCDEF0011223344556677889900AA


class Layout:
    def __init__(self, size, val_at, val_size, key_at, len_at, edge_at, parent_idx=None):
        self.size, self.val_at, self.val_size, self.key_at, self.len_at, self.edge_at, self.parent_idx = size, val_at, val_size, key_at, len_at, edge_at, parent_idx


L_SET = Layout(0xC8, 0, 0, 8, 0x62, 0x68, 0x60)
L_BALANCE = Layout(0x1E0, 0x60, 0x18, 8, 0x16A, 0x170)
L_SUPPLY = Layout(0x120, 0x60, 8, 8, 0xBA, 0xC0)
STATUS_CODES = (7, 8, 9)
TARGET_HANDLERS = tuple(sorted(HANDLERS))


def hash_of(key):
    return ((key * 0x9E3779B97F4A7C15) ^ (key >> 13)) & TOP | 1 << 40


def out_rec(token=None):
    return dict(name=b"alpha", desc=b"first text", sides=(11, 12))


class Case:
    DEFAULTS = dict(entry=HANDLER, user=USER, chain=0, poison=0, arm=0, ids=None, x=5, quote=3, n=2, used=0, nextq=7, nexto=100, tokens=10, fail=None, ret=0x4444, fail_at=None, flen=4, dlen=9, oid=21, qid=41, outcomes=None, questions=None,
                    links=None, crowd=0, bits=0x3FE0000000000000, gate="none", settle=(SETTLED,), root=1, mlen=2, nd=(b"name", b"text"), text_len=5, strict=None, supply=None, balances=None, side=0, deep=False, cap=16, status=0x5A5A)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, fields.pop(key, value))
        if fields:
            raise EvidenceError("unknown case fields: %s" % sorted(fields))
        self.fail = self.fail or {}
        self.outcomes = dict(self.outcomes) if self.outcomes is not None else {21: dict(), 22: dict(name=b"beta")}
        self.questions = dict(self.questions) if self.questions is not None else {41: dict(fallback=21, named=(22, 23))}
        self.links = dict(self.links) if self.links is not None else {}


def ctrl_head(entry):
    return S + 0x190 if entry == DUP_Q else S + 0x160


def fail_image(tag):
    data = bytearray((index * 7 + 0x21) & 0xFF for index in range(0x60))
    data[0:2] = tag.to_bytes(2, "little")
    return bytes(data)


def limit_of(chain):
    return None if chain < 2 else 500 if chain == 2 else 50


def sat_add(left, right):
    return min(left + right, TOP)


def sat_inc(value):
    return min(value + 1, TOP)


def is_fraction(bits):
    magnitude = bits & (TOP >> 1)
    if magnitude > 0x7FF0000000000000 - 1:
        return False
    if bits >> 63 and magnitude:
        return False
    return not to_float(bits) > 1.0


def spec_run(case, before):
    heap = bytearray(before)
    events = []

    def poke(addr, data):
        heap[addr - HEAP_BASE:addr - HEAP_BASE + len(data)] = data

    def word(addr, size=8):
        return int.from_bytes(heap[addr - HEAP_BASE:addr - HEAP_BASE + size], "little")

    def put(addr, value, size=8):
        poke(addr, value.to_bytes(size, "little"))

    def done(label):
        return ("run", bytes(heap), [], tuple(events), None, label)

    entry = case.entry
    if entry in HANDLERS:
        return spec_handler(case, heap, events, poke, word, put, done, HANDLERS[entry])
    if entry in WRAPS:
        return spec_wrap(case, heap, events, poke, word, put, done, WRAPS[entry])
    if entry == GATE:
        return spec_gate(case, events, poke, put, done)
    if entry == NAME:
        name, desc = case.nd_lens if hasattr(case, "nd_lens") else (len(case.nd[0]), len(case.nd[1]))
        caps = case.nd_caps
        if name >= 101 or desc >= 2001:
            put(OUT, TAG_LEN, 2)
            put(OUT + 0x18, name if name >= 101 else desc)
            for cap, ptr in caps if name >= 101 else caps[::-1]:
                if cap:
                    events.append(("free", ptr, cap))
            return done("len")
        for index, value in enumerate((word(ND_IN), word(ND_IN + 8), word(ND_IN + 0x10), word(ND_IN + 0x18), word(ND_IN + 0x20), word(ND_IN + 0x28))):
            put(OUT + 8 + 8 * index, value)
        put(OUT, OK, 2)
        return done("ok")
    if entry in (DESC_Q, DESC_O):
        table = case.questions if entry == DESC_Q else case.outcomes
        key = case.qid if entry == DESC_Q else case.oid
        new_cap, new_ptr = word(DETAILS), word(DETAILS + 8)
        if key not in table:
            put(OUT, TAG_INPUT, 2)
            if new_cap:
                events.append(("free", new_ptr, new_cap))
            return done("missing")
        if word(DETAILS + 0x10) >= 2001:
            put(OUT, TAG_LEN, 2)
            if new_cap:
                events.append(("free", new_ptr, new_cap))
            return done("long")
        at = case.at_record[key] + (0x20 if entry == DESC_Q else 0x70)
        if word(at):
            events.append(("free", word(at + 8), word(at)))
        poke(at, bytes(heap[DETAILS - HEAP_BASE:DETAILS - HEAP_BASE + 0x18]))
        put(OUT, OK, 2)
        return done("ok")
    if entry == QBUILD:
        return spec_qbuild(case, heap, events, poke, word, put, done)
    if entry == OPEN:
        return spec_open(case, events, put, done)
    if entry == QINSERT:
        events.append(("record copy",))
        q, fallback = word(RECORD + 0x68), word(RECORD + 0x70)
        events.append(("insert question", q))
        if case.status != 2 ** 63:
            events.append(("drop old",))
        events.append(("link", fallback, q))
        put(T + 0x138, sat_inc(word(T + 0x138)))
        put(OUT, q)
        poke(OUT + 8, bytes(heap[RECORD - HEAP_BASE:RECORD - HEAP_BASE + 0x68]))
        return done("ok")
    if entry == YESNO:
        events.extend((("alloc", 3), ("alloc", 2)))
        for index, value in enumerate((3, ALLOC_AT, 3, 2, ALLOC_AT + 0x10, 2)):
            put(OUT + 8 * index, value)
        poke(ALLOC_AT, b"Yes")
        poke(ALLOC_AT + 0x10, b"No")
        return done("ok")
    if entry in (DUP_Q, DUP_O):
        wanted = case.nd
        pool = case.questions if entry == DUP_Q else case.outcomes
        keys = sorted(pool)
        if entry == DUP_O:
            keys = [key for key in keys if key not in case.links]
        events.append(("keys", len(pool)))
        hit = any((pool[key].get("name", b"alpha"), pool[key].get("desc", b"first text")) == wanted for key in keys)
        if hit:
            put(OUT, TAG_TEXT, 2)
            text = TEXTS["dup q" if entry == DUP_Q else "dup o"]
            put(OUT + 8, text[0])
            put(OUT + 0x10, text[1])
        else:
            put(OUT, OK, 2)
        events.append(("drop keys",))
        return done("dup" if hit else "ok")
    raise EvidenceError("no rule for %#x" % entry)


def spec_gate(case, events, poke, put, done):
    def text(name):
        put(OUT, TAG_TEXT, 2)
        put(OUT + 8, TEXTS[name][0])
        put(OUT + 0x10, TEXTS[name][1])
        return done(name)

    oid = case.oid
    if oid not in case.links:
        put(OUT + 8, 0)
        put(OUT, OK, 2)
        return done("not linked")
    q = case.links[oid]
    if q not in case.questions:
        put(OUT, TAG_STATUS, 2)
        put(OUT + 2, 8, 1)
        return done("status 8")
    record = case.questions[q]
    if record["fallback"] == oid:
        return text("fallback")
    value = to_float(case.bits)
    if value == 0.0:
        put(OUT + 8, 0)
        put(OUT, OK, 2)
        return done("zero")
    if value != 1.0:
        return text("exact")
    count = 1 + (len(record["named"]) if record["named"] else 0)
    events.append(("collect", record["fallback"], count))
    if count == 2:
        put(OUT + 8, 1)
        put(OUT + 0x10, record["fallback"])
        put(OUT, OK, 2)
        events.append(("free", VEC_AT, count * 8))
        return done("winner")
    events.append(("free", VEC_AT, count * 8))
    return text("others")


def spec_wrap(case, heap, events, poke, word, put, done, role):
    detail_cap, detail_ptr = word(DETAILS), word(DETAILS + 8)

    def drop():
        if detail_cap:
            events.append(("free", detail_ptr, detail_cap))

    if not is_fraction(case.bits):
        put(OUT, TAG_TEXT, 2)
        put(OUT + 8, role["text"])
        put(OUT + 0x10, 0x18)
        drop()
        return done("bad price")
    events.append(("gate", case.oid, case.bits))
    if isinstance(case.gate, int):
        poke(OUT, fail_image(case.gate))
        drop()
        return done("gate %#x" % case.gate)
    result = case.settle[0]
    events.append(("settle", case.oid, case.bits, detail_ptr))
    if case.gate != "none":
        if result == SETTLED:
            result = case.settle[1]
            events.append(("settle", case.gate[1], 0, 1))
    if result == SETTLED:
        put(OUT, OK, 2)
        return done("settled")
    put(S + 0x1E8, 1, 1)
    events.append(("record", 4, role["location"]))
    if case.user:
        events.append(("insert", S + role["set_at"]))
    put(OUT, TAG_INPUT, 2)
    return done("poison")


def spec_qbuild(case, heap, events, poke, word, put, done):
    def refuse(name=None, status=None):
        if name:
            put(OUT + 8, TAG_TEXT, 2)
            put(OUT + 0x10, TEXTS[name][0])
            put(OUT + 0x18, TEXTS[name][1])
        else:
            put(OUT + 8, TAG_STATUS, 2)
            put(OUT + 10, status, 1)
        put(OUT, 2 ** 63)
        for at in (ND_IN, ND_IN + 0x18):
            if word(at):
                events.append(("free", word(at + 8), word(at)))
        return done(name or "status %d" % status)

    q, fallback = case.nextq, case.oid
    if q > 9999:
        return refuse("limit2")
    if q in case.questions:
        return refuse("question")
    if fallback in case.links:
        return refuse("bad fallback")
    for side in (0, 1):
        events.append(("open", fallback, side))
        answer = case.fail.get(side, 0)
        if answer == "error":
            return refuse(status=8)
        if answer:
            return refuse(status=9)
    poke(OUT, bytes(heap[ND_IN - HEAP_BASE:ND_IN - HEAP_BASE + 0x30]))
    put(OUT + 0x30, fallback)
    put(OUT + 0x38, 0)
    put(OUT + 0x48, 0)
    put(OUT + 0x50, 0)
    put(OUT + 0x60, 0)
    put(OUT + 0x68, q)
    put(OUT + 0x70, fallback)
    return done("ok")


def spec_open(case, events, put, done):
    def result(error, code, value=None):
        put(OUT, int(error), 1)
        if error:
            put(OUT + 1, code, 1)
        if value is not None:
            put(OUT + 8, value)
        return done("code %d" % code if error else "ok")

    if case.oid not in case.outcomes:
        return result(True, 4)
    token = case.outcomes[case.oid].get("sides", (11, 12))[case.side]
    events.append(("spot user", token))
    if case.supply is None or token not in case.supply:
        return result(True, 0x16)
    total = case.supply[token]
    held = (case.balances or {}).get(token, 0)
    if held > total:
        return result(True, 0x12)
    return result(False, 0, total - held)


def spec_handler(case, heap, events, poke, word, put, done, role):
    arm = case.arm
    a = ACTION

    def refuse(tag, payload=None):
        put(OUT, 0xE, 1)
        put(OUT + 8, tag, 2)
        if payload is not None:
            put(OUT + 0x10, payload)
        return done("%#x" % tag)

    def text(name, tag=TAG_TEXT):
        put(OUT, 0xE, 1)
        put(OUT + 8, tag, 2)
        put(OUT + 0x10, role["limit"] if name == "limit" else TEXTS[name][0])
        put(OUT + 0x18, TEXTS[name][1])
        return done(name)

    def wide(name, tag=TAG_TEXT):
        """The refusal built at the shared tail: stale stack words go out behind the text."""
        poke(OUT + 0xA, bytes([STACK_MARK]) * 6)
        put(OUT + 0x20, T)
        poke(OUT + 0x28, bytes([STACK_MARK]) * 0x40)
        return text(name, tag)

    def failed(key):
        poke(OUT + 8, fail_image(case.fail[key]))
        put(OUT, 0xE, 1)
        return done("%s %#x" % (key, case.fail[key]))

    if case.user and role["chain"] and case.chain:
        return refuse(TAG_CHAIN)
    if case.poison:
        put(OUT, 0xE, 1)
        put(OUT + 8, TAG_STATUS, 2)
        put(OUT + 10, 7, 1)
        return done("status 7")
    limit = limit_of(case.chain)

    def ok():
        put(OUT, 0xD, 1)
        return done("ok")

    def over_daily(extra=1):
        return limit is not None and sat_add(case.used, extra) > limit

    def clone(src):
        events.append(("clone", src))

    def name_step(key="name"):
        events.append((key,))
        return key in case.fail

    if arm == 0:
        if case.x >= CAP:
            return refuse(TAG_NUM, case.x)
        events.append(("token", case.x))
        if "token" in case.fail:
            return failed("token")
        put(OUT, 7, 1)
        put(OUT + 8, case.ret)
        return done("token ok")
    if arm in (1, 2):
        if over_daily():
            return text("daily")
        clone(a + 8)
        if name_step():
            return failed("name")
        events.append(("dup outcome",))
        if "dup outcome" in case.fail:
            events.append(("drop",))
            return failed("dup outcome")
        events.append(("sides", a + 0x38))
        if arm == 1 and case.quote >= case.tokens:
            events.extend((("drop sides",), ("drop",)))
            put(OUT, 0xE, 1)
            put(OUT + 8, TAG_TOKEN, 2)
            put(OUT + 0x10, case.quote)
            return done("quote")
        events.append(("deploy", case.quote))
        if "deploy" in case.fail:
            return failed("deploy")
        return ok()
    if arm == 3:
        if case.nextq > 9999:
            return wide("limit")
        if sat_add(case.nexto, case.n + 1) > 20000:
            return wide("limit")
        if case.n > 50:
            return wide("limit", TAG_LEN)
        if over_daily(case.n + 1):
            return wide("daily")
        clone(a)
        clone(a + 0x18)
        if name_step():
            return failed_wide(case, "name", poke, put, done)
        events.append(("dup question",))
        if "dup question" in case.fail:
            events.append(("drop",))
            return failed_wide(case, "dup question", poke, put, done)
        clone(a + 0x30)
        if name_step("name 2"):
            events.append(("drop",))
            return failed_wide(case, "name 2", poke, put, done)
        events.append(("map names", case.n))
        if "map names" in case.fail:
            events.append(("drop",))
            events.append(("drop",))
            return failed_wide(case, "map names", poke, put, done)
        events.append(("yes no",))
        events.append(("deploy", case.quote))
        if "deploy" in case.fail:
            events.extend((("drop list",), ("drop",)))
            return failed_wide(case, "deploy", poke, put, done)
        events.append(("outcomes", case.n))
        for index in range(case.n):
            put(IDS + 8 * index, 0x900 + index)
        if "outcomes" in case.fail:
            events.append(("drop",))
            return failed_wide(case, "outcomes", poke, put, done)
        events.append(("question", case.ret))
        if "question" in case.fail:
            events.append(("free", IDS, case.n * 8))
            return failed_wide(case, "question", poke, put, done)
        for index in range(case.n):
            events.append(("named", case.ret + 1, 0x900 + index))
            if case.fail_at == index:
                if case.n:
                    events.append(("free", IDS, case.n * 8))
                return failed_wide(case, "named", poke, put, done)
        if case.n:
            events.append(("free", IDS, case.n * 8))
        return ok()
    if arm in (4, 6, 7):
        if case.oid not in case.outcomes:
            return refuse(TAG_OUTCOME, case.oid)
        if arm == 4:
            if case.flen >= 0x65:
                return refuse(TAG_LEN, a + 8)
            events.append(("parse",))
            if "parse" in case.fail:
                poke(OUT + 8, fail_image(case.fail["parse"]))
                put(OUT, 0xE, 1)
                return done("parse")
            if case.dlen >= 0x7D1:
                return refuse(TAG_LEN)
            clone(a + 0x20)
            events.append(("settle", case.oid, case.bits))
            if "settle" in case.fail:
                return failed("settle")
            return ok()
        if arm == 6:
            clone(a + 8)
            events.append(("change outcome", case.oid))
            if "change" in case.fail:
                return failed("change")
            return ok()
        clone(a + 8)
        if name_step():
            return failed("name")
        events.append(("question", case.oid))
        if "question" in case.fail:
            return failed("question")
        return ok()
    if case.qid not in case.questions:
        return refuse(TAG_QUESTION, case.qid)
    if arm == 5:
        if case.mlen >= 0x33:
            return refuse(TAG_LEN, a + 0x10)
        events.append(("collect", case.root, case.mlen if case.root else 0))
        if "collect" in case.fail:
            return failed("collect")
        events.append(("settle question", case.qid))
        if "settle question" in case.fail:
            return failed("settle question")
        return ok()
    if arm == 8:
        events.append(("find", case.oid))
        if "find" in case.fail:
            return failed("find")
        events.append(("named", case.qid, case.ret))
        if "named" in case.fail:
            return failed("named")
        return ok()
    clone(a + 8)
    events.append(("change question", case.qid))
    if "change" in case.fail:
        return failed("change")
    return ok()


def failed_wide(case, key, poke, put, done):
    poke(OUT + 8, fail_image(case.fail[key] if key != "named" or key in case.fail else case.fail_tag))
    put(OUT, 0xE, 1)
    return done("%s" % key)


COPY_CALLS = {}


def copy_calls(image, calls):
    """Callee of each copy, joined to the first handler by row order; kept, since every mutant builds a harness."""
    if not COPY_CALLS:
        base = decode_range(image, *image.exact_fde(HANDLER))
        for copy in (HANDLER_A, HANDLER_B):
            for left, right in zip(base, decode_range(image, *image.exact_fde(copy))):
                if left.op == "call" and left.target in calls and right.target not in calls:
                    COPY_CALLS[right.target] = left.target
    return COPY_CALLS


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        statics = memory.statics
        calls = {HASH: self.on_hash, C_TOKEN: self.on_token, C_CLONE: self.on_clone, C_SIDES2: self.on_sides2, C_SIDES3: self.on_sides3, C_DEPLOY: self.on_deploy, C_MARKET: self.on_market, C_QUESTION: self.on_question,
                 C_NAMED: self.on_named, C_COLLECT: self.on_collect, C_SETTLEQ: self.on_settle_question, C_MAPND: self.on_map, C_OUTCOMES: self.on_outcomes, C_DROP_A: self.on_drop, C_DROP_B: self.on_drop_sides, C_DROP_C: self.on_drop_list,
                 WRAP: self.on_settle_action, COLLECT_SET: self.on_collect_set, KEYS_Q: self.on_keys, KEYS_O: self.on_keys, DROP_KEYS_Q: self.on_drop_keys, NEXT_KEY: self.on_next_key, OPEN: self.on_open,
                 Q_CLONE: self.on_q_clone, Q_INSERT: self.on_q_insert, Q_DROP: self.on_q_drop, L_INSERT: self.on_link}
        for target, source in copy_calls(image, calls).items():
            calls[target] = calls[source]
        for role in WRAPS.values():
            calls[role["settle"]] = self.on_settle_real
            calls[role["insert"]] = self.on_insert
        machine.calls = calls
        hooks = {SLOT_NAME: self.on_name, SLOT_DUP_O: self.on_dup_o, SLOT_DESC_Q: self.on_desc_q, SLOT_DESC_O: self.on_desc_o, SLOT_DUP_Q: self.on_dup_q, SLOT_YESNO: self.on_yesno, SLOT_GATE: self.on_gate, SLOT_PARSE: self.on_parse,
                 SLOT_FIND: self.on_find, SLOT_STR: self.on_string, SLOT_FREE: self.on_free, SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_FAIL: self.on_panic, SLOT_BCMP: self.on_bcmp, SLOT_RECORD: self.on_record, SLOT_SPOT_USER: self.on_spot_user,
                 SLOT_UNWIND: self.on_panic}
        for slot, hook in hooks.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.case = None
        self.events = []
        self.node_cur = NODES
        self.str_cur = STRS
        self.alloc_cur = ALLOC_AT
        self.over = {}

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_panic(self, machine):
        raise Panicked("panic path")

    def rdi_image(self, key, ok_words=()):
        """Write a result at rdi: the case's failure image, or the ok tag followed by words."""
        machine = self.machine
        at = machine.regs[RDI]
        if key in self.case.fail:
            machine.memory.put_bytes(at, fail_image(self.case.fail[key]))
            return
        machine.memory.write(at, 2, OK)
        for index, value in enumerate(ok_words):
            machine.memory.write(at + 8 + 8 * index, 8, value)

    def on_hash(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] in self.states, "hash state")
        key = machine.memory.read(regs[RSI], 8)
        regs[RAX] = self.over.get(key, hash_of(key))

    def on_token(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == S and regs[RDX] == USER_AT and regs[RCX] == 1, "token arguments")
        self.events.append(("token", regs[R8]))
        self.rdi_image("token", (self.case.ret,))

    def on_clone(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], 0x30)
        self.events.append(("clone", regs[RSI]))

    def on_string(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], 0x18)
        self.events.append(("clone", regs[RSI]))

    def on_sides2(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == ACTION + 0x68, "sides end")
        machine.memory.copy(regs[RDI], regs[RSI], 0x30)
        self.events.append(("sides", regs[RSI]))

    def on_sides3(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == ACTION + 0x78, "sides end")
        machine.memory.copy(regs[RDI], regs[RSI], 0x40)
        self.events.append(("sides", regs[RSI]))

    def on_name(self, machine):
        regs = machine.regs
        key = "name 2" if self.named_once else "name"
        self.named_once = self.case.arm == 3
        self.events.append((key,))
        if key in self.case.fail:
            self.rdi_image(key)
            return
        machine.memory.write(regs[RDI], 2, OK)
        machine.memory.copy(regs[RDI] + 8, regs[RSI], 0x30)

    def on_dup_o(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == T, "dup state")
        self.events.append(("dup outcome",))
        self.rdi_image("dup outcome")

    def on_dup_q(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == T, "dup state")
        self.events.append(("dup question",))
        self.rdi_image("dup question")

    def on_deploy(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == S and regs[RDX] == USER_AT, "deploy arguments")
        self.events.append(("deploy", regs[RCX]))
        self.rdi_image("deploy", (self.case.ret,))

    def on_market(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == S and regs[RDX] == USER_AT, "market arguments")
        self.events.append(("deploy", regs[R8]))
        self.rdi_image("deploy")

    def on_question(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == S, "question state")
        self.events.append(("question", regs[RDX]))
        self.rdi_image("question", (self.case.ret + 1,))

    def on_named(self, machine):
        regs = machine.regs
        case = self.case
        self.expect(regs[RSI] == S, "named state")
        self.events.append(("named", regs[RDX], regs[RCX]))
        if case.arm == 3:
            if self.named_count == case.fail_at:
                machine.memory.put_bytes(regs[RDI], fail_image(case.fail["named"]))
            else:
                machine.memory.write(regs[RDI], 2, OK)
            self.named_count += 1
        else:
            self.rdi_image("named")

    def on_map(self, machine):
        regs = machine.regs
        case = self.case
        self.expect(regs[RSI] == case.list_at and regs[RDX] == case.list_at + case.n * 0x30, "name list")
        self.events.append(("map names", case.n))
        self.rdi_image("map names", (case.n, 0x7000, case.n))

    def on_yesno(self, machine):
        machine.memory.put_bytes(machine.regs[RDI], bytes(range(0x30)))
        self.events.append(("yes no",))

    def on_outcomes(self, machine):
        regs = machine.regs
        case = self.case
        memory = machine.memory
        at = regs[RSI]
        self.expect(memory.read(at, 8) == 0x7000 and memory.read(at + 8, 8) == 0x7000 and memory.read(at + 0x10, 8) == case.n and memory.read(at + 0x18, 8) == 0x7000 + 0x30 * case.n, "outcome list")
        self.expect(memory.read(at + 0x20, 8) == S, "outcome state")
        self.expect(memory.bytes_at(memory.read(at + 0x28, 8), 20) == case.user.to_bytes(20, "big"), "outcome user")
        self.expect(memory.read(memory.read(at + 0x30, 8), 8) == case.quote, "outcome quote")
        self.events.append(("outcomes", case.n))
        for index in range(case.n):
            memory.write(IDS + 8 * index, 8, 0x900 + index)
        self.rdi_image("outcomes", (case.n, IDS, case.n))

    def on_collect(self, machine):
        regs = machine.regs
        case = self.case
        memory = machine.memory
        at = regs[RSI]
        words = [memory.read(at + 8 * index, 8) for index in range(10)]
        root = 0x7100 if case.root else 0
        flag = 1 if case.root else 0
        self.expect(words == [flag, 0, root, 0x55 if case.root else 0x55, flag, 0, root, 0x55, case.mlen if case.root else 0, T], "map iterator %s" % words)
        self.events.append(("collect", case.root, words[8]))
        self.rdi_image("collect", (1, 2, 3))

    def on_settle_question(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == S and regs[RDX] == USER_AT, "settle question arguments")
        self.expect(machine.memory.read(regs[R8], 8) == 1, "settle list")
        self.events.append(("settle question", regs[RCX]))
        self.rdi_image("settle question")

    def on_parse(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == ACTION + 8, "parse source")
        self.events.append(("parse",))
        self.rdi_image("parse", (self.case.bits,))

    def on_find(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == T, "find state")
        self.events.append(("find", regs[RSI]))
        self.rdi_image("find", (self.case.ret,))

    def on_desc_q(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == T, "change state")
        self.events.append(("change question", regs[RDX]))
        self.expect(machine.memory.read(regs[RCX], 8) == machine.memory.read(ACTION + 8, 8), "change text")
        self.rdi_image("change")

    def on_desc_o(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == T, "change state")
        self.events.append(("change outcome", regs[RDX]))
        self.expect(machine.memory.read(regs[RCX], 8) == machine.memory.read(ACTION + 8, 8), "change text")
        self.rdi_image("change")

    def on_settle_action(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == S and regs[RDX] == USER_AT, "settle arguments")
        self.expect(machine.memory.read(regs[R8], 8) == machine.memory.read(ACTION + 0x20, 8), "settle details")
        self.events.append(("settle", regs[RCX], machine.xmm[0] & TOP))
        self.rdi_image("settle")

    def on_drop(self, machine):
        self.events.append(("drop",))

    def on_drop_sides(self, machine):
        self.events.append(("drop sides",))

    def on_drop_list(self, machine):
        self.events.append(("drop list",))

    def on_free(self, machine):
        regs = machine.regs
        self.events.append(("free", regs[RDI], regs[RSI]))

    def on_alloc(self, machine):
        regs = machine.regs
        self.events.append(("alloc", regs[RDI]))
        regs[RAX] = self.alloc_cur
        self.alloc_cur += 0x10

    def on_bcmp(self, machine):
        regs = machine.regs
        left = machine.memory.bytes_at(regs[RDI], regs[RDX])
        right = machine.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else 1

    def on_gate(self, machine):
        regs = machine.regs
        case = self.case
        self.expect(regs[RSI] == T, "gate state")
        self.events.append(("gate", regs[RDX], machine.xmm[0] & TOP))
        at = regs[RDI]
        if isinstance(case.gate, int):
            machine.memory.put_bytes(at, fail_image(case.gate))
            return
        machine.memory.write(at, 2, OK)
        machine.memory.write(at + 8, 8, 0 if case.gate == "none" else 1)
        machine.memory.write(at + 0x10, 8, 0 if case.gate == "none" else case.gate[1])

    def on_settle_real(self, machine):
        regs = machine.regs
        case = self.case
        self.expect(regs[RDI] == S, "settle state")
        index = self.settle_count
        self.settle_count += 1
        if index == 0:
            self.events.append(("settle", regs[RSI], machine.xmm[0] & TOP, machine.memory.read(regs[RDX] + 8, 8)))
        else:
            memory = machine.memory
            self.expect(memory.read(regs[RDX], 8) == 0 and memory.read(regs[RDX] + 8, 8) == 1 and memory.read(regs[RDX] + 0x10, 8) == 0, "empty details")
            self.events.append(("settle", regs[RSI], machine.xmm[0] & TOP, 1))
        regs[RAX] = case.settle[index]

    def on_record(self, machine):
        regs = machine.regs
        self.events.append(("record", regs[RDI] & MASK[4], regs[RSI]))

    def on_insert(self, machine):
        regs = machine.regs
        self.expect(machine.memory.bytes_at(regs[RSI], 20) == self.case.user.to_bytes(20, "big"), "insert user")
        self.events.append(("insert", regs[RDI]))

    def on_collect_set(self, machine):
        regs = machine.regs
        memory = machine.memory
        case = self.case
        at = regs[RSI]
        record = case.questions[case.links[case.oid]]
        root, height, length = self.set_heads[case.links[case.oid]]
        flag = 1 if root else 0
        words = [memory.read(at + 8 * index, 8) for index in range(11)]
        self.expect(words == [1, record["fallback"], flag, 0, root, height, flag, 0, root, height, length if root else 0], "set iterator %s" % words)
        count = 1 + (length if root else 0)
        self.events.append(("collect", record["fallback"], count))
        memory.write(regs[RDI], 8, count)
        memory.write(regs[RDI] + 8, 8, VEC_AT)
        memory.write(regs[RDI] + 0x10, 8, count)

    def on_keys(self, machine):
        regs = machine.regs
        memory = machine.memory
        at = regs[RSI]
        case = self.case
        ctrl, pool = (Q_CTRL, case.questions) if case.entry == DUP_Q else (OUT_CTRL, case.outcomes)
        self.expect(memory.read(at, 8) == ctrl and memory.read(at + 0x20, 8) == memory.read(ctrl_head(case.entry) + 0x18, 8), "key iterator")
        self.events.append(("keys", len(pool)))
        root, height = self.key_tree
        memory.write(regs[RDI], 8, root)
        memory.write(regs[RDI] + 8, 8, height)
        memory.write(regs[RDI] + 0x10, 8, len(pool))

    def on_drop_keys(self, machine):
        self.events.append(("drop keys",))

    def on_next_key(self, machine):
        regs = machine.regs
        if not self.dropped:
            self.events.append(("drop keys",))
        self.dropped = True
        machine.memory.write(regs[RDI], 8, 0)

    def on_open(self, machine):
        regs = machine.regs
        case = self.case
        side = regs[RCX] & 0xFF
        self.expect(regs[RSI] == SP, "open state")
        self.events.append(("open", regs[RDX], side))
        answer = case.fail.get(side, 0)
        memory = machine.memory
        if answer == "error":
            memory.write(regs[RDI], 1, 1)
            return
        memory.write(regs[RDI], 1, 0)
        memory.write(regs[RDI] + 8, 8, answer)

    def on_q_clone(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == RECORD, "record copy")
        self.events.append(("record copy",))

    def on_q_insert(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == T + 0x100, "question table")
        self.events.append(("insert question", regs[RDX]))
        machine.memory.write(regs[RDI], 8, self.case.status)

    def on_q_drop(self, machine):
        self.events.append(("drop old",))

    def on_link(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == T + 0xA0, "link table")
        self.events.append(("link", regs[RSI], regs[RDX]))

    def on_spot_user(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.expect(regs[RDI] == SP, "spot state")
        at = regs[RSI]
        token = int.from_bytes(memory.bytes_at(at + 12, 8), "big")
        self.expect(memory.bytes_at(at, 12) == b"\x32" + bytes(11), "system address")
        self.events.append(("spot user", token))
        regs[RAX] = SPOT_REC

    def text(self, data):
        at = self.str_cur
        self.str_cur += (len(data) + 8) & ~7
        self.machine.memory.put_bytes(at, data)
        return at

    def alloc_node(self, layout):
        at = self.node_cur
        self.node_cur += layout.size
        memory = self.machine.memory
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF for index in range(layout.size)))
        return at

    def u64_node(self, layout, items, children=(), stale=None):
        at = self.alloc_node(layout)
        memory = self.machine.memory
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(11):
            key = stale if stale is not None and slot >= len(items) else 0x5A5A0000 + slot
            memory.write(at + layout.key_at + 8 * slot, 8, key)
        for slot, (key, value) in enumerate(items):
            memory.write(at + layout.key_at + 8 * slot, 8, key)
            for index, word in enumerate(value):
                memory.write(at + layout.val_at + layout.val_size * slot + 8 * index, 8, word)
        for slot, child in enumerate(children):
            memory.write(at + layout.edge_at + 8 * slot, 8, child)
        return at


    def set_node(self, items, children=(), stale=None):
        at = self.u64_node(L_SET, [(key, ()) for key in items], children, stale=stale)
        memory = self.machine.memory
        memory.write(at, 8, 0)
        for slot, child in enumerate(children):
            memory.write(child, 8, at)
            memory.write(child + 0x60, 2, slot)
        return at

    def set_tree(self, keys, stale=None):
        """Sorted keys into a set: one leaf up to 11 keys, else leaves of 5 below one root."""
        keys = sorted(keys)
        if not keys:
            return 0, 0xFEED
        if len(keys) <= 11:
            return self.set_node(keys, stale=stale), 0
        parts, seps, at = [], [], 0
        while at < len(keys):
            parts.append(keys[at:at + 5])
            at += 5
            if at < len(keys):
                seps.append(keys[at])
                at += 1
        return self.set_node(seps, [self.set_node(part, stale=stale) for part in parts]), 1

    def table(self, ctrl, stride, head, keys, crowd_key=None, crowd=0):
        """A real hashbrown layout: control bytes after the group, values below; decoys share the target hash."""
        memory = self.machine.memory
        mask = BUCKETS - 1
        memory.put_bytes(ctrl, bytes([0xFF]) * (BUCKETS + 16))
        memory.put_bytes(ctrl - stride * BUCKETS, bytes((index * 11 + 3) & 0xFF or 1 for index in range(stride * BUCKETS)))
        memory.write(head, 8, ctrl)
        memory.write(head + 8, 8, mask)
        memory.write(head + 0x10, 8, BUCKETS)
        where = {}

        def place(key):
            value = self.over.get(key, hash_of(key))
            pos, step = value & mask, 0
            while True:
                group = [memory.read(ctrl + pos + index, 1) for index in range(16)]
                free = [index for index, byte in enumerate(group) if byte & 0x80]
                if free:
                    break
                step += 16
                pos = (pos + step) & mask
            slot = (pos + free[0]) & mask
            for index in (slot, ((slot - 16) & mask) + 16):
                memory.write(ctrl + index, 1, value >> 57)
            at = ctrl - stride * (slot + 1)
            memory.write(at, 8, key)
            where[key] = at
            return at

        if crowd_key is not None:
            target = self.over.get(crowd_key, hash_of(crowd_key))
            for index in range(crowd):
                decoy = crowd_key + 0x10000 + index
                self.over[decoy] = target
                place(decoy)
        for key in sorted(keys):
            place(key)
        memory.write(head + 0x18, 8, len(keys) + (crowd if crowd_key is not None else 0))
        return where

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, HEAP_FILL)
        self.case, self.events, self.node_cur, self.str_cur, self.alloc_cur = case, [], NODES, STRS, ALLOC_AT
        self.over, self.named_once, self.named_count, self.settle_count, self.dropped = {}, False, 0, 0, False
        self.states = (S + 0x180, S + 0x1B0, S + 0x150, SP + 0x100)
        memory.put_bytes(USER_AT, case.user.to_bytes(20, "big"))
        memory.write(S + 0x1E8, 1, case.poison)
        memory.write(S + 0x1D8, 8, case.used)
        memory.write(S + 0x1C0, 8, case.nexto)
        memory.write(S + 0x1C8, 8, case.nextq)
        memory.write(S + 0x218, 8, case.tokens)
        entry = case.entry
        if entry in HANDLERS:
            memory.write(S + HANDLERS[entry]["chain"], 1, case.chain)
        crowded = case.crowd
        keys_o = dict(case.outcomes)
        keys_q = dict(case.questions)
        for key in list(keys_o) + list(keys_q) + list(case.links):
            hash_of(key)
        at_o = self.table(OUT_CTRL, 0x90, S + 0x160, keys_o, case.oid if crowded else None, crowded)
        at_q = self.table(Q_CTRL, 0x70, S + 0x190, keys_q, case.qid if crowded else None, crowded)
        at_l = self.table(L_CTRL, 0x10, S + 0x130, case.links, case.oid if crowded else None, crowded)
        case.at_record = at_q if entry == DESC_Q else at_o
        for key, at in at_o.items():
            if key not in keys_o:
                continue
            rec = keys_o[key]
            sides = rec.get("sides", (11, 12))
            name, desc = self.text(rec.get("name", b"alpha")), self.text(rec.get("desc", b"first text"))
            memory.write(at + 0x28, 8, sides[0])
            memory.write(at + 0x50, 8, sides[1])
            memory.write(at + 0x58, 8, 0)
            memory.write(at + 0x60, 8, name)
            memory.write(at + 0x68, 8, len(rec.get("name", b"alpha")))
            memory.write(at + 0x70, 8, rec.get("cap", 16))
            memory.write(at + 0x78, 8, desc)
            memory.write(at + 0x80, 8, len(rec.get("desc", b"first text")))
        self.set_heads = {}
        for key, at in at_q.items():
            if key not in keys_q:
                continue
            rec = keys_q[key]
            name, desc = self.text(rec.get("name", b"alpha")), self.text(rec.get("desc", b"first text"))
            memory.write(at + 8, 8, 16)
            memory.write(at + 0x10, 8, name)
            memory.write(at + 0x18, 8, len(rec.get("name", b"alpha")))
            memory.write(at + 0x20, 8, rec.get("cap", 16))
            memory.write(at + 0x28, 8, desc)
            memory.write(at + 0x30, 8, len(rec.get("desc", b"first text")))
            memory.write(at + 0x38, 8, rec["fallback"])
            named = rec.get("named") or ()
            root, height = self.set_tree(named, stale=rec["fallback"])
            memory.write(at + 0x40, 8, root)
            memory.write(at + 0x48, 8, height)
            memory.write(at + 0x50, 8, len(named))
            self.set_heads[key] = (root, height, len(named))
        for key, at in at_l.items():
            if key in case.links:
                memory.write(at + 8, 8, case.links[key])
        self.fill_action(case)
        if entry == NAME or entry in (DUP_Q, DUP_O):
            name, desc = case.nd
            ptrs = self.text(name), self.text(desc)
            caps = (len(name) + 3, len(desc) + 5)
            lens = getattr(case, "nd_lens", (len(name), len(desc)))
            for index, value in enumerate((caps[0], ptrs[0], lens[0], caps[1], ptrs[1], lens[1])):
                memory.write(ND_IN + 8 * index, 8, value)
            case.nd_caps = ((caps[0], ptrs[0]), (caps[1], ptrs[1]))
        if entry == QBUILD:
            for index, value in enumerate((24, 0xAA00, 3, 32, 0xBB00, 4)):
                memory.write(ND_IN + 8 * index, 8, value)
        if entry in WRAPS or entry in (DESC_Q, DESC_O):
            cap = case.cap
            for index, value in enumerate((cap, 0xCC00, case.dlen)):
                memory.write(DETAILS + 8 * index, 8, value)
        if entry == DUP_Q or entry == DUP_O:
            self.key_tree = self.set_tree(list(case.questions if entry == DUP_Q else case.outcomes), stale=case.oid)
        if entry == OPEN:
            self.spot_fixture(case)
        if entry == QINSERT:
            memory.put_bytes(RECORD, bytes((index * 3 + 7) & 0xFF for index in range(0x78)))
        return bytes(memory.heap[:USED])

    def small_tree(self, layout, items, head):
        """One leaf, or with `deep` one separator above two leaves; a stale unused slot holds a later key."""
        memory = self.machine.memory
        if len(items) >= 3 and self.case.deep:
            left = self.u64_node(layout, items[:1], stale=items[-1][0])
            right = self.u64_node(layout, items[2:], stale=items[0][0])
            root = self.u64_node(layout, items[1:2], (left, right), stale=items[0][0])
            memory.write(head, 8, root)
            memory.write(head + 8, 8, 1)
            return
        memory.write(head, 8, self.u64_node(layout, items, stale=999))
        memory.write(head + 8, 8, 0)

    def spot_fixture(self, case):
        memory = self.machine.memory
        head = SP + 0x388
        if case.supply is None:
            memory.write(head, 8, 0)
            memory.write(head + 8, 8, 0)
        else:
            self.small_tree(L_SUPPLY, [(key, (case.supply[key],)) for key in sorted(case.supply)], head)
        balances = case.balances
        if balances is None:
            memory.write(SPOT_REC + 0x10, 8, 0)
            memory.write(SPOT_REC + 0x18, 8, 0)
        else:
            self.small_tree(L_BALANCE, [(key, (balances[key], 0x71, 0x72)) for key in sorted(balances)], SPOT_REC + 0x10)

    def fill_action(self, case):
        memory = self.machine.memory
        memory.put_bytes(ACTION, bytes((index * 5 + 9) & 0xFF for index in range(0x90)))
        a = ACTION
        arm = case.arm
        word = (1 << 63) | arm if arm != 3 else case.cap
        memory.write(a, 8, word)
        case.list_at = 0x7000
        if arm == 0:
            memory.write(a + 8, 8, case.x)
        elif arm == 1:
            memory.write(a + 0x78, 8, case.quote)
        elif arm == 2:
            memory.write(a + 0x68, 8, case.quote)
        elif arm == 3:
            memory.write(a + 0x68, 8, 0x7000)
            memory.write(a + 0x70, 8, case.n)
            memory.write(a + 0x78, 8, case.quote)
        elif arm == 4:
            memory.write(a + 0x18, 8, case.flen)
            memory.write(a + 0x30, 8, case.dlen)
            memory.write(a + 0x38, 8, case.oid)
        elif arm == 5:
            memory.write(a + 8, 8, case.qid)
            memory.write(a + 0x10, 8, 0x7100 if case.root else 0)
            memory.write(a + 0x18, 8, 0x55)
            memory.write(a + 0x20, 8, case.mlen)
        elif arm == 6:
            memory.write(a + 0x20, 8, case.oid)
        elif arm == 7:
            memory.write(a + 0x38, 8, case.oid)
        elif arm == 8:
            memory.write(a + 8, 8, case.qid)
            memory.write(a + 0x10, 8, case.oid)
        else:
            memory.write(a + 0x20, 8, case.qid)

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        memory = machine.memory
        entry = case.entry
        calls = machine.calls
        machine.real = frozenset((entry,))
        try:
            if entry in HANDLERS:
                role = None
                machine.run(entry, {RDI: OUT, RSI: S, RDX: USER_AT, RCX: ACTION})
            elif entry in WRAPS:
                machine.xmm[0] = case.bits
                machine.run(entry, {RDI: OUT, RSI: S, RDX: USER_AT, RCX: case.oid, R8: DETAILS})
            elif entry == GATE:
                machine.xmm[0] = case.bits
                machine.run(GATE, {RDI: OUT, RSI: T, RDX: case.oid})
            elif entry == NAME:
                machine.run(NAME, {RDI: OUT, RSI: ND_IN})
            elif entry == DESC_Q:
                machine.run(DESC_Q, {RDI: OUT, RSI: T, RDX: case.qid, RCX: DETAILS})
            elif entry == DESC_O:
                machine.run(DESC_O, {RDI: OUT, RSI: T, RDX: case.oid, RCX: DETAILS})
            elif entry == QBUILD:
                machine.run(QBUILD, {RDI: OUT, RSI: T, RDX: case.oid, RCX: ND_IN, R8: SP})
            elif entry == OPEN:
                machine.run(OPEN, {RDI: OUT, RSI: SP, RDX: case.oid, RCX: case.side})
                if memory.read(OUT, 1) == 1:
                    memory.put_bytes(OUT + 8, before[OUT - HEAP_BASE + 8:OUT - HEAP_BASE + 16])
                else:
                    memory.put_bytes(OUT + 1, before[OUT - HEAP_BASE + 1:OUT - HEAP_BASE + 2])
            elif entry == QINSERT:
                machine.run(QINSERT, {RDI: OUT, RSI: T, RDX: RECORD})
            elif entry == YESNO:
                machine.run(YESNO, {RDI: OUT})
            else:
                machine.run(entry, {RDI: OUT, RSI: T, RDX: ND_IN})
        except Panicked as panic:
            return before, ("panic", str(panic), [], tuple(self.events), None, None)
        return before, ("run", bytes(memory.heap[:USED]), [], tuple(self.events), None, None)



def same(got, want):
    return got[:5] == want[:5]


def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & TOP
        yield state


FRACTIONS = (("zero", 0), ("negative zero", 1 << 63), ("half", 0x3FE0000000000000), ("one", ONE), ("just above one", ONE + 1), ("just below one", ONE - 1), ("two", 0x4000000000000000), ("smallest subnormal", 1),
             ("largest subnormal", 0x000FFFFFFFFFFFFF), ("smallest normal", 0x0010000000000000), ("negative subnormal", (1 << 63) | 1), ("negative largest subnormal", (1 << 63) | 0x000FFFFFFFFFFFFF), ("negative normal", 0xBFE0000000000000),
             ("negative one", 0xBFF0000000000000), ("negative huge", 0xFFEFFFFFFFFFFFFF), ("largest finite", 0x7FEFFFFFFFFFFFFF), ("infinity", 0x7FF0000000000000), ("negative infinity", 0xFFF0000000000000), ("quiet nan", 0x7FF8000000000000),
             ("negative nan", 0xFFF8000000000001), ("signalling nan", 0x7FF0000000000001))


def handler_cases():
    cases = []
    add = cases.append
    for entry in sorted(HANDLERS):
        tag = "%x " % entry
        for arm in range(10):
            add(Case(tag + "arm %d happy" % arm, entry=entry, arm=arm, quote=3, oid=21, qid=41, n=2))
        for chain in (0, 1, 2, 3, 4, 255):
            add(Case(tag + "system user chain %d" % chain, entry=entry, user=0, chain=chain, arm=7))
            add(Case(tag + "signed user chain %d" % chain, entry=entry, chain=chain, arm=7))
        add(Case(tag + "user one low byte", entry=entry, user=1, chain=3, arm=7))
        add(Case(tag + "user one high byte", entry=entry, user=1 << 152, chain=3, arm=7))
        add(Case(tag + "user at byte 16", entry=entry, user=1 << 24, chain=3, arm=7))
        add(Case(tag + "poison", entry=entry, poison=1, arm=7))
        add(Case(tag + "poison system mainnet", entry=entry, user=0, poison=1, chain=3, arm=7))
        add(Case(tag + "chain before poison", entry=entry, poison=1, chain=3, arm=7))
        add(Case(tag + "question ids over", entry=entry, arm=3, nextq=10000))
        add(Case(tag + "too many names", entry=entry, arm=3, n=51))
        add(Case(tag + "daily over", entry=entry, arm=1, user=0, chain=3, used=50))
    tag = ""
    for arm in (1, 2):
        for chain, used, label in ((2, 499, "testnet last"), (2, 500, "testnet over"), (3, 49, "main last"), (3, 50, "main over"), (4, 50, "byte 4 over"), (1, 10 ** 6, "byte 1 free"), (0, 10 ** 6, "byte 0 free"), (3, TOP, "main saturated"), (3, TOP - 1, "main one below"), (2, TOP, "testnet saturated")):
            add(Case("arm %d %s" % (arm, label), arm=arm, user=0, chain=chain, used=used))
        add(Case("arm %d name refused" % arm, arm=arm, fail={"name": TAG_LEN}))
        add(Case("arm %d duplicate" % arm, arm=arm, fail={"dup outcome": TAG_TEXT}))
        add(Case("arm %d deploy refused" % arm, arm=arm, fail={"deploy": 0xEF}))
    add(Case("arm 1 quote last", arm=1, quote=9))
    add(Case("arm 1 quote at count", arm=1, quote=10))
    add(Case("arm 1 quote huge", arm=1, quote=TOP))
    add(Case("arm 1 no tokens", arm=1, quote=0, tokens=0))
    add(Case("arm 2 quote not bounded here", arm=2, quote=10 ** 6))
    add(Case("arm 0 cap edge below", arm=0, x=CAP - 1))
    add(Case("arm 0 cap edge at", arm=0, x=CAP))
    add(Case("arm 0 huge", arm=0, x=TOP))
    add(Case("arm 0 zero", arm=0, x=0))
    add(Case("arm 0 refused", arm=0, fail={"token": 0x7E}))
    add(Case("arm 3 question last", arm=3, nextq=9999))
    add(Case("arm 3 question over", arm=3, nextq=10000))
    add(Case("arm 3 question huge", arm=3, nextq=TOP))
    add(Case("arm 3 outcome ids last", arm=3, nexto=20000 - 3, n=2))
    add(Case("arm 3 outcome ids over", arm=3, nexto=20000 - 2, n=2))
    add(Case("arm 3 outcome ids saturate", arm=3, nexto=TOP, n=2))
    add(Case("arm 3 outcome ids carry", arm=3, nexto=TOP - 2, n=2))
    add(Case("arm 3 outcome ids exact wrap", arm=3, nexto=TOP - 2, n=1))
    add(Case("arm 3 fifty names", arm=3, n=50))
    add(Case("arm 3 fifty one names", arm=3, n=51))
    add(Case("arm 3 no names", arm=3, n=0))
    add(Case("arm 3 main daily last", arm=3, user=0, chain=3, used=47, n=2))
    add(Case("arm 3 main daily over", arm=3, user=0, chain=3, used=48, n=2))
    add(Case("arm 3 test daily last", arm=3, user=0, chain=2, used=497, n=2))
    add(Case("arm 3 test daily over", arm=3, user=0, chain=2, used=498, n=2))
    add(Case("arm 3 daily saturates", arm=3, user=0, chain=3, used=TOP, n=2))
    add(Case("arm 3 daily carry", arm=3, user=0, chain=3, used=TOP - 2, n=2))
    add(Case("arm 3 byte 1 free", arm=3, user=0, chain=1, used=10 ** 6, n=2))
    add(Case("arm 3 limits checked before names", arm=3, n=51, nextq=10000))
    add(Case("arm 3 ids before length", arm=3, n=60, nexto=20000))
    add(Case("arm 3 length before daily", arm=3, n=60, user=0, chain=3, used=50))
    add(Case("arm 3 main fifty names", arm=3, n=49, user=0, chain=3))
    add(Case("arm 3 main fifty names over", arm=3, n=50, user=0, chain=3))
    for key, tagv in (("name", 0x143), ("dup question", 0x17B), ("name 2", 0x143), ("map names", 0x143), ("deploy", 0xEF), ("outcomes", 0x7E), ("question", 0x17D)):
        add(Case("arm 3 %s refused" % key, arm=3, fail={key: tagv}))
    add(Case("arm 3 first named refused", arm=3, n=3, fail_at=0, fail={"named": 0x17B}))
    add(Case("arm 3 last named refused", arm=3, n=3, fail_at=2, fail={"named": 0x17B}))
    for arm, key in ((4, "oid"), (6, "oid"), (7, "oid"), (8, "qid"), (9, "qid"), (5, "qid")):
        add(Case("arm %d missing" % arm, arm=arm, **{key: 77}))
        add(Case("arm %d crowded hit" % arm, arm=arm, crowd=40))
        add(Case("arm %d crowded miss" % arm, arm=arm, crowd=40, **{key: 77}))
        add(Case("arm %d empty maps" % arm, arm=arm, outcomes={}, questions={}, oid=21, qid=41))
    add(Case("arm 4 fraction text 100", arm=4, flen=100))
    add(Case("arm 4 fraction text 101", arm=4, flen=101))
    add(Case("arm 4 details 2000", arm=4, dlen=2000))
    add(Case("arm 4 details 2001", arm=4, dlen=2001))
    add(Case("arm 4 parse refused", arm=4, fail={"parse": 0x7E}))
    add(Case("arm 4 parse before details", arm=4, dlen=5000, fail={"parse": 0x7E}))
    add(Case("arm 4 settle refused", arm=4, fail={"settle": 0x17B}))
    add(Case("arm 5 fifty rows", arm=5, mlen=50))
    add(Case("arm 5 fifty one rows", arm=5, mlen=51))
    add(Case("arm 5 empty map", arm=5, root=0, mlen=0))
    add(Case("arm 5 empty root stale length", arm=5, root=0, mlen=9))
    add(Case("arm 5 collect refused", arm=5, fail={"collect": 0x143}))
    add(Case("arm 5 settle refused", arm=5, fail={"settle question": 0x17B}))
    add(Case("arm 6 refused", arm=6, fail={"change": 0x143}))
    add(Case("arm 7 name refused", arm=7, fail={"name": 0x143}))
    add(Case("arm 7 question refused", arm=7, fail={"question": 0x17B}))
    add(Case("arm 8 find refused", arm=8, fail={"find": 0xEC}))
    add(Case("arm 8 named refused", arm=8, fail={"named": 0x17D}))
    add(Case("arm 9 refused", arm=9, fail={"change": 0x140}))
    return cases


def wrap_cases():
    cases = []
    add = cases.append
    for entry in sorted(WRAPS):
        tag = "%x " % entry
        for name, bits in FRACTIONS:
            add(Case(tag + "price " + name, entry=entry, bits=bits))
        add(Case(tag + "gate refused", entry=entry, gate=0x17B))
        add(Case(tag + "gate refused empty details", entry=entry, gate=0x17B, cap=0))
        add(Case(tag + "bad price empty details", entry=entry, bits=ONE + 1, cap=0))
        add(Case(tag + "settle fails", entry=entry, settle=(0x11,)))
        add(Case(tag + "settle fails system", entry=entry, settle=(0x11,), user=0))
        add(Case(tag + "user only high byte", entry=entry, settle=(0x11,), user=1 << 152))
        add(Case(tag + "user only byte 16", entry=entry, settle=(0x11,), user=1 << 24))
        add(Case(tag + "winner", entry=entry, gate=("some", 21), bits=ONE, settle=(SETTLED, SETTLED)))
        add(Case(tag + "winner first fails", entry=entry, gate=("some", 21), bits=ONE, settle=(0x11,)))
        add(Case(tag + "winner fallback fails", entry=entry, gate=("some", 21), bits=ONE, settle=(SETTLED, 0x11)))
        add(Case(tag + "winner fallback fails system", entry=entry, gate=("some", 21), bits=ONE, settle=(SETTLED, 0x11), user=0))
    return cases


def gate_cases():
    cases = []
    add = cases.append
    linked = dict(links={22: 41, 21: 41, 23: 41}, oid=22, questions={41: dict(fallback=21, named=(22,))})
    add(Case("gate no link", entry=GATE))
    add(Case("gate empty link map", entry=GATE, links={}, oid=22))
    add(Case("gate crowded link", entry=GATE, crowd=40, **linked))
    add(Case("gate crowded no link", entry=GATE, crowd=40, oid=30, links={22: 41}))
    add(Case("gate question gone", entry=GATE, links={22: 42}, oid=22))
    add(Case("gate question gone empty", entry=GATE, links={22: 42}, oid=22, questions={}))
    add(Case("gate crowded question gone", entry=GATE, links={22: 77}, oid=22, qid=77, crowd=40))
    add(Case("gate fallback", entry=GATE, links={21: 41}, oid=21, bits=0))
    add(Case("gate fallback one", entry=GATE, links={21: 41}, oid=21, bits=ONE))
    for name, bits in FRACTIONS:
        add(Case("gate " + name, entry=GATE, bits=bits, **linked))
    for named in ((), (22,), (22, 23), (22, 23, 24), tuple(range(22, 40))):
        add(Case("gate one with %d named" % len(named), entry=GATE, bits=ONE, links={22: 41}, oid=22, questions={41: dict(fallback=21, named=named)}))
        add(Case("gate half with %d named" % len(named), entry=GATE, bits=0x3FE0000000000000, links={22: 41}, oid=22, questions={41: dict(fallback=21, named=named)}))
    return cases


def named_cases():
    cases = handler_cases() + wrap_cases() + gate_cases()
    add = cases.append

    def nd(name, name_len, desc_len):
        case = Case(name, entry=NAME, nd=(b"abcd", b"efgh"))
        case.nd_lens = (name_len, desc_len)
        add(case)

    for a, b in ((0, 0), (100, 2000), (101, 0), (0, 2001), (101, 2001), (100, 2001), (101, 2000), (TOP, 1), (1, TOP)):
        nd("lengths %d %d" % (a, b), a, b)
    for entry, key in ((DESC_Q, "qid"), (DESC_O, "oid")):
        tag = NAMES[entry] + " "
        add(Case(tag + "ok", entry=entry))
        add(Case(tag + "2000", entry=entry, dlen=2000))
        add(Case(tag + "2001", entry=entry, dlen=2001))
        add(Case(tag + "2001 no capacity", entry=entry, dlen=2001, cap=0))
        add(Case(tag + "missing", entry=entry, **{key: 77}))
        add(Case(tag + "missing no capacity", entry=entry, cap=0, **{key: 77}))
        add(Case(tag + "empty", entry=entry, outcomes={}, questions={}))
        add(Case(tag + "crowded hit", entry=entry, crowd=40))
        add(Case(tag + "crowded miss", entry=entry, crowd=40, **{key: 77}))
        add(Case(tag + "old has no capacity", entry=entry, outcomes={21: dict(cap=0)}, questions={41: dict(fallback=21, cap=0)}))
    add(Case("record ok", entry=QBUILD))
    add(Case("record id 9999", entry=QBUILD, nextq=9999))
    add(Case("record id 10000", entry=QBUILD, nextq=10000))
    add(Case("record id huge", entry=QBUILD, nextq=TOP))
    add(Case("record id taken", entry=QBUILD, nextq=41))
    add(Case("record id taken crowded", entry=QBUILD, nextq=41, qid=41, crowd=40))
    add(Case("record id free crowded", entry=QBUILD, nextq=42, qid=42, crowd=40))
    add(Case("record empty questions", entry=QBUILD, questions={}))
    add(Case("record fallback linked", entry=QBUILD, links={21: 41}, nextq=42))
    add(Case("record fallback linked crowded", entry=QBUILD, links={21: 41}, nextq=42, crowd=40))
    add(Case("record fallback free crowded", entry=QBUILD, links={22: 41}, nextq=42, crowd=40))
    add(Case("record side 0 error", entry=QBUILD, fail={0: "error"}))
    add(Case("record side 1 error", entry=QBUILD, fail={1: "error"}))
    add(Case("record side 0 held", entry=QBUILD, fail={0: 5}))
    add(Case("record side 1 held", entry=QBUILD, fail={1: 5}))
    add(Case("record one unit held", entry=QBUILD, fail={1: 1}))
    add(Case("record high word held", entry=QBUILD, fail={0: 1 << 40}))
    base = dict(entry=OPEN, oid=21)
    for side in (0, 1):
        tag = "open side %d " % side
        add(Case(tag + "missing outcome", side=side, entry=OPEN, oid=77))
        add(Case(tag + "empty", side=side, entry=OPEN, outcomes={}))
        add(Case(tag + "crowded hit", side=side, crowd=40, supply={11: 9, 12: 8}, balances={11: 3, 12: 2}, **base))
        add(Case(tag + "crowded miss", side=side, crowd=40, entry=OPEN, oid=77))
        add(Case(tag + "no supply map", side=side, **base))
        add(Case(tag + "token not in supply", side=side, supply={5: 1, 13: 2}, **base))
        add(Case(tag + "no balance tree", side=side, supply={11: 9, 12: 8}, **base))
        add(Case(tag + "no balance row", side=side, supply={11: 9, 12: 8}, balances={5: 3, 13: 3}, **base))
        add(Case(tag + "all held", side=side, supply={11: 9, 12: 8}, balances={11: 9, 12: 8}, **base))
        add(Case(tag + "partly held", side=side, supply={11: 9, 12: 8}, balances={11: 3, 12: 2}, **base))
        add(Case(tag + "more held than supply", side=side, supply={11: 9, 12: 8}, balances={11: 10, 12: 9}, **base))
        add(Case(tag + "row after token", side=side, supply={11: 9, 12: 8, 13: 1}, balances={10: 1, 13: 3}, **base))
        add(Case(tag + "deep left", side=side, deep=True, supply={side + 11: 9, 20: 8, 21: 1}, balances={side + 11: 3, 20: 2, 21: 1}, **base))
        add(Case(tag + "deep separator", side=side, deep=True, supply={5: 9, side + 11: 8, 21: 1}, balances={5: 3, side + 11: 2, 21: 1}, **base))
        add(Case(tag + "deep right", side=side, deep=True, supply={5: 9, 6: 8, side + 11: 1}, balances={5: 3, 6: 2, side + 11: 1}, **base))
        add(Case(tag + "deep missing", side=side, deep=True, supply={5: 9, 6: 8, 7: 1}, balances={5: 3, 6: 2, 7: 1}, **base))
        add(Case(tag + "deep no balance", side=side, deep=True, supply={5: 9, side + 11: 8, 21: 1}, balances={5: 3, 6: 2, 7: 1}, **base))
    add(Case("insert new", entry=QINSERT, status=2 ** 63))
    add(Case("insert replaced", entry=QINSERT, status=5))
    add(Case("insert counter saturates", entry=QINSERT, status=2 ** 63, nextq=TOP))
    add(Case("insert counter edge", entry=QINSERT, status=2 ** 63, nextq=TOP - 1))
    add(Case("yes no", entry=YESNO))
    outcomes = {21: dict(name=b"alpha", desc=b"first text"), 22: dict(name=b"beta", desc=b"second"), 23: dict(name=b"gamma", desc=b"third")}
    many = {key: dict(name=b"n%d" % key, desc=b"d%d" % key) for key in range(30, 60)}
    many[50] = dict(name=b"beta", desc=b"second")
    questions = {41: dict(fallback=21, name=b"alpha", desc=b"first text"), 42: dict(fallback=22, name=b"beta", desc=b"second")}
    for entry, tag, pool, field in ((DUP_O, "standalone ", outcomes, "outcomes"), (DUP_Q, "question ", questions, "questions")):
        def dup(name, nd, **fields):
            fields.setdefault(field, pool)
            add(Case(tag + name, entry=entry, nd=nd, **fields))

        dup("same", (b"beta", b"second"))
        dup("first same", (b"alpha", b"first text"))
        dup("name differs", (b"betb", b"second"))
        dup("name shorter", (b"bet", b"second"))
        dup("name longer", (b"betaa", b"second"))
        dup("text differs", (b"beta", b"seconb"))
        dup("text shorter", (b"beta", b"secon"))
        dup("text longer", (b"beta", b"secondd"))
        dup("names swapped", (b"second", b"beta"))
        dup("other pair", (b"alpha", b"second"))
        dup("empty pool", (b"beta", b"second"), **{field: {}})
    add(Case("standalone linked same is free", entry=DUP_O, nd=(b"beta", b"second"), outcomes=outcomes, links={22: 41}))
    add(Case("standalone unlinked other", entry=DUP_O, nd=(b"beta", b"second"), outcomes=outcomes, links={21: 41}))
    add(Case("standalone crowded links", entry=DUP_O, nd=(b"beta", b"second"), outcomes=outcomes, links={22: 41}, crowd=40, oid=22))
    add(Case("standalone crowded hit", entry=DUP_O, nd=(b"beta", b"second"), outcomes=outcomes, crowd=40, oid=22))
    add(Case("standalone tree", entry=DUP_O, nd=(b"beta", b"second"), outcomes=many))
    add(Case("standalone tree miss", entry=DUP_O, nd=(b"beta", b"zzz"), outcomes=many))
    add(Case("question tree", entry=DUP_Q, nd=(b"beta", b"second"), questions={key: dict(many[key], fallback=21) for key in many}))
    add(Case("question tree miss", entry=DUP_Q, nd=(b"beta", b"zzz"), questions={key: dict(many[key], fallback=21) for key in many}))
    add(Case("question crowded hit", entry=DUP_Q, nd=(b"beta", b"second"), questions=questions, crowd=40, qid=42))
    return cases


def vector_cases(count):
    rand = lcg(0x94)
    cases = []
    spots = [0, 1, 2, 3, 47, 48, 49, 50, 51, 497, 499, 500, 501, 9999, 10000, 19997, 19998, 20000, TOP - 1, TOP]
    for index in range(count):
        draw = [next(rand) for _ in range(10)]
        kind = draw[0] % 4
        if kind == 0:
            cases.append(Case("v%d" % index, entry=TARGET_HANDLERS[draw[1] % 3], arm=draw[2] % 10, user=0 if draw[3] & 1 else USER, chain=draw[4] % 5, used=spots[draw[5] % len(spots)], n=draw[6] % 53, nexto=spots[draw[7] % len(spots)],
                              nextq=spots[draw[8] % len(spots)], quote=draw[9] % 13, x=(draw[9] >> 4) if draw[9] & 8 else draw[9] & 0xFF, oid=21 + (draw[5] & 1) * 55, qid=41 + (draw[6] & 1) * 36))
        elif kind == 1:
            bits = FRACTIONS[draw[1] % len(FRACTIONS)][1] if draw[2] & 1 else draw[3]
            cases.append(Case("v%d" % index, entry=sorted(WRAPS)[draw[4] % 3], bits=bits, user=0 if draw[5] & 1 else USER, settle=(SETTLED if draw[6] & 1 else 0x11, SETTLED if draw[7] & 1 else 0x11), gate="none" if draw[8] & 1 else ("some", 21)))
        elif kind == 2:
            bits = FRACTIONS[draw[1] % len(FRACTIONS)][1] if draw[2] & 1 else draw[3]
            named = tuple(range(22, 22 + draw[4] % 5))
            cases.append(Case("v%d" % index, entry=GATE, bits=bits, oid=22 + draw[5] % 2 - 1, links={21: 41, 22: 41}, questions={41: dict(fallback=21, named=named)}))
        else:
            cases.append(Case("v%d" % index, entry=QBUILD, nextq=spots[draw[1] % len(spots)], oid=21, links={21: 41} if draw[2] & 3 == 0 else {}, fail={0: draw[3] % 3 and 0}))
    return cases


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        before, got = harness.run(case)
        want = spec_run(case, before)
        if not same(got, want):
            raise EvidenceError("case disagrees with the rule list: %s" % case.name + diff_text(got, want))
        outcomes.append((got, want[5]))
    return outcomes


def diff_text(got, want):
    if got[0] != want[0]:
        return " form %r %r" % (got[:2] if got[0] != "run" else got[0], want[:2] if want[0] != "run" else want[0])
    if got[1] != want[1]:
        at = next(index for index in range(len(got[1])) if got[1][index] != want[1][index])
        return " heap +%#x got %s want %s" % (at, got[1][at:at + 16].hex(), want[1][at:at + 16].hex())
    return " events %r %r" % (got[3], want[3])


def text_at(image, arm):
    start = image.offset(arm)
    data = bytes(image.blob[start:start + 40])
    at = data.find(b"\x48\x8d\x35")
    if at < 0 or data[at + 7] != 0xBA:
        raise EvidenceError("no text at %#x" % arm)
    target = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
    size = struct.unpack_from("<I", data, at + 8)[0]
    return bytes(image.blob[image.offset(target):image.offset(target) + size]).decode()


def arm_of(image, table, index):
    return table + struct.unpack_from("<i", image.blob, image.offset(table) + 4 * index)[0]


def text_rows(image):
    rows = []
    for tag in (TAG_CHAIN, TAG_LEN, TAG_NUM, TAG_OUTCOME, TAG_QUESTION, TAG_TOKEN, TAG_INPUT):
        rows.append(("tag", "%#x" % tag, text_at(image, arm_of(image, TEXT_TABLE, tag))))
    for code in STATUS_CODES:
        rows.append(("status", code, text_at(image, arm_of(image, STATUS_TABLE, code))))
    for name, (address, size) in sorted(TEXTS.items()):
        rows.append(("refusal", name, bytes(image.blob[image.offset(address):image.offset(address) + size]).decode()))
    return rows


ARM_NAMES = ("RegisterOutcomeToken", "RegisterOutcome", "RegisterTokensAndStandaloneOutcome", "RegisterTokensAndQuestion", "SettleOutcome", "SettleQuestion", "ChangeOutcomeDescription", "RegisterQuestion", "RegisterNamedOutcome", "ChangeQuestionDescription")
ARM_ELEMENTS = (1, 3, 3, 4, 3, 2, 2, 2, 2, 2)


def arm_rows(image):
    rows = []
    for index in range(10):
        text = ("struct variant OutcomeDeploy::%s with %d element" % (ARM_NAMES[index], ARM_ELEMENTS[index])).encode()
        if bytes(image.blob).find(text) < 0:
            raise EvidenceError("no text for %s" % ARM_NAMES[index])
        rows.append((index, ARM_NAMES[index], ARM_ELEMENTS[index]) + tuple("%#x" % arm_of(image, HANDLERS[entry]["table"], index) for entry in sorted(HANDLERS)))
    return rows


def strings_row(image):
    blob = bytes(image.blob)
    run = b"registerOutcomeToken"
    at = blob.find(run)
    if at < 0:
        raise EvidenceError("no variant name run")
    end = at
    while 0x20 < blob[end] < 0x7F:
        end += 1
    return [("%#x" % at, blob[at:end].decode())]


def location_rows(image):
    rows = []
    relative = image.relative()
    for role in WRAPS.values():
        at = role["location"]
        pointer = relative.get(at)
        size = struct.unpack_from("<Q", image.blob, image.offset(at) + 8)[0]
        line, column = struct.unpack_from("<II", image.blob, image.offset(at) + 16)
        text = bytes(image.blob[image.offset(pointer):image.offset(pointer) + size]).decode()
        rows.append(("%#x" % at, "l1/" + text.split("/l1/")[-1] if "/l1/" in text else text.rsplit("/", 1)[-1], line, column))
    return sorted(set(rows))


def holder_rows(image):
    rows = []
    relative = image.relative()
    slots = {}
    for slot, value in relative.items():
        slots.setdefault(value, []).append(slot)
    text = image.text_bytes()
    base = image.text_address if hasattr(image, "text_address") else None
    for target in TARGETS:
        rows.append(("%#x" % target, NAMES[target], " ".join("%#x" % slot for slot in sorted(slots.get(target, ())))))
    return rows


def rows_of(image, target):
    return decode_range(image, *image.exact_fde(target))


def copy_rows(image):
    """Each handler copy against the first, row by row, without any text from a disassembler."""
    base = rows_of(image, HANDLER)
    out = []
    changed = set()
    for copy in (HANDLER_A, HANDLER_B):
        rows = rows_of(image, copy)
        if len(rows) != len(base):
            raise EvidenceError("copy row count")
        same_rows, moved, other = 0, 0, []
        for left, right in zip(base, rows):
            if left.data == right.data:
                same_rows += 1
            elif left.size == right.size and (left.op == "call" or left.rip_at is not None):
                moved += 1
            else:
                other.append("%#x" % right.va)
                changed.add(right.va)
        out.append(("%#x" % copy, len(rows), same_rows, moved, " ".join(other)))
    return out, changed


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


def first_failure(harness, cases):
    for case in cases:
        try:
            before, got = harness.run(case)
            if not same(got, spec_run(case, before)):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked):
            return case
    return None


SHUFFLE = "same: shuffle of a value whose bytes are all equal"
SATURATED = "same: the saturated value stays above every limit it is compared with"
DEAD_STORE = "same: this store is overwritten or never read"
EMPTY_MAP = "same or gap: shortcut for an empty map; a probe of an empty table gives the same miss, and a one-item map was not tried on this row"
PROBE_STEP = "gap: probe stride edit; crowded fixtures still find or miss the same key"
NEXT_MATCH = "gap: edit of the step to the next control match; crowded fixtures still end the same"
FREE_LIST = "gap: free of the id list on this refusal; every fixture has a non-zero capacity"
ITERATOR = "gap: key iterator word or state pointer; the stub reads only control base and item count"
WALK = "gap: tree walk or drop iterator around the stubbed key set; fixtures hold one or two levels"
EXPECTED_SURVIVORS = {}
for _rows, _kind, _text in (
        ((0x27499F0, 0x2749AC2, 0x2749E0F, 0x2749F3E, 0x274A009, 0x274A0D4, 0x3719268, 0x372988C, 0x3729A26, 0x3729AD4, 0x3729CFC, 0x3729E55, 0x3729F1E, 0x372AC53, 0x372B20A, 0x372B27C), "immediate", SHUFFLE),
        ((0x2749B4E, 0x2749D2E, 0x2749EB1, 0x274A9B2), "immediate", SATURATED),
        ((0x274989B, 0x274B4C4, 0x4D69A54, 0x4D69D14, 0x3719313), "immediate", DEAD_STORE),
        ((0x274999C, 0x2749DC2, 0x2749FBC, 0x3719221), "immediate", EMPTY_MAP),
        ((0x274999C, 0x2749DC2, 0x2749FBC, 0x3719221, 0x2749A75, 0x2749EEC, 0x274A08A, 0x3729842, 0x37299E5, 0x3729A93, 0x3729CB2, 0x3729E08, 0x3729EDF), "displacement", EMPTY_MAP),
        ((0x2749A62, 0x2749A66, 0x2749B29, 0x2749E75, 0x2749E79, 0x2749FAD, 0x274A073, 0x274A077, 0x274A13B, 0x37192D1, 0x37192D5, 0x3729901, 0x3729905, 0x3729A8D, 0x3729B39, 0x3729D65, 0x3729EC9, 0x3729F7F, 0x372AA67, 0x372B06B, 0x372B2E3, 0x372B2E7), "immediate", PROBE_STEP),
        ((0x2749A40, 0x2749B05, 0x2749E59, 0x2749F87, 0x274A053, 0x274A118, 0x37192B0, 0x37298D4, 0x3729A6B, 0x3729B17, 0x3729D3D, 0x3729E9B, 0x3729F5F, 0x372AA3D, 0x372B03C, 0x372B2C4), "displacement", NEXT_MATCH),
        ((0x274B197,), "immediate", FREE_LIST),
        ((0x372A95D, 0x372A96D, 0x372AEF0, 0x372AEFF, 0x372AFA9), "displacement", ITERATOR),
        ((0x372AB32, 0x372ABE5, 0x372B0E2, 0x372B195, 0x372B1D9, 0x372B247, 0x372B39C, 0x372B3BD, 0x372B3D9), "immediate", WALK),
        ((0x372AB7B, 0x372ABD3, 0x372B12B, 0x372B183, 0x372B1CC, 0x372B227), "displacement", WALK),
        ((0x372B1E2, 0x372B39A, 0x372B40B), "condition", WALK)):
    for _row in _rows:
        EXPECTED_SURVIVORS[_row, _kind] = _text


def run_mutants(image, table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    changed = copy_rows(image)[1]
    groups = collections.defaultdict(list)
    for case in cases:
        groups[case.entry].append(case)
    extra = vector_cases(100)
    for target in TARGETS:
        chosen = groups[target] + [case for case in extra if case.entry == target]
        reach = collections.defaultdict(list)
        for case in chosen:
            control.machine.seen = set()
            control.run(case)
            for va in control.machine.seen:
                reach[va].append(case)
        rows = [row for row in table[target] if row.va in changed] if target in (HANDLER_A, HANDLER_B) else table[target]
        for va, kind, patch in edits_for(image, rows, seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, reach[va])
            if hit is not None:
                results.append((va, kind, "killed", hit.name))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results



def analyse(image, mutate=True, vectors=400):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, texts=text_rows(image), arms=arm_rows(image), strings=strings_row(image), locations=location_rows(image), holders=holder_rows(image), copies=copy_rows(image)[0])
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    got, label = outcome
    return "%#x" % case.entry, case.name, label, hashlib.sha256(repr((got[0], got[1], got[3], got[4])).encode()).hexdigest()[:16], len(got[3])


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("texts.tsv", ("kind", "code", "text"), result["texts"])
    tsv("arms.tsv", ("index", "variant", "elements", "arm_0x2749880", "arm_0x4d66400", "arm_0x4d67e10"), result["arms"])
    tsv("strings.tsv", ("file_offset", "text"), result["strings"])
    tsv("locations.tsv", ("record", "file", "line", "column"), result["locations"])
    tsv("holders.tsv", ("function", "name", "relative_slots"), result["holders"])
    tsv("copy-rows.tsv", ("copy", "rows", "identical_bytes", "call_or_rip_moved", "other_rows"), result["copies"])
    tsv("outcomes.tsv", ("entry", "case", "result", "digest", "events"), [describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"],
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"), "survived": sum(1 for r in rows if r[2] == "survived")}
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

