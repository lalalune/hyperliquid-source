#!/usr/bin/env python3
"""RE-006: static byte evaluation of the spot price-level erase path.

The instruction evaluator below is adapted from tools/queued_row_rewrite.py
in this MIT-licensed repository. It interprets selected instructions; it never
runs the captured executable or calls an external program.
"""
import argparse
import bisect
import csv
import copy
import hashlib
import json
import math
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records

BINARY = ROOT / "artifacts/node/94/hl-node"
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
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 30000

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
        self.sections = sections(blob)
        # SHT_NOBITS sections have no file bytes, so they never resolve an address.
        self.mapped = sorted((s for s in self.sections if s["type"] != 8 and s["address"] and s["size"]),
                             key=lambda s: s["address"])
        self.named = {s["name"]: s for s in self.sections}
        _, fdes = eh_frame_records(blob, self.sections)
        ends = {}
        for row in fdes:
            if row["start"] in ends:
                raise EvidenceError("duplicate FDE start")
            ends[row["start"]] = row["end"]
        self.fde_ends = ends
        self.starts = sorted(ends)

    def offset(self, va):
        matches = [section for section in self.mapped
                   if section["address"] <= va < section["address"] + section["size"]]
        if len(matches) != 1:
            raise EvidenceError("address has no unique file-backed section: %#x" % va)
        section = matches[0]
        return va - section["address"] + section["offset"]

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

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/", "/base/", "/chrono-"):
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
SHIFTS = {0: "rol", 4: "shl", 5: "shr", 7: "sar"}


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
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1)
            if value != 0:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd", ("x", reg), rm, 8)
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
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, width)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
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
        if two == 0xA3:
            reg, rm = modrm()
            return finish("bt", rm, ("r", reg), width)
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
            return raw_at(self.image, addr, count)
        except EvidenceError:
            raise Halt("read outside one file-backed section: %#x" % addr)

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
        self.edges = set()
        self.steps = 0
        self.keep_rdx = False
        self.keep_float = False
        self.step_limit = STEP_LIMIT
        self.jump_low = self.jump_high = 0

    def read_code(self, va, count):
        data = bytearray(raw_at(self.image, va, count))
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
        self.keep_rdx = self.keep_float = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        kept = self.xmm[0]
        self.xmm = [POISON | POISON << 64] * 16
        if self.keep_float:
            self.xmm[0] = kept

    def run(self, entry, args):
        self.regs = [POISON] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
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
            dest = row.target if self.condition(row.cc) else row.next
            self.edges.add((row.va, dest))
            return dest
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
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            right = self.get(row.a, 8)
            right = right - (1 << 64) if right & SIGN[8] else right
            product = (left * right) & ((1 << 128) - 1)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
        elif op == "jmp":
            return row.target
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.call_site = row.va
            self.call_target = target
            self.stub(hook)
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            if not self.jump_low <= target < self.jump_high:
                raise Halt("indirect jump out of the function at %#x" % row.va)
            return target
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (self.regs[row.b[1]] & (8 * width - 1)) & 1)
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
        elif op in ("shl", "shr", "sar", "rol"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "rol":
                result = (value << count | value >> (8 * width - count)) & MASK[width]
            elif op == "shl":
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
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
        elif op == "nop":
            pass
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
                self.xmm[row.a[1]] = self.low(row.b) if row.b[0] != "r" else self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "cmpeqsd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left == right else 0)
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "divsd":
                result = left / right if right else math.copysign(math.inf, left) * math.copysign(1.0, right) if left == left and left else math.nan
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
        elif op == "andnpd":
            self.xmm[row.a[1]] = (~self.xmm[row.a[1]] & ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpcklpd":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((((left >> (8 * at)) & 0xFF) | ((right >> (8 * at)) & 0xFF) << 8) << (16 * at) for at in range(8))
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = sum(((source >> (16 * ((row.target >> (2 * at)) & 3))) & 0xFFFF) << (16 * at) for at in range(4))
            self.xmm[row.a[1]] = (source >> 64) << 64 | words
        elif op == "pshufd":
            source = self.vector(row.b)
            self.xmm[row.a[1]] = sum(((source >> (32 * ((row.target >> (2 * at)) & 3))) & MASK[4]) << (32 * at) for at in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            bits = 8 * size
            self.xmm[row.a[1]] = sum((MASK[size] if (left >> at) & MASK[size] == (right >> at) & MASK[size] else 0) << at for at in range(0, 128, bits))
        elif op == "pmovmskb":
            source = self.xmm[row.b[1]]
            self.put(row.a, 4, sum(((source >> (8 * at + 7)) & 1) << at for at in range(16)))
        elif op == "tzcnt":
            value = self.get(row.b, row.width)
            result = 8 * row.width if value == 0 else (value & -value).bit_length() - 1
            self.cf = value == 0
            self.zf = result == 0
            self.put(row.a, row.width, result)
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


# The six selected extents form one price-level deletion path. Labels describe
# observed roles, not recovered symbols.
FUNCTIONS = (
    ("erase-entry", 0x28666E0),
    ("leaf-or-predecessor", 0x1B21B80),
    ("leaf-delete-repair", 0x1B1F0B0),
    ("merge-children", 0x1B00AA0),
    ("borrow-from-left", 0x1AF8B70),
    ("borrow-from-right", 0x1AFB1F0),
)
FUNC_STARTS = frozenset(start for _, start in FUNCTIONS)
# Exact-byte identities for the six selected FDE windows, in addition to the
# whole-file digest. This prevents silently interpreting a changed opcode body.
EXPECTED_BODIES = {
    0x28666E0: (0x286686C, '7beab0053519877e1cdc19284ef4ecac066abe02e78edde77d3f00c1b84155f6'),
    0x1B21B80: (0x1B21E31, '42858f353632eac644a905ddb841ec7c852105ad6ac0c6014d0b4563ba11cb33'),
    0x1B1F0B0: (0x1B1F8D9, 'c69bacf6977686741f51a220350e3e30b82f5aea6e219537ece5705df940fe59'),
    0x1B00AA0: (0x1B00EC8, '20f7e2a504205385632ca5ec05c616ad76b801571a35527c890e26de98eadf85'),
    0x1AF8B70: (0x1AF8EBB, '9f3df8fc8d137fc09fe98beaceb125311bf0a5732c375ab0e7225361000bc5f8'),
    0x1AFB1F0: (0x1AFB56F, '1ccf6ff000d0a235aadbb8f725c18bea3bd777df61bc00b616cd0461b2e27ca0'),
}
TREE = HEAP_BASE + 0x100
OUT = HEAP_BASE + 0x200
QUERY = HEAP_BASE + 0x300
NODES = HEAP_BASE + 0x1000
NODE_STRIDE = 0x300
FAKE_COPY = 0xFACE0010
FAKE_MOVE = 0xFACE0011
FAKE_FREE = 0xFACE0020
FAKE_PANIC = 0xFACE0030


def signed(value):
    return value if value < (1 << 63) else value - (1 << 64)


def payload(key):
    """Distinct non-niche 32-byte values make key/value displacement visible."""
    return struct.pack('<QQQQ', 1, key & MASK[8], (key ^ 0x1122334455667788) & MASK[8], 0x123456789abcdef0)


class Node:
    def __init__(self, keys, children=()):
        self.keys = list(keys)
        self.children = list(children)
        self.address = None


def assign_keys(node, cursor):
    """Build an ordered tree with values spanning negative and positive keys."""
    for i in range(len(node.keys)):
        if node.children:
            assign_keys(node.children[i], cursor)
        node.keys[i] = cursor[0]
        cursor[0] += 2
    if node.children:
        assign_keys(node.children[-1], cursor)


def tree_keys(node):
    if node is None:
        return []
    out = []
    for i, key in enumerate(node.keys):
        if node.children:
            out.extend(tree_keys(node.children[i]))
        out.append(key)
    if node.children:
        out.extend(tree_keys(node.children[-1]))
    return out


def leaf(n):
    return Node([0] * n)


def shallow(left, right, parent_count=1):
    if parent_count == 1:
        return Node([0], [leaf(left), leaf(right)])
    return Node([0, 0], [leaf(left), leaf(right), leaf(5)])


def deep(left=5, right=5):
    children = [Node([0] * n, [leaf(5) for _ in range(n + 1)]) for n in (left, right)]
    return Node([0], children)


def clone_shape(node):
    return None if node is None else [list(node.keys), [clone_shape(c) for c in node.children]]


def model_delete(root, key):
    """Independent structural prediction for valid trees, not a target run."""
    root = clone_shape(root) if root is None or isinstance(root, Node) else copy.deepcopy(root)
    def repair(parent, i):
        children, keys = parent[1], parent[0]
        child = children[i]
        if len(child[0]) >= 5:
            return
        left_index = i - 1 if i else 0
        left, right = children[left_index:left_index + 2]
        if len(left[0]) + len(right[0]) + 1 <= 11:
            left[0].append(keys.pop(left_index))
            left[0].extend(right[0])
            left[1].extend(right[1])
            children.pop(left_index + 1)
        elif i:
            n = 5 - len(right[0])
            for _ in range(n):
                right[0].insert(0, keys[left_index])
                keys[left_index] = left[0].pop()
                if left[1]:
                    right[1].insert(0, left[1].pop())
        else:
            n = 5 - len(left[0])
            for _ in range(n):
                left[0].append(keys[left_index])
                keys[left_index] = right[0].pop(0)
                if right[1]:
                    left[1].append(right[1].pop(0))
    def remove(node, target):
        keys, children = node
        i = bisect.bisect_left(keys, target)
        if i < len(keys) and keys[i] == target:
            if not children:
                keys.pop(i)
                return True
            predecessor = children[i]
            while predecessor[1]:
                predecessor = predecessor[1][-1]
            replacement = predecessor[0][-1]
            keys[i] = replacement
            if not remove(children[i], replacement):
                raise ValueError('missing predecessor in model')
            repair(node, i)
            return True
        if not children:
            return False
        found = remove(children[i], target)
        if found:
            repair(node, i)
        return found
    if root is None:
        return None
    found = remove(root, key)
    if found and not root[0] and root[1]:
        root = root[1][0]
    return root


def fixtures():
    """Each fixture starts valid, with deterministic keys and opaque values."""
    cases = [("empty", None, None)]
    for length in range(1, 12):
        for index in sorted({0, length // 2, length - 1}):
            root = leaf(length)
            assign_keys(root, [-20])
            cases.append((f"leaf-{length}-{index}", root, root.keys[index]))
        root = leaf(length)
        assign_keys(root, [-20])
        for q in (-101, 101):
            cases.append((f"leaf-{length}-missing-{q}", root, q))
    for left in range(5, 12):
        for right in range(5, 12):
            for which in ("left", "root", "right"):
                root = shallow(left, right)
                assign_keys(root, [-(left + right + 1)])
                target = root.keys[0] if which == "root" else root.children[0 if which == "left" else 1].keys[0]
                cases.append((f"pair-{left}-{right}-{which}", root, target))
    for left in (5, 6, 7):
        for right in (5, 6, 7):
            for which in (0, 1, 2):
                root = shallow(left, right, 2)
                assign_keys(root, [-20])
                cases.append((f"three-{left}-{right}-{which}", root, root.children[which].keys[0]))
    for path in ((0, 0), (0, 3), (1, 0), (1, 5)):
        root = deep()
        assign_keys(root, [-100])
        child = root.children[path[0]].children[path[1]]
        cases.append((f"deep-{path[0]}-{path[1]}", root, child.keys[0]))
    for left in (5, 6, 7, 11):
        for right in (5, 6, 7, 11):
            for side in (0, 1):
                if (left, right)[side] != 5:
                    continue
                root = deep(left, right)
                assign_keys(root, [-150])
                child = root.children[side].children[0]
                cases.append((f"deep-pair-{left}-{right}-{side}", root, child.keys[0]))
    for left, right in ((5, 5), (5, 7), (7, 5), (7, 7)):
        for which in ('root', 'left-internal', 'right-internal', 'missing'):
            root = deep(left, right)
            assign_keys(root, [-150])
            query = {'root': root.keys[0], 'left-internal': root.children[0].keys[2],
                     'right-internal': root.children[1].keys[2], 'missing': -9999}[which]
            cases.append((f"deep-internal-{left}-{right}-{which}", root, query))
    # Three levels force a multi-edge predecessor descent and upward repairs.
    def height_two():
        return Node([0] * 5, [Node([0] * 5, [leaf(5) for _ in range(6)]) for _ in range(6)])
    for which in ('root', 'left-internal', 'right-internal'):
        root = Node([0], [height_two(), height_two()])
        assign_keys(root, [-1000])
        query = {'root': root.keys[0], 'left-internal': root.children[0].keys[2],
                 'right-internal': root.children[1].keys[2]}[which]
        cases.append(('height-three-' + which, root, query))
    for key in (-(1 << 63), -1, 0, (1 << 63) - 1):
        root = Node([-(1 << 63), -1, 0, (1 << 63) - 1])
        cases.append((f"signed-{key}", root, key))
    return cases


class Harness:
    def __init__(self, image, patches=None):
        self.m = Machine(image, patches)
        self.m.real = FUNC_STARTS
        self.m.memory.statics.update({0x576DFE0: FAKE_COPY, 0x576E0E0: FAKE_MOVE,
                                      0x576E010: FAKE_FREE, 0x576E098: FAKE_PANIC,
                                      0x576E108: FAKE_PANIC, 0x576E470: FAKE_PANIC})
        self.m.slots = {FAKE_COPY: self.copy, FAKE_MOVE: self.copy,
                        FAKE_FREE: self.free, FAKE_PANIC: self.panic}
        self.freed = []

    def copy(self, m):
        n = m.regs[RDX]
        if n > 0x1000:
            raise Halt('copy outside fixture limit')
        dst, src = m.regs[RDI], m.regs[RSI]
        if n and m.call_target == FAKE_COPY and dst < src + n and src < dst + n:
            raise Halt('overlapping memcpy in synthetic fixture')
        if n:
            m.memory.copy(dst, src, n)
        m.regs[RAX] = dst

    def free(self, m):
        address, size = m.regs[RDI], m.regs[RSI]
        if size not in (0x1c8, 0x228):
            raise Halt('unexpected node release size')
        self.freed.append((address, size))
        m.memory.put_bytes(address, bytes([0xdd]) * size)
        m.regs[RAX] = 0

    def panic(self, m):
        raise Panicked((m.call_site, m.regs[RDI], m.regs[RSI]))

    def write_tree(self, root):
        m = self.m.memory
        all_nodes = []
        def collect(node):
            node.address = NODES + len(all_nodes) * NODE_STRIDE
            all_nodes.append(node)
            for child in node.children:
                collect(child)
        if root:
            collect(root)
        if NODES + len(all_nodes) * NODE_STRIDE >= HEAP_BASE + HEAP_SIZE:
            raise ValueError('fixture too large')
        self.node_sizes = {node.address: (0x228 if node.children else 0x1c8) for node in all_nodes}
        for node in all_nodes:
            m.put_bytes(node.address, bytes(NODE_STRIDE))
            m.write(node.address + 0x1c2, 2, len(node.keys))
            for i, key in enumerate(node.keys):
                m.write(node.address + 0x168 + 8 * i, 8, key)
                m.put_bytes(node.address + 0x20 * i, payload(key))
            for i, child in enumerate(node.children):
                m.write(node.address + 0x1c8 + 8 * i, 8, child.address)
                m.write(child.address + 0x160, 8, node.address)
                m.write(child.address + 0x1c0, 2, i)
        # Parent links must be written after each node is zeroed.
        for node in all_nodes:
            for i, child in enumerate(node.children):
                m.write(child.address + 0x160, 8, node.address)
                m.write(child.address + 0x1c0, 2, i)
        height = 0
        n = root
        while n and n.children:
            height += 1
            n = n.children[0]
        m.write(TREE, 8, root.address if root else 0)
        m.write(TREE + 8, 8, height)
        m.write(TREE + 16, 8, len(tree_keys(root)))
        return set(n.address for n in all_nodes)

    def view(self, valid_nodes):
        memory = self.m.memory
        root = memory.read(TREE, 8)
        height = memory.read(TREE + 8, 8)
        count = memory.read(TREE + 16, 8)
        visited = set()
        def walk(addr, h, parent, index):
            if addr not in valid_nodes or addr in visited:
                raise Halt('invalid or repeated child pointer')
            if h > 8:
                raise Halt('invalid tree height')
            visited.add(addr)
            if memory.read(addr + 0x160, 8) != parent:
                raise Halt('wrong parent pointer')
            if parent and memory.read(addr + 0x1c0, 2) != index:
                raise Halt('wrong parent index')
            n = memory.read(addr + 0x1c2, 2)
            if n > 11 or (parent and n < 5):
                raise Halt('node occupancy outside permitted range')
            result = []
            for i in range(n):
                if h:
                    result.extend(walk(memory.read(addr + 0x1c8 + 8*i, 8), h-1, addr, i))
                k = signed(memory.read(addr + 0x168 + 8*i, 8))
                v = memory.bytes_at(addr + 0x20*i, 32)
                if v != payload(k):
                    raise Halt('key and value separated')
                result.append(k)
            if h:
                result.extend(walk(memory.read(addr + 0x1c8 + 8*n, 8), h-1, addr, n))
            return result
        result = walk(root, height, 0, 0) if root else []
        def shape(addr, h):
            n = memory.read(addr + 0x1c2, 2)
            keys = [signed(memory.read(addr + 0x168 + i*8, 8)) for i in range(n)]
            children = ([shape(memory.read(addr + 0x1c8 + i*8, 8), h-1)
                         for i in range(n + 1)] if h else [])
            return [keys, children]
        tree_shape = shape(root, height) if root else None
        if result != sorted(set(result)) or len(result) != count:
            raise Halt('keys or map length inconsistent')
        if len(set(a for a, _ in self.freed)) != len(self.freed):
            raise Halt('duplicate node free')
        freed = {a for a, _ in self.freed}
        if visited & freed:
            raise Halt('freed node remains reachable')
        if visited | freed != valid_nodes:
            raise Halt('allocated node neither reachable nor freed')
        if any(a not in self.node_sizes or self.node_sizes[a] != size for a, size in self.freed):
            raise Halt('node freed with wrong address or size')
        return result, height, len(visited), count, tree_shape

    def run(self, case):
        label, root, key = case
        machine = self.m
        machine.memory.reset()
        machine.seen.clear()
        machine.edges.clear()
        machine.steps = 0
        self.freed = []
        valid_nodes = self.write_tree(root)
        expected = tree_keys(root)
        query = 0 if key is None else key
        machine.memory.write(QUERY, 8, query)
        machine.memory.put_bytes(OUT, bytes(32))
        machine.run(FUNCTIONS[0][1], {RDI: OUT, RSI: TREE, RDX: QUERY})
        actual, height, reachable, count, tree_shape = self.view(valid_nodes)
        found = key in expected if key is not None else False
        expected_after = [k for k in expected if k != key] if found else expected
        returned = machine.memory.bytes_at(OUT, 32)
        expected_return = payload(key) if found else struct.pack('<Q', 2)
        if actual != expected_after:
            raise Halt('key set differs from delete specification')
        if tree_shape != model_delete(root, query):
            raise Halt('tree shape differs from delete specification')
        if (returned if found else returned[:8]) != expected_return:
            raise Halt('returned value differs from delete specification')
        return {'case': label, 'query': query, 'found': found, 'before_count': len(expected),
                'after_count': count, 'height_after': height, 'reachable_nodes': reachable,
                'freed': len(self.freed), 'freed_sizes': tuple(size for _, size in self.freed), 'return_hex': returned.hex(),
                'seen': tuple(sorted(machine.seen)), 'edges': tuple(sorted(machine.edges)), 'steps': machine.steps,
                'keys': tuple(actual), 'before_shape': clone_shape(root), 'shape': tree_shape}


def failure_cases(image):
    """Exercise helper preconditions with deliberately invalid synthetic nodes."""
    specs = (
        ('merge-track-index', 0x1B00AA0, 5, 5, 0, 6, 0, 0),
        ('merge-right-track-index', 0x1B00AA0, 5, 5, 1, 6, 0, 0),
        ('merge-capacity', 0x1B00AA0, 6, 5, 0, 0, 0, 0),
        ('left-capacity', 0x1AF8B70, 5, 11, 1, 0, 0, 0),
        ('left-donor', 0x1AF8B70, 0, 5, 1, 0, 0, 0),
        ('right-capacity', 0x1AFB1F0, 11, 5, 1, 0, 0, 0),
        ('right-donor', 0x1AFB1F0, 5, 0, 1, 0, 0, 0),
        ('left-height', 0x1AF8B70, 6, 5, 1, 0, 0, 1),
        ('right-height', 0x1AFB1F0, 5, 6, 1, 0, 0, 1),
    )
    out = []
    for label, entry, left, right, count, track, hleft, hright in specs:
        h = Harness(image)
        mem = h.m.memory
        mem.reset()
        ctx = HEAP_BASE + 0x500
        parent, lnode, rnode = NODES, NODES + NODE_STRIDE, NODES + 2*NODE_STRIDE
        for addr in (parent, lnode, rnode):
            mem.put_bytes(addr, bytes(NODE_STRIDE))
        mem.write(parent + 0x1c2, 2, 1)
        mem.write(lnode + 0x1c2, 2, left)
        mem.write(rnode + 0x1c2, 2, right)
        mem.write(ctx, 8, parent)
        mem.write(ctx + 0x10, 8, 0)
        mem.write(ctx + 0x18, 8, lnode)
        mem.write(ctx + 0x20, 8, hleft)
        mem.write(ctx + 0x28, 8, rnode)
        mem.write(ctx + 0x30, 8, hright)
        args = ({RDI: OUT, RSI: ctx, RDX: count, RCX: track} if entry == 0x1B00AA0
                else {RDI: ctx, RSI: count})
        try:
            h.m.run(entry, args)
        except Panicked as exc:
            site, pointer, length = exc.args[0]
            if length > 512:
                raise Halt('unexpected diagnostic length')
            message = mem.bytes_at(pointer, length).decode('ascii')
            out.append({'case': label, 'function': hex(entry), 'call_site': hex(site),
                        'message_va': hex(pointer), 'message': message,
                        'seen': tuple(sorted(h.m.seen)), 'edges': tuple(sorted(h.m.edges))})
        else:
            raise Halt('expected helper failure did not happen: ' + label)
    # A non-root underfull child whose parent has no separators is malformed.
    h = Harness(image)
    m = h.m.memory
    m.reset()
    parent, child, ctx, flag = NODES, NODES+NODE_STRIDE, HEAP_BASE+0x500, HEAP_BASE+0x600
    for address in (parent, child):
        m.put_bytes(address, bytes(NODE_STRIDE))
    m.write(parent+0x1c2, 2, 0)
    m.write(child+0x1c2, 2, 5)
    m.write(child+0x160, 8, parent)
    m.write(child+0x1c0, 2, 0)
    m.write(ctx, 8, child)
    m.write(ctx+8, 8, 0)
    m.write(ctx+16, 8, 0)
    m.write(flag, 1, 0)
    try:
        h.m.run(0x1B1F0B0, {RDI: OUT, RSI: ctx, RDX: flag})
    except Panicked as exc:
        site, pointer, length = exc.args[0]
        if length > 512:
            raise Halt('unexpected diagnostic length')
        out.append({'case': 'empty-internal-parent', 'function': hex(0x1B1F0B0),
                    'call_site': hex(site), 'message_va': hex(pointer),
                    'message': m.bytes_at(pointer, length).decode('ascii'),
                    'seen': tuple(sorted(h.m.seen)), 'edges': tuple(sorted(h.m.edges))})
    else:
        raise Halt('empty internal parent failure was not reached')
    return out


def raw_at(image, va, size):
    if size < 0:
        raise EvidenceError('negative read length')
    matches = [s for s in image.mapped if s['address'] <= va and
               va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise EvidenceError('range is not uniquely file backed')
    off = matches[0]['offset'] + va - matches[0]['address']
    return bytes(image.blob[off:off + size])


def validate_body(start, end, body):
    expected = EXPECTED_BODIES.get(start)
    if (expected is None or end != expected[0] or len(body) != end-start or
            hashlib.sha256(body).hexdigest() != expected[1]):
        raise EvidenceError('selected FDE body changed')


def instruction_rows(image):
    result = {}
    for label, start in FUNCTIONS:
        _, end = image.exact_fde(start)
        validate_body(start, end, raw_at(image, start, end-start))
        result[label] = decode_range(image, start, end)
    return result


def rows_for_slots(image, slots):
    """Decode ELF64 relocation records and dynamic names without external tools."""
    sym = image.named['.dynsym']
    strings = image.named['.dynstr']
    result = {}
    for slot, kind, addend, symbol_index in image.relocations():
        if slot not in slots:
            continue
        if slot in result:
            raise EvidenceError('duplicate relocation slot')
        name = ''
        if symbol_index:
            off = sym['offset'] + symbol_index * 24
            if off + 24 > sym['offset'] + sym['size']:
                raise EvidenceError('dynamic symbol out of bounds')
            name_offset = struct.unpack_from('<I', image.blob, off)[0]
            if name_offset >= strings['size']:
                raise EvidenceError('dynamic name out of bounds')
            pos = strings['offset'] + name_offset
            limit = strings['offset'] + strings['size']
            end = image.blob.find(b'\0', pos, limit)
            if end < 0:
                raise EvidenceError('unterminated dynamic name')
            name = image.blob[pos:end].decode('ascii')
        result[slot] = {'slot': hex(slot), 'type': kind, 'symbol_index': symbol_index,
                        'symbol': name, 'addend': hex(addend) if addend >= 0 else str(addend)}
    if set(result) != set(slots):
        raise EvidenceError('missing selected relocation')
    return [result[slot] for slot in sorted(result)]


def collect_cases(image):
    harness = Harness(image)
    observations = []
    for case in fixtures():
        observations.append(harness.run(case))
    return observations


def fingerprint(result):
    return (result['found'], result['after_count'], result['height_after'], result['freed'],
            result['return_hex'], result['freed_sizes'], result['shape'])


def mutation_controls(image, rows, cases, observations):
    """Flip each observed Jcc condition, compare one witness for each edge."""
    edge_cases = {}
    for case, result in zip(cases, observations):
        for edge in result['edges']:
            bucket = edge_cases.setdefault(edge, {})
            parts = case[0].split('-')
            family = (parts[0], parts[-1])
            bucket.setdefault(family, (case, result))
    records = []
    for label, _ in FUNCTIONS:
        for ins in rows[label]:
            if ins.op != 'jcc':
                continue
            raw = raw_at(image, ins.va, ins.size)
            index = 1 if raw[0] == 0x0f else 0
            opcode = raw[index]
            candidates = []
            used = set()
            for edge in ((ins.va, ins.next), (ins.va, ins.target)):
                for case, result in edge_cases.get(edge, {}).values():
                    if case[0] not in used:
                        candidates.append((case, result))
                        used.add(case[0])
            outcome, witness, reason, tested = 'unreached', '', '', 0
            if candidates:
                outcome = 'survived-sampled-cases'
                for case, baseline in candidates:
                    tested += 1
                    harness = Harness(image, {ins.va + index: opcode ^ 1})
                    harness.m.step_limit = 4000
                    try:
                        observed = harness.run(case)
                        if fingerprint(observed) != fingerprint(baseline):
                            outcome, witness, reason = 'killed', case[0], 'different result or tree'
                            break
                    except (Halt, Panicked, EvidenceError, IndexError, ValueError, OverflowError, struct.error) as exc:
                        outcome, witness, reason = 'killed', case[0], type(exc).__name__
                        break
            records.append({'function': label, 'site': hex(ins.va), 'byte_va': hex(ins.va + index),
                            'original': f'{opcode:02x}', 'mutant': f'{opcode ^ 1:02x}',
                            'outcome': outcome, 'witness': witness, 'reason': reason, 'tested': tested})
    return records


def write_tsv(path, fields, records):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fields, delimiter='\t', lineterminator='\n', extrasaction='ignore')
        writer.writeheader()
        writer.writerows(records)


def anchor_rows(image):
    """Short windows inside the selected FDEs; full bodies are retained too."""
    spans = (
        ('signed-key-search', 0x286670D, 0x2866777),
        ('after-delete-root-shrink', 0x28667B3, 0x2866802),
        ('predecessor-leaf-selection', 0x1B21B96, 0x1B21CA8),
        ('remove-leaf-and-underflow-test', 0x1B1F0CC, 0x1B1F170),
        ('choose-left-sibling', 0x1B1F185, 0x1B1F205),
        ('choose-right-sibling', 0x1B1F223, 0x1B1F29D),
        ('propagation-or-stop', 0x1B1F30C, 0x1B1F349),
        ('mark-empty-root-and-borrow', 0x1B1F85D, 0x1B1F8A7),
        ('merge-guard', 0x1B00AB1, 0x1B00AF6),
        ('merge-parent-entry-and-values', 0x1B00B3F, 0x1B00C2F),
        ('merge-release-and-return', 0x1B00E3B, 0x1B00E7D),
        ('left-borrow-guard', 0x1AF8B86, 0x1AF8BD1),
        ('right-borrow-guard', 0x1AFB201, 0x1AFB241),
        ('left-internal-child-reparent', 0x1AF8DC0, 0x1AF8E2E),
        ('right-internal-child-reparent', 0x1AFB490, 0x1AFB4FE),
    )
    result = []
    for label, start, end in spans:
        raw = raw_at(image, start, end-start)
        result.append({'anchor': label, 'start_va': hex(start), 'end_va': hex(end),
                       'file_offset': hex(image.offset(start)), 'bytes': len(raw),
                       'raw_hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest()})
    return result


def instruction_controls(image):
    """Corrupt independent operand bytes in the evaluator, never the input ELF."""
    specs = (
        ('signed-compare', 0x286673F, 0x9C, 0x0E, 'signed-0'),
        ('merge-threshold', 0x1B1F1EC, 0x0C, 0x01, 'pair-7-5-right'),
        ('value-stride', 0x1B1F11D, 0x05, 0x01, 'leaf-5-2'),
        ('node-length-offset', 0x2866710, 0xC2, 0x01, 'leaf-5-2'),
        ('tree-length-offset', 0x28667B6, 0x10, 0x01, 'leaf-5-2'),
        ('root-parent-offset', 0x28667ED, 0x60, 0x01, 'pair-5-5-left'),
    )
    cases = {case[0]: case for case in fixtures()}
    results = []
    for label, address, expected, mask, case_name in specs:
        byte = raw_at(image, address, 1)[0]
        if byte != expected:
            raise EvidenceError('control instruction changed')
        case = cases[case_name]
        baseline = Harness(image).run(case)
        h = Harness(image, {address: byte ^ mask})
        h.m.step_limit = 4000
        outcome, reason = 'survived', ''
        try:
            altered = h.run(case)
            if fingerprint(altered) != fingerprint(baseline):
                outcome, reason = 'killed', 'different result or tree'
        except (Halt, Panicked, EvidenceError, IndexError, ValueError, OverflowError, struct.error) as exc:
            outcome, reason = 'killed', type(exc).__name__
        results.append({'control': label, 'byte_va': hex(address), 'original': f'{byte:02x}',
                        'mutant': f'{byte ^ mask:02x}', 'case': case_name,
                        'outcome': outcome, 'reason': reason})
    for label, address, runner in (('merge-track-selector', 0x1B00AC3, merge_cases),
                                   ('cursor-depth', 0x1B21D40, cursor_cases),
                                   ('cursor-remainder', 0x1B21D54, cursor_cases),
                                   ('cursor-loop', 0x1B21D70, cursor_cases),
                                   ('predecessor-unrolled-loop', 0x1B21C7C, descent_fragments),
                                   ('successor-unrolled-loop', 0x1B21DFF, descent_fragments),
                                   ('first-empty-gate', 0x26DF218, caller_gate_cases),
                                   ('second-empty-gate', 0x26E02D5, caller_gate_cases)):
        byte = raw_at(image, address, 1)[0]
        if byte not in (0x74, 0x75):
            raise EvidenceError('control branch changed')
        try:
            runner(image, {address: byte ^ 1})
        except (Halt, Panicked, EvidenceError, IndexError, ValueError, OverflowError, struct.error) as exc:
            outcome, reason = 'killed', type(exc).__name__
        else:
            outcome, reason = 'survived', ''
        results.append({'control': label, 'byte_va': hex(address), 'original': f'{byte:02x}',
                        'mutant': f'{byte ^ 1:02x}', 'case': ('sparse-fragment' if runner is descent_fragments else
                                 'caller-gate' if runner is caller_gate_cases else 'direct-helper'),
                        'outcome': outcome, 'reason': reason})
    return results


def caller_gates(image):
    result = []
    for label, start, site in (('first', 0x26DF213, 0x26DF231),
                               ('second', 0x26E02C9, 0x26E02E7)):
        first = decode(lambda va, n: raw_at(image, va, n), start)
        second = decode(lambda va, n: raw_at(image, va, n), first.next)
        next_test = decode(lambda va, n: raw_at(image, va, n), second.next)
        fourth = decode(lambda va, n: raw_at(image, va, n), next_test.next)
        call = decode(lambda va, n: raw_at(image, va, n), site)
        if (first.op != 'cmp' or first.width != 1 or first.b != ('i', 0) or first.a[4] != -32 or
                second.op != 'jcc' or second.cc != 5 or next_test.op != 'cmp' or
                next_test.width != 1 or next_test.b != ('i', 0) or next_test.a[4] != -16 or
                fourth.op != 'jcc' or fourth.cc != 5 or fourth.target != second.target or
                call.op != 'call' or call.target != FUNCTIONS[0][1]):
            raise EvidenceError('caller gate instruction shape changed')
        result.append({'caller_copy': label, 'gate_start': hex(start),
                       'first_byte_displacement': first.a[4], 'first_branch_site': hex(second.va),
                       'first_nonzero_target': hex(second.target),
                       'second_byte_displacement': next_test.a[4], 'second_branch_site': hex(fourth.va),
                       'second_nonzero_target': hex(fourth.target),
                       'call_site': hex(site), 'call_bytes': raw_at(image, site, call.size).hex(),
                       'target': hex(call.target)})
    return result


def caller_gate_cases(image, patches=None):
    """Run just the two caller gate windows on synthetic option-tag bytes."""
    result = []
    for name, start, call, skip in (('first', 0x26DF213, 0x26DF231, 0x26DF236),
                                    ('second', 0x26E02C9, 0x26E02E7, 0x26E02F1)):
        for first in (0, 1, 2, 255):
            for second in (0, 1, 2, 255):
                machine = Machine(image, patches)
                machine.memory.reset()
                machine.regs = [0]*16
                machine.regs[RAX] = NODES + 0x40
                machine.regs[RCX] = 0
                machine.regs[RSP] = STACK_TOP - 0x200
                machine.memory.write(NODES+0x20, 1, first)
                machine.memory.write(NODES+0x30, 1, second)
                pc, steps = start, 0
                while pc not in (call, skip):
                    if steps >= 30:
                        raise Halt('caller gate fragment step limit')
                    row = decode(machine.read_code, pc)
                    machine.seen.add(pc)
                    pc = machine.step(row)
                    steps += 1
                actual = pc == call
                if actual != (first == 0 and second == 0):
                    raise Halt('caller gate differs from tag model')
                result.append({'caller': name, 'first_tag': first, 'second_tag': second,
                               'outcome': 'call' if actual else 'skip', 'steps': steps,
                               'seen': tuple(sorted(machine.seen)),
                               'edges': tuple(sorted(machine.edges))})
    return result


def rotation_cases(image):
    """Evaluate multiple-entry transfers directly, including internal child links.

    These are helper contract tests; the selected erase caller passes one.
    """
    results = []
    for side in ('left', 'right'):
        for height in (0, 1):
            for count in range(1, 6):
                def child(n):
                    return Node([0] * n, [leaf(5) for _ in range(n+1)] if height else ())
                left_n, right_n = ((5+count, 5) if side == 'left' else (5, 5+count))
                root = Node([0], [child(left_n), child(right_n)])
                assign_keys(root, [-200])
                expected = clone_shape(root)
                left, right = expected[1]
                for _ in range(count):
                    if side == 'left':
                        right[0].insert(0, expected[0][0])
                        expected[0][0] = left[0].pop()
                        if height:
                            right[1].insert(0, left[1].pop())
                    else:
                        left[0].append(expected[0][0])
                        expected[0][0] = right[0].pop(0)
                        if height:
                            left[1].append(right[1].pop(0))
                h = Harness(image)
                h.m.memory.reset()
                nodes = h.write_tree(root)
                ctx = HEAP_BASE + 0x500
                mem = h.m.memory
                mem.write(ctx, 8, root.address)
                mem.write(ctx+0x10, 8, 0)
                mem.write(ctx+0x18, 8, root.children[0].address)
                mem.write(ctx+0x20, 8, height)
                mem.write(ctx+0x28, 8, root.children[1].address)
                mem.write(ctx+0x30, 8, height)
                entry = 0x1AF8B70 if side == 'left' else 0x1AFB1F0
                h.m.run(entry, {RDI: ctx, RSI: count})
                keys, hgt, _, length, shape = h.view(nodes)
                if shape != expected or keys != tree_keys(root) or hgt != height+1 or length != len(keys):
                    raise Halt('direct rotation differs from structural specification')
                results.append({'case': f'{side}-height-{height}-count-{count}',
                                'function': hex(entry), 'count': count, 'height': height,
                                'keys': len(keys), 'shape': shape,
                                'seen': tuple(sorted(h.m.seen)), 'edges': tuple(sorted(h.m.edges))})
    return results


def descent_fragments(image, patches=None):
    """Run bounded navigation blocks on sparse synthetic chains.

    These fragments deliberately omit unrelated siblings. They exercise loop
    mechanics only and are not represented as valid full book trees.
    """
    results = []
    for direction in ('predecessor', 'successor'):
        depths = (1, 2, 7, 8, 9, 10, 16, 17) if direction == 'predecessor' else (0, 1, 2, 7, 8, 9, 10, 16, 17)
        for depth in depths:
            m = Machine(image, patches)
            m.memory.reset()
            m.regs = [0] * 16
            for level in range(depth+1):
                at = NODES + level*NODE_STRIDE
                m.memory.put_bytes(at, bytes(NODE_STRIDE))
                m.memory.write(at+0x1c2, 2, 5)
            for level in range(depth):
                at, nxt = NODES + level*NODE_STRIDE, NODES + (level+1)*NODE_STRIDE
                edge = 0 if direction == 'successor' and level else (1 if direction == 'successor' else (0 if level == 0 else 5))
                m.memory.write(at+0x1c8+8*edge, 8, nxt)
            m.regs[RAX] = NODES
            if direction == 'predecessor':
                m.regs[RDI], m.regs[RCX] = depth, 0
                pc, stop = 0x1B21B96, 0x1B21C7E
            else:
                m.regs[RDX], m.regs[RSI] = depth, 0
                pc, stop = 0x1B21D3D, 0x1B21E01
            steps = 0
            while pc != stop:
                if steps >= 1000:
                    raise Halt('fragment step limit')
                row = decode(m.read_code, pc)
                m.seen.add(pc)
                pc = m.step(row)
                steps += 1
            actual = m.regs[RCX] if direction == 'predecessor' else m.regs[RAX]
            expected = NODES + depth*NODE_STRIDE
            if actual != expected or (direction == 'successor' and m.regs[RSI] != (1 if depth == 0 else 0)):
                raise Halt('bounded descent disagrees with chain specification')
            results.append({'direction': direction, 'depth': depth, 'steps': steps,
                            'result_node_ordinal': (actual-NODES)//NODE_STRIDE,
                            'result_index': m.regs[RSI] if direction == 'successor' else '',
                            'seen': tuple(sorted(m.seen)), 'edges': tuple(sorted(m.edges))})
    return results


def cursor_cases(image, patches=None):
    """Probe the cursor returned by the leaf/predecessor helper itself."""
    def balanced(height):
        if height == 0:
            return leaf(6)
        return Node([0] * 6, [balanced(height-1) for _ in range(7)])
    specs = [(0, i) for i in (0, 3, 5)] + [(height, 0) for height in (1, 2, 3)]
    results = []
    for height, index in specs:
        root = (leaf(6) if not height else
                Node([0], [balanced(height-1), balanced(height-1)]))
        assign_keys(root, [-1000])
        key = root.keys[index]
        successor = root
        if height:
            successor = root.children[1]
            while successor.children:
                successor = successor.children[0]
        h = Harness(image, patches)
        h.m.memory.reset()
        nodes = h.write_tree(root)
        ctx, flag = HEAP_BASE + 0x500, HEAP_BASE + 0x600
        m = h.m.memory
        m.write(ctx, 8, root.address)
        m.write(ctx+8, 8, height)
        m.write(ctx+16, 8, index)
        m.write(flag, 1, 0)
        h.m.run(0x1B21B80, {RDI: OUT, RSI: ctx, RDX: flag})
        returned_key = signed(m.read(OUT, 8))
        returned_value = m.bytes_at(OUT+8, 32)
        cursor_node = m.read(OUT+0x28, 8)
        cursor_height = m.read(OUT+0x30, 8)
        cursor_index = m.read(OUT+0x38, 8)
        expected_index = index if not height else 0
        if (returned_key != key or returned_value != payload(key) or
                cursor_node != successor.address or cursor_height != 0 or
                cursor_index != expected_index or m.read(flag, 1) != 0):
            raise Halt('returned cursor differs from specification')
        # The entry wrapper, not this helper, decrements the map length.
        m.write(TREE+16, 8, m.read(TREE+16, 8)-1)
        _, _, _, _, actual = h.view(nodes)
        if actual != model_delete(root, key):
            raise Halt('cursor helper changed unexpected tree contents')
        results.append({'case': f'height-{height}-index-{index}', 'height': height,
                        'removed_key': key, 'returned_value': returned_value.hex(),
                        'cursor_node_ordinal': (cursor_node-NODES)//NODE_STRIDE,
                        'cursor_height': cursor_height, 'cursor_index': cursor_index,
                        'seen': tuple(sorted(h.m.seen)), 'edges': tuple(sorted(h.m.edges))})
    return results


def merge_cases(image, patches=None):
    """Check tracked edges for balanced and one-underfull synthetic siblings."""
    results = []
    for height in (0, 1):
        for left_len, right_len in ((5, 5), (4, 6), (6, 4)):
            for selector in (0, 1):
                bound = (left_len, right_len)[selector]
                for index in range(bound + 1):
                    def child(n):
                        return Node([0] * n, [leaf(5) for _ in range(n+1)] if height else ())
                    root = Node([0], [child(left_len), child(right_len)])
                    assign_keys(root, [-100])
                    original = tree_keys(root)
                    prior_shape = clone_shape(root)
                    left, right = prior_shape[1]
                    expected = [[], [[left[0] + prior_shape[0] + right[0], left[1] + right[1]]]]
                    h = Harness(image, patches)
                    h.m.memory.reset()
                    nodes = h.write_tree(root)
                    ctx = HEAP_BASE + 0x500
                    m = h.m.memory
                    m.write(ctx, 8, root.address)
                    m.write(ctx + 0x08, 8, height + 1)
                    m.write(ctx + 0x10, 8, 0)
                    m.write(ctx + 0x18, 8, root.children[0].address)
                    m.write(ctx + 0x20, 8, height)
                    m.write(ctx + 0x28, 8, root.children[1].address)
                    m.write(ctx + 0x30, 8, height)
                    h.m.run(0x1B00AA0, {RDI: OUT, RSI: ctx, RDX: selector, RCX: index})
                    keys, tree_height, _, length, shape = h.view(nodes)
                    returned_node = m.read(OUT, 8)
                    returned_height = m.read(OUT + 8, 8)
                    returned_index = m.read(OUT + 16, 8)
                    wanted_index = index + (left_len + 1 if selector else 0)
                    if (keys != original or tree_height != height+1 or length != len(original) or
                        returned_node != root.children[0].address or returned_height != height or
                        returned_index != wanted_index or len(h.freed) != 1 or
                        shape != expected):
                        raise Halt('merge edge or structure differs from specification')
                    results.append({'case': f'height-{height}-left-{left_len}-right-{right_len}-selector-{selector}-edge-{index}',
                                    'height': height, 'left_len': left_len, 'right_len': right_len,
                                    'selector': selector, 'old_edge': index, 'new_edge': returned_index,
                                    'freed_size': h.freed[0][1], 'before_keys': len(original),
                                    'after_shape': shape, 'seen': tuple(sorted(h.m.seen)),
                                    'edges': tuple(sorted(h.m.edges))})
    return results


def sequential_cases(image):
    """Apply many deletes to each evolving synthetic map without rebuilding it."""
    factories = (
        ('shallow-ascending', lambda: shallow(5, 7), 'ascending'),
        ('shallow-descending', lambda: shallow(7, 5, 2), 'descending'),
        ('deep-ascending', lambda: deep(5, 5), 'ascending'),
        ('deep-descending', lambda: deep(5, 7), 'descending'),
        ('deep-alternating', lambda: deep(7, 5), 'alternating'),
        ('deep-center', lambda: deep(7, 7), 'center'),
    )
    result = []
    for label, factory, order in factories:
        root = factory()
        assign_keys(root, [-150])
        keys = tree_keys(root)
        if order == 'ascending':
            deletion_order = list(keys)
        elif order == 'descending':
            deletion_order = list(reversed(keys))
        elif order == 'center':
            center = keys[len(keys)//2]
            deletion_order = sorted(keys, key=lambda key: (abs(key-center), key))
        else:
            deletion_order = []
            low, high = 0, len(keys)-1
            while low <= high:
                deletion_order.append(keys[low])
                low += 1
                if low <= high:
                    deletion_order.append(keys[high])
                    high -= 1
        queries = [1000001]
        for i, key in enumerate(deletion_order):
            queries.append(key)
            if i % 7 == 0:
                queries.append(key)  # missing after a successful deletion
        h = Harness(image)
        h.m.memory.reset()
        nodes = h.write_tree(root)
        shape = clone_shape(root)
        remaining = set(keys)
        for index, query in enumerate(queries):
            before = len(remaining)
            found = query in remaining
            m = h.m.memory
            m.write(QUERY, 8, query)
            m.put_bytes(OUT, bytes(32))
            h.m.run(FUNCTIONS[0][1], {RDI: OUT, RSI: TREE, RDX: QUERY})
            returned = m.bytes_at(OUT, 32)
            if (returned if found else returned[:8]) != (payload(query) if found else struct.pack('<Q', 2)):
                raise Halt('sequential return mismatch')
            shape = model_delete(shape, query)
            remaining.discard(query)
            actual, height, _, count, actual_shape = h.view(nodes)
            if actual != sorted(remaining) or actual_shape != shape or count != len(remaining):
                raise Halt('sequential tree mismatch')
            encoded_shape = json.dumps(actual_shape, separators=(',', ':')).encode('ascii')
            result.append({'sequence': label, 'step': index, 'query': query, 'found': int(found),
                           'before_count': before, 'after_count': count, 'height_after': height,
                           'cumulative_frees': len(h.freed), 'shape_sha256': hashlib.sha256(encoded_shape).hexdigest(),
                           'seen': tuple(sorted(h.m.seen)), 'edges': tuple(sorted(h.m.edges))})
    return result


def generate(out):
    image = load_image()
    rows = instruction_rows(image)
    fixtures_list = fixtures()
    cases = collect_cases(image)
    failures = failure_cases(image)
    gate_cases = caller_gate_cases(image)
    rotations = rotation_cases(image)
    merges = merge_cases(image)
    cursors = cursor_cases(image)
    fragments = descent_fragments(image)
    sequences = sequential_cases(image)
    all_results = cases + failures + rotations + merges + cursors + fragments + sequences + gate_cases
    seen = set().union(*(set(c['seen']) for c in all_results))
    edges = set().union(*(set(c['edges']) for c in all_results))
    mutations = mutation_controls(image, rows, fixtures_list, cases)
    controls = instruction_controls(image)
    gates = caller_gates(image)
    _, fdes = eh_frame_records(image.blob, image.sections)
    fde_by_start = {f['start']: f for f in fdes}
    if len(fde_by_start) != len(fdes):
        raise EvidenceError('duplicate FDE start')
    funcs, branches, calls, windows = [], [], [], []
    for label, start in FUNCTIONS:
        fde = fde_by_start[start]
        code = raw_at(image, start, fde['end'] - start)
        insns = rows[label]
        funcs.append({'function': label, 'start_va': hex(start), 'end_va': hex(fde['end']),
                      'file_offset': hex(image.offset(start)), 'fde_va': hex(fde['fde']),
                      'body_bytes': len(code), 'sha256': hashlib.sha256(code).hexdigest(),
                      'decoded_instructions': len(insns),
                      'evaluated_instructions': sum(r.va in seen for r in insns)})
        windows.append({'function': label, 'start_va': hex(start), 'end_va': hex(fde['end']),
                        'raw_hex': code.hex()})
        for ins in insns:
            raw = raw_at(image, ins.va, ins.size)
            if ins.op == 'jcc':
                branches.append({'function': label, 'site_va': hex(ins.va), 'bytes': raw.hex(),
                                 'condition_code': ins.cc, 'taken_va': hex(ins.target),
                                 'fallthrough_va': hex(ins.next),
                                 'taken_seen': int((ins.va, ins.target) in edges),
                                 'fallthrough_seen': int((ins.va, ins.next) in edges)})
            if ins.op in ('call', 'calli'):
                if ins.op == 'call':
                    kind, dest = 'direct', hex(ins.target)
                elif ins.a[0] == 'm' and ins.a[1] is None and ins.a[2] is None:
                    kind, dest = 'indirect-slot', hex(ins.a[4])
                else:
                    kind, dest = 'indirect-register', ''
                calls.append({'function': label, 'site_va': hex(ins.va), 'bytes': raw.hex(),
                              'kind': kind, 'target_or_slot': dest, 'seen': int(ins.va in seen)})
    # These windows are only caller-side gates. The selected FDEs start above.
    for label, start, end in (('first-empty-level-gate', 0x26DF213, 0x26DF236),
                              ('second-empty-level-gate', 0x26E02C9, 0x26E02EC)):
        windows.append({'function': label, 'start_va': hex(start), 'end_va': hex(end),
                        'raw_hex': raw_at(image, start, end-start).hex()})
    case_rows = []
    for c in cases:
        case_rows.append({'case': c['case'], 'query': c['query'], 'found': int(c['found']),
                          'before_count': c['before_count'], 'after_count': c['after_count'],
                          'height_after': c['height_after'], 'reachable_nodes': c['reachable_nodes'],
                          'freed': c['freed'], 'freed_sizes': ','.join(hex(n) for n in c['freed_sizes']), 'return_hex': c['return_hex'],
                          'before_shape': json.dumps(c['before_shape'], separators=(',', ':')),
                          'shape': json.dumps(c['shape'], separators=(',', ':'))})
    failure_rows = []
    for f in failures:
        failure_rows.append({**f, 'text_span': f['message'].replace('\n', ' ')})
    relocations = rows_for_slots(image, (0x576DFE0, 0x576E0E0, 0x576E010, 0x576E098, 0x576E108, 0x576E470))
    summary = {
        'target_sha256': SHA256, 'coordinate_system': 'linked ELF virtual address',
        'captured_executable_run': False,
        'cases': len(cases), 'failure_cases': len(failures), 'caller_gate_cases': len(gate_cases), 'direct_rotation_cases': len(rotations), 'direct_merge_cases': len(merges), 'direct_cursor_cases': len(cursors), 'descent_fragment_cases': len(fragments), 'sequential_steps': len(sequences),
        'functions': len(funcs), 'instruction_count': sum(f['decoded_instructions'] for f in funcs),
        'seen_instructions': sum(f['evaluated_instructions'] for f in funcs),
        'conditional_branches': len(branches),
        'both_branch_edges_seen': sum(b['taken_seen'] and b['fallthrough_seen'] for b in branches),
        'mutation_killed': sum(m['outcome'] == 'killed' for m in mutations),
        'mutation_survived_sample': sum(m['outcome'] == 'survived-sampled-cases' for m in mutations),
        'mutation_unreached': sum(m['outcome'] == 'unreached' for m in mutations),
        'focused_controls_killed': sum(m['outcome'] == 'killed' for m in controls),
        'focused_controls_total': len(controls),
        'limitations': 'Synthetic tree fixtures and stubs; evaluator is not native execution. No whole-node gate or identity claim.',
    }
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / 'functions.tsv', ('function', 'start_va', 'end_va', 'file_offset', 'fde_va', 'body_bytes', 'sha256', 'decoded_instructions', 'evaluated_instructions'), funcs)
    write_tsv(out / 'branches.tsv', ('function', 'site_va', 'bytes', 'condition_code', 'taken_va', 'fallthrough_va', 'taken_seen', 'fallthrough_seen'), branches)
    write_tsv(out / 'calls.tsv', ('function', 'site_va', 'bytes', 'kind', 'target_or_slot', 'seen'), calls)
    write_tsv(out / 'cases.tsv', ('case', 'query', 'found', 'before_count', 'after_count', 'height_after', 'reachable_nodes', 'freed', 'freed_sizes', 'return_hex', 'before_shape', 'shape'), case_rows)
    write_tsv(out / 'sequences.tsv', ('sequence', 'step', 'query', 'found', 'before_count',
              'after_count', 'height_after', 'cumulative_frees', 'shape_sha256'), sequences)
    write_tsv(out / 'descent-fragments.tsv', ('direction', 'depth', 'steps',
              'result_node_ordinal', 'result_index'), fragments)
    write_tsv(out / 'cursors.tsv', ('case', 'height', 'removed_key', 'returned_value',
              'cursor_node_ordinal', 'cursor_height', 'cursor_index'), cursors)
    write_tsv(out / 'merges.tsv', ('case', 'height', 'left_len', 'right_len', 'selector', 'old_edge', 'new_edge',
              'freed_size', 'before_keys', 'after_shape'),
              [{**r, 'after_shape': json.dumps(r['after_shape'], separators=(',', ':'))} for r in merges])
    write_tsv(out / 'rotations.tsv', ('case', 'function', 'count', 'height', 'keys', 'shape'),
              [{**r, 'shape': json.dumps(r['shape'], separators=(',', ':'))} for r in rotations])
    write_tsv(out / 'failures.tsv', ('case', 'function', 'call_site', 'message_va', 'text_span'), failure_rows)
    write_tsv(out / 'anchors.tsv', ('anchor', 'start_va', 'end_va', 'file_offset',
              'bytes', 'raw_hex', 'sha256'), anchor_rows(image))
    write_tsv(out / 'caller-gate-cases.tsv', ('caller', 'first_tag', 'second_tag', 'outcome', 'steps'), gate_cases)
    write_tsv(out / 'caller-gates.tsv', ('caller_copy', 'gate_start', 'first_byte_displacement', 'first_branch_site',
              'first_nonzero_target', 'second_byte_displacement', 'second_branch_site', 'second_nonzero_target',
              'call_site', 'call_bytes', 'target'), gates)
    write_tsv(out / 'focused-controls.tsv', ('control', 'byte_va', 'original', 'mutant',
              'case', 'outcome', 'reason'), controls)
    write_tsv(out / 'mutations.tsv', ('function', 'site', 'byte_va', 'original', 'mutant', 'outcome', 'tested', 'witness', 'reason'), mutations)
    for name, value in (('windows.json', windows), ('relocations.json', relocations), ('summary.json', summary)):
        (out / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    generate(args.out)


if __name__ == '__main__':
    main()
