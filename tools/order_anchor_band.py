#!/usr/bin/env python3
"""Pin the node #94 order price band that max_order_distance_from_anchor bounds, from ELF bytes.

Gates 0x372f240 (spot) and 0x3713db0 (perp) turn order price a and reference price b into
r = float(a)/float(b) - 1 and admit the order when p > |r|, or when p < 1, r > 0 and
1/(1-p) - 1 >= r. Every failure is tag 0x5f with p*100. Outcome-class spot tokens skip the band and
compare a with a stored word minus 1000 (tag 0xee). A symbolic walk lists every path of the float
decision for all inputs, the real bytes run over real hash table layouts with only the classifier,
exemption and hash calls stubbed, and a separately written specification predicts every run. No
objdump or readelf output is parsed, and the binary is never executed. Standard library only.

    python3 tools/order_anchor_band.py --out <dir>
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
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd"}
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
            return self.get(row.a, 8)
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.stub(hook)
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
                if right == 0.0:
                    result = math.nan if left == 0.0 or left != left else math.copysign(math.inf, left) * math.copysign(1.0, right)
                else:
                    result = left / right
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
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



# ---- targets ----

SPOT_GATE = 0x372F240
PERP_GATE = 0x3713DB0
CAP_HELPER = 0x372B4B0
WRAPPER = 0x372EFE0
GATES = (("spot", SPOT_GATE, 0x372F39A), ("perp", PERP_GATE, 0x3713E40))
CLASSIFIER = 0x3728670
EXEMPT = 0x37E4FB0
HASH = 0x399C4A0
SLOT_SPOT = 0x5773990
SLOT_PERP = 0x5773980
SLOT_WRAPPER = 0x5773988
SLOT_CLASS = 0x5773198
SLOT_EXEMPT = 0x5773228
SLOT_HELPER = 0x5774788
SLOT_BOUNDS = 0x576DFC8
BOUNDS_META = 0x56F1FD8
BOUNDS_HELPER = 0x56F1FD8
TAG_TABLE = 0x59A8D0
PIECES_BAND = 0x1E41CB
BAND_ARM_LEA = 0x3800043
KEY_ANCHOR = 0x3EF309
KEY_TEXT = b"max_order_distance_from_anchor"
FIELDS = (0x3980, 0x4400)

TAG_OK = 0x186
TAG_BAND = 0x5F
TAG_CAP = 0xEE
TAG_CLASS = 0x17F
TAG_VOTE = 0x41
BIAS = 1000
SCALE = 100.0
VOTE_LOW = 0.2
VOTE_HIGH = 0.99

ABS_MASK = bytes.fromhex("ffffffffffffff7fffffffffffffff7f")
CONVERT_OPS = ("movq", "movq", "punpckldq", "movx", "subpd", "movx", "unpckhpd", "addsd",
               "movq", "punpckldq", "subpd", "movx", "unpckhpd", "addsd")
CONVERT_CONSTANTS = {"exponents": bytes.fromhex("0000304300003045"), "offsets": bytes.fromhex("00000000000030430000000000003045")}

META_POINTER = 0x178
META_COUNT = 0x180
META_STRIDE = 0x20
TOKENS = 0x10
FIRST_CTRL = 0x80
FIRST_MASK = 0x88
FIRST_ITEMS = 0x98
FIRST_HASHER = 0xA0
SECOND_CTRL = 0xE0
SECOND_MASK = 0xE8
SECOND_ITEMS = 0xF8
SECOND_HASHER = 0x100
RECORD_SIZE = 0x90
SIDES = ((0x28, 0x20), (0x50, 0x48))

HEAP_USED = 0x14000
OUT = HEAP_BASE + 0x100
CONTEXT = HEAP_BASE + 0x1000
META = HEAP_BASE + 0x3800
FIRST_TABLE = HEAP_BASE + 0x8400
SECOND_TABLE = HEAP_BASE + 0x11000
BUCKETS = 64
H2 = 0x2A
EMPTY = 0xFF
BOUNDS_MARK = 0xD0000001
DECOY = 0xC3C3C3C3C3C3C3C3
USER_MARK = 0xB7B7B7B7B7B7B7B0
UNUSED_MARK = 0xE1E1E1E1E1E1E1E0

HITS = ("hit_first", "hit_second", "full_hit", "third_hit")
TABLE_KINDS = ("empty", "miss_empty", "miss_collide", "full_miss") + HITS


# ---- specification, written from the claim and not from the walker ----

def band_ratio(a, b):
    left, right = float(a), float(b)
    if right == 0.0:
        return math.nan if left == 0.0 else math.inf
    return left / right - 1.0


def band_admits(a, b, p):
    ratio = band_ratio(a, b)
    if abs(ratio) < p:
        return True
    if p < 1.0 and ratio > 0.0:
        return 1.0 / (1.0 - p) - 1.0 >= ratio
    return False


def band_outcome(a, b, p):
    if band_admits(a, b, p):
        return TAG_OK, None
    return TAG_BAND, to_bits(p * SCALE)


class Case:
    KEYS = {"kind": "spot", "a": 100, "b": 100, "p": 0.5, "index": 1, "count": 3, "token": 7, "cls": 0, "first": "hit_first",
            "second": "hit_first", "side": 0, "value": 5000, "link": 0x51, "exempt": 0}

    def __init__(self, **extra):
        for key, value in self.KEYS.items():
            setattr(self, key, extra.pop(key, value))
        if extra:
            raise ValueError("unknown case field %r" % sorted(extra))


def helper_spec(case):
    if case.index >= case.count:
        return "panic", BOUNDS_HELPER, case.index, case.count
    if case.first not in HITS:
        return "err", 3
    if case.second not in HITS:
        return "err", 4
    if case.side not in (0, 1):
        return "err", 2
    return "ok", case.value


def spec(case):
    """(kind, tag or location, payload, calls) for one gate run."""
    if case.kind == "perp":
        if case.exempt:
            return "tag", TAG_OK, None, ("exempt",)
        tag, payload = band_outcome(case.a, case.b, case.p)
        return "tag", tag, payload, ("exempt",)
    if case.index >= case.count:
        return "panic", BOUNDS_META, (case.index, case.count), ()
    if case.cls == 0:
        tag, payload = band_outcome(case.a, case.b, case.p)
        return "tag", tag, payload, ("class",)
    if case.cls == 1:
        return "tag", TAG_CLASS, None, ("class",)
    calls = ("class",)
    if case.first != "empty":
        calls += ("hash",)
    if case.first in HITS and case.second != "empty":
        calls += ("hash",)
    kind, value = helper_spec(case)
    if kind == "err" or value < BIAS or value - BIAS < case.a:
        return "tag", TAG_CAP, None, calls
    return "tag", TAG_OK, None, calls


# ---- real bytes over real hash table layouts ----

class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        relative = image.relative()
        memory = self.machine.memory
        hooks = {}
        for slot, mark, hook, want in ((SLOT_CLASS, None, self.on_class, CLASSIFIER), (SLOT_EXEMPT, None, self.on_exempt, EXEMPT),
                                       (SLOT_BOUNDS, BOUNDS_MARK, self.on_bounds, None)):
            target = relative.get(slot, mark)
            if want is not None and target != want:
                raise EvidenceError("slot changed: %#x" % slot)
            memory.statics[slot] = target
            hooks[target] = hook
        if relative.get(SLOT_HELPER) != CAP_HELPER:
            raise EvidenceError("helper slot changed")
        memory.statics[SLOT_HELPER] = CAP_HELPER
        self.machine.slots = hooks
        self.machine.calls = {HASH: self.on_hash}
        self.machine.real = frozenset((CAP_HELPER,))
        self.case = None
        self.events = []
        self.words = {}

    def on_class(self, machine):
        self.events.append("class")
        if machine.regs[RDI] != CONTEXT + TOKENS or machine.regs[RSI] != self.case.token:
            raise Halt("class arguments differ")
        machine.regs[RAX] = POISON & ~0xFF | self.case.cls

    def on_exempt(self, machine):
        self.events.append("exempt")
        if machine.regs[RDI] != USER_MARK:
            raise Halt("exemption argument differs")
        machine.regs[RAX] = POISON & ~0xFF | self.case.exempt

    def on_hash(self, machine):
        self.events.append("hash")
        hasher = machine.regs[RDI]
        if hasher not in self.words:
            raise Halt("hash state differs")
        key, word = self.words[hasher]
        if machine.memory.read(machine.regs[RSI], 8) != key:
            raise Halt("hash key differs")
        machine.regs[RAX] = word

    def on_bounds(self, machine):
        raise Panicked((machine.regs[RDX], machine.regs[RDI], machine.regs[RSI]))

    def write_table(self, ctrl, kind, start, key, size, fill):
        """One hashbrown table: `fill(address, is_target)` writes one entry at its bucket."""
        memory = self.machine.memory
        control = bytearray([EMPTY]) * BUCKETS
        hit = {"hit_first": 2, "empty": 2, "hit_second": 3, "full_hit": 16, "third_hit": 48}.get(kind)

        def bucket(offset):
            return (start + offset) & (BUCKETS - 1)

        if kind in ("full_hit", "full_miss", "third_hit"):
            for offset in range(32 if kind == "third_hit" else 16):
                control[bucket(offset)] = 0x80 if offset & 1 else 0x11
        if kind in ("miss_collide", "hit_second"):
            control[bucket(1)] = H2
        if hit is not None:
            control[bucket(hit)] = H2
        for slot in range(BUCKETS):
            memory.write(ctrl + slot, 1, control[slot])
            fill(ctrl - size * (slot + 1), hit is not None and slot == bucket(hit))
        for slot in range(16):
            memory.write(ctrl + BUCKETS + slot, 1, control[slot])

    def prepare(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_USED)
        self.case = case
        self.events = []
        self.words = {}
        memory.write(CONTEXT + META_POINTER, 8, META)
        memory.write(CONTEXT + META_COUNT, 8, case.count)
        for row in range(min(case.count, 8)):
            memory.write(META + row * META_STRIDE, 8, case.token if row == case.index else DECOY + row)

        def first_entry(at, target):
            memory.write(at, 8, case.token if target else case.token ^ 0x100)
            memory.write(at + 8, 8, case.link if target else DECOY)

        def second_entry(at, target):
            memory.write(at, 8, case.link if target else case.link ^ 0x100)
            for side, (token_at, value_at) in enumerate(SIDES):
                chosen = target and side == case.side
                memory.write(at + token_at, 8, case.token if chosen else case.token ^ 0x40)
                memory.write(at + value_at, 8, case.value if chosen else case.value ^ DECOY)

        first_start = case.token * 7 & (BUCKETS - 1)
        second_start = case.link * 5 & (BUCKETS - 1)
        self.write_table(FIRST_TABLE, case.first, first_start, case.token, 16, first_entry)
        self.write_table(SECOND_TABLE, case.second, second_start, case.link, RECORD_SIZE, second_entry)
        for ctrl_at, mask_at, items_at, table, kind in ((FIRST_CTRL, FIRST_MASK, FIRST_ITEMS, FIRST_TABLE, case.first),
                                                        (SECOND_CTRL, SECOND_MASK, SECOND_ITEMS, SECOND_TABLE, case.second)):
            memory.write(CONTEXT + ctrl_at, 8, table)
            memory.write(CONTEXT + mask_at, 8, BUCKETS - 1)
            memory.write(CONTEXT + items_at, 8, 0 if kind == "empty" else 1)
        self.words[CONTEXT + FIRST_HASHER] = (case.token, H2 << 57 | 0x4000 | first_start)
        self.words[CONTEXT + SECOND_HASHER] = (case.link, H2 << 57 | 0x8000 | second_start)

    def run_case(self, case):
        self.prepare(case)
        machine = self.machine
        memory = machine.memory
        machine.xmm = [POISON | POISON << 64] * 16
        machine.xmm[0] = to_bits(case.p) | POISON << 64
        args = {RDI: OUT, R8: case.a, R9: case.b}
        if case.kind == "spot":
            entry = SPOT_GATE
            args.update({RSI: CONTEXT, RDX: case.index, RCX: UNUSED_MARK})
        else:
            entry = PERP_GATE
            args.update({RSI: UNUSED_MARK, RDX: UNUSED_MARK, RCX: USER_MARK})
        try:
            result = machine.run(entry, args)
        except Panicked as panic:
            location, one, two = panic.args[0]
            return ("panic", location, (one, two), tuple(self.events))
        if result != OUT:
            raise Halt("rax is not the out pointer")
        tag = memory.read(OUT, 2)
        payload = memory.read(OUT + 8, 8) if tag == TAG_BAND else None
        mark = bytes([STACK_MARK])
        if memory.bytes_at(OUT + 2, 6) != mark * 6 or memory.bytes_at(OUT + 16, 16) != mark * 16:
            raise Halt("result wrote more than its fields")
        if payload is None and memory.bytes_at(OUT + 8, 8) != mark * 8:
            raise Halt("result wrote an unexpected payload")
        return ("tag", tag, payload, tuple(self.events))

    def run_helper(self, case):
        self.prepare(case)
        machine = self.machine
        memory = machine.memory
        try:
            machine.run(CAP_HELPER, {RDI: OUT, RSI: CONTEXT + TOKENS, RDX: case.index, RCX: CONTEXT + TOKENS})
        except Panicked as panic:
            return ("panic", panic.args[0][0], panic.args[0][1], panic.args[0][2])
        if memory.read(OUT, 1) == 0:
            return ("ok", memory.read(OUT + 8, 8))
        return ("err", memory.read(OUT + 1, 1))


# ---- every path of the float decision, for all inputs ----

def show(value):
    return repr(value) if isinstance(value, float) else value


class Walker:
    """Symbolic run from the divide to the join. A compare forks only at its branch."""

    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)

    def constant(self, operand, size):
        if operand[1] is not None or operand[2] is not None:
            raise EvidenceError("not a constant operand: %r" % (operand,))
        return bytes(self.image.blob[self.image.offset(operand[4]):self.image.offset(operand[4]) + size])

    def scalar(self, regs, operand):
        if operand[0] == "x":
            return regs[operand[1]]
        if operand[1] == RSP and operand[4] == 8:
            return "P"
        return struct.unpack("<d", self.constant(operand, 8))[0]

    def paths(self, start, join):
        leaves = []
        self.walk(start, join, {0: "A", 2: "B"}, (), None, None, leaves, 64)
        return leaves

    def walk(self, pc, join, regs, conditions, compare, tag, leaves, fuel):
        regs = dict(regs)
        while True:
            fuel -= 1
            if fuel < 0:
                raise EvidenceError("walk did not reach the join")
            if pc == join:
                leaves.append((conditions, tag[0], tag[1]))
                return
            row = decode(self.machine.read_code, pc)
            op = row.op
            if op == "divsd" or op == "addsd" or op == "subsd" or op == "mulsd":
                sign = {"divsd": "/", "addsd": "+", "subsd": "-", "mulsd": "*"}[op]
                regs[row.a[1]] = "(%s%s%s)" % (show(regs[row.a[1]]), sign, show(self.scalar(regs, row.b)))
            elif op == "movx":
                if row.b[0] == "x":
                    regs[row.a[1]] = regs[row.b[1]]
                elif self.constant(row.b, 16) == ABS_MASK:
                    regs[row.a[1]] = "MASK"
                else:
                    raise EvidenceError("unknown vector constant at %#x" % pc)
            elif op == "andpd":
                if regs[row.a[1]] != "MASK":
                    raise EvidenceError("and without the sign mask at %#x" % pc)
                regs[row.a[1]] = "abs(%s)" % show(self.scalar(regs, row.b))
            elif op == "xorps":
                if row.a != row.b:
                    raise EvidenceError("xor of two registers at %#x" % pc)
                regs[row.a[1]] = 0.0
            elif op == "movsd":
                if row.a[0] == "x":
                    regs[row.a[1]] = self.scalar(regs, row.b)
                elif row.a[1] == RBX and row.a[4] == 8:
                    tag = (tag[0], show(regs[row.b[1]]))
                else:
                    raise EvidenceError("unexpected store at %#x" % pc)
            elif op == "ucomisd":
                compare = (show(self.scalar(regs, row.a)), show(self.scalar(regs, row.b)))
            elif op == "jcc":
                sign = {7: ">", 6: "<=!", 3: ">="}.get(row.cc)
                if sign is None or compare is None:
                    raise EvidenceError("unexpected branch at %#x" % pc)
                if row.cc == 6:
                    holds = "%s>%s" % compare
                    self.walk(row.next, join, regs, conditions + (holds,), None, tag, leaves, fuel)
                    conditions, pc, compare = conditions + ("!(%s)" % holds,), row.target, None
                    continue
                holds = "%s%s%s" % (compare[0], sign, compare[1])
                self.walk(row.target, join, regs, conditions + (holds,), None, tag, leaves, fuel)
                conditions, pc, compare = conditions + ("!(%s)" % holds,), row.next, None
                continue
            elif op == "mov" and row.a == ("m", RBX, None, 1, 0, False) and row.b[0] == "i" and row.width == 2:
                tag = (row.b[1], "")
            elif op == "jmp":
                pc = row.target
                continue
            else:
                raise EvidenceError("instruction outside the decision at %#x: %s" % (pc, op))
            pc = row.next


RATIO = "((A/B)+-1.0)"
UPPER = "((1.0/(1.0-P))+-1.0)"
WITHIN = "P>abs(%s)" % RATIO
BELOW_ONE = "1.0>P"
ABOVE = "%s>0.0" % RATIO
INSIDE = "%s>=%s" % (UPPER, RATIO)
FAIL = (TAG_BAND, "(P*100.0)")
OK_ROW = (TAG_OK, "")


def expected_paths():
    no = "!(%s)"
    return sorted([
        ((WITHIN,),) + OK_ROW,
        ((no % WITHIN, no % BELOW_ONE),) + FAIL,
        ((no % WITHIN, BELOW_ONE, no % ABOVE),) + FAIL,
        ((no % WITHIN, BELOW_ONE, ABOVE, INSIDE),) + OK_ROW,
        ((no % WITHIN, BELOW_ONE, ABOVE, no % INSIDE),) + FAIL,
    ])


def conversion_rows(image, patches, entry):
    """The rows from the first u64 move to the divide, with their rodata operands."""
    machine = Machine(image, patches)
    rows = []
    pc = entry
    while True:
        row = decode(machine.read_code, pc)
        if row.op == "divsd":
            return rows, pc
        if row.op == "movq" or rows:
            rows.append(row)
        pc = row.next
        if pc > entry + 0x100:
            raise EvidenceError("no divide near %#x" % entry)


def check_conversion(image, patches, entry):
    rows, divide = conversion_rows(image, patches, entry)
    if tuple(row.op for row in rows) != CONVERT_OPS:
        raise EvidenceError("conversion shape changed at %#x" % entry)
    walker = Walker(image, patches)
    exponents = walker.constant(rows[1].b, 8)
    offsets = walker.constant(rows[3].b, 16)
    if exponents != CONVERT_CONSTANTS["exponents"] or offsets != CONVERT_CONSTANTS["offsets"]:
        raise EvidenceError("conversion constants changed at %#x" % entry)
    return divide


def prove_paths(image, patches=None):
    rows = []
    for name, entry, join in GATES:
        divide = check_conversion(image, patches, entry)
        got = sorted(Walker(image, patches).paths(divide, join))
        if got != expected_paths():
            raise EvidenceError("%s paths differ: %r" % (name, got))
        rows.extend((name, "%#x" % divide, index + 1, " & ".join(conds), "%#x" % tag, payload) for index, (conds, tag, payload) in enumerate(got))
    return rows


# ---- vectors ----

GRID_U64 = (0, 1, 2, 3, 5, 10, 999, 1000, 1001, 10 ** 6, 10 ** 8, 2 ** 31, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1, 2 ** 52 + 1, 2 ** 53 - 1, 2 ** 53, 2 ** 53 + 1, 2 ** 54 + 2, 10 ** 15,
            2 ** 63 - 1, 2 ** 63, 2 ** 63 + 1025, 2 ** 64 - 1025, 2 ** 64 - 1)
GRID_P = (-math.inf, -1.0, -0.0, 0.0, 5e-324, 1e-300, VOTE_LOW, 0.25, 0.5, 0.8, VOTE_HIGH, 0.9999999999999999, 1.0, 1.0000000000000002, 2.0, math.inf, math.nan)
CAP_VALUES = (0, 1, 999, 1000, 1001, 5000, 2 ** 63, 2 ** 64 - 1)


def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MASK[8]
        yield state >> 11 ^ state


def named_cases():
    rows = [
        ("spot_inside", Case()),
        ("spot_equal_ref", Case(a=7, b=7, p=0.2)),
        ("spot_above", Case(a=301, b=100, p=0.5)),
        ("spot_below", Case(a=49, b=100, p=0.5)),
        ("spot_lower_edge_strict", Case(a=50, b=100, p=0.5)),
        ("spot_upper_edge_inclusive", Case(a=200, b=100, p=0.5)),
        ("spot_upper_past_edge", Case(a=201, b=100, p=0.5)),
        ("spot_zero_ref", Case(a=1, b=0, p=0.5)),
        ("spot_zero_both", Case(a=0, b=0, p=0.5)),
        ("spot_nan_distance", Case(a=100, b=100, p=math.nan)),
        ("spot_distance_one", Case(a=200, b=100, p=1.0)),
        ("spot_distance_one_below", Case(a=199, b=100, p=1.0)),
        ("spot_distance_two", Case(a=299, b=100, p=2.0)),
        ("spot_class_one", Case(cls=1, a=1, b=1)),
        ("spot_bound_panic", Case(index=3, count=3)),
        ("spot_bound_panic_high", Case(index=9, count=3, cls=1)),
        ("cap_ok", Case(cls=2, a=4000, value=5000)),
        ("cap_edge", Case(cls=2, a=4000, value=5000 - 1)),
        ("cap_equal", Case(cls=2, a=4000, value=5000, side=1)),
        ("cap_over", Case(cls=2, a=4001, value=5000)),
        ("cap_small_value", Case(cls=2, a=0, value=999)),
        ("cap_value_bias", Case(cls=2, a=0, value=1000)),
        ("cap_value_bias_over", Case(cls=2, a=1, value=1000)),
        ("cap_class_255", Case(cls=255, a=1, value=5000)),
        ("cap_no_band", Case(cls=2, a=4000, b=1, p=0.2, value=5000)),
        ("cap_neither_side", Case(cls=2, a=1, side=2)),
        ("perp_inside", Case(kind="perp")),
        ("perp_exempt_far", Case(kind="perp", exempt=1, a=10 ** 9, b=1, p=0.2)),
        ("perp_exempt_any_byte", Case(kind="perp", exempt=0x81, a=10 ** 9, b=1, p=0.2)),
        ("perp_above", Case(kind="perp", a=301, b=100, p=0.5)),
        ("perp_lower_edge_strict", Case(kind="perp", a=50, b=100, p=0.5)),
        ("perp_upper_edge_inclusive", Case(kind="perp", a=200, b=100, p=0.5)),
        ("perp_zero_ref", Case(kind="perp", a=1, b=0, p=0.5)),
        ("perp_nan_distance", Case(kind="perp", p=math.nan)),
    ]
    for first in TABLE_KINDS:
        rows.append(("first_" + first, Case(cls=2, a=1, first=first)))
    for second in TABLE_KINDS:
        rows.append(("second_" + second, Case(cls=2, a=1, second=second)))
    for side in (0, 1):
        rows.append(("side_%d_decoys" % side, Case(cls=2, a=4000, side=side, first="full_hit", second="third_hit")))
    return rows


def grid_cases(values=GRID_U64, distances=GRID_P):
    rows = []
    for a in values:
        for b in values:
            for p in distances:
                rows.append(Case(a=a, b=b, p=p))
                rows.append(Case(kind="perp", a=a, b=b, p=p))
    return rows


def cap_cases():
    rows = []
    for value in CAP_VALUES:
        for a in sorted({0, 1, value, (value - BIAS) & MASK[8], (value - BIAS + 1) & MASK[8], (value - BIAS - 1) & MASK[8], MASK[8]}):
            for side in (0, 1):
                rows.append(Case(cls=2, a=a, value=value, side=side))
    return rows


def random_cases(count, seed=0x9E3779B97F4A7C15):
    source = lcg(seed)
    rows = []
    for _ in range(count):
        b = next(source) >> (next(source) % 64)
        kind = next(source) % 3
        if kind == 0:
            a = next(source) >> (next(source) % 64)
        else:
            a = int(b * (0.1 + (next(source) % 1000) / 200.0)) & MASK[8]
        p = VOTE_LOW + (VOTE_HIGH - VOTE_LOW) * (next(source) % 10 ** 6) / 10 ** 6
        rows.append(Case(kind="perp" if next(source) & 1 else "spot", a=a, b=b, p=p))
    return rows


# ---- band edges, by binary search on a monotone ratio, then real bytes ----

EDGE_REFERENCES = (1, 2, 5, 10, 999, 10 ** 5, 10 ** 8, 123456789, 10 ** 12, 2 ** 53 + 2, 10 ** 18)
EDGE_DISTANCES = (VOTE_LOW, 0.25, 0.5, 0.75, 0.8, 0.9, 0.95, VOTE_HIGH)


def band_edges(b, p):
    """The admitted set is -p < ratio <= upper; ratio never falls as a grows, so it is one interval."""
    if not band_admits(b, b, p):
        raise EvidenceError("reference outside its own band")
    low, high = 0, b
    if band_admits(0, b, p):
        high = 0
    while high - low > 1:
        middle = (low + high) // 2
        if band_admits(middle, b, p):
            high = middle
        else:
            low = middle
    first = high
    low, high = b, MASK[8]
    if band_admits(high, b, p):
        low = high
    while high - low > 1:
        middle = (low + high) // 2
        if band_admits(middle, b, p):
            low = middle
        else:
            high = middle
    return first, low


def exact_edges(b, p):
    """Real-number edges of (1 - p) b < a <= b / (1 - p), with the stored double as p."""
    keep = 1 - fractions.Fraction(p)
    return int(b * keep) + 1, int(b / keep)


def edge_rows(harness):
    rows, runs = [], 0
    for b in EDGE_REFERENCES:
        for p in EDGE_DISTANCES:
            upper = 1.0 / (1.0 - p) - 1.0
            if not upper >= p:
                raise EvidenceError("upper bound below distance at %r" % p)
            first, last = band_edges(b, p)
            exact_first, exact_last = exact_edges(b, p)
            for kind in ("spot", "perp"):
                for a, want in ((first - 1, TAG_BAND), (first, TAG_OK), (last, TAG_OK), (last + 1, TAG_BAND)):
                    if a < 0 or a > MASK[8]:
                        continue
                    got = harness.run_case(Case(kind=kind, a=a, b=b, p=p))
                    runs += 1
                    if got[1] != want or (want == TAG_BAND and got[2] != to_bits(p * SCALE)):
                        raise EvidenceError("edge %d %r %d: %r" % (b, p, a, got))
            rows.append((b, repr(p), first, last, exact_first, exact_last, first - exact_first, last - exact_last))
    return rows, runs


# ---- byte census ----

def text_view(image):
    base, text = image.text_bytes()
    return base, text


def tag_writes(image, tag):
    base, text = text_view(image)
    word = re.escape(struct.pack("<H", tag))
    shapes = rb"\x66(?:\x41)?\xc7[\x00-\xbf]" + word + rb"|\x66(?:\x41)?\xc7[\x40-\x7f][\x00-\xff]" + word
    return sorted(base + match.start() for match in re.finditer(shapes, text))


def slot_rows(image):
    """All RIP-relative calls and jumps through the gate slots, with the f64 load before each call."""
    base, text = text_view(image)
    relative = image.relative()
    want = {SLOT_SPOT: SPOT_GATE, SLOT_PERP: PERP_GATE, SLOT_WRAPPER: WRAPPER, SLOT_HELPER: CAP_HELPER}
    for slot, target in want.items():
        if relative.get(slot) != target:
            raise EvidenceError("slot changed: %#x" % slot)
    if len([slot for slot, value in relative.items() if value in want.values()]) != len(want):
        raise EvidenceError("a gate has another pointer slot")
    rows = []
    at = text.find(b"\xff")
    while 0 <= at <= len(text) - 6:
        if text[at + 1] in (0x15, 0x25):
            slot = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
            if slot in (SLOT_SPOT, SLOT_PERP):
                window = text[at - 0x48:at]
                loads = list(re.finditer(rb"\xf3(?:\x41)?\x0f\x7e[\x80-\xbf](\x80\x39\x00\x00|\x00\x44\x00\x00)", window))
                if len(loads) != 1:
                    raise EvidenceError("field load near %#x: %d" % (base + at, len(loads)))
                load = loads[0]
                rows.append(("spot" if slot == SLOT_SPOT else "perp", base + at, slot, base + at - 0x48 + load.start(), struct.unpack("<I", load[1])[0]))
        at = text.find(b"\xff", at + 1)
    return sorted(rows)


def direct_calls(image, target):
    base, text = text_view(image)
    found = []
    at = text.find(b"\xe8")
    while 0 <= at <= len(text) - 5:
        if base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            found.append(base + at)
        at = text.find(b"\xe8", at + 1)
    return found


FIELD_FORMS = (
    ("store f64", rb"\xf2(?:\x41)?\x0f\x11[\x80-\xbf]"),
    ("load f64", rb"\xf2(?:\x41)?\x0f\x10[\x80-\xbf]"),
    ("load u64", rb"\xf3(?:\x41)?\x0f\x7e[\x80-\xbf]"),
    ("address", rb"[\x48\x49\x4c\x4d]\x8d[\x80-\xbf]"),
)


def field_census(image):
    base, text = text_view(image)
    rows = []
    for field in FIELDS:
        word = re.escape(struct.pack("<I", field))
        for form, shape in FIELD_FORMS:
            for match in re.finditer(shape + word, text):
                modrm = text[match.start() + len(match[0]) - 5]
                if modrm & 7 != 4:
                    rows.append(("%#x" % field, base + match.start(), form))
    return sorted(rows, key=lambda row: (row[0], row[1]))


VOTE_SHAPE = re.compile(rb"\xf2\x0f\x10\x0d(....)\x66\x0f\x2e\xc8\x0f\x87(....)\x66\x0f\x2e\x05(....)\x0f\x87(....)\xf2(?:\x41)?\x0f\x11[\x80-\xbf](\x80\x39\x00\x00|\x00\x44\x00\x00)", re.S)


def vote_rows(image):
    base, text = text_view(image)
    rows = []
    for match in VOTE_SHAPE.finditer(text):
        at = base + match.start()
        low_at = at + 8 + struct.unpack("<i", match[1])[0]
        high_at = at + 26 + struct.unpack("<i", match[3])[0]
        first = at + 18 + struct.unpack("<i", match[2])[0]
        second = at + 32 + struct.unpack("<i", match[4])[0]
        low = struct.unpack("<d", image.blob[image.offset(low_at):image.offset(low_at) + 8])[0]
        high = struct.unpack("<d", image.blob[image.offset(high_at):image.offset(high_at) + 8])[0]
        if low != VOTE_LOW or high != VOTE_HIGH:
            continue
        block = bytes(image.blob[image.offset(first):image.offset(first) + 9])
        if first != second or block != b"\x48\x8b\x04\x24\x66\xc7\x00" + struct.pack("<H", TAG_VOTE):
            raise EvidenceError("vote error block changed at %#x" % at)
        rows.append((at, low_at, repr(low), high_at, repr(high), first, "%#x" % TAG_VOTE, "%#x" % struct.unpack("<I", match[5])[0]))
    return rows


KEY_SHAPE = re.compile(rb"\xf2(?:\x41)?\x0f\x10[\x80-\xbf](\x80\x39\x00\x00|\x00\x44\x00\x00).{0,16}?\x48\x8d\x15(....)", re.S)


def key_rows(image):
    base, text = text_view(image)
    rows = []
    for match in KEY_SHAPE.finditer(text):
        at = base + match.start()
        target = at + len(match[0]) + struct.unpack("<i", match[2])[0]
        if target == KEY_ANCHOR:
            data = image.blob[image.offset(target):image.offset(target) + len(KEY_TEXT)]
            tail = text[match.end():match.end() + 16]
            if bytes(data) != KEY_TEXT or b"\x1e\x00\x00\x00" not in tail:
                raise EvidenceError("serde key changed at %#x" % at)
            rows.append((at, "%#x" % struct.unpack("<I", match[1])[0], target, KEY_TEXT.decode("ascii")))
    return rows


def display_tag(image, tag):
    entry = struct.unpack_from("<i", image.blob, image.offset(TAG_TABLE + 4 * tag))[0]
    arm = (TAG_TABLE + entry) & MASK[8]
    code = bytes(image.blob[image.offset(arm):image.offset(arm) + 32])
    prefix = bytes.fromhex("488b3e488b4608488b4018488d35")
    if not code.startswith(prefix) or code[18] != 0xBA:
        raise EvidenceError("unexpected Display arm %#x" % arm)
    start = arm + 18 + struct.unpack_from("<i", code, 14)[0]
    size = struct.unpack_from("<I", code, 19)[0]
    return arm, start, bytes(image.blob[image.offset(start):image.offset(start) + size]).decode("ascii")


def band_message(image):
    """Tag 0x5f prints one f64 between two literal pieces of a fmt string."""
    entry = struct.unpack_from("<i", image.blob, image.offset(TAG_TABLE + 4 * TAG_BAND))[0]
    arm = (TAG_TABLE + entry) & MASK[8]
    data = bytes(image.blob[image.offset(BAND_ARM_LEA):image.offset(BAND_ARM_LEA) + 7])
    if data[:3] != b"\x48\x8d\x15" or BAND_ARM_LEA + 7 + struct.unpack_from("<i", data, 3)[0] != PIECES_BAND:
        raise EvidenceError("band message lea changed")
    at = image.offset(PIECES_BAND)
    size = image.blob[at]
    first = bytes(image.blob[at + 1:at + 1 + size]).decode("ascii")
    at += 1 + size
    if image.blob[at] != 0xC0:
        raise EvidenceError("band message has no placeholder")
    size = image.blob[at + 1]
    second = bytes(image.blob[at + 2:at + 2 + size]).decode("ascii")
    return arm, first, second


WRAPPER_BYTES = bytes.fromhex("488b87800100004839c67319488b87780100004883c71048c1e605488b3430ff2593410402")


def wrapper_check(image):
    start = image.offset(WRAPPER)
    data = bytes(image.blob[start:start + 37])
    if data != WRAPPER_BYTES:
        raise EvidenceError("wrapper changed")
    return data.hex()


def targets(image):
    rows = []
    for name, start in (("spot gate", SPOT_GATE), ("perp gate", PERP_GATE), ("cap helper", CAP_HELPER)):
        low, high = image.exact_fde(start)
        rows.append((name, low, high, high - low, len(decode_range(image, low, high))))
    return rows


# ---- mutation controls ----

EXPECTED_SURVIVORS = {
    (0x372B51A, "immediate"): "pshufd 0x45 picks an equal dword, every byte of xmm0 is the same tag",
    (0x372B5E3, "immediate"): "pshufd 0x45 picks an equal dword, every byte of xmm0 is the same tag",
}


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] is None or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def mutation_targets(image, seen):
    edits = []
    for start in (SPOT_GATE, PERP_GATE, CAP_HELPER):
        low, high = image.exact_fde(start)
        for row in decode_range(image, low, high):
            if row.va not in seen or row.rip_at is not None:
                continue
            data = image.blob[image.offset(row.va):image.offset(row.va) + row.size]
            if row.op == "jcc":
                at = row.size - 5 if row.size >= 6 else 0
                edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
                continue
            if row.imm_at is not None and row.op not in ("call", "jmp"):
                edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
            if row.op in ("shl", "shr") and row.imm_at is None:
                edits.append((row.va, "shift", {row.va + row.size - 1: data[row.size - 1] ^ 8}))
            at = displacement_at(row, data)
            if at is not None:
                edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def first_failure(harness, sets):
    for name, case in sets:
        try:
            got = harness.run_case(case)
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError) as error:
            return "%s: %s" % (name, type(error).__name__)
        if got != spec(case):
            return "%s: differs" % name
    return None


def run_mutants(image, sets, seen):
    rows = []
    for va, kind, patch in mutation_targets(image, seen):
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        reason = first_failure(harness, sets)
        if reason is None:
            helper_cases = [case for name, case in sets if case.cls >= 2 and case.index < case.count] + [Case(index=5, count=3, cls=2)]
            for case in helper_cases:
                try:
                    got = harness.run_helper(case)
                except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError) as error:
                    reason = "helper: %s" % type(error).__name__
                    break
                if got != helper_spec(case):
                    reason = "helper: differs"
                    break
        if reason is None:
            rows.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "")))
        else:
            rows.append((va, kind, "killed", reason))
    survivors = sorted({(row[0], row[1]) for row in rows if row[2] == "survived"})
    if survivors != sorted(EXPECTED_SURVIVORS):
        raise EvidenceError("survivor list changed: %s" % " ".join("%#x/%s" % row for row in survivors))
    return rows


# ---- analysis ----

SPOT_SITES = (0x21F8BB4, 0x4C1818D, 0x4C19A9D)
PERP_SITES = (0x21F83BD, 0x4C189DD, 0x4C192BD)


def analyse(image, full=True, vectors=3000):
    harness = Harness(image)
    named = named_cases()
    counts = collections.Counter()
    outcomes = []
    for name, case in named:
        got = harness.run_case(case)
        want = spec(case)
        if got != want:
            raise EvidenceError("%s: %r != %r" % (name, got, want))
        counts["panic" if got[0] == "panic" else "%#x" % got[1]] += 1
        helper = "" if case.cls < 2 or case.index >= case.count else "%s/%s" % harness_helper(harness, case)
        outcomes.append((name, case.kind, got[0], "%#x" % got[1], "" if got[2] is None else got[2] if isinstance(got[2], tuple) else "%#x" % got[2], ",".join(got[3]), helper))
    grids = grid_cases()
    caps = cap_cases()
    randoms = random_cases(vectors)
    for group, rows in (("grid", grids), ("cap", caps), ("random", randoms)):
        for case in rows:
            got = harness.run_case(case)
            want = spec(case)
            if got != want:
                raise EvidenceError("%s %r: %r != %r" % (group, vars(case), got, want))
            counts["panic" if got[0] == "panic" else "%#x" % got[1]] += 1
    edges, edge_runs = edge_rows(harness)
    seen = set(harness.machine.seen)
    sites = slot_rows(image)
    spot_sites = tuple(row[1] for row in sites if row[0] == "spot")
    perp_sites = tuple(row[1] for row in sites if row[0] == "perp")
    if spot_sites != SPOT_SITES or perp_sites != PERP_SITES:
        raise EvidenceError("call sites changed")
    for start in (SPOT_GATE, PERP_GATE):
        if direct_calls(image, start):
            raise EvidenceError("gate has a direct call")
    tags = {"band": tag_writes(image, TAG_BAND), "cap": tag_writes(image, TAG_CAP)}
    if tags["band"] != [0x3713E87, 0x372F34F] or tags["cap"] != [0x372F38E]:
        raise EvidenceError("tag census changed: %r" % (tags,))
    keys = key_rows(image)
    votes = vote_rows(image)
    if len(votes) != 3 or {row[7] for row in votes} != {"0x3980", "0x4400"}:
        raise EvidenceError("vote guards changed: %r" % (votes,))
    result = {
        "targets": targets(image), "paths": prove_paths(image), "named": len(named), "grid": len(grids), "cap": len(caps), "random": len(randoms),
        "edge_runs": edge_runs, "edges": edges, "counts": counts, "outcomes": outcomes, "sites": sites, "fields": field_census(image), "votes": votes, "keys": keys,
        "tags": tags, "cap_text": display_tag(image, TAG_CAP), "class_text": display_tag(image, TAG_CLASS), "vote_text": display_tag(image, TAG_VOTE), "band_text": band_message(image),
        "wrapper": wrapper_check(image), "helper_calls": len([1 for _ in helper_sites(image)]),
    }
    if full:
        short = [("grid", case) for case in grid_cases(GRID_U64[::3], GRID_P[::2])]
        result["mutations"] = run_mutants(image, named + [("cap", case) for case in caps[:30]] + short[:120], seen)
    return result


def harness_helper(harness, case):
    got = harness.run_helper(case)
    want = helper_spec(case)
    if got != want:
        raise EvidenceError("helper: %r != %r" % (got, want))
    return got


def helper_sites(image):
    base, text = text_view(image)
    at = text.find(b"\xff\x15")
    while 0 <= at:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == SLOT_HELPER:
            yield base + at
        at = text.find(b"\xff\x15", at + 1)


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("targets.tsv", ("name", "fde_start", "fde_end", "bytes", "instructions"), [(a, "%#x" % b, "%#x" % c, d, e) for a, b, c, d, e in result["targets"]])
    tsv("paths.tsv", ("gate", "divide_at", "path", "conditions", "tag", "payload"), result["paths"])
    tsv("band-edges.tsv", ("b", "p", "first_admitted", "last_admitted", "exact_first", "exact_last", "first_minus_exact", "last_minus_exact"), result["edges"])
    tsv("outcomes.tsv", ("case", "gate", "kind", "tag_or_location", "payload", "calls", "helper"), result["outcomes"])
    tsv("call-sites.tsv", ("gate", "site", "slot", "distance_load", "field"), [(a, "%#x" % b, "%#x" % c, "%#x" % d, "%#x" % e) for a, b, c, d, e in result["sites"]])
    tsv("field-census.tsv", ("field", "address", "form"), [(a, "%#x" % b, c) for a, b, c in result["fields"]])
    tsv("vote-guards.tsv", ("guard", "low_at", "low", "high_at", "high", "error_block", "tag", "stored_field"),
        [("%#x" % a, "%#x" % b, c, "%#x" % d, e, "%#x" % f, g, h) for a, b, c, d, e, f, g, h in result["votes"]])
    tsv("serde-keys.tsv", ("load", "field", "key_at", "key"), [("%#x" % a, b, "%#x" % c, d) for a, b, c, d in result["keys"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    arm, first, second = result["band_text"]
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "named_cases": result["named"], "grid_cases": result["grid"], "cap_cases": result["cap"],
        "random_cases": result["random"], "edge_runs": result["edge_runs"], "runs_per_outcome": dict(sorted(result["counts"].items())),
        "paths_per_gate": len(expected_paths()), "tag_writes": {key: ["%#x" % va for va in value] for key, value in result["tags"].items()},
        "texts": {"0x5f": {"arm": "%#x" % arm, "first": first, "second": second},
                  "0xee": {"arm": "%#x" % result["cap_text"][0], "text": result["cap_text"][2]},
                  "0x17f": {"arm": "%#x" % result["class_text"][0], "text": result["class_text"][2]},
                  "0x41": {"arm": "%#x" % result["vote_text"][0], "text": result["vote_text"][2]}},
        "rule": "with r = float(a)/float(b) - 1: admitted when p > |r|, or p < 1 and r > 0 and 1/(1-p) - 1 >= r",
        "cap_rule": "admitted when the helper returns v, v >= 1000 and a <= v - 1000",
        "wrapper_bytes": result["wrapper"], "cap_helper_call_sites": result["helper_calls"],
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
    result = analyse(image)
    files = render(result)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files), "named": result["named"], "grid": result["grid"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
