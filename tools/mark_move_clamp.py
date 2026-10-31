#!/usr/bin/env python3
"""Pin the node #94 oracle price move band and the 1 percent mark clamp from ELF bytes.

Functions 0x21ff400 and 0x42d0250 apply one oracle update. When the dex config byte is not 3, a price
outside [daily/band, daily*band] is refused and keeps its old value. A Mark price that moves more
than 0.010000000000001 from the previous price is replaced by round(previous * (1 +- 0.01)), floored
at 1, and still reports an error string. A symbolic walk lists every path of the float decision, the
real bytes run over real B-tree layouts with only the calls stubbed, and a separately written
specification predicts every run. No objdump or readelf output is parsed, and the binary is never
executed. Standard library only.

    python3 tools/mark_move_clamp.py --out <dir>
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

COPY_A = 0x21FF400
COPY_B = 0x42D0250
DELTA = COPY_B - COPY_A
WRITERS = (0x235E840, 0x4CBBDE0, 0x4CBC720)
CALL_SITES = (("direct", 0x2707CDB, COPY_A), ("direct", 0x4CF3C3B, COPY_B), ("direct", 0x4CF98DB, COPY_B))
SITE_CONTEXT = ((0x2707CDB, 0x2707C73, 0x2707C4C, 0x2707910), (0x4CF3C3B, 0x4CF3BCB, 0x4CF3BA4, 0x4CF386B), (0x4CF98DB, 0x4CF9873, 0x4CF984C, 0x4CF9513))
SLOT_CHECK = 0x5773998
SLOT_ROUND = 0x576F6D8
SLOT_FORMAT = 0x576E040
SLOT_PAD = 0x576E000
SLOT_FREE = 0x576E010
SLOT_GROW = 0x576EA38
SLOT_GUARD = 0x576E8C0
SLOT_INDEX = 0x576E470
SLOT_BOUND = 0x576E150
SLOT_UNWRAP = 0x576E048
SLOT_LOOKUP = 0x5773EB8
PIECES_REJECT = 0x1E52AD
PIECES_CLAMP = 0x1E7579
REJECT_TEXT = b"\x1aPrice moved too far asset="
CLAMP_TEXT = b"0Price moved too far, new price is clamped asset="
GUARD_PATH = 0x216D9F
GUARD_TEXT = b"base/src/err_dur_guard.rs"
GUARD_ARGUMENT = 0x1700000001
GUARD_LENGTH = 0x36
LOCATION_INDEX = 0x56F21C0
LOCATION_DIGITS = 0x56F3350
KIND_TABLES = {COPY_A: (0x56A0AD0, 0x3D8380), COPY_B: (0x571EE00, 0x6F1650)}
POWER_TABLES = {COPY_A: 0x3E0E90, COPY_B: 0x6F7470}
KIND_NAMES = ("Spot", "Mark", "ExternalPerp")
PINS = {0x20A188: 0x3F847AE147AE16BB, 0x20A2F0: 0xBF847AE147AE147B, 0x20A2F8: 0x3F847AE147AE147B, 0x20A278: 0xBFF0000000000000,
        0x20A730: 0x3FF0000000000000, 0x20A940: 0x3FE0000000000000, 0x20A510: 0x43F0000000000000, 0x20A218: 0x43EFFFFFFFFFFFFF, 0x20A7F0: 0x43E0000000000000}
ROW_CONSTANTS = {"gate": 0x20A188, "low": 0x20A2F0, "high": 0x20A2F8, "half": 0x20A940, "two64": 0x20A510, "below64": 0x20A218}
GATE = to_float(PINS[0x20A188])
LOW = to_float(PINS[0x20A2F0])
HIGH = to_float(PINS[0x20A2F8])
TWO64 = to_float(PINS[0x20A510])
BELOW64 = to_float(PINS[0x20A218])
ONE_HI = 0x2083B0
ABS_CONSTANT = 0x202ED0
ABS_MASK = bytes.fromhex("ffffffffffffff7fffffffffffffff7f")
CONVERT_LOW = bytes.fromhex("0000304300003045")
CONVERT_HIGH = bytes.fromhex("00000000000030430000000000003045")
MINUS_SIGN = 1 << 63
OK_RESULT = 1 << 63
STRING_CAP = 0x31
STRING_BASE = 0xE000000000
UNUSED_MARK = 0xB7B7B7B7B7B7B7B0
DECOY = 0xC3C3C3C3C3C3C3C3

HEAP_USED = 0x1C000
ORACLE = HEAP_BASE + 0x100
INPUT = HEAP_BASE + 0x300
LISTS = HEAP_BASE + 0x400
UPDATES = HEAP_BASE + 0x800
UPDATE_STRIDE = 0x800
CONFIG = HEAP_BASE + 0x2400
DEX = HEAP_BASE + 0x2600
OUT_VEC = HEAP_BASE + 0x2700
OUT_BUF = HEAP_BASE + 0x2800
ROWS = HEAP_BASE + 0x4000
META = HEAP_BASE + 0x5000
FIRST_TREE = HEAP_BASE + 0x6000
SECOND_TREE = HEAP_BASE + 0xB000
WRITER_OUT = HEAP_BASE + 0x100
WRITER_NAME = HEAP_BASE + 0x300
WRITER_STATE = HEAP_BASE + 0x1000
WRITER_DEXES = HEAP_BASE + 0x8000
ROW_SIZE = 0x60
ENTRY_SIZE = 0x20
META_SIZE = 0x30
FIRST_NODE = 0x720
FIRST_VALUE = 0x90
FIRST_KEYS = 0x638
FIRST_LEN = 0x692
FIRST_EDGES = 0x698
SECOND_NODE = 0x280
SECOND_VALUE = 0x28
SECOND_KEYS = 8
SECOND_LEN = 0x21A
SECOND_EDGES = 0x220
SECOND_VALUES = 0x60
FILL = 0x5A
TAG_OK = 0x186
TAG_NO_DEX = 0x141
TAG_LENGTH = 0x143
NAME_LIMIT = 100
DEX_STRIDE = 0x2F0
DEX_BAND = 0x1A8
DEX_MODE = 0x230


def fdiv(left, right):
    if right == 0.0:
        return math.nan if left == 0.0 or left != left else math.copysign(math.inf, left) * math.copysign(1.0, right)
    return left / right


def fround(value):
    if value != value or math.isinf(value) or abs(value) >= 2.0 ** 52:
        return value
    whole = float(math.trunc(value))
    if abs(value - whole) >= 0.5:
        whole += math.copysign(1.0, value)
    return math.copysign(whole, value)


def tail(value):
    """Round output to a raw price: the bytes after the helper call."""
    kept = value if value > 0.0 else 0.0
    if math.isinf(kept):
        kept = 0.0
    elif kept > TWO64:
        kept = TWO64
    if kept > BELOW64:
        return MASK[8]
    return int(kept) or 1


def wire(asset):
    if asset <= 9999:
        return asset
    if asset <= 0x5F45A5F:
        return asset + 100000
    return 0xFFFFFFFF


def band_admits(new, daily, band):
    ratio = fdiv(float(new), float(daily))
    return not float(band) < ratio and not ratio < fdiv(1.0, float(band))


def clamp_input(new, previous):
    """The argument of the round call, or None when the raw price is stored."""
    moved = fdiv(float(new), float(previous)) - 1.0
    if abs(moved) <= GATE:
        return None
    step = moved
    if not math.isinf(moved) and moved == moved:
        low = LOW if LOW > moved else moved
        step = HIGH if HIGH < low else low
    return (step + 1.0) * float(previous)


class Case:
    FIELDS = dict(updates=None, length=8, meta=None, dex=0, mode=0, band=3, rows=None, time=(0x11, 0x22, 0x33), old=(1, 2, 3), flag=7, refs=None, over=None,
                  default=(0.25, 9, 1), fails=(), pad=(0, 0), capacity=32, prelen=0, guard=(0, 0, 0, 0, 0, 0), first=0)

    def __init__(self, **extra):
        for key, value in self.FIELDS.items():
            setattr(self, key, extra.pop(key, value))
        if extra:
            raise EvidenceError("unknown case field")
        self.updates = self.updates or ((), (), ())
        self.meta = self.meta or tuple((0, 2) for _ in range(self.length))
        self.rows = self.rows or {}
        self.refs = self.refs or {}
        self.over = self.over or {}


def entry_of(case, local, kind):
    return case.rows.get((local, kind), (1000, 1000))


class Stop(Exception):
    pass


def spec(case):
    """Separately written prediction of one whole run: events, stored rows, out vector, guard words."""
    events = []
    stored = {}
    out = [("old", index) for index in range(case.prelen)]
    capacity = case.capacity
    guard = list(case.guard)

    def price(local, kind):
        return stored.get((local, kind), entry_of(case, local, kind) + (case.old,))

    def store(local, kind, value=None):
        current = price(local, kind)
        stored[(local, kind)] = (current[0] if value is None else value, current[1], case.time)

    def push(cap, length):
        nonlocal capacity
        if len(out) == capacity:
            events.append(("grow",))
            capacity = capacity * 2 + 4
        out.append((cap, length))

    def meta_row(asset):
        local = asset % 10000
        if asset // 10000 != case.dex or local >= len(case.meta) + case.first:
            raise Stop(("panic", "index", LOCATION_INDEX))
        return case.meta[local - case.first]

    def divisor(digits):
        if digits >= 7:
            raise Stop(("panic", "digits", LOCATION_DIGITS))
        return 10.0 ** (6 - digits)

    result = ("done",)
    try:
        for kind in range(3):
            for asset, new in case.updates[kind]:
                local = asset % 10000
                if local >= case.length + case.first:
                    continue
                reference = case.refs.get(asset, (0, 0, 0))[kind]
                first, second, third = case.over.get(asset, (None, None, None))
                events.append(("check", case.flag, kind, asset, new, reference, to_bits(case.default[0] if first is None else first),
                               case.default[1] if second is None else second, case.default[2] if third in (None, 3) else third))
                if (kind, asset) in case.fails:
                    store(local, kind)
                    push(STRING_CAP, 3)
                    continue
                if case.mode == 3:
                    store(local, kind, new)
                    continue
                previous, daily, _ = price(local, kind)
                if not band_admits(new, daily, case.band):
                    scale = divisor(meta_row(asset)[1])
                    events.append(("log", PIECES_REJECT, wire(asset) & MASK[4], kind, to_bits(float(previous) / scale), to_bits(float(new) / scale), to_bits(float(daily) / scale)))
                    store(local, kind)
                    push(STRING_CAP, 5)
                    continue
                flag = meta_row(asset)[0]
                ratio = fdiv(float(new), float(daily)) - 1.0
                if not flag and abs(ratio) > 0.5:
                    events.append(("pad", KIND_NAMES[kind]))
                    if case.pad[0]:
                        raise Stop(("panic", "unwrap", 0))
                    if case.pad[1]:
                        events.append(("free", case.pad[1]))
                if kind != 1:
                    store(local, kind, new)
                    continue
                argument = clamp_input(new, previous)
                if argument is None:
                    store(local, kind, new)
                    continue
                events.append(("round", to_bits(argument)))
                clamped = tail(fround(argument))
                scale = divisor(meta_row(asset)[1])
                events.append(("log", PIECES_CLAMP, wire(asset) & MASK[4], kind, to_bits(float(previous) / scale), to_bits(float(new) / scale), to_bits(float(clamped) / scale), to_bits(float(daily) / scale)))
                store(local, kind, clamped)
                push(STRING_CAP, 6)
        if not out:
            guard[0] = 0
            guard[3] = 0
        elif case.mode == 3:
            if guard[0] == 0:
                guard[:3] = case.time
            guard[3:] = case.time
            events.append(("guard", tuple(guard[:3]), tuple(case.time)))
    except Stop as stop:
        result = stop.args[0]
    rows = {}
    for local in range(case.first, case.first + case.length):
        for kind in range(3):
            rows[(local, kind)] = price(local, kind)
    return result, tuple(events), tuple(sorted(rows.items())), tuple(out), capacity, tuple(guard)


class Harness:
    def __init__(self, image, patches=None, constants=None):
        self.image = image
        self.machine = Machine(image, patches)
        memory = self.machine.memory
        relative = image.relative()
        hooks = {}
        for slot, hook in ((SLOT_CHECK, self.on_check), (SLOT_ROUND, self.on_round), (SLOT_FORMAT, self.on_format), (SLOT_PAD, self.on_pad), (SLOT_FREE, self.on_free),
                           (SLOT_GROW, self.on_grow), (SLOT_GUARD, self.on_guard), (SLOT_INDEX, self.on_index), (SLOT_BOUND, self.on_bound), (SLOT_UNWRAP, self.on_unwrap),
                           (SLOT_LOOKUP, self.on_lookup)):
            target = relative[slot]
            memory.statics[slot] = target
            hooks[target] = hook
        for pointers, _ in KIND_TABLES.values():
            for kind in range(len(KIND_NAMES)):
                memory.statics[pointers + 8 * kind] = relative[pointers + 8 * kind]
        for address, value in (constants or {}).items():
            memory.statics[address] = value
        self.machine.slots = hooks
        self.case = None
        self.events = []
        self.entry = None
        self.strings = 0
        self.lookup = None

    def string(self, destination, length):
        self.strings += 1
        memory = self.machine.memory
        memory.write(destination, 8, STRING_CAP)
        memory.write(destination + 8, 8, STRING_BASE + self.strings)
        memory.write(destination + 16, 8, length)

    def on_check(self, machine):
        memory = machine.memory
        regs = machine.regs
        config = memory.read(regs[RSP], 8)
        if memory.read(regs[RSP] + 8, 8) != DEX:
            raise Halt("check context differs")
        third = memory.read(config + 16, 1)
        kind = memory.read(regs[RSP] + 0x15, 1)
        self.events.append(("check", regs[RSI] & 0xFF, kind, regs[RDX], regs[R8], regs[R9], memory.read(config, 8), memory.read(config + 8, 8), third))
        self.current = (self.events[-1][2], regs[RDX])
        if self.current in self.case.fails:
            self.string(regs[RDI], 3)
        else:
            memory.write(regs[RDI], 8, OK_RESULT)

    def on_round(self, machine):
        value = machine.xmm[0] & MASK[8]
        self.events.append(("round", value))
        machine.xmm_result = to_bits(fround(to_float(value)))

    def on_format(self, machine):
        memory = machine.memory
        regs = machine.regs
        pieces = regs[RSI]
        count = {PIECES_REJECT: 5, PIECES_CLAMP: 6}.get(pieces)
        if count is None:
            raise Halt("unknown pieces")
        args = regs[RDX]
        values = [memory.read(memory.read(args + 16 * index, 8), 8) for index in range(count)]
        self.events.append(("log", pieces, values[0] & MASK[4], values[1] & 0xFF) + tuple(values[2:]))
        self.string(regs[RDI], count)

    def on_pad(self, machine):
        memory = machine.memory
        regs = machine.regs
        self.events.append(("pad", memory.bytes_at(regs[RSI], regs[RDX]).decode()))
        string = memory.read(regs[RDI], 8)
        if memory.read(string, 8) != 0 or memory.read(string + 8, 8) != 1 or memory.read(string + 16, 8) != 0 or memory.read(regs[RDI] + 16, 8) != 0x60000020:
            raise Halt("formatter differs")
        if self.case.pad[1]:
            buffer = memory.read(regs[RDI], 8)
            memory.write(buffer, 8, self.case.pad[1])
            memory.write(buffer + 8, 8, STRING_BASE)
        regs[RAX] = POISON & ~0xFF | self.case.pad[0]

    def on_free(self, machine):
        self.events.append(("free", machine.regs[RSI]))

    def on_grow(self, machine):
        memory = machine.memory
        vector = machine.regs[RDI]
        self.events.append(("grow",))
        memory.write(vector, 8, memory.read(vector, 8) * 2 + 4)

    def on_guard(self, machine):
        memory = machine.memory
        now, record = machine.regs[RDI], machine.regs[RSI]
        words = tuple(memory.read(record + 4 * index, 4) for index in range(3))
        if memory.read(record + 16, 8) != GUARD_ARGUMENT or memory.read(record + 24, 8) != GUARD_PATH or memory.read(record + 32, 8) != GUARD_LENGTH:
            raise Halt("guard record differs")
        self.events.append(("guard", words, tuple(memory.read(now + 4 * index, 4) for index in range(3))))

    def on_index(self, machine):
        raise Panicked(("index", machine.regs[RDI]))

    def on_bound(self, machine):
        raise Panicked(("digits", machine.regs[RDI]))

    def on_unwrap(self, machine):
        if machine.regs[RSI] != 0x37:
            raise Halt("unwrap message length differs")
        raise Panicked(("unwrap", 0))

    def on_lookup(self, machine):
        memory = machine.memory
        regs = machine.regs
        self.events.append(("lookup", regs[RSI] - WRITER_STATE, regs[RCX]))
        memory.write(regs[RDI], 2, self.lookup[0])
        if self.lookup[0] == TAG_OK:
            memory.write(regs[RDI] + 8, 8, self.lookup[1])

    def stale_key(self):
        """Unused key slots repeat the last update, so a wrong length finds a false hit."""
        lists = [row for row in self.case.updates if row]
        return lists[-1][-1][0] if lists else 0

    def write_first(self, refs):
        memory = self.machine.memory
        keys = sorted(refs)
        if not keys:
            return 0, 0
        stale = self.stale_key()

        def leaf(at, chosen):
            memory.write(at + FIRST_LEN, 2, len(chosen))
            for index, key in enumerate(chosen):
                memory.write(at + FIRST_KEYS + 8 * index, 8, key)
                for kind in range(3):
                    memory.write(at + FIRST_VALUE * index + 0x28 + 0x30 * kind, 8, refs[key][kind])
            for index in range(len(chosen), 11):
                memory.write(at + FIRST_KEYS + 8 * index, 8, stale)
            return at

        if len(keys) <= 11:
            return leaf(FIRST_TREE, keys), 0
        middle = len(keys) // 2
        root = leaf(FIRST_TREE, keys[middle:middle + 1])
        memory.write(root + FIRST_EDGES, 8, leaf(FIRST_TREE + FIRST_NODE, keys[:middle]))
        memory.write(root + FIRST_EDGES + 8, 8, leaf(FIRST_TREE + 2 * FIRST_NODE, keys[middle + 1:]))
        return root, 1

    def write_second(self, over):
        memory = self.machine.memory
        keys = sorted(over)
        if not keys:
            return 0, 0
        stale = self.stale_key()

        def leaf(at, chosen):
            memory.write(at + SECOND_LEN, 2, len(chosen))
            for index, key in enumerate(chosen):
                memory.write(at + SECOND_KEYS + 8 * index, 8, key)
                value = at + SECOND_VALUES + SECOND_VALUE * index
                first, second, third = over[key]
                memory.write(value, 1, 0 if first is None else 1)
                memory.write(value + 8, 8, to_bits(first) if first is not None else DECOY)
                memory.write(value + 16, 1, 0 if second is None else 1)
                memory.write(value + 24, 8, DECOY if second is None else second)
                memory.write(value + 32, 1, 3 if third is None else third)
            for index in range(len(chosen), 11):
                memory.write(at + SECOND_KEYS + 8 * index, 8, stale)
                memory.write(at + SECOND_VALUES + SECOND_VALUE * index, 1, 1)
                memory.write(at + SECOND_VALUES + SECOND_VALUE * index + 8, 8, to_bits(0.875))
            return at

        if len(keys) <= 11:
            return leaf(SECOND_TREE, keys), 0
        middle = len(keys) // 2
        root = leaf(SECOND_TREE, keys[middle:middle + 1])
        memory.write(root + SECOND_EDGES, 8, leaf(SECOND_TREE + SECOND_NODE, keys[:middle]))
        memory.write(root + SECOND_EDGES + 8, 8, leaf(SECOND_TREE + 2 * SECOND_NODE, keys[middle + 1:]))
        return root, 1

    def prepare(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_USED)
        self.case = case
        self.events = []
        self.strings = 0
        write = memory.write
        write(ORACLE + 8, 8, ROWS - ROW_SIZE * case.first)
        write(ORACLE + 16, 8, case.first + case.length)
        root, height = self.write_first(case.refs)
        write(ORACLE + 0x18, 8, root)
        write(ORACLE + 0x20, 8, height)
        root, height = self.write_second(case.over)
        write(ORACLE + 0x48, 8, root)
        write(ORACLE + 0x50, 8, height)
        write(ORACLE + 0x60, 8, to_bits(case.default[0]))
        write(ORACLE + 0x68, 8, case.default[1])
        write(ORACLE + 0x70, 1, case.default[2])
        for index, value in enumerate(case.guard):
            write(ORACLE + 0x80 + 4 * index, 4, value)
        write(INPUT, 8, LISTS)
        write(INPUT + 8, 8, CONFIG)
        write(INPUT + 16, 8, DEX)
        write(INPUT + 24, 8, UNUSED_MARK)
        write(INPUT + 32, 8, OUT_VEC)
        for index, word in enumerate(case.time):
            write(INPUT + 40 + 4 * index, 4, word)
        write(INPUT + 52, 1, case.flag)
        for kind in range(3):
            write(LISTS + 0x18 * kind + 8, 8, UPDATES + UPDATE_STRIDE * kind)
            write(LISTS + 0x18 * kind + 16, 8, len(case.updates[kind]))
            for index, (asset, new) in enumerate(case.updates[kind]):
                write(UPDATES + UPDATE_STRIDE * kind + 16 * index, 8, asset)
                write(UPDATES + UPDATE_STRIDE * kind + 16 * index + 8, 8, new)
            write(UPDATES + UPDATE_STRIDE * kind + 16 * len(case.updates[kind]), 8, case.first)
            write(UPDATES + UPDATE_STRIDE * kind + 16 * len(case.updates[kind]) + 8, 8, 7777)
        write(CONFIG, 8, case.band)
        write(CONFIG + 0x88, 1, case.mode)
        write(DEX + 8, 8, META - META_SIZE * case.first)
        write(DEX + 16, 8, len(case.meta) + case.first)
        write(DEX + 0x30, 8, case.dex)
        for index, (flag, digits) in enumerate(case.meta):
            write(META + META_SIZE * index + 0x28, 1, flag)
            write(META + META_SIZE * index + 0x2A, 1, digits)
        write(OUT_VEC, 8, case.capacity)
        write(OUT_VEC + 8, 8, OUT_BUF)
        write(OUT_VEC + 16, 8, case.prelen)
        for local in range(case.first, case.first + case.length):
            for kind in range(3):
                at = ROWS + ROW_SIZE * (local - case.first) + ENTRY_SIZE * kind
                previous, daily = entry_of(case, local, kind)
                write(at, 8, previous)
                write(at + 8, 8, daily)
                for index, word in enumerate(case.old):
                    write(at + 16 + 4 * index, 4, word)
                write(at + 28, 4, 0x5A5A5A5A)

    def run_case(self, case, entry=COPY_A):
        self.prepare(case)
        machine = self.machine
        memory = machine.memory
        result = ("done",)
        try:
            machine.run(entry, {RDI: ORACLE, RSI: INPUT})
        except Panicked as panic:
            result = ("panic",) + panic.args[0]
        rows = {}
        for local in range(case.first, case.first + case.length):
            for kind in range(3):
                at = ROWS + ROW_SIZE * (local - case.first) + ENTRY_SIZE * kind
                if memory.read(at + 28, 4) != 0x5A5A5A5A:
                    raise Halt("row padding changed")
                rows[(local, kind)] = (memory.read(at, 8), memory.read(at + 8, 8), tuple(memory.read(at + 16 + 4 * index, 4) for index in range(3)))
        length = memory.read(OUT_VEC + 16, 8)
        out = []
        for index in range(length):
            if index < case.prelen:
                out.append(("old", index))
            else:
                out.append((memory.read(OUT_BUF + 24 * index, 8), memory.read(OUT_BUF + 24 * index + 16, 8)))
        guard = tuple(memory.read(ORACLE + 0x80 + 4 * index, 4) for index in range(6))
        return result, tuple(self.events), tuple(sorted(rows.items())), tuple(out), memory.read(OUT_VEC, 8), guard

    def run_writer(self, entry, name, value, dexes, lookup, layout):
        state_field, state_count, state_pointer, _ = layout
        memory = self.machine.memory
        memory.reset(HEAP_USED)
        self.events = []
        self.lookup = lookup
        memory.write(WRITER_STATE + state_pointer, 8, WRITER_DEXES)
        memory.write(WRITER_STATE + state_count, 8, len(dexes))
        memory.write(WRITER_STATE + state_field, 8, 0x77)
        for index, (mode, word) in enumerate(dexes):
            memory.write(WRITER_DEXES + DEX_STRIDE * index + DEX_MODE, 1, mode)
            memory.write(WRITER_DEXES + DEX_STRIDE * index + DEX_BAND, 8, word)
        memory.write(WRITER_NAME, 8, OK_RESULT if name is None else 0x40)
        memory.write(WRITER_NAME + 8, 8, STRING_BASE)
        memory.write(WRITER_NAME + 16, 8, name or 0)
        self.machine.run(entry, {RDI: WRITER_OUT, RSI: WRITER_NAME, RDX: WRITER_STATE, RCX: value})
        words = tuple(memory.read(WRITER_DEXES + DEX_STRIDE * index + DEX_BAND, 8) for index in range(len(dexes)))
        return memory.read(WRITER_OUT, 2), words, memory.read(WRITER_STATE + state_field, 8), tuple(self.events)


# ---- every path of the float decision, for all inputs ----

WALK_START = 0x21FF93E
LOAD_PREVIOUS = 0x21FFAB7
EXITS = {0x21FFC33: "reject", 0x21FF82A: "store", 0x21FFB64: "clamp", 0x22000FB: "panic", 0x2200108: "panic"}
LABELS = {0x21FF964: ("inband", False), 0x21FF978: ("dex", False), 0x21FF982: ("bound", False), 0x21FF9A7: ("flag", True), 0x21FFA55: ("padfail", True),
          0x21FFA80: ("nocap", True), 0x21FFAB1: ("notmark", True), 0x21FFB35: ("nonfinite", True)}
CONVERT_OPS = ("movsd", "punpckldq", "subpd", "movx", "unpckhpd", "addsd")
INT_ROWS = frozenset(("mov", "lea", "movzx", "shl", "cmp", "test", "and", "imul3", "add", "xor"))
JUNK = "J"


def show(value):
    return repr(value) if isinstance(value, float) else value


class Walker:
    def __init__(self, image, delta=0, patches=None):
        self.image = image
        self.delta = delta
        self.machine = Machine(image, patches)

    def constant(self, operand, size):
        if operand[1] is not None or operand[2] is not None:
            raise EvidenceError("not a constant operand: %r" % (operand,))
        return bytes(self.image.blob[self.image.offset(operand[4]):self.image.offset(operand[4]) + size])

    def low(self, regs, operand):
        if operand[0] == "x":
            return regs[operand[1]][0]
        return struct.unpack("<d", self.constant(operand, 8))[0]

    def paths(self):
        leaves = []
        regs = {index: (JUNK, JUNK) for index in range(16)}
        regs[4] = ("N", JUNK)
        regs[3] = ("D", "B")
        self.walk(WALK_START + self.delta, regs, {}, (), None, leaves, 400)
        return leaves

    def walk(self, pc, regs, stack, conditions, compare, leaves, fuel):
        regs = dict(regs)
        stack = dict(stack)
        while True:
            fuel -= 1
            if fuel < 0:
                raise EvidenceError("walk did not end")
            home = pc - self.delta
            if home in EXITS:
                leaves.append((conditions, EXITS[home], show(regs[0][0]) if EXITS[home] == "clamp" else ""))
                return
            if home == LOAD_PREVIOUS:
                rows = []
                at = pc
                for _ in CONVERT_OPS:
                    rows.append(decode(self.machine.read_code, at))
                    at = rows[-1].next
                if tuple(row.op for row in rows) != CONVERT_OPS or self.constant(rows[1].b, 8) != CONVERT_LOW or self.constant(rows[2].b, 16) != CONVERT_HIGH:
                    raise EvidenceError("previous price conversion changed")
                regs[5] = ("P", JUNK)
                regs[0] = (JUNK, JUNK)
                pc = at
                continue
            row = decode(self.machine.read_code, pc)
            op = row.op
            if op == "movx":
                if row.a[0] == "x" and row.b[0] == "x":
                    regs[row.a[1]] = regs[row.b[1]]
                elif row.a[0] == "x" and row.b[1] == RSP:
                    regs[row.a[1]] = stack[row.b[4]]
                elif row.b[0] == "x" and row.a[1] == RSP:
                    stack[row.a[4]] = regs[row.b[1]]
                else:
                    raise EvidenceError("vector move at %#x" % pc)
            elif op == "shufpd":
                left, right = regs[row.a[1]], None
                if row.b[0] == "x":
                    right = regs[row.b[1]]
                else:
                    data = self.constant(row.b, 16)
                    right = (show(struct.unpack_from("<d", data, 0)[0]), show(struct.unpack_from("<d", data, 8)[0]))
                regs[row.a[1]] = (left[row.target & 1], right[(row.target >> 1) & 1])
            elif op == "divpd":
                left, right = regs[row.a[1]], regs[row.b[1]]
                regs[row.a[1]] = tuple("(%s/%s)" % (a, b) for a, b in zip(left, right))
            elif op == "cmppd":
                if row.target != 5:
                    raise EvidenceError("compare predicate at %#x" % pc)
                left, right = regs[row.a[1]], regs[row.b[1]]
                regs[row.a[1]] = tuple("!(%s<%s)" % (a, b) for a, b in zip(left, right))
            elif op == "movmskpd":
                compare = ("mask", regs[row.b[1]])
            elif op in ("addsd", "mulsd", "divsd"):
                sign = {"addsd": "+", "mulsd": "*", "divsd": "/"}[op]
                regs[row.a[1]] = ("(%s%s%s)" % (show(regs[row.a[1]][0]), sign, show(self.low(regs, row.b))), JUNK)
            elif op in ("minsd", "maxsd"):
                regs[row.a[1]] = ("%s(%s,%s)" % (op, show(regs[row.a[1]][0]), show(self.low(regs, row.b))), JUNK)
            elif op == "andpd":
                if self.constant(row.b, 16) != ABS_MASK:
                    raise EvidenceError("and without the sign mask")
                regs[row.a[1]] = ("abs(%s)" % show(regs[row.a[1]][0]), JUNK)
            elif op == "movsd":
                regs[row.a[1]] = (self.low(regs, row.b), JUNK)
            elif op == "ucomisd":
                compare = ("float", show(self.low(regs, row.a)), show(self.low(regs, row.b)))
            elif op == "movq":
                pass
            elif op in ("calli", "call"):
                regs = {index: (JUNK, JUNK) for index in range(16)}
            elif op == "jcc":
                label = LABELS.get(home)
                if label:
                    name, when = label
                    if name == "inband":
                        name = "&".join(compare[1])
                    taken = (conditions + ((name if when else "not " + name),))
                    fall = (conditions + (("not " + name if when else name),))
                elif compare and compare[0] == "float":
                    sign = {6: ">", 3: ">="}.get(row.cc)
                    if sign is None:
                        raise EvidenceError("branch form at %#x" % pc)
                    holds = "%s%s%s" % (compare[1], sign, compare[2])
                    if row.cc == 6:
                        taken, fall = conditions + ("not " + holds,), conditions + (holds,)
                    else:
                        taken, fall = conditions + (holds,), conditions + ("not " + holds,)
                else:
                    raise EvidenceError("unlabelled branch at %#x" % pc)
                self.walk(row.target, regs, stack, taken, compare, leaves, fuel)
                conditions, pc = fall, row.next
                continue
            elif op == "jmp":
                pc = row.target
                continue
            elif op not in INT_ROWS:
                raise EvidenceError("row outside the decision at %#x: %s" % (pc, op))
            pc = row.next


BAND = "!(B<(N/D))&!((N/D)<(1.0/B))"
MOVE = "((N/P)+-1.0)"
WITHIN = "%r>=abs(%s)" % (GATE, MOVE)
CLAMP_FINITE = "((minsd(%r,maxsd(%r,%s))+1.0)*P)" % (HIGH, LOW, MOVE)
CLAMP_OTHER = "((%s+1.0)*P)" % MOVE
DROPPED = ("flag", "padfail", "nocap", "dex", "bound")


def expected_paths():
    return sorted([
        (("not " + BAND,), "reject", ""),
        ((BAND, "notmark"), "store", ""),
        ((BAND, "not notmark", WITHIN), "store", ""),
        ((BAND, "not notmark", "not " + WITHIN, "nonfinite"), "clamp", CLAMP_OTHER),
        ((BAND, "not notmark", "not " + WITHIN, "not nonfinite"), "clamp", CLAMP_FINITE),
    ])


def reduce_path(row):
    conditions = tuple(c for c in row[0] if c.replace("not ", "") not in DROPPED and "0.5" not in c)
    return conditions, row[1], row[2]


def prove_paths(image, delta=0, patches=None):
    leaves = Walker(image, delta, patches).paths()
    kept = sorted({reduce_path(row) for row in leaves if row[1] != "panic"})
    if kept != expected_paths():
        raise EvidenceError("paths differ: %r" % (kept,))
    return len(leaves), kept


# ---- static facts ----

def targets(image):
    rows = []
    for name, start in (("clamp A", COPY_A), ("clamp B", COPY_B), ("band writer 1", WRITERS[0]), ("band writer 2", WRITERS[1]), ("band writer 3", WRITERS[2])):
        low, high = image.exact_fde(start)
        rows.append((name, low, high, high - low, len(decode_range(image, low, high))))
    return rows


def copies_match(image):
    """Both copies decode to the same rows with branches shifted by DELTA; returns compared and rip-relative rows."""
    first = decode_range(image, *image.exact_fde(COPY_A))
    second = decode_range(image, *image.exact_fde(COPY_B))
    if len(first) != len(second):
        raise EvidenceError("copies differ in length")
    rips = 0
    low, high = image.exact_fde(COPY_A)
    for one, two in zip(first, second):
        if one.va + DELTA != two.va or one.op != two.op or one.width != two.width or one.size != two.size:
            raise EvidenceError("copies differ at %#x" % one.va)
        if one.rip_at is not None:
            rips += 1
            continue
        same = (one.a == two.a and one.b == two.b) or one.op in ("jcc", "jmp", "call")
        if not same:
            raise EvidenceError("copies differ at %#x" % one.va)
        if one.op in ("jcc", "jmp", "call") and low <= one.target < high and one.target + DELTA != two.target:
            raise EvidenceError("branch differs at %#x" % one.va)
    return len(first), rips


def constant_rows(image):
    rows = []
    for address, bits in sorted(PINS.items()):
        got = struct.unpack_from("<Q", image.blob, image.offset(address))[0]
        if got != bits:
            raise EvidenceError("constant changed at %#x" % address)
        rows.append(("%#x" % address, "%#018x" % got, repr(to_float(got))))
    return rows


def site_constants(image):
    """Each float constant the clamp reads, per copy, from decoded rip operands."""
    rows = []
    for start in (COPY_A, COPY_B):
        wanted = {address: name for name, address in ROW_CONSTANTS.items()}
        counts = collections.Counter()
        for row in decode_range(image, *image.exact_fde(start)):
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] is None and operand[2] is None and operand[4] in wanted and row.rip_at is not None:
                    counts[wanted[operand[4]]] += 1
        rows.append(("%#x" % start, ",".join("%s=%d" % item for item in sorted(counts.items()))))
    return rows


def kind_rows(image):
    rows = []
    relative = image.relative()
    for start, (pointers, lengths) in KIND_TABLES.items():
        for kind, name in enumerate(KIND_NAMES):
            pointer = relative[pointers + 8 * kind]
            size = struct.unpack_from("<Q", image.blob, image.offset(lengths + 8 * kind))[0]
            text = bytes(image.blob[image.offset(pointer):image.offset(pointer) + size]).decode()
            if text != name:
                raise EvidenceError("kind text changed: %s" % text)
            rows.append(("%#x" % start, kind, "%#x" % pointer, size, text))
    return rows


def power_rows(image):
    for start, table in POWER_TABLES.items():
        data = struct.unpack_from("<7d", image.blob, image.offset(table))
        if data != tuple(10.0 ** index for index in range(7)):
            raise EvidenceError("power table changed at %#x" % table)
    return {"%#x" % start: "%#x" % table for start, table in POWER_TABLES.items()}


def message_rows(image):
    reject = bytes(image.blob[image.offset(PIECES_REJECT):image.offset(PIECES_REJECT) + len(REJECT_TEXT)])
    clamp = bytes(image.blob[image.offset(PIECES_CLAMP):image.offset(PIECES_CLAMP) + len(CLAMP_TEXT)])
    guard = bytes(image.blob[image.offset(GUARD_PATH):image.offset(GUARD_PATH) + GUARD_LENGTH])
    if reject != REJECT_TEXT or clamp != CLAMP_TEXT or not guard.endswith(GUARD_TEXT):
        raise EvidenceError("messages changed")
    return {"reject": reject[1:-7].decode(), "clamp": clamp[1:-7].decode(), "guard": GUARD_TEXT.decode()}


def text_view(image):
    return image.text_bytes()


def direct_calls(image, target):
    base, text = text_view(image)
    found = []
    at = text.find(b"\xe8")
    while 0 <= at < len(text) - 5:
        if base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            found.append(base + at)
        at = text.find(b"\xe8", at + 1)
    return found


def lea_sites(image, target):
    base, text = text_view(image)
    found = []
    at = text.find(b"\x48\x8d")
    while 0 <= at < len(text) - 7:
        if text[at + 2] & 0xC7 == 5 and base + at + 7 + struct.unpack_from("<i", text, at + 3)[0] == target:
            found.append(base + at)
        at = text.find(b"\x48\x8d", at + 1)
    return found


def locations(image):
    relative = image.relative()
    rows = []
    for name, slot in (("index", LOCATION_INDEX), ("digits", LOCATION_DIGITS)):
        path, line, column = image.location(slot, relative)
        rows.append((name, "%#x" % slot, path, line, column))
    return rows


def site_rows(image):
    """Each call site: the lea of the band word (+0x1a8), the lea of the oracle (+0x60) and the +0x230 == 3 gate."""
    rows = []
    for site, band, oracle, gate in SITE_CONTEXT:
        lea = bytes(image.blob[image.offset(band):image.offset(band) + 7])
        second = bytes(image.blob[image.offset(oracle):image.offset(oracle) + 4])
        third = bytes(image.blob[image.offset(gate):image.offset(gate) + 7])
        if not re.fullmatch(rb"\x48\x8d[\x80-\xbf]\xa8\x01\x00\x00", lea, re.S) or not re.fullmatch(rb"\x4c\x8d[\x40-\x7f]\x60", second, re.S) or not re.fullmatch(rb"\x80[\xb8-\xbf]\x30\x02\x00\x00\x03", third, re.S):
            raise EvidenceError("call site context changed at %#x" % site)
        rows.append(("%#x" % site, "%#x" % band, "%#x" % oracle, "%#x" % gate))
    return rows


def state_layout(image, start):
    """The state offsets one band writer uses, read from its rows: field, count, pointer, lookup base."""
    rows = decode_range(image, *image.exact_fde(start))
    field = next(row.a[4] for row in rows if row.op == "mov" and row.a[0] == "m" and row.a[1] == RDX and row.b == ("r", RCX))
    count = next(row.b[4] for row in rows if row.op == "mov" and row.b[0] == "m" and row.b[1] == RDX and row.a == ("r", RAX))
    pointer = next(row.b[4] for row in rows if row.op == "mov" and row.b[0] == "m" and row.b[1] == R9 and row.a == ("r", RAX))
    base = next(row.b[1] for row in rows if row.op == "add" and row.a == ("r", RDX) and row.b[0] == "i")
    return field, count, pointer, base


def writer_spec(name, value, dexes, lookup, layout):
    words = [word for _, word in dexes]
    events = []
    if name is None:
        return TAG_OK, tuple(max(word, value) if mode != 3 else word for mode, word in dexes), value, tuple(events)
    if name > NAME_LIMIT:
        events.append(("free", 0x40))
        return TAG_LENGTH, tuple(words), 0x77, tuple(events)
    events.append(("lookup", layout[3], name))
    if lookup[0] != TAG_OK:
        events.append(("free", 0x40))
        return lookup[0], tuple(words), 0x77, tuple(events)
    index = (lookup[1] - WRITER_DEXES) // DEX_STRIDE
    if dexes[index][0] == 3:
        events.append(("free", 0x40))
        return TAG_NO_DEX, tuple(words), 0x77, tuple(events)
    words[index] = value
    events.append(("free", 0x40))
    return TAG_OK, tuple(words), 0x77, tuple(events)


def writer_cases():
    rows = []
    for count in range(0, 7):
        for value in (0, 5, 2 ** 64 - 1):
            rows.append((None, value, tuple((3 if index == 1 else 0, 4 + index) for index in range(count)), None))
    three = ((0, 9), (3, 8), (2, 7))
    rows.append((5, 4, three, (TAG_OK, WRITER_DEXES)))
    rows.append((5, 4, three, (TAG_OK, WRITER_DEXES + 2 * DEX_STRIDE)))
    rows.append((5, 4, three, (TAG_OK, WRITER_DEXES + DEX_STRIDE)))
    rows.append((100, 4, three, (TAG_OK, WRITER_DEXES)))
    rows.append((101, 4, three, None))
    rows.append((7, 4, three, (TAG_NO_DEX + 1, 0)))
    return rows


def check_writers(image, patches=None):
    rows = []
    runs = 0
    for start in WRITERS:
        layout = state_layout(image, start)
        harness = Harness(image, patches)
        for name, value, dexes, lookup in writer_cases():
            got = harness.run_writer(start, name, value, dexes, lookup, layout)
            want = writer_spec(name, value, dexes, lookup, layout)
            if got != want:
                raise EvidenceError("writer %#x: %r != %r" % (start, got, want))
            runs += 1
        rows.append(("%#x" % start,) + tuple("%#x" % value for value in layout))
    return rows, runs


# ---- vectors ----

SITE = 5
ASSET = 5
GRID_PRICES = (0, 1, 2, 3, 49, 50, 51, 99, 100, 101, 1000, 1009, 1010, 1011, 1500, 3000, 3001, 9999, 10 ** 6, 10 ** 12, 2 ** 53 + 1, 2 ** 63, 2 ** 64 - 1)
GRID_BANDS = (0, 1, 2, 3, 10, 2 ** 64 - 1)


def one(kind, new, previous=1000, daily=1000, asset=ASSET, **extra):
    updates = [(), (), ()]
    updates[kind] = ((asset, new),)
    rows = dict(extra.pop("rows", {}))
    rows[(asset % 10000, kind)] = (previous, daily)
    return Case(updates=tuple(updates), rows=rows, **extra)


def named_cases():
    rows = []

    def add(name, case):
        rows.append((name, case))

    add("no_updates", Case())
    add("no_updates_guard_cleared", Case(guard=(4, 5, 6, 7, 8, 9)))
    add("no_updates_old_errors_mode3", Case(prelen=2, mode=3, guard=(4, 5, 6, 7, 8, 9)))
    add("old_errors_mode0_guard_kept", Case(prelen=2, guard=(4, 5, 6, 7, 8, 9)))
    add("local_past_table", one(1, 1000, asset=8))
    add("local_past_table_dex", one(1, 1000, asset=10008))
    for kind in range(3):
        add("plain_store_%d" % kind, one(kind, 1005))
        add("reject_high_%d" % kind, one(kind, 3001))
        add("reject_low_%d" % kind, one(kind, 333))
        add("band_edge_high_%d" % kind, one(kind, 3000, previous=3000))
        add("band_edge_low_%d" % kind, one(kind, 334, previous=334))
        add("half_gate_%d" % kind, one(kind, 1501, previous=1501))
        add("half_gate_flag_%d" % kind, one(kind, 1501, previous=1501, meta=tuple((1, 2) for _ in range(8))))
        add("half_gate_exact_%d" % kind, one(kind, 1500, previous=1500))
        add("mode3_%d" % kind, one(kind, 5, mode=3))
        add("mode3_guard_%d" % kind, one(kind, 5, mode=3, fails=((kind, ASSET),)))
        add("check_fail_%d" % kind, one(kind, 1005, fails=((kind, ASSET),)))
        add("check_fail_mode3_old_guard_%d" % kind, one(kind, 1005, mode=3, fails=((kind, ASSET),), guard=(4, 5, 6, 7, 8, 9)))
        add("pad_fail_%d" % kind, one(kind, 1501, previous=1501, pad=(1, 0)))
        add("pad_capacity_%d" % kind, one(kind, 1501, previous=1501, pad=(0, 16)))
        add("dex_differs_%d" % kind, one(kind, 1005, asset=10005))
        add("dex_differs_reject_%d" % kind, one(kind, 9000, asset=10005))
        add("dex_same_%d" % kind, one(kind, 1005, asset=30005, dex=3))
        add("digits_6_reject_%d" % kind, one(kind, 9000, meta=tuple((0, 6) for _ in range(8))))
        add("digits_7_reject_%d" % kind, one(kind, 9000, meta=tuple((0, 7) for _ in range(8))))
        add("digits_0_reject_%d" % kind, one(kind, 9000, meta=tuple((0, 0) for _ in range(8))))
        add("meta_shorter_%d" % kind, one(kind, 9000, meta=((0, 2),) * 3))
    add("digits_6_clamp", one(1, 1500, meta=tuple((0, 6) for _ in range(8))))
    add("digits_7_clamp", one(1, 1500, meta=tuple((0, 7) for _ in range(8))))
    add("clamp_up", one(1, 1020))
    add("clamp_down", one(1, 980))
    add("clamp_wire_spot_range", one(1, 1020, asset=10005, dex=1))
    add("clamp_wire_top", one(1, 1020, asset=99890005, dex=9989))
    add("clamp_wire_past", one(1, 1020, asset=99910005, dex=9991))
    add("mark_no_gate_at_1", one(1, 1010))
    add("mark_past_1", one(1, 1011))
    add("mark_below_1", one(1, 989))
    add("mark_previous_zero", one(1, 1000, previous=0))
    add("mark_previous_zero_new_zero", one(1, 0, previous=0))
    add("daily_zero_new_zero_band", one(0, 0, previous=9, daily=0))
    add("daily_zero_new_one", one(1, 1, previous=9, daily=0))
    add("band_zero", one(0, 1000, band=0))
    add("band_max", one(0, 1000, band=2 ** 64 - 1))
    add("grow_out", Case(updates=(((1, 9000), (2, 9000), (3, 9000)), (), ()), capacity=1))
    add("order_of_kinds", Case(updates=(((1, 1001),), ((1, 1002),), ((1, 1003),))))
    add("same_asset_twice", Case(updates=((), ((1, 1005), (1, 1012)), ())))
    add("later_list_after_short", Case(updates=((), ((9, 1), (2, 1005)), ((3, 1005),))))
    add("gate_far_inside", one(1, 10100, 10000, 10000))
    add("gate_far_outside", one(1, 10101, 10000, 10000))
    add("gate_far_near_constant", one(1, 10105, 10000, 10000))
    add("gate_gap_inside", one(1, 10 ** 16 + 10 ** 14 + 6, 10 ** 16, 10 ** 16))
    add("gate_gap_outside", one(1, 10 ** 16 + 10 ** 14 + 40, 10 ** 16, 10 ** 16))
    add("saturate_top_edge", one(1, 2 ** 64 - 1, 17 * 10 ** 18, 17 * 10 ** 18))
    add("saturate_top", one(1, 2 ** 64 - 1, 18300000000000000000, 18300000000000000000))
    add("near_two64", one(1, 2 ** 64 - 1, 18250000000000000000, 18250000000000000000))
    add("wire_last_perp", one(1, 1020, asset=9999, first=9999, length=1, meta=((0, 2),)))
    add("wire_first_spot", one(1, 1020, asset=10000, dex=1, first=0, length=1, meta=((0, 2),)))
    add("wire_last_range", one(1, 1020, asset=99899999, dex=9989, first=9999, length=1, meta=((0, 2),)))
    add("wire_past_range", one(1, 1020, asset=99900000, dex=9990, first=0, length=1, meta=((0, 2),)))
    add("wire_last_perp_reject", one(1, 9000, asset=9999, first=9999, length=1, meta=((0, 2),)))
    add("wire_last_range_reject", one(1, 9000, asset=99899999, dex=9989, first=9999, length=1, meta=((0, 2),)))
    add("wire_past_range_reject", one(1, 9000, asset=99900000, dex=9990, first=0, length=1, meta=((0, 2),)))
    add("meta_shorter_accept", one(1, 1005, meta=((0, 2),) * 3))
    add("dex_same_reject", one(1, 9000, asset=30005, dex=3))
    add("dex_same_clamp", one(1, 1020, asset=30005, dex=3))
    add("dex_same_accept_half", one(0, 1501, 1501, 1000, asset=30005, dex=3))
    add("guard_first_word_only", one(0, 5, mode=3, fails=((0, ASSET),), guard=(4, 0, 0, 0, 0, 0)))
    add("guard_third_word_only", one(0, 5, mode=3, fails=((0, ASSET),), guard=(0, 0, 6, 0, 0, 0)))
    add("guard_clear_keeps_rest", Case(guard=(4, 5, 6, 7, 8, 9)))
    add("reference_tree_gap", Case(updates=(((5, 1005),), (), ()), refs={3: (11, 12, 13), 7: (14, 15, 16)}))
    add("override_miss_stale", Case(updates=(((5, 1005),), (), ()), over={3: (0.5, 77, 2)}))
    add("override_gap", Case(updates=(((5, 1005),), (), ()), over={3: (0.5, 77, 2), 7: (0.75, 78, 0)}))
    add("override_two_levels_gap", Case(updates=(((2, 1005), (9, 1005)), (), ()), length=20, meta=tuple((0, 2) for _ in range(20)), over={key: (0.125, key, 1) for key in range(0, 30, 3)} | {30: (0.25, 1, 1), 33: (0.25, 1, 1), 36: (0.25, 1, 1), 39: (0.25, 1, 1)}))
    refs = {key: (key + 1, key + 2, key + 3) for key in range(0, 16)}
    add("reference_tree_leaf", Case(updates=(((3, 1005),), ((4, 1005),), ((5, 1005),)), refs={3: (11, 12, 13), 4: (21, 22, 23), 5: (31, 32, 33), 7: (1, 1, 1)}, length=8))
    add("reference_tree_two_levels", Case(updates=(((1, 1005), (7, 1005)), ((6, 1005), (14, 1005)), ((15, 1005),)), refs=refs, length=16, meta=tuple((0, 2) for _ in range(16))))
    add("reference_tree_miss", Case(updates=(((9, 1005),), (), ()), refs={3: (11, 12, 13)}, length=10, meta=tuple((0, 2) for _ in range(10))))
    add("reference_tree_two_levels_miss", Case(updates=(((16, 1005),), (), ()), refs=refs, length=20, meta=tuple((0, 2) for _ in range(20))))
    add("override_all", Case(updates=(((3, 1005),), (), ()), over={3: (0.5, 77, 2)}))
    add("override_none", Case(updates=(((3, 1005),), (), ()), over={3: (None, None, None)}))
    add("override_first", Case(updates=(((3, 1005),), (), ()), over={3: (0.5, None, None)}))
    add("override_second", Case(updates=(((3, 1005),), (), ()), over={3: (None, 77, None)}))
    add("override_third", Case(updates=(((3, 1005),), (), ()), over={3: (None, None, 0)}))
    add("override_two_levels", Case(updates=(((2, 1005), (6, 1005), (15, 1005)), ((16, 1005),), ()), over={key: (0.125 * (key + 1), key, 1) for key in range(15)}, length=20, meta=tuple((0, 2) for _ in range(20))))
    return rows


def grid_cases(prices=GRID_PRICES, bands=GRID_BANDS):
    rows = []
    for kind in (0, 1):
        for new in prices:
            for previous in prices:
                for daily in prices[::2]:
                    rows.append(one(kind, new, previous, daily, band=bands[(new ^ previous ^ daily) % len(bands)], meta=tuple(((new ^ daily) & 1, 2) for _ in range(8))))
    return rows


def lcg(seed):
    while True:
        seed = (seed * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MASK[8]
        yield seed


def random_cases(count, seed=0x9E3779B97F4A7C15):
    stream = lcg(seed)
    rows = []
    for _ in range(count):
        words = [next(stream) for _ in range(7)]
        bits = [8 + word % 56 for word in words[:3]]
        previous = 1 + (words[0] >> (64 - bits[0]))
        ratio = 1 << (words[3] & 3)
        new = max(1, (previous * (1000 + (words[4] >> 56) - 128) // 1000) >> (words[3] >> 3 & 1)) & MASK[8]
        daily = max(1, new // ratio) if words[5] & 1 else 1 + (words[1] >> (64 - bits[1]))
        rows.append(one(int(words[6] % 3), new, previous, daily, band=1 + (words[2] >> 60), meta=tuple(((words[6] >> 8) & 1, words[6] >> 9 & 7 if (words[6] >> 9 & 7) < 7 else 6) for _ in range(8))))
    return rows


EDGE_PRICES = (100, 1000, 12345, 10 ** 6, 123456789, 10 ** 12, 10 ** 15, 2 ** 53, 10 ** 17, 10 ** 18)


def mark_after(harness, new, previous, entry=COPY_A):
    case = one(1, new, previous, previous, band=1000)
    got = harness.run_case(case, entry)
    if got != spec(case):
        raise EvidenceError("edge run differs at %d %d" % (new, previous))
    return dict(got[2])[(ASSET, 1)][0], any(event[0] == "log" for event in got[1])


def stored_edge(harness, previous, step):
    """Last new price, moving by step from previous, that is stored raw."""
    good, bad = previous, previous + step * max(1, previous // 10)
    if not mark_after(harness, good, previous)[1] and mark_after(harness, bad, previous)[1]:
        while abs(good - bad) > 1:
            middle = (good + bad) // 2
            if mark_after(harness, middle, previous)[1]:
                bad = middle
            else:
                good = middle
        return good
    raise EvidenceError("no edge near %d" % previous)


def edge_rows(harness):
    rows = []
    for previous in EDGE_PRICES:
        high = stored_edge(harness, previous, 1)
        low = stored_edge(harness, previous, -1)
        exact_high = fractions.Fraction(previous) * fractions.Fraction(101, 100)
        exact_low = fractions.Fraction(previous) * fractions.Fraction(99, 100)
        up = mark_after(harness, previous * 2, previous)[0]
        down = mark_after(harness, max(previous // 2, 1), previous)[0]
        rows.append((previous, high, high - math.floor(exact_high), low, low - math.ceil(exact_low), up, down))
    return rows


def fixed_rows(harness, limit=160):
    """Clamped result next to the previous price for small raw prices, real bytes on both directions."""
    rows = []
    for previous in range(1, limit + 1):
        up = mark_after(harness, previous * 3, previous)
        down = mark_after(harness, 1, previous) if previous >= 2 else (None, False)
        rows.append((previous, up[0], up[1], "" if down[0] is None else down[0], down[1]))
    return rows


def fixed_summary(rows):
    first_up = next(row[0] for row in rows if row[2] and row[1] != row[0])
    first_down = next(row[0] for row in rows if row[4] and row[3] != row[0])
    unmoved_up = [row[0] for row in rows if row[2] and row[1] == row[0]]
    unmoved_down = [row[0] for row in rows if row[4] and row[3] == row[0]]
    return {"first_previous_moved_up": first_up, "first_previous_moved_down": first_down, "last_unmoved_up": max(unmoved_up), "last_unmoved_down": max(unmoved_down)}


def fixed_model(limit=200000):
    """Integer sweep of the closed form: past the listed points every clamp moves the price."""
    up = max(previous for previous in range(1, limit) if tail(fround(1.01 * previous)) == previous)
    down = max(previous for previous in range(2, limit) if tail(fround((LOW + 1.0) * previous)) == previous)
    return {"last_fixed_up": up, "last_fixed_down": down, "swept_to": limit}


# ---- mutation controls ----

EXPECTED_SURVIVORS = {
    (0x20A510, "constant:two64"): "a value at 2^64 or above already saturates at the next compare",
    (0x21FF454, "displacement"): "iterator end pointer, never read back here",
    (0x21FF458, "immediate"): "iterator state slot, never read back here",
    (0x21FF48B, "immediate"): "iterator state slot, never read back here",
    (0x21FF493, "displacement"): "padding bytes of the config copy, the stub reads the low byte",
    (0x21FF786, "displacement"): "padding bytes of the config copy, the stub reads the low byte",
    (0x21FF7C9, "displacement"): "padding bytes of the config copy, the stub reads the low byte",
    (0x21FF4EA, "immediate"): "second exit test of the kind loop, the rbx test stops it first",
    (0x21FFB09, "immediate"): "low bit of the abs mask, q is never that close to infinity",
    (0x21FFB16, "immediate"): "low bit of the finite limit, q is never that close to infinity",
    (0x21FFB77, "immediate"): "low bit of the abs mask, the rounded value is never that close to infinity",
    (0x21FFB84, "immediate"): "low bit of the finite limit, the rounded value is never that close to infinity",
    (0x21FFBB1, "immediate"): "sar by 62 keeps all but bit 0, doubles at or above 2^63 are multiples of 2048",
    (0x21FFBD4, "immediate"): "the value is never below zero after maxsd",
    (0x21FFBE6, "immediate"): "saturation is unreachable: a clamped rise stays below the new u64 price",
    (0x21FFE00, "immediate"): "a formatted String capacity is never i64::MIN",
    (0x21FFE6C, "displacement"): "the same bound was already tested at 0x21ff982 on this path",
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


def mutation_targets(image, seen):
    edits = []
    low, high = image.exact_fde(COPY_A)
    for row in decode_range(image, low, high):
        if row.va not in seen or row.rip_at is not None:
            continue
        data = image.blob[image.offset(row.va):image.offset(row.va) + row.size]
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp", "shufpd", "cmppd"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        if row.op in ("shufpd", "cmppd"):
            edits.append((row.va, "immediate", {row.va + row.size - 1: data[row.size - 1] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def first_failure(harness, sets):
    for name, case in sets:
        try:
            got = harness.run_case(case)
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, struct.error, AttributeError) as error:
            return "%s: %s" % (name, type(error).__name__)
        if got != spec(case):
            return "%s: differs" % name
    return None


def constant_mutants(image, sets):
    rows = []
    for name, address in sorted(ROW_CONSTANTS.items()) + [("one", 0x20A730), ("minus_one", 0x20A278)]:
        bits = PINS[address]
        harness = Harness(image, None, {address: bits ^ (1 << 49)})
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        reason = first_failure(harness, sets)
        rows.append((address, "constant:" + name, "survived" if reason is None else "killed", reason or ""))
    return rows


def run_mutants(image, sets, seen):
    rows = []
    for va, kind, patch in mutation_targets(image, seen):
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        reason = first_failure(harness, sets)
        rows.append((va, kind, "killed" if reason else "survived", reason or EXPECTED_SURVIVORS.get((va, kind), "")))
    rows.extend(constant_mutants(image, sets))
    survivors = sorted((row[0], row[1]) for row in rows if row[2] == "survived")
    if survivors != sorted(EXPECTED_SURVIVORS):
        raise EvidenceError("survivor list changed: %s" % " ".join("%#x/%s" % row for row in survivors))
    return rows


# ---- analysis ----

def check_all(harness, cases, entry):
    for name, case in cases:
        got = harness.run_case(case, entry)
        want = spec(case)
        if got != want:
            raise EvidenceError("%s at %#x: %r != %r" % (name, entry, got, want))


def analyse(image, full=True, vectors=2500):
    harness = Harness(image)
    named = named_cases()
    grids = [("grid", case) for case in grid_cases()]
    randoms = [("random", case) for case in random_cases(vectors)]
    counts = collections.Counter()
    outcomes = []
    check_all(harness, named, COPY_A)
    seen_named = set(harness.machine.seen)
    for name, case in named:
        got = harness.run_case(case, COPY_A)
        logs = ",".join(event[0] + (":" + ("reject" if event[1] == PIECES_REJECT else "clamp") if event[0] == "log" else "") for event in got[1])
        outcomes.append((name, got[0][0] + ("" if len(got[0]) == 1 else ":" + got[0][1]), logs, len(got[3])))
    check_all(harness, grids + randoms, COPY_A)
    second = Harness(image)
    check_all(second, named + grids[::7] + randoms[::5], COPY_B)
    for group in (named, grids, randoms):
        for _, case in group:
            got = spec(case)
            counts[got[0][0]] += 1
            for event in got[1]:
                counts[event[0] + (":reject" if event[0] == "log" and event[1] == PIECES_REJECT else ":clamp" if event[0] == "log" else "")] += 1
    edges = edge_rows(harness)
    fixed = fixed_rows(harness)
    seen = set(harness.machine.seen)
    low, high = image.exact_fde(COPY_A)
    rows_a = decode_range(image, low, high)
    reached = sum(1 for row in rows_a if row.va in seen)
    paths_a, kept = prove_paths(image)
    paths_b, kept_b = prove_paths(image, DELTA)
    if kept != kept_b or paths_a != paths_b:
        raise EvidenceError("copies have different paths")
    sites = [(kind, site, target) for kind, site, target in CALL_SITES]
    for kind, site, target in sites:
        if site not in direct_calls(image, target):
            raise EvidenceError("call site changed: %#x" % site)
    if len(direct_calls(image, COPY_A)) != 1 or len(direct_calls(image, COPY_B)) != 2:
        raise EvidenceError("call census changed")
    leas = {"%#x" % address: ["%#x" % va for va in lea_sites(image, address)] for address in (PIECES_REJECT, PIECES_CLAMP)}
    if len(leas["%#x" % PIECES_REJECT]) != 2 or len(leas["%#x" % PIECES_CLAMP]) != 2:
        raise EvidenceError("message census changed")
    writers, writer_runs = check_writers(image)
    compared, rips = copies_match(image)
    result = {
        "targets": targets(image), "constants": constant_rows(image), "constant_reads": site_constants(image), "kinds": kind_rows(image), "powers": power_rows(image),
        "messages": message_rows(image), "named": len(named), "grid": len(grids), "random": len(randoms), "counts": counts, "outcomes": outcomes, "edges": edges,
        "site_context": site_rows(image), "fixed": fixed, "fixed_summary": fixed_summary(fixed), "fixed_model": fixed_model(), "paths": kept, "raw_paths": paths_a, "sites": sites, "leas": leas,
        "locations": locations(image), "writers": writers, "writer_runs": writer_runs, "reached": reached, "rows": len(rows_a), "compared": compared, "rip_rows": rips,
    }
    if full:
        result["mutations"] = run_mutants(image, named + grids[:40] + randoms[:40], seen_named | seen)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("targets.tsv", ("name", "fde_start", "fde_end", "bytes", "instructions"), [(a, "%#x" % b, "%#x" % c, d, e) for a, b, c, d, e in result["targets"]])
    tsv("constants.tsv", ("address", "bits", "value"), result["constants"])
    tsv("kinds.tsv", ("copy", "kind", "text_at", "size", "text"), result["kinds"])
    tsv("paths.tsv", ("path", "conditions", "exit", "clamp_argument"), [(index + 1, " && ".join(row[0]), row[1], row[2]) for index, row in enumerate(result["paths"])])
    tsv("gate-edges.tsv", ("previous", "last_raw_up", "last_raw_up_minus_floor_1.01p", "last_raw_down", "last_raw_down_minus_ceil_0.99p", "clamped_up", "clamped_down"), result["edges"])
    tsv("fixed-points.tsv", ("previous", "clamped_up", "up_logged", "clamped_down", "down_logged"), result["fixed"])
    tsv("outcomes.tsv", ("case", "end", "events", "out_rows"), result["outcomes"])
    tsv("call-sites.tsv", ("form", "site", "target"), [(a, "%#x" % b, "%#x" % c) for a, b, c in result["sites"]])
    tsv("site-context.tsv", ("site", "band_lea", "oracle_lea", "mode_gate"), result["site_context"])
    tsv("band-writers.tsv", ("writer", "state_field", "dex_count_field", "dex_pointer_field", "lookup_base"), result["writers"])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "named_cases": result["named"], "grid_cases": result["grid"], "random_cases": result["random"],
        "writer_runs": result["writer_runs"], "events_per_kind": dict(sorted(result["counts"].items())), "raw_paths": result["raw_paths"], "distinct_paths": len(result["paths"]),
        "messages": result["messages"], "message_leas": result["leas"], "panic_locations": result["locations"], "power_tables": result["powers"], "constant_reads": result["constant_reads"],
        "reached_rows": result["reached"], "total_rows": result["rows"], "copy_rows_compared": result["compared"], "copy_rip_rows": result["rip_rows"],
        "fixed_points": result["fixed_summary"], "fixed_model": result["fixed_model"],
        "rule": "with r = float(new)/float(daily): rejected unless !(band < r) and !(r < 1/band); then kind Mark: q = float(new)/float(previous) - 1, |q| <= 0.010000000000001 stores new, else stores max(1, saturated round(previous * (1 +- 0.01)))",
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
