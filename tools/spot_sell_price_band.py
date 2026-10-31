#!/usr/bin/env python3
"""Pin the node #94 price band and size that `0x37344a0` gives the spot sell preprocess, from ELF bytes.

`0x37344a0` reads two token rows and two account words, and returns a tag, a size, a low and a high price and a last word.
The real bytes, with the real round at `0x565f410`, run in a Python evaluator with the callees at the edge stubbed. A
separately written specification predicts every result and stub argument, and every condition, immediate and field
offset is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed.
Standard library only.
"""

import argparse
import bisect
import hashlib
import json
import math
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

BAND = 0x37344A0
PRICE = 0x3594EC0
TICK = 0x36F3350
SCALE = 0x333E310
ROUND = 0x565F410

SLOT_QUOTE = 0x5774778
SLOT_ROUND = 0x576F6D8
SLOT_RESCALE = 0x5774790
SLOT_UDIV = 0x576E1A8
FAKE_UDIV = 0xFACE0020
SLOT_MEMCPY = 0x576DFE0

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
HEAP_SIZE = 0x10000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 30000

MAP = HEAP_BASE + 0x100
ACCOUNT = HEAP_BASE + 0x200
META = HEAP_BASE + 0x300
OUT = HEAP_BASE + 0x400
ROW_ROOT = HEAP_BASE + 0x1000
ROW_LEAVES = HEAP_BASE + 0x2000
WORD_ROOT = HEAP_BASE + 0x4000
WORD_LEAVES = HEAP_BASE + 0x4400

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
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
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
        if byte == 0xFF and kind == 6:
            return finish("pushi", rm, w=8)
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
        self.keep_float = False
        self.step_limit = STEP_LIMIT
        self.jump_low = self.jump_high = 0

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
        elif op == "pushi":
            self.push(self.get(row.a, 8))
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


# ---- specification, written from the instruction read and kept apart from the evaluator ----

RAMPS = {}


def ramp(size, start):
    """Non-periodic filler, so that a wrong field offset reads a wrong value."""
    key = (size, start)
    if key not in RAMPS:
        RAMPS[key] = bytes((start + index * 37 + (index >> 4)) & 0xFF | 1 for index in range(size))
    return RAMPS[key]


def word(data, at, width=8):
    return int.from_bytes(data[at:at + width], "little")


U64 = MASK[8]
TOP = 1 << 64
UNIT = 100000000000000
KINK = 50000000000000
HIGH_FACTOR = 0.98
SLOPE = -0.9
RESULT_BYTES = 0x28
JUST_BELOW_HALF = 0.49999999999999994
LAST_FIT = 1.844674407370955e19


def round_away(value):
    return math.copysign(float(math.floor(abs(value) + JUST_BELOW_HALF)), value)


def saturate(value):
    """The f64 to u64 cast of both prices: 0 and NaN-free inputs, capped at the top, never 0."""
    value = max(value, 0.0)
    if math.isinf(value):
        value = 0.0
    result = U64 if value > LAST_FIT else int(value)
    return result or 1


def next_tick(value, tick):
    """The tick multiple above value: an exact multiple still moves up."""
    count = value // tick + 1
    if count > U64:
        count = U64
    return min(count * tick, U64) or 1


def rate(ltv):
    if ltv < KINK:
        return (ltv * 3 * UNIT // (UNIT + 2 * ltv)) & U64
    return ((ltv + 2 * UNIT) // 3) & U64


def signed(value):
    return value - TOP if value >= 1 << 63 else value


def low_factor(ltv):
    return (signed(rate(ltv)) / -1e14 + 1.0) * SLOPE + 1.0


def ceil_div(number, divisor):
    return number // divisor + (1 if number % divisor else 0)


def tag_out(tag, code=None):
    out = bytearray([STACK_MARK]) * RESULT_BYTES
    out[0:8] = tag.to_bytes(8, "little")
    if code is not None:
        out[8] = code
    return out


def spec_band(w):
    events = []
    answer = {"events": events, "out": None}
    base, quote, spot = w["base"], w["quote"], w["spot"]
    rows = w["rows"]
    if rows is None or base not in rows or quote not in rows:
        answer["out"] = tag_out(3, 9)
        return answer
    b, q = rows[base], rows[quote]
    if b["active"] == 0:
        answer["out"] = tag_out(2)
        return answer
    events.append(("price", b["b10"], q["q10"], quote, META))
    price = w["price"]
    if price == 0:
        answer["out"] = tag_out(2)
        return answer
    d = float(price)
    v1 = saturate(round_away(d * HIGH_FACTOR))
    events.append(("tick", META, spot, v1))
    high = next_tick(v1, w["ticks"][0])
    v2 = saturate(round_away(low_factor(b["b8"]) * d))
    events.append(("tick", META, spot, v2))
    low = min(next_tick(v2, w["ticks"][1]), high)
    words = w["words"]
    if words is None or quote not in words:
        answer["out"] = tag_out(2)
        return answer
    a = words[quote][0]
    c = ceil_div(a * q["q58"], UNIT)
    if c > U64:
        answer["out"] = tag_out(3, 3)
        return answer
    if base not in words:
        answer["out"] = tag_out(2)
        return answer
    held = words[base][1]
    events.append(("scale", 100000000, base, b["b10"], 1, META))
    ok, v = w["scale1"]
    if not ok & 1:
        answer["out"] = tag_out(3, 3)
        return answer
    b78 = b["b78"]
    if b78 == 0:
        answer["out"] = tag_out(3, 6)
        return answer
    need = ceil_div(v * UNIT, b78)
    if need > U64:
        answer["out"] = tag_out(3, 3)
        return answer
    excess = max(held - need, 0)
    product = excess * b78
    if product >> 64 > UNIT - 1:
        answer["out"] = tag_out(3, 3)
        return answer
    last = (product // UNIT) & U64
    events.append(("scale", c, base, low, 1, META))
    ok, v = w["scale2"]
    if ok & 1:
        last = min(last, v)
        events.append(("rescale", v, base, META))
        tag, x = 1, w["rescale"]
    else:
        tag, x = 0, ok
    out = bytearray()
    for value in (tag, x, low, high, last):
        out += value.to_bytes(8, "little")
    answer["out"] = out
    return answer


# ---- harness: real bytes; the callees at the edge are stubbed and their arguments compared ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Case:
    def __init__(self, label, kind, copy, world):
        self.label = label
        self.kind = kind
        self.copy = copy
        self.world = world


ROW_NODE = {"size": 0x858, "stride": 0xB0, "keys": 0x798, "length": 0x7F2, "edges": 0x7F8, "room": 11}
WORD_NODE = {"size": 0x228, "stride": 0x20, "keys": 0x168, "length": 0x1C2, "edges": 0x1C8, "room": 11}
UNMAPPED = 0x10


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        machine.memory.statics.update(self.relative)
        machine.memory.statics[SLOT_UDIV] = FAKE_UDIV
        self.real = RealExcept()
        machine.real = self.real
        self.events = []

    def on_udiv(self, m):
        number = m.regs[RSI] << 64 | m.regs[RDI]
        divisor = m.regs[RCX] << 64 | m.regs[RDX]
        if divisor == 0:
            raise Halt("division by zero")
        result = number // divisor
        m.regs[RAX] = result & U64
        m.regs[RDX] = result >> 64
        m.keep_rdx = True

    def write_tree(self, shape, fill, entries, node, root_at, leaves_at, writer):
        """Height 0 or 1; unused key slots hold a tempting key, leaf edges are unmapped, values take a ramp."""
        memory = self.machine.memory

        def write(at, keys, edges):
            memory.put_bytes(at, ramp(node["size"], 0x2F))
            for index in range(node["room"]):
                memory.write(at + node["keys"] + index * 8, 8, keys[index] if index < len(keys) else fill)
            for index, key in enumerate(keys):
                writer(at + index * node["stride"], entries[key])
            memory.write(at + node["length"], 2, len(keys))
            for index in range(node["room"] + 1):
                memory.write(at + node["edges"] + index * 8, 8, edges[index] if index < len(edges) else UNMAPPED + index * 8)
        keys, leaves = shape
        edges = [leaves_at + index * node["size"] for index in range(len(leaves))]
        write(root_at, keys, edges)
        for at, leaf in zip(edges, leaves):
            write(at, leaf, [])
        return 1 if leaves else 0

    def write_row(self, at, row):
        memory = self.machine.memory
        memory.write(at, 1, row["active"])
        memory.write(at + 8, 8, row["b8"])
        memory.write(at + 0x10, 8, row.get("b10", row.get("q10", 0)))
        memory.write(at + 0x58, 8, row.get("q58", 0))
        memory.write(at + 0x78, 8, row.get("b78", 0))

    def write_word(self, at, pair):
        memory = self.machine.memory
        memory.write(at + 8, 8, pair[0])
        memory.write(at + 0x18, 8, pair[1])

    def run(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.events = []
        events = self.events
        ticks = list(w["ticks"])
        scales = [w["scale1"], w["scale2"]]

        def on_price(m):
            events.append(("price", m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX]))
            m.regs[RAX] = w["price"]

        def on_tick(m):
            events.append(("tick", m.regs[RDI], m.regs[RSI], m.regs[RDX]))
            m.regs[RAX] = ticks.pop(0)

        def on_scale(m):
            events.append(("scale", m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8]))
            ok, value = scales.pop(0)
            m.regs[RAX] = ok
            m.regs[RDX] = value
            m.keep_rdx = True

        def on_rescale(m):
            events.append(("rescale", m.regs[RDI], m.regs[RSI], m.regs[RDX]))
            m.regs[RAX] = w["rescale"]

        relative = self.relative
        machine.slots = {FAKE_UDIV: self.on_udiv, relative[SLOT_RESCALE]: on_rescale}
        machine.calls = {PRICE: on_price, TICK: on_tick, SCALE: on_scale}
        self.real.stubs = frozenset(machine.slots) | frozenset(machine.calls)
        memory.reset()
        memory.put_bytes(MAP, ramp(0x20, 0x13))
        memory.put_bytes(ACCOUNT, ramp(0x30, 0x65))
        if w["rows"] is None:
            memory.write(MAP + 8, 8, 0)
            memory.write(MAP + 0x10, 8, 3)
        else:
            shape = w.get("row_shape") or (tuple(sorted(w["rows"])), ())
            height = self.write_tree(shape, w["fill"], w["rows"], ROW_NODE, ROW_ROOT, ROW_LEAVES, self.write_row)
            memory.write(MAP + 8, 8, ROW_ROOT)
            memory.write(MAP + 0x10, 8, height)
        if w["words"] is None:
            memory.write(ACCOUNT + 0x18, 8, 0)
            memory.write(ACCOUNT + 0x20, 8, 3)
        else:
            shape = w.get("word_shape") or (tuple(sorted(w["words"])), ())
            height = self.write_tree(shape, w["fill"], w["words"], WORD_NODE, WORD_ROOT, WORD_LEAVES, self.write_word)
            memory.write(ACCOUNT + 0x18, 8, WORD_ROOT)
            memory.write(ACCOUNT + 0x20, 8, height)
        memory.stack_argument = None
        machine.regs = [POISON] * 16
        rax = self.enter({RDI: OUT, RSI: ACCOUNT, RDX: w["spot"], RCX: w["base"], R8: w["quote"], R9: MAP})
        if rax != OUT:
            raise Halt("result pointer")
        return {"events": events, "out": bytearray(memory.bytes_at(OUT, RESULT_BYTES))}

    def enter(self, regs):
        """The meta pointer is a stack word above the return address."""
        machine = self.machine
        memory = machine.memory
        memory.write(STACK_TOP - 0x100 + 0, 8, META)
        return machine.run(BAND, regs)


def spec_run(case):
    return spec_band(case.world)


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError)


def compare_run(harness, case):
    """Empty when the bytes and the specification agree, else one line."""
    wanted = spec_run(case)
    try:
        found = harness.run(case)
    except CRASHES as error:
        return "%s: crash %s %s" % (case.label, type(error).__name__, error)
    if found != wanted:
        return "%s: differs: events %s %s out %s %s" % (case.label, str(found["events"])[-260:], str(wanted["events"])[-260:], bytes(found["out"]).hex(), bytes(wanted["out"]).hex())
    return ""


# ---- cases ----

BASE_TOKEN = 0x11
QUOTE_TOKEN = 0x22
FILL_KEY = 0x7777
DEFAULT_PRICE = 2000000000
LTV_HALF = 50000000000000


def base_row(**change):
    row = {"active": 1, "b8": 40000000000000, "b10": 0x1234567, "q10": 0x1234567, "b78": 5000000000000000, "q58": 0x71}
    row.update(change)
    return row


def quote_row(**change):
    row = {"active": 0, "b8": 0x55, "q10": 0x7654321, "b10": 0x7654321, "q58": 300000000000000, "b78": 0x66}
    row.update(change)
    return row


def band_world(**change):
    w = {"base": BASE_TOKEN, "quote": QUOTE_TOKEN, "spot": 7, "fill": FILL_KEY, "rows": {0x05: quote_row(), BASE_TOKEN: base_row(), QUOTE_TOKEN: quote_row(), 0x90: quote_row()},
         "words": {0x05: (3, 4), BASE_TOKEN: (0x31, 700000000000), QUOTE_TOKEN: (5000000000000, 0x32), 0x90: (6, 8)},
         "price": DEFAULT_PRICE, "ticks": (100, 10), "scale1": (1, 1000000), "scale2": (1, 250000000), "rescale": 123456}
    w.update(change)
    return w


def band_cases():
    rows = []

    def add(label, **change):
        rows.append((label, band_world(**change)))

    def row(**change):
        data = band_world()["rows"]
        data[BASE_TOKEN] = base_row(**change)
        return data

    def quote(**change):
        data = band_world()["rows"]
        data[QUOTE_TOKEN] = quote_row(**change)
        return data

    def words(**change):
        data = dict(band_world()["words"])
        data.update({int(key[1:], 16): value for key, value in change.items()})
        return data

    add("default")
    add("no row map", rows=None)
    add("base row missing", rows={0x05: quote_row(), QUOTE_TOKEN: quote_row()})
    add("quote row missing", rows={0x05: quote_row(), BASE_TOKEN: base_row()})
    add("base key only in a spare slot", rows={QUOTE_TOKEN: quote_row(), 0x90: quote_row()}, base=0x40, fill=0x40)
    add("rows deep", row_shape=((QUOTE_TOKEN,), ((0x05, BASE_TOKEN), (0x90,))))
    add("rows deep, base in the root", row_shape=((BASE_TOKEN,), ((0x05,), (QUOTE_TOKEN, 0x90))))
    add("rows deep, low filler", row_shape=((0x08,), ((0x05,), (BASE_TOKEN, QUOTE_TOKEN, 0x90))), fill=1, rows=dict(band_world()["rows"], **{}) | {8: quote_row()})
    add("rows flat, low filler", fill=1)
    add("rows, base past the end, low filler", fill=1, base=0xF0)
    add("rows, quote past the end, low filler", fill=1, quote=0xF0)
    add("rows deep, base missing", rows={0x05: quote_row(), QUOTE_TOKEN: quote_row(), 0x90: quote_row()}, row_shape=((QUOTE_TOKEN,), ((0x05,), (0x90,))))
    add("rows deep, quote missing", rows={0x05: quote_row(), BASE_TOKEN: base_row(), 0x90: quote_row()}, row_shape=((BASE_TOKEN,), ((0x05,), (0x90,))))
    add("base row not active", rows=row(active=0))
    add("active byte 2", rows=row(active=2))
    add("quote row active", rows=quote(active=1))
    add("no price", price=0)
    for price in (1, 2, 49, 50, 51, 1000, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1, 2 ** 53 + 1, 2 ** 62, 2 ** 63, 2 ** 63 + 2048, U64 - 2047, U64):
        add("price %d" % price, price=price)
    for ticks in ((1, 1), (3, 7), (7, 3), (1000, 1000), (2 ** 32, 2 ** 32), (2 ** 33 + 1, 3), (3, 2 ** 33 + 1), (U64, U64)):
        add("ticks %s" % (ticks,), ticks=ticks)
    add("tick above the word", ticks=(10 ** 12, 10 ** 12))
    add("exact multiple", price=1000, ticks=(10, 10))
    add("top words", price=U64, ticks=(1, 1))
    add("top words, tick 2", price=U64, ticks=(2, 2))
    for ltv in (0, 1, 1000, 10000000000000, 49999999999999, 50000000000000, 50000000000001, 75000000000000, UNIT, 2 * UNIT, 10 ** 18, 2 ** 63 - 1, 2 ** 63, 2 ** 63 + 5, U64 - 200000000000000, U64 - 199999999999999, U64 - 3, U64):
        add("ltv %d" % ltv, rows=row(b8=ltv))
    add("low above high", rows=row(b8=2 * UNIT))
    for ltv in (10000000000000, 10000000000012, 75000000000000):
        add("fine rate, word %d" % ltv, rows=row(b8=ltv), price=2 ** 53, ticks=(1, 1))
    add("low cast at the top, tick 1", rows=row(b8=2 ** 62), price=2 ** 63, ticks=(1, 1))
    add("both prices saturate at the tick product", price=U64, ticks=(2 ** 63, 2 ** 63))
    add("low word rounds to 0", rows=row(b8=0), price=1)
    add("low word rounds to 0, price 4", rows=row(b8=0), price=4)
    add("low word rounds to 1, price 5", rows=row(b8=0), price=5)
    add("no word map", words=None)
    add("quote word missing", words={0x05: (3, 4), BASE_TOKEN: (0x31, 700000000000), 0x90: (6, 8)})
    add("base word missing", words={0x05: (3, 4), QUOTE_TOKEN: (5000000000000, 0x32), 0x90: (6, 8)})
    add("words deep", word_shape=((QUOTE_TOKEN,), ((0x05, BASE_TOKEN), (0x90,))))
    add("words deep, base in the root", word_shape=((BASE_TOKEN,), ((0x05,), (QUOTE_TOKEN, 0x90))))
    add("words deep, low filler", word_shape=((0x08,), ((0x05,), (BASE_TOKEN, QUOTE_TOKEN, 0x90))), fill=1, words=dict(band_world()["words"]) | {8: (1, 2)})
    add("low price above the cap", rows=row(b8=2 ** 62), price=2 ** 63)
    add("low price at a huge word", rows=row(b8=UNIT * 1000), price=2 ** 63)
    add("words flat, low filler", fill=1)
    add("words, quote spare slot", words={BASE_TOKEN: (0x31, 700000000000), 0x90: (6, 8)}, fill=QUOTE_TOKEN)
    add("words, base spare slot", words={QUOTE_TOKEN: (5000000000000, 0x32), 0x90: (6, 8)}, fill=BASE_TOKEN)
    add("words, quote absent past the end, low filler", words={0x05: (3, 4), BASE_TOKEN: (0x31, 700000000000)}, fill=1)
    add("words, base absent past the end, low filler", base=0xF0, rows=band_world()["rows"] | {0xF0: base_row()}, fill=1)
    add("words deep, base absent", words={0x05: (3, 4), QUOTE_TOKEN: (5000000000000, 0x32), 0x90: (6, 8)}, word_shape=((QUOTE_TOKEN,), ((0x05,), (0x90,))))
    add("words deep, quote absent", words={0x05: (3, 4), BASE_TOKEN: (0x31, 700000000000), 0x90: (6, 8)}, word_shape=((BASE_TOKEN,), ((0x05,), (0x90,))))
    add("zero debt", words=words(k22=(0, 0x32)))
    add("debt rounds up", words=words(k22=(1, 0x32)), rows=quote(q58=1))
    add("debt exact", words=words(k22=(UNIT, 0x32)), rows=quote(q58=1))
    add("debt at the top of a word", words=words(k22=(U64, 0x32)), rows=quote(q58=UNIT))
    add("debt past a word", words=words(k22=(U64, 0x32)), rows=quote(q58=UNIT + 1))
    add("debt far past a word", words=words(k22=(U64, 0x32)), rows=quote(q58=U64))
    add("scale refused", scale1=(0, 5))
    add("scale flag 2", scale1=(2, 5))
    add("scale flag 3", scale1=(3, 1000000))
    add("value zero", scale1=(1, 0))
    add("no divisor", rows=row(b78=0))
    add("need rounds up", scale1=(1, 1), rows=row(b78=3))
    add("need exact", scale1=(1, 3), rows=row(b78=UNIT))
    add("need at a word", scale1=(1, U64), rows=row(b78=UNIT))
    add("need past a word", scale1=(1, U64), rows=row(b78=UNIT - 1))
    add("need above held", scale1=(1, 10 ** 13), rows=row(b78=1), words=words(k11=(0x31, 5)))
    add("need equals held", scale1=(1, 1), rows=row(b78=UNIT), words=words(k11=(0x31, 1)))
    add("held one above need", scale1=(1, 1), rows=row(b78=UNIT), words=words(k11=(0x31, 2)))
    add("product at the limit", scale1=(1, 0), rows=row(b78=U64), words=words(k11=(0x31, U64)))
    add("product just fits", scale1=(1, 0), rows=row(b78=(UNIT << 64) // U64), words=words(k11=(0x31, U64)))
    add("product past the limit", scale1=(1, 0), rows=row(b78=((UNIT << 64) // U64) + 2), words=words(k11=(0x31, U64)))
    add("product high word below", scale1=(1, 0), rows=row(b78=UNIT - 1), words=words(k11=(0x31, U64)))
    add("product high word at", scale1=(1, 0), rows=row(b78=UNIT + 1), words=words(k11=(0x31, U64)))
    add("second scale refused", scale2=(0, 77))
    add("second scale flag 2", scale2=(2, 77))
    add("second scale flag 3", scale2=(3, 7))
    add("second scale above last", scale2=(1, 10 ** 18))
    add("second scale equal last", scale2=(1, (700000000000 - 200000000) * 5000000000000000 // UNIT))
    add("second scale below last", scale2=(1, 3))
    add("second scale zero", scale2=(1, 0))
    add("other spot", spot=0xABCDEF)
    return rows


def all_cases():
    return [Case("band: " + label, "band", "", w) for label, w in band_cases()]


# ---- static reads ----

def direct_sites(image, targets):
    """Every E8/E9 rel32 byte pattern in .text that lands on a target."""
    base, text = image.text_bytes()
    found = {target: [] for target in targets}
    for opcode in (b"\xe8", b"\xe9"):
        at = text.find(opcode)
        while 0 <= at <= len(text) - 5:
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in found:
                found[target].append((base + at, opcode[0]))
            at = text.find(opcode, at + 1)
    return found


def slot_sites(image, slot):
    """Every FF 15 call in .text through one data slot."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            rows.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return rows


# ---- mutation ----

def displacement_at(image, row):
    """Offset inside the instruction of a non-stack field displacement, or None."""
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
            disp = operand[4]
            end = row.size - (row.imm_size or 0)
            data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    """Yield (va, offset in instruction, kind) for every conditional, immediate and field offset."""
    for row in rows:
        at = displacement_at(image, row)
        if at is not None:
            yield row.va, at, "offset"
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), "branch"
        elif row.op in ("set", "cmov"):
            yield row.va, None, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, "immediate"


def mutate_patch(image, row_va, at, kind="branch"):
    base = image.offset(row_va)
    window = bytes(image.blob[base:base + 16])
    if at is None:
        at = window.index(b"\x0f") + 1
    return {row_va + at: window[at] ^ (8 if kind == "offset" else 1)}




GROUPS = ((BAND, "band"),)


def mutated_groups(image):
    """(function start, role, decoded rows)."""
    return [(start, role, decode_range(image, *image.exact_fde(start))) for start, role in GROUPS]


def run_mutants(image, reached, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run."""
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    cases = all_cases()
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for start, _, rows in mutated_groups(image):
        for va, at, kind in mutation_targets(image, rows):
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            wanted = set(indices)
            order = [index for index in first_kill if index in wanted] + indices
            for index in order:
                failed = compare_run(harness, cases[index])
                if failed:
                    if index in first_kill:
                        first_kill.remove(index)
                    first_kill.insert(0, index)
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

CONSTANTS = ((0x20AA58, 0.98, "factor of the high price"), (0x20AE90, -1e14, "divisor of the rate"), (0x20A730, 1.0, "added twice"), (0x20A978, -0.9, "slope of the low factor"),
             (0x20A510, 18446744073709551616.0, "cap of a cast"), (0x20A218, 18446744073709549568.0, "last cast below the top"), (0x20A7F0, 9223372036854775808.0, "cast shift"))
HOST_BYTES = (
    (0x373470B, "48b8ff1f3d88792d0000", "mov rax, 0x2d79883d1fff: last word on the lower arm of the rate"),
    (0x3734715, "48be00407a10f35a0000", "mov rsi, 1e14: added to twice the word in the divisor"),
    (0x3734724, "48b80080f420e6b50000", "mov rax, 2e14: added on the upper arm"),
    (0x373473C, "48beabaaaaaaaaaaaaaa", "mov rsi, inverse of 3"),
    (0x373475F, "48b900c06e31d9100100", "mov rcx, 3e14: multiplier on the lower arm"),
    (0x3734A2C, "bf00e1f505", "mov edi, 100000000: first argument of the first scale call"),
)


def read_host_bytes(image):
    rows = []
    for va, wanted, meaning in HOST_BYTES:
        data = bytes(image.blob[image.offset(va):image.offset(va) + len(wanted) // 2]).hex()
        if data != wanted:
            raise EvidenceError("host bytes at %#x: %s" % (va, data))
        rows.append({"va": "%#x" % va, "bytes": data, "meaning": meaning})
    return rows


def read_constants(image):
    rows = []
    for va, value, meaning in CONSTANTS:
        found = struct.unpack("<d", bytes(image.blob[image.offset(va):image.offset(va) + 8]))[0]
        if found != value:
            raise EvidenceError("constant at %#x: %r" % (va, found))
        rows.append({"va": "%#x" % va, "bits": "%#018x" % to_bits(value), "value": repr(value), "meaning": meaning})
    return rows


FIELDS = {
    "arguments": {"rdi": "result", "rsi": "account", "rdx": "spot", "rcx": "base", "r8": "quote", "r9": "map at state +0x560", "first stack word": "meta at state +0x90"},
    "token_row": {"+0x00": "byte: 0 on the base row gives tag 2", "+0x08": "base: the word of the rate", "+0x10": "first argument of 0x3594ec0 (base), second (quote), also a scale argument (base)", "+0x58": "quote: multiplies the debt word", "+0x78": "base: divides and multiplies the held word"},
    "account": {"+0x18/+0x20": "root and height of a tree by token, stride 0x20", "word +0x08": "quote row: debt word", "word +0x18": "base row: held word"},
    "row_map_node": {"+0x00": "values, stride 0xb0", "+0x798": "keys", "+0x7f2": "length", "+0x7f8": "edges"},
    "word_tree_node": {"+0x00": "values, stride 0x20", "+0x168": "keys", "+0x1c2": "length", "+0x1c8": "edges"},
    "result": {"+0x00": "tag", "+0x08": "x, or the stop code", "+0x10": "low", "+0x18": "high", "+0x20": "last"},
}
DIVIDE = "the 32 bit divide is a shortcut: the 64 bit divide gives the same quotient"
ROUND_TWO = "a mutant that keeps the low word: the second adc of a sum that cannot carry twice"
LOW_BIT = "a word from 2^63 up, as an f64, has a clear low bit, so the mask drops nothing"
DEAD_CAP = "0.98 of a u64 is below the cap, so this arm is never taken"
NEVER_ZERO = "the high word is at least 1 for any nonzero price, because 0.98 rounds to 1"
NO_WRAP = "the count wraps only for word u64::MAX and tick 1, and 0.98 of a price cannot be that word"
PRODUCT_ONE = "count and tick are both nonzero here, so the product is never 0"
FINITE = "the value is finite for every input, and a mask one bit off gives the same test"
ZERO_TOP = "the arm needs a nonzero quotient from a zero numerator, so it is never taken"
REASONS = {0x3734673: LOW_BIT, 0x3734820: LOW_BIT, 0x373468F: DEAD_CAP, 0x373469A: NEVER_ZERO, 0x37346EB: NO_WRAP, 0x37346FE: PRODUCT_ONE, 0x37348A1: PRODUCT_ONE,
           0x37347C9: FINITE, 0x37347D6: FINITE, 0x373499D: ZERO_TOP, 0x3734AB8: ZERO_TOP, 0x3734B06: ZERO_TOP}
REASON_RANGES = ()


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "no case in the list separates this mutant; no claim rests on this row")


def outcome_name(spec):
    tag = word(spec["out"], 0)
    return "tag %d" % tag if tag < 3 else "stop %d" % spec["out"][8]


def curve_rows():
    """The low factor at round words, and the word that gives the factor 1.0."""
    return [{"word": value, "rate": rate(value), "low_factor": repr(low_factor(value))} for value in (0, 10 ** 13, 25 * 10 ** 12, KINK - 1, KINK, 75 * 10 ** 12, UNIT, 2 * UNIT)]


def worked_runs(harness):
    w = band_world()
    found = harness.run(Case("worked", "band", "", w))
    data = found["out"]
    return {"price": w["price"], "word": w["rows"][BASE_TOKEN]["b8"], "ticks": list(w["ticks"]), "low": word(data, 0x10), "high": word(data, 0x18), "last": word(data, 0x20), "x": word(data, 8), "tag": word(data, 0)}


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    lines = []
    machine = harness.machine
    for case in cases:
        machine.seen = set()
        trouble = compare_run(harness, case)
        if trouble:
            mismatches.append(trouble)
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        spec = spec_run(case)
        name = outcome_name(spec)
        outcomes[name] = outcomes.get(name, 0) + 1
        lines.append("%s\t%s" % (case.label.split(": ", 1)[1], name))
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    for start, role in GROUPS + ((ROUND, "round, real, no mutants"),):
        begin, end = image.exact_fde(start) if start != ROUND else (ROUND, ROUND + 0x71)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = harness.relative
    slots = {SLOT_QUOTE: BAND, SLOT_ROUND: ROUND, SLOT_RESCALE: 0x32813D0}
    for slot, value in slots.items():
        if relative.get(slot) != value:
            raise EvidenceError("slot %#x" % slot)
    site_rows = [(BAND, va, "slot %#x" % SLOT_QUOTE, image.fde(va)[0], image.fde(va)[1]) for va in slot_sites(image, SLOT_QUOTE)]
    direct = direct_sites(image, (BAND, PRICE, TICK))
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    worked = worked_runs(harness)
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "slots": {"%#x" % slot: "%#x" % value for slot, value in sorted(slots.items())},
        "constants": read_constants(image),
        "host_bytes": read_host_bytes(image),
        "curve": curve_rows(),
        "fields": FIELDS,
        "worked_example": worked,
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_lines": lines,
    }


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["label\toutcome"] + case_lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += ["%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_)) for row_ in results]
    files["mutations.tsv"] = "\n".join(lines) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (folder / name).write_text(text, encoding="ascii", newline="\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="output folder")
    options = parser.parse_args(argv)
    files = render(analyse(load_image()))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
