#!/usr/bin/env python3
"""Pin the node #94 generated Bole order price from ELF bytes.

Functions 0x2774c40 and 0x4c6bf70 turn one (key, quote, m) triple into a generated order row. The
price is round(((m - 1.0) + 1.0) * reference) with the two additions kept by the compiler, then a
saturating cast and a floor of 1. The real bytes run in a Python evaluator with only the edges
stubbed, and a separately written specification predicts every outcome. The chain after the round
call is refined over all 2^64 f64 bit patterns. Three filter loops are driven the same way. No
objdump or readelf output is parsed, and the binary is never executed. Standard library only.

    python3 tools/bole_generated_px.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
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
        value = immediate(8 if wide else 4)
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
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, 8)
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
                self.xmm[row.a[1]] = self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op in ("addsd", "subsd", "mulsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
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
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



# ---- targets ----

ROW_BUILDERS = (0x2774C40, 0x4C6BF70)
WRAPPERS = ((0x251A290, 0x2774C40), (0x47F71D0, 0x4C6BF70), (0x47F8550, 0x4C6BF70))
HELPER_ROW = 0x327F720
ROUND = 0x565F410
SLOT_ROUND = 0x576F6D8
SLOT_ROW = 0x5774E20
SLOT_COPY = 0x576DFE0
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576DFC8
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
LOCATION_TABLE = 0x56F21F0
LOCATION_SLOTS = 0x56F1FD8
LOCATION_ROW = {0x2774C40: 0x56BDFA0, 0x4C6BF70: 0x5742368}
MINUS_ONE_AT = 0x20A278
ONE_AT = 0x20A730
TWO_64_AT = 0x20A510
TWO_63_AT = 0x20A7F0
BELOW_TWO_64_AT = 0x20A218
TWO_64 = 18446744073709551616.0
U64_MAX = MASK[8]

# Offsets from the function start, the same in both copies.
OFFSET_LOAD_M = 0x35
OFFSET_MINUS_ONE = 0x1F5
OFFSET_REFERENCE = 0x1FD
OFFSET_PLUS_ONE = 0x226
OFFSET_MULTIPLY = 0x22E
OFFSET_ROUND = 0x232
OFFSET_TAIL_END = 0x2BD

EXCHANGE = HEAP_BASE + 0x1000
TABLE = HEAP_BASE + 0x2000
LIST = HEAP_BASE + 0x8000
SLOTS = HEAP_BASE + 0x9000
CONTEXT = HEAP_BASE + 0x100
POINTERS = HEAP_BASE + 0x140
USER = HEAP_BASE + 0x180
EXTRA = HEAP_BASE + 0x1A0
TRIPLE = HEAP_BASE + 0x200
OUT = HEAP_BASE + 0x400
NODES = HEAP_BASE + 0x10000
TEMP = HEAP_BASE + 0x20000
TABLE_STRIDE = 0xE8
SLOT_STRIDE = 0x20
POOL_STRIDE = 0xB0
POOL_REFERENCE = 0x10
NODE_KEYS = 0x798
NODE_LEN = 0x7F2
NODE_EDGES = 0x7F8
NODE_SIZE = 0x860
ROW_SIZE = 0x228
TEMPLATE_SIZE = 0x1F0
IMPORT_MARK = 0xF00000000000
USER_BYTES = bytes(range(0x31, 0x45))
EXTRA_BYTES = bytes(range(0x71, 0x7D))


class Traced(Machine):
    """Records every decision taken in one address window."""

    def __init__(self, image, patches=None):
        super().__init__(image, patches)
        self.window = (0, 0)
        self.trace = []
        self.round_result = None

    def stub(self, hook):
        super().stub(hook)
        if self.round_result is not None:
            self.xmm[0] = self.round_result
            self.round_result = None

    def step(self, row):
        if self.window[0] <= row.va < self.window[1]:
            op = row.op
            if op in ("jcc", "cmov"):
                self.trace.append((row.va, self.condition(row.cc)))
            following = super().step(row)
            if op in ("ucomisd", "cmp"):
                self.trace.append((row.va, self.cf, self.zf, self.pf))
            elif op == "cvttsd2si":
                self.trace.append((row.va, self.regs[row.a[1]] == 1 << 63))
            elif op == "maxsd":
                self.trace.append((row.va, self.xmm[row.a[1]] & MASK[8] == 0))
            return following
        return super().step(row)


# ---- the specification, written from the claim and not from the evaluator ----

def spec_round(value):
    """f64 round half away from zero, exact."""
    if value != value or math.isinf(value):
        return value
    magnitude = fractions.Fraction(abs(value))
    return math.copysign(float(math.floor(magnitude + fractions.Fraction(1, 2))), value)


def spec_multiplier(m):
    return (m + -1.0) + 1.0


def spec_tail(y):
    """The chain after the round call, for any f64 y."""
    if y != y or y <= 0.0 or math.isinf(y):
        return 1
    if y >= TWO_64:
        return U64_MAX
    return max(1, int(y))


def spec_price(m, reference):
    return spec_tail(spec_round(spec_multiplier(m) * float(reference)))


def reference_price(m, reference):
    """The formula written in impl_bole.rs: multiplier * reference_px."""
    return spec_tail(spec_round(m * float(reference)))


class Case:
    def __init__(self, key=5, quote=7000, m=1.0, tables=9, lists=None, slots=None, tree=None, counter=41, status=0):
        self.key, self.quote, self.m, self.tables = key, quote, m, tables
        self.lists = {key: [2]} if lists is None else lists
        self.slots = {2: 0} if slots is None else slots
        self.tree = {key: 1000000} if tree is None else tree
        self.counter, self.status = counter, status
        self.slot_count = 12
        self.height = 1 if len(self.tree) > 11 else 0


def spec_outcome(case, entry=ROW_BUILDERS[0]):
    """What one call does; the row helper is an edge and `status` stands for its answer."""
    if case.key == 0:
        return ("none", case.counter, None)
    if case.key >= case.tables:
        return ("panic", case.counter, LOCATION_TABLE)
    chosen = None
    for index in case.lists.get(case.key, []):
        if index >= case.slot_count:
            return ("bounds", case.counter, index, LOCATION_SLOTS)
        if case.slots.get(index, 1) == 0:
            chosen = index
            break
    if chosen is None or case.key not in case.tree:
        return ("none", case.counter, None)
    reference = case.tree[case.key]
    counter = min(case.counter + 1, U64_MAX)
    call = (chosen, 1, spec_price(case.m, reference), case.quote, EXCHANGE + 0x90, LOCATION_ROW[entry])
    template = spec_template(case.counter)
    if case.status == 2:
        return ("none", counter, call, template)
    return ("row", counter, call, template, spec_row(case.status, reference))


def spec_template(oid):
    """Template bytes the builder writes; other bytes keep the stack mark."""
    data = bytearray([STACK_MARK]) * TEMPLATE_SIZE
    for at, value in TEMPLATE_WORDS:
        data[at:at + 8] = value.to_bytes(8, "little")
    for at in (0xC8, 0x1C0):
        data[at:at + 8] = oid.to_bytes(8, "little")
    data[0xD0:0xE4] = b"\xbb" * 20
    data[0xE4] = 0
    data[0x1C8:0x1DC] = USER_BYTES
    data[0x1DC] = 0
    return bytes(data)


TEMPLATE_WORDS = ((0x00, 0), (0x18, 0), (0x28, 0), (0x50, 0), (0x60, 2), (0xF8, 0), (0x110, 0), (0x120, 0),
                  (0x148, 0), (0x158, 2))


def row_bytes(status):
    data = bytearray((index * 7 + 3) & 0xFF for index in range(ROW_SIZE))
    data[:8] = status.to_bytes(8, "little")
    return bytes(data)


def spec_row(status, reference):
    source = row_bytes(status)
    return source[:0x210] + reference.to_bytes(8, "little") + source[0x218:0x228]


# ---- harness ----

def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 0xD1342543DE82EF95 + 1) & MASK[8]
        yield state >> 3 ^ state


class Harness:
    def __init__(self, image, patches=None, statics=None):
        self.image = image
        self.machine = Traced(image, patches)
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        self.relative = relative
        # Slots filled by the loader have no RELATIVE record; they get a marker address here.
        target = {slot: relative.get(slot, IMPORT_MARK + slot) for slot in
                  (SLOT_ROUND, SLOT_ROW, SLOT_COPY, SLOT_PANIC, SLOT_BOUNDS, SLOT_ALLOC, SLOT_FREE)}
        machine.memory.statics.update(target)
        machine.memory.statics.update(statics or {})
        machine.slots = {target[SLOT_ROW]: self.on_row, target[SLOT_COPY]: self.on_copy,
                         target[SLOT_PANIC]: self.on_panic, target[SLOT_BOUNDS]: self.on_bounds,
                         target[SLOT_ALLOC]: self.on_alloc, target[SLOT_FREE]: self.on_free}
        machine.real = frozenset((ROUND,))
        self.used = 0x24000
        self.status = 0
        self.call = None
        self.brk = NODES

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def on_row(self, machine):
        regs = machine.regs
        memory = machine.memory
        if regs[RDI] <= machine.memory.stack_base or regs[RDX] <= machine.memory.stack_base:
            raise Halt("row helper pointers")
        if memory.bytes_at(regs[RDX], 12) != EXTRA_BYTES:
            raise Halt("row helper extra bytes")
        stack = regs[RSP]
        template = memory.read(stack, 8)
        self.call = ((regs[RSI], regs[RCX], regs[R8], regs[R9], memory.read(stack + 8, 8), memory.read(stack + 16, 8)),
                     memory.bytes_at(template, TEMPLATE_SIZE))
        memory.put_bytes(regs[RDI], row_bytes(self.status))

    def on_copy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_bounds(self, machine):
        raise Panicked(("bounds", machine.regs[RDI], machine.regs[RDX]))

    def on_alloc(self, machine):
        at = self.brk
        self.brk += (machine.regs[RDI] + 15) & ~15
        self.events.append(("alloc", machine.regs[RDI]))
        machine.regs[RAX] = at

    def on_free(self, machine):
        self.events.append(("free", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def install(self, case):
        memory = self.machine.memory
        memory.reset(self.used)
        self.brk = TEMP
        self.call = None
        self.events = []
        self.status = case.status
        self.word(CONTEXT, POINTERS)
        self.word(POINTERS, EXCHANGE)
        self.word(POINTERS + 8, USER)
        self.word(POINTERS + 0x10, EXTRA)
        memory.put_bytes(USER, USER_BYTES)
        memory.put_bytes(EXTRA, EXTRA_BYTES)
        self.word(TRIPLE, case.key)
        self.word(TRIPLE + 8, case.quote)
        self.word(TRIPLE + 0x10, to_bits(case.m))
        self.word(EXCHANGE + 0x38, case.counter)
        self.word(EXCHANGE + 0x1F8, SLOTS)
        self.word(EXCHANGE + 0x200, case.slot_count)
        self.word(EXCHANGE + 0x210, TABLE)
        self.word(EXCHANGE + 0x218, case.tables)
        at = LIST
        for key, entries in case.lists.items():
            if key < 16:
                row = TABLE + key * TABLE_STRIDE
                self.word(row + 0x58, at)
                self.word(row + 0x60, len(entries))
                for entry in entries:
                    self.word(at, entry)
                    at += 8
        for index in range(case.slot_count):
            self.word(SLOTS + index * SLOT_STRIDE + 8, case.slots.get(index, 1))
        self.install_tree(case)

    def install_tree(self, case):
        keys = sorted(case.tree)
        if not keys:
            self.word(EXCHANGE + 0x568, 0)
            self.word(EXCHANGE + 0x570, 0)
            return
        if case.height == 0:
            root = self.leaf(case, keys)
        else:
            root, position = self.carve_node(), 6
            middle = keys[position]
            self.fill_node(root, case, [middle])
            self.word(root + NODE_EDGES, self.leaf(case, keys[:position]))
            self.word(root + NODE_EDGES + 8, self.leaf(case, keys[position + 1:]))
        self.word(EXCHANGE + 0x568, root)
        self.word(EXCHANGE + 0x570, case.height)

    def carve_node(self):
        at = NODES + self.node_count * NODE_SIZE
        self.node_count += 1
        return at

    node_count = 0

    def leaf(self, case, keys):
        node = self.carve_node()
        self.fill_node(node, case, keys)
        return node

    def fill_node(self, node, case, keys):
        self.word(node + NODE_LEN, len(keys), 2)
        for index, key in enumerate(keys):
            self.word(node + NODE_KEYS + index * 8, key)
            self.word(node + index * POOL_STRIDE + POOL_REFERENCE, case.tree[key])
        # Slots past the length hold a stale copy of the searched key, as a freed entry would.
        for index in range(len(keys), 11):
            self.word(node + NODE_KEYS + index * 8, case.key)
            self.word(node + index * POOL_STRIDE + POOL_REFERENCE, 0xDEAD)

    def run_case(self, entry, case):
        self.node_count = 0
        self.install(case)
        machine = self.machine
        try:
            value = machine.run(entry, {RDI: OUT, RSI: CONTEXT, RDX: TRIPLE})
        except Panicked as stop:
            detail = stop.args[0]
            counter = machine.memory.read(EXCHANGE + 0x38, 8)
            if detail[0] == "panic":
                return ("panic", counter, detail[1])
            return ("bounds", counter, detail[1], detail[2])
        if value != OUT:
            raise Halt("return value")
        counter = machine.memory.read(EXCHANGE + 0x38, 8)
        tag = machine.memory.read(OUT, 8)
        if self.call is None:
            if tag != 2:
                raise Halt("tag without a row")
            return ("none", counter, None)
        if tag == 2:
            return ("none", counter, self.call[0], self.call[1])
        return ("row", counter, self.call[0], self.call[1], machine.memory.bytes_at(OUT, ROW_SIZE))

    def tail_value(self, entry, bits):
        """Run the whole function with the round call answering `bits`; return (trace, px)."""
        machine = self.machine
        hook = self.tail_hook
        machine.real = frozenset()
        machine.slots[ROUND] = hook
        machine.window = (entry + OFFSET_ROUND + 6, entry + OFFSET_TAIL_END)
        machine.trace = []
        machine.round_result = None
        self.pending = bits
        try:
            result = self.run_case(entry, TAIL_CASE)
        finally:
            machine.real = frozenset((ROUND,))
            del machine.slots[ROUND]
            machine.window = (0, 0)
            machine.round_result = None
        return machine.trace, result[2][2]

    def tail_hook(self, machine):
        machine.round_result = self.pending

    def run_wrapper(self, wrapper, items, keep):
        """Drive one filter loop with the row function as an edge."""
        entry, inner = wrapper
        machine = self.machine
        machine.memory.reset(self.used)
        self.brk = TEMP
        self.events = []
        grow = wrapper_grow(self.image, entry, inner)
        calls = []

        def on_item(m):
            triple = m.regs[RDX]
            key = m.memory.read(triple, 8)
            calls.append((key, m.memory.read(triple + 8, 8), m.memory.read(triple + 16, 8)))
            word = m.memory.read(m.regs[RSI], 8)
            if m.memory.read(word, 8) != 0x1234:
                raise Halt("wrapper context")
            data = bytearray(ROW_SIZE)
            data[:8] = (0 if key in keep else 2).to_bytes(8, "little")
            data[8:16] = key.to_bytes(8, "little")
            m.memory.put_bytes(m.regs[RDI], bytes(data))

        def on_grow(m):
            regs = m.regs
            vector, size = regs[RDI], regs[RSI]
            old_cap, old_ptr = m.memory.read(vector, 8), m.memory.read(vector + 8, 8)
            if regs[RDX] != 1 or regs[RCX] != 8 or regs[R8] != ROW_SIZE or size != old_cap:
                raise Halt("grow arguments")
            cap = old_cap * 2
            at = self.brk
            self.brk += (cap * ROW_SIZE + 15) & ~15
            m.memory.put_bytes(at, m.memory.bytes_at(old_ptr, size * ROW_SIZE))
            m.memory.write(vector, 8, cap)
            m.memory.write(vector + 8, 8, at)
            self.events.append(("grow", cap))

        machine.calls = {inner: on_item, grow: on_grow}
        iterator, buffer, result = HEAP_BASE + 0x100, HEAP_BASE + 0x300, HEAP_BASE + 0x200
        self.word(iterator, buffer)
        self.word(iterator + 8, buffer)
        self.word(iterator + 0x10, len(items) + 3)
        self.word(iterator + 0x18, buffer + len(items) * 24)
        self.word(iterator + 0x20, 0x1234)
        for index, key in enumerate(items):
            self.word(buffer + index * 24, key)
            self.word(buffer + index * 24 + 8, key * 3)
            self.word(buffer + index * 24 + 16, key * 5)
        value = machine.run(entry, {RDI: result, RSI: iterator})
        if value != result:
            raise Halt("wrapper return")
        cap, pointer, length = (machine.memory.read(result + o, 8) for o in (0, 8, 16))
        rows = [(machine.memory.read(pointer + i * ROW_SIZE, 8), machine.memory.read(pointer + i * ROW_SIZE + 8, 8))
                for i in range(length)]
        return {"calls": calls, "cap": cap, "length": length, "rows": rows, "events": list(self.events), "buffer": buffer}


TAIL_CASE = Case(key=5, m=1.0, tree={5: 3})


def wrapper_grow(image, entry, inner):
    low, end = image.exact_fde(entry)
    rows = decode_range(image, low, end)
    plt = image.named[".plt"]
    calls = {row.target for row in rows if row.op == "call"
             and not plt["address"] <= row.target < plt["address"] + plt["size"]}
    if inner not in calls or len(calls) != 2:
        raise EvidenceError("wrapper calls at %#x: %s" % (entry, sorted(calls)))
    return next(iter(calls - {inner}))


def spec_wrapper(items, keep):
    """Every item is offered in order; kept rows stay in order.  Doubling is the stub's own rule."""
    kept = [key for key in items if key in keep]
    cap = 4 if kept else 0
    while cap < len(kept):
        cap *= 2
    return {"calls": [(key, key * 3, key * 5) for key in items], "length": len(kept),
            "rows": [(0, key) for key in kept], "cap": cap}


# ---- cases ----

def price_values():
    """(m, reference) pairs: named edges, then a fixed generator."""
    edges_m = [0.0, -0.0, 1.0, -1.0, 0.5, 2.0, 0.1, 0.9, 0.99, 1.01, 1.1, 1e-9, 1e-16, 1e-17, 1e-300, 5e-324, 1e300, 1.5,
               0.49999999999999994, 1.0000000000000002, 2.5, 3.0, math.inf, -math.inf, math.nan, 1e19, 1.8446744073709552e19]
    edges_ref = [0, 1, 2, 3, 5, 15, 1000000, 99999999, 100000000, (1 << 53) + 1, (1 << 63) - 1, 1 << 63, U64_MAX]
    pairs = [(m, r) for m in edges_m for r in edges_ref]
    stream = lcg(0x1357)
    for _ in range(1500):
        word, width, other = next(stream), next(stream), next(stream)
        exponent = 1023 + (width % 121) - 60
        m = to_float((word & (MASK[8] >> 12)) | exponent << 52)
        pairs.append((m, other >> (other & 63)))
    return pairs


def outcome_cases():
    cases = [("zero key", Case(key=0)),
             ("key equals table length", Case(key=9, tables=9)),
             ("key past table length", Case(key=1 << 40, tables=9)),
             ("empty table", Case(key=1, tables=0)),
             ("empty slot list", Case(lists={5: []})),
             ("all slots marked", Case(lists={5: [1, 3]}, slots={1: 7, 3: 1})),
             ("slot index at the slot count", Case(lists={5: [12]})),
             ("slot index past a marked slot", Case(lists={5: [1, 13]}, slots={1: 2})),
             ("second slot free", Case(lists={5: [1, 3]}, slots={1: 7, 3: 0})),
             ("first free wins", Case(lists={5: [2, 3]}, slots={2: 0, 3: 0})),
             ("no tree", Case(tree={})),
             ("key below every tree key", Case(tree={6: 10, 8: 20})),
             ("key above every tree key", Case(tree={3: 10, 4: 20})),
             ("key between tree keys", Case(tree={3: 10, 7: 20})),
             ("key first in leaf", Case(tree={5: 10, 7: 20})),
             ("key last in full leaf", Case(key=11, tables=20, lists={11: [2]}, tree={k: k * 10 for k in range(1, 12)})),
             ("key in root of two levels", Case(tree={k: k * 11 for k in range(1, 15) if k != 0}, key=7, lists={7: [2]})),
             ("key in left child", Case(tree={k: k * 11 for k in range(1, 15)}, key=2, lists={2: [2]})),
             ("key in right child", Case(tree={k: k * 11 for k in range(1, 15)}, key=12, tables=20, lists={12: [2]})),
             ("key missing under two levels", Case(tree={k * 2: k for k in range(1, 15)}, key=5)),
             ("counter at zero", Case(counter=0)),
             ("counter at MAX-1", Case(counter=U64_MAX - 1)),
             ("counter saturated", Case(counter=U64_MAX)),
             ("row helper says 2", Case(status=2)),
             ("row helper says 1", Case(status=1)),
             ("row helper says 3", Case(status=3)),
             ("quote zero", Case(quote=0)),
             ("quote MAX", Case(quote=U64_MAX))]
    return cases


def price_cases():
    return [Case(m=m, tree={5: r}) for m, r in price_values()]


def same_outcome(left, right):
    return repr(left) == repr(right)


def round_cases():
    values = [0.0, -0.0, 0.25, 0.5, 0.49999999999999994, 1.5, 2.5, -0.5, -1.5, 4503599627370495.5, 4503599627370496.0,
              9007199254740991.0, 1e300, -1e300, 5e-324, math.inf, -math.inf]
    for exponent in range(-3, 54):
        for delta in (-1, 0, 1):
            for sign in (1.0, -1.0):
                x = to_float(to_bits(2.0 ** exponent + 0.5 if exponent >= 0 else 2.0 ** exponent) + delta)
                values.append(sign * x)
    return values


def compare_round(harness, value):
    machine = harness.machine
    machine.memory.reset(0x100)
    machine.regs = [POISON] * 16
    machine.real = frozenset((ROUND,))
    bits = to_bits(value)
    result = spec_round(value)

    def run():
        machine.regs[RSP] = STACK_TOP - 0x100
        machine.push(RETURN_SENTINEL)
        pc = ROUND
        cache = machine.cache
        for _ in range(100):
            if pc == RETURN_SENTINEL:
                return
            row = cache.get(pc)
            if row is None:
                row = decode(machine.read_code, pc)
                cache[pc] = row
            pc = machine.step(row)
        raise Halt("round did not return")

    machine.xmm[0] = bits
    run()
    return (machine.xmm[0] & MASK[8]) == to_bits(result)


# ---- whole-domain proof of the tail ----

FLOAT_SEEDS = ((0, 0x7FEFFFFFFFFFFFFF), (0x7FF0000000000000, 0x7FF0000000000000), (0x7FF0000000000001, (1 << 63) - 1),
               (1 << 63, (1 << 63) | 0x7FEFFFFFFFFFFFFF), ((1 << 63) | 0x7FF0000000000000, (1 << 63) | 0x7FF0000000000000),
               ((1 << 63) | 0x7FF0000000000001, MASK[8]))


def interior(lo, hi):
    """256 fixed points of one piece, evenly spread and independent of the run order."""
    return [lo + (hi - lo) * index // 257 for index in range(1, 257)]


def refine_tail(harness, entry):
    """Split the f64 bit patterns until each piece has one decision record; check the closed form."""
    pieces = []
    runs = 0
    for seed in FLOAT_SEEDS:
        stack = [seed]
        found = []
        while stack:
            lo, hi = stack.pop()
            first = harness.tail_value(entry, lo)
            last = harness.tail_value(entry, hi) if hi != lo else first
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
        points = [lo, hi] + (interior(lo, hi) if hi > lo else [])
        for bits in points:
            out = harness.tail_value(entry, bits)
            if out[0] != trace:
                raise EvidenceError("interior point left its piece: %#x" % bits)
            if out[1] != spec_tail(to_float(bits)):
                raise EvidenceError("tail mismatch at %#x: %#x" % (bits, out[1]))
        rows.append((lo, hi, harness.tail_value(entry, lo)[1], harness.tail_value(entry, hi)[1], len(trace)))
    return rows, runs


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


def operand_text(operand):
    if operand is None:
        return ""
    kind = operand[0]
    if kind == "r":
        return "r%d" % operand[1]
    if kind == "x":
        return "x%d" % operand[1]
    if kind == "i":
        return "%#x" % (operand[1] & MASK[8])
    _, base, index, scale, disp, _ = operand
    parts = []
    if base is not None:
        parts.append("r%d" % base)
    if index is not None:
        parts.append("r%d*%d" % (index, scale))
    parts.append("%#x" % (disp & MASK[8]))
    return "[" + "+".join(parts) + "]"


def row_shape(row, start, end):
    target = row.target
    if target is not None and row.op in ("jcc", "jmp", "call") and start <= target < end:
        target = "+%#x" % (target - start)
    elif target is not None:
        target = "%#x" % (target & MASK[8])
    return (row.op, row.width, row.cc, operand_text(row.a), operand_text(row.b), target)


def copy_differences(image, first, second):
    low, end = image.exact_fde(first)
    other, other_end = image.exact_fde(second)
    if end - low != other_end - other:
        raise EvidenceError("copies differ in size: %#x %#x" % (first, second))
    rows = decode_range(image, low, end)
    others = decode_range(image, other, other_end)
    if [row.va - low for row in rows] != [row.va - other for row in others]:
        raise EvidenceError("copies differ in instruction boundaries")
    found = []
    for row, peer in zip(rows, others):
        left, right = row_shape(row, low, end), row_shape(peer, other, other_end)
        if left != right:
            found.append((row.va - low, " ".join(map(str, left)), " ".join(map(str, right))))
    return len(rows), found


def pin_price_rows(image, entry):
    """The instructions that form the multiplier, by exact form and constant."""
    low, end = image.exact_fde(entry)
    rows = {row.va - low: row for row in decode_range(image, low, end)}

    def memory_at(offset, op):
        row = rows.get(offset)
        if row is None or row.op != op or row.a != ("x", 0) or row.b[0] != "m" or row.b[1] is not None:
            raise EvidenceError("expected %s xmm0,[abs] at +%#x" % (op, offset))
        return row.b[4]

    load = rows.get(OFFSET_LOAD_M)
    if load is None or load.op != "movsd" or load.a != ("x", 0) or load.b != ("m", RDX, None, 1, 0x10, False):
        raise EvidenceError("no load of the third word at +%#x" % OFFSET_LOAD_M)
    if memory_at(OFFSET_MINUS_ONE, "addsd") != MINUS_ONE_AT or memory_at(OFFSET_PLUS_ONE, "addsd") != ONE_AT:
        raise EvidenceError("constants moved")
    multiply = rows.get(OFFSET_MULTIPLY)
    if multiply is None or multiply.op != "mulsd" or multiply.a != ("x", 0) or multiply.b != ("x", 2):
        raise EvidenceError("no multiply at +%#x" % OFFSET_MULTIPLY)
    reference = rows.get(OFFSET_REFERENCE)
    if reference is None or reference.op != "mov" or reference.a != ("r", RBP):
        raise EvidenceError("no reference load at +%#x" % OFFSET_REFERENCE)
    call = rows.get(OFFSET_ROUND)
    if call is None or call.op != "calli" or call.a[4] != SLOT_ROUND:
        raise EvidenceError("no round call at +%#x" % OFFSET_ROUND)
    writers = [offset for offset, row in sorted(rows.items())
               if row.a == ("x", 0) and OFFSET_LOAD_M <= offset < OFFSET_ROUND]
    if writers != [OFFSET_LOAD_M, OFFSET_MINUS_ONE, OFFSET_PLUS_ONE, OFFSET_MULTIPLY]:
        raise EvidenceError("other writes to xmm0: %s" % writers)
    return writers


def constant_rows(image):
    rows = []
    for name, at in (("minus one", MINUS_ONE_AT), ("one", ONE_AT), ("2^64", TWO_64_AT), ("2^63", TWO_63_AT),
                     ("largest f64 below 2^64", BELOW_TWO_64_AT)):
        bits = struct.unpack_from("<Q", image.blob, image.offset(at))[0]
        rows.append((name, at, bits, to_float(bits)))
    return rows


# ---- mutation pass ----

# Mutations no input can see, each with the reason.
EXPECTED_SURVIVORS = {
    0x2774E85: "the mask loses bit 0 only; maxsd left a non-negative value, and bit 0 never decides a compare with the largest finite bits",
    0x2774ED4: "sar 62 gives -2 instead of -1 only for values at or above 2^63, whose low bits are already zero",
    0x2774F7B: "copying 0x211 bytes writes +0x210, which the next store replaces with the reference word",
}


def mutation_targets(image, entry, seen):
    """Reached rows with a condition or an immediate, plus nops of the multiplier additions."""
    low, end = image.exact_fde(entry)
    edits = []
    for row in decode_range(image, low, end):
        if row.va not in seen:
            continue
        data = image.blob[image.offset(row.va):image.offset(row.va) + row.size]
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
        elif row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
        elif row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
    return edits


def nop_edits(entry):
    def nops(offset, size):
        return {entry + offset + i: 0x90 for i in range(size)}

    both = nops(OFFSET_MINUS_ONE, 8)
    both.update(nops(OFFSET_PLUS_ONE, 8))
    return ((entry + OFFSET_MINUS_ONE, "nop of the -1 addition", nops(OFFSET_MINUS_ONE, 8)),
            (entry + OFFSET_PLUS_ONE, "nop of the +1 addition", nops(OFFSET_PLUS_ONE, 8)),
            (entry + OFFSET_MINUS_ONE, "nop of both additions (the reference formula)", both))


def run_all(harness, entry, sets):
    """None when every case matches the specification, else a short reason."""
    for name, case in sets:
        try:
            got = harness.run_case(entry, case)
        except (Halt, EvidenceError) as error:
            return "stopped: %s" % str(error)[:60]
        if not same_outcome(got, spec_outcome(case, entry)):
            return "differs: %s" % name
    return None


def run_mutants(image, entry, sets, seen):
    rows = []
    for va, kind, patch in list(mutation_targets(image, entry, seen)) + list(nop_edits(entry)):
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        reason = run_all(harness, entry, sets)
        if reason is None and entry + OFFSET_ROUND < va < entry + OFFSET_TAIL_END:
            # One-point changes in the tail are beyond the vectors; the whole-domain pass sees them.
            try:
                refine_tail(Harness(image, patch), entry)
            except (Halt, EvidenceError) as error:
                reason = "whole-domain tail: %s" % str(error)[:50]
        if reason is None:
            if va not in EXPECTED_SURVIVORS:
                raise EvidenceError("unexplained survivor at %#x" % va)
            rows.append((va, kind, "survived", EXPECTED_SURVIVORS[va]))
        else:
            rows.append((va, kind, "killed", reason))
    if {row[0] for row in rows if row[2] == "survived"} != set(EXPECTED_SURVIVORS):
        raise EvidenceError("survivor list changed")
    return rows


def constant_controls(image, entry, sets):
    rows = []
    for name, at, value in (("minus one becomes -2", MINUS_ONE_AT, to_bits(-2.0)), ("one becomes 2", ONE_AT, to_bits(2.0)),
                            ("2^64 bound becomes 2^63", TWO_64_AT, to_bits(2.0 ** 63)),
                            ("2^63 bias becomes 2^62", TWO_63_AT, to_bits(2.0 ** 62))):
        harness = Harness(image, None, {at: value})
        reason = run_all(harness, entry, sets)
        rows.append((at, name, "survived" if reason is None else "killed", "" if reason is None else reason))
    return rows


# ---- analysis ----

def multiplier_rows(harness):
    rows = []
    for exponent in range(-60, 61, 4):
        for mantissa in (0, 1, 1 << 51, (1 << 52) - 1):
            m = to_float(mantissa | (1023 + exponent) << 52)
            after = spec_multiplier(m)
            case = Case(m=m, tree={5: 1 << 40})
            got = harness.run_case(ROW_BUILDERS[0], case)
            if got[2][2] != spec_price(m, 1 << 40):
                raise EvidenceError("multiplier row mismatch at %r" % m)
            rows.append((exponent, mantissa, m.hex(), after.hex(), int(after == m), got[2][2], reference_price(m, 1 << 40)))
    return rows


WORKED = ((0.1, 15), (0.1, 5), (0.1, 1000000), (0.3, 5), (0.7, 5), (1e-17, 10 ** 18), (0.99, 2500000), (1.01, 2500000),
          (1.5, 3), (2.5, 3), (0.5, 1), (0.5, 3), (0.0, 7), (-1.0, 7), (math.nan, 7), (math.inf, 7), (1e19, 3))


def worked_rows(harness, entry):
    rows = []
    for m, reference in WORKED:
        got = harness.run_case(entry, Case(m=m, tree={5: reference}))
        rows.append((repr(m), reference, spec_multiplier(m).hex(), got[2][2], spec_price(m, reference), reference_price(m, reference)))
    return rows


def wrapper_sets():
    return (("no items", [], set()), ("all dropped", [1, 2, 3], set()), ("one kept", [1, 2, 3], {2}), ("all kept", [1, 2, 3], {1, 2, 3}),
            ("first kept", [4, 5], {4}), ("four kept", [1, 2, 3, 4], {1, 2, 3, 4}), ("five kept, grow", [1, 2, 3, 4, 5], {1, 2, 3, 4, 5}),
            ("nine kept", list(range(1, 10)), set(range(1, 10))), ("mixed", list(range(1, 12)), {2, 3, 5, 7, 11}))


def analyse_wrappers(image):
    rows = []
    for wrapper in WRAPPERS:
        harness = Harness(image)
        for name, items, keep in wrapper_sets():
            got = harness.run_wrapper(wrapper, items, keep)
            want = spec_wrapper(items, keep)
            for field in ("calls", "length", "rows", "cap"):
                if got[field] != want[field]:
                    raise EvidenceError("wrapper %#x %s: %s" % (wrapper[0], name, field))
            cap = len(items) + 3
            freed = [event for event in got["events"] if event[0] == "free"]
            if freed != [("free", got["buffer"], cap * 24, 0)]:
                raise EvidenceError("wrapper %#x %s: free %s" % (wrapper[0], name, freed))
            rows.append((wrapper[0], wrapper[1], name, len(items), got["length"], got["cap"]))
    return rows


def analyse(image, full=True):
    pins = {entry: pin_price_rows(image, entry) for entry in ROW_BUILDERS}
    instructions, differences = copy_differences(image, *ROW_BUILDERS)
    harness = Harness(image)
    outcome_set = outcome_cases()
    price_set = [("price %d" % index, case) for index, case in enumerate(price_cases())]
    tables = {}
    for entry in ROW_BUILDERS:
        counts = collections.Counter()
        for name, case in outcome_set + price_set:
            got = harness.run_case(entry, case)
            want = spec_outcome(case, entry)
            if not same_outcome(got, want):
                raise EvidenceError("%#x %s: %r" % (entry, name, got[:3]))
            counts[got[0]] += 1
        tables[entry] = counts
    outcomes = []
    for name, case in outcome_set:
        got = spec_outcome(case)
        outcomes.append((name, got[0], got[1], got[3] if got[0] == "bounds" else got[2] if got[0] == "panic" else ""))
    rounds = round_cases()
    if not all(compare_round(harness, value) for value in rounds):
        raise EvidenceError("round mismatch")
    differing = sum(1 for m, r in price_values() if spec_price(m, r) != reference_price(m, r))
    multiplier = multiplier_rows(harness)
    worked = worked_rows(harness, ROW_BUILDERS[0])
    tails = {}
    runs = 0
    for entry in ROW_BUILDERS:
        tails[entry], used = refine_tail(harness, entry)
        runs += used
    wrappers = analyse_wrappers(image)
    relative = harness.relative
    sites = direct_calls(image, set(ROW_BUILDERS) | {w[0] for w in WRAPPERS} | {ROUND})
    result = {
        "pins": pins, "instructions": instructions, "differences": differences, "tables": tables, "outcomes": outcomes,
        "round_cases": len(rounds), "price_cases": len(price_set), "reference_differs": differing, "multiplier": multiplier,
        "worked": worked, "tails": tails, "tail_runs": runs, "wrappers": wrappers,
        "row_sites": {entry: sites.get(entry, []) for entry in ROW_BUILDERS},
        "wrapper_sites": {w[0]: sites.get(w[0], []) for w in WRAPPERS},
        "round_direct": len(sites.get(ROUND, [])), "round_slot": len(slot_calls(image, SLOT_ROUND)),
        "row_helper_slot": relative[SLOT_ROW], "round_slot_target": relative[SLOT_ROUND],
        "row_helper_calls": len(slot_calls(image, SLOT_ROW)),
        "locations": {va: image.location(va, relative) for va in (LOCATION_TABLE, LOCATION_SLOTS) + tuple(LOCATION_ROW.values())},
        "constants": constant_rows(image),
        "fde": {entry: image.exact_fde(entry) for entry in ROW_BUILDERS + tuple(w[0] for w in WRAPPERS)},
    }
    if full:
        seen = set(harness.machine.seen)
        sets = outcome_set + price_set[:400] + [("price %d" % index, case) for index, case in enumerate(price_cases()[-200:])]
        result["mutations"] = run_mutants(image, ROW_BUILDERS[0], sets, seen) + constant_controls(image, ROW_BUILDERS[0], sets)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("copy-differences.tsv", ("offset", "first", "second"), [("%#x" % o, a, b) for o, a, b in result["differences"]])
    tsv("outcomes.tsv", ("case", "outcome", "counter_after", "location"),
        [(n, o, "%#x" % c, "%#x" % l if l != "" and l is not None else "") for n, o, c, l in result["outcomes"]])
    tsv("price-examples.tsv", ("m", "reference", "multiplier_after_additions", "px_real_bytes", "px_specification", "px_reference_formula"),
        result["worked"])
    tsv("multiplier-identity.tsv", ("exponent", "mantissa", "m", "after_additions", "unchanged", "px_real_bytes_at_ref_2_pow_40", "px_reference_formula"),
        result["multiplier"])
    tsv("tail-pieces.tsv", ("function", "bits_lo", "bits_hi", "px_at_lo", "px_at_hi", "decisions"),
        [("%#x" % entry, "%#x" % lo, "%#x" % hi, "%#x" % a, "%#x" % b, n)
         for entry, rows in sorted(result["tails"].items()) for lo, hi, a, b, n in rows])
    tsv("wrappers.tsv", ("wrapper", "row_function", "case", "items", "kept", "capacity"),
        [("%#x" % a, "%#x" % b, c, d, e, f) for a, b, c, d, e, f in result["wrappers"]])
    tsv("template.tsv", ("offset", "size", "value"),
        [("%#x" % at, 8, "%#x" % value) for at, value in TEMPLATE_WORDS]
        + [("0xc8", 8, "counter before the bump"), ("0x1c0", 8, "counter before the bump"), ("0xd0", 20, "0xbb bytes"),
           ("0xe4", 1, "0x0"), ("0x1c8", 20, "context user bytes"), ("0x1dc", 1, "0x0")])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"),
            [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "row_functions": ["%#x" % e for e in ROW_BUILDERS],
        "fde": {"%#x" % k: ["%#x" % v[0], "%#x" % v[1], v[1] - v[0]] for k, v in result["fde"].items()},
        "instructions_per_copy": result["instructions"], "copy_differences": len(result["differences"]),
        "row_call_sites": {"%#x" % k: ["%#x" % s for s in v] for k, v in result["row_sites"].items()},
        "wrapper_call_sites": {"%#x" % k: ["%#x" % s for s in v] for k, v in result["wrapper_sites"].items()},
        "row_helper": "%#x" % result["row_helper_slot"], "row_helper_slot": "%#x" % SLOT_ROW, "row_helper_calls": result["row_helper_calls"],
        "round": "%#x" % result["round_slot_target"], "round_slot": "%#x" % SLOT_ROUND,
        "round_calls": {"direct": result["round_direct"], "slot": result["round_slot"]},
        "locations": {"%#x" % k: "%s:%d:%d" % v for k, v in result["locations"].items()},
        "constants": [{"name": n, "address": "%#x" % a, "bits": "%#x" % b, "value": repr(v)} for n, a, b, v in result["constants"]],
        "multiplier_offsets": ["%#x" % o for o in result["pins"][ROW_BUILDERS[0]]],
        "cases_per_copy": {"%#x" % k: dict(sorted(v.items())) for k, v in result["tables"].items()},
        "price_cases": result["price_cases"], "round_cases": result["round_cases"],
        "price_cases_where_reference_formula_differs": result["reference_differs"],
        "tail_pieces": {"%#x" % k: len(v) for k, v in result["tails"].items()}, "tail_runs": result["tail_runs"],
        "wrapper_cases": len(result["wrappers"]),
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
    print(json.dumps({"files": sorted(files), "tail_pieces": {"%#x" % k: len(v) for k, v in result["tails"].items()}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
