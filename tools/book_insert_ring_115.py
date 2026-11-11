#!/usr/bin/env python3
"""Rebuild the node #115 book insert path (level lookup, order registration, ring append) and prove it on the bytes.

Two twin owner bodies (0x5911890 and 0x5911b30) take a 0x110-byte order, derive a signed price key, find the
price level, call the level operation, and then either register the order (order kind dword != 1) or append a
32-byte element to the level ring (kind dword == 1) after asking the level tree for a cached argument. The real
bytes of each owner run in a Python x86-64 evaluator with only the callees stubbed (key construction, level
lookup, level operation, tree range and next, shared insert, track-caller recorder, ring grow, copy, panic). A
separately written specification predicts every stub call and every byte of the level record and the ring.
The tree next function they call (0x4e188f0) runs as real bytes on hand-built trees and chunk states against its own
specification. Conditions are then flipped on the bytes to show that the comparison can fail. No disassembler or ELF dump text
is parsed and the binary is never executed. Standard library only.
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

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# owner body, key construction, level lookup, shared insert
OWNERS = (
    dict(owner=0x5911890, key=0x4DC42F0, lookup=0x4DA5F90, insert=0x58DF360),
    dict(owner=0x5911B30, key=0x4DC52B0, lookup=0x4DA7010, insert=0x58DF790),
)
LEVEL_OP = 0x518E690
DERIVE = 0x4DCE580
NEXT = 0x4E188F0
TRACK = 0x4DBE910
SLOT_COPY = 0x64DF508
SLOT_PANIC = 0x64DF6A0
SLOT_GROW = 0x64E27A8
PANIC_MESSAGE = 0x91F9EB
PANIC_ARGS = 0x64A35E0
PANIC_LOCATION = 0x64A3508
PANIC_LENGTH = 0x2B
TRACK_LOCATION = 0x64B6558
ORDER_SIZE = 0x110
ELEMENT_SIZE = 0x20

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
HEAP_SIZE = 0x200000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 300000
MUTANT_STEP_LIMIT = 6000
FAKE_COPY = 0x7E000000

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
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value & MASK[8]), w=8)
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
        if byte == 0xFF and kind == 6 and rm[0] == "m":
            return finish("pushm", rm, w=8)
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
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd"}
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
            self.push(row.a[1])
        elif op == "pushm":
            self.push(self.memory.read(self.address(row.a), 8))
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


# ---- specification ----




# ---- specification ----

BOOK = HEAP_BASE + 0x1000
ORDER = HEAP_BASE + 0x2000
ARG3 = HEAP_BASE + 0x2200
LEVEL = HEAP_BASE + 0x3000
RING = HEAP_BASE + 0x4000
GROWN = HEAP_BASE + 0x5000
DERIVED = HEAP_BASE + 0x6000
USED = 0x7000
COPY_FILL = 0xA5


def lcg(variant):
    """A small fixed generator so the sampled cases are the same on every run."""
    state = (variant * 0x9E3779B97F4A7C15 + 0x1234567) & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 16


def order_bytes(seed):
    return bytes((seed * 31 + at * 7 + 5) & 0xFF for at in range(ORDER_SIZE))


def ring_slot(slot):
    return bytes((slot * 29 + at * 7 + 3) & 0xFF for at in range(ELEMENT_SIZE))


class Case:
    __slots__ = ("twin", "side", "key", "kind", "dc", "f0", "arg_q", "arg_d", "rcx", "xmm", "book110", "flag", "cached",
                 "cap", "head", "length", "found", "derived", "result", "seed", "label")

    def __init__(self, **kw):
        for name in self.__slots__:
            setattr(self, name, kw.get(name, 0))

    def patched(self, **kw):
        out = Case(**{name: getattr(self, name) for name in self.__slots__})
        for name, value in kw.items():
            setattr(out, name, value)
        return out


def order_for(case):
    data = bytearray(order_bytes(case.seed))
    struct.pack_into("<Q", data, 0xB0, case.key)
    data[0xD2] = case.side
    struct.pack_into("<I", data, 0xD8, case.kind)
    struct.pack_into("<I", data, 0xDC, case.dc)
    struct.pack_into("<Q", data, 0xF0, case.f0)
    return bytes(data)


def spec_insert(case, variant=""):
    """Expected stub events, final level bytes, ring bytes and return word for one owner call."""
    M = MASK[8]
    events = []
    order = order_for(case)
    if case.key & SIGN[8] and variant != "panic_off":
        return dict(events=events, stop=("panic", PANIC_LENGTH, PANIC_MESSAGE, PANIC_ARGS, PANIC_LOCATION))
    side = case.side
    if variant == "no_negate":
        key = case.key
    elif variant == "negate_nonzero":
        key = (-case.key) & M if side else case.key
    else:
        key = case.key if side else (-case.key) & M
    offset = (32 if side else 0) if variant == "side_bool" else (side << 5) & MASK[4]
    events.append(("key", BOOK + 0xA8 + offset, key))
    events.append(("lookup", BOOK + 0xA8 + offset, key))
    events.append(("level", LEVEL, ARG3, BOOK + 0x80, case.xmm))
    flag, cached = case.flag, case.cached
    length, cap, head = case.length, case.cap, case.head
    ring = [ring_slot(slot) for slot in range(cap)]
    buffer = RING
    arm_append = (case.kind == 1) if variant != "kind_ne1_append" else (case.kind != 1)
    if not arm_append:
        events.append(("insert", BOOK + 0x80, order, case.book110, case.rcx, BOOK + 0x118, LEVEL, 0, None))
        result = case.result
        tested = flag if variant == "flag_word" else flag & 0xFF
        if variant == "cache_always" or tested == 0:
            if variant != "no_cache":
                flag, cached = 1, result
        return finish(events, result, flag, cached, cap, buffer, head, length, ring)
    events.append(("derive", LEVEL + 0x50, 1, case.f0, case.dc, 2))
    events.append(("next", 0x77))
    if case.found and variant != "found_ignored":
        carry, argument = (1 if variant != "flag_not_one" else flag), case.derived
    else:
        carry, argument = flag, cached
    events.append(("insert", BOOK + 0x80, order, case.book110, case.rcx, BOOK + 0x118, LEVEL, carry, argument))
    result = case.result
    events.append(("track", LEVEL + 0x50, case.f0, case.dc, result, TRACK_LOCATION))
    patch = bytearray(order[:16])
    if variant == "patch_swapped":
        patch[4:8] = struct.pack("<I", case.arg_d)
        patch[8:16] = struct.pack("<Q", case.arg_q)
    else:
        patch[4:12] = struct.pack("<Q", case.arg_q)
        patch[12:16] = struct.pack("<I", case.arg_d)
    if length == cap and variant != "no_grow":
        events.append(("grow", cap, head, length))
        new_cap = cap * 2 if cap else 4
        logical = [ring[(head + i) % cap] for i in range(length)] if cap else []
        ring = logical + [bytes([COPY_FILL]) * ELEMENT_SIZE] * (new_cap - len(logical))
        cap, head, buffer = new_cap, 0, GROWN
    index = head + length
    if variant == "wrap_none":
        pass
    elif variant == "wrap_gt":
        index = index - cap if index > cap else index
    else:
        index = index - cap if index >= cap else index
    if variant != "len_unchanged":
        length += 1
    element = bytearray(ring[index] if index < len(ring) else ELEMENT_SIZE)
    struct.pack_into("<Q", element, 0, case.f0)
    struct.pack_into("<I", element, 8, case.dc & MASK[4])
    element[0xC:0x1C] = patch
    if index < len(ring):
        ring[index] = bytes(element)
    return finish(events, result, flag, cached, cap, buffer, head, length, ring)




def finish(events, result, flag, cached, cap, buffer, head, length, ring):
    level = struct.pack("<QQQQQQ", flag, cached, cap, buffer, head, length)
    return dict(events=events, ret=result, level=level, ring=b"".join(ring), buffer=buffer)


# ---- harness ----

class Harness:
    def __init__(self, image, patches=None, track_location=None):
        self.image = image
        self.machine = Machine(image, patches)
        self.machine.step_limit = STEP_LIMIT if not patches else MUTANT_STEP_LIMIT
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        symbols = {slot: (symbol, kind) for slot, kind, _, symbol in image.relocations()}
        if symbols[SLOT_COPY][1] != 6 or symbols[SLOT_COPY][0] == 0:
            raise EvidenceError("copy slot is not an imported symbol")
        machine.memory.statics[SLOT_COPY] = FAKE_COPY
        for slot in (SLOT_PANIC, SLOT_GROW):
            machine.memory.statics[slot] = relative[slot]
        machine.slots = {FAKE_COPY: self.on_copy, relative[SLOT_PANIC]: self.on_panic, relative[SLOT_GROW]: self.on_grow}
        calls = {LEVEL_OP: self.on_level, DERIVE: self.on_derive, NEXT: self.on_next, TRACK: self.on_track}
        for row in OWNERS:
            calls[row["key"]] = self.on_key
            calls[row["lookup"]] = self.on_lookup
            calls[row["insert"]] = self.on_insert
        machine.calls = calls
        self.events = []
        self.case = None

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[size])

    def run(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        self.events = []
        self.case = case
        memory.put_bytes(ORDER, order_for(case))
        self.word(ARG3, case.arg_q)
        self.word(ARG3 + 8, case.arg_d, 4)
        self.word(BOOK + 0x110, case.book110)
        self.word(DERIVED, case.derived)
        for offset, value in ((0x20, case.flag), (0x28, case.cached), (0x30, case.cap), (0x38, RING), (0x40, case.head),
                              (0x48, case.length)):
            self.word(LEVEL + offset, value)
        for slot in range(case.cap):
            memory.put_bytes(RING + slot * ELEMENT_SIZE, ring_slot(slot))
        machine.xmm[0] = case.xmm
        try:
            ret = machine.run(OWNERS[case.twin]["owner"], {RDI: BOOK, RSI: ORDER, RDX: ARG3, RCX: case.rcx})
        except Panicked as stop:
            return dict(events=self.events, stop=stop.args[0])
        level = memory.bytes_at(LEVEL + 0x20, 0x30)
        cap, buffer = struct.unpack_from("<QQ", level, 0x10)
        ring = memory.bytes_at(buffer, cap * ELEMENT_SIZE) if cap <= 16 and buffer in (RING, GROWN) else b""
        return dict(events=self.events, ret=ret, level=level, ring=ring, buffer=buffer)

    def on_key(self, machine):
        regs = machine.regs
        self.events.append(("key", regs[RSI], regs[RDX]))
        machine.memory.write(regs[RDI], 8, regs[RSI])
        machine.memory.write(regs[RDI] + 8, 8, regs[RDX])

    def on_lookup(self, machine):
        memory = machine.memory
        self.events.append(("lookup", memory.read(machine.regs[RDI], 8), memory.read(machine.regs[RDI] + 8, 8)))
        machine.regs[RAX] = LEVEL

    def on_level(self, machine):
        regs = machine.regs
        self.events.append(("level", regs[RDI], regs[RSI], regs[RDX], machine.xmm[0] & MASK[8]))

    def on_derive(self, machine):
        regs = machine.regs
        memory = machine.memory
        at = regs[RDX]
        self.events.append(("derive", regs[RSI], memory.read(at, 8), memory.read(at + 8, 8), memory.read(at + 16, 4),
                            memory.read(at + 24, 8)))
        memory.write(regs[RDI], 8, 0x77)

    def on_next(self, machine):
        self.events.append(("next", machine.memory.read(machine.regs[RDI], 8)))
        machine.keep_rdx = True
        machine.regs[RAX] = 1 if self.case.found else 0
        machine.regs[RDX] = DERIVED

    def on_insert(self, machine):
        regs = machine.regs
        memory = machine.memory
        stack = regs[RSP]
        arm_append = self.case.kind == 1
        self.events.append(("insert", regs[RDI], memory.bytes_at(regs[RSI], ORDER_SIZE), regs[RDX], regs[RCX], regs[R8],
                            regs[R9], memory.read(stack + 8, 8), memory.read(stack + 16, 8) if arm_append else None))
        machine.regs[RAX] = self.case.result

    def on_track(self, machine):
        regs = machine.regs
        self.events.append(("track", regs[RDI], regs[RSI], regs[RDX] & MASK[4], regs[RCX], regs[R8]))

    def on_copy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])

    def on_grow(self, machine):
        memory = machine.memory
        at = machine.regs[RDI]
        cap, buffer, head, length = (memory.read(at + 8 * n, 8) for n in range(4))
        self.events.append(("grow", cap, head, length))
        new_cap = cap * 2 if cap else 4
        logical = [memory.bytes_at(buffer + ((head + i) % cap) * ELEMENT_SIZE, ELEMENT_SIZE) for i in range(length)]
        for slot in range(new_cap):
            memory.put_bytes(GROWN + slot * ELEMENT_SIZE, logical[slot] if slot < len(logical) else bytes([COPY_FILL]) * ELEMENT_SIZE)
        memory.write(at, 8, new_cap)
        memory.write(at + 8, 8, GROWN)
        memory.write(at + 0x10, 8, 0)

    def on_panic(self, machine):
        regs = machine.regs
        raise Panicked(("panic", regs[RSI], regs[RDI], regs[RCX], regs[R8]))


# ---- cases ----

SIDES = (0, 1, 0, 1, 2, 0x80, 0xFF, 3)
KEYS = (0, 1, 2, 0x7FFFFFFFFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 12345678901, 0x8000000000000000,
        0xFFFFFFFFFFFFFFFF, 0x4000000000000000)
KINDS = (1, 1, 1, 1, 0, 2, 3, 0xFFFFFFFF, 0x100)
FLAGS = (0, 1, 0x100, 0xFF00, 0x8000000000000000, 0x2, 0xFF, 0)
CAPS = (0, 1, 2, 3, 4, 5, 8)
EDGE_WORDS = (0, 1, 2, 0xFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
              0xFFFFFFFFFFFFFFFF)
FLOATS = (0, 0x3FF0000000000000, 0xBFF0000000000000, 0x7FF8000000000000, 0x7FF0000000000000, 0x3C9CD2B297D889BC)


def pick(source, pool):
    return pool[next(source) % len(pool)]


def make_case(twin, source, number):
    cap = pick(source, CAPS)
    length = next(source) % (cap + 1)
    head = next(source) % cap if cap else 0
    mode = number % 7
    if mode == 0:
        length = cap
    elif mode == 1 and cap:
        head = cap - 1
        length = max(length, 1) if length < cap else length
    return Case(twin=twin, side=pick(source, SIDES), key=pick(source, KEYS) if number % 3 == 0 else next(source) % (1 << 62),
                kind=pick(source, KINDS), dc=pick(source, EDGE_WORDS) & MASK[4], f0=pick(source, EDGE_WORDS) if number % 2 else next(source),
                arg_q=pick(source, EDGE_WORDS) if number % 4 == 0 else next(source), arg_d=pick(source, EDGE_WORDS) & MASK[4],
                rcx=next(source), xmm=pick(source, FLOATS), book110=next(source), flag=pick(source, FLAGS),
                cached=pick(source, EDGE_WORDS) if number % 2 else next(source), cap=cap, head=head, length=length,
                found=next(source) % 3 != 0, derived=next(source) if number % 5 else 0, result=next(source) if number % 6 else 0,
                seed=next(source) % 251, label="rand%d" % number)


def edge_cases(twin):
    base = Case(twin=twin, side=0, key=5, kind=1, dc=7, f0=0x1122334455667788, arg_q=0x0102030405060708, arg_d=0x0A0B0C0D,
                rcx=0x55, xmm=0x3FF0000000000000, book110=0x99, flag=0, cached=0xCAFE, cap=4, head=1, length=2, found=0,
                derived=0xD00D, result=0xBEEF, seed=3, label="base")
    yield base
    yield base.patched(key=1 << 63, label="negative key panics")
    yield base.patched(key=(1 << 64) - 1, label="all ones key panics")
    yield base.patched(key=(1 << 63) - 1, label="largest key")
    yield base.patched(found=1, label="derived qword used")
    yield base.patched(found=1, flag=0, label="found carry flag 1")
    yield base.patched(flag=0x100, label="flag byte clear with high bits")
    yield base.patched(kind=0, label="registration arm")
    yield base.patched(kind=0, flag=1, label="registration arm flag set")
    yield base.patched(kind=0, flag=0x100, label="registration arm flag high bits")
    yield base.patched(length=4, label="full ring grows")
    yield base.patched(cap=0, length=0, head=0, label="empty ring grows to 4")
    yield base.patched(head=3, length=3, cap=4, label="wrap by one conditional subtraction")
    yield base.patched(head=3, length=1, cap=4, label="sum equals capacity")
    yield base.patched(head=2, length=1, cap=4, label="sum below capacity")
    yield base.patched(side=2, label="side byte 2")
    yield base.patched(side=0xFF, label="side byte 255")
    yield base.patched(side=1, key=9, label="side 1 keeps sign")


def cases_for(twin, count):
    yield from edge_cases(twin)
    source = lcg(twin + 11)
    for number in range(count):
        yield make_case(twin, source, number)


def outcome_of(actual):
    if "stop" in actual:
        return "panic"
    return "append" if any(event[0] == "derive" for event in actual["events"]) else "register"


def matches(actual, expected):
    if actual["events"] != expected["events"]:
        return False
    if ("stop" in actual) != ("stop" in expected):
        return False
    if "stop" in expected:
        return actual["stop"] == expected["stop"]
    return (actual["ret"] == expected["ret"] and actual["level"] == expected["level"]
            and actual["buffer"] == expected["buffer"] and actual["ring"] == expected["ring"])


def check(harness, case, variant=""):
    expected = spec_insert(case, variant)
    try:
        actual = harness.run(case)
    except (Halt, Panicked, EvidenceError, ZeroDivisionError):
        return False, expected, None
    return matches(actual, expected), expected, actual


def analyse(image, per_twin, rows_every):
    harness = Harness(image)
    counts, outcomes, mismatches, rows = {}, {}, [], []
    for twin in range(len(OWNERS)):
        for number, case in enumerate(cases_for(twin, per_twin)):
            ok, expected, actual = check(harness, case)
            counts[twin] = counts.get(twin, 0) + 1
            if not ok:
                mismatches.append((twin, number, case.label))
                continue
            kind = outcome_of(actual)
            outcomes[(twin, kind)] = outcomes.get((twin, kind), 0) + 1
            if number % rows_every == 0:
                length = struct.unpack_from("<Q", actual["level"], 0x28)[0] if kind != "panic" else 0
                rows.append((twin, number, kind, case.label, length, len(actual["events"])))
    return harness, counts, outcomes, mismatches, rows


# ---- mutation, variants, evidence ----

VARIANTS = ("no_negate", "negate_nonzero", "side_bool", "panic_off", "kind_ne1_append", "flag_word", "no_cache", "cache_always",
            "wrap_none", "wrap_gt", "no_grow", "found_ignored", "flag_not_one", "patch_swapped", "len_unchanged")
VARIANT_NOTE = {
    "no_negate": "key is the order qword for both sides",
    "negate_nonzero": "key negated for a nonzero side byte instead of a zero one",
    "side_bool": "book half chosen by side != 0 instead of side << 5",
    "panic_off": "a negative order qword does not panic",
    "kind_ne1_append": "append arm for every kind except 1",
    "flag_word": "level flag tested as a whole qword instead of its low byte",
    "no_cache": "registration arm never caches the insert result",
    "cache_always": "registration arm caches even when the flag byte is set",
    "wrap_none": "ring index without the capacity reduction",
    "wrap_gt": "ring index reduced only when above capacity",
    "no_grow": "ring never grows when full",
    "found_ignored": "append arm ignores the tree's derived argument",
    "flag_not_one": "append arm passes the level flag even when the tree found a value",
    "patch_swapped": "patch dword and qword placed the other way round",
    "len_unchanged": "ring length not incremented",
}


def jcc_patch(image, row):
    at = image.offset(row.va)
    first = image.blob[at]
    if 0x70 <= first <= 0x7F:
        return row.va, first ^ 1
    if first == 0x0F and 0x80 <= image.blob[at + 1] <= 0x8F:
        return row.va + 1, image.blob[at + 1] ^ 1
    return None


def detects(image, patches, probe):
    harness = Harness(image, patches)
    for case in probe:
        try:
            ok, _, _ = check(harness, case)
        except Exception:  # a crashed mutant is a detected mutant
            return True
        if not ok:
            return True
    return False


def imm_patch(image, row):
    """Flip the low bit of an immediate operand byte (a constant such as 1, 5, 0x110 or a displacement-free mask)."""
    if row.imm_at is None or row.op not in ("cmp", "mov", "shl", "sub", "add", "test", "and", "pushi") or row.imm_size not in (1, 4):
        return None
    va = row.va + row.imm_at
    if row.op in ("sub", "add") and row.a[0] == "r" and row.a[1] == RSP:
        return None  # a frame size change moves every stack slot and is a layout change, not a rule change
    return va, image.blob[image.offset(va)] ^ 1


def run_mutants(image, seen, probes):
    rows = []
    for twin in range(len(OWNERS)):
        start, end = image.exact_fde(OWNERS[twin]["owner"])
        for row in decode_range(image, start, end):
            if row.va not in seen:
                continue
            for kind, patch in (("jcc", jcc_patch(image, row) if row.op == "jcc" else None), ("imm", imm_patch(image, row))):
                if not patch:
                    continue
                at, byte = patch
                caught = False
                for stage, probe in enumerate(probes, 1):
                    if detects(image, {at: byte}, probe[twin]):
                        caught = True
                        break
                rows.append((twin, row.va, kind, at, byte, "detected" if caught else "survived", stage))
    return rows


def twin_rows(image, twin):
    start, end = image.exact_fde(OWNERS[twin]["owner"])
    return start, end, decode_range(image, start, end)


def shape(row, start):
    target = row.target
    if row.op in ("jcc", "jmp") and target is not None:
        target = target - start
    return (row.op, row.a, row.b, row.width, row.cc, target if row.op != "call" else None)


def twin_differences(image):
    out = []
    sa, ea, ra = twin_rows(image, 0)
    sb, eb, rb = twin_rows(image, 1)
    if len(ra) != len(rb):
        out.append((-1, 0, 0, "instruction count", len(ra), len(rb)))
    for index, (x, y) in enumerate(zip(ra, rb)):
        if shape(x, sa) != shape(y, sb):
            out.append((index, hex(x.va), hex(y.va), x.op, shape(x, sa)[1:], shape(y, sb)[1:]))
        elif x.op == "call" and x.target != y.target:
            out.append((index, hex(x.va), hex(y.va), "call target", hex(x.target), hex(y.target)))
    return out


def table(rows):
    return "".join("\t".join(str(cell) for cell in row) + "\n" for row in rows)


def tsv_cell(value):
    return str(value).replace("\t", " ").replace("\n", " ")


def corrupt_controls(image):
    """Structural negatives: wrong digest, address outside every FDE, address that is not an FDE start."""
    results = []
    for label, action in (("wrong digest", lambda: load_image(BINARY, "0" * 64)),
                          ("outside every FDE", lambda: image.fde(0x10)),
                          ("not an FDE start", lambda: image.exact_fde(OWNERS[0]["owner"] + 1)),
                          ("next function is not an FDE start", lambda: image.exact_fde(NEXT + 1))):
        try:
            action()
            results.append((label, False))
        except EvidenceError:
            results.append((label, True))
    return results



# ---- tree next (0x4e188f0): the cached-argument derivation, run as real bytes ----

NEXT_USED = 0x100000
STATE = HEAP_BASE + 0x1000
TREE = HEAP_BASE + 0x2000
LEAF_SIZE = 0x118
INTERNAL_SIZE = 0x178
NODE_CAPACITY = 11
SLOT_NEXT_PANIC = 0x64DF830
PANIC_NO_FRONT_PARENT = 0x64A3760
PANIC_NO_FRONT_NODE = 0x64A3748
ENTRY_RDX = 0x5151
LIST_STRIDE = 0x18


class TreeNode:
    __slots__ = ("addr", "height", "keys", "vals", "children", "parent", "pidx")

    def __init__(self, addr, height):
        self.addr, self.height = addr, height
        self.keys, self.vals, self.children, self.parent, self.pidx = [], [], [], None, 0


def build_tree(source, height, nodes, fixed=None):
    """A random B-tree of the given height; every node holds 1..11 entries and keys rise in order."""
    counter = [0]
    free = [TREE]

    def make(level, parent, pidx):
        at = free[0]
        free[0] = (at + (INTERNAL_SIZE if level else LEAF_SIZE) + 0x1F) & ~0x1F
        node = TreeNode(at, level)
        node.parent, node.pidx = parent, pidx
        nodes.append(node)
        length = fixed or 1 + next(source) % NODE_CAPACITY
        for slot in range(length):
            if level:
                node.children.append(make(level - 1, node, slot))
            counter[0] += 1
            node.keys.append(counter[0] * 7 + next(source) % 3)
            node.vals.append(struct.pack("<QQ", next(source), next(source)))
        if level:
            node.children.append(make(level - 1, node, length))
        return node

    root = make(height, None, 0)
    return root


def write_tree(memory, nodes):
    for node in nodes:
        length = len(node.keys)
        for slot in range(length):
            memory.put_bytes(node.addr + 16 * slot, node.vals[slot])
            memory.write(node.addr + 0xB8 + 8 * slot, 8, node.keys[slot])
        memory.write(node.addr + 0xB0, 8, node.parent.addr if node.parent else 0)
        memory.write(node.addr + 0x110, 2, node.pidx)
        memory.write(node.addr + 0x112, 2, length)
        for slot, child in enumerate(node.children):
            memory.write(node.addr + 0x118 + 8 * slot, 8, child.addr)


class NextCase:
    __slots__ = ("kind", "words", "height_tree", "nodes", "front", "back", "label")

    def __init__(self, kind, words=None, height_tree=0, nodes=None, front=None, back=None, label=""):
        self.kind, self.words, self.height_tree, self.nodes, self.front, self.back, self.label = (
            kind, words or (0,) * 7, height_tree, nodes or [], front, back, label)


def spec_next(case, variant=""):
    """Expected registers and state words for one call of the next function on a tag/words state."""
    words = list(case.words)
    tag = words[0]
    if tag == 0:
        return dict(rax=0, rdx=ENTRY_RDX, words=words)
    if tag & MASK[4] == 1 and variant != "list_tag_wide":
        first, second, third, fourth = words[1], words[2], words[3], words[4]
        if first == second:
            words[1], words[2] = third, fourth
            words[3], words[4] = first, second
            if words[1] == words[2]:
                return dict(rax=0, rdx=0x10, words=words)
        at = words[1]
        words[1] = (at + LIST_STRIDE) & MASK[8]
        return dict(rax=at, rdx=(at + 0x10) & MASK[8], words=words)
    front_node, height, idx, back_node, back_idx = words[1], words[2], words[3], words[4], words[6]
    by_addr = dict((n.addr, n) for n in case.nodes)
    if front_node == 0:
        if back_node != 0:
            return dict(stop=("panic", PANIC_NO_FRONT_NODE))
        return dict(rax=0, rdx=back_node, words=words)
    if front_node == back_node and idx == back_idx:
        return dict(rax=0, rdx=back_node, words=words)
    node = by_addr[front_node]
    while True:
        limit = len(node.keys)
        ascend = idx > limit if variant == "ascend_gt" else idx >= limit
        if not ascend:
            break
        if node.parent is None:
            return dict(stop=("panic", PANIC_NO_FRONT_PARENT))
        height += 1
        idx = node.pidx
        node = node.parent
    rax = node.addr + 16 * idx
    rdx = node.addr + 0xB8 + 8 * idx
    if height == 0:
        new_node, new_idx = node.addr, idx + 1
    else:
        leaf = node.children[idx + 1]
        for _ in range(height - 1):
            leaf = leaf.children[0]
        new_node, new_idx = leaf.addr, 0
    words[1], words[2], words[3] = new_node, 0, (new_idx if variant != "idx_plain" else idx)
    return dict(rax=rax, rdx=rdx, words=words)


def next_cases(count):
    source = lcg(77)
    for number in range(count):
        mode = number % 10
        if mode == 0:
            yield NextCase("zero", words=(0, next(source), next(source), next(source), next(source), next(source), next(source)), label="tag 0")
            continue
        if mode in (1, 2):
            tag = (1, 0x100000001, 1)[number % 3]
            a = TREE + 0x40 * (next(source) % 8)
            b = a if number % 2 else a + LIST_STRIDE * (1 + next(source) % 4)
            c = TREE + 0x400 + 0x40 * (next(source) % 8)
            d = c if number % 5 == 0 else c + LIST_STRIDE * (1 + next(source) % 3)
            yield NextCase("list", words=(tag, a, b, c, d, next(source), next(source)), label="list a%s b%s" % ("=" if a == b else "<", "=" if c == d else "<"))
            continue
        nodes = []
        if number % 50 == 9:
            # one entry per node and a front handle past the end of the rightmost leaf of the first child: the walk
            # climbs and then descends as many levels as the tree is high, which reaches the eight-level unrolled loop
            height = 8 + (number // 50) % 3
            root = build_tree(source, height, nodes, fixed=1)
            leaf = root.children[0]
            while leaf.children:
                leaf = leaf.children[-1]
            words = (2, leaf.addr, 0, len(leaf.keys), root.addr, next(source), 1)
            yield NextCase("tree", words=words, height_tree=height, nodes=nodes, front=(leaf.addr, 0, len(leaf.keys)),
                           back=(root.addr, 1), label="deep h%d" % height)
            continue
        height = next(source) % 4
        root = build_tree(source, height, nodes)
        tag = (2, 0x300000002, 0x100000000, 7)[number % 4]
        pick = nodes[next(source) % len(nodes)]
        idx = next(source) % (len(pick.keys) + 1)
        if number % 11 == 3:
            idx = len(pick.keys)
        other = nodes[next(source) % len(nodes)]
        back_idx = next(source) % (len(other.keys) + 1)
        front, back = (pick.addr, pick.height, idx), (other.addr, back_idx)
        if number % 6 == 0:
            back = (pick.addr, idx)
        if number % 13 == 5:
            front = (0, 0, 0)
            back = (0, 0) if number % 2 else (other.addr, back_idx)
        if number % 17 == 7 and root.addr != pick.addr:
            pick = root
            front, idx = (root.addr, root.height, len(root.keys)), len(root.keys)
        words = (tag, front[0], front[1], front[2], back[0], next(source), back[1])
        yield NextCase("tree", words=words, height_tree=height, nodes=nodes, front=front, back=back,
                       label="h%d len%d idx%d" % (height, len(pick.keys), idx))


class NextHarness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        self.machine.step_limit = STEP_LIMIT if not patches else MUTANT_STEP_LIMIT
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        self.machine.memory.statics[SLOT_NEXT_PANIC] = relative[SLOT_NEXT_PANIC]
        self.machine.slots = {relative[SLOT_NEXT_PANIC]: self.on_panic}
        self.machine.real = frozenset()

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def run(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(NEXT_USED)
        write_tree(memory, case.nodes)
        for slot, value in enumerate(case.words):
            memory.write(STATE + 8 * slot, 8, value)
        try:
            rax = machine.run(NEXT, {RDI: STATE, RDX: ENTRY_RDX})
        except Panicked as stop:
            return dict(stop=stop.args[0])
        words = [memory.read(STATE + 8 * slot, 8) for slot in range(7)]
        return dict(rax=rax, rdx=machine.regs[RDX], words=words)


def check_next(harness, case, variant=""):
    try:
        expected = spec_next(case, variant)
    except (KeyError, IndexError):  # a wrong variant followed a pointer that is not a tree node: it cannot agree with the bytes
        return False, None, None
    try:
        actual = harness.run(case)
    except (Halt, Panicked, EvidenceError, ZeroDivisionError, KeyError):
        return False, expected, None
    return actual == expected, expected, actual


EQUIVALENT_NEXT = {
    0x4E189E8: "cmp rsi,8 after the remainder loop (rsi mod 8 != 0): changing 8 to 9 differs only for rsi == 8, "
               "and 8 mod 8 == 0 takes the other entry (0x4e18a10), so the compare is never reached with rsi == 8",
}

NEXT_VARIANTS = ("list_tag_wide", "ascend_gt", "idx_plain")
NEXT_NOTE = {
    "list_tag_wide": "tag compared as a full qword when choosing the chunk arm",
    "ascend_gt": "ascend only when the index is above the length",
    "idx_plain": "next index left at the entry index after a step",
}


def analyse_next(image, count, rows_every):
    harness = NextHarness(image)
    outcomes, mismatches, rows = {}, [], []
    total = 0
    for number, case in enumerate(next_cases(count)):
        ok, expected, actual = check_next(harness, case)
        total += 1
        if not ok:
            mismatches.append((number, case.label))
            continue
        kind = "panic" if "stop" in actual else ("none" if actual["rax"] == 0 else case.kind)
        key = (case.kind, kind)
        outcomes[key] = outcomes.get(key, 0) + 1
        if number % rows_every == 0:
            rows.append((number, case.kind, kind, case.label, hex(actual.get("rax", 0))))
    return harness, total, outcomes, mismatches, rows


def run_next_mutants(image, seen, probes):
    rows = []
    start, end = image.exact_fde(NEXT)
    for row in decode_range(image, start, end):
        if row.va not in seen:
            continue
        for kind, patch in (("jcc", jcc_patch(image, row) if row.op == "jcc" else None), ("imm", imm_patch(image, row))):
            if not patch:
                continue
            at, byte = patch
            caught = False
            for stage, probe in enumerate(probes, 1):
                harness = NextHarness(image, {at: byte})
                for case in probe:
                    try:
                        ok, _, _ = check_next(harness, case)
                    except Exception:  # a crashed mutant is a detected mutant
                        ok = False
                    if not ok:
                        caught = True
                        break
                if caught:
                    break
            rows.append((hex(row.va), kind, hex(at), hex(byte), "detected" if caught else "survived", stage))
    return rows


def render(image, per_twin, rows_every, next_count):
    harness, counts, outcomes, mismatches, rows = analyse(image, per_twin, rows_every)
    if mismatches:
        raise EvidenceError("%d mismatches, first %r" % (len(mismatches), mismatches[0]))
    seen = harness.machine.seen
    coverage = []
    for twin in range(len(OWNERS)):
        start, end, decoded = twin_rows(image, twin)
        coverage.append((twin, hex(start), hex(end), end - start, len(decoded), sum(1 for row in decoded if row.va in seen)))
    probes = [{twin: list(cases_for(twin, 300)) for twin in range(2)}, {twin: list(cases_for(twin, 1500)) for twin in range(2)}]
    mutants = run_mutants(image, seen, probes)
    variants = []
    for variant in VARIANTS:
        first, wrong, tried = None, 0, 0
        for twin in range(2):
            for case in cases_for(twin, 800):
                ok, _, _ = check(harness, case, variant)
                tried += 1
                if not ok:
                    wrong += 1
                    first = first or case.label
        variants.append((variant, VARIANT_NOTE[variant], first or "-", wrong, tried))
    next_harness, next_total, next_outcomes, next_mismatches, next_rows = analyse_next(image, next_count, rows_every)
    if next_mismatches:
        raise EvidenceError("%d next mismatches, first %r" % (len(next_mismatches), next_mismatches[0]))
    next_start, next_end = image.exact_fde(NEXT)
    next_decoded = decode_range(image, next_start, next_end)
    next_stepped = sum(1 for row in next_decoded if row.va in next_harness.machine.seen)
    next_probes = [list(next_cases(300)), list(next_cases(1500))]
    next_mutants = run_next_mutants(image, next_harness.machine.seen, next_probes)
    equivalent = [row for row in next_mutants if row[4] == "survived" and int(row[0], 16) in EQUIVALENT_NEXT]
    next_mutants = [row[:4] + ("equivalent",) + row[5:] if row in equivalent else row for row in next_mutants]
    next_variants = []
    for variant in NEXT_VARIANTS:
        first, wrong, tried = None, 0, 0
        for case in next_cases(1200):
            ok, _, _ = check_next(next_harness, case, variant)
            tried += 1
            if not ok:
                wrong += 1
                first = first or case.label
        next_variants.append((variant, NEXT_NOTE[variant], first or "-", wrong, tried))
    controls = corrupt_controls(image)
    detected_mutants = sum(1 for row in mutants if row[5] == "detected")
    survivors = len(mutants) - detected_mutants
    detected_variants = sum(1 for row in variants if row[3] > 0)
    total = sum(counts.values())
    files = {}
    files["cases.tsv"] = "owner\tcase\toutcome\tlabel\tring length after\tstub events\n" + table(
        (hex(OWNERS[t]["owner"]), n, k, label, ln, e) for t, n, k, label, ln, e in rows)
    files["outcomes.tsv"] = "owner\toutcome\tcases\n" + table((hex(OWNERS[t]["owner"]), k, outcomes[(t, k)]) for t, k in sorted(outcomes))
    files["owners.tsv"] = "owner\tstart\tend\tbytes\tinstructions\tstepped\tkey callee\tlookup callee\tinsert callee\n" + table(
        (hex(OWNERS[c[0]]["owner"]),) + c[1:] + (hex(OWNERS[c[0]]["key"]), hex(OWNERS[c[0]]["lookup"]), hex(OWNERS[c[0]]["insert"]))
        for c in coverage)
    files["owner_differences.tsv"] = "index\tva first\tva second\twhat\tfirst\tsecond\n" + table(
        tuple(tsv_cell(cell) for cell in row) for row in twin_differences(image))
    files["mutants.tsv"] = "owner\tinstruction va\tkind\tpatched byte va\tnew byte\tresult\tstage\n" + table(
        (hex(OWNERS[t]["owner"]), hex(v), k, hex(a), hex(b), r, s) for t, v, k, a, b, r, s in mutants)
    files["variants.tsv"] = "variant\tmeaning\tfirst case where the bytes disagree\tdisagreeing cases\tcases tried\n" + table(variants)
    files["controls.tsv"] = "control\tdetected\n" + table(controls)
    files["next_cases.tsv"] = "case\tstate kind\toutcome\tlabel\trax\n" + table(
        (n, k, o, label, rax) for n, k, o, label, rax in next_rows)
    files["next_outcomes.tsv"] = "state kind\toutcome\tcases\n" + table((k, o, next_outcomes[(k, o)]) for k, o in sorted(next_outcomes))
    files["next_mutants.tsv"] = "instruction va\tkind\tpatched byte va\tnew byte\tresult\tstage\n" + table(next_mutants)
    files["next_variants.tsv"] = "variant\tmeaning\tfirst case where the bytes disagree\tdisagreeing cases\tcases tried\n" + table(next_variants)
    next_detected = sum(1 for row in next_mutants if row[4] == "detected")
    files["equivalent-mutants.tsv"] = "mutant\taddress\treason\n" + table(
        ("next function immediate flip", row[0], EQUIVALENT_NEXT[int(row[0], 16)]) for row in equivalent)
    next_variants_detected = sum(1 for row in next_variants if row[3] > 0)
    summary = dict(binary_sha256=SHA256, cases=total, mismatches=len(mismatches), per_twin=per_twin,
                   next=dict(function=hex(NEXT), bytes=next_end - next_start, instructions=len(next_decoded), stepped=next_stepped,
                             cases=next_total, mutants=len(next_mutants), mutants_detected=next_detected, mutants_equivalent=len(equivalent),
                             variants=len(next_variants), variants_detected=next_variants_detected),
                   coverage=[dict(owner=c[1], bytes=c[3], instructions=c[4], stepped=c[5]) for c in coverage],
                   mutants=len(mutants), mutants_detected=detected_mutants, survivors=survivors,
                   variants=len(variants), variants_detected=detected_variants, controls=len(controls))
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    negative = len(mutants) + len(variants) + len(controls) + len(next_mutants) + len(next_variants)
    detected = (detected_mutants + detected_variants + sum(1 for _, ok in controls if ok) + next_detected
                + next_variants_detected)
    measure = dict(cases=total + next_total, negative_controls=negative, negative_detected=detected, equivalent=len(equivalent),
                   owner_cases=total, next_cases=next_total)
    files["measure.json"] = json.dumps(measure, indent=1, sort_keys=True) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (folder / name).write_text(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--cases", type=int, default=5200, help="cases per owner")
    parser.add_argument("--sample", type=int, default=4, help="keep every Nth case in cases.tsv")
    parser.add_argument("--next-cases", type=int, default=5000, help="cases for the tree next function")
    args = parser.parse_args(argv)
    image = load_image()
    write_outputs(args.out, render(image, args.cases, args.sample, args.next_cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
