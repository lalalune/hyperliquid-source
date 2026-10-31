#!/usr/bin/env python3
"""Pin the node #94 JSON state form of Bridge2 from bytes.

The real serializer bytes run in an emulator on fixture states with real B-tree nodes. A separately written rule
list predicts every output byte, and reached rows of the named functions are edited. No objdump or readelf output
is parsed and the binary is never executed. Standard library only.

    python3 tools/bridge_state_wire.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
import hashlib
import json
import math
import multiprocessing
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
HEAP_SIZE = 0x400000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 120000


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


def fdiv(left, right):
    return left / right


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
SHIFTS = {0: "rol", 1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
            if op != "mov" and any(operand and operand[0] == "r" and 4 <= operand[1] <= 7 for operand in (a, b)):
                raise EvidenceError("high byte register at %#x" % va)
            if a and a[0] == "r" and 4 <= a[1] <= 7:
                a = ("h", a[1] - 4)
            if b and b[0] == "r" and 4 <= b[1] <= 7:
                b = ("h", b[1] - 4)

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
    if byte == 0xA9:
        value = immediate(4)
        return finish("test", ("r", RAX), ("i", value), width)
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
        if two == 0xAB:
            reg, rm = modrm()
            return finish("btsr", rm, ("r", reg), width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("btr", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two == 0x13:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
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
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two == 0x16 and not opsize:
            reg, rm = modrm(True)
            return finish("movhps", ("x", reg), rm, 8)
        if two == 0x12 and not opsize and not rep and not repne:
            reg, rm = modrm(True)
            return finish("movlps", ("x", reg), rm, 8)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movdout", rm, ("x", reg), 4)
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
        if kind == "h":
            return self.regs[operand[1]] >> 8 & 0xFF
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "h":
            self.regs[operand[1]] = (self.regs[operand[1]] & ~0xFF00) | value << 8
            return
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

    def run(self, entry, args, stack=()):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        for value in reversed(stack):
            self.push(value)
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
        elif op == "btsr":
            bit = self.get(row.b, width) & (8 * width - 1)
            value = self.get(row.a, width)
            self.cf = bool(value >> bit & 1)
            self.put(row.a, width, value | 1 << bit)
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
        elif op == "movsx":
            value = self.get(row.b, row.cc)
            self.put(row.a, width, value - (1 << (8 * row.cc)) if value & SIGN[row.cc] else value)
        elif op == "ror":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) & MASK[width])
        elif op == "rol":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) & MASK[width])
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
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            left -= (left >> 63) << 64
            right -= (right >> 63) << 64
            product = left * right
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
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
        elif op == "movhps":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | self.get(row.b, 8) << 64
        elif op == "movlps":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 << 64 | self.get(row.b, 8)
        elif op == "movdout":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
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



ROOT_JSON = 0x2215860
FIELD_JSON = 0x27AFFA0
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_REALLOC = 0x576E030
SLOT_BCMP = 0x576E378
SLOT_NO_INSTANCE = 0x57706C8
SLOT_MEMSET = 0x576E1F8
SLOT_PARENT = 0x576EA68
SLOT_WRITE = 0x576F670
STOP_SLOTS = (0x576E470, 0x576E098, 0x576E108, 0x576E020, 0x576E2E0, 0x576E468, 0x576E118)
MARK_BASE = 0x7700000000

ARENA = HEAP_BASE + 0x10000
HEAP_USED = 0x400000
ARENA_END = HEAP_BASE + 0x300000
OUT = HEAP_BASE + 0x100
BRIDGE = HEAP_BASE + 0x1000
SERIALIZER = HEAP_BASE + 0x2000
WRITER = SERIALIZER + 0x40
COMPOUND = HEAP_BASE + 0x2800
FILE_STATE = HEAP_BASE + 0x1000
FILE_LOCATION = 0x5A5A5A
BODY_OK = 0x8000000000000004
FAIL_MARK = 0xE5
FILE_ROUTES = ((0x28EB1E0, 0x2206F00, 0x2206FF0, 0x28EB900, 0x28EB970), (0x3C165B0, 0x3273BE0, 0x3273970, 0x3C16CD0, 0x3C16D40))
INDENT_AT = HEAP_BASE + 0x2900
NAMES_AT = HEAP_BASE + 0x3000
LONG_STEP_LIMIT = 6000000
MUTANT_STEP_LIMIT = 450000

Layout = collections.namedtuple("Layout", "name key_at key_size val_at val_size parent index count size")
ROWS = Layout("deposit vote rows", 0, 0x40, 0x2C8, 0x48, 0x2C0, 0x5E0, 0x5E2, 0x5E8)
SIGN_ROWS = Layout("withdrawal signature rows", 0, 0x20, 0x168, 0x48, 0x160, 0x480, 0x482, 0x488)
FINAL_ROWS = Layout("withdrawal finalize rows", 0x2C0, 0x20, 0, 0x40, 0x420, 0x428, 0x42A, 0x430)
INNER = Layout("rows of one amount and user", 0, 0x20, 0x160, 0x30, 0x370, 0x378, 0x37A, 0x380)
VOTERS = Layout("voter set", 0, 0x20, 0, 0, 0x160, 0x168, 0x16A, 0x170)
VOTES = Layout("signature votes", 0, 0x20, 0x168, 0x48, 0x160, 0x480, 0x482, 0x488)
SET_ROWS = Layout("validator set vote rows", 0x168, 8, 0, 0x20, 0x160, 0x1C0, 0x1C2, 0x1C8)
NO_VOTER = Layout("empty by type", 8, 0, 0, 0, 0, 0x320, 0x322, 0x328)
BUCKET = Layout("unit key bucket", 0, 0, 0, 0x30, 0x210, 0x218, 0x21A, 0x220)
ENTRIES = Layout("validator set entries", 0, 0x30, 0, 0, 0x210, 0x218, 0x21A, 0x220)
FINISHED = Layout("finished deposits", 0, 0x40, 0x2C8, 0x28, 0x2C0, 0x480, 0x482, 0x488)
TIMES = Layout("finished withdrawals", 0, 0x20, 0x168, 12, 0x160, 0x1EC, 0x1EE, 0x1F0)


class Harness:
    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = image.real_set()
        machine.step_limit = LONG_STEP_LIMIT
        machine.memory.statics = image.static_view()
        table = {SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_BCMP: self.on_compare, SLOT_REALLOC: self.on_realloc, SLOT_MEMSET: self.on_set, SLOT_PARENT: self.on_parent, SLOT_WRITE: self.on_write}
        for slot in STOP_SLOTS:
            table[slot] = self.on_stop
        table[SLOT_NO_INSTANCE] = self.on_no_instance
        for slot, hook in table.items():
            machine.slots[MARK_BASE + slot] = hook
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        for root, form, pretty_form, fail_body, fail_tree in FILE_ROUTES:
            machine.calls[form] = self.on_form
            machine.calls[pretty_form] = self.on_pretty
            machine.calls[fail_body] = self.on_fail_body
            machine.calls[fail_tree] = self.on_fail_tree
        self.top = ARENA
        self.live = {}
        self.root, self.field_root = ROOT_JSON, FIELD_JSON
        self.events, self.file_case = [], None

    def expect(self, condition, text):
        if not condition:
            raise Halt("fixture check failed: " + text)

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def data(self, at, size):
        return self.machine.memory.bytes_at(at, size)

    def write(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def put(self, at, data):
        self.machine.memory.put_bytes(at, data)

    def alloc(self, size):
        at = self.top
        self.top += (size + 15) & ~15
        if self.top > ARENA_END:
            raise Halt("fixture arena full")
        self.live[at] = size
        return at

    def on_alloc(self, machine):
        machine.regs[RAX] = self.alloc(machine.regs[RDI])

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.get(at) == size, "freed block size")
        del self.live[at]

    def on_realloc(self, machine):
        old, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(old in self.live, "realloc of a live block")
        at = self.alloc(size)
        self.put(at, self.data(old, min(size, self.live[old])))
        del self.live[old]
        machine.regs[RAX] = at

    def on_copy(self, machine):
        if machine.regs[RDX]:
            self.put(machine.regs[RDI], self.data(machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = machine.regs[RDI]

    def on_set(self, machine):
        if machine.regs[RDX]:
            self.put(machine.regs[RDI], bytes([machine.regs[RSI] & 0xFF]) * machine.regs[RDX])
        machine.regs[RAX] = machine.regs[RDI]

    def on_form(self, machine):
        at = machine.regs[RDX]
        vec = self.read(at)
        self.expect(machine.regs[RSI] == FILE_STATE, "state pointer reaches the msgpack body")
        self.events.append("msgpack options %s" % self.data(at + 8, 5).hex())
        block = self.alloc(8)
        self.put(block, b"rmp")
        self.write(vec, 8)
        self.write(vec + 8, block)
        self.write(vec + 16, 3)
        self.write(machine.regs[RDI], BODY_OK if not self.file_case.body else 0x8000000000000001)
        machine.regs[RAX] = machine.regs[RDI]

    def on_pretty(self, machine):
        at = machine.regs[RSI]
        vec = self.read(at)
        self.expect(machine.regs[RDI] == FILE_STATE, "state pointer reaches the JSON body")
        self.events.append("json indent %s level %d has_value %d buffer %d" % (self.data(self.read(at + 8), self.read(at + 16)).hex(), self.read(at + 0x18), self.read(at + 0x20, 1), self.read(vec)))
        self.put(self.read(vec + 8), b"{}\n")
        self.write(vec + 16, 3)
        machine.regs[RAX] = self.file_case.body

    def on_fail_body(self, machine):
        self.events.append("json failure helper")
        machine.regs[RAX] = FAIL_MARK

    def on_fail_tree(self, machine):
        self.events.append("msgpack failure helper")
        machine.regs[RAX] = FAIL_MARK

    def on_parent(self, machine):
        self.events.append("parent step %s" % self.data(machine.regs[RDI], machine.regs[RSI]).decode())
        machine.regs[RAX] = self.file_case.parent

    def on_write(self, machine):
        self.events.append("write %s to %s" % (self.data(machine.regs[RDI], machine.regs[RSI]).decode(), self.data(machine.regs[RDX], machine.regs[RCX]).decode()))
        self.expect(machine.regs[R8] == FILE_LOCATION, "fourth word kept")
        machine.regs[RAX] = self.file_case.write

    def run_file(self, case):
        """The real path route, with the bodies and the file steps as stubs."""
        self.fresh()
        self.file_case, self.events = case, []
        data = case.path.encode()
        self.put(NAMES_AT, data + bytes(8))
        self.machine.run(case.route, {RDI: FILE_STATE, RSI: NAMES_AT, RDX: len(data), RCX: FILE_LOCATION})
        self.expect(not self.live, "every buffer freed")
        return ("file", " | ".join(self.events), self.machine.regs[RAX])

    def on_compare(self, machine):
        left, right = self.data(machine.regs[RDI], machine.regs[RDX]), self.data(machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]

    def on_stop(self, machine):
        raise Panicked("panic path reached")

    def on_no_instance(self, machine):
        raise Panicked(self.data(machine.regs[RDI], machine.regs[RSI]).decode())

    def fresh(self):
        self.machine.memory.reset(HEAP_USED)
        self.top = ARENA
        self.live = {}

    def build(self, layout, items):
        """A tree of height 0 or 1; items are sorted (key bytes, value bytes)."""
        def node(entries, edges=()):
            size = layout.size + 12 * 8 if edges else layout.size
            at = self.alloc(size)
            self.put(at, bytes([0xDD]) * size)
            self.write(at + layout.parent, 0)
            self.write(at + layout.count, len(entries), 2)
            for index, (key, value) in enumerate(entries):
                if layout.key_size:
                    self.put(at + layout.key_at + index * layout.key_size, key)
                if layout.val_size:
                    self.put(at + layout.val_at + index * layout.val_size, value)
            for index, child in enumerate(edges):
                self.write(at + layout.size + 8 * index, child)
                self.write(child + layout.parent, at)
                self.write(child + layout.index, index, 2)
            return at
        if len(items) <= 11:
            return node(items)
        children, separators = [], []
        at = 0
        while at < len(items):
            take = 11 if len(items) - at == 11 else 10
            children.append(node(items[at:at + take]))
            if at + take < len(items):
                separators.append(items[at + take])
            at += take + 1
        self.expect(len(separators) <= 11, "fixture tree too wide")
        return node(separators, children)

    def tree(self, at, layout, items):
        self.write(at, self.build(layout, items) if items else 0)
        self.write(at + 8, 0 if len(items) <= 11 else 1)
        self.write(at + 0x10, len(items))

    def serialize(self, case):
        """One real run; returns ("text", output) or ("panic", text)."""
        self.fresh()
        lay_state(self, case.state)
        pointer = self.alloc(case.capacity)
        self.write(WRITER, case.capacity)
        self.write(WRITER + 8, pointer)
        self.write(WRITER + 16, 0)
        self.put(INDENT_AT, case.indent.encode())
        self.write(SERIALIZER, WRITER)
        self.write(SERIALIZER + 8, INDENT_AT)
        self.write(SERIALIZER + 0x10, len(case.indent))
        self.write(SERIALIZER + 0x18, case.level)
        self.write(SERIALIZER + 0x20, 0xEE, 1)
        fixture = set(self.live)
        try:
            if case.field:
                self.write(COMPOUND, 0x100 * case.field, 2)
                self.write(COMPOUND + 8, SERIALIZER)
                self.machine.run(self.field_root, {RDI: COMPOUND, RSI: BRIDGE})
            else:
                self.machine.run(self.root, {RDI: BRIDGE, RSI: SERIALIZER})
        except Panicked as stop:
            return ("panic", str(stop))
        self.expect(self.machine.regs[RAX] == 0, "serializer status %#x" % self.machine.regs[RAX])
        self.expect(self.read(SERIALIZER + 0x18) == case.level, "indent level back at its start")
        self.expect(self.read(SERIALIZER + 0x20, 1) == 1, "has_value set")
        data = self.data(self.read(WRITER + 8), self.read(WRITER + 16))
        self.expect(set(self.live) - fixture <= {self.read(WRITER + 8)}, "only the writer stays allocated")
        return ("text", data.decode())

    def tree_bytes(self, layout, items):
        return struct.pack("<QQQ", self.build(layout, items) if items else 0, 0 if len(items) <= 11 else 1, len(items))


EVENTS = ("Deposit", "InvalidatedWithdrawal", "RequestedWithdrawal", "FinalizedWithdrawal", "FinalizedValidatorSetUpdate", "RequestedValidatorSetUpdateEvent")


class State:
    def __init__(self, **kw):
        self.dep = kw.get("dep", ())
        self.names = kw.get("names", ("deposits", "signs", "finals", "setsigns", "setfinals"))
        self.q, self.i = kw.get("q", 0x3FE0000000000000), kw.get("i", 0x3FD0000000000000)
        self.sig = kw.get("sig", ())
        self.fin = kw.get("fin", ())
        self.vs = kw.get("vs", ())
        self.vf = kw.get("vf", ())
        self.finished = kw.get("finished", ())
        self.times = kw.get("times", ())
        self.bal, self.pruned, self.oaw = kw.get("bal", 500), kw.get("pruned", 9), kw.get("oaw", 1)


VOTE_SIGS = Layout("signature votes", 0, 0x20, 0x168, 0x48, 0x160, 0x480, 0x482, 0x488)
LISTED = Layout("20-byte set", 8, 0x14, 0, 0, 0, 0xE4, 0xE6, 0xE8)
FINAL_INNER = INNER
SET_INNER = BUCKET


def blob(seed, size):
    return bytes((seed + index * 7) & 0xFF for index in range(size))


class Row:
    """One vote row: `key`, `arq`, `status` (None or payload), `inner` a list of (inner key, vks, hvs)."""

    def __init__(self, key, arq=0, status=None, inner=()):
        self.key, self.arq, self.status, self.inner = key, arq, status, inner


def id_bytes(item):
    block, t, event, i, digest = item
    return struct.pack("<QQQ", block, t, i) + digest + bytes([event]) + bytes(7)


def un_bytes(key):
    return struct.pack("<Q", key[0]) + key[1] + bytes(4)


def is_leap(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def time_bytes(item):
    year, ordinal, secs, frac = item
    flags = 0 if is_leap(year) else 8
    return struct.pack("<iII", year << 13 | ordinal << 4 | flags, secs, frac)


def hot_bytes(harness, hvs):
    if hvs == "novoter":
        return harness.tree_bytes(NO_VOTER, [(b"", b"")])
    return harness.tree_bytes(LISTED, [(key, b"") for key in hvs])


def plain_bucket(harness, vks, hvs):
    return harness.tree_bytes(VOTERS, [(key, b"") for key in vks]) + hot_bytes(harness, hvs)


def sign_bucket(harness, vks, hvs):
    return harness.tree_bytes(VOTE_SIGS, [(key, sig_bytes(sig)) for key, sig in vks]) + hot_bytes(harness, hvs)


def sig_bytes(sig):
    return sig[0].to_bytes(32, "little") + sig[1].to_bytes(32, "little") + bytes([sig[2]]) + bytes([0xEE] * 7)


def amount_row(status):
    if status is None:
        return struct.pack("<Q", 1) + bytes([0xEE]) * 0x20
    return struct.pack("<QQ", 0, status[0]) + status[1] + bytes(4)


def deposit_value(harness, row):
    inner = [(struct.pack("<Q", usd) + user + bytes(4), plain_bucket(harness, vks, hvs)) for (usd, user), vks, hvs in row.inner]
    return amount_row(row.status) + harness.tree_bytes(INNER, inner) + bytes([row.arq]) + bytes(7)


def sign_value(harness, row):
    inner = [(struct.pack("<Q", usd) + user + bytes(4), sign_bucket(harness, vks, hvs)) for (usd, user), vks, hvs in row.inner]
    return amount_row(row.status) + harness.tree_bytes(INNER, inner) + bytes([row.arq]) + bytes(7)


def final_value(harness, row):
    inner = [(digest, plain_bucket(harness, vks, hvs)) for digest, vks, hvs in row.inner]
    tag = bytes([1]) + bytes([0xEE]) * 0x20 if row.status is None else bytes([0]) + row.status
    return harness.tree_bytes(INNER, inner) + tag + bytes([row.arq]) + bytes(6)


def set_value(harness, row, bucket):
    inner = [(b"", bucket(harness, vks, hvs)) for vks, hvs in row.inner]
    return harness.tree_bytes(BUCKET, inner) + bytes([row.arq, 1 if row.status is None else 0]) + bytes(6)


def lay_state(h, state):
    B = BRIDGE
    h.put(NAMES_AT, "".join(state.names).encode())
    at = NAMES_AT
    for offset, name in zip((0, 0x40, 0x70, 0xA0, 0xD0), state.names):
        h.write(B + offset, 0x40)
        h.write(B + offset + 8, at)
        h.write(B + offset + 0x10, len(name.encode()))
        at += len(name.encode())
    h.write(B + 0x18, state.q)
    h.write(B + 0x20, state.i)
    h.tree(B + 0x28, ROWS, [(id_bytes(row.key), deposit_value(h, row)) for row in state.dep])
    h.tree(B + 0x58, SIGN_ROWS, [(un_bytes(row.key), sign_value(h, row)) for row in state.sig])
    h.tree(B + 0x88, FINAL_ROWS, [(un_bytes(row.key), final_value(h, row)) for row in state.fin])
    h.tree(B + 0xB8, SET_ROWS, [(struct.pack("<Q", row.key), set_value(h, row, sign_bucket)) for row in state.vs])
    h.tree(B + 0xE8, SET_ROWS, [(struct.pack("<Q", row.key), set_value(h, row, plain_bucket)) for row in state.vf])
    h.tree(B + 0x100, FINISHED, [(id_bytes(key), struct.pack("<Q", usd) + time_bytes(moment) + user) for key, usd, moment, user in state.finished])
    h.tree(B + 0x118, TIMES, [(un_bytes(key), time_bytes(moment)) for key, moment in state.times])
    h.write(B + 0x130, state.bal)
    h.write(B + 0x138, state.pruned)
    h.write(B + 0x140, state.oaw, 1)
    h.put(B + 0x141, bytes([0xEE]) * 7)


class Pairs:
    """A struct: an object with its field names."""

    def __init__(self, *rows):
        self.rows = rows


class Fixed(Pairs):
    """An enum variant with a payload: an object of one key."""


class Bits:
    def __init__(self, word):
        self.word = word


def float_text(word):
    """The shortest round trip digits, in the layout of the real f64 writer: e16 and 1e-7 forms, never e+."""
    value = struct.unpack("<d", word.to_bytes(8, "little"))[0]
    if value != value or value in (float("inf"), float("-inf")):
        return "null"
    sign = "-" if word >> 63 else ""
    if value == 0:
        return sign + "0.0"
    mantissa, power = ("%r" % abs(value) if "e" in "%r" % abs(value) else "%.17e" % 0).split("e") if "e" in "%r" % abs(value) else ("%r" % abs(value), "0")
    whole, _, part = mantissa.partition(".")
    if part == "0":
        part = ""
    digits = (whole + part).lstrip("0")
    point = len(whole) + int(power) if whole != "0" else int(power) - (len(part) - len(part.lstrip("0")))
    digits = digits.rstrip("0") or "0"
    size = len(digits)
    if 0 <= size <= point <= 16:
        return sign + digits + "0" * (point - size) + ".0"
    if 0 < point <= 16:
        return sign + digits[:point] + "." + digits[point:]
    if -5 < point <= 0:
        return sign + "0." + "0" * -point + digits
    if size == 1:
        return "%s%se%d" % (sign, digits, point - 1)
    return "%s%s.%se%d" % (sign, digits[0], digits[1:], point - 1)


def text_of(data):
    """A JSON string body."""
    out = []
    table = {0x22: '\\"', 0x5C: "\\\\", 8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}
    for char in data:
        code = ord(char)
        out.append(table.get(code) or ("\\u%04x" % code if code < 0x20 else char))
    return '"' + "".join(out) + '"'


def pretty(item, indent, level):
    gap = indent * (level + 1)
    close = "\n" + indent * level
    if item is None:
        return "null"
    if item is True or item is False:
        return "true" if item else "false"
    if isinstance(item, int):
        return "%d" % item
    if isinstance(item, str):
        return text_of(item)
    if isinstance(item, Bits):
        return float_text(item.word)
    if isinstance(item, Pairs):
        if not item.rows:
            return "{}"
        return "{\n" + ",\n".join(gap + text_of(key) + ": " + pretty(value, indent, level + 1) for key, value in item.rows) + close + "}"
    if not item:
        return "[]"
    return "[\n" + ",\n".join(gap + pretty(value, indent, level + 1) for value in item) + close + "]"


def hex_of(data):
    return "0x" + data.hex()


def id_shape(item):
    block, t, event, i, digest = item
    return Pairs(("b", block), ("t", t), ("e", EVENTS[event]), ("i", i), ("h", hex_of(digest)))


def un_shape(key):
    return Pairs(("u", hex_of(key[1])), ("n", key[0]))


def time_shape(item):
    year, ordinal, secs, frac = item
    days = [31, 29 if is_leap(year) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    month, day = 0, ordinal
    while day > days[month]:
        day -= days[month]
        month += 1
    year_text = "%04d" % year if 0 <= year <= 9999 else "%+05d" % year
    second = secs % 60 + (1 if frac >= 1000000000 else 0)
    nano = frac % 1000000000
    text = "%s-%02d-%02dT%02d:%02d:%02d" % (year_text, month + 1, day, secs // 3600, secs // 60 % 60, second)
    if nano == 0:
        return text
    if nano % 1000000 == 0:
        return text + ".%03d" % (nano // 1000000)
    if nano % 1000 == 0:
        return text + ".%06d" % (nano // 1000)
    return text + ".%09d" % nano


def status_shape(status, kind):
    if status is None:
        return "N"
    if kind == "deposit":
        return Fixed(("Q", Pairs(("user", hex_of(status[1])), ("usd", status[0]))))
    if kind == "sign":
        return Fixed(("Q", Pairs(("destination", hex_of(status[1])), ("usd", status[0]))))
    if kind == "final":
        return Fixed(("Q", hex_of(status)))
    return Fixed(("Q", None))


def sig_shape(sig):
    return Pairs(("r", "0x%x" % sig[0]), ("s", "0x%x" % sig[1]), ("v", sig[2]))


def plain_shape(vks, hvs):
    return Pairs(("vks", [[hex_of(key), None] for key in vks]), ("hvs", [[hex_of(key), None] for key in hvs]))


def signed_shape(vks, hvs):
    return Pairs(("vks", [[hex_of(key), sig_shape(sig)] for key, sig in vks]), ("hvs", []))


def tracker_shape(row, kind):
    if kind == "deposit":
        votes = [[Pairs(("user", hex_of(key[1])), ("usd", key[0])), plain_shape(vks, hvs)] for key, vks, hvs in row.inner]
    elif kind == "sign":
        votes = [[Pairs(("destination", hex_of(key[1])), ("usd", key[0])), signed_shape(vks, hvs)] for key, vks, hvs in row.inner]
    elif kind == "final":
        votes = [[hex_of(key), plain_shape(vks, hvs)] for key, vks, hvs in row.inner]
    elif kind == "set":
        votes = [[None, signed_shape(vks, hvs)] for vks, hvs in row.inner]
    else:
        votes = [[None, plain_shape(vks, hvs)] for vks, hvs in row.inner]
    return Pairs(("arq", bool(row.arq)), ("qst", status_shape(row.status, kind)), ("vts", votes))


def bridge_shape(state):
    return Pairs(
        ("eth_id_to_deposit_votes", Pairs(("name", state.names[0]), ("hsc", Pairs(("q", Bits(state.q)), ("i", Bits(state.i)))), ("i", [[id_shape(row.key), tracker_shape(row, "deposit")] for row in state.dep]))),
        ("finished_deposits_data", [[id_shape(key), Pairs(("u", hex_of(user)), ("s", usd), ("t", time_shape(moment)))] for key, usd, moment, user in state.finished]),
        ("withdrawal_signatures", Pairs(("name", state.names[1]), ("hsc", None), ("i", [[un_shape(row.key), tracker_shape(row, "sign")] for row in state.sig]))),
        ("withdrawal_finalized_votes", Pairs(("name", state.names[2]), ("hsc", None), ("i", [[un_shape(row.key), tracker_shape(row, "final")] for row in state.fin]))),
        ("finished_withdrawal_to_time", [[un_shape(key), time_shape(moment)] for key, moment in state.times]),
        ("validator_set_signatures", Pairs(("name", state.names[3]), ("hsc", None), ("i", [[row.key, tracker_shape(row, "set")] for row in state.vs]))),
        ("validator_set_finalized_votes", Pairs(("name", state.names[4]), ("hsc", None), ("i", [[row.key, tracker_shape(row, "setfinal")] for row in state.vf]))),
        ("bal", state.bal), ("last_pruned_deposit_block_number", state.pruned), ("oaw", bool(state.oaw)))


NO_VOTER_TEXT = "attempted to instantiate uninhabited type `l1::hard_quorum_policy::NoVoter`"


def spec_run(case):
    if isinstance(case, FileCase):
        return spec_file(case)
    state = case.state
    if any(hvs == "novoter" for rows in (state.sig, state.fin, state.vs, state.vf) for row in rows for *_, hvs in row.inner):
        return ("panic", NO_VOTER_TEXT)
    body = pretty(bridge_shape(state), case.indent, case.level)
    if case.field:
        gap = ("\n" if case.field == 1 else ",\n") + case.indent * case.level
        return ("text", gap + '"bridge2": ' + body)
    return ("text", body)


class Case:
    def __init__(self, name, state, indent="  ", level=0, field=0, capacity=0x4000):
        self.name, self.state, self.indent, self.level, self.field, self.capacity = name, state, indent, level, field, capacity


class FileCase:
    def __init__(self, name, path, parent=0, write=0, body=0, route=FILE_ROUTES[0][0]):
        self.name, self.path, self.parent, self.write, self.body, self.route = name, path, parent, write, body, route


def extension(path):
    """The last normal part of a path, text after its last dot, as the reached rows read it."""
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if not parts or parts[-1] == "..":
        return None
    name = parts[-1]
    at = name.rfind(".")
    return None if at <= 0 else name[at + 1:]


def is_rmp(path):
    tail = extension(path)
    return tail is not None and tail.encode().translate(FOLD) == b"rmp"


FOLD = bytes(code + 32 if 0x41 <= code <= 0x5A else code for code in range(256))


def spec_file(case):
    if case.path == "/dev/null":
        return ("file", "", 0)
    if is_rmp(case.path):
        events = ["msgpack options " + RMP_OPTIONS]
        if case.body:
            return ("file", " | ".join(events + ["msgpack failure helper"]), FAIL_MARK)
        data = "rmp"
    else:
        events = ["json indent 2020 level 0 has_value 0 buffer 128"]
        if case.body:
            return ("file", " | ".join(events + ["json failure helper"]), FAIL_MARK)
        data = "{}\n"
    events.append("parent step " + case.path)
    if case.parent:
        return ("file", " | ".join(events), case.parent)
    events.append("write %s to %s" % (data, case.path))
    return ("file", " | ".join(events), case.write)


def run_case(harness, case):
    return harness.run_file(case) if isinstance(case, FileCase) else harness.serialize(case)


def check_all(harness, cases):
    """Every real run must equal the rule list."""
    rows = []
    for case in cases:
        got = run_case(harness, case)
        if got != spec_run(case):
            raise EvidenceError("case %s differs from the rule list" % case.name)
        rows.append((case, got))
    return rows


USER = blob(0x40, 20)
OTHER = blob(0x21, 20)
HOT = blob(0x81, 20)
VOTER = blob(0x60, 32)
VOTER2 = blob(0x61, 32)
DIGEST = blob(0x33, 32)
EVENT_ID = (0x1234, 0x7F, 2, 0x80, blob(0xA0, 32))
SIG = (int.from_bytes(blob(0x10, 32), "little"), int.from_bytes(blob(0x95, 32), "little"), 0x1B)
MOMENT = (2023, 318, 80000, 123000000)


def deposit_row(key=EVENT_ID, arq=1, status=(777, USER), inner=None):
    return Row(key, arq, status, inner if inner is not None else [((777, USER), [VOTER], [HOT])])


def sign_row(number=55, arq=1, status=(777, OTHER), inner=None):
    return Row((number, USER), arq, status, inner if inner is not None else [((777, OTHER), [(VOTER, SIG)], [])])


def final_row(number=55, arq=1, status=DIGEST, inner=None):
    return Row((number, USER), arq, status, inner if inner is not None else [(DIGEST, [VOTER], [])])


def set_row(epoch=7, arq=1, status=1, inner=None):
    return Row(epoch, arq, status, inner if inner is not None else [([(VOTER, SIG)], [])])


def setfinal_row(epoch=7, arq=1, status=1, inner=None):
    return Row(epoch, arq, status, inner if inner is not None else [([VOTER], [])])


def full_state():
    return State(dep=[deposit_row()], sig=[sign_row()], fin=[final_row()], vs=[set_row()], vf=[setfinal_row()], finished=[(EVENT_ID, 777, MOMENT, USER)], times=[((55, USER), MOMENT)])


def many(count, seed=0):
    return [blob(seed + index, 32) for index in range(count)]


WORDS = (0, 1, 0x3FF0000000000000, 0x3FE0000000000000, 0x7FF8000000000000, 0x7FF0000000000000, 0xFFF0000000000000, 0x8000000000000000, 0xBFF0000000000000, 0x3FB999999999999A,
         0x4340000000000000, 0x4341C37937E08000, 0x4341C37937E08001, 0x3EE4F8B588E368F1, 0x3F1A36E2EB1C432D, 0x3EB0C6F7A0B5ED8D, 0x7FEFFFFFFFFFFFFF, 0x000FFFFFFFFFFFFF, 0x4059000000000000, 0x4415AF1D78B58C40)


def named_cases():
    out = []

    def add(name, state, levels=(0,), capacity=0x4000):
        for level in levels:
            out.append(Case("%s_l%d" % (name, level), state, level=level, capacity=capacity))
    add("empty", State())
    add("full", full_state(), (0, 1, 2))
    out.append(Case("full_as_first_field", full_state(), level=1, field=1))
    out.append(Case("full_as_later_field", full_state(), level=1, field=2))
    out.append(Case("full_wide_indent", full_state(), indent="\t\t\t"))
    out.append(Case("full_no_indent", full_state(), indent=""))
    add("full_tiny_writer", full_state(), (0,), 1)
    add("empty_tiny_writer", State(), (0,), 1)
    for word in WORDS:
        add("hsc_q_%x" % word, State(q=word))
        add("hsc_i_%x" % word, State(i=word))
    for value in (0, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFFFFFF):
        add("bal_%x" % value, State(bal=value))
        add("pruned_%x" % value, State(pruned=value))
    add("oaw_false", State(oaw=0))
    add("names_escape", State(names=('quote"', "back\\slash", "ctrl\x01\x1f\x7f", "tab\t\n\r\x08\x0c", "snow\u2603\U0001F600")))
    for size in (0, 1, 31, 32, 255, 256, 0x10000 >> 4):
        add("name_size_%d" % size, State(names=("d" * size, "s" * size, "f" * size, "v" * size, "w" * size)))
    for index in range(6):
        key = (0x10 + index, 0x7F + index, index, 0x80 + index, blob(0xA0 + index, 32))
        add("event_%d" % index, State(dep=[deposit_row(key)], finished=[(key, 1, MOMENT, USER)]))
    add("deposit_no_quorum", State(dep=[deposit_row(arq=0, status=None)]))
    add("deposit_arq_false_status_q", State(dep=[deposit_row(arq=0)]))
    add("deposit_arq_true_status_n", State(dep=[deposit_row(status=None)]))
    add("deposit_no_votes", State(dep=[deposit_row(inner=[])]))
    add("deposit_two_amounts", State(dep=[deposit_row(inner=[((5, USER), [VOTER], []), ((6, OTHER), [VOTER, VOTER2], [HOT, OTHER])])]))
    add("deposit_hot_only", State(dep=[deposit_row(inner=[((5, USER), [], [HOT])])]))
    add("deposit_16_voters", State(dep=[deposit_row(inner=[((5, USER), many(16), [])])]))
    add("deposit_16_hot", State(dep=[deposit_row(inner=[((5, USER), [], [blob(index, 20) for index in range(16)])])]))
    add("deposit_16_rows", State(dep=[deposit_row((index, 1, 0, 1, DIGEST)) for index in range(16)]))
    add("deposit_rows_keep_node_order", State(dep=[deposit_row((9 - index, 1, 0, 1, DIGEST)) for index in range(9)]))
    add("deposit_130_rows", State(dep=[deposit_row((index, 1, 0, 1, DIGEST), inner=[]) for index in range(130)]))
    add("finished_16", State(finished=[((index, 1, 0, 1, DIGEST), index, MOMENT, USER) for index in range(16)]))
    add("times_16", State(times=[((index, USER), MOMENT) for index in range(16)]))
    add("sign_no_quorum", State(sig=[sign_row(arq=0, status=None)]))
    add("sign_two", State(sig=[sign_row(5), sign_row(6, inner=[((1, USER), [(VOTER, SIG), (VOTER2, SIG)], []), ((2, OTHER), [], [])])]))
    add("sign_16_rows", State(sig=[sign_row(index) for index in range(16)]))
    add("final_no_quorum", State(fin=[final_row(arq=0, status=None)]))
    add("final_two", State(fin=[final_row(5), final_row(6, inner=[(DIGEST, [VOTER, VOTER2], []), (blob(1, 32), [], [])])]))
    add("final_16_rows", State(fin=[final_row(index) for index in range(16)]))
    add("set_no_quorum", State(vs=[set_row(arq=0, status=None)]))
    add("set_two", State(vs=[set_row(1), set_row(2, inner=[([(VOTER, SIG), (VOTER2, SIG)], [])])]))
    add("set_16_rows", State(vs=[set_row(index) for index in range(16)]))
    add("set_no_bucket", State(vs=[set_row(inner=[])]))
    add("setfinal_no_quorum", State(vf=[setfinal_row(arq=0, status=None)]))
    add("setfinal_two", State(vf=[setfinal_row(1), setfinal_row(2, inner=[([VOTER, VOTER2], [])])]))
    add("setfinal_16_rows", State(vf=[setfinal_row(index) for index in range(16)]))
    add("setfinal_no_bucket", State(vf=[setfinal_row(inner=[])]))
    for word in (0, 1, 0xF, 0x10, 1 << 64, (1 << 256) - 1):
        add("sig_r_%x" % (word & 0xFFFF), State(sig=[sign_row(inner=[((1, USER), [(VOTER, (word, 1, 0))], [])])]))
        add("sig_s_%x" % (word & 0xFFFF), State(vs=[set_row(inner=[([(VOTER, (1, word, 0xFF))], [])])]))
    for value in (0, 0x1B, 0x1C, 0x7F, 0x80, 0xFF):
        add("sig_v_%x" % value, State(sig=[sign_row(inner=[((1, USER), [(VOTER, (1, 2, value))], [])])]))
    for moment in ((1970, 1, 0, 0), (2024, 60, 86399, 0), (2023, 365, 3661, 500000000), (2024, 366, 59, 999000), (2023, 2, 3599, 999999999), (2023, 3, 3599, 1000000000), (2023, 4, 3599, 1500000000), (0, 1, 0, 1), (9999, 365, 1, 1000), (10000, 1, 1, 0), (-1, 1, 1, 0), (207519, 100, 1, 0)):
        add("time_%d_%d_%d_%d" % moment, State(times=[((1, USER), moment)]))
    add("novoter_sign", State(sig=[sign_row(inner=[((1, USER), [], "novoter")])]))
    add("novoter_final", State(fin=[final_row(inner=[(DIGEST, [], "novoter")])]))
    add("novoter_set", State(vs=[set_row(inner=[([], "novoter")])]))
    add("novoter_setfinal", State(vf=[setfinal_row(inner=[([], "novoter")])]))
    return out


RMP_OPTIONS = "0004000100"
PATHS = ("state.rmp", "a/b/state.rmp", "x.RMP", "x.Rmp", "x.rMp", "x.rmP", "x.json", "x.rm", "x.rmpp", "x.rmq", "x.qmp", "x.rqp", "x.`mp", "x.r`p", "x.rm`", "x", "", ".rmp", "..rmp", "a.b.rmp", "a.rmp.json", "a.rmp/", "a.rmp/.", "a.rmp/..", "..", "/", "a.rmp/b", "x.", ".", "./x.rmp", "x.rmp ",
         "/dev/null", "/dev/nul", "/dev/nulL", "/dev/null/", "/dev/null.rmp", "/dev/nulll")


def file_cases():
    out = []
    for index, path in enumerate(PATHS):
        for route in FILE_ROUTES:
            out.append(FileCase("path_%d_%x" % (index, route[0]), path, route=route[0]))
    for route in FILE_ROUTES:
        for path in ("x.rmp", "x.json"):
            for name, keys in (("parent_fails", dict(parent=0xE3)), ("write_fails", dict(write=0xE4)), ("body_fails", dict(body=0xE6))):
                out.append(FileCase("%s_%s_%x" % (name, path[2:], route[0]), path, route=route[0], **keys))
    return out


class Draw:
    def __init__(self, seed):
        self.seed, self.pool = seed, b""

    def bytes(self, size):
        while len(self.pool) < size:
            self.seed = hashlib.sha256(self.seed).digest()
            self.pool += self.seed
        out, self.pool = self.pool[:size], self.pool[size:]
        return out

    def below(self, limit):
        return int.from_bytes(self.bytes(8), "big") % limit

    def word(self):
        return int.from_bytes(self.bytes(8), "big") >> (8 * self.below(8))

    def status(self, kind):
        if self.below(2):
            return None
        return self.bytes(32) if kind == "final" else 1 if kind in ("set", "setfinal") else (self.word(), self.bytes(20))

    def moment(self):
        year = 1970 + self.below(200)
        return (year, 1 + self.below(365), self.below(86400), self.below(1000) * 1000000)

    def sig(self):
        return (int.from_bytes(self.bytes(32), "big") >> self.below(256), int.from_bytes(self.bytes(32), "big") >> self.below(256), 27 + self.below(2))

    def event(self):
        return (self.word(), self.word(), self.below(6), self.word(), self.bytes(32))

    def row(self, kind):
        votes = self.below(3)
        keys = [self.bytes(32) for _ in range(self.below(3))]
        pairs = [(key, self.sig()) for key in keys]
        hot = [self.bytes(20) for _ in range(self.below(3))]
        status = self.status(kind)
        arq = self.below(2)
        if kind == "deposit":
            return Row(self.event(), arq, status, [((self.word(), self.bytes(20)), keys, hot) for _ in range(votes)])
        if kind == "sign":
            return Row((self.word(), self.bytes(20)), arq, status, [((self.word(), self.bytes(20)), pairs, []) for _ in range(votes)])
        if kind == "final":
            return Row((self.word(), self.bytes(20)), arq, status, [(self.bytes(32), keys, []) for _ in range(votes)])
        if kind == "set":
            return Row(self.word(), arq, status, [(pairs, []) for _ in range(votes % 2)])
        return Row(self.word(), arq, status, [(keys, []) for _ in range(votes % 2)])

    def state(self):
        rows = {kind: [self.row(kind) for _ in range(self.below(4))] for kind in ("deposit", "sign", "final", "set", "setfinal")}
        return State(dep=rows["deposit"], sig=rows["sign"], fin=rows["final"], vs=rows["set"], vf=rows["setfinal"], q=self.word(), i=self.word(), bal=self.word(), pruned=self.word(), oaw=self.below(2),
                     finished=[(self.event(), self.word(), self.moment(), self.bytes(20)) for _ in range(self.below(4))], times=[((self.word(), self.bytes(20)), self.moment()) for _ in range(self.below(4))],
                     names=tuple("n" * self.below(40) for _ in range(5)))


def vector_cases(count):
    draw = Draw(b"bridge2 state json")
    return [Case("vector_%d" % index, draw.state(), level=draw.below(3), capacity=0x8000) for index in range(count)]


STUBBED = frozenset(address for route in FILE_ROUTES for address in route[1:])


class TextRange:
    """Every code address runs for real, except the bodies behind the path route."""

    def __contains__(self, va):
        return va < 0x6000000 and va not in STUBBED


def real_set(self):
    return TextRange()


def static_view(self):
    if self.static_map is None:
        table = dict(self.relative())
        for slot in (SLOT_ALLOC, SLOT_FREE, SLOT_MEMCPY, SLOT_MEMMOVE, SLOT_MEMCMP, SLOT_BCMP, SLOT_REALLOC, SLOT_NO_INSTANCE, SLOT_MEMSET, SLOT_PARENT, SLOT_WRITE) + STOP_SLOTS:
            table[slot] = MARK_BASE + slot
        self.static_map = table
    return self.static_map


Image.real_set = real_set
Image.static_view = static_view
Image.static_map = None


ROLE = {
    0x2215860: "bridge2_struct", 0x27AFFA0: "bridge2_field_of_exchange", 0x22BB000: "struct_end", 0x2327010: "deposit_tracker", 0x2327F60: "withdrawal_signature_tracker", 0x2328C20: "withdrawal_finalize_tracker",
    0x23278B0: "set_signature_tracker", 0x2327CC0: "set_finalize_tracker", 0x22BAD50: "times_field", 0x22BAC80: "set_signature_field", 0x22BAF30: "set_finalize_field", 0x22BA9C0: "bal_field", 0x2204220: "hsc_q_i",
    0x25DB920: "deposit_rows", 0x25E09A0: "finished_rows", 0x25EBE00: "signature_rows", 0x25E6390: "finalize_rows", 0x25DFD70: "time_rows", 0x25DD880: "set_signature_rows", 0x25E8B00: "set_finalize_rows",
    0x25DEE00: "deposit_vote_rows", 0x25E9DB0: "signature_vote_rows", 0x25EC890: "finalize_vote_rows", 0x25DC870: "set_signature_vote_rows", 0x25E4C60: "set_finalize_vote_rows",
    0x2580B10: "tree_walk_deposit_rows", 0x2579E70: "tree_walk_finished", 0x2573A20: "tree_walk_signature_rows", 0x2574000: "tree_walk_finalize_rows", 0x2562240: "tree_walk_times", 0x2562A50: "tree_walk_set_rows", 0x257E730: "tree_walk_vote_rows", 0x256BCB0: "tree_walk_finalize_votes", 0x256DA20: "tree_walk_set_votes",
    0x2906D60: "deposit_row_pair", 0x291BC70: "finished_pair", 0x29303A0: "signature_row_pair", 0x291E480: "time_pair", 0x29279B0: "signature_vote_pair",
    0x23253C0: "deposit_row_value", 0x23250D0: "signature_row_value", 0x231FF50: "finalize_row_value", 0x2321830: "set_signature_row_value", 0x23256B0: "set_finalize_row_value",
    0x231AE20: "deposit_status", 0x231B200: "signature_status", 0x231AA20: "finalize_status", 0x231B5E0: "set_status",
    0x2216FE0: "user_and_usd", 0x22186A0: "destination_and_usd", 0x2217910: "user_and_nonce", 0x2217DF0: "finished_deposit_u_s_t",
    0x231E230: "deposit_votes_vks_hvs", 0x231DB10: "signed_votes_vks_hvs", 0x231F790: "plain_votes_vks_hvs", 0x295B560: "text_entry", 0x2961580: "null_entry", 0x295C220: "bool_entry", 0x2958170: "u64_entry", 0x2955BD0: "bal_entry", 0x2954E00: "nonce_entry", 0x295BE60: "address_entry",
    0x29967E0: "time_text", 0x28C5220: "json_string", 0x27E2690: "address_text", 0x28EB1E0: "state_file_route", 0x3C165B0: "state_file_route_twin"}
NAMES = dict(ROLE)
TARGETS = tuple(sorted(NAMES))
COPIES = ((0x374B450, 0x3791A60), (0x48F5E70, 0x4DF54E0))
FIELDS = (("eth_id_to_deposit_votes", 0x3D6926, 0x0, 0x2327010, "tracker {name, hsc, i}"), ("finished_deposits_data", 0x3D693D, 0x100, 0x25E09A0, "array of pairs, value {u, s, t}"), ("withdrawal_signatures", 0x3D6953, 0x40, 0x2327F60, "tracker, hsc null"),
          ("withdrawal_finalized_votes", 0x3D6968, 0x70, 0x2328C20, "tracker, hsc null"), ("finished_withdrawal_to_time", 0x597DD8, 0x118, 0x22BAD50, "array of pairs, value time text"), ("validator_set_signatures", 0x597DF3, 0xA0, 0x22BAC80, "tracker, hsc null"),
          ("validator_set_finalized_votes", 0x597E0B, 0xD0, 0x22BAF30, "tracker, hsc null"), ("bal", 0x597E28, 0x130, 0x22BA9C0, "number"), ("last_pruned_deposit_block_number", 0x20C820, 0x138, 0x2958170, "number"), ("oaw", 0x3D69D5, 0x140, 0x295C220, "true or false"))
TEXTS = ()
FIND_TEXTS = (NO_VOTER_TEXT, "bridge2")
KEY_ROWS = ((0x2215886, "has_value byte cleared at struct head", "mov"), (0x221589B, "open brace", "mov"), (0x22158A6, "compound head: tag 0, state 1 for the first key", "mov"), (0x22158B1, "first key text", "lea"), (0x22158EF, "colon and space after a key", "mov"), (0x2215934, "finished deposits at +0x100", "lea"),
            (0x2215A4B, "finished times at +0x118", "lea"), (0x2215A63, "set signatures at +0xa0", "lea"), (0x2215A7B, "set finalize at +0xd0", "lea"), (0x2215A93, "bal at +0x130", "lea"), (0x2215AB5, "pruned at +0x138", "lea"), (0x2215AE3, "oaw at +0x140", "add"), (0x29741D7, "line feed before a first key", "mov"), (0x29741FC, "comma and line feed before a later key", "mov"), (0x2974211, "indent level read from serializer +0x18", "mov"), (0x297421F, "indent text pointer +8", "mov"), (0x2974223, "indent text size +0x10", "mov"),
            (0x28EB204, "path size 9 test", "cmp"), (0x28EB20A, "first eight bytes of /dev/null", "movabs"), (0x28EB22F, "extension test through slot 0x576f620", "calli"), (0x28EB25E, "msgpack options word: byte +0xb is 1, the named flag", "mov"), (0x28EB2A8, "JSON buffer size 0x80", "mov"), (0x28EB2DD, "two spaces of indent", "lea"), (0x28EB2E9, "indent size 2", "mov"), (0x2206F1E, "named flag picks the map or array head", "cmp"), (0x2206F77, "key exchange under the named flag", "lea"))
CHAIN = ((0x28EB278, 0x2206F00, "route, msgpack branch"), (0x28EB308, 0x2206FF0, "route, JSON branch"), (0x2207096, 0x275B800, "exchange JSON key to the Exchange JSON body"), (0x275BABB, 0x27AFFA0, "Exchange JSON body to the bridge2 field"), (0x27AFFFA, 0x2215860, "bridge2 field to the struct"),
         (0x3C16648, 0x3273BE0, "twin route, msgpack branch"), (0x3C166D8, 0x3273970, "twin route, JSON branch"), (0x3273A16, 0x3752B40, "exchange JSON key to the Exchange JSON body"), (0x3752DFB, 0x3791A60, "Exchange JSON body to the bridge2 field"), (0x3791ABA, 0x374B450, "bridge2 field to the copy"),
         (0x46CEC00, 0x446C320, "state.rs line 145 body, JSON alternative"), (0x446C3C6, 0x4D874F0, "exchange JSON key to the Exchange JSON body"), (0x4D877AB, 0x4DF54E0, "Exchange JSON body to the bridge2 field"), (0x46D0030, 0x446C590, "twin body, JSON alternative"), (0x446C636, 0x4D86110, "exchange JSON key to the Exchange JSON body"), (0x4D863CB, 0x4DF54E0, "Exchange JSON body to the bridge2 field"), (0x4DF553A, 0x48F5E70, "bridge2 field to the copy"),
         (0x2812810, 0x28EB1E0, "caller of the route"), (0x22AF060, 0x3C165B0, "caller of the twin route"))
SAMPLE = 2
TIGHT_CASES = ("full_tiny_writer_l0", "names_escape_l0", "full_l1", "deposit_16_rows_l0")
MUTANT_CASES = 4
WORKERS = 4
SURVIVED = "class: equal outcome on every picked case that reaches the row, such as a spill slot, a register choice or a word no rule reads"
MUTANT_STATE = {}


def row_at(image, va):
    return decode(lambda at, count: bytes(image.blob[image.offset(at):image.offset(at) + count]), va)


def edits_for(image, rows):
    edits = []
    for row in rows:
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
    return edits


def first_failure(harness, cases, wants):
    for case, want in zip(cases, wants):
        try:
            if run_case(harness, case) != want:
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, UnicodeDecodeError, struct.error):
            return case
    return None


def spread(items, count):
    if len(items) <= count:
        return items
    head = items[:count // 2]
    rest = items[count // 2:]
    step = len(rest) / (count - count // 2)
    return head + [rest[int(index * step)] for index in range(count - count // 2)]


def mutant_job(job):
    va, kind, patch = job
    state = MUTANT_STATE
    picked = spread([case for case in state["order"] if va in state["reach"][case.name]], MUTANT_CASES)
    picked += [case for case in state["order"] if case.name in TIGHT_CASES and va in state["reach"][case.name] and case not in picked]
    harness = Harness(state["image"], patch, state["cache"])
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    hit = first_failure(harness, picked, [state["wants"][case.name] for case in picked])
    return va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else SURVIVED


def run_mutants(image, table, cases):
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    wants, reach, cost = {}, {}, {}
    for case in cases:
        control.machine.seen = set()
        before = control.machine.steps
        got = run_case(control, case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("an unedited image fails on %s" % case.name)
        wants[case.name], reach[case.name], cost[case.name] = want, control.machine.seen, control.machine.steps - before
    order = sorted(cases, key=lambda item: (cost[item.name], item.name))
    jobs = []
    for target in sorted(table):
        jobs += edits_for(image, table[target])
    MUTANT_STATE.update(image=image, order=order, reach=reach, wants=wants, cache=control.machine.cache)
    with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
        return pool.map(mutant_job, jobs[::SAMPLE], 8)


def key_rows(image):
    out = []
    for va, text, op in KEY_ROWS:
        row = row_at(image, va)
        out.append(("%#x" % image.fde(va)[0], "%#x" % va, bytes(image.blob[image.offset(va):image.offset(va) + row.size]).hex(), row.op, text))
    return out


def text_rows(image):
    rows = []
    for text in FIND_TEXTS:
        at = bytes(image.blob).find(text.encode())
        if at < 0:
            raise EvidenceError("no text %s" % text)
        rows.append(("%#x" % at, text))
    return rows


def field_table(image):
    rows = []
    for index, (name, at, offset, writer, form) in enumerate(FIELDS):
        data = bytes(image.blob[image.offset(at):image.offset(at) + len(name)]).decode()
        if data != name:
            raise EvidenceError("field text at %#x is %s" % (at, data))
        rows.append((index, name, "%#x" % at, "%#x" % offset, "%#x" % writer, form))
    return rows


def copy_rows(image, harness, cases):
    rows = []
    for root, field in COPIES:
        count = 0
        texts = set()
        harness.root, harness.field_root = root, field
        for case in cases:
            got, want = run_case(harness, case), spec_run(case)
            if want[0] == "panic" and got[0] == "panic" and got[1].endswith("hard_quorum_policy::NoVoter`"):
                texts.add(got[1])
            elif got != want:
                raise EvidenceError("copy %#x differs on %s: %s" % (root, case.name, str(got)[:120]))
            count += 1
        harness.root, harness.field_root = ROOT_JSON, FIELD_JSON
        rows.append(("%#x" % root, image.exact_fde(root)[1] - root, "%#x" % field, "%#x" % ROOT_JSON, count, " ".join(sorted(texts))))
    return rows


def chain_rows(image):
    rows = []
    for site, target, note in CHAIN:
        row = row_at(image, site)
        if row.op != "call" or row.target != target:
            raise EvidenceError("site %#x does not call %#x" % (site, target))
        rows.append(("%#x" % site, "%#x" % target, note))
    return rows


def file_rows(harness):
    rows = []
    for case in file_cases():
        got = harness.run_file(case)
        if got != spec_file(case):
            raise EvidenceError("case %s differs from the rule list: %s" % (case.name, got))
        rows.append((case.name, "%#x" % case.route, json.dumps(case.path), got[1], "%#x" % got[2]))
    return rows


def float_rows(harness):
    """The real text of each f64 in hsc q."""
    rows = []
    for word in WORDS:
        text = harness.serialize(Case("float", State(q=word)))[1]
        rows.append(("%016x" % word, re.search(r'"q": ([^,]+),', text).group(1)))
    return rows


def analyse(image, mutate=True, vectors=60):
    harness = Harness(image)
    cases = named_cases() + file_cases()
    named = check_all(harness, cases)
    check_all(harness, vector_cases(vectors))
    seen = set(harness.machine.seen)
    table = {}
    for target in TARGETS:
        low, high = image.exact_fde(target)
        table[target] = [row_at(image, va) for va in sorted(seen) if low <= va < high]
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    light = [case for case in named_cases() if not case.name.startswith(("deposit_130", "name_size_4096"))]
    result = dict(table=table, named=named, vector_count=vectors, keys=key_rows(image), texts=text_rows(image), fields=field_table(image), copies=copy_rows(image, harness, light), floats=float_rows(harness), chain=chain_rows(image), files=file_rows(harness), sample=harness.serialize(Case("sample", full_state()))[1], sizes={target: image.exact_fde(target)[1] - target for target in TARGETS})
    if mutate:
        pool = [case for case in cases if "130_rows" not in case.name]
        result["mutations"] = run_mutants(image, table, pool)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    table = result["table"]
    sizes = result["sizes"]
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in TARGETS for row in table[target]])
    tsv("path.tsv", ("name", "address", "body_bytes", "reached_rows", "reached_bytes"), [(NAMES[target], "%#x" % target, sizes[target], len(table[target]), sum(row.size for row in table[target])) for target in TARGETS])
    tsv("fields.tsv", ("index", "name", "text_at", "state_offset", "writer", "json_form"), result["fields"])
    tsv("texts.tsv", ("address", "text"), result["texts"])
    tsv("copies.tsv", ("copy", "body_bytes", "field_wrapper", "same_rules_as", "cases_matched", "no_voter_panic_text"), result["copies"])
    tsv("call-chain.tsv", ("site", "target", "note"), result["chain"])
    tsv("file-forms.tsv", ("case", "route", "path", "events", "result"), result["files"])
    tsv("float-text.tsv", ("f64_bits", "real_text"), result["floats"])
    tsv("key-rows.tsv", ("function", "at", "bytes", "operation", "note"), result["keys"])
    files["sample-full.json"] = result["sample"] + "\n"
    rows = []
    for case, trace in result["named"]:
        if trace[0] == "file":
            rows.append((case.name, " ".join(str(item) for item in trace[:2]) + " result %#x" % trace[2]))
        elif trace[0] == "text":
            rows.append((case.name, "text %d chars sha256 %s" % (len(trace[1]), hashlib.sha256(trace[1].encode()).hexdigest()[:16])))
        else:
            rows.append((case.name, " ".join(str(item) for item in trace)))
    tsv("scenarios.tsv", ("case", "outcome"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    named = result["named"]
    reached = sum(row.size for rows in table.values() for row in rows)
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(TARGETS), "instructions": sum(len(items) for items in table.values()), "named_scenarios": len(named), "vector_scenarios": result["vector_count"], "body_bytes": sum(sizes.values()), "reached_bytes": reached, "unreached_rows": sum(sizes.values()) - reached, "copies": len(result["copies"])}
    if "mutations" in result:
        items = result["mutations"]
        summary["mutations"] = {"total": len(items), "killed": sum(1 for item in items if item[2] == "killed"), "survived": sum(1 for item in items if item[2] == "survived")}
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

