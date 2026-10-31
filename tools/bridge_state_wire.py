#!/usr/bin/env python3
"""Pin the node #94 msgpack state form of Bridge2 from bytes.

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



ROOT_RMP = 0x3797BA0
DECODE_ROOT = 0x18761F0
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_REALLOC = 0x576E030
SLOT_BCMP = 0x576E378
SLOT_NO_INSTANCE = 0x57706C8
STOP_SLOTS = (0x576E470, 0x576E098, 0x576E108, 0x576E020, 0x576E2E0, 0x576E468, 0x576E118)
MARK_BASE = 0x7700000000

ARENA = HEAP_BASE + 0x10000
HEAP_USED = 0x400000
ARENA_END = HEAP_BASE + 0x300000
OUT = HEAP_BASE + 0x100
BRIDGE = HEAP_BASE + 0x1000
SERIALIZER = HEAP_BASE + 0x2000
WRITER = SERIALIZER + 0x40
NAMES_AT = HEAP_BASE + 0x3000
DECODER = HEAP_BASE + 0x6000
DECODED = HEAP_BASE + 0x8000
INPUT = HEAP_BASE + 0x300000
ERROR_WORD = 0x8000000000000000
STATUS_OK = 0x8000000000000004
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
        table = {SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_BCMP: self.on_compare, SLOT_REALLOC: self.on_realloc}
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
        self.top = ARENA
        self.live = {}

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
        """One real run; returns ("bytes", hex) or ("panic", text)."""
        self.fresh()
        lay_state(self, case.state)
        pointer = self.alloc(case.capacity)
        self.write(WRITER, case.capacity)
        self.write(WRITER + 8, pointer)
        self.write(WRITER + 16, 0)
        self.write(SERIALIZER, WRITER)
        self.write(SERIALIZER + 8, 0)
        self.write(SERIALIZER + 0xB, case.named, 1)
        self.write(SERIALIZER + 0xC, case.mode, 1)
        fixture = set(self.live)
        try:
            self.machine.run(ROOT_RMP, {RDI: OUT, RSI: SERIALIZER, RDX: BRIDGE})
        except Panicked as stop:
            return ("panic", str(stop))
        self.expect(self.read(OUT) == STATUS_OK, "serializer status %#x" % self.read(OUT))
        data = self.data(self.read(WRITER + 8), self.read(WRITER + 16))
        self.expect(set(self.live) - fixture <= {self.read(WRITER + 8)}, "only the writer stays allocated")
        return ("bytes", data.hex())

    def decode(self, case):
        """One real decode. A kept state is fed back through the real serializer in array form."""
        self.fresh()
        self.put(INPUT, case.data)
        self.write(DECODER + 0x10, INPUT)
        self.write(DECODER + 0x18, len(case.data))
        self.write(DECODER + 0x20, 1, 1)
        self.write(DECODER + 0x22, 1024, 2)
        self.machine.run(case.entry, {RDI: DECODED, RSI: DECODER})
        if self.read(DECODED) == ERROR_WORD:
            tag = self.read(DECODED + 8, 1)
            if tag == 6:
                return ("error", 6, self.data(self.read(DECODED + 0x18), self.read(DECODED + 0x20)).decode())
            if tag == 4:
                return ("error", 4, "length %d" % self.read(DECODED + 0xC, 4))
            return ("error", tag, "")
        pointer = self.alloc(0x10000)
        self.write(WRITER, 0x10000)
        self.write(WRITER + 8, pointer)
        self.write(WRITER + 16, 0)
        self.write(SERIALIZER, WRITER)
        self.write(SERIALIZER + 8, 0)
        self.write(SERIALIZER + 0xB, 0, 1)
        self.write(SERIALIZER + 0xC, 0, 1)
        self.machine.run(ROOT_RMP, {RDI: OUT, RSI: SERIALIZER, RDX: DECODED})
        self.expect(self.read(OUT) == STATUS_OK, "serializer status after decode")
        return ("ok", self.data(self.read(WRITER + 8), self.read(WRITER + 16)).hex())

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


def mp_uint(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return bytes([0xCC, value])
    if value < 0x10000:
        return b"\xcd" + value.to_bytes(2, "big")
    if value < 0x100000000:
        return b"\xce" + value.to_bytes(4, "big")
    return b"\xcf" + value.to_bytes(8, "big")


def mp_str(text):
    data = text.encode()
    if len(data) < 32:
        return bytes([0xA0 | len(data)]) + data
    if len(data) < 256:
        return bytes([0xD9, len(data)]) + data
    return b"\xda" + len(data).to_bytes(2, "big") + data


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
        h.write(B + offset + 0x10, len(name))
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
    """A struct: a map under the named flag, an array without it."""

    def __init__(self, *rows):
        self.rows = rows


class Fixed:
    """Always a map, named or not."""

    def __init__(self, *rows):
        self.rows = rows


class Bits:
    def __init__(self, word):
        self.word = word


def mp_head(size, small, wide16, wide32):
    if size < 16:
        return bytes([small | size])
    if size < 0x10000:
        return bytes([wide16]) + size.to_bytes(2, "big")
    return bytes([wide32]) + size.to_bytes(4, "big")


def pack(item, named):
    if item is None:
        return b"\xc0"
    if item is True or item is False:
        return b"\xc3" if item else b"\xc2"
    if isinstance(item, int):
        return mp_uint(item)
    if isinstance(item, str):
        return mp_str(item)
    if isinstance(item, Bits):
        return b"\xcb" + item.word.to_bytes(8, "big")
    if isinstance(item, Fixed):
        return mp_head(len(item.rows), 0x80, 0xDE, 0xDF) + b"".join(pack(key, named) + pack(value, named) for key, value in item.rows)
    if isinstance(item, Pairs):
        if named:
            return mp_head(len(item.rows), 0x80, 0xDE, 0xDF) + b"".join(mp_str(key) + pack(value, named) for key, value in item.rows)
        return mp_head(len(item.rows), 0x90, 0xDC, 0xDD) + b"".join(pack(value, named) for _, value in item.rows)
    return mp_head(len(item), 0x90, 0xDC, 0xDD) + b"".join(pack(value, named) for value in item)


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
        ("withdrawal_signatures", Pairs(("name", state.names[1]), ("hsc", []), ("i", [[un_shape(row.key), tracker_shape(row, "sign")] for row in state.sig]))),
        ("withdrawal_finalized_votes", Pairs(("name", state.names[2]), ("hsc", []), ("i", [[un_shape(row.key), tracker_shape(row, "final")] for row in state.fin]))),
        ("finished_withdrawal_to_time", [[un_shape(key), time_shape(moment)] for key, moment in state.times]),
        ("validator_set_signatures", Pairs(("name", state.names[3]), ("hsc", []), ("i", [[row.key, tracker_shape(row, "set")] for row in state.vs]))),
        ("validator_set_finalized_votes", Pairs(("name", state.names[4]), ("hsc", []), ("i", [[row.key, tracker_shape(row, "setfinal")] for row in state.vf]))),
        ("bal", state.bal), ("last_pruned_deposit_block_number", state.pruned), ("oaw", bool(state.oaw)))


NO_VOTER_TEXT = "attempted to instantiate uninhabited type `hard_quorum_policy::NoVoter`"


def spec_run(case):
    if isinstance(case, De):
        return case.want
    state = case.state
    if any(hvs == "novoter" for rows in (state.sig, state.fin, state.vs, state.vf) for row in rows for *_, hvs in row.inner):
        return ("panic", NO_VOTER_TEXT)
    return ("bytes", ((mp_str("bridge2") if case.named else b"") + pack(bridge_shape(state), case.named)).hex())


class Case:
    def __init__(self, name, state, named=1, mode=0, capacity=0x4000):
        self.name, self.state, self.named, self.mode, self.capacity = name, state, named, mode, capacity


def run_case(harness, case):
    return harness.decode(case) if isinstance(case, De) else harness.serialize(case)


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


def named_cases():
    out = []

    def add(name, state, modes=(0,), capacity=0x4000):
        for named in (1, 0):
            for mode in modes:
                out.append(Case("%s_%s_m%d" % (name, "named" if named else "array", mode), state, named, mode, capacity))
    add("empty", State())
    add("full", full_state(), (0, 1, 2))
    add("full_tiny_writer", full_state(), (0,), 1)
    add("empty_tiny_writer", State(), (0,), 1)
    for word in (0, 1, 0x3FF0000000000000, 0x7FF8000000000000, 0xFFF0000000000000, 0x8000000000000000):
        add("hsc_q_%x" % word, State(q=word))
        add("hsc_i_%x" % word, State(i=word))
    for value in (0, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFFFFFF):
        add("bal_%x" % value, State(bal=value))
        add("pruned_%x" % value, State(pruned=value))
    add("oaw_false", State(oaw=0))
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
    draw = Draw(b"bridge2 state wire")
    return [Case("vector_%d" % index, draw.state(), draw.below(2), (0, 1, 2)[draw.below(3)], 0x8000) for index in range(count)]


REQUIRED = ("eth_id_to_deposit_votes", "withdrawal_signatures", "withdrawal_finalized_votes", "validator_set_signatures", "validator_set_finalized_votes")
FIELD_ORDER = ("eth_id_to_deposit_votes", "finished_deposits_data", "withdrawal_signatures", "withdrawal_finalized_votes", "finished_withdrawal_to_time", "validator_set_signatures", "validator_set_finalized_votes", "bal", "last_pruned_deposit_block_number", "oaw")
MIN_ARRAY = 7
ARRAY_TEXT = "invalid length %d, expected struct Bridge2 with 10 elements"
TYPE_TEXT = "invalid type: %s, expected struct Bridge2"
HEX_HEAD = "invalid length %d, expected a (both 0x-prefixed or not) hex string or byte array containing %d bytes"


class De:
    def __init__(self, name, data, want, entry=DECODE_ROOT):
        self.name, self.data, self.want, self.entry = name, data, want, entry


def row_keys(kind):
    if kind == "deposit":
        return lambda key: key
    return lambda key: (key[0], key[1])


def order_id(key):
    return key


def canon_deposit(row):
    inner = {}
    for (usd, user), vks, hvs in row.inner:
        inner[(usd, user)] = (sorted(set(vks)), sorted(set(hvs)))
    return Row(row.key, row.arq, row.status, [((usd, user), value[0], value[1]) for (usd, user), value in sorted(inner.items(), key=lambda item: (item[0][1], item[0][0]))])


def canon_sign(row):
    inner = {}
    for (usd, user), vks, hvs in row.inner:
        inner[(usd, user)] = sorted(dict(vks).items())
    return Row(row.key, row.arq, row.status, [((usd, user), value, []) for (usd, user), value in sorted(inner.items(), key=lambda item: (item[0][1], item[0][0]))])


def canon_final(row):
    inner = {}
    for digest, vks, hvs in row.inner:
        inner[digest] = sorted(set(vks))
    return Row(row.key, row.arq, row.status, [(digest, value, []) for digest, value in sorted(inner.items())])


def canon_set(row, signed):
    rows = []
    for vks, hvs in row.inner[-1:]:
        rows.append(((sorted(dict(vks).items()) if signed else sorted(set(vks))), []))
    return Row(row.key, row.arq, row.status, rows)


def last_wins(rows, key):
    table = {}
    for row in rows:
        table[key(row)] = row
    return [table[item] for item in sorted(table)]


def canon(state):
    """What a real decode keeps: every map sorted by its key type, last row of a key wins."""
    out = State(names=state.names, q=state.q, i=state.i, bal=state.bal, pruned=state.pruned, oaw=state.oaw)
    out.dep = last_wins([canon_deposit(row) for row in state.dep], lambda row: id_order(row.key))
    out.sig = last_wins([canon_sign(row) for row in state.sig], lambda row: un_order(row.key))
    out.fin = last_wins([canon_final(row) for row in state.fin], lambda row: un_order(row.key))
    out.vs = last_wins([canon_set(row, True) for row in state.vs], lambda row: row.key)
    out.vf = last_wins([canon_set(row, False) for row in state.vf], lambda row: row.key)
    out.finished = last_wins(state.finished, lambda row: id_order(row[0]))
    out.times = last_wins(state.times, lambda row: un_order(row[0]))
    return out


def id_order(key):
    return key


def un_order(key):
    return (key[1], key[0])


def bare(state):
    """Fields a decode leaves at their default when absent."""
    return state


def array_of(state):
    return pack(bridge_shape(canon(state)), 0).hex()


def ok(state):
    return ("ok", array_of(state))


def wire(state, named=1, rows=None):
    shape = bridge_shape(state)
    return pack(Pairs(*(shape.rows if rows is None else rows)), named)


def field_rows(state):
    return list(bridge_shape(state).rows)


def without(state, drop):
    out = State(names=state.names, q=state.q, i=state.i, dep=state.dep, sig=state.sig, fin=state.fin, vs=state.vs, vf=state.vf, finished=state.finished, times=state.times, bal=state.bal, pruned=state.pruned, oaw=state.oaw)
    if drop == "finished_deposits_data":
        out.finished = ()
    elif drop == "finished_withdrawal_to_time":
        out.times = ()
    elif drop == "bal":
        out.bal = 0
    elif drop == "last_pruned_deposit_block_number":
        out.pruned = 0
    elif drop == "oaw":
        out.oaw = 0
    return out


def tracker_edit(rows, field, edit):
    return [(key, edit(value) if key == field else value) for key, value in rows]


def edit_pairs(value, **changes):
    return Pairs(*[(key, changes.get(key, item)) for key, item in value.rows if changes.get(key, item) is not DROP])


DROP = object()
HSC_DEFAULT = State()


def tracker_cases(base):
    rows = field_rows(base)
    deposit = dict(rows)["eth_id_to_deposit_votes"]
    signs = dict(rows)["withdrawal_signatures"]
    row = dict(deposit.rows)["i"][0]
    ident, votes = row
    cases = []

    def dep(name, value, want):
        cases.append(De(name, pack(Pairs(*tracker_edit(rows, "eth_id_to_deposit_votes", lambda _: value)), 1), want))

    def sgn(name, value, want):
        cases.append(De(name, pack(Pairs(*tracker_edit(rows, "withdrawal_signatures", lambda _: value)), 1), want))

    def fail(text):
        return ("error", 6, text)

    def same(**changes):
        state = State(names=base.names, q=base.q, i=base.i, dep=base.dep, sig=base.sig, fin=base.fin, vs=base.vs, vf=base.vf, finished=base.finished, times=base.times, bal=base.bal, pruned=base.pruned, oaw=base.oaw)
        for key, value in changes.items():
            setattr(state, key, value)
        return state

    def row_with(ident_item, votes_item):
        return edit_pairs(deposit, i=[[ident_item, votes_item]])

    dep("tracker_drop_name", edit_pairs(deposit, name=DROP), fail("missing field `name`"))
    dep("tracker_drop_i", edit_pairs(deposit, i=DROP), fail("missing field `i`"))
    dep("tracker_drop_hsc_keeps_zero_policy", edit_pairs(deposit, hsc=DROP), ok(same(q=0, i=0)))
    dep("tracker_hsc_array", edit_pairs(deposit, hsc=[Bits(1), Bits(2)]), ok(same(q=1, i=2)))
    dep("tracker_hsc_q_only", edit_pairs(deposit, hsc=Pairs(("q", Bits(1)))), fail("missing field `i`"))
    dep("tracker_rows_as_a_map", edit_pairs(deposit, i=Fixed((ident, votes))), ok(base))
    dep("tracker_rows_string", edit_pairs(deposit, i="x"), fail('invalid type: string "x", expected a map or a sequence of tuples'))
    dep("tracker_row_of_three", edit_pairs(deposit, i=[[ident, votes, 1]]), ("error", 4, "length 2"))
    dep("tracker_row_of_one", edit_pairs(deposit, i=[[ident]]), fail("invalid length 1, expected a tuple of size 2"))
    sgn("noop_policy_map", edit_pairs(signs, hsc=Pairs()), fail("invalid type: map, expected unit struct NoopHardQuorumPolicy"))
    sgn("noop_policy_sequence", edit_pairs(signs, hsc=[1]), fail("invalid type: sequence, expected unit struct NoopHardQuorumPolicy"))
    sgn("noop_policy_nil", edit_pairs(signs, hsc=None), ok(base))
    sgn("noop_policy_absent", edit_pairs(signs, hsc=DROP), ok(base))
    dep("event_unknown", row_with(edit_pairs(ident, e="Nope"), votes), fail("unknown variant `Nope`, expected one of " + ", ".join("`%s`" % name for name in EVENTS)))
    dep("hash_two_digits", row_with(edit_pairs(ident, h="0x12"), votes), fail(HEX_HEAD % (2, 32)))
    dep("hash_odd_digits", row_with(edit_pairs(ident, h="0x" + "a" * 63), votes), fail(HEX_HEAD % (63, 32)))
    dep("hash_bad_digit", row_with(edit_pairs(ident, h="0x" + "z" * 64), votes), fail("invalid hex character: z, at 2"))
    good = EVENT_ID[4].hex()
    dep("hash_without_prefix", row_with(edit_pairs(ident, h=good), votes), ok(base))
    dep("hash_upper_case", row_with(edit_pairs(ident, h="0x" + good.upper()), votes), ok(base))
    dep("event_id_drop_e", row_with(edit_pairs(ident, e=DROP), votes), fail("missing field `e`"))
    dep("status_unknown", row_with(ident, edit_pairs(votes, qst="Z")), fail("unknown variant `Z`, expected `Q` or `N`"))
    dep("status_q_nil", row_with(ident, edit_pairs(votes, qst=Fixed(("Q", None)))), fail("invalid type: unit value, expected struct UserAndUsd"))
    no_status = [Row(item.key, item.arq, None, item.inner) for item in base.dep]
    dep("status_n_as_map", row_with(ident, edit_pairs(votes, qst=Fixed(("N", None)))), ok(same(dep=no_status)))
    dep("status_absent_is_n", row_with(ident, edit_pairs(votes, qst=DROP)), ok(same(dep=no_status)))
    dep("tracker_drop_arq", row_with(ident, edit_pairs(votes, arq=DROP)), fail("missing field `arq`"))
    dep("tracker_drop_vts", row_with(ident, edit_pairs(votes, vts=DROP)), fail("missing field `vts`"))
    dep("tracker_arq_int", row_with(ident, edit_pairs(votes, arq=1)), fail("invalid type: integer `1`, expected a boolean"))
    times = lambda value: pack(Pairs(*tracker_edit(rows, "finished_withdrawal_to_time", lambda _: [[un_shape((55, USER)), value]])), 1)
    for name, text, want in (("time_word", "nope", "input contains invalid characters"), ("time_zone_mark", "2023-11-14T22:13:20Z", "trailing input"), ("time_date_only", "2023-11-14", "premature end of input"), ("time_no_seconds", "2023-11-14T22:13", "premature end of input"), ("time_space", "2023-11-14 22:13:20", "input contains invalid characters")):
        cases.append(De(name, times(text), fail(want)))
    cases.append(De("time_integer", times(5), fail("invalid type: integer `5`, expected a formatted date and time string")))
    cases.append(De("time_without_fraction", times("2023-11-14T22:13:20"), ok(same(times=[((55, USER), (2023, 318, 80000, 0))]))))
    cases.append(De("time_leap_fraction", times("2023-11-14T22:13:59.5"), ok(same(times=[((55, USER), (2023, 318, 79999 + 40, 500000000))]))))
    return cases


def decoder_cases():
    base = full_state()
    rows = field_rows(base)
    cases = [De("round_named", wire(base), ok(base)), De("round_array", wire(base, 0), ok(base)), De("empty_state_named", wire(State()), ok(State())), De("empty_state_array", wire(State(), 0), ok(State()))]
    for index, (key, _) in enumerate(rows):
        rest = rows[:index] + rows[index + 1:]
        want = ("error", 6, "missing field `%s`" % key) if key in REQUIRED else ok(without(base, key))
        cases.append(De("drop_" + key, pack(Pairs(*rest), 1), want))
        cases.append(De("duplicate_" + key, pack(Pairs(*(rows + [rows[index]])), 1), ("error", 6, "duplicate field `%s`" % key)))
    cases.append(De("keys_reversed", pack(Pairs(*rows[::-1]), 1), ok(base)))
    cases.append(De("unknown_key_skipped", pack(Pairs(*(rows[:3] + [("zz", 5)] + rows[3:])), 1), ok(base)))
    cases.append(De("unknown_key_with_nested_value", pack(Pairs(*(rows[:3] + [("zz", [1, "x", None, [Bits(0)]])] + rows[3:])), 1), ok(base)))
    cases.append(De("index_keys", mp_head(10, 0x80, 0xDE, 0xDF) + b"".join(bytes([index]) + pack(value, 1) for index, (_, value) in enumerate(rows)), ok(base)))
    cases.append(De("index_key_10_skipped", mp_head(11, 0x80, 0xDE, 0xDF) + b"".join(bytes([index]) + pack(value, 1) for index, (_, value) in enumerate(rows)) + b"\x0a\x05", ok(base)))
    for size in range(0, 11):
        short = pack(Pairs(*rows[:size]), 0)
        if size < MIN_ARRAY:
            want = ("error", 6, ARRAY_TEXT % next(index for index in range(size, 10) if FIELD_ORDER[index] in REQUIRED))
        else:
            state = base
            for key, _ in rows[size:]:
                state = without(state, key)
            want = ok(state)
        cases.append(De("array_of_%d" % size, short, want))
    cases.append(De("array_of_11", pack(Pairs(*(rows + [("zz", 5)])), 0), ("error", 4, "length 10")))
    cases.append(De("empty_map", b"\x80", ("error", 6, "missing field `eth_id_to_deposit_votes`")))
    for name, data, text in (("nil", b"\xc0", "unit value"), ("integer", b"\x05", "integer `5`"), ("string", b"\xa1a", 'string "a"'), ("bytes", b"\xc4\x01a", "byte array")):
        cases.append(De("top_" + name, data, ("error", 6, TYPE_TEXT % text)))
    cases.append(De("no_input", b"", ("error", 0, "")))
    cases.append(De("truncated_input", wire(base)[:100], ("error", 1, "")))
    return cases + tracker_cases(base)


def sort_cases():
    key_a, key_b, key_c = (5, 9, 0, 1, DIGEST), (6, 1, 0, 1, DIGEST), (5, 10, 0, 1, DIGEST)
    out = []

    def add(name, state):
        out.append(De(name, wire(state), ok(state)))
    add("sort_deposit_rows", State(dep=[deposit_row(key_b), deposit_row(key_c), deposit_row(key_a)]))
    add("sort_deposit_rows_i_field", State(dep=[deposit_row((1, 1, 0, 9, DIGEST)), deposit_row((1, 1, 0, 2, DIGEST))]))
    add("sort_deposit_rows_event", State(dep=[deposit_row((1, 1, 3, 1, DIGEST)), deposit_row((1, 1, 2, 2, DIGEST)), deposit_row((1, 1, 4, 0, DIGEST))]))
    add("sort_deposit_rows_hash", State(dep=[deposit_row((1, 1, 0, 1, blob(9, 32))), deposit_row((1, 1, 0, 1, blob(3, 32)))]))
    add("sort_finished", State(finished=[(key_b, 1, MOMENT, USER), (key_a, 2, MOMENT, USER)]))
    add("sort_sign_nonce", State(sig=[sign_row(9), sign_row(2)]))
    add("sort_sign_user", State(sig=[Row((1, OTHER), 1, None, []), Row((9, USER), 1, None, []), Row((3, OTHER), 1, None, [])]))
    add("sort_final", State(fin=[final_row(9), final_row(2)]))
    add("sort_times", State(times=[((9, USER), MOMENT), ((2, USER), MOMENT), ((1, OTHER), MOMENT)]))
    add("sort_sets", State(vs=[set_row(9), set_row(2)], vf=[setfinal_row(8), setfinal_row(3)]))
    add("sort_votes_amount", State(dep=[deposit_row(inner=[((9, USER), [], []), ((2, USER), [], []), ((5, OTHER), [], [])])]))
    add("sort_voters", State(dep=[deposit_row(inner=[((1, USER), [VOTER2, VOTER], [HOT, OTHER])])]))
    add("sort_sign_votes", State(sig=[sign_row(inner=[((9, USER), [(VOTER2, SIG), (VOTER, SIG)], []), ((2, USER), [], [])])]))
    add("sort_final_hashes", State(fin=[final_row(inner=[(blob(9, 32), [], []), (blob(3, 32), [], [])])]))
    twice = ("error", 6, "duplicate key")
    out.append(De("repeat_deposit_key", wire(State(dep=[deposit_row(key_a, arq=1), deposit_row(key_a, arq=0, status=None)])), twice))
    out.append(De("repeat_finished_key", wire(State(finished=[(key_a, 1, MOMENT, USER), (key_a, 2, MOMENT, USER)])), twice))
    out.append(De("repeat_sign_key", wire(State(sig=[sign_row(1), sign_row(1)])), twice))
    out.append(De("repeat_final_key", wire(State(fin=[final_row(1), final_row(1)])), twice))
    out.append(De("repeat_set_key", wire(State(vs=[set_row(1), set_row(1)])), twice))
    out.append(De("repeat_setfinal_key", wire(State(vf=[setfinal_row(1), setfinal_row(1)])), twice))
    out.append(De("repeat_time_key", wire(State(times=[((1, USER), MOMENT), ((1, USER), MOMENT)])), twice))
    out.append(De("repeat_vote_key", wire(State(dep=[deposit_row(inner=[((1, USER), [], []), ((1, USER), [], [])])])), twice))
    out.append(De("repeat_voter", wire(State(dep=[deposit_row(inner=[((1, USER), [VOTER, VOTER], [])])])), twice))
    out.append(De("repeat_hot_voter", wire(State(dep=[deposit_row(inner=[((1, USER), [], [HOT, HOT])])])), twice))
    out.append(De("repeat_sign_vote", wire(State(sig=[sign_row(inner=[((1, USER), [(VOTER, SIG), (VOTER, SIG)], [])])])), twice))
    return out


def vector_decoder_cases(count):
    draw = Draw(b"bridge2 state decode")
    out = []
    for index in range(count):
        state = draw.state()
        named = draw.below(2)
        out.append(De("decode_vector_%d" % index, wire(state, named), ok(state)))
    return out


class TextRange:
    """Every code address runs for real."""

    def __contains__(self, va):
        return va < 0x6000000


def real_set(self):
    return TextRange()


def static_view(self):
    if self.static_map is None:
        table = dict(self.relative())
        for slot in (SLOT_ALLOC, SLOT_FREE, SLOT_MEMCPY, SLOT_MEMMOVE, SLOT_MEMCMP, SLOT_BCMP, SLOT_REALLOC, SLOT_NO_INSTANCE) + STOP_SLOTS:
            table[slot] = MARK_BASE + slot
        self.static_map = table
    return self.static_map


Image.real_set = real_set
Image.static_view = static_view
Image.static_map = None


NAMES = {ROOT_RMP: "bridge2_field_and_struct", 0x393F5A0: "deposit_tracker", 0x3C00730: "hsc_q_i", 0x3940860: "withdrawal_signature_tracker", 0x393E700: "withdrawal_finalize_tracker", 0x393FC50: "set_signature_tracker", 0x393E290: "set_finalize_tracker",
         0x393C1B0: "deposit_vote_row", 0x393D780: "signature_vote_row", 0x3938210: "finalize_vote_row", 0x3939D80: "set_signature_vote_row", 0x393C4C0: "set_finalize_vote_row", 0x3936090: "plain_votes_vks_hvs", 0x3935F60: "signed_votes_vks_hvs", 0x3936B40: "third_votes_vks_hvs",
         0x374C850: "user_and_usd", 0x374DE60: "destination_and_usd", 0x374CD50: "user_and_nonce", 0x374D6B0: "finished_deposit_u_s_t", 0x3796A10: "oaw_field", 0x3794530: "bal_field", 0x3798180: "pruned_field", 0x3795C20: "set_signature_field", 0x3794C30: "set_finalize_field", 0x3246AB0: "status_q_of_unit",
         0x36088D0: "deposit_rows_map", 0x3612740: "finished_map", 0x360B4E0: "signature_rows_map", 0x360A8F0: "finalize_rows_map", 0x360B5B0: "times_map", 0x3611590: "set_rows_map", 0x36135A0: "set_finalize_rows_map", 0x3C00730: "hsc_q_i", DECODE_ROOT: "bridge2_decode_map_and_array"}
TARGETS = tuple(sorted(NAMES))
DECODE_COPIES = (0x2B00840, 0x3DDAD10)
FIELDS = (("eth_id_to_deposit_votes", 0x597D7C, 0x0, 0x393F5A0, "required", "tracker with QuorumHsc q and i"), ("finished_deposits_data", 0x597D93, 0x100, 0x3612740, "absent keeps an empty map", "pairs of EthEventId and u s t"), ("withdrawal_signatures", 0x597DA9, 0x40, 0x3940860, "required", "tracker with NoopHardQuorumPolicy"),
          ("withdrawal_finalized_votes", 0x597DBE, 0x70, 0x393E700, "required", "tracker with NoopHardQuorumPolicy"), ("finished_withdrawal_to_time", 0x597DD8, 0x118, 0x360B5B0, "absent keeps an empty map", "pairs of u n and a time string"), ("validator_set_signatures", 0x597DF3, 0xA0, 0x393FC50, "required", "tracker with NoopHardQuorumPolicy"),
          ("validator_set_finalized_votes", 0x597E0B, 0xD0, 0x393E290, "required", "tracker with NoopHardQuorumPolicy"), ("bal", 0x597E28, 0x130, 0x3794530, "absent keeps 0", "compact u64"), ("last_pruned_deposit_block_number", 0x20C820, 0x138, 0x3798180, "absent keeps 0", "compact u64"), ("oaw", 0x597E2B, 0x140, 0x3796A10, "absent keeps false", "bool"))
TRACKERS = (("eth_id_to_deposit_votes", "q and i, or absent for zero", "EthEventId", "user usd", "user usd", "address 32 bytes then nil", "20 byte address then nil"), ("withdrawal_signatures", "nil or absent", "u n", "destination usd", "destination usd", "32 bytes then r s v", "always empty, NoVoter"),
            ("withdrawal_finalized_votes", "nil or absent", "u n", "32 byte hash", "32 byte hash", "32 bytes then nil", "always empty, NoVoter"), ("validator_set_signatures", "nil or absent", "u64", "nil", "nil", "32 bytes then r s v", "always empty, NoVoter"), ("validator_set_finalized_votes", "nil or absent", "u64", "nil", "nil", "32 bytes then nil", "always empty, NoVoter"))
TEXTS = ((0x57ADA0, NO_VOTER_TEXT), (0x3AF6FE, "struct Bridge2 with 10 elements"), (0x5A8053, "QuorumStatus"))
FIND_TEXTS = ("NoopHardQuorumPolicy", "a map or a sequence of tuples", "UserAndUsd")
KEY_ROWS = ((0x3797BBE, "field head: the key is written only under the named flag", "cmp"), (0x3797BEF, "ten field struct head", "mov"), (0x3797DB0, "bal key text", "lea"), (0x3797DF5, "oaw is read at +0x140", "mov"), (0x3796A5A, "oaw byte joins 0xc2: c2 false, c3 true", "or"), (0x393F610, "name pointer +8", "mov"), (0x393F672, "hsc at +0x18", "lea"), (0x393F6AC, "rows at +0x28", "add"), (0x3C007A3, "q is f64 +0", "movsd"), (0x3C007E1, "i is f64 +8", "movsd"), (0x3940932, "NoopHardQuorumPolicy head", "lea"), (0x3940938, "array of zero fields", "xor"), (0x394096A, "rows at +0x18", "add"), (0x393C226, "arq is byte +0x40", "movzx"), (0x393C2BC, "status word 1 is N", "cmp"), (0x393C3B5, "vts at +0x28", "add"), (0x3938210 + 0, "finalize row entry", "push"))
SAMPLE = 6
MUTANT_CASES = 5
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
    for at, text in TEXTS:
        data = bytes(image.blob[image.offset(at):image.offset(at) + len(text)]).decode()
        if data != text:
            raise EvidenceError("text at %#x is %s" % (at, data))
        rows.append(("%#x" % at, text))
    for text in FIND_TEXTS:
        at = bytes(image.blob).find(text.encode())
        if at < 0:
            raise EvidenceError("no text %s" % text)
        rows.append(("%#x" % at, text))
    return rows


def field_table(image):
    rows = []
    for index, (name, at, offset, writer, rule, form) in enumerate(FIELDS):
        data = bytes(image.blob[image.offset(at):image.offset(at) + len(name)]).decode()
        if data != name:
            raise EvidenceError("field text at %#x is %s" % (at, data))
        rows.append((index, name, "%#x" % at, "%#x" % offset, "%#x" % writer, rule, form))
    return rows


def copy_rows(image, harness, cases):
    rows = []
    for copy in DECODE_COPIES:
        count = 0
        for case in cases:
            twin = De(case.name, case.data, case.want, copy)
            if run_case(harness, twin) != case.want:
                raise EvidenceError("copy %#x differs on %s" % (copy, case.name))
            count += 1
        rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, "%#x" % DECODE_ROOT, count))
    return rows


def samples():
    return [Case("sample_named", full_state(), 1), Case("sample_array", full_state(), 0)]


def analyse(image, mutate=True, vectors=100, decode_vectors=15):
    harness = Harness(image)
    cases = decoder_cases() + sort_cases() + named_cases()
    named = check_all(harness, cases)
    generated = vector_decoder_cases(decode_vectors) + vector_cases(vectors)
    check_all(harness, generated)
    seen = set(harness.machine.seen)
    table = {}
    for target in TARGETS:
        low, high = image.exact_fde(target)
        table[target] = [row_at(image, va) for va in sorted(seen) if low <= va < high]
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    light = [case for case in decoder_cases() if case.want[0] == "error"][:40] + decoder_cases()[:2]
    wire = [(case.name, harness.serialize(case)[1]) for case in samples()]
    result = dict(table=table, named=named, vector_count=len(generated), keys=key_rows(image), texts=text_rows(image), fields=field_table(image), copies=copy_rows(image, harness, light), wire=wire, sizes={target: image.exact_fde(target)[1] - target for target in TARGETS})
    if mutate:
        pool = [case for case in cases if not case.name.endswith(("130_rows_named_m0", "130_rows_array_m0"))]
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
    tsv("fields.tsv", ("index", "name", "text_at", "state_offset", "writer", "decode_rule", "wire_form"), result["fields"])
    tsv("trackers.tsv", ("tracker", "hsc", "row_key", "status_payload", "vote_key", "vks_row", "hvs_row"), TRACKERS)
    tsv("texts.tsv", ("address", "text"), result["texts"])
    tsv("copies.tsv", ("copy", "body_bytes", "same_rules_as", "cases_matched"), result["copies"])
    tsv("wire-samples.tsv", ("case", "bytes"), result["wire"])
    tsv("key-rows.tsv", ("function", "at", "bytes", "operation", "note"), result["keys"])
    rows = []
    for case, trace in result["named"]:
        if trace[0] in ("bytes", "ok"):
            rows.append((case.name, "%s %d bytes sha256 %s" % (trace[0], len(trace[1]) // 2, hashlib.sha256(trace[1].encode()).hexdigest()[:16])))
        else:
            rows.append((case.name, " ".join(str(item) for item in trace)))
    tsv("scenarios.tsv", ("case", "outcome"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    named = result["named"]
    reached = sum(row.size for rows in table.values() for row in rows)
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(TARGETS), "instructions": sum(len(items) for items in table.values()), "named_scenarios": len(named), "decoder_cases": sum(1 for case, _ in named if isinstance(case, De)), "serializer_cases": sum(1 for case, _ in named if isinstance(case, Case)), "vector_scenarios": result["vector_count"], "body_bytes": sum(sizes.values()), "reached_bytes": reached, "unreached_rows": sum(sizes.values()) - reached, "copies": len(result["copies"])}
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

