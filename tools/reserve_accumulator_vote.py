#!/usr/bin/env python3
"""Pin the node #94 SetReserveAccumulator vote: wire keys, the rebuild of the map at +0x3a00 and the row's two codecs.

Real rows run end to end: the JSON vote reader, the three dispatcher arms with the real map code, the row writers and
readers. A separately written rule list predicts the status, the stored rows and every encoded byte, and every reached
conditional row, immediate and field offset of the subject functions is mutated. No objdump or readelf output is parsed
and the binary is never executed. Standard library only.

    python3 tools/reserve_accumulator_vote.py --out <dir>
"""

import argparse
import bisect
import collections
import datetime
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
STEP_LIMIT = 3000000
MUTANT_STEP_LIMIT = 200000


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
        if two == 0xAB:
            reg, rm = modrm()
            return finish("bts", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("bt", rm, ("r", reg), width)
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
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmpsd", ("x", reg), rm, 8, target=value)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movdr", rm, ("x", reg), 4)
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
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
        if two == 0xA5:
            reg, rm = modrm()
            return finish("shldc", rm, ("r", reg), width)
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
        self.stop = None
        self.frame = 0

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
        self.regs[RSP] -= self.frame
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL and pc != self.stop:
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
        if pc == self.stop:
            return None
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
            count = self.regs[row.b[1]] if row.b[0] == "r" else row.b[1]
            self.cf = bool(self.get(row.a, width) >> (count & (8 * width - 1)) & 1)
        elif op == "bts":
            count = self.regs[row.b[1]] & (8 * width - 1)
            value = self.get(row.a, width)
            self.cf = bool(value >> count & 1)
            self.put(row.a, width, value | 1 << count)
        elif op == "movsx":
            size = row.cc
            value = self.get(row.b, size)
            self.put(row.a, width, value - (1 << (8 * size)) if value & SIGN[size] else value)
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
            self.zf = source == 0
            if source:
                self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd", "shrdi", "shldc"):
            bits = 8 * width
            count = (self.regs[RCX] if op in ("shrd", "shldc") else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op in ("shld", "shldc"):
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
        elif op == "rol":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) if count else value)
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
        elif op == "cmpsd":
            if row.target != 2:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left <= right else 0)
        elif op == "movdr":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
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


OK = 0x186
TOP = MASK[8]
TAG_NUMBER = 0x13F
TAG_LENGTH = 0x143
TAG_TEXT = 0xDF
TAG_BAD_TEXT = 0xAC
CAP = 0x0CCCCCCCCCCCCCCC
SCALE_CUT = 0x68DB8BAC710CB
ROW_LIMIT = 0x28F5C28F5C28F5B
TEXT_LIMIT = 100
WORD = 61
WINDOW_FLOOR = 10.0
NATIVE_TEXT = b"native token is not set"
TOKEN_STRIDE = 0xE8
ROW_SIZE = 0x48
LEAF = 0x380
INNER = 0x3E0
TREE_AT = 0x3A00
SHIFT_C = 0xA80
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
ONCE_STATE = 0x577AB98
SLOT_SET = 0x576E1F8
SLOT_PARSE = 0x5773328
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150)
RESUME = 0x5660110
MARK_BASE = 0x7700000000
ARMS = 98
FILL_END = 0x9000
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))
OUT = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x200
DE = HEAP_BASE + 0x400
SEQ = HEAP_BASE + 0x500
SER = HEAP_BASE + 0x580
VEC = HEAP_BASE + 0x600
INDENT = HEAP_BASE + 0x640
ROW = HEAP_BASE + 0x700
S = HEAP_BASE + 0x1000
TOKENS = HEAP_BASE + 0x6000
SPOTS = HEAP_BASE + 0x7000
TEXT = HEAP_BASE + 0x7800
SINK = HEAP_BASE + 0x8000
BUMP = HEAP_BASE + 0x9000
BUMP_END = HEAP_BASE + 0x3F000
OLD_MARK = 0x5A


class Copy:
    def __init__(self, name, arm, table, shift):
        self.name, self.arm, self.table, self.shift = name, arm, table, shift

    def entry(self, image):
        """The dispatcher that holds this copy's arm; the arm comes from the copy's jump table."""
        at = image.offset(self.table + 4 * (WORD - 18))
        return image.fde(self.table + struct.unpack_from("<i", image.blob, at)[0])[0]


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, len_at, edge_at, index_at, parent_at):
        self.key_at, self.key_size, self.val_at, self.val_size = key_at, key_size, val_at, val_size
        self.len_at, self.edge_at, self.index_at, self.parent_at = len_at, edge_at, index_at, parent_at


L_ROW = Layout(8, 8, 0x60, ROW_SIZE, 0x37A, 0x380, 0x378, 0)
COPIES = (Copy("a", 0x2356317, 0x3DD1B8, 0), Copy("b", None, 0x711064, 0), Copy("c", None, 0x711244, SHIFT_C))
VOTE_READ = (0x1BC1470, 0x306AFA0)
ROW_READ = (0x1C2C470, 0x3102F10)
PAIR_READ = (0x1B80AC0, 0x3041730)
FIELD_ID = (0x33264E0, 0x1E73830, 0x42C6180)
RMP_GENERAL = (0x333A810, 0x1E84190, 0x42E2170)
RMP_DIRECT = (0x333A9E0, 0x1E83E20, 0x42E1E00)
JSON_ROW = (0x333AD50, 0x1E84360, 0x42E2340)
MAP_JSON = 0x3C3DA20
CLEAR = 0x333A6D0
CLONE = 0x254E740
SUBJECTS = (CLEAR, CLONE, MAP_JSON) + VOTE_READ + ROW_READ + PAIR_READ + FIELD_ID + RMP_GENERAL + RMP_DIRECT + JSON_ROW
MUTATED = (CLEAR, CLONE, MAP_JSON, VOTE_READ[0], ROW_READ[0], PAIR_READ[0], FIELD_ID[0], RMP_GENERAL[0], RMP_DIRECT[0], JSON_ROW[0])
NAMES = {CLEAR: "clear_map", CLONE: "clone_word_list", MAP_JSON: "map_json_writer"}
for _prefix, _family in (("vote_json_reader", VOTE_READ), ("row_json_reader", ROW_READ), ("pair_json_reader", PAIR_READ), ("row_field_id", FIELD_ID), ("row_rmp_writer", RMP_GENERAL), ("row_rmp_direct_writer", RMP_DIRECT), ("row_json_writer", JSON_ROW)):
    for _index, _target in enumerate(_family):
        NAMES[_target] = "%s_%d" % (_prefix, _index)
FIELD_NAMES = ((b"spot", 0), (b"order_ntl", 1), (b"max_px", 2), (b"ema", 3))
SERDE = (b"struct variant VoteGlobalAction::SetReserveAccumulator with 3 elements", b"struct ReserveAccumulator with 4 elements", b"tuple struct ReserveAccumulators", b"struct DeterministicEma with 5 elements", b"reserve_accumulators")


def bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def stored_amount(order_ntl):
    """The reserved word of the row, or None when the constructor gives no row."""
    value = order_ntl if order_ntl > SCALE_CUT else order_ntl * 100
    value = value // 100 * 100
    return None if value > ROW_LIMIT else value


def window_of(decay):
    """maxsd with 10.0 as destination: the wire value wins on a tie and on NaN."""
    return WINDOW_FLOOR if WINDOW_FLOOR > decay else decay


def rust_float(value):
    """ryu text as serde_json prints it; the non-finite values are null there."""
    if value != value or value in (math.inf, -math.inf):
        return "null"
    text = repr(value)
    if "e" in text:
        mantissa, exponent = text.split("e")
        if int(exponent) == -5:
            sign, digits = ("-", mantissa[1:]) if mantissa[0] == "-" else ("", mantissa)
            return "%s0.0000%s" % (sign, digits.replace(".", ""))
        return "%se%d" % (mantissa, int(exponent))
    return text


def object_bytes(tag):
    return struct.pack("<H", tag) + bytes((0x41 + index) & 0xFF for index in range(2, 0x60))


class Time:
    def __init__(self, date, seconds, nanos):
        self.date, self.seconds, self.nanos = date, seconds, nanos

    def text(self):
        day = word_to_date(self.date)
        text = "%04d-%02d-%02dT%02d:%02d:%02d" % (day.year, day.month, day.day, self.seconds // 3600, self.seconds // 60 % 60, self.seconds % 60)
        if self.nanos % 1000000 == 0 and self.nanos:
            return text + ".%03d" % (self.nanos // 1000000)
        if self.nanos % 1000 == 0 and self.nanos:
            return text + ".%06d" % (self.nanos // 1000)
        return text + (".%09d" % self.nanos if self.nanos else "")


class Row:
    DEFAULTS = dict(num=0.0, denom=0.0, decay=30.0, samples=0, time=None, spot=0, amount=0, max_px=1.0)

    def __init__(self, **fields):
        for key, value in self.DEFAULTS.items():
            setattr(self, key, fields.pop(key, value))
        if fields:
            raise EvidenceError("unknown row field %s" % sorted(fields))

    def bytes(self):
        date, seconds, nanos = (self.time.date, self.time.seconds, self.time.nanos) if self.time else (0, 0, 0)
        return struct.pack("<dddQIIIIQQd", self.num, self.denom, self.decay, self.samples, date, seconds, nanos, 0, self.spot, self.amount, self.max_px)


def date_word(year, ordinal):
    """chrono's packed date: year, ordinal, and the year flags."""
    first = datetime.date(year, 1, 1).weekday()
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    return year << 13 | ordinal << 4 | _flags(first, leap)


def _flags(weekday, leap):
    """Dominical letter of 1 January: Monday G, Tuesday F, ... Sunday A; a leap year clears bit 3."""
    table = {0: 0o16, 1: 0o17, 2: 0o11, 3: 0o12, 4: 0o13, 5: 0o14, 6: 0o15}
    if leap:
        return {0: 0o06, 1: 0o07, 2: 0o01, 3: 0o02, 4: 0o03, 5: 0o04, 6: 0o05}[weekday]
    return table[weekday]


def word_to_date(word):
    return datetime.date(word >> 13, 1, 1) + datetime.timedelta(days=((word >> 4) & 0x1FF) - 1)


def rmp_str(text):
    return (bytes([0xA0 | len(text)]) if len(text) < 32 else bytes([0xD9, len(text)])) + text


def rmp_uint(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return bytes([0xCC, value])
    if value < 0x10000:
        return b"\xcd" + struct.pack(">H", value)
    if value < 0x100000000:
        return b"\xce" + struct.pack(">I", value)
    return b"\xcf" + struct.pack(">Q", value)


def rmp_float(value):
    return b"\xcb" + struct.pack(">d", value)


def rmp_time(row):
    return b"\xc0" if row.time is None else rmp_str(row.time.text().encode())


def spec_rmp(row, keyed):
    """Keyed is a 4-entry map with field names; plain is a 4-entry array."""
    if keyed:
        ema = b"\x85" + rmp_str(b"num") + rmp_float(row.num) + rmp_str(b"denom") + rmp_float(row.denom) + rmp_str(b"decay_duration") + rmp_float(row.decay)
        ema += rmp_str(b"last_sample_time") + rmp_time(row) + rmp_str(b"n_samples") + rmp_uint(row.samples)
        return b"\x84" + rmp_str(b"spot") + rmp_uint(row.spot) + rmp_str(b"order_ntl") + rmp_uint(row.amount) + rmp_str(b"max_px") + rmp_float(row.max_px) + rmp_str(b"ema") + ema
    ema = b"\x95" + rmp_float(row.num) + rmp_float(row.denom) + rmp_float(row.decay) + rmp_time(row) + rmp_uint(row.samples)
    return b"\x94" + rmp_uint(row.spot) + rmp_uint(row.amount) + rmp_float(row.max_px) + ema


def spec_json(row, depth=0):
    pad = "  " * depth
    time = "null" if row.time is None else '"%s"' % row.time.text()
    ema = ('{\n%s    "num": %s,\n%s    "denom": %s,\n%s    "decay_duration": %s,\n%s    "last_sample_time": %s,\n%s    "n_samples": %d\n%s  }'
           % (pad, rust_float(row.num), pad, rust_float(row.denom), pad, rust_float(row.decay), pad, time, pad, row.samples, pad))
    return ('{\n%s  "spot": %d,\n%s  "order_ntl": %d,\n%s  "max_px": %s,\n%s  "ema": %s\n%s}'
            % (pad, row.spot, pad, row.amount, pad, rust_float(row.max_px), pad, ema, pad)).encode()


def spec_map_json(rows):
    if not rows:
        return b"[]"
    parts = []
    for key, row in rows:
        parts.append(b"  [\n    %d,\n    " % key + spec_json(row, 2) + b"\n  ]")
    return b"[\n" + b",\n".join(parts) + b"\n]"


class Case:
    DEFAULTS = dict(kind="vote", copy=0, text=b"", fn=0, row=None, rows=(), keyed=0, want=None, native=1, native_index=1, tokens=2, spots=(5, 2, 8), old=(), o=7000000, d=b"12.5", m=b"99",
                    d_value=12.5, m_value=99.0, bad=None, real_parser=False, stale=None, cap_d=None, cap_m=None, cap=0x3000, depth=128)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.DEFAULTS:
                raise EvidenceError("unknown case field %s" % key)
            setattr(self, key, value)


class AllCode:
    def __contains__(self, target):
        return 0x1300000 < target < 0x5660000


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        if Harness.statics is None:
            table = dict(image.relative())
            hooks = (SLOT_FREE, SLOT_ALLOC, SLOT_REALLOC, SLOT_COPY, SLOT_MOVE, SLOT_CMP, SLOT_BCMP, SLOT_SET, SLOT_PARSE) + PANIC_SLOTS
            for slot in hooks:
                table[slot] = MARK_BASE + slot
            table[ONCE_STATE] = 0
            Harness.statics = table
        machine.memory.statics = Harness.statics
        for slot, hook in ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set), (SLOT_PARSE, self.on_parse)):
            machine.slots[MARK_BASE + slot] = hook
        for slot in PANIC_SLOTS:
            machine.slots[MARK_BASE + slot] = self.on_panic
        machine.real = AllCode()
        machine.calls = {RESUME: self.on_panic}
        self.case = None
        self.live = {}
        self.events = []
        self.cur = BUMP

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_panic(self, machine):
        raise Panicked("panic path")

    def bump(self, size):
        at = self.cur
        self.cur += (size + 15) & ~15
        self.expect(self.cur <= BUMP_END, "allocator room")
        self.live[at] = size
        return at

    def on_alloc(self, machine):
        machine.regs[RAX] = self.bump(machine.regs[RDI])

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.pop(at, None) == size, "free of a live block with its size")
        self.events.append(("free", size))

    def on_realloc(self, machine):
        old, new = machine.regs[RDI], machine.regs[RSI]
        size = self.live.pop(old, None)
        self.expect(size is not None, "realloc of a live block")
        at = self.bump(new)
        machine.memory.put_bytes(at, machine.memory.bytes_at(old, min(size, new)))
        machine.regs[RAX] = at

    def on_copy(self, machine):
        dst, src, size = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        if size:
            machine.memory.put_bytes(dst, machine.memory.bytes_at(src, size))
        machine.regs[RAX] = dst

    def on_cmp(self, machine):
        one, two = machine.memory.bytes_at(machine.regs[RDI], machine.regs[RDX]), machine.memory.bytes_at(machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = 0 if one == two else 1 if one > two else MASK[8]

    def on_set(self, machine):
        machine.memory.put_bytes(machine.regs[RDI], bytes([machine.regs[RSI] & 0xFF]) * machine.regs[RDX])
        machine.regs[RAX] = machine.regs[RDI]

    def on_parse(self, machine):
        case = self.case
        memory = machine.memory
        out, record = machine.regs[RDI], machine.regs[RSI]
        self.expect(record in (ACTION + 8, ACTION + 0x20), "parse argument is a field of the action")
        which = 0 if record == ACTION + 8 else 1
        self.events.append(("parse", which))
        pointer, size = memory.read(record + 8, 8), memory.read(record + 0x10, 8)
        self.expect(size <= TEXT_LIMIT, "parse length gate ran first")
        text = memory.bytes_at(pointer, size)
        self.expect(text == (case.d, case.m)[which], "parse text")
        if case.bad == which:
            memory.put_bytes(out, object_bytes(TAG_BAD_TEXT))
            return
        memory.write(out, 2, OK)
        memory.write(out + 8, 8, bits((case.d_value, case.m_value)[which]))

    def node(self, items, stale, size):
        memory = self.machine.memory
        layout = L_ROW
        at = self.bump(size)
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
        memory.write(at + layout.parent_at, 8, 0)
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(11):
            memory.write(at + layout.key_at + 8 * slot, 8, stale)
        for slot, (key, value) in enumerate(items):
            memory.write(at + layout.key_at + 8 * slot, 8, key)
            memory.put_bytes(at + layout.val_at + ROW_SIZE * slot, value)
        return at

    def tree(self, items, stale):
        memory = self.machine.memory
        layout = L_ROW
        if not items:
            return 0, 0xFEED, 0
        if len(items) <= 11:
            return self.node(items, stale, LEAF), 0, len(items)
        parts, seps, at = [], [], 0
        while len(items) - at > 11:
            parts.append(items[at:at + 5])
            seps.append(items[at + 5])
            at += 6
        parts.append(items[at:])
        kids = [self.node(part, stale, LEAF) for part in parts]
        root = self.node(seps, stale, INNER)
        for slot, kid in enumerate(kids):
            memory.write(root + layout.edge_at + 8 * slot, 8, kid)
            memory.write(kid + layout.parent_at, 8, root)
            memory.write(kid + layout.index_at, 2, slot)
        return root, 1, len(items)

    def walk(self, root, height):
        memory = self.machine.memory
        layout = L_ROW
        rows, nodes = [], []

        def visit(at, level, parent, index):
            nodes.append(at)
            size = memory.read(at + layout.len_at, 2)
            self.expect(memory.read(at + layout.parent_at, 8) == parent, "parent link")
            if parent:
                self.expect(memory.read(at + layout.index_at, 2) == index, "parent index")
            for slot in range(size + 1):
                if level:
                    visit(memory.read(at + layout.edge_at + 8 * slot, 8), level - 1, at, slot)
                if slot < size:
                    rows.append((memory.read(at + layout.key_at + 8 * slot, 8), memory.bytes_at(at + layout.val_at + ROW_SIZE * slot, ROW_SIZE)))
        if root:
            visit(root, height, 0, 0)
        return rows, nodes

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:FILL_END] = HEAP_FILL
        self.case = case
        self.events = []
        self.live = {}
        self.cur = BUMP
        self.machine.steps_at = self.machine.steps

    def text_block(self, text):
        at = self.bump(max(len(text), 1))
        self.machine.memory.put_bytes(at, text)
        return at

    def reader(self, text):
        memory = self.machine.memory
        memory.put_bytes(TEXT, text)
        memory.write(DE, 8, 0)
        memory.write(DE + 8, 8, 1)
        memory.write(DE + 0x10, 8, 0)
        memory.write(DE + 0x18, 8, TEXT)
        memory.write(DE + 0x20, 8, len(text))
        memory.write(DE + 0x28, 8, 0)
        memory.write(DE + 0x48, 1, self.case.depth)

    def error_of(self, pointer):
        """serde_json boxes (code, line, column); code 0 carries a text and others a number."""
        memory = self.machine.memory
        code, first, second, line, column = (memory.read(pointer + offset, 8) for offset in (0, 8, 0x10, 0x18, 0x20))
        text = memory.bytes_at(first, second) if code == 0 else b""
        return ("error", code, text, line, column)

    def text_at(self, at):
        memory = self.machine.memory
        size = memory.read(at + 8, 8)
        return memory.bytes_at(memory.read(at, 8), size) if size else b""

    def run_field(self, case):
        out = OUT
        memory = self.machine.memory
        memory.put_bytes(TEXT, case.text)
        self.machine.run(case.fn, {RDI: out, RSI: TEXT, RDX: len(case.text)})
        return dict(tag=memory.read(out, 1), id=memory.read(out + 1, 1))

    def run_read_vote(self, case):
        memory = self.machine.memory
        self.reader(case.text)
        self.machine.run(case.fn, {RDI: OUT, RSI: DE})
        word = memory.read(OUT, 8)
        if word != WORD:
            return dict(result=self.error_of(memory.read(OUT + 8, 8)), word=word, depth=None)
        d, m = self.text_at(OUT + 0x10), self.text_at(OUT + 0x28)
        return dict(result=("vote", memory.read(OUT + 0x38, 8), d, m), word=word, depth=memory.read(DE + 0x48, 1))

    def row_text(self, pointer):
        memory = self.machine.memory
        return memory.bytes_at(pointer, ROW_SIZE)

    def run_read_row(self, case):
        memory = self.machine.memory
        self.reader(case.text)
        self.machine.run(case.fn, {RDI: OUT, RSI: DE})
        if memory.read(OUT, 8) != 0:
            return dict(result=self.error_of(memory.read(OUT + 8, 8)), depth=None)
        return dict(result=("row", mask_read(memory.bytes_at(OUT + 8, ROW_SIZE))), depth=memory.read(DE + 0x48, 1))

    def run_read_pairs(self, case):
        memory = self.machine.memory
        self.reader(case.text)
        memory.write(DE + 0x28, 8, 1)
        memory.write(SEQ, 8, DE)
        memory.write(SEQ + 8, 1, 1)
        rows = []
        for _ in range(8):
            self.machine.run(case.fn, {RDI: OUT, RSI: SEQ})
            word = memory.read(OUT, 8)
            if word == 0:
                return dict(result=("end", tuple(rows)), depth=memory.read(DE + 0x48, 1))
            if word != 1:
                return dict(result=self.error_of(memory.read(OUT + 8, 8)), rows=tuple(rows), depth=None)
            rows.append((memory.read(OUT + 0x8, 8), mask_read(memory.bytes_at(OUT + 0x10, ROW_SIZE))))
        raise Halt("pair loop did not end")

    def sink(self):
        memory = self.machine.memory
        memory.write(VEC, 8, self.case.cap)
        memory.write(VEC + 8, 8, self.bump(self.case.cap))
        memory.write(VEC + 0x10, 8, 0)

    def sink_bytes(self):
        memory = self.machine.memory
        self.expect(memory.read(VEC + 0x10, 8) <= memory.read(VEC, 8), "sink length within capacity")
        return memory.bytes_at(memory.read(VEC + 8, 8), memory.read(VEC + 0x10, 8))

    def run_rmp(self, case):
        memory = self.machine.memory
        self.sink()
        memory.put_bytes(ROW, case.row.bytes())
        if case.fn in RMP_GENERAL:
            memory.write(SER, 8, VEC)
            memory.write(SER + 0xB, 1, case.keyed)
            memory.write(SER + 0xC, 1, 2)
            self.machine.run(case.fn, {RDI: OUT, RSI: ROW, RDX: SER})
        else:
            memory.write(VEC + 0x1B, 1, case.keyed)
            self.machine.run(case.fn, {RDI: OUT, RSI: ROW, RDX: VEC})
        return dict(result=self.sink_bytes(), word=memory.read(OUT, 8))

    def json_ser(self):
        memory = self.machine.memory
        self.sink()
        memory.put_bytes(INDENT, b"  ")
        memory.write(SER, 8, VEC)
        memory.write(SER + 8, 8, INDENT)
        memory.write(SER + 0x10, 8, 2)
        memory.write(SER + 0x18, 8, 0)
        memory.write(SER + 0x20, 1, 0)

    def run_json(self, case):
        memory = self.machine.memory
        self.json_ser()
        memory.put_bytes(ROW, case.row.bytes())
        result = self.machine.run(case.fn, {RDI: ROW, RSI: SER})
        return dict(result=self.sink_bytes(), word=result)

    def run_map_json(self, case):
        memory = self.machine.memory
        self.json_ser()
        table = self.bump(max(1, 0x10 * len(case.rows)))
        for index, (key, row) in enumerate(case.rows):
            at = self.bump(0x50)
            memory.write(at, 8, key)
            memory.put_bytes(at + 8, row.bytes())
            memory.write(table + 0x10 * index, 8, at)
            memory.write(table + 0x10 * index + 8, 8, at + 8)
        memory.write(ROW, 8, 0)
        memory.write(ROW + 8, 8, table)
        memory.write(ROW + 0x10, 8, len(case.rows))
        result = self.machine.run(MAP_JSON, {RDI: SER, RSI: ROW})
        return dict(result=self.sink_bytes(), word=result)

    def run_clear(self, case):
        memory = self.machine.memory
        root, height, count = self.tree(case.old, case.stale if case.stale is not None else 3)
        memory.write(S, 8, root)
        memory.write(S + 8, 8, height)
        memory.write(S + 0x10, 8, count)
        self.machine.run(CLEAR, {RDI: S})
        return dict(root=memory.read(S, 8), height=memory.read(S + 8, 8), count=memory.read(S + 0x10, 8), live=len(self.live))

    def run_vote(self, case):
        memory = self.machine.memory
        copy = COPIES[case.copy]
        tree_at = S + TREE_AT + copy.shift
        memory.write(S + 0x80, 8, case.native)
        memory.write(S + 0x88, 8, case.native_index)
        memory.write(S + 0x210, 8, TOKENS)
        memory.write(S + 0x218, 8, case.tokens)
        for index in range(4):
            row = TOKENS + index * TOKEN_STRIDE
            memory.write(row + 0x50, 8, len(case.spots) + 1)
            memory.write(row + 0x58, 8, SPOTS if index == case.native_index else SPOTS + 0x400)
            memory.write(row + 0x60, 8, len(case.spots) if index == case.native_index else 1)
        for index, spot in enumerate(case.spots):
            memory.write(SPOTS + 8 * index, 8, spot)
        memory.write(SPOTS + 0x400, 8, 0x77)
        old = [(key, bytes([OLD_MARK]) * ROW_SIZE) for key in case.old]
        root, height, count = self.tree(old, case.stale if case.stale is not None else 3)
        memory.write(tree_at, 8, root)
        memory.write(tree_at + 8, 8, height)
        memory.write(tree_at + 0x10, 8, count)
        cap_d = len(case.d) if case.cap_d is None else case.cap_d
        cap_m = len(case.m) if case.cap_m is None else case.cap_m
        pointer_d = self.bump(max(cap_d, 1))
        pointer_m = self.bump(max(cap_m, 1))
        if not cap_d:
            self.live.pop(pointer_d)
        if not cap_m:
            self.live.pop(pointer_m)
        memory.put_bytes(pointer_d, case.d)
        memory.put_bytes(pointer_m, case.m)
        memory.write(ACTION, 8, WORD)
        memory.write(ACTION + 8, 8, cap_d)
        memory.write(ACTION + 0x10, 8, pointer_d)
        memory.write(ACTION + 0x18, 8, len(case.d))
        memory.write(ACTION + 0x20, 8, cap_m)
        memory.write(ACTION + 0x28, 8, pointer_m)
        memory.write(ACTION + 0x30, 8, len(case.m))
        memory.write(ACTION + 0x38, 8, case.o)
        before_status = bytes(memory.heap[S - HEAP_BASE:S - HEAP_BASE + 0x5000])
        out = bytes(0)
        panic = None
        try:
            self.machine.run(copy.entry(self.image), {RDI: OUT, RSI: ACTION, RDX: S})
            out = memory.bytes_at(OUT, 0x60)
        except Panicked as stop:
            panic = str(stop)
            return dict(panic=panic)
        new_root, new_height, new_count = memory.read(tree_at, 8), memory.read(tree_at + 8, 8), memory.read(tree_at + 0x10, 8)
        rows, nodes = self.walk(new_root, new_height)
        after = bytearray(memory.heap[S - HEAP_BASE:S - HEAP_BASE + 0x5000])
        at = tree_at - S
        after[at:at + 0x18] = before_status[at:at + 0x18]
        text = memory.bytes_at(struct.unpack_from("<Q", out, 8)[0], len(NATIVE_TEXT)) if struct.unpack_from("<H", out)[0] == TAG_TEXT else b""
        return dict(panic=None, text=text, status=struct.unpack_from("<H", out)[0], word1=struct.unpack_from("<Q", out, 8)[0], word2=struct.unpack_from("<Q", out, 0x10)[0], out=out, rows=tuple((key, mask(value)) for key, value in rows), count=new_count,
                    root=new_root, height=new_height, leftover=tuple(sorted(at for at in self.live if at not in nodes)), state_same=bytes(after) == before_status,
                    parses=tuple(event[1] for event in self.events if event[0] == "parse"))

    def run_end(self, case):
        """The real JSON reader, then the real dispatcher on its record, with the real text parser."""
        memory = self.machine.memory
        statics = self.machine.memory.statics
        self.reader(case.text)
        self.machine.run(VOTE_READ[case.copy % 2], {RDI: OUT, RSI: DE})
        self.expect(memory.read(OUT, 8) == WORD, "reader gave the vote record")
        memory.put_bytes(ACTION, memory.bytes_at(OUT, 0x40))
        copy = COPIES[case.copy]
        tree_at = S + TREE_AT + copy.shift
        memory.write(S + 0x80, 8, 1)
        memory.write(S + 0x88, 8, 1)
        memory.write(S + 0x210, 8, TOKENS)
        memory.write(S + 0x218, 8, 2)
        row = TOKENS + TOKEN_STRIDE
        memory.write(row + 0x50, 8, 2)
        memory.write(row + 0x58, 8, SPOTS)
        memory.write(row + 0x60, 8, len(case.spots))
        for index, spot in enumerate(case.spots):
            memory.write(SPOTS + 8 * index, 8, spot)
        memory.write(tree_at, 8, 0)
        memory.write(tree_at + 0x10, 8, 0)
        old = statics[SLOT_PARSE]
        statics[SLOT_PARSE] = self.image.relative()[SLOT_PARSE]
        try:
            self.machine.run(copy.entry(self.image), {RDI: OUT, RSI: ACTION, RDX: S})
        finally:
            statics[SLOT_PARSE] = old
        status = memory.read(OUT, 2)
        rows, _ = self.walk(memory.read(tree_at, 8), memory.read(tree_at + 8, 8))
        return dict(status=status, word1=memory.read(OUT + 8, 8), rows=tuple((key, mask(value)) for key, value in rows))

    def run(self, case):
        self.fresh(case)
        return getattr(self, "run_" + case.kind)(case)


def mask(value):
    """The twelve bytes behind the time tag word hold whatever the constructor's frame held."""
    return value[:0x24] + bytes(12) + value[0x30:]


def mask_read(value):
    """Reader output: the date word 0 means no time and then the rest of that field is not written."""
    if value[0x20:0x24] == bytes(4):
        return mask(value)
    return value[:0x2C] + bytes(4) + value[0x30:]


def spec_row(spot, order_ntl, decay, max_px):
    return Row(decay=window_of(decay), spot=spot, amount=stored_amount(order_ntl), max_px=max_px).bytes()


def spec_vote(case):
    if not case.native:
        return dict(status=TAG_TEXT, kept=True, text=NATIVE_TEXT)
    if case.native_index >= case.tokens:
        return dict(panic=True)
    if case.o >= CAP:
        return dict(status=TAG_NUMBER, word1=case.o, rows=(), kept=False, parses=())
    spots = case.spots
    if not spots:
        return dict(status=OK, rows=(), parses=(), kept=False)
    if len(case.d) > TEXT_LIMIT:
        return dict(status=TAG_LENGTH, rows=(), parses=(), kept=False)
    if case.bad == 0:
        return dict(status=TAG_BAD_TEXT, rows=(), parses=(0,), kept=False, object=True)
    if len(case.m) > TEXT_LIMIT:
        return dict(status=TAG_LENGTH, rows=(), parses=(0,), kept=False)
    if case.bad == 1:
        return dict(status=TAG_BAD_TEXT, rows=(), parses=(0, 1), kept=False, object=True)
    rows = {}
    if stored_amount(case.o) is not None:
        for spot in spots:
            rows[spot] = mask(spec_row(spot, case.o, case.d_value, case.m_value))
    return dict(status=OK, rows=tuple(sorted(rows.items())), parses=(0, 1) * len(spots), kept=False)


def same_vote(case, got, want):
    if want.get("panic"):
        return got.get("panic") is not None
    if got.get("panic") is not None or got["status"] != want["status"] or not got["state_same"]:
        return False
    if want["kept"]:
        old = tuple((key, mask(bytes([OLD_MARK]) * ROW_SIZE)) for key in case.old)
        return got["rows"] == old and got["text"] == want["text"] and got["count"] == len(old) and not got["leftover"] and not got["parses"]
    if got["leftover"] or got["parses"] != want["parses"] or got["rows"] != want["rows"] or got["count"] != len(want["rows"]):
        return False
    if "word1" in want and got["word1"] != want["word1"]:
        return False
    if want.get("object") and got["out"] != object_bytes(TAG_BAD_TEXT):
        return False
    return bool(want["rows"]) or got["root"] == 0


def spec_for(case):
    if case.kind == "field":
        return dict(tag=9, id=dict(FIELD_NAMES).get(case.text, 4))
    if case.kind == "vote":
        return spec_vote(case)
    if case.kind in ("read_vote", "read_row", "read_pairs"):
        return case.want
    if case.kind == "end":
        return case.want
    if case.kind == "rmp":
        return dict(result=spec_rmp(case.row, case.keyed), word=(1 << 63) + 4)
    if case.kind == "json":
        return dict(result=spec_json(case.row), word=0)
    if case.kind == "map_json":
        return dict(result=spec_map_json(case.rows), word=0)
    if case.kind == "clear":
        return dict(root=0, height=None, count=0, live=0)
    raise EvidenceError("unknown case kind")


def same(case, got, want):
    if case.kind == "vote":
        return same_vote(case, got, want)
    if case.kind == "clear":
        return got["root"] == 0 and got["count"] == 0 and got["live"] == 0
    if case.kind in ("read_vote", "read_row", "read_pairs"):
        return got["result"] == want["result"] and got["depth"] in (None, case.depth)
    if case.kind == "end":
        if want is None:
            return got["status"] != OK and got["rows"] == ()
        return got["status"] == OK and got["rows"] == want["rows"]
    return got == want


J_ROW = b'{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}'
J_TIME = b'{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":"2026-07-19T01:02:03.004","n_samples":5}}'
WIRE_TEXTS = (
    b'{"o":7,"d":"12.5","m":"99"}', b'{"o":7,"m":"99","d":"12.5"}', b'{"d":"12.5","o":7,"m":"99"}', b'{"d":"12.5","m":"99","o":7}', b'{"m":"99","o":7,"d":"12.5"}', b'{"m":"99","d":"12.5","o":7}',
    b'  { "o" : 7 , "d" : "12.5" , "m" : "99" }  ', b'[7,"12.5","99"]', b'[ 7 , "12.5" , "99" ]', b'{"o":0,"d":"","m":""}', b'{"o":18446744073709551615,"d":"a","m":"b"}',
    b'{"o":18446744073709551616,"d":"a","m":"b"}', b'{"o":-1,"d":"a","m":"b"}', b'{"o":1.5,"d":"a","m":"b"}', b'{"o":"7","d":"a","m":"b"}', b'{"o":null,"d":"a","m":"b"}', b'{"o":1,"d":2,"m":"b"}', b'{"o":1,"d":"a","m":2}',
    b'{"o":1,"d":"a"}', b'{"o":1,"m":"b"}', b'{"d":"a","m":"b"}', b'{}', b'{"o":1,"o":2,"d":"a","m":"b"}', b'{"o":1,"d":"a","d":"b","m":"c"}', b'{"o":1,"d":"a","m":"b","m":"c"}',
    b'{"x":[1,2],"o":1,"d":"z","m":"b"}', b'{"order_ntl":3,"decay_duration":"q","max_px":"r","o":1,"d":"z","m":"b"}', b'{"oo":1,"o":1,"d":"z","m":"b"}', b'{"":1,"o":1,"d":"z","m":"b"}', b'{"\\u006f":1,"\\u0064":"z","\\u006d":"b"}',
    b'{"o":1,"d":"a\\nb","m":"\\u0041"}', b'[]', b'[1]', b'[1,"a"]', b'[1,"a","b","c"]', b'"s"', b'1', b'null', b'', b'{', b'{"o"', b'{"o":', b'{"o":1', b'{"o":1,', b'{"o":1,}', b'[1,', b'[1,"a",', b'[1,"a","b"', b'{"o":1 "d":"a"}', b'{"o":1,"d":"a","m":"b"',
) + tuple(text.replace(b"!", junk) for junk in (b"!", b"\x00", b"\x0b") for text in (b'!', b'{!"o":1}', b'{"o"!:1}', b'{"o":!1}', b'{"o":1!}', b'{"o":1,!"d":"a"}', b'[!1]', b'[1!]', b'[1,!"a"]', b'{"d"!:"a"}', b'{"m"!:"a"}', b'{"d":!1}', b'{"m":!1}')) + (
    b'\t{\n"o"\r:\t1\n,\r"d"\n:\t"a"\r,\n"m"\t:\r"b"\n}\t', b'\t[\n1\r,\t"a"\n,\r"b"\t]\n')
ROW_TEXTS = (
    J_ROW, J_TIME, b'[9,1,0.5,[1.0,2.0,3.0,null,4]]', b'{"spot":9}', b'{}', b'[9]', b'[9,1,0.5]', b'[9,1,0.5,[1.0]]', b'[9,1,0.5,[1.0,2.0,3.0,null]]', b'[9,1,0.5,[1.0,2.0,3.0,null,4],5]',
    b'{"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5},"max_px":1,"order_ntl":2,"spot":3}', b'{"spot":9,"spot":8,"order_ntl":1,"max_px":0.25,"ema":[1.0,2.0,3.0,null,4]}',
    b'{"spot":9,"order_ntl":1,"order_ntl":2,"max_px":0.25,"ema":[1.0,2.0,3.0,null,4]}', b'{"spot":9,"order_ntl":1,"max_px":0.25,"max_px":0.5,"ema":[1.0,2.0,3.0,null,4]}',
    b'{"spot":9,"order_ntl":1,"max_px":0.25,"ema":[1.0,2.0,3.0,null,4],"ema":[1.0,2.0,3.0,null,4]}', b'{"spot":9,"order_ntl":1,"max_px":0.25,"ema":[1.0,2.0,3.0,null,4],"extra":[1]}',
    b'{"spot":-1,"order_ntl":1,"max_px":0.25,"ema":[1.0,2.0,3.0,null,4]}', b'{"spot":9,"order_ntl":1,"max_px":"x","ema":[1.0,2.0,3.0,null,4]}', b'{"spot":9,"order_ntl":1,"max_px":7,"ema":[1,2,3,null,4]}',
    b'{"spot":9,"order_ntl":1,"max_px":null,"ema":[1.0,2.0,3.0,null,4]}', b'"s"', b'', b'{', b'[', b'{"spot":9', b'{"spot":9,', b'[9,', b'{"spot" 9}', b'{"spot":9 "order_ntl":1}',
) + tuple(text.replace(b"!", junk) for junk in (b"!", b"\x00", b"\x0b") for text in (b'!', b'{!"spot":1}', b'{"spot"!:1}', b'{"spot":!1}', b'{"spot":1!}', b'{"spot":1,!"max_px":1}', b'[!1]', b'[1!]', b'[1,!1]', b'{"order_ntl"!:1}', b'{"max_px"!:1}', b'{"ema"!:1}', b'{"order_ntl":!1}', b'{"max_px":!1}')) + (
    b'\t{\n"spot"\r:\t9\n,\r"order_ntl"\n:\t1\r,\n"max_px"\t:\r0.5\n,"ema":[1.0,2.0,3.0,null,4]}\t', b'\t[\n9\r,\t1\n,\r0.5\t,[1.0,2.0,3.0,null,4]]\n')
PAIR_TEXTS = (
    b'[]', b'[ ]', b'[[9,' + J_ROW + b']]', b'[[9,' + J_ROW + b'],[2,' + J_ROW + b']]', b'[ [ 9 , ' + J_ROW + b' ] ]', b'[[9,' + J_ROW + b'],]', b'[[9]]', b'[[]]', b'[[9,' + J_ROW + b',1]]', b'[1]', b'[[-1,' + J_ROW + b']]', b'[', b'[[', b'[[9', b'[[9,', b'[[9,' + J_ROW, b'[[9,' + J_ROW + b']', b'[[9,' + J_ROW + b'] [1]]',
) + tuple(text.replace(b"!", junk) for junk in (b"!", b"\x00", b"\x0b") for text in (b'[!]', b'[!1]', b'[[!9]]', b'[[9!]]', b'[[9,!' + J_ROW + b']]', b'[[9,' + J_ROW + b'!]]', b'[[9,' + J_ROW + b']!]', b'[[9,' + J_ROW + b'],![2,' + J_ROW + b']]')) + (
    b'\t[\n[\r9\t,\n' + J_ROW + b'\r]\t,\n[\r2\t,\n' + J_ROW + b'\r]\t]',)
WIRE = {b'': {'result': ('error', 5, b'', 1, 0)},
 b'\x00': {'result': ('error', 10, b'', 1, 1)},
 b'\t[\n1\r,\t"a"\n,\r"b"\t]\n': {'result': ('vote', 1, b'a', b'b')},
 b'\t{\n"o"\r:\t1\n,\r"d"\n:\t"a"\r,\n"m"\t:\r"b"\n}\t': {'result': ('vote', 1, b'a', b'b')},
 b'\x0b': {'result': ('error', 10, b'', 1, 1)},
 b'  { "o" : 7 , "d" : "12.5" , "m" : "99" }  ': {'result': ('vote', 7, b'12.5', b'99')},
 b'!': {'result': ('error', 10, b'', 1, 1)},
 b'"s"': {'result': ('error', 0, b'invalid type: string "s", expected struct variant VoteGlobalAction::SetReserveAccumulator', 1, 3)},
 b'1': {'result': ('error', 0, b'invalid type: integer `1`, expected struct variant VoteGlobalAction::SetReserveAccumulator', 1, 1)},
 b'[\x001]': {'result': ('error', 10, b'', 1, 2)},
 b'[\x0b1]': {'result': ('error', 10, b'', 1, 2)},
 b'[ 7 , "12.5" , "99" ]': {'result': ('vote', 7, b'12.5', b'99')},
 b'[!1]': {'result': ('error', 10, b'', 1, 2)},
 b'[1\x00]': {'result': ('error', 7, b'', 1, 3)},
 b'[1\x0b]': {'result': ('error', 7, b'', 1, 3)},
 b'[1!]': {'result': ('error', 7, b'', 1, 3)},
 b'[1,': {'result': ('error', 5, b'', 1, 3)},
 b'[1,\x00"a"]': {'result': ('error', 10, b'', 1, 4)},
 b'[1,\x0b"a"]': {'result': ('error', 10, b'', 1, 4)},
 b'[1,!"a"]': {'result': ('error', 10, b'', 1, 4)},
 b'[1,"a",': {'result': ('error', 5, b'', 1, 7)},
 b'[1,"a","b"': {'result': ('error', 2, b'', 1, 10)},
 b'[1,"a","b","c"]': {'result': ('error', 22, b'', 1, 12)},
 b'[1,"a"]': {'result': ('error', 0, b'invalid length 2, expected struct variant VoteGlobalAction::SetReserveAccumulator with 3 elements', 1, 7)},
 b'[1]': {'result': ('error', 0, b'invalid length 1, expected struct variant VoteGlobalAction::SetReserveAccumulator with 3 elements', 1, 3)},
 b'[7,"12.5","99"]': {'result': ('vote', 7, b'12.5', b'99')},
 b'[]': {'result': ('error', 0, b'invalid length 0, expected struct variant VoteGlobalAction::SetReserveAccumulator with 3 elements', 1, 2)},
 b'null': {'result': ('error', 0, b'invalid type: null, expected struct variant VoteGlobalAction::SetReserveAccumulator', 1, 4)},
 b'{': {'result': ('error', 3, b'', 1, 1)},
 b'{\x00"o":1}': {'result': ('error', 17, b'', 1, 2)},
 b'{\x0b"o":1}': {'result': ('error', 17, b'', 1, 2)},
 b'{!"o":1}': {'result': ('error', 17, b'', 1, 2)},
 b'{"":1,"o":1,"d":"z","m":"b"}': {'result': ('vote', 1, b'z', b'b')},
 b'{"\\u006f":1,"\\u0064":"z","\\u006d":"b"}': {'result': ('vote', 1, b'z', b'b')},
 b'{"d"\x00:"a"}': {'result': ('error', 6, b'', 1, 5)},
 b'{"d"\x0b:"a"}': {'result': ('error', 6, b'', 1, 5)},
 b'{"d"!:"a"}': {'result': ('error', 6, b'', 1, 5)},
 b'{"d":\x001}': {'result': ('error', 10, b'', 1, 6)},
 b'{"d":\x0b1}': {'result': ('error', 10, b'', 1, 6)},
 b'{"d":!1}': {'result': ('error', 10, b'', 1, 6)},
 b'{"d":"12.5","m":"99","o":7}': {'result': ('vote', 7, b'12.5', b'99')},
 b'{"d":"12.5","o":7,"m":"99"}': {'result': ('vote', 7, b'12.5', b'99')},
 b'{"d":"a","m":"b"}': {'result': ('error', 0, b'missing field `o`', 1, 17)},
 b'{"m"\x00:"a"}': {'result': ('error', 6, b'', 1, 5)},
 b'{"m"\x0b:"a"}': {'result': ('error', 6, b'', 1, 5)},
 b'{"m"!:"a"}': {'result': ('error', 6, b'', 1, 5)},
 b'{"m":\x001}': {'result': ('error', 10, b'', 1, 6)},
 b'{"m":\x0b1}': {'result': ('error', 10, b'', 1, 6)},
 b'{"m":!1}': {'result': ('error', 10, b'', 1, 6)},
 b'{"m":"99","d":"12.5","o":7}': {'result': ('vote', 7, b'12.5', b'99')},
 b'{"m":"99","o":7,"d":"12.5"}': {'result': ('vote', 7, b'12.5', b'99')},
 b'{"o"': {'result': ('error', 3, b'', 1, 4)},
 b'{"o"\x00:1}': {'result': ('error', 6, b'', 1, 5)},
 b'{"o"\x0b:1}': {'result': ('error', 6, b'', 1, 5)},
 b'{"o"!:1}': {'result': ('error', 6, b'', 1, 5)},
 b'{"o":': {'result': ('error', 5, b'', 1, 5)},
 b'{"o":\x001}': {'result': ('error', 10, b'', 1, 6)},
 b'{"o":\x0b1}': {'result': ('error', 10, b'', 1, 6)},
 b'{"o":!1}': {'result': ('error', 10, b'', 1, 6)},
 b'{"o":"7","d":"a","m":"b"}': {'result': ('error', 0, b'invalid type: string "7", expected u64', 1, 8)},
 b'{"o":-1,"d":"a","m":"b"}': {'result': ('error', 0, b'invalid value: integer `-1`, expected u64', 1, 7)},
 b'{"o":0,"d":"","m":""}': {'result': ('vote', 0, b'', b'')},
 b'{"o":1': {'result': ('error', 3, b'', 1, 6)},
 b'{"o":1\x00}': {'result': ('error', 8, b'', 1, 7)},
 b'{"o":1\x0b}': {'result': ('error', 8, b'', 1, 7)},
 b'{"o":1 "d":"a"}': {'result': ('error', 8, b'', 1, 8)},
 b'{"o":1!}': {'result': ('error', 8, b'', 1, 7)},
 b'{"o":1,': {'result': ('error', 5, b'', 1, 7)},
 b'{"o":1,\x00"d":"a"}': {'result': ('error', 17, b'', 1, 8)},
 b'{"o":1,\x0b"d":"a"}': {'result': ('error', 17, b'', 1, 8)},
 b'{"o":1,!"d":"a"}': {'result': ('error', 17, b'', 1, 8)},
 b'{"o":1,"d":"a","d":"b","m":"c"}': {'result': ('error', 0, b'duplicate field `d`', 1, 18)},
 b'{"o":1,"d":"a","m":"b"': {'result': ('error', 3, b'', 1, 22)},
 b'{"o":1,"d":"a","m":"b","m":"c"}': {'result': ('error', 0, b'duplicate field `m`', 1, 26)},
 b'{"o":1,"d":"a","m":2}': {'result': ('error', 0, b'invalid type: integer `2`, expected a string', 1, 20)},
 b'{"o":1,"d":"a"}': {'result': ('error', 0, b'missing field `m`', 1, 15)},
 b'{"o":1,"d":"a\\nb","m":"\\u0041"}': {'result': ('vote', 1, b'a\nb', b'A')},
 b'{"o":1,"d":2,"m":"b"}': {'result': ('error', 0, b'invalid type: integer `2`, expected a string', 1, 12)},
 b'{"o":1,"m":"b"}': {'result': ('error', 0, b'missing field `d`', 1, 15)},
 b'{"o":1,"o":2,"d":"a","m":"b"}': {'result': ('error', 0, b'duplicate field `o`', 1, 10)},
 b'{"o":1,}': {'result': ('error', 21, b'', 1, 8)},
 b'{"o":1.5,"d":"a","m":"b"}': {'result': ('error', 0, b'invalid type: floating point `1.5`, expected u64', 1, 8)},
 b'{"o":18446744073709551615,"d":"a","m":"b"}': {'result': ('vote', 18446744073709551615, b'a', b'b')},
 b'{"o":18446744073709551616,"d":"a","m":"b"}': {'result': ('error', 0, b'invalid type: floating point `1.8446744073709552e19`, expected u64', 1, 25)},
 b'{"o":7,"d":"12.5","m":"99"}': {'result': ('vote', 7, b'12.5', b'99')},
 b'{"o":7,"m":"99","d":"12.5"}': {'result': ('vote', 7, b'12.5', b'99')},
 b'{"o":null,"d":"a","m":"b"}': {'result': ('error', 0, b'invalid type: null, expected u64', 1, 9)},
 b'{"oo":1,"o":1,"d":"z","m":"b"}': {'result': ('vote', 1, b'z', b'b')},
 b'{"order_ntl":3,"decay_duration":"q","max_px":"r","o":1,"d":"z","m":"b"}': {'result': ('vote', 1, b'z', b'b')},
 b'{"x":[1,2],"o":1,"d":"z","m":"b"}': {'result': ('vote', 1, b'z', b'b')},
 b'{}': {'result': ('error', 0, b'missing field `o`', 1, 2)}}
ROWS_READ = {b'': {'result': ('error', 5, b'', 1, 0)},
 b'\x00': {'result': ('error', 10, b'', 1, 1)},
 b'\t[\n9\r,\t1\n,\r0.5\t,[1.0,2.0,3.0,null,4]]\n': {'result': ('row',
                                                                b'\x00\x00\x00\x00\x00\x00\xf0?\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x08\x40\x04\x00\x00\x00\x00\x00\x00\x00'
                                                                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
                                                                b'\x00\x00\x00\x00\x00\x00\xe0?')},
 b'\t{\n"spot"\r:\t9\n,\r"order_ntl"\n:\t1\r,\n"max_px"\t:\r0.5\n,"ema":[1.0,2.0,3.0,null,4]}\t': {'result': ('row',
                                                                                                              b'\x00\x00\x00\x00\x00\x00\xf0?\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x08\x40'
                                                                                                              b'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                                                                                              b'\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
                                                                                                              b'\x00\x00\x00\x00\x00\x00\xe0?')},
 b'\x0b': {'result': ('error', 10, b'', 1, 1)},
 b'!': {'result': ('error', 10, b'', 1, 1)},
 b'"s"': {'result': ('error', 0, b'invalid type: string "s", expected struct ReserveAccumulator', 1, 3)},
 b'[': {'result': ('error', 2, b'', 1, 1)},
 b'[\x001]': {'result': ('error', 10, b'', 1, 2)},
 b'[\x0b1]': {'result': ('error', 10, b'', 1, 2)},
 b'[!1]': {'result': ('error', 10, b'', 1, 2)},
 b'[1\x00]': {'result': ('error', 7, b'', 1, 3)},
 b'[1\x0b]': {'result': ('error', 7, b'', 1, 3)},
 b'[1!]': {'result': ('error', 7, b'', 1, 3)},
 b'[1,\x001]': {'result': ('error', 10, b'', 1, 4)},
 b'[1,\x0b1]': {'result': ('error', 10, b'', 1, 4)},
 b'[1,!1]': {'result': ('error', 10, b'', 1, 4)},
 b'[9,': {'result': ('error', 5, b'', 1, 3)},
 b'[9,1,0.5,[1.0,2.0,3.0,null,4],5]': {'result': ('error', 22, b'', 1, 31)},
 b'[9,1,0.5,[1.0,2.0,3.0,null,4]]': {'result': ('row',
                                                b'\x00\x00\x00\x00\x00\x00\xf0?\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x08\x40\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0?')},
 b'[9,1,0.5,[1.0,2.0,3.0,null]]': {'result': ('error', 0, b'invalid length 4, expected struct DeterministicEma with 5 elements', 1, 27)},
 b'[9,1,0.5,[1.0]]': {'result': ('error', 0, b'invalid length 1, expected struct DeterministicEma with 5 elements', 1, 14)},
 b'[9,1,0.5]': {'result': ('error', 0, b'invalid length 3, expected struct ReserveAccumulator with 4 elements', 1, 9)},
 b'[9]': {'result': ('error', 0, b'invalid length 1, expected struct ReserveAccumulator with 4 elements', 1, 3)},
 b'{': {'result': ('error', 3, b'', 1, 1)},
 b'{\x00"spot":1}': {'result': ('error', 17, b'', 1, 2)},
 b'{\x0b"spot":1}': {'result': ('error', 17, b'', 1, 2)},
 b'{!"spot":1}': {'result': ('error', 17, b'', 1, 2)},
 b'{"ema"\x00:1}': {'result': ('error', 6, b'', 1, 7)},
 b'{"ema"\x0b:1}': {'result': ('error', 6, b'', 1, 7)},
 b'{"ema"!:1}': {'result': ('error', 6, b'', 1, 7)},
 b'{"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5},"max_px":1,"order_ntl":2,"spot":3}': {'result': ('row',
                                                                                                                                               b'\x00\x00\x00\x00\x00\x00\xf8?\x00\x00\x00\x00'
                                                                                                                                               b'\x00\x00\x04\x40\x00\x00\x00\x00\x00\x00>\x40'
                                                                                                                                               b'\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                                                                                                                               b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                                                                                                                               b'\x03\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00'
                                                                                                                                               b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0?')},
 b'{"max_px"\x00:1}': {'result': ('error', 6, b'', 1, 10)},
 b'{"max_px"\x0b:1}': {'result': ('error', 6, b'', 1, 10)},
 b'{"max_px"!:1}': {'result': ('error', 6, b'', 1, 10)},
 b'{"max_px":\x001}': {'result': ('error', 10, b'', 1, 11)},
 b'{"max_px":\x0b1}': {'result': ('error', 10, b'', 1, 11)},
 b'{"max_px":!1}': {'result': ('error', 10, b'', 1, 11)},
 b'{"order_ntl"\x00:1}': {'result': ('error', 6, b'', 1, 13)},
 b'{"order_ntl"\x0b:1}': {'result': ('error', 6, b'', 1, 13)},
 b'{"order_ntl"!:1}': {'result': ('error', 6, b'', 1, 13)},
 b'{"order_ntl":\x001}': {'result': ('error', 10, b'', 1, 14)},
 b'{"order_ntl":\x0b1}': {'result': ('error', 10, b'', 1, 14)},
 b'{"order_ntl":!1}': {'result': ('error', 10, b'', 1, 14)},
 b'{"spot"\x00:1}': {'result': ('error', 6, b'', 1, 8)},
 b'{"spot"\x0b:1}': {'result': ('error', 6, b'', 1, 8)},
 b'{"spot" 9}': {'result': ('error', 6, b'', 1, 9)},
 b'{"spot"!:1}': {'result': ('error', 6, b'', 1, 8)},
 b'{"spot":\x001}': {'result': ('error', 10, b'', 1, 9)},
 b'{"spot":\x0b1}': {'result': ('error', 10, b'', 1, 9)},
 b'{"spot":!1}': {'result': ('error', 10, b'', 1, 9)},
 b'{"spot":-1,"order_ntl":1,"max_px":0.25,"ema":[1.0,2.0,3.0,null,4]}': {'result': ('error', 0, b'invalid value: integer `-1`, expected usize', 1, 10)},
 b'{"spot":1\x00}': {'result': ('error', 8, b'', 1, 10)},
 b'{"spot":1\x0b}': {'result': ('error', 8, b'', 1, 10)},
 b'{"spot":1!}': {'result': ('error', 8, b'', 1, 10)},
 b'{"spot":1,\x00"max_px":1}': {'result': ('error', 17, b'', 1, 11)},
 b'{"spot":1,\x0b"max_px":1}': {'result': ('error', 17, b'', 1, 11)},
 b'{"spot":1,!"max_px":1}': {'result': ('error', 17, b'', 1, 11)},
 b'{"spot":9': {'result': ('error', 3, b'', 1, 9)},
 b'{"spot":9 "order_ntl":1}': {'result': ('error', 8, b'', 1, 11)},
 b'{"spot":9,': {'result': ('error', 5, b'', 1, 10)},
 b'{"spot":9,"order_ntl":1,"max_px":"x","ema":[1.0,2.0,3.0,null,4]}': {'result': ('error', 0, b'invalid type: string "x", expected f64', 1, 36)},
 b'{"spot":9,"order_ntl":1,"max_px":0.25,"ema":[1.0,2.0,3.0,null,4],"ema":[1.0,2.0,3.0,null,4]}': {'result': ('error', 0, b'duplicate field `ema`', 1, 70)},
 b'{"spot":9,"order_ntl":1,"max_px":0.25,"ema":[1.0,2.0,3.0,null,4],"extra":[1]}': {'result': ('row',
                                                                                               b'\x00\x00\x00\x00\x00\x00\xf0?\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x08\x40'
                                                                                               b'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                                                                               b'\t\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0?')},
 b'{"spot":9,"order_ntl":1,"max_px":0.25,"max_px":0.5,"ema":[1.0,2.0,3.0,null,4]}': {'result': ('error', 0, b'duplicate field `max_px`', 1, 46)},
 b'{"spot":9,"order_ntl":1,"max_px":7,"ema":[1,2,3,null,4]}': {'result': ('row',
                                                                          b'\x00\x00\x00\x00\x00\x00\xf0?\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x08\x40\x04\x00\x00\x00\x00\x00\x00\x00'
                                                                          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
                                                                          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x40')},
 b'{"spot":9,"order_ntl":1,"max_px":null,"ema":[1.0,2.0,3.0,null,4]}': {'result': ('error', 0, b'invalid type: null, expected f64', 1, 37)},
 b'{"spot":9,"order_ntl":1,"order_ntl":2,"max_px":0.25,"ema":[1.0,2.0,3.0,null,4]}': {'result': ('error', 0, b'duplicate field `order_ntl`', 1, 35)},
 b'{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":"2026-07-19T01:02:03.004","n_samples":5}}': {'result': ('row',
                                                                                                                                                                             b'\x00\x00\x00\x00'
                                                                                                                                                                             b'\x00\x00\xf8?'
                                                                                                                                                                             b'\x00\x00\x00\x00'
                                                                                                                                                                             b'\x00\x00\x04\x40'
                                                                                                                                                                             b'\x00\x00\x00\x00'
                                                                                                                                                                             b'\x00\x00>\x40'
                                                                                                                                                                             b'\x05\x00\x00\x00'
                                                                                                                                                                             b'\x00\x00\x00\x00'
                                                                                                                                                                             b'\x8aL\xfd\x00'
                                                                                                                                                                             b'\x8b\x0e\x00\x00'
                                                                                                                                                                             b'\x00\t=\x00'
                                                                                                                                                                             b'\x00\x00\x00\x00'
                                                                                                                                                                             b'\t\x00\x00\x00'
                                                                                                                                                                             b'\x00\x00\x00\x00'
                                                                                                                                                                             b'\x40B\x0f\x00'
                                                                                                                                                                             b'\x00\x00\x00\x00'
                                                                                                                                                                             b'\x00\x00\x00\x00'
                                                                                                                                                                             b'\x00\x00\xd0?')},
 b'{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}': {'result': ('row',
                                                                                                                                                        b'\x00\x00\x00\x00\x00\x00\xf8?\x00\x00\x00\x00'
                                                                                                                                                        b'\x00\x00\x04\x40\x00\x00\x00\x00\x00\x00>\x40'
                                                                                                                                                        b'\x05\x00\x00\x00\x00\x00\x00\x00'
                                                                                                                                                        b'\x00\x00\x00\x00\x00\x00\x00\x00'
                                                                                                                                                        b'\x00\x00\x00\x00\x00\x00\x00\x00'
                                                                                                                                                        b'\t\x00\x00\x00\x00\x00\x00\x00\x40B\x0f\x00'
                                                                                                                                                        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0?')},
 b'{"spot":9,"spot":8,"order_ntl":1,"max_px":0.25,"ema":[1.0,2.0,3.0,null,4]}': {'result': ('error', 0, b'duplicate field `spot`', 1, 16)},
 b'{"spot":9}': {'result': ('error', 0, b'missing field `order_ntl`', 1, 10)},
 b'{}': {'result': ('error', 0, b'missing field `spot`', 1, 2)}}
PAIRS_READ = {b'\t[\n[\r9\t,\n{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}\r]\t,\n[\r2\t,\n{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}\r]\t]': {'result': ('error',
                                                                                                                                                                                                                                                                                                                                   0,
                                                                                                                                                                                                                                                                                                                                   b'inva'
                                                                                                                                                                                                                                                                                                                                   b'lid '
                                                                                                                                                                                                                                                                                                                                   b'type'
                                                                                                                                                                                                                                                                                                                                   b': se'
                                                                                                                                                                                                                                                                                                                                   b'quen'
                                                                                                                                                                                                                                                                                                                                   b'ce, '
                                                                                                                                                                                                                                                                                                                                   b'expe'
                                                                                                                                                                                                                                                                                                                                   b'cted'
                                                                                                                                                                                                                                                                                                                                   b' usi'
                                                                                                                                                                                                                                                                                                                                   b'ze',
                                                                                                                                                                                                                                                                                                                                   2,
                                                                                                                                                                                                                                                                                                                                   0)},
 b'[': {'result': ('error', 2, b'', 1, 1)},
 b'[\x001]': {'result': ('error', 10, b'', 1, 2)},
 b'[\x00]': {'result': ('error', 10, b'', 1, 2)},
 b'[\x0b1]': {'result': ('error', 10, b'', 1, 2)},
 b'[\x0b]': {'result': ('error', 10, b'', 1, 2)},
 b'[ [ 9 , {"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}} ] ]': {'result': ('end',
                                                                                                                                                                    ((9,
                                                                                                                                                                      b'\x00\x00\x00\x00\x00\x00\xf8?'
                                                                                                                                                                      b'\x00\x00\x00\x00\x00\x00\x04\x40'
                                                                                                                                                                      b'\x00\x00\x00\x00\x00\x00>\x40'
                                                                                                                                                                      b'\x05\x00\x00\x00'
                                                                                                                                                                      b'\x00\x00\x00\x00'
                                                                                                                                                                      b'\x00\x00\x00\x00'
                                                                                                                                                                      b'\x00\x00\x00\x00'
                                                                                                                                                                      b'\x00\x00\x00\x00'
                                                                                                                                                                      b'\x00\x00\x00\x00\t\x00\x00\x00'
                                                                                                                                                                      b'\x00\x00\x00\x00\x40B\x0f\x00'
                                                                                                                                                                      b'\x00\x00\x00\x00'
                                                                                                                                                                      b'\x00\x00\x00\x00\x00\x00\xd0?'),))},
 b'[ ]': {'result': ('end', ())},
 b'[!1]': {'result': ('error', 10, b'', 1, 2)},
 b'[!]': {'result': ('error', 10, b'', 1, 2)},
 b'[1]': {'result': ('error', 0, b'invalid type: integer `1`, expected a tuple of size 2', 1, 2)},
 b'[[': {'result': ('error', 2, b'', 1, 2)},
 b'[[\x009]]': {'result': ('error', 10, b'', 1, 3)},
 b'[[\x0b9]]': {'result': ('error', 10, b'', 1, 3)},
 b'[[!9]]': {'result': ('error', 10, b'', 1, 3)},
 b'[[-1,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]': {'result': ('error',
                                                                                                                                                               0,
                                                                                                                                                               b'invalid value: integer `-1`, expecte'
                                                                                                                                                               b'd usize',
                                                                                                                                                               1,
                                                                                                                                                               4)},
 b'[[9': {'result': ('error', 2, b'', 1, 3)},
 b'[[9\x00]]': {'result': ('error', 7, b'', 1, 4)},
 b'[[9\x0b]]': {'result': ('error', 7, b'', 1, 4)},
 b'[[9!]]': {'result': ('error', 7, b'', 1, 4)},
 b'[[9,': {'result': ('error', 5, b'', 1, 4)},
 b'[[9,\x00{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]': {'result': ('error', 10, b'', 1, 5)},
 b'[[9,\x0b{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]': {'result': ('error', 10, b'', 1, 5)},
 b'[[9,!{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]': {'result': ('error', 10, b'', 1, 5)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}': {'result': ('error', 2, b'', 1, 138)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}\x00]]': {'result': ('error', 22, b'', 1, 139)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}\x0b]]': {'result': ('error', 22, b'', 1, 139)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}!]]': {'result': ('error', 22, b'', 1, 139)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}},1]]': {'result': ('error', 22, b'', 1, 140)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]': {'result': ('error', 2, b'', 1, 139)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]\x00]': {'result': ('error', 7, b'', 1, 140)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]\x0b]': {'result': ('error', 7, b'', 1, 140)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}] [1]]': {'result': ('error', 7, b'', 1, 141)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]!]': {'result': ('error', 7, b'', 1, 140)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}],\x00[2,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]': {'result': ('error',
                                                                                                                                                                                                                                                                                                             10,
                                                                                                                                                                                                                                                                                                             b'',
                                                                                                                                                                                                                                                                                                             1,
                                                                                                                                                                                                                                                                                                             141)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}],\x0b[2,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]': {'result': ('error',
                                                                                                                                                                                                                                                                                                             10,
                                                                                                                                                                                                                                                                                                             b'',
                                                                                                                                                                                                                                                                                                             1,
                                                                                                                                                                                                                                                                                                             141)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}],![2,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]': {'result': ('error',
                                                                                                                                                                                                                                                                                                          10,
                                                                                                                                                                                                                                                                                                          b'',
                                                                                                                                                                                                                                                                                                          1,
                                                                                                                                                                                                                                                                                                          141)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}],[2,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]': {'result': ('end',
                                                                                                                                                                                                                                                                                                         ((9,
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\xf8?'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x04\x40'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00>\x40'
                                                                                                                                                                                                                                                                                                           b'\x05\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\t\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x40B\x0f\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\xd0?'),
                                                                                                                                                                                                                                                                                                          (2,
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\xf8?'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x04\x40'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00>\x40'
                                                                                                                                                                                                                                                                                                           b'\x05\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\t\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x40B\x0f\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                                                                                                                                                           b'\x00\x00\xd0?')))},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}],]': {'result': ('error', 21, b'', 1, 141)},
 b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]': {'result': ('end',
                                                                                                                                                              ((9,
                                                                                                                                                                b'\x00\x00\x00\x00\x00\x00\xf8?'
                                                                                                                                                                b'\x00\x00\x00\x00\x00\x00\x04\x40'
                                                                                                                                                                b'\x00\x00\x00\x00\x00\x00>\x40'
                                                                                                                                                                b'\x05\x00\x00\x00\x00\x00\x00\x00'
                                                                                                                                                                b'\x00\x00\x00\x00\x00\x00\x00\x00'
                                                                                                                                                                b'\x00\x00\x00\x00\x00\x00\x00\x00'
                                                                                                                                                                b'\t\x00\x00\x00\x00\x00\x00\x00'
                                                                                                                                                                b'\x40B\x0f\x00\x00\x00\x00\x00'
                                                                                                                                                                b'\x00\x00\x00\x00\x00\x00\xd0?'),))},
 b'[[9]]': {'result': ('error', 0, b'invalid length 1, expected a tuple of size 2', 1, 4)},
 b'[[]]': {'result': ('error', 0, b'invalid length 0, expected a tuple of size 2', 1, 3)},
 b'[]': {'result': ('end', ())}}
DEPTH_READ = {('read_pairs', 1, b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]'): {'result': ('error',
                                                                                                                                                                                 24,
                                                                                                                                                                                 b'',
                                                                                                                                                                                 1,
                                                                                                                                                                                 2)},
 ('read_pairs', 2, b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]'): {'result': ('error',
                                                                                                                                                                                 24,
                                                                                                                                                                                 b'',
                                                                                                                                                                                 1,
                                                                                                                                                                                 5)},
 ('read_pairs', 3, b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]'): {'result': ('error',
                                                                                                                                                                                 24,
                                                                                                                                                                                 b'',
                                                                                                                                                                                 1,
                                                                                                                                                                                 55)},
 ('read_pairs', 255, b'[[9,{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}]]'): {'result': ('end',
                                                                                                                                                                                   ((9,
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00\xf8?'
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00\x04\x40'
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00>\x40'
                                                                                                                                                                                     b'\x05\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\t\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\x40B\x0f\x00'
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00\x00\x00'
                                                                                                                                                                                     b'\x00\x00\xd0?'),))},
 ('read_row', 1, b'[9,1,0.5,[1.0,2.0,3.0,null,4]]'): {'result': ('error', 24, b'', 1, 1)},
 ('read_row', 1, b'{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}'): {'result': ('error', 24, b'', 1, 1)},
 ('read_row', 2, b'[9,1,0.5,[1.0,2.0,3.0,null,4]]'): {'result': ('error', 24, b'', 1, 10)},
 ('read_row', 2, b'{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}'): {'result': ('error', 24, b'', 1, 51)},
 ('read_row', 3, b'[9,1,0.5,[1.0,2.0,3.0,null,4]]'): {'result': ('row',
                                                                 b'\x00\x00\x00\x00\x00\x00\xf0?\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x08\x40\x04\x00\x00\x00\x00\x00\x00\x00'
                                                                 b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
                                                                 b'\x00\x00\x00\x00\x00\x00\xe0?')},
 ('read_row', 3, b'{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}'): {'result': ('row',
                                                                                                                                                                         b'\x00\x00\x00\x00'
                                                                                                                                                                         b'\x00\x00\xf8?'
                                                                                                                                                                         b'\x00\x00\x00\x00'
                                                                                                                                                                         b'\x00\x00\x04\x40'
                                                                                                                                                                         b'\x00\x00\x00\x00\x00\x00>\x40'
                                                                                                                                                                         b'\x05\x00\x00\x00'
                                                                                                                                                                         b'\x00\x00\x00\x00'
                                                                                                                                                                         b'\x00\x00\x00\x00'
                                                                                                                                                                         b'\x00\x00\x00\x00'
                                                                                                                                                                         b'\x00\x00\x00\x00'
                                                                                                                                                                         b'\x00\x00\x00\x00'
                                                                                                                                                                         b'\t\x00\x00\x00'
                                                                                                                                                                         b'\x00\x00\x00\x00\x40B\x0f\x00'
                                                                                                                                                                         b'\x00\x00\x00\x00'
                                                                                                                                                                         b'\x00\x00\x00\x00'
                                                                                                                                                                         b'\x00\x00\xd0?')},
 ('read_row', 255, b'[9,1,0.5,[1.0,2.0,3.0,null,4]]'): {'result': ('row',
                                                                   b'\x00\x00\x00\x00\x00\x00\xf0?\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x08\x40\x04\x00\x00\x00\x00\x00\x00\x00'
                                                                   b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
                                                                   b'\x00\x00\x00\x00\x00\x00\xe0?')},
 ('read_row', 255, b'{"spot":9,"order_ntl":1000000,"max_px":0.25,"ema":{"num":1.5,"denom":2.5,"decay_duration":30.0,"last_sample_time":null,"n_samples":5}}'): {'result': ('row',
                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                           b'\x00\x00\xf8?'
                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                           b'\x00\x00\x04\x40'
                                                                                                                                                                           b'\x00\x00\x00\x00\x00\x00>\x40'
                                                                                                                                                                           b'\x05\x00\x00\x00'
                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                           b'\t\x00\x00\x00'
                                                                                                                                                                           b'\x00\x00\x00\x00\x40B\x0f\x00'
                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                           b'\x00\x00\x00\x00'
                                                                                                                                                                           b'\x00\x00\xd0?')},
 ('read_vote', 1, b'[1,"a","b"]'): {'result': ('error', 24, b'', 1, 1)},
 ('read_vote', 1, b'{"o":1,"d":"a","m":"b"}'): {'result': ('error', 24, b'', 1, 1)},
 ('read_vote', 2, b'[1,"a","b"]'): {'result': ('vote', 1, b'a', b'b')},
 ('read_vote', 2, b'{"o":1,"d":"a","m":"b"}'): {'result': ('vote', 1, b'a', b'b')},
 ('read_vote', 3, b'[1,"a","b"]'): {'result': ('vote', 1, b'a', b'b')},
 ('read_vote', 3, b'{"o":1,"d":"a","m":"b"}'): {'result': ('vote', 1, b'a', b'b')},
 ('read_vote', 255, b'[1,"a","b"]'): {'result': ('vote', 1, b'a', b'b')},
 ('read_vote', 255, b'{"o":1,"d":"a","m":"b"}'): {'result': ('vote', 1, b'a', b'b')}}



def shown_text(text):
    return text.decode().encode("unicode_escape").decode()


def named_vote_cases():
    cases = []
    edge = (ROW_LIMIT // 100 + 1) * 100

    def add(label, **fields):
        for copy in range(3):
            cases.append(Case("%s copy %s" % (label, COPIES[copy].name), copy=copy, **fields))
    add("plain vote")
    add("native token unset keeps the map", native=0, old=(4, 7))
    add("native token unset, strings freed", native=0, old=())
    add("native index at the bound panics", native_index=2)
    add("native index past the bound panics", native_index=3, tokens=3)
    add("native index last in range", native_index=1, tokens=2)
    add("no spots empties the map", spots=(), old=(4, 7))
    add("no spots ignores long texts", spots=(), d=b"9" * 101, m=b"9" * 101)
    add("no spots ignores bad text", spots=(), bad=0)
    add("no spots still gates the amount", spots=(), o=CAP, old=(4,))
    add("one spot", spots=(11,))
    add("spots out of order", spots=(9, 1, 5, 3))
    add("repeated spot", spots=(5, 5, 2, 5))
    add("twelve spots split the root", spots=tuple(range(100, 112)))
    add("twenty five spots", spots=tuple(range(200, 225)))
    add("old leaf replaced", old=(1, 2, 5))
    add("old leaf with stale key", old=(2, 5, 8), stale=5)
    add("old two level map replaced", old=tuple(range(30, 50)))
    add("old rows on another spot set", old=(70, 71), spots=(70,))
    for label, order_ntl in (("zero", 0), ("one", 1), ("99", 99), ("100", 100), ("101", 101), ("cut", SCALE_CUT), ("cut plus one", SCALE_CUT + 1), ("cut plus 100", SCALE_CUT + 100),
                             ("first multiple past the cut", (SCALE_CUT // 100 + 1) * 100), ("row limit", ROW_LIMIT), ("edge less one", edge - 1), ("edge", edge), ("edge plus one", edge + 1),
                             ("cap less one", CAP - 1), ("cap", CAP), ("cap plus one", CAP + 1), ("top", TOP)):
        add("order_ntl " + label, o=order_ntl, old=(4,))
    add("amount above the row edge empties the map", o=edge, old=(4, 7), spots=(4,))
    add("d text of 100 bytes", d=b"1" * 100)
    add("d text of 101 bytes", d=b"1" * 101, old=(4,))
    add("m text of 100 bytes", m=b"1" * 100)
    add("m text of 101 bytes", m=b"1" * 101, old=(4,))
    add("amount gate before the length gate", o=CAP, d=b"1" * 101)
    add("d length before m length", d=b"1" * 101, m=b"1" * 101)
    add("bad d", bad=0, old=(4,))
    add("bad m", bad=1, old=(4,))
    add("bad d with long m", bad=0, m=b"1" * 101)
    add("long m after good d", m=b"1" * 101, bad=1)
    add("empty texts with no capacity", d=b"", m=b"", cap_d=0, cap_m=0)
    add("spare capacity", cap_d=40, cap_m=50)
    for label, value in (("10", 10.0), ("below 10", 9.999), ("above 10", 10.000000000000002), ("zero", 0.0), ("negative", -5.0), ("huge", 1e300), ("nan", math.nan), ("infinity", math.inf)):
        add("d value " + label, d_value=value)
    for label, value in (("negative", -1.5), ("zero", 0.0), ("minus zero", -0.0), ("nan", math.nan), ("huge", 1e300)):
        add("m value " + label, m_value=value)
    return cases


END_CASES = ((b'{"o":7000000,"d":"12.5","m":"99"}', OK, 7000000, 12.5, 99.0), (b'{"o":7000000,"d":"0.5","m":"0.25"}', OK, 7000000, 0.5, 0.25), (b'[1000,"86400","1000000"]', OK, 1000, 86400.0, 1000000.0),
             (b'{"o":1,"d":"x","m":"1"}', None, 0, 0, 0), (b'{"o":1,"d":"1","m":""}', None, 0, 0, 0))


def end_cases():
    cases = []
    for copy in range(3):
        for text, status, order_ntl, decay, max_px in END_CASES:
            want = None
            if status == OK:
                want = dict(status=OK, rows=tuple((spot, mask(spec_row(spot, order_ntl, decay, max_px))) for spot in sorted((5, 2, 8))))
            cases.append(Case("real parser %s copy %s" % (text.decode(), COPIES[copy].name), kind="end", copy=copy, text=text, want=want))
    return cases


SINK_CAPS = (1, 2, 3, 4, 5, 6, 7, 9, 15, 16, 17, 18, 19, 20, 21, 25, 30, 35, 40, 46, 50, 60, 100, 130)
ROWS = (Row(), Row(num=1.5, denom=2.5, decay=30.0, samples=5, spot=9, amount=1000000, max_px=0.25), Row(decay=1e16, samples=0x7F, spot=0x7F, amount=0x80, max_px=1e-5), Row(decay=1e15, samples=0x80, spot=0xFF, amount=0x100, max_px=-0.0),
        Row(samples=0xFF, spot=0xFFFF, amount=0x10000, max_px=math.inf), Row(samples=0x100, spot=0xFFFFFFFF, amount=0x100000000, max_px=math.nan), Row(samples=TOP, spot=TOP, amount=TOP, num=-1.5, denom=1e300),
        Row(time=Time(date_word(2026, 200), 3723, 4000000), samples=1), Row(time=Time(date_word(2024, 366), 86399, 0)), Row(time=Time(date_word(2026, 1), 0, 123456000)), Row(time=Time(date_word(2026, 59), 60, 1)))


def out_cases():
    cases = []
    for family in (RMP_GENERAL, RMP_DIRECT):
        for fn in family:
            for keyed in (0, 1):
                for index, row in enumerate(ROWS):
                    cases.append(Case("%s keyed %d row %d" % (NAMES[fn], keyed, index), kind="rmp", fn=fn, row=row, keyed=keyed))
    for fn in JSON_ROW:
        for index, row in enumerate(ROWS):
            cases.append(Case("%s row %d" % (NAMES[fn], index), kind="json", fn=fn, row=row))
    for cap in SINK_CAPS:
        for fn in RMP_GENERAL[:1] + RMP_DIRECT[:1]:
            for keyed in (0, 1):
                cases.append(Case("%s keyed %d capacity %d" % (NAMES[fn], keyed, cap), kind="rmp", fn=fn, row=ROWS[7], keyed=keyed, cap=cap))
        cases.append(Case("%s capacity %d" % (NAMES[JSON_ROW[0]], cap), kind="json", fn=JSON_ROW[0], row=ROWS[7], cap=cap))
        cases.append(Case("map writer capacity %d" % cap, kind="map_json", rows=((1, ROWS[1]), (2, ROWS[7])), cap=cap))
    cases.append(Case("map writer no rows capacity 1", kind="map_json", rows=(), cap=1))
    cases.append(Case("map writer no rows capacity 2", kind="map_json", rows=(), cap=2))
    for count in range(4):
        rows = tuple((key * 3 + 1, ROWS[key % len(ROWS)]) for key in range(count))
        cases.append(Case("map writer %d rows" % count, kind="map_json", rows=rows))
    return cases


def field_cases():
    cases = []
    for fn in FIELD_ID:
        texts = [name for name, _ in FIELD_NAMES] + [b"", b"sp", b"spots", b"max_p", b"max_pxx", b"order_nt", b"order_ntll", b"em", b"emaa"]
        for name, _ in FIELD_NAMES:
            for at in range(len(name)):
                texts.append(name[:at] + bytes([name[at] ^ 0x20]) + name[at + 1:])
        for text in texts:
            cases.append(Case("%s %s" % (NAMES[fn], text.decode()), kind="field", fn=fn, text=text))
    return cases


def clear_cases():
    return [Case("clear %d rows" % len(old), kind="clear", old=old) for old in ((), tuple((key, bytes(ROW_SIZE)) for key in (1, 2)), tuple((key, bytes(ROW_SIZE)) for key in range(1, 21)))]


def read_cases():
    cases = []
    for fn in VOTE_READ:
        for text in WIRE_TEXTS:
            cases.append(Case("%s %s" % (NAMES[fn], shown_text(text)), kind="read_vote", fn=fn, text=text, want=WIRE[text]))
    for fn in ROW_READ:
        for text in ROW_TEXTS:
            cases.append(Case("%s %s" % (NAMES[fn], shown_text(text)[:60]), kind="read_row", fn=fn, text=text, want=ROWS_READ[text]))
    for fn in PAIR_READ:
        for text in PAIR_TEXTS:
            cases.append(Case("%s %s" % (NAMES[fn], shown_text(text)[:40]), kind="read_pairs", fn=fn, text=text, want=PAIRS_READ[text]))
    for (kind, depth, text), want in DEPTH_READ.items():
        fn = dict(read_vote=VOTE_READ[0], read_row=ROW_READ[0], read_pairs=PAIR_READ[0])[kind]
        cases.append(Case("%s depth %d %s" % (kind, depth, shown_text(text)[:40]), kind=kind, fn=fn, text=text, depth=depth, want=want))
    return cases


def base_cases():
    return named_vote_cases() + end_cases() + out_cases() + field_cases() + clear_cases() + read_cases()


def lcg(seed):
    state = seed

    def next_value(bound):
        nonlocal state
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return (state >> 16) % bound
    return next_value


def vector_cases(count):
    random = lcg(0x52455345)
    edge = (ROW_LIMIT // 100 + 1) * 100
    cases = []
    for index in range(count):
        anchor = (0, SCALE_CUT, edge, CAP, 1 << 40)[random(5)]
        order_ntl = (anchor + random(400) - 200) & MASK[8] if random(4) else random(1 << 62)
        spots = tuple(random(40) for _ in range(random(9)))
        old = tuple(sorted({random(40) for _ in range(random(16))}))
        fields = dict(copy=random(3), o=order_ntl, spots=spots, old=old, d_value=random(4000) / 100.0, m_value=random(4000) / 7.0, stale=random(40))
        if not random(8):
            fields["bad"] = random(2)
        if not random(12):
            fields["d"] = b"7" * (98 + random(5))
        if not random(12):
            fields["m"] = b"7" * (98 + random(5))
        if not random(30):
            fields["native"] = 0
        cases.append(Case("vector %d" % index, **fields))
    return cases


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_for(case)
        if not same(case, got, want):
            raise EvidenceError("case %s: got %s want %s" % (case.name, {key: value for key, value in got.items() if key != "out"}, want))
        outcomes.append(got)
    return outcomes


def arms_of(image, copy):
    at = image.offset(copy.table)
    return [copy.table + struct.unpack_from("<i", image.blob, at + 4 * index)[0] for index in range(ARMS)]


def arm_windows(image, seen, cache):
    tables = {}
    for copy in COPIES:
        arms = arms_of(image, copy)
        low, high = image.fde(arms[WORD - 18])
        head = min(arms)
        vas = sorted(va for va in seen if head <= va < high)
        rows = [cache[va] for va in vas]
        for row in rows:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        tables[copy.name] = rows
    return tables


def rows_of(image, target):
    return decode_range(image, *image.exact_fde(target))


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
            if not same(case, harness.run(case), spec_for(case)):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError):
            return case
    return None


REACH_CAP = 10
SECOND_CAP = 90
UNCLASSIFIED = "not classified: survived its capped case list"
def survivor_reason(va, kind):
    return UNCLASSIFIED



def spread(items, cap=REACH_CAP):
    step = max(1, len(items) // cap)
    return items[::step]


def run_mutants(image, table, window, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    chosen = cases + vector_cases(240)
    reach = collections.defaultdict(list)
    for case in chosen:
        control.machine.seen = set()
        control.run(case)
        for va in control.machine.seen:
            reach[va].append(case)
    groups = [table[target] for target in SUBJECTS if target in MUTATED] + [window[name] for name in ("a", "b", "c")]
    for rows in groups:
        for va, kind, patch in edits_for(image, rows, seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, spread(reach[va]))
            if hit is None:
                hit = first_failure(harness, spread(reach[va], SECOND_CAP))
            if hit is not None:
                results.append((va, kind, "killed", hit.name))
            else:
                results.append((va, kind, "survived", survivor_reason(va, kind)))
    return results


def ladder_rows():
    """The stored amount over all of u64, by closed form; the divide step is shown exact by the multiplier bound."""
    divisor = 0x28F5C28F5C28F5C3
    excess = divisor * 25 - (1 << 66)
    if not 0 <= excess * ((1 << 62) - 1) < (1 << 66):
        raise EvidenceError("the reciprocal does not give floor(x/100) for every u64")
    if SCALE_CUT != TOP // 10000 or SCALE_CUT * 100 > ROW_LIMIT:
        raise EvidenceError("the scale cut is not floor(u64::MAX / 10000), or its product passes the row limit")
    edge = (ROW_LIMIT // 100 + 1) * 100
    return [("0", "%#x" % SCALE_CUT, "row", "x * 100"), ("%#x" % (SCALE_CUT + 1), "%#x" % (edge - 1), "row", "floor(x / 100) * 100, not scaled"),
            ("%#x" % edge, "%#x" % (CAP - 1), "no row, status ok", "the map stays empty"), ("%#x" % CAP, "%#x" % TOP, "refused, status 0x13f, payload x", "the map stays empty")]


PIN_ROWS = (
    (0x2356317, "498b6f38", "arm a: rbp = action +0x38, the order amount"), (0x235634F, "4180bd8000000000", "arm a: native flag at state +0x80"), (0x2356394, "498dbd003a0000", "arm a: map at state +0x3a00"),
    (0x23563A9, "48b8cccccccccccccc0c", "arm a: amount bound"), (0x23597B2, "4883bc240002000065", "arm a: length of d against 0x65"), (0x23597EB, "4883bc24d002000065", "arm a: length of m against 0x65"),
    (0x4CAACDB, "ff15", "arm b: clear call"), (0x4CB366B, "ff15", "arm c: clear call"), (0x4CAE147, "ff15", "arm b: constructor call"), (0x4CB6AD7, "ff15", "arm c: constructor call"),
    (0x1F3EE05, "488d35", "value-array reader: newtype name `Unvalidated` for the first element"),
)
TEXTS = ((0x3E181B, 0x17, "native token is not set"), (0x3F682F, 0xB, "Unvalidated"), (0x209FC0, 4, "spot"), (0x58B181, 9, "order_ntl"), (0x58B18A, 6, "max_px"), (0x58B190, 3, "ema"), (0x5A6F13, 3, "num"), (0x5A6F16, 5, "denom"), (0x5A6F1B, 14, "decay_duration"), (0x203EC0, 16, "last_sample_time"), (0x5A6F29, 9, "n_samples"))
FLOOR_ROW = (0x20A8A8, 10.0, "window floor")
SLOTS = ((0x5773E10, "row constructor"), (0x5773D78, "clear_map"), (0x5773328, "wire decimal to f64"))
REFERENCE = (
    ("l1/action/vote_global.rs:342", "field order_ntl: i128", "u64 at action +0x38, wire key `o`"), ("l1/action/vote_global.rs:344", "field decay_duration: u128", "text at action +0x08, wire key `d`, a decimal string read as f64"),
    ("l1/action/vote_global.rs:345", "field max_px: u64", "text at action +0x20, wire key `m`, a decimal string read as f64"), ("l1/books.rs:984 (per RE-006-system-buy-order-94)", "ImpactState::observe", "the row type is ReserveAccumulator; its average is DeterministicEma"),
)


def pin_rows(image):
    rows = []
    for va, prefix, reading in PIN_ROWS:
        data = bytes(image.blob[image.offset(va):image.offset(va) + len(prefix) // 2])
        if data.hex() != prefix:
            raise EvidenceError("pin mismatch at %#x: %s" % (va, data.hex()))
        rows.append(("%#x" % va, prefix, reading))
    return rows


def text_rows(image):
    rows = []
    for va, size, text in TEXTS:
        data = bytes(image.blob[image.offset(va):image.offset(va) + size])
        if data.decode() != text:
            raise EvidenceError("text mismatch at %#x" % va)
        rows.append(("%#x" % va, text))
    return rows


def slot_rows(image):
    relative = image.relative()
    return [("%#x" % slot, "%#x" % relative[slot], name) for slot, name in SLOTS if name != "row constructor"] + [("%#x" % SLOTS[0][0], "see RE-006-quote-token-enable-94", SLOTS[0][1])]


def serde_rows(image):
    rows = []
    for text in SERDE:
        at = image.blob.find(text)
        if at < 0:
            raise EvidenceError("serde text missing: %s" % text)
        rows.append(("%#x" % at, text.decode()))
    return rows


def float_rows(image):
    va, value, reading = FLOOR_ROW
    got = struct.unpack_from("<d", image.blob, image.offset(va))[0]
    if got != value:
        raise EvidenceError("constant mismatch")
    return [("%#x" % va, repr(value), reading)]


def analyse(image, mutate=True, vectors=800):
    harness = Harness(image)
    cases = base_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in SUBJECTS}
    cache = harness.machine.cache
    window = arm_windows(image, seen, cache)
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in SUBJECTS}
    result = dict(table=table, window=window, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, texts=text_rows(image), serde=serde_rows(image), pins=pin_rows(image), ladder=ladder_rows(), slots=slot_rows(image), floats=float_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, window, seen, cases)
    return result


def outcome_row(case, got):
    if case.kind == "vote":
        label = "panic" if got.get("panic") else "status %#x rows %d" % (got["status"], len(got["rows"]))
    elif case.kind == "end":
        label = "status %#x rows %d" % (got["status"], len(got["rows"]))
    elif case.kind in ("read_vote", "read_row", "read_pairs"):
        label = repr(got["result"][0])
    else:
        label = case.kind
    digest = hashlib.sha256(repr(sorted((key, value) for key, value in got.items() if key not in ("out", "word1", "word2", "root"))).encode()).hexdigest()[:16]
    return (case.kind, COPIES[case.copy].name if case.kind in ("vote", "end") else "-", case.name.replace("\t", " ").replace("\n", " "), label, digest)


def wire_rows():
    rows = []
    for family, texts, table in (("vote", WIRE_TEXTS, WIRE), ("row", ROW_TEXTS, ROWS_READ), ("pairs", PAIR_TEXTS, PAIRS_READ)):
        for text in texts:
            result = table[text]["result"]
            if result[0] == "error":
                shown = "error %d: %s, line %d column %d" % (result[1], result[2].decode(), result[3], result[4])
            elif result[0] == "vote":
                shown = "o=%d d=%s m=%s" % (result[1], result[2].decode().replace("\n", "\\n"), result[3].decode())
            elif result[0] == "row":
                shown = "row"
            else:
                shown = "%d pairs" % len(result[1])
            rows.append((family, shown_text(text), shown))
    return rows


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, row.data.hex(), row.op) for target in SUBJECTS for row in result["table"][target]])
    tsv("arm-rows.tsv", ("copy", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in sorted(result["window"]) for row in result["window"][name]])
    tsv("amount-ladder.tsv", ("from", "to", "result", "stored"), result["ladder"])
    tsv("pins.tsv", ("address", "bytes", "reading"), result["pins"])
    tsv("texts.tsv", ("address", "text"), result["texts"])
    tsv("serde.tsv", ("file_offset", "text"), result["serde"])
    tsv("slots.tsv", ("slot", "target", "meaning"), result["slots"])
    tsv("constants.tsv", ("address", "value", "meaning"), result["floats"])
    tsv("reference.tsv", ("reference", "says", "bytes say"), REFERENCE)
    tsv("wire.tsv", ("family", "text", "result"), wire_rows())
    tsv("outcomes.tsv", ("kind", "copy", "case", "result", "digest"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in SUBJECTS},
        "arm_rows_reached": {name: len(rows) for name, rows in sorted(result["window"].items())},
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
    parser.add_argument("--mutants", action="store_true", help="also run the byte edit sweep (about 10 minutes) and write mutations.tsv")
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image, mutate=args.mutants))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

