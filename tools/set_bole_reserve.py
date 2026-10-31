#!/usr/bin/env python3
"""Pin the node #94 SetBole vote: its 18 inner words, the Reserve config apply, the config check and the side gate.

Real rows run from the vote dispatcher entry and from the side gate entry. A separately written rule list predicts the
status, every stored row, every warning and every state byte, and every reached conditional row, immediate and field
offset of the subject code is mutated. No objdump or readelf output is parsed and the binary is never executed.
Standard library only.

    python3 tools/set_bole_reserve.py --out <dir>
"""

import argparse
import bisect
import collections
import datetime
import fractions
import hashlib
import itertools
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
TAG_NUMBER = 0x13F
TAG_LENGTH = 0x143
TAG_TOKEN = 0xEA
TAG_NESTED = 0xE1
TAG_TESTNET = 0x8D
TAG_BAD_TEXT = 0xAC
TAG_BAD_CURVE = 0x7B
CAP = 0x0CCCCCCCCCCCCCCC
TEXT_LIMIT = 100
ONE = 10 ** 14
STATUS_OK = 0x11
STATUS_INVALID = 4
STATUS_SHORT = 0x10
STATUS_OVERFLOW = 3
SELECT_ENTRY = 0x4E
SUB_ARMS = 16
SHIFT_C = 0xA80
ROW_SIZE = 0xB0
TREE_AT = 0x568
QUOTE_AT = 0x2E0
SIDE_LEAF = 0x1C8
SIDE_INNER = 0x228
RESERVE_LEAF = 0x7F8
RESERVE_INNER = 0x858
QUOTE_LEAF = 0x70
QUOTE_INNER = 0xD0
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_FORMAT = 0x576E040
SLOT_TEXT = 0x57731D8
SLOT_LTV = 0x5773E78
SLOT_CURVE = 0x5773E98
SLOT_PRICE = 0x5773EA0
SLOT_SEED = 0x5773EA8
SLOT_APPLY = 0x5773EB0
SLOT_RECORD = 0x5773190
SLOT_GATE = 0x5775108
SLOT_ROOM = 0x5775100
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150)
RESUME = 0x5660110
MARK_BASE = 0x7700000000
OUT = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x200
SIDE_A = HEAP_BASE + 0x400
SIDE_B = HEAP_BASE + 0x480
RECORD = HEAP_BASE + 0x500
S = HEAP_BASE + 0x1000
BUMP = HEAP_BASE + 0x6000
BUMP_END = HEAP_BASE + 0x3F000
LIMIT_MIN = 0x8000000000000000
FILL = 0xAA
PIECES_INVALID = 0x2022DC
PIECES_CAP = 0x1E77C8
PIECES_USER = 0x200E1C
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x6000))


class Copy:
    def __init__(self, name, table, sub):
        self.name, self.table, self.sub = name, table, sub

    def arm(self, image):
        return self.table + struct.unpack_from("<i", image.blob, image.offset(self.table + 4 * SELECT_ENTRY))[0]

    def entry(self, image):
        return image.fde(self.arm(image))[0]


class Layout:
    def __init__(self, key_at, val_at, val_size, parent_at, index_at, len_at, edge_at, leaf, inner):
        self.key_at, self.val_at, self.val_size, self.parent_at = key_at, val_at, val_size, parent_at
        self.index_at, self.len_at, self.edge_at, self.leaf, self.inner = index_at, len_at, edge_at, leaf, inner


L_RESERVE = Layout(0x798, 0, ROW_SIZE, 0x790, 0x7F0, 0x7F2, 0x7F8, RESERVE_LEAF, RESERVE_INNER)
L_SIDE = Layout(0x168, 0, 0x20, 0x160, 0x1C0, 0x1C2, 0x1C8, SIDE_LEAF, SIDE_INNER)
L_QUOTE = Layout(8, 0x64, 1, 0, 0x60, 0x62, 0x70, QUOTE_LEAF, QUOTE_INNER)
COPIES = (Copy("a", 0x3DD1B8, 0x3DD340), Copy("b", 0x711064, None), Copy("c", 0x711244, None))
APPLY = 0x37417B0
CHECK = 0x3740300
GATE = 0x3734E00
ROOM = 0x37407B0
SUBJECTS = (APPLY, CHECK, GATE)
NAMES = {APPLY: "reserve_apply", CHECK: "reserve_check", GATE: "reserve_side_gate"}
FLAGS = {2: 0x5B3, 6: 0x5B2, 9: 0x5B0, 10: 0x5B1}
CAPS = {11: 0x550, 12: 0x558, 13: 0x548, 15: 0x590}
RATE_FIELDS = (("flag", 0x08, 0x10, 0x4F0), ("flag", 0x18, 0x20, 0x500), ("nonzero", None, 0x48, 0x4F8), ("flag", 0x28, 0x30, 0x510), ("nonzero", None, 0x50, 0x508), ("flag", 0x38, 0x40, 0x520), ("nonzero", None, 0x58, 0x518))
SERDE = (b"struct variant SetBole::Reserve with 9 elements", b"struct variant SetBole::RateLimit with 7 elements", b"struct variant SetBole::ResetIndex with 2 elements", b"struct variant SetBole::BackstopLiquidatorTokenParams with 4 elements", b"struct variant SetBole::TestnetAction with 2 elements", b"struct variant SetBole::Adl with 2 elements",
         b"lybubusMpmp", b"ubglnubglmubulnubulm")


def object_bytes(tag):
    return struct.pack("<H", tag) + bytes((0x41 + index) & 0xFF for index in range(2, 0x60))


class Row:
    """One reserve row, 22 words; names follow the three warning texts where those name a field."""
    NAMES = ("ltv_tag", "ltv", "seed", "balance", "held", "paid", "min_px", "max_px", "borrowed", "borrow_cap", "user_borrow_cap", "borrow_index", "supplied", "supply_cap", "user_supply_cap", "supply_index", "rate_0", "rate_1", "rate_2", "rate_3", "stamp_0", "stamp_1")

    def __init__(self, **fields):
        for name in self.NAMES:
            setattr(self, name, fields.pop(name, 0))
        if fields:
            raise EvidenceError("unknown row field %s" % sorted(fields))

    def words(self):
        return [getattr(self, name) for name in self.NAMES]

    def bytes(self):
        return struct.pack("<22Q", *self.words())

    def copy(self, **fields):
        return Row(**dict({name: getattr(self, name) for name in self.NAMES}, **fields))


BASE_ROW = dict(ltv_tag=1, ltv=70000000000000, seed=0x5151, balance=7000, held=11, paid=13, max_px=9000, borrowed=50, borrow_index=ONE, supplied=70, borrow_cap=0, user_borrow_cap=0, supply_cap=1000, user_supply_cap=100, supply_index=ONE,
                rate_0=0x1001, rate_1=0x1002, rate_2=0x1003, rate_3=0x1004, stamp_0=0x7777, stamp_1=0x8888)


class Case:
    DEFAULTS = dict(kind="reserve", copy=0, word=2, value=0, values=(), chain=0, token=2, tokens=6, b=None, s=None, ub=None, us=None, l=None, l_value=None, y=None, y_cap=0, min_text=None, max_text=None, min_value=None, max_value=None,
                    bad_text=False, bad_ltv=False, bad_curve=False, bad_min=False, bad_max=False, rows=(), quote=(), stale=None, seed_value=0x2525, time_word=0x6161616161616161, time_tail=0x62626262, depth=1,
                    amount=0, side=0, keep=0, new=(), old=(), rec=None, sat=False)

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
            hooks = (SLOT_FREE, SLOT_ALLOC, SLOT_REALLOC, SLOT_COPY, SLOT_MOVE, SLOT_CMP, SLOT_BCMP, SLOT_SET, SLOT_FORMAT, SLOT_TEXT, SLOT_LTV, SLOT_CURVE, SLOT_PRICE, SLOT_SEED, SLOT_RECORD) + PANIC_SLOTS
            for slot in hooks:
                table[slot] = MARK_BASE + slot
            Harness.statics = table
        machine.memory.statics = Harness.statics
        for slot, hook in ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set),
                           (SLOT_FORMAT, self.on_format), (SLOT_TEXT, self.on_text), (SLOT_LTV, self.on_ltv), (SLOT_CURVE, self.on_curve), (SLOT_PRICE, self.on_price), (SLOT_SEED, self.on_seed), (SLOT_RECORD, self.on_record)):
            machine.slots[MARK_BASE + slot] = hook
        for slot in PANIC_SLOTS:
            machine.slots[MARK_BASE + slot] = self.on_panic
        machine.real = AllCode()
        machine.calls = {RESUME: self.on_panic}
        self.case = None
        self.live = {}
        self.events = []
        self.warned = []
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

    def on_record(self, machine):
        self.events.append("saturated")

    def on_format(self, machine):
        memory = machine.memory
        out, pieces, args = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]

        def word(index):
            return memory.read(memory.read(memory.read(args + 16 * index, 8), 8), 8)

        def flag(index):
            return memory.read(memory.read(memory.read(args + 16 * index, 8), 8), 1)

        if pieces == PIECES_INVALID:
            self.warned.append(("invalid", word(0)) + tuple(flag(index) for index in range(1, 7)))
        else:
            self.expect(pieces in (PIECES_CAP, PIECES_USER), "format text of the check")
            self.warned.append(("cap" if pieces == PIECES_CAP else "user", word(0), word(1), word(2)))
        at = self.bump(8)
        memory.write(out, 8, 8)
        memory.write(out + 8, 8, at)
        memory.write(out + 0x10, 8, 8)

    def on_text(self, machine):
        memory, case = machine.memory, self.case
        out, pointer, size = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.expect(size <= TEXT_LIMIT, "length gate ran first")
        self.expect((memory.bytes_at(pointer, size) if size else b"") == case.l, "ltv text")
        self.events.append("text")
        if case.bad_text:
            memory.put_bytes(out, object_bytes(TAG_BAD_TEXT))
            return
        memory.write(out, 2, OK)
        memory.put_bytes(out + 4, bytes(range(0xA0, 0xB0)))

    def on_ltv(self, machine):
        memory, case = machine.memory, self.case
        out, record = machine.regs[RDI], machine.regs[RSI]
        self.expect(memory.bytes_at(record, 16) == bytes(range(0xA0, 0xB0)), "decimal passed on whole")
        self.events.append("ltv")
        if case.bad_ltv:
            memory.write(out, 8, 2)
        elif case.l_value is None:
            memory.write(out, 8, 0)
        else:
            memory.write(out, 8, 1)
            memory.write(out + 8, 8, case.l_value)

    def on_curve(self, machine):
        memory, case = machine.memory, self.case
        out, record = machine.regs[RDI], machine.regs[RSI]
        self.events.append("curve")
        self.expect(memory.bytes_at(record, 0x60) == memory.bytes_at(ACTION + 0x58, 0x60), "curve record passed on whole")
        if case.bad_curve:
            memory.put_bytes(out, object_bytes(TAG_BAD_CURVE))
            return
        memory.write(out, 2, OK)
        for index, value in enumerate(case.y):
            memory.write(out + 8 + 8 * index, 8, value)

    def on_price(self, machine):
        memory, case = machine.memory, self.case
        out, record, token, meta = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX]
        self.expect(token == case.token, "price token")
        self.expect(meta == S + 0x90, "price state")
        cap, pointer, size = (memory.read(record + offset, 8) for offset in (0, 8, 0x10))
        which = sum(1 for event in self.events if event == "price")
        self.events.append("price")
        text = case.min_text if which == 0 else case.max_text
        value = case.min_value if which == 0 else case.max_value
        bad = case.bad_min if which == 0 else case.bad_max
        if text is None:
            self.expect(cap == LIMIT_MIN, "absent price text")
            memory.write(out, 2, OK)
            memory.write(out + 8, 8, 0)
            memory.write(out + 0x10, 8, 0x5A5A)
            return
        self.expect(memory.bytes_at(pointer, size) == text, "price text")
        if cap:
            self.expect(self.live.pop(pointer, None) == cap, "price text freed once")
        if bad:
            memory.put_bytes(out, object_bytes(TAG_BAD_TEXT))
            return
        memory.write(out, 2, OK)
        memory.write(out + 8, 8, 1 if value == 0 else 2)
        memory.write(out + 0x10, 8, value or 0x5C5C)

    def on_seed(self, machine):
        self.expect(machine.regs[RDI] == S + 0x90, "seed state")
        self.expect(machine.regs[RSI] == self.case.token, "seed token")
        self.events.append("seed")
        machine.regs[RAX] = self.case.seed_value

    def node(self, items, stale, size, layout):
        memory = self.machine.memory
        at = self.bump(size)
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
        memory.write(at + layout.parent_at, 8, 0)
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(11):
            memory.write(at + layout.key_at + 8 * slot, 8, stale)
        for slot, (key, value) in enumerate(items):
            memory.write(at + layout.key_at + 8 * slot, 8, key)
            memory.put_bytes(at + layout.val_at + layout.val_size * slot, value)
        return at

    def tree(self, items, stale, layout):
        memory = self.machine.memory
        if not items:
            return 0, 0xFEED, 0
        if len(items) <= 11:
            return self.node(items, stale, layout.leaf, layout), 0, len(items)
        parts, seps, at = [], [], 0
        while len(items) - at > 11:
            parts.append(items[at:at + 5])
            seps.append(items[at + 5])
            at += 6
        parts.append(items[at:])
        kids = [self.node(part, stale, layout.leaf, layout) for part in parts]
        root = self.node(seps, stale, layout.inner, layout)
        for slot, kid in enumerate(kids):
            memory.write(root + layout.edge_at + 8 * slot, 8, kid)
            memory.write(kid + layout.parent_at, 8, root)
            memory.write(kid + layout.index_at, 2, slot)
        return root, 1, len(items)

    def walk(self, root, height, layout):
        memory = self.machine.memory
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
                    rows.append((memory.read(at + layout.key_at + 8 * slot, 8), memory.bytes_at(at + layout.val_at + layout.val_size * slot, layout.val_size)))
        if root:
            visit(root, height, 0, 0)
        return rows, nodes

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:len(HEAP_FILL)] = HEAP_FILL
        self.case = case
        self.events = []
        self.warned = []
        self.live = {}
        self.cur = BUMP
        self.machine.steps_at = self.machine.steps

    def text(self, value):
        """A heap string as (cap, pointer, length), or the None niche."""
        if value is None:
            return LIMIT_MIN, 0x7171, 0
        if not value:
            return 0, 1, 0
        at = self.bump(len(value))
        self.machine.memory.put_bytes(at, value)
        return len(value), at, len(value)

    def put_words(self, at, values):
        for index, value in enumerate(values):
            self.machine.memory.write(at + 8 * index, 8, value)

    def base_state(self, case):
        memory = self.machine.memory
        memory.write(S + 0x218, 8, case.tokens)
        memory.write(S + 0x210, 8, 1)
        memory.write(S + 0x60, 8, case.time_word)
        memory.write(S + 0x68, 4, case.time_tail)
        memory.write(S + 0x8F2, 1, case.chain)
        items = sorted(((token, row.bytes()) for token, row in case.rows))
        stale = case.stale if case.stale is not None else 1
        root, height, count = self.tree(items, stale, L_RESERVE)
        memory.write(S + TREE_AT, 8, root)
        memory.write(S + TREE_AT + 8, 8, height)
        memory.write(S + TREE_AT + 0x10, 8, count)
        quote = sorted((token, b"\x01") for token in case.quote)
        root, height, count = self.tree(quote, stale, L_QUOTE)
        memory.write(S + QUOTE_AT, 8, root)
        memory.write(S + QUOTE_AT + 8, 8, height)

    def run_reserve(self, case):
        memory = self.machine.memory
        self.base_state(case)
        nodes_before = set(self.live)
        given = lambda value: 0 if value is None else 1
        ltv = self.text(case.l)
        block = [memory.read(ACTION + 0x58, 8)]
        self.put_words(ACTION, (given(case.b), case.b or 0, given(case.s), case.s or 0, given(case.ub), case.ub or 0, given(case.us), case.us or 0) + ltv)
        if case.y is None:
            self.put_words(ACTION + 0x58, (LIMIT_MIN,) + (0x7171,) * 11)
        else:
            parts = []
            for index in range(4):
                parts.extend(self.text(bytes([0x61 + index]) * case.y_cap if case.y_cap else b""))
            if case.y_cap:
                parts[0] = case.y_cap
            self.put_words(ACTION + 0x58, parts)
            if case.y_cap:
                memory.write(ACTION + 0x58, 8, case.y_cap)
        self.put_words(ACTION + 0xB8, self.text(case.min_text) + self.text(case.max_text) + (case.token,))
        before = bytes(memory.heap[S - HEAP_BASE:S - HEAP_BASE + 0x2000])
        copy = COPIES[case.copy]
        self.machine.run(copy.entry(self.image), {RDI: OUT, RSI: ACTION, RDX: S})
        root, height = memory.read(S + TREE_AT, 8), memory.read(S + TREE_AT + 8, 8)
        rows, nodes = self.walk(root, height, L_RESERVE)
        count = memory.read(S + TREE_AT + 0x10, 8)
        after = bytearray(memory.heap[S - HEAP_BASE:S - HEAP_BASE + 0x2000])
        after[TREE_AT:TREE_AT + 0x18] = before[TREE_AT:TREE_AT + 0x18]
        status = memory.read(OUT, 2)
        word1 = memory.read(OUT + 8, 8)
        leftover = tuple(sorted(at for at in self.live if at not in nodes and at not in nodes_before))
        return dict(status=status, word1=word1, nested=memory.read(OUT + 2, 1), rows=tuple((key, row_view(value)) for key, value in rows), count=count, state_same=bytes(after) == before, leftover=leftover, warned=tuple(self.warned), events=tuple(self.events), out=memory.bytes_at(OUT, 0x60))

    def run_word(self, case):
        memory = self.machine.memory
        memory.put_bytes(S, bytes([FILL]) * 0x2000)
        memory.write(S + 0x8F2 + (SHIFT_C if case.copy == 2 else 0), 1, case.chain)
        if case.word == 14:
            self.put_words(ACTION, (case.word,) + tuple(case.values))
        else:
            self.put_words(ACTION, (case.word, case.value))
        before = bytes(memory.heap[S - HEAP_BASE:S - HEAP_BASE + 0x2000])
        self.machine.run(COPIES[case.copy].entry(self.image), {RDI: OUT, RSI: ACTION, RDX: S})
        after = bytes(memory.heap[S - HEAP_BASE:S - HEAP_BASE + 0x2000])
        changes = {}
        at = 0
        while at < 0x2000:
            if after[at] != before[at]:
                base = at & ~7
                changes[base] = struct.unpack_from("<Q", after, base)[0]
                at = base + 8
            else:
                at += 1
        return dict(status=memory.read(OUT, 2), word1=memory.read(OUT + 8, 8), changes=tuple(sorted(changes.items())), out=memory.bytes_at(OUT, 0x10))

    def run_gate(self, case):
        memory = self.machine.memory
        for at, items in ((SIDE_A, case.new), (SIDE_B, case.old)):
            values = sorted((token, struct.pack("<4Q", 0x7E7E, low, 0x7F7F, high)) for token, low, high in items)
            root, height, _ = self.tree(values, case.stale if case.stale is not None else 1, L_SIDE)
            memory.write(at + 0x18, 8, root)
            memory.write(at + 0x20, 8, height)
        memory.put_bytes(RECORD, case.rec.bytes())
        memory.write(STACK_TOP - 0x100, 8, RECORD)
        result = self.machine.run(GATE, {RDI: SIDE_A, RSI: SIDE_B, RDX: case.amount, RCX: case.token, R8: case.side, R9: case.keep})
        return dict(status=result & 0xFF, saturated=self.events.count("saturated"))

    def run(self, case):
        self.fresh(case)
        return getattr(self, "run_" + case.kind)(case)


def row_view(value):
    """The last four bytes of a row are padding behind the 32-bit stamp."""
    return value[:ROW_SIZE - 4]


def spec_check(token, row, quote):
    """The warnings the check produces for a row, in order."""
    is_quote = token in quote
    has_ltv = row.ltv_tag & 0xFF
    borrow = row.borrow_cap != 0
    user = row.user_borrow_cap != 0
    has_min = row.min_px != 0
    has_max = row.max_px != 0
    good = (not is_quote and has_ltv and not borrow and not user and not has_min and has_max) or (not has_ltv and token == 0) or (is_quote and not has_ltv and has_min and not has_max)
    out = []
    if not good:
        out.append(("invalid", token, int(is_quote), int(bool(has_ltv)), int(borrow), int(user), int(has_min), int(has_max)))
    if row.borrow_cap > row.supply_cap:
        out.append(("cap", token, row.borrow_cap, row.supply_cap))
    if row.user_borrow_cap > row.user_supply_cap:
        out.append(("user", token, row.user_borrow_cap, row.user_supply_cap))
    return out


def price_tag(text, value):
    return 0 if text is None else 1 if value == 0 else 2


def spec_reserve(case):
    """Refusals in dispatch order, then the patch or the new row."""
    rows = {token: row for token, row in case.rows}
    keep = lambda: tuple((key, row_view(rows[key].bytes())) for key in sorted(rows))
    refused = lambda status, **extra: dict(status=status, rows=keep(), warned=(), **extra)
    if case.token >= case.tokens:
        return refused(TAG_TOKEN, word1=case.token)
    if case.l is not None:
        if len(case.l) > TEXT_LIMIT:
            return refused(TAG_LENGTH)
        if case.bad_text:
            return refused(TAG_BAD_TEXT)
        if case.bad_ltv:
            return refused(TAG_NESTED, nested=0xA)
    if case.y is not None and case.bad_curve:
        return refused(TAG_BAD_CURVE)
    if case.s is not None and case.s >= CAP:
        return refused(TAG_NUMBER)
    if case.b is not None and case.b >= CAP:
        return refused(TAG_NUMBER, word1=1)
    if case.us is not None and case.us >= CAP:
        return refused(TAG_NUMBER)
    if case.ub is not None and case.ub >= CAP:
        return refused(TAG_NUMBER)
    if case.min_text is not None and case.bad_min:
        return refused(TAG_BAD_TEXT)
    if case.max_text is not None and case.bad_max:
        return refused(TAG_BAD_TEXT)
    ltv_tag = 0 if case.l is None else 1 if case.l_value is None else 2
    min_tag, max_tag = price_tag(case.min_text, case.min_value), price_tag(case.max_text, case.max_value)
    if case.token in rows:
        row = rows[case.token].copy()
        if case.y is not None:
            row.rate_0, row.rate_1, row.rate_2, row.rate_3 = case.y
        if ltv_tag == 2:
            row.ltv_tag, row.ltv = 1, case.l_value
        elif ltv_tag == 1:
            row.ltv_tag = 0
        for field, value in (("borrow_cap", case.b), ("supply_cap", case.s), ("user_borrow_cap", case.ub), ("user_supply_cap", case.us)):
            if value is not None:
                setattr(row, field, value)
        if min_tag:
            row.min_px = case.min_value
        if max_tag:
            row.max_px = case.max_value
        warned = spec_check(case.token, row, case.quote)
        if warned:
            return dict(status=TAG_NESTED, nested=0xA, rows=keep(), warned=tuple(warned))
        rows[case.token] = row
        return dict(status=OK, rows=keep(), warned=())
    complete = ltv_tag and min_tag and max_tag and case.y is not None and None not in (case.b, case.s, case.ub, case.us)
    if not complete or (ltv_tag == 2 and min_tag != 1):
        return dict(status=TAG_NESTED, nested=0xA, rows=keep(), warned=())
    row = Row(ltv_tag=int(ltv_tag == 2), ltv=case.l_value if ltv_tag == 2 else ltv_word(case), seed=case.seed_value, min_px=case.min_value if min_tag == 2 and ltv_tag == 1 else 0, max_px=case.max_value if max_tag == 2 else 0, borrow_cap=case.b, user_borrow_cap=case.ub, borrow_index=ONE,
              supply_cap=case.s, user_supply_cap=case.us, supply_index=ONE, rate_0=case.y[0], rate_1=case.y[1], rate_2=case.y[2], rate_3=case.y[3], stamp_0=case.time_word, stamp_1=case.time_tail)
    warned = spec_check(case.token, row, case.quote)
    if warned:
        return dict(status=TAG_NESTED, nested=0xA, rows=keep(), warned=tuple(warned))
    rows[case.token] = row
    return dict(status=OK, rows=keep(), warned=())


def ltv_word(case):
    """With no LTV the new row's word 1 holds the field the arm passed: the min price tag word."""
    return 1 if case.min_text is not None and case.min_value == 0 else 2 if case.min_text is not None else 0


def spec_word(case):
    if case.word in FLAGS:
        base = bytearray([FILL]) * 8
        base[FLAGS[case.word] & 7] = case.value & 1
        return dict(status=OK, changes=((FLAGS[case.word] & ~7, struct.unpack("<Q", base)[0]),))
    if case.word in CAPS:
        if case.value >= CAP:
            return dict(status=TAG_NUMBER, word1=case.value, changes=())
        return dict(status=OK, changes=((CAPS[case.word], case.value),))
    if case.word == 8:
        return dict(status=TAG_TESTNET, changes=())
    words = {8 * index + 8: value for index, value in enumerate(case.values)}
    changes = {}
    for kind, flag_at, value_at, target in RATE_FIELDS:
        value = words[value_at]
        if kind == "flag" and not words[flag_at] & 1:
            continue
        if kind == "nonzero" and value == 0:
            continue
        if value >= CAP:
            return dict(status=TAG_NUMBER, word1=value, changes=tuple(sorted(changes.items())))
        changes[target] = value
    return dict(status=OK, changes=tuple(sorted(changes.items())))


def ceil_div(left, right):
    return -(-left // right)


def spec_room(rec):
    """The real room helper: status byte or room."""
    borrowed = ceil_div(rec.borrowed * rec.borrow_index, ONE)
    supplied = rec.supplied * rec.supply_index // ONE
    if borrowed >> 64:
        return STATUS_OVERFLOW, 0, 0
    if rec.supplied * rec.supply_index >> 64 >= ONE:
        return STATUS_OVERFLOW, 0, 0
    if supplied >> 64:
        raise EvidenceError("quotient past 64 bits behind the guard")
    saturated = 0
    left = rec.balance + borrowed
    if left >> 64:
        left, saturated = MASK[8], saturated + 1
    right = rec.paid + supplied
    if right >> 64:
        right, saturated = MASK[8], saturated + 1
    if left < right:
        return STATUS_SHORT, 0, saturated
    rest = rec.held + rec.paid
    if rest >> 64:
        rest, saturated = MASK[8], saturated + 1
    room = rest + (left - right)
    if room >> 64:
        room, saturated = MASK[8], saturated + 1
    return None, room, saturated


def spec_gate(case):
    rec = case.rec
    index = rec.borrow_index if case.side & 1 else rec.supply_index

    def scaled(items):
        for token, low, high in items:
            if token == case.token:
                value = low if case.side & 1 else high
                product = value * index
                return ceil_div(product, ONE) if case.side & 1 else product // ONE
        return 0

    first = scaled(case.old)
    if first >> 64:
        return dict(status=STATUS_OVERFLOW, saturated=0)
    second = scaled(case.new)
    if second >> 64:
        return dict(status=STATUS_OVERFLOW, saturated=0)
    if not (first >= second if case.keep & 1 else first <= second):
        return dict(status=STATUS_SHORT, saturated=0)
    status, room, saturated = spec_room(rec)
    if status is not None:
        return dict(status=status, saturated=saturated)
    return dict(status=STATUS_SHORT if case.amount > room else STATUS_OK, saturated=saturated)


def spec_for(case):
    return {"reserve": spec_reserve, "word": spec_word, "gate": spec_gate}[case.kind](case)


def same(case, got, want):
    if not all(got.get(key) == value for key, value in want.items()):
        return False
    if case.kind != "reserve":
        return True
    status = want["status"]
    if status in (TAG_BAD_TEXT, TAG_BAD_CURVE) and got["out"] != object_bytes(status):
        return False
    if status == TAG_NUMBER and got["out"][2:8] != bytes(6):
        return False
    return got["state_same"] and not got["leftover"] and got["count"] == len(got["rows"])


CURVE = (0x3FB0000000000001, 0x3FD0000000000002, 0x3FC0000000000003, 0x3FE0000000000004)
SIDE_ROW = dict(balance=7000, held=11, paid=13, borrowed=50, borrow_index=ONE, supplied=70, supply_index=ONE)
REACH_CAP = 8
SECOND_CAP = 500
UNCLASSIFIED = "not classified"
SURVIVOR_GROUPS = (
    ("the check reads none of these row words, so the working copy may hold anything there", (0x37418AF, 0x37418C1, 0x37418C7, 0x37418DD, 0x37418EE, 0x37418FB, 0x374199C, 0x37419A0, 0x37419B4, 0x37419B9)),
    ("the warning text length is never read: the list is freed by capacity and pointer", (0x3740554, 0x3740634, 0x37406F0)),
    ("empty list pointer: not read before the first push", (0x3740331,)),
    ("any status but 0x11 gives the same 0xe1 with inner 0xa at the dispatcher", (0x3741FDA,)),
    ("a larger node length: sorted keys stop the search first", (0x3734E4B,)),
    ("drop flag of the arm: every case frees every string either way", (0x235C4E8, 0x235C505, 0x235D6F7, 0x235D972, 0x4CB0E7D, 0x4CB0E9A, 0x4CB20CF, 0x4CB2348, 0x4CB980D, 0x4CB982A, 0x4CBAA5F, 0x4CBACD8)),
    ("entry height word: this path reaches a leaf, the insert did not read it", (0x3741A3F,)),
)


def survivor_reason(va, kind):
    for reason, addresses in SURVIVOR_GROUPS:
        if va in addresses:
            return reason
    return UNCLASSIFIED

VECTORS = 600
MUTANT_VECTORS = 200
REFERENCE = (
    ("l1/action/vote_global.rs SetBoleAction", "Reserve is a unit variant, the rest are raw bytes", "Reserve carries nine fields; the serde text says 9 elements and the arm reads them"),
    ("l1/action/vote_global.rs LowTagVoteGlobalAction", "raw tags below 0x12 are perp dex selectors", "words 0 to 17 share the niche of the SetBole payload and reach sub table 0x3dd340 through entry 0x4e"),
    ("l1/action/vote_global.rs raw 0x62", "SetBole(SetBoleAction)", "the selector maps every word below 0x12 to entry 0x4e; no separate 0x62 entry reaches this arm"),
)



def base_row(**fields):
    return Row(**dict(BASE_ROW, **fields))


def reserve_cases():
    cases = []

    def add(label, **fields):
        fields.setdefault("rows", ((2, base_row()),))
        cases.append(("reserve " + label, fields))

    add("no field given")
    add("token at the count", token=6)
    add("token past the count", token=0xFFFF)
    add("last token", token=5, rows=((5, base_row()),))
    add("set supply cap", s=2000)
    add("set supply cap zero", s=0, b=None, rows=((2, base_row(supply_cap=9)),))
    add("set user supply cap", us=7)
    add("set borrow and cap on a quote row", token=2, quote=(2,), b=5, s=9, rows=((2, base_row(ltv_tag=0, ltv=0, min_px=5, max_px=0)),))
    add("borrow cap equals supply cap", quote=(2,), b=9, s=9, rows=((2, base_row(ltv_tag=0, ltv=0, min_px=5, max_px=0)),))
    add("borrow cap above supply cap", quote=(2,), b=10, s=9, rows=((2, base_row(ltv_tag=0, ltv=0, min_px=5, max_px=0)),))
    add("user borrow equals user supply", quote=(2,), ub=9, us=9, rows=((2, base_row(ltv_tag=0, ltv=0, min_px=5, max_px=0)),))
    add("user borrow above user supply", quote=(2,), ub=10, us=9, rows=((2, base_row(ltv_tag=0, ltv=0, min_px=5, max_px=0)),))
    add("all three warnings", b=10, s=9, ub=10, us=9, rows=((2, base_row()),))
    add("set ltv", l=b"0.7", l_value=60000000000000)
    add("clear ltv refused by the check", l=b"0", l_value=None)
    add("clear ltv on token 0", token=0, l=b"0", l_value=None, rows=((0, base_row()),))
    add("ltv text 100 bytes", l=b"0" * 100, l_value=5)
    add("ltv text 101 bytes", l=b"0" * 101)
    add("ltv text empty", l=b"", l_value=5)
    add("ltv text parse refused", bad_text=True, l=b"0.7")
    add("ltv value refused", bad_ltv=True, l=b"9")
    add("curve set", y=CURVE)
    add("curve refused", y=CURVE, bad_curve=True)
    add("curve dropped on a refused ltv", y=CURVE, y_cap=2, bad_text=True, l=b"x")
    add("curve dropped on a token refusal", y=CURVE, y_cap=2, token=9)
    add("min price set refused by the check", min_text=b"1.5", min_value=77)
    add("max price set", max_text=b"2.5", max_value=88)
    add("max price cleared refused", max_text=b"0", max_value=0)
    add("min price cleared", min_text=b"0", min_value=0, rows=((2, base_row(min_px=9)),), quote=())
    add("min price refused", min_text=b"x", bad_min=True, max_text=b"2", max_value=1)
    add("max price refused", min_text=b"1", min_value=0, max_text=b"y", bad_max=True)
    add("max price refused, no min", max_text=b"y", bad_max=True)
    for name, field in (("s", "supply"), ("b", "borrow"), ("us", "user supply"), ("ub", "user borrow")):
        add("%s at the cap" % field, **{name: CAP})
        add("%s top" % field, **{name: MASK[8]})
        add("%s one below the cap, rejected or not by the check" % field, **{name: CAP - 1}, rows=((2, base_row(supply_cap=CAP - 1, user_supply_cap=CAP - 1)),))
    add("refusal order: supply over borrow", s=CAP, b=CAP)
    add("refusal order: borrow over user supply", b=CAP, us=CAP)
    add("refusal order: user supply over user borrow", us=CAP, ub=CAP)
    add("refusal order: curve over supply", y=CURVE, bad_curve=True, s=CAP)
    add("refusal order: ltv over curve", l=b"9", bad_ltv=True, y=CURVE, bad_curve=True)
    add("refusal order: supply over price", s=CAP, min_text=b"x", bad_min=True)
    add("refusal order: token over ltv", token=8, l=b"9", bad_ltv=True)
    full = dict(b=0, s=100, ub=0, us=50, y=CURVE, l=b"0.7", l_value=50000000000000, min_text=b"0", min_value=0, max_text=b"9", max_value=321, rows=())
    add("new row with ltv", **full)
    add("new row quote", **dict(full, quote=(2,), l=b"0", l_value=None, b=7, ub=3, min_text=b"1", min_value=44, max_text=b"0", max_value=0))
    add("new row token 0", **dict(full, token=0, l=b"0", l_value=None, b=1, ub=1, min_text=b"0", min_value=0, max_text=b"0", max_value=0))
    add("new row, ltv and a min price", **dict(full, min_value=4, min_text=b"1"))
    add("new row, ltv absent", **dict(full, l=None))
    add("new row, min absent", **dict(full, min_text=None))
    add("new row, max absent", **dict(full, max_text=None))
    add("new row, curve absent", **dict(full, y=None))
    for name in ("b", "s", "ub", "us"):
        add("new row, %s absent" % name, **dict(full, **{name: None}))
    add("new row, fails the check", **dict(full, l=b"0", l_value=None))
    add("new row, borrow over supply", **dict(full, b=200, quote=(2,), l=b"0", l_value=None, min_text=b"1", min_value=44, max_text=b"0", max_value=0))
    add("set ltv on a row with none", l=b"7", l_value=5, rows=((2, base_row(ltv_tag=0, ltv=0)),))
    add("set ltv, clear both borrow caps", l=b"7", l_value=5, b=0, ub=0, rows=((2, base_row(ltv_tag=0, ltv=0, borrow_cap=5, user_borrow_cap=5)),))
    add("set ltv, patch user supply", l=b"7", l_value=5, us=33, s=44, rows=((2, base_row(ltv_tag=0, ltv=0)),))
    add("set ltv, clear min, set max", l=b"7", l_value=5, min_text=b"0", min_value=0, max_text=b"8", max_value=77, y=CURVE, rows=((2, base_row(ltv_tag=0, ltv=0, min_px=5)),))
    add("set ltv, supply cap and user borrow cap", l=b"7", l_value=5, s=44, ub=0, rows=((2, base_row(ltv_tag=0, ltv=0, user_borrow_cap=5)),))
    add("max price cleared on a quote row", quote=(2,), max_text=b"0", max_value=0, rows=((2, base_row(ltv_tag=0, ltv=0, min_px=5, max_px=3)),))
    add("new row, ltv top byte", **dict(full, l_value=0x0123456789ABCDEF))
    add("new row, quote tree misses", **dict(full, quote=(1, 7)))
    add("new row, two warnings", **dict(full, b=200, ub=99))
    add("new row, three warnings", **dict(full, l=b"0", l_value=None, b=200, ub=99))
    many = tuple((key, base_row(seed=key)) for key in range(10, 10 + 11))
    add("new row into a full leaf", **dict(full, token=25, tokens=30, rows=many))
    add("new row into a leaf with room", **dict(full, token=3, rows=((1, base_row()), (5, base_row(seed=7)))))
    add("new row, first key in an inner tree", **dict(full, token=0, tokens=40, l=b"0", l_value=None, b=1, ub=1, min_text=b"0", min_value=0, max_text=b"0", max_value=0, rows=tuple((key, base_row(seed=key)) for key in range(10, 25))))
    tree = tuple((key, base_row(seed=key)) for key in range(1, 15))
    for token in (1, 4, 6, 7, 10, 14):
        add("existing row %d in a tree of 14" % token, token=token, tokens=30, s=31, rows=tree)
    add("stale key in unused slots", token=3, s=31, rows=((1, base_row()), (2, base_row(seed=2)), (5, base_row(seed=5))), stale=3)
    add("absent key equal to a stale key", token=3, rows=((1, base_row()),), stale=3)
    add("quote key found in a tree", quote=tuple(range(1, 15)), token=7, tokens=30, rows=((7, base_row(ltv_tag=0, ltv=0, min_px=5, max_px=0)),))
    add("quote stale key", quote=(1, 5), stale=2, rows=((2, base_row()),))
    return [Case(label, **fields) for label, fields in cases]


def validity_cases():
    cases = []
    for token, quote, ltv, borrow, user, low, high in itertools.product((0, 2), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1)):
        row = base_row(ltv_tag=ltv, borrow_cap=borrow * 3, user_borrow_cap=user * 3, min_px=low * 5, max_px=high * 6, supply_cap=9, user_supply_cap=9)
        cases.append(Case("check t%d q%d l%d b%d u%d m%d M%d" % (token, quote, ltv, borrow, user, low, high), token=token, quote=(token,) if quote else (), rows=((token, row),)))
    return cases


def new_row_cases():
    cases = []
    for ltv, low, high, curve in itertools.product((None, 0, 5), (None, 0, 5), (None, 0, 5), (0, 1)):
        fields = dict(b=0, s=100, ub=0, us=50, token=2, quote=())
        if ltv is not None:
            fields.update(l=b"3", l_value=ltv or None)
        if low is not None:
            fields.update(min_text=b"4", min_value=low)
        if high is not None:
            fields.update(max_text=b"5", max_value=high)
        if curve:
            fields.update(y=CURVE)
        cases.append(Case("new l%s m%s M%s y%d" % (ltv, low, high, curve), **fields))
    return cases


def word_cases():
    cases = []
    for word in sorted(FLAGS):
        for value in (0, 1, 2, 0xFF, 0xFE):
            cases.append(Case("word %d value %#x" % (word, value), kind="word", word=word, value=value))
    for word in sorted(CAPS):
        for value in (0, 1, CAP - 1, CAP, MASK[8]):
            cases.append(Case("word %d value %#x" % (word, value), kind="word", word=word, value=value))
    cases.append(Case("word 8 on the mainnet byte", kind="word", word=8, chain=3))
    empty = [0] * 11
    cases.append(Case("rate limit all absent", kind="word", word=14, values=tuple(empty)))
    for index, (kind, flag_at, value_at, target) in enumerate(RATE_FIELDS):
        for value in (5, CAP - 1, CAP, MASK[8]):
            words = list(empty)
            if kind == "flag":
                words[flag_at // 8 - 1] = 1
            words[value_at // 8 - 1] = value
            cases.append(Case("rate limit field %#x value %#x" % (target, value), kind="word", word=14, values=tuple(words)))
        if kind == "flag":
            words = list(empty)
            words[value_at // 8 - 1] = 9
            cases.append(Case("rate limit field %#x flag clear" % target, kind="word", word=14, values=tuple(words)))
    words = [1, 21, 1, 22, 1, 23, 1, 24, 25, 26, 27]
    words[RATE_FIELDS[3][2] // 8 - 1] = CAP
    cases.append(Case("rate limit writes before the refusal stay", kind="word", word=14, values=tuple(words)))
    return cases


def gate_cases():
    cases = []
    plain = Row(**SIDE_ROW)

    def add(label, **fields):
        fields.setdefault("rec", plain)
        fields.setdefault("token", 3)
        cases.append(Case("gate " + label, kind="gate", **fields))

    for side in (0, 1):
        for keep in (0, 1):
            tag = "side %d keep %d" % (side, keep)
            add(tag + ", both absent", side=side, keep=keep)
            add(tag + ", old only", side=side, keep=keep, old=((3, 8, 9),))
            add(tag + ", new only", side=side, keep=keep, new=((3, 8, 9),))
            add(tag + ", equal", side=side, keep=keep, old=((3, 8, 9),), new=((3, 8, 9),))
            add(tag + ", old above", side=side, keep=keep, old=((3, 9, 10),), new=((3, 8, 9),))
            add(tag + ", old below", side=side, keep=keep, old=((3, 7, 8),), new=((3, 8, 9),))
            add(tag + ", other token only", side=side, keep=keep, old=((2, 7, 8),), new=((4, 8, 9),))
            add(tag + ", stale key", side=side, keep=keep, old=((1, 7, 8), (5, 7, 8)), new=((1, 8, 9), (5, 8, 9)), stale=3)
            add(tag + ", rounding: index 1.5", side=side, keep=keep, old=((3, 1, 1),), new=((3, 1, 1),), rec=Row(**dict(SIDE_ROW, borrow_index=3 * ONE // 2, supply_index=3 * ONE // 2)))
            add(tag + ", rounding differs a step", side=side, keep=keep, old=((3, 3, 3),), new=((3, 2, 2),), rec=Row(**dict(SIDE_ROW, borrow_index=ONE // 3, supply_index=ONE // 3)))
            add(tag + ", first past 64 bits", side=side, keep=keep, old=((3, MASK[8], MASK[8]),), rec=Row(**dict(SIDE_ROW, borrow_index=ONE * 2, supply_index=ONE * 2)))
            add(tag + ", second past 64 bits", side=side, keep=keep, new=((3, MASK[8], MASK[8]),), rec=Row(**dict(SIDE_ROW, borrow_index=ONE * 2, supply_index=ONE * 2)))
    tall = tuple((token, token, token + 1) for token in range(1, 15))
    for token in (1, 6, 7, 12, 14):
        add("tall tree token %d" % token, token=token, new=tall, old=tall)
    room = spec_room(plain)[1]
    add("amount equals room", amount=room)
    add("amount past room", amount=room + 1)
    add("amount zero", amount=0)
    for label, fields in (("short side", dict(balance=0, borrowed=0, paid=5, supplied=0)), ("exact side", dict(balance=5, borrowed=0, paid=5, supplied=0)), ("balance top", dict(balance=MASK[8], borrowed=1, held=0, paid=0, supplied=0)), ("paid top", dict(paid=MASK[8], supplied=1, balance=MASK[8], borrowed=0, held=0)),
                          ("held top", dict(held=MASK[8], paid=1, balance=1, borrowed=0, supplied=0)), ("room top", dict(held=5, paid=5, balance=MASK[8], borrowed=0, supplied=0)), ("borrowed past 64 bits", dict(borrowed=MASK[8], borrow_index=2 * ONE)),
                          ("borrowed ceil", dict(borrowed=3, borrow_index=ONE // 3)), ("supplied past 64 bits", dict(supplied=MASK[8], supply_index=2 * ONE)), ("supplied guard edge", dict(supplied=ONE + 1, supply_index=(1 << 64) - 1)), ("supplied below edge", dict(supplied=ONE - 1, supply_index=(1 << 64) - 1)),
                          ("supplied floor", dict(supplied=5, supply_index=ONE // 3))):
        add("room: " + label, rec=Row(**dict(SIDE_ROW, **fields)), amount=1)
        add("room with side short: " + label, rec=Row(**dict(SIDE_ROW, **fields)), old=((3, 1, 1),), new=((3, 2, 2),), side=1, keep=1)
    return cases


def base_cases():
    named = reserve_cases() + validity_cases() + new_row_cases() + word_cases()
    copies = []
    for case in named:
        for copy in (0, 1, 2):
            fields = {key: getattr(case, key) for key in Case.DEFAULTS}
            fields["copy"] = copy
            copies.append(Case("%s, copy %s" % (case.name, COPIES[copy].name), **fields))
    return copies + gate_cases()


def lcg(seed):
    state = seed

    def next_value(bound):
        nonlocal state
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return (state >> 16) % bound

    return next_value


def vector_cases(count):
    pick = lcg(0x312111)
    out = []
    amounts = (0, 1, 3, 9, 10, 100, 101, CAP - 1, CAP, MASK[8])

    def amount():
        return amounts[pick(len(amounts))]

    def word():
        return (pick(1 << 16) << 48 | pick(1 << 16) << 32 | pick(1 << 16) << 16 | pick(1 << 16)) >> (pick(5) * 12)

    for index in range(count):
        if index % 2:
            token = pick(6)
            rows = tuple((key, base_row(ltv_tag=pick(2), ltv=key, min_px=pick(2) * 4, max_px=pick(2) * 5, borrow_cap=amounts[pick(5)], user_borrow_cap=amounts[pick(5)], supply_cap=amounts[pick(5)], user_supply_cap=amounts[pick(5)])) for key in range(1, 6) if pick(3))
            fields = dict(copy=pick(3), token=token, rows=rows, quote=tuple(key for key in range(6) if pick(2)))
            for name in ("b", "s", "ub", "us"):
                if pick(2):
                    fields[name] = amount()
            if pick(2):
                fields.update(l=b"4", l_value=(None, 6)[pick(2)])
            if not pick(8):
                fields["bad_ltv"] = True
            if pick(2):
                fields.update(min_text=b"7", min_value=(0, 5)[pick(2)])
            if pick(2):
                fields.update(max_text=b"8", max_value=(0, 6)[pick(2)])
            if pick(2):
                fields["y"] = CURVE
            out.append(Case("vector reserve %d" % index, **fields))
        else:
            rec = Row(balance=word(), held=word(), paid=word(), borrowed=word(), borrow_index=word(), supplied=word(), supply_index=word())
            out.append(Case("vector gate %d" % index, kind="gate", token=3, rec=rec, side=pick(2), keep=pick(2), amount=word(), old=((3, word(), word()),) if pick(4) else (), new=((3, word(), word()),) if pick(4) else ()))
    return out


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_for(case)
        if not same(case, got, want):
            raise EvidenceError("case %s: got %s want %s" % (case.name, {key: value for key, value in got.items() if key != "out"}, want))
        outcomes.append(got)
    return outcomes


def sub_table(image, copy):
    arm = copy.arm(image)
    data = bytes(image.blob[image.offset(arm):image.offset(arm) + 0x70])
    at = data.index(b"\x48\x8d\x05")
    return arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]


def word_rows(image):
    rows = []
    for copy in COPIES:
        table = sub_table(image, copy)
        for index in range(SUB_ARMS):
            arm = table + struct.unpack_from("<i", image.blob, image.offset(table + 4 * index))[0]
            word = "0,1" if index == 1 else str(index + 2)
            rows.append((copy.name, "%#x" % table, index, word, "%#x" % arm))
    return rows


def arm_windows(image, seen, cache):
    tables = {}
    for copy in COPIES:
        low, high = image.fde(copy.arm(image))
        head = low + 0x3F
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


def spread(items, cap=REACH_CAP):
    step = max(1, len(items) // cap)
    return items[::step]


def run_mutants(image, table, window, seen, cases, vectors):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    chosen = cases + vectors
    if first_failure(control, chosen) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    reach = collections.defaultdict(list)
    for case in chosen:
        control.machine.seen = set()
        control.run(case)
        for va in control.machine.seen:
            reach[va].append(case)
    groups = [table[target] for target in SUBJECTS] + [window["a"], window["b"], window["c"]]
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


def text_rows(image):
    rows = []
    for pieces in (PIECES_INVALID, PIECES_CAP, PIECES_USER):
        at = pieces
        parts = []
        while True:
            size = image.blob[at]
            at += 1
            if size == 0:
                break
            if size >= 0xC0:
                parts.append("{}")
                continue
            parts.append(bytes(image.blob[at:at + size]).decode("ascii").replace("\x40", "[at]"))
            at += size
        rows.append(("%#x" % pieces, "".join(parts)))
    return rows


def serde_rows(image):
    out = []
    for text in SERDE:
        at = image.blob.find(text)
        if at < 0:
            raise EvidenceError("text not in the image: %r" % text)
        out.append(("%#x" % at, text.decode()))
    return out


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, meaning in ((SLOT_APPLY, "reserve_apply"), (SLOT_GATE, "reserve_side_gate"), (SLOT_ROOM, "room helper, run real"), (SLOT_TEXT, "decimal text parser, hook"), (SLOT_LTV, "ltv gate, hook"), (SLOT_CURVE, "curve parser, hook"), (SLOT_PRICE, "price text parser, hook"), (SLOT_SEED, "seed word reader, hook"), (SLOT_RECORD, "saturation recorder, hook"), (SLOT_FORMAT, "format, hook")):
        rows.append(("%#x" % slot, "%#x" % relative.get(slot, 0), meaning))
    return rows


def validity_rows(cases, outcomes):
    rows = []
    for case, got in zip(cases, outcomes):
        if case.name.startswith("check ") and case.copy == 0:
            row = case.rows[0][1]
            rows.append((int(case.token == 0), int(bool(case.quote)), row.ltv_tag, int(row.borrow_cap != 0), int(row.user_borrow_cap != 0), int(row.min_px != 0), int(row.max_px != 0), "valid" if not got["warned"] else "invalid config"))
    return rows


def analyse(image, mutate=True, vectors=VECTORS):
    harness = Harness(image)
    cases = base_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in SUBJECTS}
    window = arm_windows(image, seen, harness.machine.cache)
    for target in SUBJECTS:
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in SUBJECTS}
    result = dict(table=table, window=window, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, texts=text_rows(image), serde=serde_rows(image), slots=slot_rows(image), words=word_rows(image), validity=validity_rows(cases, outcomes))
    if mutate:
        result["mutations"] = run_mutants(image, table, window, seen, cases, vector_cases(MUTANT_VECTORS))
    return result


def outcome_row(case, got):
    if case.kind == "reserve":
        label = "status %#x rows %d warnings %d" % (got["status"], len(got["rows"]), len(got["warned"]))
    elif case.kind == "word":
        label = "status %#x writes %d" % (got["status"], len(got["changes"]))
    else:
        label = "status %#x saturated %d" % (got["status"], got["saturated"])
    digest = hashlib.sha256(repr(sorted((key, value) for key, value in got.items() if key not in ("out", "word1", "leftover"))).encode()).hexdigest()[:16]
    return (case.kind, COPIES[case.copy].name if case.kind != "gate" else "-", case.name, label, digest)


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, row.data.hex(), row.op) for target in SUBJECTS for row in result["table"][target]])
    tsv("arm-rows.tsv", ("copy", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in sorted(result["window"]) for row in result["window"][name]])
    tsv("word-table.tsv", ("copy", "table", "index", "word", "arm"), result["words"])
    tsv("validity.tsv", ("token_is_0", "is_quote", "has_ltv", "borrow_cap_set", "user_borrow_cap_set", "has_min_px", "has_max_px", "result"), result["validity"])
    tsv("texts.tsv", ("address", "text"), result["texts"])
    tsv("serde.tsv", ("file_offset", "text"), result["serde"])
    tsv("slots.tsv", ("slot", "target", "meaning"), result["slots"])
    tsv("reference.tsv", ("reference", "says", "bytes say"), REFERENCE)
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

