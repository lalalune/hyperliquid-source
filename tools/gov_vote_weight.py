#!/usr/bin/env python3
"""Pin node #94 governance arithmetic: vote weight with the long term stake lock, proposal gates, quorum.

0x398d1a0 stores a vote, with the delegated total times four while the user's lock runs and unchanged
from 2^62 up. 0x3c0f350 raises the lockup time of every delegation of the voter to the proposal end.
0x398d540 applies the length, stake, duplicate and per user limits, then stores the end time and
trunc(f64(base) * rate). 0x398cc10 moves out every proposal whose end has come. The real bytes run under
recording stubs over real B-tree nodes, a separately written rule list predicts every run including all
fixture bytes, and every reached conditional row is mutated. No objdump or readelf output is parsed and
the binary is never executed. Standard library only.

    python3 tools/gov_vote_weight.py --out <dir>
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
HEAP_SIZE = 0x20000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 20000


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
SHIFTS = {1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
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
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd", "shrdi"):
            bits = 8 * width
            count = (self.regs[RCX] if op == "shrd" else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op == "shld":
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
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


VOTE = 0x398D1A0
RAISE = 0x3C0F350
PROPOSE = 0x398D540
DRAIN = 0x398CC10
TARGETS = (VOTE, RAISE, PROPOSE, DRAIN)
NAMES = {VOTE: "vote", RAISE: "lockup_raise", PROPOSE: "propose", DRAIN: "drain_ended"}

SLOT_VOTE = 0x57732D0
SLOT_PROPOSE = 0x5773338
SLOT_DRAIN = 0x5774920
SLOT_TOTAL = 0x5774900
SLOT_COMPARE = 0x576E488
SLOT_TIME = 0x576EFB8
SLOT_FREE = 0x576E010
SLOT_GROW = 0x5775700
UPSERT = 0x33A5470
INSERT = 0x339C6E0
REMOVE = 0x33AC460
DROP = 0x33F32F0
STATUS_TABLE = 0x59A8D0
TEST_SECONDS = 0x2084E0
LONG_SECONDS = 0x20A8D0
SHORT_SECONDS = 0x20AFA0
RATES = 0x20BB20
LIMIT_WORD = 0x20ADE8
SERIALIZER = 0x336C350
STATE_SERIALIZER_SITE = 0x238D9AB
PROPOSALS_KEY_FN = 0x23D2520
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_TITLE = 0x100
TAG_DESCRIPTION = 0x101
TAG_STAKE = 0x102
TAG_EXISTS = 0x103
TAG_LIMIT = 0x104
TAG_MISSING = 0x105
TAG_VOTED = 0x106
TAG_VOTE_STAKE = 0x107
TAG_ENDED = 0x108
TEXT_ARMS = (0xFF, TAG_TITLE, TAG_DESCRIPTION, TAG_STAKE, TAG_EXISTS, TAG_MISSING, TAG_VOTED, TAG_VOTE_STAKE, TAG_ENDED, 0x12C)
SIDE = 1 << 62
NONE_WORD = 1 << 63
MIN_STAKE = 1000000000

S_DELEGATIONS = 0x168
S_PROPOSALS = 0x198
S_USERS = 0x1F8

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
ARG = HEAP_BASE + 0x300
USER_AT = HEAP_BASE + 0x500
KEY_AT = HEAP_BASE + 0x520
NOW_AT = HEAP_BASE + 0x560
TITLE_PTR = HEAP_BASE + 0x600
DESC_PTR = HEAP_BASE + 0x640
OLD_TITLE = HEAP_BASE + 0x680
OLD_DESC = HEAP_BASE + 0x6C0
NODES = HEAP_BASE + 0x1000
NODE_STRIDE = 0x800
STATE = HEAP_BASE + 0x14000
NEW_KEYS = HEAP_BASE + 0x15000
NEW_ROOT = HEAP_BASE + 0x16000
COMPARED = 0x16100
USED = 0x18000
FILL = 0xCC
WHO = bytes(range(0x41, 0x55))
KEY = bytes(range(0x81, 0xA1))


def near(first=0, last=0):
    return bytes([(WHO[0] + first) & 0xFF]) + WHO[1:19] + bytes([(WHO[19] + last) & 0xFF])


def near_key(first=0, last=0):
    return bytes([(KEY[0] + first) & 0xFF]) + KEY[1:31] + bytes([(KEY[31] + last) & 0xFF])


class Layout:
    def __init__(self, key_size, val_size, val_at, key_at, len_at, edge_at, parent_at, slot_at):
        self.key_size, self.val_size, self.val_at, self.key_at = key_size, val_size, val_at, key_at
        self.len_at, self.edge_at, self.parent_at, self.slot_at = len_at, edge_at, parent_at, slot_at


USER_MAP = Layout(0x14, 0x18, 8, 0x110, 0x1EE, 0x1F0, 0, 0x1EC)
VOTE_MAP = Layout(0x14, 0x10, 0, 0xB8, 0x196, 0x198, 0xB0, 0x194)
PROPOSAL_MAP = Layout(0x20, 0x78, 0x168, 0, 0x692, 0x698, 0x160, 0x690)


def pack_time(value):
    return struct.pack("<iII", *value)


def bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class Case:
    FIELDS = dict(now=(20000, 100, 5), end=(20001, 100, 5), s=5000, choice=1, p_present=True, p_shape="leaf", p_near=((-1, 0), (1, 0)), voted=False, voters=(), v_shape="leaf", rows=((20000, 7, 7),), r_shape="leaf", d_near=((-1, 0), (1, 0)), d_present=True, d_empty=False, d_zero_len=False, d_tree="leaf",
                  u_present=True, u_shape="leaf", u_near=((-1, 0), (1, 0)), lock=(0, 0, 0), title=5, description=20, title_cap=5, desc_cap=20, mode=3, long=0, base=1000000000000, others=(), old=False, ends=(), ghost=(), old_rows=(), below=0)

    def __init__(self, name, kind, **fields):
        self.name = name
        self.kind = kind
        for key, value in self.FIELDS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.FIELDS:
                raise EvidenceError("field " + key)
            setattr(self, key, value)


def blank():
    return bytes((index * 7 + 0x40) & 0xFF for index in range(OUT_SIZE))


def record(end, votes=(0, 0, 0), proposer=b"\x11" * 20, quorum=77, long=1, title=(9, TITLE_PTR, 9), description=(19, DESC_PTR, 19)):
    data = struct.pack("<3Q", *title) + struct.pack("<3Q", *description) + struct.pack("<3Q", *votes) + struct.pack("<Q", quorum)
    return data + pack_time(end) + proposer + bytes([long]) + b"\xEE" * 7


def seconds_for(mode, long):
    if mode & 0xFF in (1, 2):
        return 300.0 if long else 120.0
    return 518400.0 if long else 86400.0


def quorum_of(base, long):
    """The stored word: the u64 to f64 idiom rounds to nearest, the product rounds to nearest, the cast truncates."""
    value = float(base) * (0.1 if long else 0.05)
    return int(value)


def spec_vote(case, before, where):
    image = bytearray(before)
    events = []

    def put(addr, data):
        at = addr - HEAP_BASE
        image[at:at + len(data)] = data

    def done(tag):
        put(OUT, struct.pack("<H", tag))
        return "done", tuple(events), bytes(image)

    if case.p_shape == "none" or not case.p_present:
        return done(TAG_MISSING)
    if tuple(case.now) > tuple(case.end):
        return done(TAG_ENDED)
    if case.voted:
        return done(TAG_VOTED)
    events.append(("total", WHO))
    if case.s == 0:
        return done(TAG_VOTE_STAKE)
    for addr, stamp in where.get("rows", ()):
        put(addr + 8, pack_time(max(tuple(stamp), tuple(case.end))))
    weight = case.s
    if where.get("user") is not None:
        if case.lock[0] == 0:
            pass
        elif tuple(case.now) < tuple(case.lock):
            if case.s < SIDE:
                weight = case.s * 4
        else:
            put(where["user"] + 8, bytes(4))
    events.append(("upsert", where["proposal"] + 0x30, WHO, weight, case.choice & 0xFF))
    return done(TAG_OK)


def spec_propose(case, before, where):
    image = bytearray(before)
    events = []

    def put(addr, data):
        at = addr - HEAP_BASE
        image[at:at + len(data)] = data

    def done(tag):
        put(OUT, struct.pack("<H", tag))
        return "done", tuple(events), bytes(image)

    def refuse(tag):
        if case.desc_cap:
            events.append(("free", DESC_PTR, case.desc_cap))
        if case.title_cap:
            events.append(("free", TITLE_PTR, case.title_cap))
        return done(tag)

    if not 1 <= case.title <= 50:
        return refuse(TAG_TITLE)
    if not 1 <= case.description <= 1000:
        return refuse(TAG_DESCRIPTION)
    events.append(("total", WHO))
    if case.s < MIN_STAKE:
        return refuse(TAG_STAKE)
    if case.p_present and case.p_shape != "none":
        return refuse(TAG_EXISTS)
    if sum(1 for row in case.others if row) > 2:
        return refuse(TAG_LIMIT)
    events.append(("time", pack_time(case.now), bits(seconds_for(case.mode, case.long))))
    quorum = quorum_of(case.base, case.long)
    title = (case.title_cap, TITLE_PTR, case.title)
    description = (case.desc_cap, DESC_PTR, case.description)
    want = bytearray(record(case.end, (0, 0, 0), WHO, quorum, case.long, title, description))
    want[0x71:0x78] = bytes(7)
    events.append(("insert", S_PROPOSALS + STATE, KEY, bytes(want)))
    if case.old:
        events.append(("free", OLD_TITLE, 33))
        events.append(("free", OLD_DESC, 44))
        events.append(("drop",))
    return done(TAG_OK)


def spec_drain(case, before, where):
    image = bytearray(before)
    events = []

    def put(addr, data):
        at = addr - HEAP_BASE
        image[at:at + len(data)] = data

    keys = sorted(where.get("ends", {}))
    gone = [key for key in keys if tuple(where["ends"][key]) <= tuple(case.now)]
    cap = 0
    for index, key in enumerate(gone):
        if index == cap:
            events.append(("grow", cap))
            cap = max(4, cap * 2)
        put(NEW_KEYS + index * 0x20, key)
    count = 0
    for key in gone:
        events.append(("remove", key))
        if key in where["ghost"]:
            continue
        events.append(("insert_out", key, where["records"][key]))
        if key in where["old_rows"]:
            events.append(("free", OLD_TITLE, 33))
            events.append(("free", OLD_DESC, 44))
            events.append(("drop",))
        else:
            count += 1
    if cap:
        events.append(("free", NEW_KEYS, cap << 5))
    if any(key not in where["ghost"] for key in gone):
        put(OUT, struct.pack("<3Q", NEW_ROOT, 0, count))
    else:
        put(OUT, struct.pack("<3Q", 0, POISON, 0))
    return "done", tuple(events), bytes(image)


SPECS = {VOTE: spec_vote, PROPOSE: spec_propose, DRAIN: spec_drain}


def spec_run(case, before, where):
    return SPECS[case.kind](case, before, where)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((RAISE,))
        statics = machine.memory.statics
        hooks = {SLOT_COMPARE: self.on_compare, SLOT_TOTAL: self.on_total, SLOT_TIME: self.on_time, SLOT_FREE: self.on_free, SLOT_GROW: self.on_grow}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        machine.calls = {UPSERT: self.on_upsert, INSERT: self.on_insert, REMOVE: self.on_remove, DROP: self.on_drop}
        self.events = []
        self.case = None
        self.before = None
        self.where = None
        self.next_node = NODES

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def bytes_at(self, addr, size):
        return self.machine.memory.bytes_at(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def on_compare(self, machine):
        regs = machine.regs
        size = regs[RDX]
        self.expect(size in (0x14, 0x20), "compare length")
        left, right = self.bytes_at(regs[RDI], size), self.bytes_at(regs[RSI], size)
        result = 0 if left == right else 0x1234 if left > right else -0x1234
        regs[RAX] = (0x5A5A5A5A << 32) | result & MASK[4]

    def on_total(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + S_DELEGATIONS, "delegations map")
        self.events.append(("total", self.bytes_at(regs[RSI], 20)))
        regs[RAX] = self.case.s

    def on_time(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == ARG + 0x58, "time input")
        self.events.append(("time", self.bytes_at(regs[RSI], 12), machine.xmm[0] & MASK[8]))
        machine.memory.put_bytes(regs[RDI], pack_time(self.case.end))

    def on_free(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 0, "free flags")
        self.events.append(("free", regs[RDI], regs[RSI]))

    def on_grow(self, machine):
        regs = machine.regs
        vec = regs[RDI]
        cap, pointer, length = struct.unpack("<3Q", self.bytes_at(vec, 24))
        self.expect(cap == length, "grow when full")
        self.events.append(("grow", cap))
        if length:
            machine.memory.put_bytes(NEW_KEYS, self.bytes_at(pointer, length * 0x20))
        self.word(vec, max(4, cap * 2))
        self.word(vec + 8, NEW_KEYS)

    def on_upsert(self, machine):
        regs = machine.regs
        self.events.append(("upsert", regs[RDI], self.bytes_at(regs[RSI], 20), regs[RDX], regs[RCX]))

    def on_insert(self, machine):
        regs = machine.regs
        data = bytearray(self.bytes_at(regs[RCX], 0x78))
        key = self.bytes_at(regs[RDX], 0x20)
        if self.case.kind == PROPOSE:
            self.expect(regs[RSI] == STATE + S_PROPOSALS, "proposals map")
            data[0x38:0x40] = bytes(8)
            data[0x71:0x78] = bytes(7)
            self.events.append(("insert", regs[RSI], key, bytes(data)))
            old = self.case.old
        else:
            self.events.append(("insert_out", key, bytes(data)))
            old = key in self.where["old_rows"]
            root, height, count = struct.unpack("<3Q", self.bytes_at(regs[RSI], 24))
            self.word(regs[RSI], NEW_ROOT)
            self.word(regs[RSI] + 8, 0)
            self.word(regs[RSI] + 0x10, count + (0 if old else 1))
        if old:
            machine.memory.put_bytes(regs[RDI], struct.pack("<3Q", 33, OLD_TITLE, 33) + struct.pack("<3Q", 44, OLD_DESC, 44))
        else:
            self.word(regs[RDI], NONE_WORD)

    def on_remove(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == STATE + S_PROPOSALS, "proposals holder")
        key = self.bytes_at(regs[RDX], 0x20)
        self.events.append(("remove", key))
        if key in self.where["ghost"]:
            self.word(regs[RDI], NONE_WORD)
        else:
            machine.memory.put_bytes(regs[RDI], self.where["records"][key])

    def on_drop(self, machine):
        self.events.append(("drop",))

    def node(self, layout, items, children, stale_key, parent=0, slot=0):
        base = self.next_node
        self.next_node += NODE_STRIDE
        if base + NODE_STRIDE > STATE:
            raise EvidenceError("fixture nodes overrun the state")
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * NODE_STRIDE)
        spots = {}
        for at in range(11):
            key, value = items[at] if at < len(items) else (stale_key, b"\xFF" * layout.val_size)
            memory.put_bytes(base + layout.key_at + layout.key_size * at, key)
            memory.put_bytes(base + layout.val_at + layout.val_size * at, value)
            if at < len(items):
                spots[key] = base + layout.val_at + layout.val_size * at
        self.word(base + layout.len_at, len(items), 2)
        self.word(base + layout.parent_at, parent)
        self.word(base + layout.slot_at, slot, 2)
        for at, child in enumerate(children):
            self.word(base + layout.edge_at + 8 * at, child)
        return base, spots

    def link(self, layout, parent, children):
        for slot, child in enumerate(children):
            self.word(child + layout.parent_at, parent)
            self.word(child + layout.slot_at, slot, 2)

    def tree(self, layout, items, shape, stale_key):
        items = sorted(items)
        if shape == "leaf":
            base, spots = self.node(layout, items, (), stale_key)
            return base, 0, spots
        if shape == "tall":
            return self.tall(layout, items, stale_key)
        half = len(items) // 2
        left, one = self.node(layout, items[:half], (), stale_key)
        right, two = self.node(layout, items[half + 1:], (), stale_key)
        base, spots = self.node(layout, items[half:half + 1], (left, right), stale_key)
        self.link(layout, base, (left, right))
        spots.update(one)
        spots.update(two)
        return base, 1, spots

    def tall(self, layout, items, stale):
        """Fifteen rows in a tree of height 2: four leaves of three, two inner nodes, one root."""
        spots = {}
        leaves = []
        for at in (0, 4, 8, 12):
            base, found = self.node(layout, items[at:at + 3], (), stale)
            leaves.append(base)
            spots.update(found)
        low, one = self.node(layout, items[3:4], leaves[:2], stale)
        high, two = self.node(layout, items[11:12], leaves[2:], stale)
        root, three = self.node(layout, items[7:8], (low, high), stale)
        self.link(layout, low, leaves[:2])
        self.link(layout, high, leaves[2:])
        self.link(layout, root, (low, high))
        spots.update(one)
        spots.update(two)
        spots.update(three)
        return root, 2, spots

    def map_at(self, at, built, count):
        self.word(at, built[0] if built else 0)
        self.word(at + 8, built[1] if built else 0)
        self.word(at + 0x10, count)

    def votes_tree(self, case):
        items = [(near(*step), struct.pack("<QQ", 90 + index, 1)) for index, step in enumerate(case.voters)]
        if case.voted:
            items.append((WHO, struct.pack("<QQ", 90, 1)))
        if case.v_shape == "none" or not items:
            return (0, 0, 0)
        built = self.tree(VOTE_MAP, items, case.v_shape, WHO)
        return (built[0], built[1], len(items))

    def proposals_vote(self, case, where):
        if case.p_shape == "none":
            self.map_at(STATE + S_PROPOSALS, None, 0)
            return
        items = [(near_key(*step), record((30000, 1, 1))) for step in case.p_near]
        if case.p_present:
            items.append((KEY, record(case.end, self.votes_tree(case))))
        built = self.tree(PROPOSAL_MAP, items, case.p_shape, KEY)
        self.map_at(STATE + S_PROPOSALS, built, len(items))
        where["proposal"] = built[2].get(KEY)

    def proposals_propose(self, case, where):
        if case.p_shape == "none":
            self.map_at(STATE + S_PROPOSALS, None, 0)
            return
        items = []
        for index, mine in enumerate(case.others):
            proposer = WHO if mine else bytes([0x41 + index % 3]) + WHO[1:19] + bytes([(0x54 + (index + 1) % 3) & 0xFF]) if index % 2 else WHO[:19] + bytes([0x60 + index])
            items.append((near_key(index + 1, 1), record((30000, 1, 1), proposer=proposer)))
        for index in range(case.below):
            items.append((near_key(-1 - index), record((30000, 1, 1), proposer=b"\x22" * 20)))
        if case.p_present:
            items.append((KEY, record(case.end)))
        built = self.tree(PROPOSAL_MAP, items, case.p_shape, KEY)
        self.map_at(STATE + S_PROPOSALS, built, len(items))

    def proposals_drain(self, case, where):
        ends, records = {}, {}
        items = []
        for index, stamp in enumerate(case.ends):
            key = near_key(index + 1, index)
            body = record(stamp, quorum=1000 + index)
            items.append((key, body))
            ends[key] = stamp
            records[key] = body
        where["ends"], where["records"] = ends, records
        where["ghost"] = {near_key(index + 1, index) for index in case.ghost}
        where["old_rows"] = {near_key(index + 1, index) for index in case.old_rows}
        if not items and case.p_shape != "stale":
            self.map_at(STATE + S_PROPOSALS, None, 0)
            return
        built = self.tree(PROPOSAL_MAP, items, "leaf" if case.p_shape == "stale" else case.p_shape, KEY)
        self.map_at(STATE + S_PROPOSALS, built, len(items))

    def users_map(self, case, where):
        if case.u_shape == "none":
            self.map_at(STATE + S_USERS, None, 0)
            return
        items = [(near(*step), struct.pack("<Q", 1 + index) + pack_time((31000, 7, 7)) + bytes(4)) for index, step in enumerate(case.u_near)]
        if case.u_present:
            items.append((WHO, struct.pack("<Q", 8) + pack_time(case.lock) + b"\xEE" * 4))
        built = self.tree(USER_MAP, items, case.u_shape, WHO)
        self.map_at(STATE + S_USERS, built, len(items))
        where["user"] = built[2].get(WHO)

    def delegation_map(self, case, where):
        rows = [(bytes([index + 1]) * 20, struct.pack("<Q", 100 + index) + pack_time(stamp) + b"\xDD" * 4) for index, stamp in enumerate(case.rows)]
        if case.d_empty:
            value = struct.pack("<3Q", 0, 0, 0)
        else:
            built = self.tree(USER_MAP, rows, case.r_shape, b"\xFE" * 20)
            value = struct.pack("<3Q", built[0], built[1], 0 if case.d_zero_len else len(rows))
            if not case.d_zero_len:
                where["rows"] = [(built[2][key], case.rows[index]) for index, (key, _) in enumerate(rows)]
        lone = self.tree(USER_MAP, [(b"\x07" * 20, struct.pack("<Q", 7777) + pack_time((1, 1, 1)) + b"\xDD" * 4)], "leaf", b"\xFE" * 20)
        items = [(near(*step), struct.pack("<3Q", lone[0], 0, 1)) for step in case.d_near]
        if case.d_present:
            items.append((WHO, value))
        else:
            where.pop("rows", None)
        if not items:
            self.map_at(STATE + S_DELEGATIONS, None, 0)
            return
        built = self.tree(USER_MAP, items, case.d_tree, WHO)
        self.map_at(STATE + S_DELEGATIONS, built, len(items))

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(HEAP_BASE, bytes([FILL]) * COMPARED)
        memory.put_bytes(OUT, blank())
        memory.put_bytes(USER_AT, WHO)
        memory.put_bytes(KEY_AT, KEY)
        memory.put_bytes(NOW_AT, pack_time(case.now))
        where = {}
        self.next_node = NODES
        if case.kind == VOTE:
            self.proposals_vote(case, where)
            self.delegation_map(case, where)
            self.users_map(case, where)
        elif case.kind == PROPOSE:
            self.proposals_propose(case, where)
            self.fill_arg(case)
        else:
            self.proposals_drain(case, where)
        self.where = where
        self.events = []
        self.case = case
        self.before = memory.bytes_at(HEAP_BASE, COMPARED)

    def fill_arg(self, case):
        memory = self.machine.memory
        data = struct.pack("<3Q", case.title_cap, TITLE_PTR, case.title) + struct.pack("<3Q", case.desc_cap, DESC_PTR, case.description) + KEY + struct.pack("<Q", case.base) + pack_time(case.now) + WHO + bytes([case.mode, case.long])
        memory.put_bytes(ARG, data)

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        try:
            if case.kind == VOTE:
                self.machine.run(VOTE, {RDI: OUT, RSI: STATE, RDX: USER_AT, RCX: KEY_AT, R8: case.choice, R9: NOW_AT})
            elif case.kind == PROPOSE:
                self.machine.run(PROPOSE, {RDI: OUT, RSI: STATE, RDX: ARG})
            else:
                self.machine.run(DRAIN, {RDI: OUT, RSI: STATE, RDX: NOW_AT})
        except Panicked as stop:
            return "panic", stop.args[0], tuple(self.events)
        return "done", tuple(self.events), memory.bytes_at(HEAP_BASE, COMPARED)


NOW = (20000, 100, 5)
LOCKED = (20000, 100, 6)
TOP = MASK[8]
TWELVE = tuple((19999 + index % 3, 100, index) for index in range(12))
FIFTEEN = tuple((19990 + index * 3, 100 + index % 2, 5) for index in range(15))
PEERS = dict(p_near=((-2, 0), (-1, 0), (0, -1), (0, 1), (1, 0), (2, 0)))
DEEP_P = dict(p_shape="deep", p_near=tuple((step, 0) for step in (-6, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 7)))
TALL_P = dict(p_shape="tall", p_near=tuple((step, 0) for step in (-7, -6, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 7)))
VOTERS = ((-2, 0), (-1, 0), (0, -1), (0, 1), (1, 0), (2, 0))
DEEP_V = tuple((step, 0) for step in (-6, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 7))
DEEP_D = dict(d_tree="deep", d_near=tuple((step, 0) for step in (-6, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 7)))
DEEP_U = dict(u_shape="deep", u_near=tuple((step, 0) for step in (-6, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 7)))
VOTE_NAMED = (
    ("plain", {}), ("no_map", dict(p_shape="none")), ("no_row", dict(p_present=False)), ("no_row_peers", dict(p_present=False, **PEERS)), ("deep_row", DEEP_P), ("deep_miss", dict(p_present=False, **DEEP_P)), ("tall_row", TALL_P), ("tall_miss", dict(p_present=False, **TALL_P)), ("eleven_row", dict(p_near=tuple((step, 0) for step in (-5, -4, -3, -2, -1, 1, 2, 3, 4, 5)))),
    ("end_equal", dict(end=NOW)), ("end_date_later", dict(end=(20001, 0, 0))), ("end_date_past", dict(end=(19999, 0xFFFFFFFF, 9))), ("end_secs_later", dict(end=(20000, 101, 0))), ("end_secs_past", dict(end=(20000, 99, 9))), ("end_frac_later", dict(end=(20000, 100, 6))), ("end_frac_past", dict(end=(20000, 100, 4))),
    ("end_top_secs", dict(now=(5, 0x80000000, 0), end=(5, 0x80000001, 0))), ("end_top_secs_past", dict(now=(5, 0x80000001, 0), end=(5, 0x80000000, 0))), ("end_top_frac", dict(now=(5, 1, 0x80000000), end=(5, 1, 0x80000001))), ("end_top_frac_past", dict(now=(5, 1, 0x80000001), end=(5, 1, 0x80000000))), ("end_negative", dict(now=(-5, 1, 0), end=(-4, 1, 0))), ("end_negative_past", dict(now=(-4, 1, 0), end=(-5, 1, 0))), ("end_sign_split", dict(now=(-1, 1, 0), end=(1, 1, 0))), ("end_sign_split_past", dict(now=(1, 1, 0), end=(-1, 1, 0))),
    ("voted", dict(voted=True)), ("voted_peers", dict(voted=True, voters=VOTERS)), ("voted_deep", dict(voted=True, voters=DEEP_V, v_shape="deep")), ("not_voted_peers", dict(voters=VOTERS)), ("not_voted_deep", dict(voters=DEEP_V, v_shape="deep")), ("voted_ended", dict(voted=True, end=(19999, 0, 0))),
    ("stake_zero", dict(s=0)), ("stake_zero_locked", dict(s=0, lock=LOCKED)), ("stake_one", dict(s=1)),
    ("no_user_map", dict(u_shape="none")), ("no_user_row", dict(u_present=False)), ("deep_user", DEEP_U), ("deep_user_locked", dict(lock=LOCKED, **DEEP_U)), ("deep_user_miss", dict(u_present=False, **DEEP_U)),
    ("lock_date_zero", dict(lock=(0, 500, 7))), ("lock_future_date", dict(lock=(20001, 0, 0))), ("lock_past_date", dict(lock=(19999, 0xFFFFFFFF, 9))), ("lock_future_secs", dict(lock=(20000, 101, 0))), ("lock_past_secs", dict(lock=(20000, 99, 9))), ("lock_future_frac", dict(lock=LOCKED)), ("lock_equal", dict(lock=NOW)), ("lock_past_frac", dict(lock=(20000, 100, 4))),
    ("lock_top_secs", dict(now=(5, 0x80000000, 0), lock=(5, 0x80000001, 0), end=(6, 0, 0))), ("lock_top_secs_past", dict(now=(5, 0x80000001, 0), lock=(5, 0x80000000, 0), end=(6, 0, 0))), ("lock_top_frac", dict(now=(5, 1, 0x80000000), lock=(5, 1, 0x80000001), end=(6, 0, 0))), ("lock_top_frac_past", dict(now=(5, 1, 0x80000001), lock=(5, 1, 0x80000000), end=(6, 0, 0))), ("lock_negative_now", dict(now=(-3, 0, 0), lock=(-2, 0, 0), end=(6, 0, 0))), ("lock_negative_past", dict(now=(-2, 0, 0), lock=(-3, 0, 0), end=(6, 0, 0))), ("lock_sign_split", dict(now=(-1, 0, 0), lock=(1, 0, 0), end=(6, 0, 0))), ("lock_sign_split_past", dict(now=(1, 0, 0), lock=(-1, 0, 0), end=(6, 0, 0))),
    ("side_below", dict(s=SIDE - 1, lock=LOCKED)), ("side_at", dict(s=SIDE, lock=LOCKED)), ("side_above", dict(s=SIDE + 1, lock=LOCKED)), ("side_half", dict(s=1 << 63, lock=LOCKED)), ("side_top", dict(s=TOP, lock=LOCKED)), ("side_open", dict(s=TOP, lock=NOW)), ("side_33", dict(s=1 << 33, lock=LOCKED)),
    ("choice_zero", dict(choice=0)), ("choice_two", dict(choice=2)), ("choice_high_bits", dict(choice=0xABCDEF02)), ("choice_byte_top", dict(choice=0xFF, lock=LOCKED)),
    ("row_raised", dict(rows=((20000, 100, 5),))), ("row_kept", dict(rows=((20002, 0, 0),))), ("row_date_equal_secs_low", dict(rows=((20001, 99, 9),))), ("row_date_equal_secs_high", dict(rows=((20001, 101, 0),))), ("row_frac_low", dict(rows=((20001, 100, 4),))), ("row_frac_high", dict(rows=((20001, 100, 6),))), ("row_equal", dict(rows=((20001, 100, 5),))), ("row_zero", dict(rows=((0, 0, 0),))), ("row_negative", dict(rows=((-1, 0xFFFFFFFF, 9),))), ("row_top_secs", dict(end=(20001, 0x80000000, 0), rows=((20001, 0x80000001, 0), (20001, 0x7FFFFFFF, 0)))), ("row_top_frac", dict(end=(20001, 9, 0x80000000), rows=((20001, 9, 0x80000001), (20001, 9, 0x7FFFFFFF)))),
    ("rows_twelve", dict(rows=TWELVE, r_shape="deep")), ("rows_two", dict(rows=((1, 2, 3), (30000, 0, 0)))), ("rows_three", dict(rows=((1, 2, 3), (30000, 0, 0), (4, 5, 6)))), ("rows_eleven", dict(rows=TWELVE[:11])), ("rows_tall", dict(rows=FIFTEEN, r_shape="tall")),
    ("deleg_absent", dict(d_present=False)), ("deleg_absent_empty_map", dict(d_present=False, d_near=())), ("deleg_null_root", dict(d_empty=True)), ("deleg_zero_len", dict(d_zero_len=True)), ("deleg_deep", DEEP_D), ("deleg_deep_rows", dict(rows=TWELVE, r_shape="deep", **DEEP_D)), ("deleg_deep_absent", dict(d_present=False, **DEEP_D)),
)
PROPOSE_NAMED = (
    ("plain", dict(p_present=False, s=MIN_STAKE)), ("title_zero", dict(title=0)), ("title_one", dict(title=1, p_present=False, s=MIN_STAKE)), ("title_fifty", dict(title=50, p_present=False, s=MIN_STAKE)), ("title_fifty_one", dict(title=51)), ("title_top", dict(title=TOP)), ("title_zero_cap", dict(title=0, title_cap=0)),
    ("desc_zero", dict(description=0)), ("desc_one", dict(description=1, p_present=False, s=MIN_STAKE)), ("desc_thousand", dict(description=1000, p_present=False, s=MIN_STAKE)), ("desc_over", dict(description=1001)), ("desc_top", dict(description=TOP)), ("desc_zero_cap", dict(description=0, desc_cap=0)), ("both_caps_zero", dict(title=51, title_cap=0, desc_cap=0)),
    ("stake_below", dict(s=MIN_STAKE - 1)), ("stake_at", dict(s=MIN_STAKE, p_present=False)), ("stake_above", dict(s=MIN_STAKE + 1, p_present=False)), ("stake_zero", dict(s=0)), ("stake_top", dict(s=TOP, p_present=False)),
    ("exists", dict(s=MIN_STAKE)), ("exists_peers", dict(s=MIN_STAKE, others=(0, 0, 0, 0))), ("exists_below", dict(s=MIN_STAKE, below=6)), ("miss_below", dict(p_present=False, s=MIN_STAKE, below=6)), ("miss_below_odd", dict(p_present=False, s=MIN_STAKE, below=7)), ("exists_both", dict(s=MIN_STAKE, below=4, others=(0, 0, 0, 0))), ("miss_both", dict(p_present=False, s=MIN_STAKE, below=4, others=(0, 0, 0, 0))), ("no_map", dict(p_shape="none", s=MIN_STAKE)), ("deep_exists", dict(s=MIN_STAKE, p_shape="deep", others=(0,) * 13)), ("deep_miss", dict(p_present=False, s=MIN_STAKE, p_shape="deep", others=(0,) * 13)), ("tall_exists", dict(s=MIN_STAKE, p_shape="tall", others=(0,) * 14)), ("tall_miss", dict(p_present=False, s=MIN_STAKE, p_shape="tall", others=(0,) * 15)),
    ("own_one", dict(p_present=False, s=MIN_STAKE, others=(1,))), ("own_two", dict(p_present=False, s=MIN_STAKE, others=(1, 1))), ("own_three", dict(p_present=False, s=MIN_STAKE, others=(1, 1, 1))), ("own_four", dict(p_present=False, s=MIN_STAKE, others=(1, 1, 1, 1))), ("mixed_two", dict(p_present=False, s=MIN_STAKE, others=(0, 1, 0, 1, 0))), ("mixed_three", dict(p_present=False, s=MIN_STAKE, others=(1, 0, 1, 0, 1))), ("mixed_eleven", dict(p_present=False, s=MIN_STAKE, others=(0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))),
    ("deep_own_two", dict(p_present=False, s=MIN_STAKE, p_shape="deep", others=(1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0))), ("deep_own_three", dict(p_present=False, s=MIN_STAKE, p_shape="deep", others=(1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1))), ("tall_own_two", dict(p_present=False, s=MIN_STAKE, p_shape="tall", others=(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))), ("tall_own_three", dict(p_present=False, s=MIN_STAKE, p_shape="tall", others=(1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1))),
    ("empty_tree_leaf", dict(p_present=False, s=MIN_STAKE, others=())),
    ("long", dict(p_present=False, s=MIN_STAKE, long=1)), ("mode_one", dict(p_present=False, s=MIN_STAKE, mode=1)), ("mode_two_long", dict(p_present=False, s=MIN_STAKE, mode=2, long=1)), ("mode_zero", dict(p_present=False, s=MIN_STAKE, mode=0)), ("mode_top", dict(p_present=False, s=MIN_STAKE, mode=0xFF, long=1)),
    ("base_zero", dict(p_present=False, s=MIN_STAKE, base=0)), ("base_one", dict(p_present=False, s=MIN_STAKE, base=1)), ("base_19", dict(p_present=False, s=MIN_STAKE, base=19)), ("base_20", dict(p_present=False, s=MIN_STAKE, base=20)), ("base_60", dict(p_present=False, s=MIN_STAKE, base=60)), ("base_top", dict(p_present=False, s=MIN_STAKE, base=TOP, long=1)), ("base_half", dict(p_present=False, s=MIN_STAKE, base=1 << 63)), ("base_half_less", dict(p_present=False, s=MIN_STAKE, base=(1 << 63) - 1, long=1)), ("base_53", dict(p_present=False, s=MIN_STAKE, base=(1 << 53) + 1)),
    ("old_row", dict(p_present=False, s=MIN_STAKE, old=True)),
)
DRAIN_NAMED = (
    ("empty_map", {}), ("zero_rows_root", dict(p_shape="stale")), ("one_live", dict(ends=((20001, 0, 0),))), ("one_gone", dict(ends=((19999, 0, 0),))), ("end_equal", dict(ends=(NOW,))), ("end_secs_later", dict(ends=((20000, 101, 0),))), ("end_secs_past", dict(ends=((20000, 99, 9),))), ("end_frac_later", dict(ends=((20000, 100, 6),))), ("end_frac_past", dict(ends=((20000, 100, 4),))),
    ("top_secs", dict(now=(5, 0x80000000, 0), ends=((5, 0x80000001, 0), (5, 0x7FFFFFFF, 0)))), ("top_frac", dict(now=(5, 1, 0x80000000), ends=((5, 1, 0x80000001), (5, 1, 0x7FFFFFFF)))), ("negative", dict(now=(-5, 0, 0), ends=((-4, 0, 0), (-6, 0, 0), (1, 0, 0)))), ("sign_past", dict(now=(1, 0, 0), ends=((-1, 0, 0), (2, 0, 0)))),
    ("five_gone", dict(ends=((19000, 0, 0),) * 5)), ("nine_gone", dict(ends=((19000, 0, 0),) * 9)), ("mixed", dict(ends=((19000, 0, 0), (21000, 0, 0), (19000, 0, 0), (21000, 0, 0), NOW))), ("eleven", dict(ends=tuple((19999 + index % 2 * 2, 0, 0) for index in range(11)))),
    ("deep", dict(p_shape="deep", ends=tuple((19999 + index % 2 * 2, 0, 0) for index in range(14)))), ("deep_all", dict(p_shape="deep", ends=((19000, 0, 0),) * 14)), ("tall", dict(p_shape="tall", ends=tuple((19999 + index % 3, 0, 0) for index in range(15)))), ("tall_all", dict(p_shape="tall", ends=((19000, 0, 0),) * 15)),
    ("ghost", dict(ends=((19000, 0, 0), (19000, 0, 0)), ghost=(0,))), ("ghost_all", dict(ends=((19000, 0, 0),), ghost=(0,))), ("old_row", dict(ends=((19000, 0, 0), (19000, 0, 0)), old_rows=(1,))),
)


def named_cases():
    rows = [Case(name, VOTE, **fields) for name, fields in VOTE_NAMED]
    rows += [Case(name, PROPOSE, **fields) for name, fields in PROPOSE_NAMED]
    rows += [Case(name, DRAIN, now=NOW, **fields) if "now" not in fields else Case(name, DRAIN, **fields) for name, fields in DRAIN_NAMED]
    return rows


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11 ^ state


def vector_cases(count):
    source = lcg(0x398D)
    rows = []
    stamp = lambda word: (20000 + (word & 3) - 1, 100 + (word >> 2 & 3) - 1, 5 + (word >> 4 & 3) - 1)
    for index in range(count):
        word, other = next(source), next(source)
        if index % 2:
            s = other >> (word & 63)
            rows.append(Case("v%d" % index, VOTE, end=stamp(word >> 6), lock=stamp(word >> 12) if word >> 18 & 3 else (0, 0, 0), s=s, choice=word >> 20 & 3, voted=not word >> 22 & 7, rows=tuple(stamp(word >> (24 + 6 * step)) for step in range(word >> 42 & 3)) or ((1, 1, 1),), u_present=bool(word >> 44 & 7), voters=VOTERS if word >> 47 & 1 else ()))
        else:
            base = other >> (word & 63)
            rows.append(Case("v%d" % index, PROPOSE, p_present=False, s=MIN_STAKE + (word >> 8 & 3) - 1, base=base, long=word >> 10 & 1, mode=word >> 11 & 3, title=48 + (word >> 13 & 3), description=998 + (word >> 15 & 3), others=tuple(word >> (17 + step) & 1 for step in range(word >> 22 & 7))))
    return rows


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case, harness.before, harness.where)
        if got != want:
            if got[0] == "done" and want[0] == "done":
                diff = [hex(HEAP_BASE + at) for at in range(COMPARED) if got[2][at] != want[2][at]][:12]
                raise EvidenceError("case %s: events %r != %r diff %s" % (case.name, got[1], want[1], diff))
            raise EvidenceError("case %s: %r != %r" % (case.name, got[:2], want[:2]))
        outcomes.append(got)
    return outcomes


def stored_quorum(harness, base, long):
    case = Case("q", PROPOSE, p_present=False, s=MIN_STAKE, base=base, long=long)
    got = harness.run(case)
    if got != spec_run(case, harness.before, harness.where):
        raise EvidenceError("quorum base %#x" % base)
    row = next(event for event in got[1] if event[0] == "insert")
    return struct.unpack_from("<Q", row[3], 0x48)[0]


def lock_pieces(harness):
    """Both ends of each stake piece: locked weight is 4s below 2^62 and s from there up."""
    rows = []
    machine = harness.machine
    for label, low, high, lock, tag in (("refused", 0, 0, (20000, 100, 6), TAG_VOTE_STAKE), ("locked_times_four", 1, SIDE - 1, (20000, 100, 6), TAG_OK), ("locked_kept", SIDE, TOP, (20000, 100, 6), TAG_OK), ("open", 1, TOP, (20000, 100, 5), TAG_OK), ("no_lock", 1, TOP, (0, 0, 0), TAG_OK)):
        walked, weights = [], []
        for value in (low, high):
            case = Case("%s_%#x" % (label, value), VOTE, s=value, lock=lock)
            saved = machine.seen
            machine.seen = set()
            got = harness.run(case)
            walked.append(machine.seen)
            machine.seen = saved | walked[-1]
            if got != spec_run(case, harness.before, harness.where):
                raise EvidenceError("piece end %#x" % value)
            if struct.unpack_from("<H", got[2], OUT - HEAP_BASE)[0] != tag:
                raise EvidenceError("piece status %#x" % value)
            weights.append(next((event[3] for event in got[1] if event[0] == "upsert"), None))
        if walked[0] != walked[1]:
            raise EvidenceError("piece %s has two paths" % label)
        rows.append((label, low, high, "%#x" % tag, weights[0], weights[1]))
    return rows


def first_above(rate, parts):
    """First base where trunc(base * rate) rounded to double exceeds base // parts, from exact fractions.

    Valid below 2^53, where f64(base) is exact. Write base = parts * k + j. The rate is above 1/parts by a
    relative delta, so the product is k + j/parts + base * delta / parts, and it rounds up to k + 1 when
    that is within half a unit in the last place of k + 1. The largest j, parts - 1, gets there first.
    """
    exact = fractions.Fraction(rate)
    delta = exact * parts - 1
    if delta <= 0:
        raise EvidenceError("rate is not above the fraction")
    best = None
    for exponent in range(30, 53):
        half = fractions.Fraction(2) ** (exponent - 53)
        low = (1 - parts * half) / delta
        low = max(low, fractions.Fraction(2 ** exponent) * parts, fractions.Fraction(0))
        base = (int(low) // parts) * parts + parts - 1
        while base < low:
            base += parts
        if base < 2 ** (exponent + 1) * parts and base < 1 << 53 and (best is None or base < best):
            best = base
    return best


def quorum_rows(harness):
    """Real rows at chosen bases, the first base above the integer floor, and witnesses past it."""
    source = lcg(0x5053)
    tried = 0
    found = []
    limits = {}
    for long, rate, parts in ((0, 0.05, 20), (1, 0.1, 10)):
        first = first_above(rate, parts)
        limits[long] = first
        if quorum_of(first, long) != first // parts + 1:
            raise EvidenceError("first base %#x does not differ" % first)
        for base in range(first - 20000, first):
            tried += 1
            if quorum_of(base, long) != base // parts:
                raise EvidenceError("model differs at %#x below the first base" % base)
        for _ in range(3000):
            base = next(source) % first
            tried += 1
            if quorum_of(base, long) != base // parts:
                raise EvidenceError("model differs at %#x" % base)
        for base in (0, 1, parts - 1, parts, 3 * parts - 1, 3 * parts, 3 * parts + 1, 1 << 40, first - 1):
            if stored_quorum(harness, base, long) != base // parts:
                raise EvidenceError("real rows differ at %#x" % base)
        for base in (first, first + parts, 1 << 53, (1 << 53) + 1, 1 << 60, 10 ** 17, TOP):
            real = stored_quorum(harness, base, long)
            if real != quorum_of(base, long):
                raise EvidenceError("witness %#x" % base)
            found.append((long, base, real, base // parts, real - base // parts))
    return found, tried, limits


def seconds_rows(harness):
    groups = {}
    for long in (0, 1):
        for byte in range(256):
            case = Case("m", PROPOSE, p_present=False, s=MIN_STAKE, mode=byte, long=long)
            got = harness.run(case)
            if got != spec_run(case, harness.before, harness.where):
                raise EvidenceError("mode byte %#x" % byte)
            event = next(row for row in got[1] if row[0] == "time")
            groups.setdefault((long, struct.unpack("<d", struct.pack("<Q", event[2]))[0]), []).append(byte)
    rows = [(long, seconds, len(found), " ".join("%#x" % byte for byte in found[:3])) for (long, seconds), found in sorted(groups.items())]
    if [row[2] for row in rows] != [2, 254, 2, 254]:
        raise EvidenceError("mode groups %r" % rows)
    return rows


def constant_rows(image):
    rows = []
    for name, va, wanted in (("test_long_seconds", TEST_SECONDS, 300.0), ("test_short_seconds", TEST_SECONDS + 8, 120.0), ("long_seconds", LONG_SECONDS, 518400.0), ("short_seconds", SHORT_SECONDS, 86400.0), ("short_rate", RATES, 0.05), ("long_rate", RATES + 8, 0.1)):
        value = struct.unpack_from("<d", image.blob, image.offset(va))[0]
        if value != wanted:
            raise EvidenceError("constant %s" % name)
        rows.append((name, "%#x" % va, value, "%016x" % bits(value)))
    limit = struct.unpack_from("<Q", image.blob, image.offset(LIMIT_WORD))[0]
    if limit != 3:
        raise EvidenceError("limit word")
    rows.append(("proposal_limit_shown", "%#x" % LIMIT_WORD, limit, "%016x" % limit))
    return rows


def direct_to(image, target):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 <= len(text) and start + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            hits.append(start + at)
    return hits


def slot_sites(image, slot):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text) and start + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            hits.append(start + at)
    return hits


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, role, target in ((SLOT_VOTE, "vote", VOTE), (SLOT_PROPOSE, "propose", PROPOSE), (SLOT_DRAIN, "drain_ended", DRAIN)):
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        sites = slot_sites(image, slot)
        if len(sites) != 3:
            raise EvidenceError("slot %#x has %d call sites" % (slot, len(sites)))
        rows.append(("%#x" % slot, role, "%#x" % target, len(sites), " ".join("%#x" % site for site in sites)))
    if direct_to(image, RAISE) != [0x398D3C9]:
        raise EvidenceError("lockup raise callers")
    rows.append(("direct", "lockup_raise", "%#x" % RAISE, 1, "%#x" % 0x398D3C9))
    return rows


def key_text(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def name_rows(image):
    """Serde keys of the Proposal serializer with the field each one is paired with, from fixed byte forms."""
    data = bytes(image.blob[image.offset(SERIALIZER):image.offset(SERIALIZER) + 0x2B8])
    rows = []
    for match in re.finditer(b"\x48\x8d\x35(.{4})" + re.escape(b"\x48\x8d\x7c\x24\x08") + b"(?:.{0,6}?)\xba(.)\x00\x00\x00", data, re.S):
        at = match.start()
        target = SERIALIZER + at + 7 + struct.unpack("<i", match[1])[0]
        size = match[2][0]
        rows.append((SERIALIZER + at, target, key_text(image, target, size), at))
    if [row[2] for row in rows] != ["title", "description", "end", "votes", "proposer", "quorum"]:
        raise EvidenceError("proposal keys %r" % [row[2] for row in rows])
    expected = {"title": 0, "description": 0x18, "end": 0x50, "votes": 0x30, "proposer": 0x5C, "quorum": 0x48}
    proofs = {"description": b"\x48\x8d\x4b\x18", "proposer": b"\x48\x8d\x4b\x5c", "quorum": b"\x48\x8d\x4b\x48", "end": b"\x4c\x8d\x63\x50", "votes": b"\x48\x8d\x7b\x30"}
    out = []
    for va, target, text, at in rows:
        if text in proofs:
            window = data[max(at - 0x10, 0):at] if text in ("description", "proposer", "quorum") else data[at:at + 0x30]
            if proofs[text] not in window:
                raise EvidenceError("field of key %s" % text)
        out.append(("%#x" % va, "%#x" % target, text, "%#x" % expected[text]))
    data = bytes(image.blob[image.offset(STATE_SERIALIZER_SITE - 0x10):image.offset(STATE_SERIALIZER_SITE) + 5])
    if b"\x48\x8d\xb3" + struct.pack("<i", S_PROPOSALS) not in data[:0x10] or data[0x10] != 0xE8:
        raise EvidenceError("state serializer row")
    callee = STATE_SERIALIZER_SITE + 5 + struct.unpack_from("<i", data, 0x11)[0]
    if callee != PROPOSALS_KEY_FN:
        raise EvidenceError("proposals key helper")
    head = bytes(image.blob[image.offset(callee):image.offset(callee) + 0x40])
    at = head.find(b"\x48\x8d\x35")
    target = callee + at + 7 + struct.unpack_from("<i", head, at + 3)[0]
    size = struct.unpack_from("<I", head, at + head[at:].find(b"\xba") + 1)[0]
    if key_text(image, target, size) != "proposals":
        raise EvidenceError("proposals key")
    out.append(("%#x" % STATE_SERIALIZER_SITE, "%#x" % target, "proposals", "%#x" % S_PROPOSALS))
    marks = (b"struct Proposal with 7 elements",)
    for mark in marks:
        if bytes(image.blob).count(mark) < 1:
            raise EvidenceError("struct text")
    return out


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag in TEXT_ARMS:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 64])
        at = data.find(b"\x48\x8d\x35")
        if at < 0 or data[at + 7] != 0xBA:
            raise EvidenceError("status arm %#x has another shape" % tag)
        text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, at + 8)[0]
        rows.append(("%#x" % tag, "%#x" % arm, key_text(image, text, size)))
    arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * TAG_LIMIT)[0]
    data = bytes(image.blob[image.offset(arm):image.offset(arm) + 0x30])
    if data[:3] != b"\x48\x8d\x05" or arm + 7 + struct.unpack_from("<i", data, 3)[0] != LIMIT_WORD:
        raise EvidenceError("limit arm")
    pieces = arm + 0x1F + 7 + struct.unpack_from("<i", data, 0x1F + 3)[0]
    size = image.blob[image.offset(pieces)]
    wanted = b"Too many active proposals. Limit is "
    found = bytes(image.blob[image.offset(pieces):image.offset(pieces) + 64])
    if wanted not in found or size == 0:
        raise EvidenceError("limit text")
    rows.append(("%#x" % TAG_LIMIT, "%#x" % arm, "Too many active proposals. Limit is {} per user."))
    return rows


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
            if harness.run(case) != spec_run(case, harness.before, harness.where):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error):
            return case
    return None


EIGHT = "the unrolled eight-step descent starts at height 8; the bound picks between two walks of one path, and no tree here is that tall"
FIRST_LEAF = "first leaf length at slot 0: only tested against 0, and any leaf reached with rows left holds a row, so a nonzero stale word reads the same"
EXPECTED_SURVIVORS = {
    (0x3C0F4F5, "immediate"): EIGHT, (0x3C0F5D8, "immediate"): EIGHT, (0x398D825, "immediate"): EIGHT, (0x398D908, "immediate"): EIGHT, (0x398CD46, "immediate"): EIGHT, (0x398CE29, "immediate"): EIGHT,
    (0x3C0F554, "displacement"): FIRST_LEAF, (0x398D883, "displacement"): FIRST_LEAF, (0x398CDA4, "displacement"): FIRST_LEAF,
    (0x398DA8A, "immediate"): "the sign mask of the cast: a shift by 62 gives the same mask while the product stays below 2^62, and the rate table keeps it below 2^61",
    (0x398DAA6, "immediate"): "the saturation constant: it needs a product of 2^64 or more, and the rate table keeps the product below 2^61",
    (0x398CC2A, "immediate"): "the dangling pointer of an empty vector: never read, the first push grows it",
    (0x398CC87, "immediate"): "the same dangling pointer in a register: the first push reloads it",
}


def cases_for(target, cases):
    wanted = {VOTE: VOTE, RAISE: VOTE, PROPOSE: PROPOSE, DRAIN: DRAIN}[target]
    return [case for case in cases if case.kind == wanted]


def run_mutants(image, table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    for target in TARGETS:
        chosen = cases_for(target, cases)
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            if first_failure(harness, chosen) is not None:
                results.append((va, kind, "killed", "whole run"))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True, vectors=400):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    check_cases(harness, vector_cases(vectors))
    pieces = lock_pieces(harness)
    seconds = seconds_rows(harness)
    witnesses, tried, limits = quorum_rows(harness)
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, slots=slot_rows(image), constants=constant_rows(image), names=name_rows(image), statuses=status_rows(image), pieces=pieces, seconds=seconds, witnesses=witnesses, sampled=tried, limits=limits)
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    if outcome[0] == "panic":
        return "panic", outcome[1], ",".join(str(event[0]) for event in outcome[2]), ""
    data = outcome[2]
    at = OUT - HEAP_BASE
    tag = struct.unpack_from("<H", data, at)[0]
    return ("-" if case.kind == DRAIN else "%#x" % tag), data[at:at + 8].hex(), ",".join(str(event[0]) for event in outcome[1]), hashlib.sha256(data).hexdigest()[:16]


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("slots.tsv", ("slot", "role", "target", "call_sites", "sites"), result["slots"])
    tsv("constants.tsv", ("name", "address", "value", "bits"), result["constants"])
    tsv("field-names.tsv", ("site", "key_address", "key", "offset"), result["names"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("stake-pieces.tsv", ("piece", "low", "high", "status", "weight_low", "weight_high"), result["pieces"])
    tsv("seconds.tsv", ("long", "seconds", "mode_bytes", "first_values"), result["seconds"])
    tsv("quorum-witnesses.tsv", ("long", "base", "stored", "floor", "difference"), result["witnesses"])
    tsv("outcomes.tsv", ("entry", "case", "status", "out_head", "events", "state_digest"),
        [("%#x" % case.kind, case.name) + describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"], "sampled_below_first": result["sampled"], "first_base_above_floor": {"short": result["limits"][0], "long": result["limits"][1]},
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
