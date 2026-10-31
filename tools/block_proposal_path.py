#!/usr/bin/env python3
"""Run node #94 block proposal 0x44b4f80 from bytes and map how a round leader builds one block.

The real rows of the proposer and nine of its leaves run under named stubs with real B-tree fixtures, a separate
rule list predicts every outcome and every state write, and every reached conditional row, immediate and field
offset is mutated. Timer, dispatch and field facts come from fixed bytes. No objdump or readelf output is parsed and
the binary is never executed. Standard library only.

    python3 tools/block_proposal_path.py --out <dir>
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
HEAP_SIZE = 0x30000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 1500000
MUTANT_STEP_LIMIT = 100000


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
        for marker in ("/node/", "/library/"):
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
        elif op == "shldc":
            bits = 8 * width
            count = self.regs[RCX] & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            self.put(row.a, width, (high << count | low >> (bits - count)) if count else high)
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


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


MARK_BASE = 0x7700000000
SLOT_MEMCMP = 0x576E488
SLOT_LEADER = 0x5773628
SLOT_PROPOSE = 0x5773630
SLOT_LOG = 0x576E978
SLOT_ADD_SECS = 0x576EFB8
SLOT_MILLIS = 0x576F6C0
SLOT_MEMCPY = 0x576DFE0
SLOT_DEALLOC = 0x576E010
SLOT_ONCE = 0x576E8B8
SLOT_GROW_HASHES = 0x5775090
SLOT_GROW_RECORDS = 0x5776A00
SLOT_SORT = 0x57766F0
SLOT_SUM_PANIC = 0x576E118
SLOT_BTREE_PANIC = 0x576E470
ONCE_WORD = 0x577AB98
PROPOSER = 0x44B4F80
PENDING = 0x44B95A0
SEEN_LOOKUP = 0x4927BD0
BLOCK_LOOKUP = 0x4927E50
INSERTION = 0x4913600
HIGH_QC = 0x47593A0
SIGN_BLOCK = 0x454AD50
PUSH_OUT = 0x44C2380
PRUNE_NEXT = 0x489B0A0
MILLIS = 0x14508E0
FROM_SECS = 0x4B27670
STATIC_FUNCTIONS = (PROPOSER, PENDING, SEEN_LOOKUP, BLOCK_LOOKUP, INSERTION, HIGH_QC, SIGN_BLOCK, PUSH_OUT, PRUNE_NEXT, MILLIS)
ROLES = {PROPOSER: "proposal gates, selection, timestamp, assembly", PENDING: "is there a block above the commit watermark with tx hashes",
         SEEN_LOOKUP: "lookup in state+0x58, result unused", BLOCK_LOOKUP: "parent block lookup in state+0x1b8", INSERTION: "insertion sort of 0x38 records by time",
         HIGH_QC: "pick the highest QC out of a TC", SIGN_BLOCK: "sign the 0xb0 byte block", PUSH_OUT: "push one 0x168 byte record to the outbox",
         PRUNE_NEXT: "extract_if step over the pending tx map", MILLIS: "time to clamped i64 milliseconds"}
STUBS = {0x42C9930: "stake snapshot lookup", 0x4B1A270: "drop of an unused error", 0x447E690: "drop of an error", 0x4847500: "clone of a QC signature vector",
         0x47328A0: "drop of a TC error", 0x44B9800: "predecessor walk, excluded tx set or missing hash (open #613)", 0x44B8050: "request throttle for the missing block",
         0x49AC240: "drop of the excluded set", 0x4480730: "drop of a removed tx", 0x45485A0: "tx re-verification", 0x42B27E0: "B-tree remove_kv", 0x454C050: "block digest",
         0x14A2710: "wallet sign"}
SLOT_STUBS = {SLOT_MEMCMP: "memcmp", SLOT_LEADER: "leader lookup 0x4b31e70", SLOT_LOG: "log formatter", SLOT_ADD_SECS: "time plus f64 seconds 0x1459ca0", SLOT_MEMCPY: "memcpy",
              SLOT_DEALLOC: "dealloc", SLOT_ONCE: "Once slow path", SLOT_GROW_HASHES: "Vec grow, 32 byte items", SLOT_GROW_RECORDS: "Vec grow, 0x38 byte items",
              SLOT_SORT: "driftsort entry 0x4486310"}
OK_TAG = 0x800000000000002A
NONE_TAG = 1 << 63
TX_SKIP_TAG = (1 << 63) + 1
RETIRED_SENTINEL = (1 << 63) + 2
TC_EMPTY_TAG = (1 << 63) + 0xB
DATE = (2025 << 13) | (200 << 4) | 0xE
STATE = HEAP_BASE + 0x1000
STATE_SIZE = 0xB08
OUTBOX = HEAP_BASE + 0x2000
OUTBOX_CAP = 3
RECORD = 0x168
TC_RECORDS = HEAP_BASE + 0x3000
SIZES = HEAP_BASE + 0x4000
NODES = HEAP_BASE + 0x8000
USED = HEAP_SIZE
SELF = bytes(range(0x40, 0x54))
OTHER = bytes(range(0x41, 0x55))
LOCATION_LOG = 0x5738668
TX_VALUE = 0x58
BLOCK_VALUE = 0xF8
BYTES_CAP = 4000000
HASHES_CAP = 100


STATE_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(STATE_SIZE))


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, pidx_at, len_at, edges_at):
        self.key_at, self.key_size, self.val_at, self.val_size = key_at, key_size, val_at, val_size
        self.parent_at, self.pidx_at, self.len_at, self.edges_at = parent_at, pidx_at, len_at, edges_at
        self.size = edges_at + 12 * 8


TX_LAYOUT = Layout(0, 32, 0x168, TX_VALUE, 0x160, 0x530, 0x532, 0x538)
BLOCK_LAYOUT = Layout(0, 32, 0x168, BLOCK_VALUE, 0x160, 0xC10, 0xC12, 0xC18)
SET_LAYOUT = Layout(0, 32, 0x16C, 0, 0x160, 0x168, 0x16A, 0x170)
SEEN_LAYOUT = Layout(0, 32, 0x16C, 1, 0x160, 0x168, 0x16A, 0x178)
STAKE_LAYOUT = Layout(0x60, 20, 0, 0, 0x58, 0x13C, 0x13E, 0x140)


class Case:
    def __init__(self, name, **fields):
        self.name = name
        self.round = 1000
        self.last = 999
        self.execution_bound = 2000
        self.leader = "self"
        self.stake = "in"
        self.high_qc = (999, 0x7000)
        self.tc = None
        self.prune = 0
        self.txs = []
        self.excluded = ()
        self.seen = ()
        self.missing = None
        self.ask = 1
        self.blocks = None
        self.watermark = 900
        self.force = 0
        self.now = (40000, 500000000)
        self.once_state = 1
        self.__dict__.update(fields)
        if self.blocks is None:
            self.blocks = [(self.high_qc[1] if self.high_qc else 0x7000, 999, 0, (39999, 0))]


def tx(key, age_ms=0, size=100, tag=0x40, used=0, bad=False):
    return (key, age_ms, size, tag, used, bad)


def add_time(time, seconds):
    """Whole fixture days are not crossed, so the date word stays fixed."""
    total = time[0] * 10 ** 9 + time[1] + int(seconds * 1e9)
    return (total // 10 ** 9, total % 10 ** 9)


def tx_time(case, item):
    total = case.now[0] * 10 ** 9 + case.now[1] - item[1] * 10 ** 6
    return (total // 10 ** 9, total % 10 ** 9)


def millis(time):
    return time[0] * 1000 + time[1] // 10 ** 6


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        hooks = {SLOT_MEMCMP: self.on_memcmp, SLOT_LEADER: self.on_leader, SLOT_LOG: self.on_log, SLOT_ADD_SECS: self.on_add_secs, SLOT_MEMCPY: self.on_memcpy,
                 SLOT_DEALLOC: self.on_nothing, SLOT_ONCE: self.on_once, SLOT_GROW_HASHES: self.on_grow_hashes, SLOT_GROW_RECORDS: self.on_grow_records,
                 SLOT_SORT: self.on_sort, SLOT_SUM_PANIC: self.on_panic, SLOT_BTREE_PANIC: self.on_panic}
        for index, (slot, hook) in enumerate(sorted(hooks.items())):
            mark = MARK_BASE + index * 16
            memory.statics[slot] = mark
            machine.slots[mark] = hook
        memory.statics[SLOT_MILLIS] = MILLIS
        machine.real = frozenset((PENDING, SEEN_LOOKUP, BLOCK_LOOKUP, INSERTION, HIGH_QC, SIGN_BLOCK, PUSH_OUT, PRUNE_NEXT, MILLIS))
        machine.calls = {0x42C9930: self.on_stakes, 0x4B1A270: self.on_nothing, 0x447E690: self.on_nothing, 0x4847500: self.on_clone, 0x47328A0: self.on_nothing,
                         0x44B9800: self.on_walk, 0x44B8050: self.on_ask, 0x49AC240: self.on_nothing, 0x4480730: self.on_removed, 0x45485A0: self.on_verify,
                         0x42B27E0: self.on_remove, 0x454C050: self.on_digest, 0x14A2710: self.on_sign}
        machine.step_limit = STEP_LIMIT
        self.case = None
        self.bump = NODES

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("fixture heap exhausted")
        return at

    def on_nothing(self, machine):
        pass

    def on_memcmp(self, machine):
        regs = machine.regs
        left = machine.memory.bytes_at(regs[RDI], regs[RDX])
        right = machine.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else 0x7 if left > right else (-5) & MASK[4]

    def on_memcpy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_leader(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        self.expect(regs[RSI] == STATE + 0x930 and regs[RDX] == case.round, "leader arguments")
        memory.write(regs[RDI], 8, OK_TAG if case.leader != "error" else (1 << 63) + 3)
        memory.put_bytes(regs[RDI] + 8, SELF if case.leader == "self" else OTHER)

    def on_stakes(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        self.expect(regs[RDI] == STATE + 0x930 and regs[RSI] == case.round, "stake lookup arguments")
        if case.stake == "none":
            regs[RAX] = 0
            return
        regs[RAX] = STATE + 0xA00
        regs[RDX] = self.stake_map
        machine.keep_rdx = True

    def on_log(self, machine):
        regs, memory = machine.regs, machine.memory
        size = memory.read(regs[RSI], 1)
        self.logs.append((regs[RCX], bytes(memory.bytes_at(regs[RSI] + 1, size)).split(b"?")[0] + b"?"))

    def on_once(self, machine):
        self.expect(machine.regs[RDI] == ONCE_WORD, "Once word")
        self.onces += 1

    def on_panic(self, machine):
        raise Panicked("panic")

    def on_add_secs(self, machine):
        regs, memory = machine.regs, machine.memory
        seconds = to_float(machine.xmm[0] & MASK[8])
        self.added.append(seconds)
        date, secs, nanos = struct.unpack("<iII", memory.bytes_at(regs[RSI], 12))
        self.expect(date == DATE, "time date word")
        secs, nanos = add_time((secs, nanos), seconds)
        memory.put_bytes(regs[RDI], struct.pack("<iII", date, secs, nanos))

    def grow(self, machine, size):
        regs, memory = machine.regs, machine.memory
        vector = regs[RDI]
        cap, pointer = memory.read(vector, 8), memory.read(vector + 8, 8)
        new = max(4, cap * 2)
        at = self.alloc(new * size)
        if cap:
            memory.copy(at, pointer, cap * size)
        memory.write(vector, 8, new)
        memory.write(vector + 8, 8, at)

    def on_grow_hashes(self, machine):
        self.grow(machine, 32)

    def on_grow_records(self, machine):
        self.grow(machine, 0x38)

    def on_sort(self, machine):
        """Stable sort, the same key as the insertion sort; only runs with at least 21 records."""
        regs, memory = machine.regs, machine.memory
        base, count = regs[RDI], regs[RSI]
        rows = [memory.bytes_at(base + 0x38 * index, 0x38) for index in range(count)]
        rows.sort(key=lambda row: struct.unpack_from("<iII", row, 0x28))
        for index, row in enumerate(rows):
            memory.put_bytes(base + 0x38 * index, row)
        self.big_sorts += 1

    def on_clone(self, machine):
        regs, memory = machine.regs, machine.memory
        memory.copy(regs[RDI], regs[RSI], 24)
        regs[RAX] = regs[RDI]

    def on_walk(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        self.expect(regs[RSI] == STATE, "walk state")
        out = regs[RDI]
        self.walk_context = regs[RDX]
        if case.missing is not None:
            memory.write(out, 1, 1)
            memory.put_bytes(out + 1, case.missing.to_bytes(32, "big"))
            return
        memory.write(out, 1, 0)
        root, height = self.build(TX_SET, [(key, b"") for key in sorted(case.excluded)])
        memory.write(out + 8, 8, root)
        memory.write(out + 16, 8, height)
        memory.write(out + 24, 8, len(case.excluded))

    def on_ask(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        self.expect(regs[RSI] == STATE, "ask state")
        time = struct.unpack("<iII", memory.bytes_at(regs[RDX], 12))
        hash_value = int.from_bytes(memory.bytes_at(regs[RCX], 32), "big")
        self.asks.append((time, hash_value, regs[R8] & 1, regs[R9] & 0xFF, to_float(machine.xmm[0] & MASK[8])))
        memory.write(regs[RDI], 1, case.ask)
        memory.put_bytes(regs[RDI] + 1, bytes(range(1, 0x31)))

    def on_verify(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        self.expect(regs[RSI] == STATE + 8 and regs[R8] & 1 == 1, "verify arguments")
        key = int.from_bytes(memory.bytes_at(regs[RDX], 32), "big")
        self.verified.append(key)
        bad = any(item[0] == key and item[5] for item in case.txs)
        memory.write(regs[RDI], 8, TC_EMPTY_TAG if bad else OK_TAG)

    def on_remove(self, machine):
        regs, memory = machine.regs, machine.memory
        node, height, index = (memory.read(regs[RSI] + 8 * at, 8) for at in range(3))
        self.expect(height == 0, "remove from a leaf only")
        layout = TX_LAYOUT
        count = memory.read(node + layout.len_at, 2)
        out = regs[RDI]
        memory.copy(out, node + 32 * index, 32)
        memory.copy(out + 32, node + layout.val_at + TX_VALUE * index, TX_VALUE)
        for at in range(index, count - 1):
            memory.copy(node + 32 * at, node + 32 * (at + 1), 32)
            memory.copy(node + layout.val_at + TX_VALUE * at, node + layout.val_at + TX_VALUE * (at + 1), TX_VALUE)
        memory.write(node + layout.len_at, 2, count - 1)
        memory.write(out + 0x78, 8, node)
        memory.write(out + 0x80, 8, 0)
        memory.write(out + 0x88, 8, index)

    def on_removed(self, machine):
        self.removed += 1

    def on_digest(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(memory.read(regs[RSI], 8) == 0, "digest variant word")
        self.signed_block = memory.bytes_at(memory.read(regs[RSI] + 8, 8), 0xB0)
        memory.put_bytes(regs[RDI], bytes(range(0x80, 0xA0)))

    def on_sign(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == STATE + 0x9D0, "signing key field")
        self.expect(memory.bytes_at(regs[RDX], 32) == bytes(range(0x80, 0xA0)), "signed digest")
        memory.write(regs[RDI], 4, 0)
        memory.put_bytes(regs[RDI] + 8, bytes(range(0x10, 0x51)))

    def build(self, layout, items):
        """Write items, sorted, as one leaf or one root over leaves; returns (root, height)."""
        if not items:
            return 0, 0
        memory = self.machine.memory

        def node(rows, edges=()):
            at = self.alloc(layout.size)
            memory.put_bytes(at, b"\xee" * layout.size)
            memory.write(at + layout.parent_at, 8, 0)
            memory.write(at + layout.len_at, 2, len(rows))
            for index, (key, value) in enumerate(rows):
                memory.put_bytes(at + layout.key_at + layout.key_size * index, key.to_bytes(layout.key_size, "big"))
                if layout.val_size:
                    memory.put_bytes(at + layout.val_at + layout.val_size * index, value)
            for index, child in enumerate(edges):
                memory.write(at + layout.edges_at + 8 * index, 8, child)
                memory.write(child + layout.parent_at, 8, at)
                memory.write(child + layout.pidx_at, 2, index)
            return at

        if len(items) <= 11:
            return node(items), 0
        leaves = (len(items) + 12) // 12
        each = (len(items) - (leaves - 1)) // leaves
        spare = (len(items) - (leaves - 1)) % leaves
        children, parents, at = [], [], 0
        for index in range(leaves):
            count = each + (1 if index < spare else 0)
            children.append(node(items[at:at + count]))
            at += count
            if index + 1 < leaves:
                parents.append(items[at])
                at += 1
        return node(parents, children), 1

    def tx_value(self, case, item):
        key, _, size, tag, used, _ = item
        size_at = SIZES + self.sizes * 0x30
        self.sizes += 1
        memory = self.machine.memory
        memory.write(size_at + 0x20, 8, size)
        secs, nanos = tx_time(case, item)
        value = bytearray(b"\xdd" * TX_VALUE)
        value[0:12] = struct.pack("<iII", DATE, secs, nanos)
        struct.pack_into("<Q", value, 0x10, tag)
        struct.pack_into("<Q", value, 0x48, size_at)
        value[0x50] = used
        return bytes(value)

    def block_value(self, row):
        _, round_number, hashes, time = row
        value = bytearray(b"\xcc" * BLOCK_VALUE)
        struct.pack_into("<Q", value, 0x10, hashes)
        struct.pack_into("<Q", value, 0x88, round_number)
        value[0x90:0x9C] = struct.pack("<iII", DATE, time[0], time[1])
        return bytes(value)

    def set_state(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        self.bump = NODES
        self.logs, self.added, self.asks, self.verified = [], [], [], []
        self.onces = self.removed = self.sizes = self.big_sorts = 0
        self.signed_block = None
        self.walk_context = None
        self.case = case
        memory.statics[ONCE_WORD] = case.once_state
        memory.put_bytes(STATE, STATE_FILL)

        def word(offset, value):
            memory.write(STATE + offset, 8, value)
        word(0, case.prune)
        word(0x198, case.watermark)
        word(0x918, case.round)
        word(0x928, case.last)
        word(0x988, case.execution_bound)
        memory.put_bytes(STATE + 0xAC8, struct.pack("<iII", DATE, case.now[0], case.now[1]))
        memory.put_bytes(STATE + 0xAEC, SELF)
        memory.write(STATE + 0xB00, 1, case.force)
        word(0x4D0, OUTBOX_CAP)
        word(0x4D8, OUTBOX)
        word(0x4E0, 0)
        if case.high_qc is None:
            word(0x438, NONE_TAG)
        else:
            self.put_qc(STATE + 0x438, case.high_qc, 0x11)
        if case.tc is None:
            word(0x8A0, NONE_TAG)
        else:
            word(0x8A0, len(case.tc) + 1)
            word(0x8A8, TC_RECORDS)
            word(0x8B0, len(case.tc))
            word(0x8B8, case.round - 1)
            for index, qc in enumerate(case.tc):
                self.put_qc(TC_RECORDS + 0xB8 * index, qc, 0x20 + index)
        rows = sorted(case.txs)
        root, height = self.build(TX_LAYOUT, [(item[0], self.tx_value(case, item)) for item in rows])
        word(0x1A0, root)
        word(0x1A8, height)
        word(0x1B0, len(rows))
        root, height = self.build(BLOCK_LAYOUT, [(row[0], self.block_value(row)) for row in sorted(case.blocks)])
        word(0x1B8, root)
        word(0x1C0, height)
        word(0x1C8, len(case.blocks))
        root, height = self.build(SEEN_LAYOUT, [(key, b"\x01") for key in sorted(case.seen)])
        word(0x58, root)
        word(0x60, height)
        word(0x68, len(case.seen))
        stakes = [(int.from_bytes(OTHER, "big"), b"")]
        if case.stake == "in":
            stakes = [(int.from_bytes(SELF, "big") - 3 + index, b"") for index in range(6)]
        elif case.stake == "deep":
            stakes = sorted((int.from_bytes(SELF, "big") + index - 14, b"") for index in range(30))
        elif case.stake == "empty":
            stakes = []
        root, height = self.build(STAKE_LAYOUT, stakes)
        self.stake_map = self.alloc(16)
        memory.write(self.stake_map, 8, root)
        memory.write(self.stake_map + 8, 8, height)

    def put_qc(self, at, qc, seed):
        memory = self.machine.memory
        for index in range(5):
            memory.write(at + 8 * index, 8, seed * 0x100 + index)
        memory.write(at + 0x28, 8, qc[0])
        memory.put_bytes(at + 0x30, qc[1].to_bytes(32, "big"))

    def run(self, case):
        machine = self.machine
        memory = machine.memory
        self.set_state(case)
        machine.xmm = [POISON | POISON << 64] * 16
        before = bytes(memory.bytes_at(STATE, STATE_SIZE))
        panicked = False
        try:
            machine.run(PROPOSER, {RDI: STATE})
        except Panicked:
            panicked = True
        return self.observe(before, panicked)

    def observe(self, before, panicked):
        memory = self.machine.memory
        after = memory.bytes_at(STATE, STATE_SIZE)
        changed = sorted({index & ~7 for index in range(0, STATE_SIZE) if before[index] != after[index]}) if before != after else []
        out = []
        for index in range(struct.unpack_from("<Q", after, 0x4E0)[0]):
            record = OUTBOX + RECORD * index
            tag = memory.read(record, 8)
            if tag == 2:
                out.append(("block", self.block_of(record + 8)))
            else:
                out.append((tag, memory.bytes_at(record + 8, 0x38)))
        return dict(panicked=panicked, last=struct.unpack_from("<Q", after, 0x928)[0], tc_word=struct.unpack_from("<Q", after, 0x8A0)[0], out=out,
                    logs=[(hex(at), text) for at, text in self.logs], onces=self.onces, asks=list(self.asks), verified=list(self.verified),
                    removed=self.removed, tx_count=struct.unpack_from("<Q", after, 0x1B0)[0], changed=changed, added=list(self.added))

    def block_of(self, at):
        memory = self.machine.memory
        count = memory.read(at + 0x10, 8)
        pointer = memory.read(at + 8, 8)
        hashes = [int.from_bytes(memory.bytes_at(pointer + 32 * index, 32), "big") for index in range(count)]
        return dict(hashes=hashes, qc_words=[memory.read(at + 0x18 + 8 * index, 8) for index in range(5)], qc_round=memory.read(at + 0x40, 8),
                    qc_hash=int.from_bytes(memory.bytes_at(at + 0x48, 32), "big"), tc=[memory.read(at + 0x68 + 8 * index, 8) for index in range(4)],
                    round=memory.read(at + 0x88, 8), time=struct.unpack("<iII", memory.bytes_at(at + 0x90, 12)), proposer=memory.bytes_at(at + 0x9C, 20),
                    signature=memory.bytes_at(at + 0xB0, 0x41))


TX_SET = SET_LAYOUT


def spec_run(case):
    """The written rules, without any instruction row. Returns (label, observation)."""
    want = dict(panicked=False, last=case.last, tc_word=NONE_TAG if case.tc is None else len(case.tc) + 1, out=[], logs=[], onces=0, asks=[], verified=[], removed=0,
                tx_count=len(case.txs), changed=set(), added=[])

    def done(label):
        return label, want

    if case.leader == "error":
        return done("leader lookup error")
    if case.leader != "self":
        return done("not the leader")
    if case.last >= case.round:
        return done("already proposed this round")
    if case.round > case.execution_bound:
        want["logs"].append((hex(LOCATION_LOG), b"Querying stakes for high round, is execution behind?"))
    if case.stake in ("none", "empty", "out"):
        want["onces"] = 1 if case.once_state else 0
        return done("no stake entry")
    if case.tc is None:
        if case.high_qc is None:
            return done("no QC")
        qc, words = case.high_qc, [0x11 * 0x100 + index for index in range(5)]
    else:
        if not case.tc:
            return done("empty TC")
        best = 0
        for index, row in enumerate(case.tc):
            if row[0] >= case.tc[best][0]:
                best = index
        qc, words = case.tc[best], [(0x20 + best) * 0x100 + index for index in range(5)]
    rows = sorted(case.txs)
    if case.prune == 1:
        kept = []
        for item in rows:
            if item[3] not in (NONE_TAG, TX_SKIP_TAG) and not item[4]:
                want["verified"].append(item[0])
                if item[5]:
                    want["removed"] += 1
                    want["tx_count"] -= 1
                    want["changed"].add(0x1B0)
                    continue
            kept.append(item)
        rows = kept
    if case.missing is not None:
        ask_time = (DATE, case.now[0], case.now[1])
        want["asks"].append((ask_time, case.missing, 1, 5, 0.0))
        if case.ask != 2:
            want["out"].append((0xA, bytes([case.ask]) + bytes(range(1, 0x31)) + bytes(0x38 - 0x31)))
            want["changed"].add(0x4E0)
        return done("missing ancestor, ask")
    picked = []
    for item in rows:
        if item[3] == TX_SKIP_TAG or item[4] or item[0] in case.excluded:
            continue
        want["added"].append(10.0)
        time = tx_time(case, item)
        if add_time(time, 10.0) < case.now:
            continue
        picked.append((time, item))
    picked.sort(key=lambda row: row[0])
    if sum(row[1][2] for row in picked) >= 1 << 64:
        want["panicked"] = True
        return done("size sum overflow panic")
    hashes, total = [], 0
    for _, item in picked:
        total = min(total + item[2], (1 << 64) - 1)
        if total > BYTES_CAP and hashes:
            break
        hashes.append(item[0])
        if len(hashes) >= HASHES_CAP:
            break
    pending = any(row[1] > case.watermark and row[2] for row in case.blocks)
    if not hashes and not pending and not case.force:
        return done("idle, no block")
    want["last"] = case.round
    if case.round != case.last:
        want["changed"].add(0x928)
    parent = next((row for row in case.blocks if row[0] == qc[1]), None)
    if parent is None:
        return done("marked, parent block unknown")
    want["added"].append(0.05)
    early = add_time(case.now, 0.05)
    if millis(early) > millis(parent[3]):
        time = early
    else:
        want["added"].append(0.001)
        time = add_time(parent[3], 0.001)
    tc = [NONE_TAG] if case.tc is None else [len(case.tc) + 1, TC_RECORDS, len(case.tc), case.round - 1]
    block = dict(hashes=hashes, qc_words=words, qc_round=qc[0], qc_hash=qc[1], tc=tc, round=case.round, time=(DATE, time[0], time[1]), proposer=SELF, signature=bytes(range(0x10, 0x51)))
    want["out"].append(("block", block))
    want["changed"].add(0x4E0)
    if case.tc is not None:
        want["tc_word"] = NONE_TAG
        want["changed"].add(0x8A0)
    return done("block sent")


def same(got, want):
    for key in ("panicked", "last", "tc_word", "logs", "onces", "asks", "verified", "removed", "tx_count", "added"):
        if got[key] != want[key]:
            return False
    if set(got["changed"]) != want["changed"]:
        return False
    if len(got["out"]) != len(want["out"]):
        return False
    for mine, other in zip(got["out"], want["out"]):
        if mine[0] != other[0]:
            return False
        if mine[0] == "block":
            left = dict(mine[1])
            if left["tc"][0] == NONE_TAG:
                left["tc"] = [NONE_TAG]
            if left != other[1]:
                return False
        elif mine[1][:0x31] != other[1][:0x31]:
            return False
    return True


def named_cases():
    out = []
    add = out.append
    txs = [tx(0x100 + index, index) for index in range(3)]
    add(Case("plain one tx", txs=[tx(0x100)]))
    add(Case("three txs", txs=txs))
    add(Case("leader error", leader="error", txs=txs))
    add(Case("other leader", leader="other", txs=txs))
    add(Case("last equal round", last=1000, txs=txs))
    add(Case("last above round", last=1001, txs=txs))
    add(Case("last one below", last=999, txs=txs))
    add(Case("round above bound", round=2001, last=2000, high_qc=(2000, 0x7000), txs=txs))
    add(Case("round at bound", round=2000, last=1999, high_qc=(1999, 0x7000), txs=txs))
    add(Case("no snapshot", stake="none", txs=txs))
    add(Case("empty stake map", stake="empty", txs=txs))
    add(Case("not staked", stake="out", txs=txs))
    add(Case("not staked once done", stake="out", once_state=0, txs=txs))
    add(Case("deep stake map", stake="deep", txs=txs))
    add(Case("no QC", high_qc=None, blocks=[(0x7000, 999, 0, (39999, 0))], txs=txs))
    add(Case("TC empty", tc=[], txs=txs))
    add(Case("TC one", tc=[(995, 0x7000)], txs=txs))
    add(Case("TC two", tc=[(995, 0x7000), (996, 0x7001)], blocks=[(0x7001, 996, 0, (39999, 0))], txs=txs))
    add(Case("TC two high first", tc=[(997, 0x7000), (996, 0x7001)], txs=txs))
    add(Case("TC tie last wins", tc=[(997, 0x7000), (997, 0x7001), (997, 0x7002)], blocks=[(0x7002, 997, 0, (39999, 0))], txs=txs))
    add(Case("TC three", tc=[(990, 0x7000), (997, 0x7001), (993, 0x7002)], blocks=[(0x7001, 997, 0, (39999, 0))], txs=txs))
    add(Case("TC four", tc=[(990, 0x7000), (991, 0x7001), (992, 0x7002), (993, 0x7003)], blocks=[(0x7003, 993, 0, (39999, 0))], txs=txs))
    add(Case("TC five middle", tc=[(990, 0x7000), (991, 0x7001), (999, 0x7002), (993, 0x7003), (992, 0x7004)], blocks=[(0x7002, 999, 0, (39999, 0))], txs=txs))
    add(Case("TC QC differs from high", tc=[(995, 0x7001)], high_qc=(999, 0x7000), blocks=[(0x7001, 995, 0, (39999, 0))], txs=txs))
    add(Case("TC empties hash list idle", tc=[(995, 0x7000)]))
    add(Case("TC forced empty", tc=[(995, 0x7000)], force=1))
    add(Case("missing ancestor", missing=0x7777, txs=txs))
    add(Case("missing ancestor throttled", missing=0x7778, ask=2, txs=txs))
    add(Case("missing ancestor answer 0", missing=0x7779, ask=0, txs=txs))
    add(Case("no txs idle"))
    add(Case("forced empty block", force=1))
    add(Case("pending block with hashes", blocks=[(0x7000, 999, 0, (39999, 0)), (0x7100, 950, 2, (39990, 0))]))
    add(Case("pending block at watermark", blocks=[(0x7000, 999, 0, (39999, 0)), (0x7100, 900, 2, (39990, 0))]))
    add(Case("pending block one above", blocks=[(0x7000, 999, 0, (39999, 0)), (0x7100, 901, 1, (39990, 0))]))
    add(Case("pending below watermark", blocks=[(0x7000, 999, 0, (39999, 0)), (0x6100, 899, 5, (39990, 0))]))
    add(Case("pending no hashes", blocks=[(0x7000, 999, 0, (39999, 0)), (0x7100, 950, 0, (39990, 0))]))
    add(Case("pending in a deep map", blocks=[(0x7000 + index, 999 if index == 0 else 800, 0, (39999, 0)) for index in range(20)] + [(0x8000, 950, 3, (39990, 0))]))
    add(Case("no pending in a deep map", blocks=[(0x7000 + index, 999 if index == 0 else 800, 0, (39999, 0)) for index in range(20)] + [(0x8000, 850, 3, (39990, 0))]))
    add(Case("pending at the end of leaf", blocks=[(0x7000 + index, 999 if index == 0 else 800, 0, (39999, 0)) for index in range(11)] + [(0x7100, 950, 1, (39990, 0))]))
    add(Case("tx exactly 10 s old", txs=[tx(0x100, 10000)]))
    add(Case("tx 10 s and 1 ms old", txs=[tx(0x100, 10001)]))
    add(Case("tx 9.999 s old", txs=[tx(0x100, 9999)]))
    add(Case("tx 1 day newer than now", txs=[tx(0x100, -2000)]))
    add(Case("skip tag", txs=[tx(0x100, tag=TX_SKIP_TAG), tx(0x101)]))
    add(Case("none tag is taken", txs=[tx(0x100, tag=NONE_TAG), tx(0x101)]))
    add(Case("used flag", txs=[tx(0x100, used=1), tx(0x101)]))
    add(Case("excluded", txs=[tx(0x100), tx(0x101), tx(0x102)], excluded=(0x101,)))
    add(Case("excluded all", txs=[tx(0x100), tx(0x101)], excluded=(0x100, 0x101)))
    add(Case("excluded deep", txs=[tx(0x100 + index) for index in range(14)], excluded=tuple(0x100 + index * 2 for index in range(7)) + tuple(0x900 + index for index in range(14))))
    add(Case("seen lookup hit changes nothing", txs=[tx(0x100), tx(0x101)], seen=(0x100,)))
    add(Case("seen lookup deep", txs=[tx(0x100), tx(0x105)], seen=tuple(0x100 + index for index in range(15))))
    add(Case("two records reversed", txs=[tx(0x100, 5), tx(0x101, 50)]))
    add(Case("sort by age", txs=[tx(0x100, 5), tx(0x101, 50), tx(0x102, 20), tx(0x103, 700)]))
    add(Case("sort tie keeps key order", txs=[tx(0x103, 7), tx(0x101, 7), tx(0x102, 7)]))
    add(Case("sort ms and nanos", txs=[tx(0x100, 1000), tx(0x101, 999), tx(0x102, 1001)]))
    add(Case("bytes exactly cap", txs=[tx(0x100, 3, 3000000), tx(0x101, 2, 1000000), tx(0x102, 1, 1)]))
    add(Case("bytes cap plus 1", txs=[tx(0x100, 3, 3000000), tx(0x101, 2, 1000001), tx(0x102, 1, 1)]))
    add(Case("first over cap is kept", txs=[tx(0x100, 3, 9000000), tx(0x101, 2, 1)]))
    add(Case("stops, does not skip", txs=[tx(0x100, 3, 3999999), tx(0x101, 2, 5), tx(0x102, 1, 1)]))
    add(Case("size sum overflow", txs=[tx(0x100, 3, 1 << 63), tx(0x101, 2, 1 << 63)]))
    add(Case("size sum top", txs=[tx(0x100, 3, (1 << 64) - 2), tx(0x101, 2, 1)]))
    add(Case("sum counts picked only", txs=[tx(0x100, 20000, 1 << 63), tx(0x101, 2, 1 << 63)]))
    add(Case("parent missing", blocks=[(0x7100, 999, 0, (39999, 0))], txs=txs))
    add(Case("parent missing with TC", tc=[(995, 0x7000)], blocks=[(0x7100, 999, 0, (39999, 0))], txs=txs))
    add(Case("parent missing idle", blocks=[(0x7100, 999, 0, (39999, 0))]))
    add(Case("parent time before", blocks=[(0x7000, 999, 0, (39000, 123456789))], txs=txs))
    add(Case("parent time equal candidate ms", blocks=[(0x7000, 999, 0, (40000, 550999999))], txs=txs))
    add(Case("parent ms just below", blocks=[(0x7000, 999, 0, (40000, 549999999))], txs=txs))
    add(Case("parent after candidate", blocks=[(0x7000, 999, 0, (40001, 7))], txs=txs))
    add(Case("parent after, sub ms", blocks=[(0x7000, 999, 0, (40002, 123999))], txs=txs))
    add(Case("prune off keeps bad", txs=[tx(0x100, bad=True), tx(0x101)]))
    add(Case("prune all good", prune=1, txs=[tx(0x100), tx(0x101)]))
    add(Case("prune one", prune=1, txs=[tx(0x100, bad=True), tx(0x101), tx(0x102)]))
    add(Case("prune two", prune=1, txs=[tx(0x100, bad=True), tx(0x101), tx(0x102, bad=True), tx(0x103)]))
    add(Case("prune skips skip tag", prune=1, txs=[tx(0x100, tag=TX_SKIP_TAG, bad=True), tx(0x101)]))
    add(Case("prune skips none tag", prune=1, txs=[tx(0x100, tag=NONE_TAG, bad=True), tx(0x101)]))
    add(Case("prune skips used", prune=1, txs=[tx(0x100, used=1, bad=True), tx(0x101)]))
    add(Case("prune empty map", prune=1))
    add(Case("prune word 2", prune=2, txs=[tx(0x100, bad=True)]))
    add(Case("prune then missing ancestor", prune=1, missing=0x7777, txs=[tx(0x100, bad=True), tx(0x101)]))
    add(Case("prune deep, all good", prune=1, txs=[tx(0x100 + index) for index in range(20)]))
    add(Case("twenty records", txs=[tx(0x100 + index, (index * 37) % 20) for index in range(20)]))
    add(Case("twenty one records", txs=[tx(0x100 + index, (index * 37) % 21) for index in range(21)]))
    add(Case("one hundred one records", txs=[tx(0x100 + index, (index * 37) % 101) for index in range(101)]))
    add(Case("one hundred records", txs=[tx(0x100 + index, index % 7) for index in range(100)]))
    add(Case("ninety nine records", txs=[tx(0x100 + index, index % 7) for index in range(99)]))
    add(Case("one hundred forty records", txs=[tx(0x100 + index, 140 - index) for index in range(140)]))
    return out


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11


def vector_cases(count):
    stream = lcg(0x44B4F80)
    cases = []
    for index in range(count):
        def pick(modulo):
            return next(stream) % modulo
        n = pick(16)
        txs = []
        for item in range(n):
            txs.append(tx(0x100 + item * 3, pick(12000), [100, 2000000, 700000, 5][pick(4)], [0x40, 0x40, 0x40, NONE_TAG, TX_SKIP_TAG][pick(5)], 1 if pick(9) == 0 else 0, pick(5) == 0))
        round_number = 1000 + pick(3)
        qc = (round_number - 1 - pick(3), 0x7000 + pick(4))
        tc = None
        if pick(3) == 0:
            tc = [(round_number - 2 - pick(9), 0x7000 + pick(4)) for _ in range(1 + pick(5))]
        blocks = [(0x7000 + at, round_number - 1 - at, pick(3), (39999 + pick(3), pick(10 ** 9))) for at in range(3)]
        cases.append(Case("vector %d" % index, round=round_number, last=round_number if pick(9) == 0 else round_number - 1 - pick(3), high_qc=qc, tc=tc, txs=txs, blocks=blocks, excluded=tuple(0x100 + 3 * pick(16) for _ in range(pick(4))),
                          prune=1 if pick(3) == 0 and n <= 11 else 0, watermark=round_number - pick(6), force=1 if pick(6) == 0 else 0, execution_bound=round_number + pick(3) - 1,
                          seen=tuple(0x100 + 3 * pick(16) for _ in range(pick(3))), missing=0x7777 if pick(11) == 0 else None))
    return cases


def check_all(harness, cases):
    rows = []
    for case in cases:
        got = harness.run(case)
        label, want = spec_run(case)
        if not same(got, want):
            raise EvidenceError("case disagrees with the rule list: %s %s" % (case.name, label))
        rows.append((case, label, got))
    return rows


PINS = (
    ('select', 0x203191b, "498b1e", 'first timer pointer of the select arm, later checked to be state+0x8c0'),
    ('select', 0x2031924, "807b1801", 'armed byte of the first timer, state+0x8d8'),
    ('select', 0x203192e, "488b7b10", 'Sleep box of the first timer, state+0x8d0'),
    ('select', 0x2031937, "ff154bd77303", 'Sleep poll through slot 0x576f088'),
    ('select', 0x2031945, "c6431800", 'clears the armed byte'),
    ('select', 0x2031956, "48c7030e000000", 'result word 0xe, first timer fired'),
    ('select', 0x2031970, "498b5e08", 'second timer pointer, state+0x8e0'),
    ('select', 0x203197a, "807b1801", 'armed byte of the second timer, state+0x8f8'),
    ('select', 0x20319ac, "48c7030f000000", 'result word 0xf, second timer fired'),
    ('task', 0x204430d, "4d8db424980b0000", 'task frame holds the state at +0xb98'),
    ('task', 0x2044315, "ba080b0000", 'state moved in, 0xb08 bytes'),
    ('task', 0x204521d, "498dbc2458140000", 'first timer struct, frame+0x1458 = state+0x8c0'),
    ('task', 0x2045225, "4d8d842478140000", 'second timer struct, frame+0x1478 = state+0x8e0'),
    ('task', 0x2045278, "4989bc24a8170000", 'stored as select pointer 0'),
    ('task', 0x2045280, "4d898424b0170000", 'stored as select pointer 1'),
    ('task', 0x2045323, "4883e90b", 'select result minus 0xb indexes the table at 0x3c3c80'),
    ('task', 0x204484a, "48c78424c80200000c000000", 'event tag 0xc, from result 0xe'),
    ('task', 0x2044858, "48c78424c80200000d000000", 'event tag 0xd, from result 0xf'),
    ('task', 0x2044461, "41c684247014000001", 'task start arms the first timer'),
    ('task', 0x204454c, "41c684249014000001", 'task start arms the second timer on the leader arm'),
    ('dispatch', 0x44adfee, "8985d00a0000", 'event time nanos into state+0xad0'),
    ('dispatch', 0x44ae004, "4883ea0a", 'event tag minus 0xa indexes the table at 0x6f2a34'),
    ('dispatch', 0x44ae016, "488995c80a0000", 'event time date and secs into state+0xac8'),
    ('dispatch', 0x44ae35a, "488b85b0090000", 'tag 0xc arm reads the fired count state+0x9b0'),
    ('dispatch', 0x44ae3a4, "4883fb02", 'fired count against 2'),
    ('dispatch', 0x44ae3bc, "488b98d0080000", 'tag 0xc arm reads the first Sleep box'),
    ('dispatch', 0x44ae3d5, "488b8fc0080000", 'adds state+0x8c0 to now'),
    ('dispatch', 0x44ae433, "c680d808000001", 'rearms: armed byte state+0x8d8 = 1'),
    ('dispatch', 0x44ae44d, "c685000b000001", 'tag 0xd arm sets state+0xb00 = 1'),
    ('dispatch', 0x44ae465, "ff15c5512c01", 'tag 0xd arm calls the proposer'),
    ('advance', 0x44b6af2, "498b8fc0080000", 'round advance adds state+0x8c0 to now'),
    ('advance', 0x44b6b49, "41c687d808000001", 'round advance arms the first timer'),
    ('advance', 0x44b6b51, "49c787b009000000000000", 'round advance clears the fired count state+0x9b0'),
    ('advance', 0x44b6b75, "ff15adca2b01", 'leader of the new round'),
    ('advance', 0x44b6b96, "f3410f6f8fec0a0000", 'compares with the own 20 byte key state+0xaec'),
    ('advance', 0x44b6bcb, "0f8584000000", 'not the leader: skip the second timer'),
    ('advance', 0x44b6be2, "498b8fe0080000", 'leader: adds state+0x8e0 to now'),
    ('advance', 0x44b6c39, "41c687f808000001", 'leader: arms the second timer'),
    ('advance', 0x44b6c55, "41c687000b000000", 'every round advance clears state+0xb00'),
    ('constructor', 0x44a9403, "f20f1005f51ad6fb", 'loads 0.3'),
    ('constructor', 0x44a940b, "e860e26700", 'Duration from f64 seconds'),
    ('constructor', 0x44a9413, "4189d5", 'nanos of the first duration'),
    ('constructor', 0x44a9445, "44896c2418", 'nanos kept in stack slot +0x18'),
    ('constructor', 0x44a94b8, "f20f10051814d6fb", 'loads the f64 just under 0.1'),
    ('constructor', 0x44a94c0, "e8abe16700", 'Duration from f64 seconds'),
    ('constructor', 0x44a94c5, "4989c7", 'secs of the second duration in r15'),
    ('constructor', 0x44a94e3, "44896c2448", 'nanos kept in stack slot +0x48'),
    ('constructor', 0x44a94ff, "48895c2410", 'secs of the first duration in stack slot +0x10'),
    ('constructor', 0x44a992e, "498986c0080000", 'state+0x8c0 secs'),
    ('constructor', 0x44a9939, "418986c8080000", 'state+0x8c8 nanos'),
    ('constructor', 0x44a995a, "4d89bee0080000", 'state+0x8e0 secs'),
    ('constructor', 0x44a9965, "418986e8080000", 'state+0x8e8 nanos'),
    ('constructor', 0x44a997b, "6641c786000b00000000", 'state+0xb00 and +0xb01 start at 0'),
    ('time', 0x1459cb6, "f20f59056205dbfe", 'seconds times 1e9'),
    ('time', 0x1459d11, "f2480f2cc9", 'truncating f64 to i64 nanoseconds'),
)


CONSTANTS = (
    (0x20A8A8, 0x4024000000000000, "tx age window added to the tx time, seconds"),
    (0x20A4C0, 0x3FA999999999999A, "added to the event time for the block time, seconds"),
    (0x20AFB8, 0x3F50624DD2F1A9FC, "added to the parent time when the parent is not older, seconds"),
    (0x20AF00, 0x3FD3333333333333, "first timer, seconds"),
    (0x20A8D8, 0x3FB9999999999999, "second timer, seconds"),
    (0x20A220, 0x41CDCD6500000000, "nanoseconds per second in 0x1459ca0"),
)
TRIGGERS = (
    (0x20445BD, 0x2043F70, "task start, after the timers are armed"),
    (0x22BF527, 0x22BF220, "task start, second copy"),
    (0x44AE334, 0x44ADFA0, "arm that calls 0x44b9a50, then 0x44ab970 and 0x44aa5a0"),
    (0x44AE465, 0x44ADFA0, "tag 0xd, second timer fired, state+0xb00 set first"),
    (0x44B1816, 0x44ADFA0, "after 0x44ab970 and 0x44aa5a0, or after 0x44b6670 from a direct TC returned true"),
    (0x44B263B, 0x44ADFA0, "after 0x44b6670 from a timeout quorum returned true"),
    (0x44B26EB, 0x44ADFA0, "after 0x44ab560 returned true"),
)
FIELDS = (
    (0x928, "last proposed round", ((0x44A96EC, "write", "constructor"), (0x44B5013, "read", "proposer gate"), (0x44B5DD9, "write", "proposer, copy of state+0x918"))),
    (0xB00, "force an empty block", ((0x44A997B, "write", "constructor, 16 bit zero"), (0x44AE44D, "write", "tag 0xd arm, 1"), (0x44B5DC4, "read", "proposer"), (0x44B6C55, "write", "round advance, 0"))),
)
FIELD_RANGE = (0x44A8420, 0x44C3000)
LAYOUT = (
    ("block", 0x00, 0x18, "tx hash vector: cap, ptr, len", 0x44B5EEF),
    ("block", 0x18, 0x18, "QC signature vector, cloned", 0x44B5F2B),
    ("block", 0x30, 0x10, "two QC words", 0x44B5F2B),
    ("block", 0x40, 0x08, "QC round", 0x44B5F2B),
    ("block", 0x48, 0x20, "QC block hash", 0x44B5F2B),
    ("block", 0x68, 0x20, "TC moved out of state+0x8a0, None word 0x8000000000000000", 0x44B5F7B),
    ("block", 0x88, 0x08, "round, state+0x918", 0x44B5FA1),
    ("block", 0x90, 0x0C, "time: date i32, secs u32, nanos u32", 0x44B5FA9),
    ("block", 0x9C, 0x14, "proposer key, state+0xaec", 0x44B5F12),
    ("signed block", 0xB0, 0x40, "signature bytes from 0x14a2710", 0x454ADFB),
    ("signed block", 0xF0, 0x01, "one more signature byte", 0x454AE1B),
    ("outbox record", 0x00, 0x08, "tag: 2 block, 0xa ask for a missing block", 0x44B5FEA),
    ("outbox record", 0x08, 0xF1, "payload", 0x44B5FDE),
    ("tx map value", 0x00, 0x0C, "time, same three words", 0x44B5A4D),
    ("tx map value", 0x10, 0x08, "tag word: 0x8000000000000001 skipped by selection, also 0x8000000000000000 skipped by prune", 0x44B5A69),
    ("tx map value", 0x48, 0x08, "pointer to a record with the byte size at +0x20", 0x44B5BD2),
    ("tx map value", 0x50, 0x01, "skip flag", 0x44B5A88),
    ("block map value", 0x10, 0x08, "tx hash count", 0x44B97A5),
    ("block map value", 0x88, 0x08, "round", 0x44B9797),
    ("block map value", 0x90, 0x0C, "time", 0x44B5DFD),
    ("QC", 0x28, 0x08, "round", 0x44B530F),
    ("QC", 0x30, 0x20, "block hash", 0x44B5313),
    ("TC record, 0xb8 bytes", 0x00, 0x50, "starts with a QC, chosen by round at +0x28", 0x475940E),
)
GATES = (
    (1, 0x44B4FB7, "leader lookup for state+0x918 through slot 0x5773628", "lookup error: drop, return", "leader lookup error"),
    (2, 0x44B5006, "20 byte result equals state+0xaec", "other key: return", "not the leader"),
    (3, 0x44B501A, "state+0x928 < round", "else return", "already proposed this round"),
    (4, 0x44B502F, "round > state+0x988 logs validator_set.rs:78:13, does not stop", "continues", ""),
    (5, 0x44B50DA, "stake snapshot exists and holds state+0xaec", "else Once word 0x577ab98, return", "no stake entry"),
    (6, 0x44B5288, "state+0x8a0 None takes the state QC +0x438, else the highest QC of the stored TC", "empty TC: drop, return", "empty TC"),
    (7, 0x44B53E1, "QC vector word is not None", "else return", "no QC"),
    (8, 0x44B5466, "word state+0 == 1 reverifies pending txs through 0x45485a0, failures leave the map", "continues", ""),
    (9, 0x44B56A7, "0x44b9800 returns no missing hash", "missing: 0x44b8050(1, 5, 0.0), tag 0xa unless answer 2, return", "missing ancestor, ask"),
    (10, 0x44B5A71, "tx tag is not 0x8000000000000001", "skip tx", ""),
    (11, 0x44B5A8C, "tx +0x50 byte is 0", "skip tx", ""),
    (12, 0x44B5B0C, "tx not in the 0x44b9800 set", "skip tx", ""),
    (13, 0x44B5BA5, "tx time + 10 s >= event time", "skip tx", ""),
    (14, 0x44B5C3C, "stable sort by time, oldest first; below 21 records 0x4913600", "continues", ""),
    (15, 0x44B5C56, "unsaturated u64 sum of all picked sizes", "overflow panics", "size sum overflow panic"),
    (16, 0x44B5D1D, "running saturated size < 4000001, or list empty", "stop at the first miss, no skipping", ""),
    (17, 0x44B5CC8, "at most 100 hashes", "stop", ""),
    (18, 0x44B5DCC, "list not empty, or 0x44b95a0 true, or state+0xb00", "else free, return", "idle, no block"),
    (19, 0x44B5DD9, "state+0x928 = round, before the parent lookup", "continues", ""),
    (20, 0x44B5DF7, "QC block hash found in state+0x1b8", "else return, round stays marked, TC stays", "marked, parent block unknown"),
    (21, 0x44B5E70, "millis(event + 0.05 s) > millis(parent): that time", "else parent + 0.001 s", ""),
    (22, 0x44B5F9A, "state+0x8a0 = None, TC moved into the block", "continues", ""),
    (23, 0x44B5FDE, "sign state+0x9d0 with 0x14a2710, unwrap", "panic on error", ""),
    (24, 0x44B6001, "push record tag 2 to the Vec at state+0x4d0", "return", "block sent"),
)
SURVIVOR_CLASSES = (
    ('cases only compare two millisecond values on one fixed date, so a changed date term moves both sides alike', (21301483, 21301535, 21301538, 21301546, 21301558, 21301568, 21301572, 21301581, 21301588, 21301597, 21301616, 21301620)),
    ('lookup whose result the proposer never reads', (76708874, 76708899, 76708905, 76708921, 76708924, 76708932, 76708936, 76708938, 76708945, 76708998)),
    ('log argument block, the stub checks only the Location and the text', (72044604, 72044613, 72044621, 72044626)),
    ('error word or argument handed to a stubbed drop or Once', (72045050, 72045147, 72045837, 76133064, 76133074, 76133079, 76133086, 76133095)),
    ('unrolled B-tree descent threshold, fixtures are at most two levels', (72045863, 72046831, 72047048, 72062533, 72062760, 76132856)),
    ('key scan budget or stride bit that sorted fixture keys do not reach', (72044967, 72047356, 76709517, 76709579)),
    ('empty Vec placeholder that is overwritten or never read', (72046515, 72047682, 72047729, 72047753)),
    ('saturating add is dead here, the checked sum at 0x44b5c53 panics first', (72047870, 72047877, 72047890)),
    ('size or branch of a free, dealloc is a stub', (72047999, 72048006, 72048271, 72048273, 72048302, 72048316)),
    ('date word of the compare, all fixtures share one date; this compare is not proved', (72047493, 76625565, 76625706)),
    ('sort arm threshold, both arms give the same stable order on these cases', (72048651, 72048655)),
    ('low bit of a copy size or stride that one record and fixture padding do not show', (72098717, 72098728, 72658391, 74814478, 74814489)),
    ('value only passed to a stub that ignores it, or a word the next step rewrites', (76132550, 76132730, 76133206)),
)
SURVIVORS = {(va, kind): text for text, sites in SURVIVOR_CLASSES for va in sites for kind in ("condition", "immediate")}


def text_rip_sites(image, opcode, targets):
    """Rows `opcode disp32` in .text whose rip target is in targets, as (site, target)."""
    base, code = image.text_bytes()
    found = []
    for match in re.finditer(re.escape(opcode), code):
        at = match.end()
        if at + 4 > len(code):
            continue
        target = base + at + 4 + struct.unpack_from("<i", code, at)[0]
        if target in targets:
            found.append((base + match.start(), target))
    return found


def slots_of(image, function):
    return {slot for slot, addend in image.relative().items() if addend == function}


def scan_triggers(image):
    found = sorted(site for site, _ in text_rip_sites(image, b"\xff\x15", slots_of(image, PROPOSER)))
    want = [row[0] for row in TRIGGERS]
    if found != want:
        raise EvidenceError("proposer call sites differ: %s" % [hex(site) for site in found])
    for site, host, _ in TRIGGERS:
        if image.fde(site)[0] != host:
            raise EvidenceError("call site host differs: %#x" % site)
    return found


def scan_fields(image):
    """Every [reg+disp32] with this disp in the state family, stack rows excluded."""
    rows = []
    base, code = image.text_bytes()
    low, high = FIELD_RANGE[0] - base, FIELD_RANGE[1] - base
    for offset, name, want in FIELDS:
        pattern = struct.pack("<I", offset)
        sites = []
        at = code.find(pattern, low, high)
        while at >= 0:
            modrm = code[at - 1]
            if modrm >> 6 == 2 and modrm & 7 != 4:
                prefix = at - 2
                while code[prefix] in (0x8B, 0x89, 0x39, 0x3B, 0x0A, 0xC6, 0xC7, 0x83, 0x81, 0x80, 0x66) or code[prefix] >> 4 == 4:
                    prefix -= 1
                sites.append(prefix + 1 + base)
            at = code.find(pattern, at + 1, high)
        if sites != [row[0] for row in want]:
            raise EvidenceError("field sites differ for %#x: %s" % (offset, [hex(site) for site in sites]))
        rows.append((offset, name, want))
    return rows


def check_pins(image):
    for _, va, text, _ in PINS:
        at = image.offset(va)
        data = bytes(image.blob[at:at + len(text) // 2])
        if data.hex() != text:
            raise EvidenceError("pin differs at %#x" % va)
        image.fde(va)
    return len(PINS)


def jump_entry(image, table, index):
    at = image.offset(table) + 4 * index
    return table + struct.unpack_from("<i", image.blob, at)[0]


def check_tables(image):
    """The two tables that turn a fired timer into an arm."""
    rows = [(0x3C3C80, 3, 0x204484A, "select result 0xe to event tag 0xc"), (0x3C3C80, 4, 0x2044858, "select result 0xf to event tag 0xd"),
            (0x6F2A34, 2, 0x44AE35A, "event tag 0xc to the first timer arm"), (0x6F2A34, 3, 0x44AE44D, "event tag 0xd to the second timer arm")]
    for table, index, want, _ in rows:
        if jump_entry(image, table, index) != want:
            raise EvidenceError("jump table entry differs: %#x %d" % (table, index))
    return rows


def check_constants(image):
    rows = []
    for va, bits, use in CONSTANTS:
        if struct.unpack_from("<Q", image.blob, image.offset(va))[0] != bits:
            raise EvidenceError("constant differs at %#x" % va)
        rows.append((va, bits, to_float(bits), use))
    return rows


def duration_of(image, bits):
    """Run the real f64 to Duration function; returns (secs, nanos)."""
    machine = Machine(image)
    machine.xmm[0] = bits
    secs = machine.run(FROM_SECS, {})
    return secs, machine.regs[RDX] & MASK[4]


def exact_duration(bits):
    """Round half even on the exact binary value."""
    value = fractions.Fraction(to_float(bits)) * 10 ** 9
    return divmod(round(value), 10 ** 9)


def timers(image):
    rows = []
    for name, bits, field in (("first", 0x3FD3333333333333, 0x8C0), ("second", 0x3FB9999999999999, 0x8E0)):
        got = duration_of(image, bits)
        if got != exact_duration(bits):
            raise EvidenceError("duration rule differs for %#x" % bits)
        rows.append((name, field, "%#x" % bits, repr(to_float(bits)), got[0], got[1]))
    return rows


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


def first_failure(harness, cases):
    for case in cases:
        try:
            got = harness.run(case)
            if not same(got, spec_run(case)[1]):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, struct.error):
            return case
    return None


def mutant_cases(cases):
    """Small cases first, so that the pass stays near one minute; the large ones run once in check_all."""
    return [case for case in cases if (len(case.txs) < 30 or case.name == "one hundred one records") and not case.name.startswith("vector")] + [case for case in cases if case.name.startswith("vector")][:40]


def run_mutants(image, cases, rows):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    for va, kind, patch in edits_for(image, rows):
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        hit = first_failure(harness, cases)
        host = image.fde(va)[0]
        if hit is not None:
            results.append((host, va, kind, "killed", hit.name))
        else:
            results.append((host, va, kind, "survived", SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True, vectors=240):
    triggers = scan_triggers(image)
    fields = scan_fields(image)
    pins = check_pins(image)
    tables = check_tables(image)
    constants = check_constants(image)
    timer_rows = timers(image)
    harness = Harness(image)
    cases = named_cases() + vector_cases(vectors)
    rows = check_all(harness, cases)
    machine = harness.machine
    reached = collections.Counter()
    selected = []
    for va in sorted(machine.seen):
        row = machine.cache[va]
        host = image.fde(va)[0]
        if host in STATIC_FUNCTIONS:
            reached[host] += row.size
            selected.append(row)
    result = dict(triggers=triggers, fields=fields, pins=pins, tables=tables, constants=constants, timers=timer_rows, cases=cases, rows=rows, reached=reached, vector_count=vectors, big_sorts=machine is None)
    labels = collections.Counter(label for _, label, _ in rows)
    result["labels"] = labels
    for _, _, _, _, label in GATES:
        if label and not labels[label]:
            raise EvidenceError("gate outcome never reached: %s" % label)
    if mutate:
        result["mutations"] = run_mutants(image, mutant_cases(cases), selected)
        unexplained = [row for row in result["mutations"] if row[4] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[1]), row[2]) for row in unexplained])
    return result


def clean(text):
    return re.sub(r"[^\x20-\x7e]", "?", text)


def render(result, image):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("gates.tsv", ("order", "site", "rule", "otherwise", "outcome_label", "cases"), [(order, "%#x" % va, rule, other, label or "-", result["labels"][label] if label else "-") for order, va, rule, other, label in GATES])
    tsv("functions.tsv", ("function", "end", "bytes", "reached_bytes", "role"), [("%#x" % start, "%#x" % image.exact_fde(start)[1], image.exact_fde(start)[1] - start, result["reached"][start], ROLES[start]) for start in STATIC_FUNCTIONS])
    tsv("stubs.tsv", ("target", "kind", "what"), [("%#x" % key, "direct call", text) for key, text in sorted(STUBS.items())] + [("%#x" % key, "data slot", text) for key, text in sorted(SLOT_STUBS.items())])
    tsv("triggers.tsv", ("site", "host", "context"), [("%#x" % site, "%#x" % host, text) for site, host, text in TRIGGERS])
    tsv("fields.tsv", ("state_offset", "name", "site", "access", "where"), [("%#x" % offset, name, "%#x" % site, access, where) for offset, name, sites in result["fields"] for site, access, where in sites])
    tsv("layouts.tsv", ("record", "offset", "size", "field", "site"), [(record, "%#x" % offset, "%#x" % size, field, "%#x" % site) for record, offset, size, field, site in LAYOUT])
    tsv("pins.tsv", ("group", "address", "bytes", "meaning"), [(group, "%#x" % va, text, meaning) for group, va, text, meaning in PINS])
    tsv("jump-tables.tsv", ("table", "index", "target", "meaning"), [("%#x" % table, index, "%#x" % target, text) for table, index, target, text in result["tables"]])
    tsv("constants.tsv", ("address", "bits", "value", "use"), [("%#x" % va, "%#018x" % bits, repr(value), use) for va, bits, value, use in result["constants"]])
    tsv("timers.tsv", ("timer", "state_field", "f64_bits", "f64", "secs", "nanos"), [(name, "%#x" % field, bits, value, secs, nanos) for name, field, bits, value, secs, nanos in result["timers"]])
    tsv("outcomes.tsv", ("outcome", "cases"), sorted(result["labels"].items()))
    rows = []
    for case, label, got in result["rows"]:
        block = next((item[1] for item in got["out"] if item[0] == "block"), None)
        rows.append((case.name, label, len(case.txs), len(block["hashes"]) if block else "-", block["qc_round"] if block else "-", "%d.%09d" % block["time"][1:] if block else "-", "yes" if block and block["tc"][0] != NONE_TAG else "no" if block else "-", got["last"], got["removed"]))
    tsv("cases.tsv", ("case", "outcome", "txs", "hashes", "qc_round", "block_time", "block_has_tc", "last_after", "removed"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("function", "address", "kind", "outcome", "detail"), [("%#x" % host, "%#x" % va, kind, outcome, detail) for host, va, kind, outcome, detail in result["mutations"]])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "cases": len(result["cases"]), "vector_cases": result["vector_count"], "named_cases": len(result["cases"]) - result["vector_count"], "functions_run": len(STATIC_FUNCTIONS),
               "reached_bytes": sum(result["reached"].values()), "function_bytes": sum(image.exact_fde(start)[1] - start for start in STATIC_FUNCTIONS), "pins": result["pins"], "proposer_call_sites": len(result["triggers"]), "gates": len(GATES), "mutant_cases": len(mutant_cases(result["cases"]))}
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[3] == "killed"), "survived": sum(1 for r in rows if r[3] == "survived")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image), image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
