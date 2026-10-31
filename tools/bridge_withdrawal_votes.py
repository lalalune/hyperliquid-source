#!/usr/bin/env python3
"""Pin the node #94 withdrawal signing and finalize votes from ELF bytes.

A withdrawal row is born in `withdrawal_signatures` (0x3941fe0), validators add signatures (0x374ec60 ->
0x3942d90), validators vote the finalized Ethereum hash (0x27177c0 -> 0x374f5b0 -> 0x3944860), and a hash
with strictly more than 2/3 of the stake removes both rows and writes `finished_withdrawal_to_time`. The
real bytes of 25 functions run under recording stubs, a separately written rule list predicts every status,
event and tree state, and reached conditional rows are mutated. No objdump or readelf output is parsed and
the binary is never executed. Standard library only.

    python3 tools/bridge_withdrawal_votes.py --out <dir>
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
HEAP_SIZE = 0x80000
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



SIGN_ARM = 0x374EC60
CORE = 0x374F5B0
WRAP = 0x27177C0
CREATE = 0x3941FE0
TRACK_SIGN = 0x3942D90
TRACK_FINAL = 0x3944860
QUORUM_SIGN = 0x39415B0
QUORUM_FINAL = 0x3940D60
REMOVE_SIGN = 0x3942240
REMOVE_FINAL = 0x3942880
FIND_OUTER = 0x2FDD3F0
FIND_INNER = 0x2FDCFB0
WEIGHT = 0x3366B60
VOTER = 0x33690C0
MEMBER = 0x3367530
TAKE_SIGN = 0x3BDDBF0
TAKE_FINAL = 0x3BD9680
PUT_TIME = 0x3399B90
PUT_VOTE = 0x339B0D0
PUT_VOTER = 0x339E610
VACANT_ROW = 0x33C03E0
VACANT_INNER = 0x33BFBC0
VACANT_FINAL = 0x33C10C0
VACANT_HASH = 0x33BF4A0
NEXT_SIGN = 0x330FD70
NEXT_FINAL = 0x330FE30
NAMES = {SIGN_ARM: "validator_sign_arm", CORE: "finalize_core", WRAP: "finalize_wrapper", CREATE: "row_create", TRACK_SIGN: "tracker_sign", TRACK_FINAL: "tracker_final", QUORUM_SIGN: "quorum_sign",
         QUORUM_FINAL: "quorum_final", REMOVE_SIGN: "remove_sign_row", REMOVE_FINAL: "remove_final_row", FIND_OUTER: "find_row", FIND_INNER: "find_inner", WEIGHT: "stake_threshold",
         MEMBER: "is_member", TAKE_SIGN: "first_100_sign", TAKE_FINAL: "first_100_final", PUT_TIME: "finish_time_insert", PUT_VOTE: "signature_insert", PUT_VOTER: "voter_insert", VACANT_ROW: "vacant_sign_row",
         VACANT_INNER: "vacant_sign_inner", VACANT_FINAL: "vacant_final_row", VACANT_HASH: "vacant_final_inner", NEXT_SIGN: "second_map_next_sign", NEXT_FINAL: "second_map_next_final"}
TARGETS = tuple(sorted(NAMES))
MUTATED = (SIGN_ARM, CORE, WRAP, CREATE, TRACK_SIGN, TRACK_FINAL, QUORUM_SIGN, QUORUM_FINAL, REMOVE_SIGN, REMOVE_FINAL, WEIGHT, MEMBER)

SLOT_REQUEST = 0x5775DA8
SLOT_RECOVER = 0x576FE58
SLOT_VOTER = 0x5773148
SLOT_MEMBER = 0x5773D38
SLOT_CORE = 0x5774A50
SLOT_EVENT = 0x5774738
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_ALLOC_ERROR = 0x576E020
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMCMP = 0x576E488
SLOT_UNWRAP = 0x576E048
SLOT_NONE = 0x576E470
SLOT_OVERFLOW = 0x576E118
HELPER_REQUEST = 0x358EA60
HELPER_RECOVER = 0x14C6F50
HELPER_EVENT = 0x3576710
HASH_HELPER = 0x37F2940
HASH_ERROR = 0x365EB00
STAKE_MAP = 0x3364ED0
STAKE_DROP = 0x33AE9E0
STATUS_DROP = 0x3379490
SET_SIGN = 0x3BB29C0
SET_FINAL = 0x3BB2DC0
REMOVE_ROW = 0x33AD8C0
REMOVE_FINAL_ROW = 0x33AB370
CLONE_SIGN_A = 0x33E79F0
CLONE_SIGN_B = 0x33E59E0
CLONE_FINAL_A = 0x33E9610
CLONE_FINAL_B = 0x33E4600
DROPS = (0x33F7F10, 0x33FA3C0, 0x33F3FC0, 0x33F2530, 0x33F1200, 0x3401150)
LEAF_ROW = 0x2F2BD40
LEAF_INNER = 0x2F0F2A0
LEAF_FINAL = 0x2F9A6D0
LEAF_HASH = 0x2F6E760
LEAF_VOTE = 0x2F95400
LEAF_VOTER = 0x2F8BAD0
LEAF_TIME = 0x2F52950
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_LIMIT = 0x13F
TAG_RECOVER = 0x7A
TAG_MISMATCH = 0x11F
TAG_NO_ROW = 0x90
TAG_NO_EPOCH = 0x97
TAG_NOT_VALIDATOR = 0x2A
TAG_DUPLICATE = 0x9A
TAG_NO_DEX = 0x141
STATUS_TABLE = 0x59A8D0
STATUS_TAGS = (TAG_LIMIT, TAG_RECOVER, TAG_MISMATCH, TAG_NO_ROW, TAG_NO_EPOCH, TAG_NOT_VALIDATOR, TAG_DUPLICATE, TAG_NO_DEX)
USD_LIMIT = 0x0CCCCCCCCCCCCCCC
ROW_NOTE = 0x64
MICRO = 1000000.0

S_NOW = 0x60
S_DEXES = 0x5C0
S_BRIDGE = 0x3398
S_CTX = 0x3840
S_EVENTS = 0x8F3
DEX_WORD = 0x250
B_SIGN = 0x40
B_FINAL = 0x70
B_TIME = 0x118
TRACKER_MAP = 0x18
C_ROOT = 0x30
C_EPOCH = 0x48
EVENT_HEAD = 0x8000000000000000

Layout = collections.namedtuple("Layout", "name key_at key_size val_at val_size parent index count size")
ROWS_SIGN = Layout("signature rows", 0, 0x20, 0x168, 0x48, 0x160, 0x480, 0x482, 0x488)
INNER = Layout("signature inner", 0, 0x20, 0x160, 0x30, 0x370, 0x378, 0x37A, 0x380)
VOTES = Layout("signature votes", 0, 0x20, 0x168, 0x48, 0x160, 0x480, 0x482, 0x488)
ROWS_FINAL = Layout("finalized rows", 0x2C0, 0x20, 0, 0x40, 0x420, 0x428, 0x42A, 0x430)
HASHES = Layout("finalized inner", 0, 0x20, 0x160, 0x30, 0x370, 0x378, 0x37A, 0x380)
VOTERS = Layout("voter set", 0, 0x20, 0, 0, 0x160, 0x168, 0x16A, 0x170)
TIMES = Layout("finish times", 0, 0x20, 0x168, 12, 0x160, 0x1EC, 0x1EE, 0x1F0)
EPOCHS = Layout("epochs", 8, 8, 0x60, 0x28, 0, 0x218, 0x21A, 0x220)
VALIDATORS = Layout("validators", 0x2C0, 0x20, 0, 0x40, 0x420, 0x428, 0x42A, 0x430)
STAKES = Layout("stake map", 0, 0x20, 0x168, 8, 0x160, 0x1C0, 0x1C2, 0x1C8)
LAYOUTS = (ROWS_SIGN, INNER, VOTES, ROWS_FINAL, HASHES, VOTERS, TIMES, EPOCHS, VALIDATORS, STAKES)
V_SIGNER = 0x18

ARENA = HEAP_BASE + 0x1000
USED = 0x80000
ARENA_END = HEAP_BASE + 0x70000
OUT = HEAP_BASE + 0x100
TEMP = HEAP_BASE + 0x300
CTX = HEAP_BASE + 0x500
ACTION = HEAP_BASE + 0x600
SIGNER = HEAP_BASE + 0x700
TIME_AT = HEAP_BASE + 0x740
DEX0 = HEAP_BASE + 0x800
EPOCH = 7


def address(tag):
    return blob(tag, 20)


def blob(tag, size):
    """Distinct bytes, so that a shifted copy never matches by accident."""
    return bytes((tag + index) & 0xFF for index in range(size))


def row_key(nonce, user):
    return (user, nonce)


def tree_key(layout, key):
    """The 32 bytes of a tree key in fixture form; ordering is by the tree's own compare."""
    if layout in (ROWS_SIGN, ROWS_FINAL, TIMES):
        return struct.pack("<Q", key[1]) + key[0] + bytes(4)
    if layout is INNER:
        return struct.pack("<Q", key[0]) + key[1] + bytes(4)
    if layout is EPOCHS:
        return struct.pack("<Q", key)
    return key


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(TARGETS)
        statics = machine.memory.statics
        statics[SLOT_MEMBER] = MEMBER
        statics[SLOT_CORE] = CORE
        table = {SLOT_VOTER: self.on_voter, SLOT_REQUEST: self.on_request, SLOT_RECOVER: self.on_recover, SLOT_EVENT: self.on_event, SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_FAIL: self.on_stop, SLOT_ALLOC_ERROR: self.on_stop,
                 SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_memcpy, SLOT_MEMCMP: self.on_memcmp, SLOT_UNWRAP: self.on_unwrap, SLOT_NONE: self.on_none, SLOT_OVERFLOW: self.on_overflow}
        for slot, hook in table.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        calls = {HASH_HELPER: self.on_hash, HASH_ERROR: self.on_hash_error, STAKE_MAP: self.on_stakes, STAKE_DROP: self.on_stake_drop, STATUS_DROP: self.on_nothing, SET_SIGN: self.on_set_sign, SET_FINAL: self.on_set_final,
                 REMOVE_ROW: self.on_remove_sign, REMOVE_FINAL_ROW: self.on_remove_final, CLONE_SIGN_A: self.on_clone, CLONE_SIGN_B: self.on_clone, CLONE_FINAL_A: self.on_clone, CLONE_FINAL_B: self.on_clone,
                 LEAF_ROW: self.leaf(ROWS_SIGN), LEAF_INNER: self.leaf(INNER), LEAF_FINAL: self.leaf(ROWS_FINAL), LEAF_HASH: self.leaf(HASHES), LEAF_VOTE: self.leaf(VOTES), LEAF_VOTER: self.leaf(VOTERS), LEAF_TIME: self.leaf(TIMES)}
        for drop in DROPS:
            calls[drop] = self.on_nothing
        machine.calls = calls
        self.events = []
        self.top = ARENA
        self.stakes = {}
        self.mode = "ok"

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

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
        return at

    def on_nothing(self, machine):
        pass

    def on_stop(self, machine):
        raise Halt("allocation failure path")

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        if size == 800:
            self.events.append(("alloc", size))
        machine.regs[RAX] = self.alloc(size)

    def on_free(self, machine):
        if machine.regs[RSI] == 800:
            self.events.append(("free", machine.regs[RSI]))

    def on_memcpy(self, machine):
        machine.memory.copy(machine.regs[RDI], machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = machine.regs[RDI]

    def on_memcmp(self, machine):
        size = machine.regs[RDX]
        left, right = self.data(machine.regs[RDI], size), self.data(machine.regs[RSI], size)
        machine.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]

    def on_unwrap(self, machine):
        raise Panicked("unwrap %#x" % self.read(machine.regs[RDX], 2))

    def on_none(self, machine):
        raise Panicked("option none")

    def on_overflow(self, machine):
        raise Panicked("add overflow")

    def on_request(self, machine):
        at = machine.regs[RSI]
        self.events.append(("request", self.read(at, 1), self.data(at + 1, 20), self.data(at + 0x15, 20), self.read(at + 0x30), self.read(at + 0x38), machine.regs[RDX] & 0xFF))
        self.write(machine.regs[RDI], 0)
        self.put(machine.regs[RDI] + 8, blob(0x77, 0x30))

    def on_hash(self, machine):
        out = machine.regs[RDI]
        if self.mode == "hash_error":
            self.write(out, 1, 1)
            self.put(out + 8, blob(0x66, 0x18))
            return
        self.write(out, 0, 1)
        self.put(out + 1, HASH_VALUE)

    def on_hash_error(self, machine):
        self.expect(self.data(machine.regs[RDI], 0x18) == blob(0x66, 0x18), "hash error record")
        machine.regs[RAX] = ERROR_WORD

    def on_recover(self, machine):
        out, sig, digest = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.events.append(("recover", self.data(sig, 0x48), self.data(digest, 32)))
        if self.mode == "recover_error":
            self.write(out, 1, 1)
            self.write(out + 8, ERROR_WORD)
            return
        self.write(out, 0, 1)
        self.put(out + 1, self.recovered)

    def on_voter(self, machine):
        out, signer = machine.regs[RDI], self.data(machine.regs[RDX], 20)
        self.expect(machine.regs[RSI] == self.ctx and machine.regs[RCX] == EPOCH, "voter lookup arguments")
        hits = [key for key, who, _ in self.scenario.validators if who == signer]
        if not self.scenario.has_epoch or not hits:
            self.write(out, TAG_NOT_VALIDATOR if self.scenario.has_epoch else TAG_NO_EPOCH, 2)
            self.put(out + 2, ERROR_TAIL)
        else:
            self.write(out, TAG_OK, 2)
            self.put(out + 2, hits[0])

    def on_stakes(self, machine):
        out, value = machine.regs[RDI], machine.regs[RSI]
        self.expect(value == self.epoch_value, "stake map of the wrong epoch")
        items = sorted(self.stakes.items())
        root = self.build(STAKES, [(key, struct.pack("<Q", stake)) for key, stake in items]) if items else 0
        self.write(out, root)
        self.write(out + 8, self.height(items))
        self.write(out + 0x10, len(items))

    def on_stake_drop(self, machine):
        self.write(machine.regs[RDI], 0)

    def key_set(self, machine, layout):
        out, source = machine.regs[RDI], machine.regs[RSI]
        root, height, count = self.read(source + 0x10), self.read(source + 0x18), self.read(source + 0x40)
        keys = [key for key, _ in self.walk(layout, root, height)] if self.read(source) else []
        self.expect(len(keys) == count, "set source length")
        built = self.build(VOTERS, [(key, b"") for key in sorted(keys)]) if keys else 0
        self.write(out, built)
        self.write(out + 8, self.height(keys))
        self.write(out + 0x10, len(keys))

    def on_set_sign(self, machine):
        self.key_set(machine, VOTES)

    def on_set_final(self, machine):
        self.key_set(machine, VOTERS)

    def on_clone(self, machine):
        out = machine.regs[RDI]
        self.write(out, machine.regs[RSI])
        self.write(out + 8, machine.regs[RDX])
        self.write(out + 0x10, 0)

    def remove(self, map_at, layout, key_at):
        """Take one entry out of a leaf or a separator-free tree view; returns its value bytes."""
        wanted = self.data(key_at, 0x1C)
        for node, index in self.positions(layout, self.read(map_at), self.read(map_at + 8)):
            if self.data(node + layout.key_at + index * layout.key_size, 0x1C) == wanted:
                value = self.data(node + layout.val_at + index * layout.val_size, layout.val_size)
                self.take_out(layout, node, index)
                self.write(map_at + 0x10, self.read(map_at + 0x10) - 1)
                return value
        return None

    def take_out(self, layout, node, index):
        count = self.read(node + layout.count, 2)
        tail = count - index - 1
        if tail:
            self.put(node + layout.key_at + index * layout.key_size, self.data(node + layout.key_at + (index + 1) * layout.key_size, tail * layout.key_size))
            self.put(node + layout.val_at + index * layout.val_size, self.data(node + layout.val_at + (index + 1) * layout.val_size, tail * layout.val_size))
        self.write(node + layout.count, count - 1, 2)

    def on_remove_sign(self, machine):
        out, map_at, key = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        value = self.remove(map_at, ROWS_SIGN, key)
        if value is None:
            self.write(out, 2)
        else:
            self.put(out, value)

    def on_remove_final(self, machine):
        out, map_at, key = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        value = self.remove(map_at, ROWS_FINAL, key)
        if value is None:
            self.write(out + 0x39, 2, 1)
        else:
            self.put(out, value)

    def leaf(self, layout):
        def hook(machine):
            out, handle = machine.regs[RDI], machine.regs[RSI]
            node, height, index = self.read(handle), self.read(handle + 8), self.read(handle + 0x10)
            self.expect(height == 0, "leaf insert above a leaf")
            count = self.read(node + layout.count, 2)
            self.expect(count < 11, "leaf overflow in a fixture")
            for size, base, source in ((layout.key_size, layout.key_at, machine.regs[RDX]), (layout.val_size, layout.val_at, machine.regs[RCX])):
                if not size:
                    continue
                if count > index:
                    self.put(node + base + (index + 1) * size, self.data(node + base + index * size, (count - index) * size))
                self.put(node + base + index * size, self.data(source, size))
            self.write(node + layout.count, count + 1, 2)
            self.write(out, node)
            self.write(out + 8, 0)
            self.write(out + 0x10, index)
        return hook

    def on_event(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == self.state + S_EVENTS, "event sink")
        self.expect((self.read(regs[RSI]), self.read(regs[RSI] + 0x10)) == (1, 1), "event user vector")
        record = regs[R8]
        self.expect(self.read(record) == EVENT_HEAD, "event head word")
        self.events.append(("finished", self.read(record + 8), self.read(record + 0x10), self.read(record + 0x18), self.data(self.read(regs[RSI] + 8), 20), self.data(regs[RDX], 12), self.data(regs[RCX], 32)))

    def build(self, layout, items):
        """Build a tree of height 0 or 1 in the fixture arena; items are sorted (key bytes, value bytes)."""
        def node(entries, edges=()):
            size = layout.size + 12 * 8 if edges else layout.size
            at = self.alloc(size)
            self.put(at, bytes([0xDD]) * size)
            self.write(at + layout.parent, 0)
            self.write(at + layout.count, len(entries), 2)
            for index, (key, value) in enumerate(entries):
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

    def height(self, items):
        return 0 if len(items) <= 11 else 1

    def positions(self, layout, root, height):
        if not root:
            return []
        count = self.read(root + layout.count, 2)
        if height == 0:
            return [(root, index) for index in range(count)]
        out = []
        for index in range(count + 1):
            out += self.positions(layout, self.read(root + layout.size + 8 * index), height - 1)
            if index < count:
                out.append((root, index))
        return out

    def walk(self, layout, root, height):
        rows = []
        for node, index in self.positions(layout, root, height):
            value = node + layout.val_at + index * layout.val_size
            rows.append((self.data(node + layout.key_at + index * layout.key_size, layout.key_size), value))
        return rows

    def fresh(self, scenario):
        memory = self.machine.memory
        memory.reset(USED)
        self.top = ARENA
        self.events = []
        self.mode = "ok"
        self.scenario = scenario
        self.recovered = bytes(20)
        self.state = HEAP_BASE + 0x70000
        self.stakes = {key: stake for key, _, stake in scenario.validators}
        memory.put_bytes(self.state, bytes(0x4000))
        self.write(self.state + S_NOW, NOW_WORD)
        self.write(self.state + S_NOW + 8, NOW_NANO, 4)
        self.bridge = self.state + S_BRIDGE
        self.write(self.state + S_DEXES, DEX0)
        self.write(self.state + S_DEXES + 8, 1)
        self.write(DEX0 + DEX_WORD, scenario.dex_word)
        self.ctx = self.state + S_CTX
        self.write(self.ctx + C_EPOCH, EPOCH)
        if scenario.has_epoch:
            items = sorted((key, blob(0xBB, V_SIGNER) + signer + blob(0xBB, 0x40 - V_SIGNER - 20)) for key, signer, _ in scenario.validators)
            root = self.build(VALIDATORS, items) if items else 0
            value = struct.pack("<QQQ", root, self.height(items), len(items)) + bytes(0x10)
            empty = bytes(0x28)
            epochs = [(struct.pack("<Q", EPOCH - 2), empty), (struct.pack("<Q", EPOCH), value), (struct.pack("<Q", EPOCH + 2), empty)]
            self.write(self.ctx + C_ROOT, self.build(EPOCHS, epochs))
            self.write(self.ctx + C_ROOT + 8, 0)
            self.epoch_value = self.read(self.ctx + C_ROOT) + EPOCHS.val_at + EPOCHS.val_size
        if scenario.rows:
            items = []
            for key, withdrawal in sorted(scenario.rows):
                inner = self.build(INNER, [(tree_key(INNER, withdrawal), bytes(0x30))])
                items.append((tree_key(ROWS_SIGN, key), struct.pack("<Q", 1) + bytes(0x20) + struct.pack("<QQQ", inner, 0, 1) + bytes(8)))
            tree = self.build(ROWS_SIGN, items)
            at = self.bridge + B_SIGN + TRACKER_MAP
            self.write(at, tree)
            self.write(at + 8, self.height(items))
            self.write(at + 0x10, len(items))
        if scenario.final_rows:
            items = [(tree_key(ROWS_FINAL, key), bytes(0x18) + struct.pack("<B", 1) + bytes(0x27)) for key in sorted(scenario.final_rows)]
            at = self.bridge + B_FINAL + TRACKER_MAP
            self.write(at, self.build(ROWS_FINAL, items))
            self.write(at + 8, self.height(items))
            self.write(at + 0x10, len(items))

    def dump(self):
        rows = {}
        at = self.bridge + B_SIGN + TRACKER_MAP
        for key, value in self.walk(ROWS_SIGN, self.read(at), self.read(at + 8)):
            inner = {}
            for ikey, ivalue in self.walk(INNER, self.read(value + 0x28), self.read(value + 0x30)):
                votes = {voter: self.data(vote, 0x48) for voter, vote in self.walk(VOTES, self.read(ivalue), self.read(ivalue + 8))}
                self.expect(self.read(ivalue + 0x18) == 0, "second map populated")
                inner[(struct.unpack_from("<Q", ikey)[0], ikey[8:28])] = votes
            winner = None
            if self.read(value) == 0:
                winner = (self.read(value + 8), self.data(value + 0x10, 20))
            rows[(key[8:28], struct.unpack_from("<Q", key)[0])] = dict(winner=winner, done=self.read(value + 0x40, 1), inner=inner)
        finals = {}
        at = self.bridge + B_FINAL + TRACKER_MAP
        for key, value in self.walk(ROWS_FINAL, self.read(at), self.read(at + 8)):
            inner = {}
            for ikey, ivalue in self.walk(HASHES, self.read(value), self.read(value + 8)):
                inner[ikey] = {voter for voter, _ in self.walk(VOTERS, self.read(ivalue), self.read(ivalue + 8))}
                self.expect(self.read(ivalue + 0x18) == 0, "second set populated")
            winner = self.data(value + 0x19, 32) if self.read(value + 0x18, 1) == 0 else None
            finals[(key[8:28], struct.unpack_from("<Q", key)[0])] = dict(winner=winner, done=self.read(value + 0x39, 1), inner=inner)
        at = self.bridge + B_TIME
        times = {(key[8:28], struct.unpack_from("<Q", key)[0]): self.data(value, 12) for key, value in self.walk(TIMES, self.read(at), self.read(at + 8))}
        return rows, finals, times

    def out_view(self, op):
        tag = self.read(OUT, 2)
        view = [tag]
        if tag in (TAG_LIMIT, TAG_RECOVER):
            view.append(self.read(OUT + 8))
        if tag in (TAG_NO_EPOCH, TAG_NOT_VALIDATOR):
            view.append(self.data(OUT + 2, len(ERROR_TAIL)))
        if tag == TAG_OK and op.kind == "final_core":
            finished = self.read(OUT + 2, 1)
            view.append(finished)
            if finished:
                view.append(self.data(OUT + 3, 32))
        return tuple(view)

    def perform(self, op):
        memory = self.machine.memory
        memory.put_bytes(OUT, bytes([0xEE]) * 0x60)
        self.events = []
        kind = op.kind
        if kind == "create":
            self.put(TEMP, struct.pack("<Q", op.nonce) + op.user + bytes(4))
            self.put(TEMP + 0x40, struct.pack("<Q", op.usd) + op.dest + bytes(4))
            self.machine.run(CREATE, {RDI: OUT, RSI: self.bridge + B_SIGN, RDX: TEMP, RCX: TEMP + 0x40})
            return self.out_view(op), tuple(self.events)
        if kind == "sign":
            self.mode, self.recovered = op.mode, op.recovered
            self.put(SIGNER, op.signer)
            self.put(ACTION, struct.pack("<QQ", op.usd, op.nonce) + op.sig + op.user + op.dest)
            self.machine.run(SIGN_ARM, {RDI: OUT, RSI: self.bridge, RDX: op.chain, RCX: SIGNER, R8: ACTION, R9: self.ctx})
            return self.out_view(op), tuple(self.events)
        if kind in ("final", "final_core"):
            self.put(SIGNER, op.signer)
            self.put(ACTION, op.hash + struct.pack("<QQ", op.nonce, op.usd) + op.user + op.dest)
            self.write(self.state + S_DEXES + 8, op.dex_len)
            if kind == "final":
                self.machine.run(WRAP, {RDI: OUT, RSI: self.state, RDX: SIGNER, RCX: ACTION})
            else:
                self.put(TIME_AT, self.data(self.state + S_NOW, 12))
                self.machine.run(CORE, {RDI: OUT, RSI: self.bridge, RDX: ACTION, RCX: SIGNER, R8: self.ctx, R9: TIME_AT})
            return self.out_view(op), tuple(self.events)
        if kind in ("track_sign", "track_final"):
            self.put(TEMP, struct.pack("<Q", op.nonce) + op.user + bytes(4))
            memory.put_bytes(TEMP + 0x80, bytes([1 if op.voter else 0]) + (op.voter or bytes(32)))
            if kind == "track_sign":
                self.put(TEMP + 0x40, struct.pack("<Q", op.usd) + op.dest + bytes(4))
                self.put(TEMP + 0xC0, op.sig)
                self.machine.run(TRACK_SIGN, {RDI: OUT, RSI: self.bridge + B_SIGN, RDX: TEMP, RCX: TEMP + 0x40, R8: TEMP + 0x80, R9: TEMP + 0xC0}, (self.ctx, 1))
            else:
                self.put(TEMP + 0x40, op.hash)
                self.machine.run(TRACK_FINAL, {RDI: OUT, RSI: self.bridge + B_FINAL, RDX: TEMP, RCX: TEMP + 0x40, R8: TEMP + 0x80, R9: self.ctx})
            return (self.read(OUT), self.data(OUT + 8, 28) if self.read(OUT) else b""), tuple(self.events)
        if kind == "weight":
            voters = sorted(op.voters)
            root = self.build(VOTERS, [(key, b"") for key in voters]) if voters else 0
            self.write(TEMP, root)
            self.write(TEMP + 8, self.height(voters))
            self.write(TEMP + 0x10, len(voters))
            result = self.machine.run(WEIGHT, {RDI: self.read(self.ctx + C_ROOT), RSI: self.read(self.ctx + C_ROOT + 8), RDX: op.epoch, RCX: TEMP})
            return (result & 0xFF,), ()
        raise EvidenceError("unknown operation " + kind)

    def run(self, scenario):
        self.fresh(scenario)
        trace = []
        for op in scenario.ops:
            try:
                view, events = self.perform(op)
            except Panicked as stop:
                trace.append(("panic", stop.args[0], ()))
                break
            trace.append((view, events, self.dump()))
        return trace


class Op:
    def __init__(self, kind, **fields):
        self.kind = kind
        defaults = dict(nonce=NONCE, user=USER, usd=USD, dest=DEST, chain=3, mode="ok", epoch=EPOCH, sig=blob(0x51, 0x48), hash=HASH_A, dex_len=1, voter=None, voters=(), signer=None)
        defaults.update(fields)
        self.__dict__.update(defaults)
        if kind == "sign" and "recovered" not in fields:
            self.recovered = self.signer

    def __repr__(self):
        return self.kind


class Scenario:
    def __init__(self, name, ops, validators=None, rows=None, final_rows=(), has_epoch=True, dex_word=2000000):
        self.name = name
        self.ops = ops
        self.validators = EQUAL if validators is None else validators
        self.rows = ((row_key(NONCE, USER), (USD, DEST)),) if rows is None else tuple(rows)
        self.final_rows = tuple(final_rows)
        self.has_epoch = has_epoch
        self.dex_word = dex_word


USER = bytes(range(0x31, 0x45))
DEST = bytes(range(0x71, 0x85))
NONCE = 1700000000000
USD = 12345678
HASH_A = blob(0xA1, 32)
HASH_B = blob(0xB2, 32)
HASH_VALUE = blob(0xC3, 32)
ERROR_WORD = 0x1357
ERROR_TAIL = blob(0x30, 0x5E)
NOW_WORD = 0x123456789A
NOW_NANO = 0x55667788


def validator(tag, stake=100):
    return (blob(tag, 32), address(tag), stake)


EQUAL = (validator(0x11), validator(0x22), validator(0x33), validator(0x44))
V1, V2, V3, V4 = EQUAL
OUTSIDER = address(0xF0)


# ---- the rule list; it is written from the path description, never from fixture reads ----

def spec_weight(stakes, voters):
    if not stakes:
        return False
    total = 0
    for stake in stakes.values():
        total += stake
        if total > MASK[8]:
            raise Panicked("add overflow")
    if not voters:
        return False
    voted = 0
    for voter in voters:
        if voter in stakes:
            voted = min(MASK[8], voted + stakes[voter])
    return 2 * total < 3 * voted


class Model:
    def __init__(self, scenario):
        self.scenario = scenario
        self.validators = scenario.validators if scenario.has_epoch else None
        self.stakes = {key: stake for key, _, stake in scenario.validators}
        self.rows = {}
        for key, withdrawal in scenario.rows:
            self.rows[key] = dict(winner=None, done=0, inner={withdrawal: {}})
        self.finals = {key: dict(winner=None, done=0, inner={}) for key in scenario.final_rows}
        self.times = {}

    def voter_of(self, signer):
        if self.validators is None:
            return TAG_NO_EPOCH, None
        hits = [key for key, who, _ in self.validators if who == signer]
        return (TAG_OK, hits[0]) if hits else (TAG_NOT_VALIDATOR, None)

    def member(self, voter):
        return self.validators is not None and any(key == voter for key, _, _ in self.validators)

    def reached(self, voters):
        if self.validators is None:
            return False
        return spec_weight(self.stakes, voters)

    def trim_events(self, size):
        return (("alloc", 800), ("free", 800)) if size > ROW_NOTE else ()

    def add_signature(self, key, withdrawal, voter, sig):
        winner = None
        if voter is not None and self.member(voter):
            row = self.rows.setdefault(key, dict(winner=None, done=0, inner={}))
            votes = row["inner"].setdefault(withdrawal, {})
            if row["done"]:
                votes[voter] = sig
            else:
                before = self.reached(votes)
                votes[voter] = sig
                if not before and self.reached(votes):
                    row["done"], row["winner"] = 1, withdrawal
                    winner = withdrawal
        return winner

    def add_final(self, key, digest, voter):
        winner = None
        if voter is not None and self.member(voter):
            row = self.finals.setdefault(key, dict(winner=None, done=0, inner={}))
            voters = row["inner"].setdefault(digest, set())
            if row["done"]:
                voters.add(voter)
            else:
                before = self.reached(voters)
                voters.add(voter)
                if not before and self.reached(voters):
                    row["done"], row["winner"] = 1, digest
                    winner = digest
        return winner

    def apply(self, op):
        """Returns the view and the events of one operation."""
        kind = op.kind
        if kind == "create":
            key = row_key(op.nonce, op.user)
            if key in self.rows:
                return (TAG_DUPLICATE,), ()
            self.rows[key] = dict(winner=None, done=0, inner={(op.usd, op.dest): {}})
            return (TAG_OK,), ()
        if kind == "sign":
            return self.apply_sign(op)
        if kind in ("final", "final_core"):
            return self.apply_final(op)
        if kind == "track_sign":
            key = row_key(op.nonce, op.user)
            winner = self.add_signature(key, (op.usd, op.dest), op.voter, op.sig)
            events = self.trim_events(len(self.rows))
            if winner is None:
                return (0, b""), events
            return (1, struct.pack("<Q", winner[0]) + winner[1]), events
        if kind == "track_final":
            key = row_key(op.nonce, op.user)
            winner = self.add_final(key, op.hash, op.voter)
            events = self.trim_events(len(self.finals))
            if winner is None:
                return (0, b""), events
            return (1, winner[:28]), events
        if kind == "weight":
            if op.epoch != EPOCH or self.validators is None:
                return (0,), ()
            return (int(spec_weight(self.stakes, set(op.voters))),), ()
        raise EvidenceError("unknown operation " + kind)

    def apply_sign(self, op):
        events = []
        if op.usd >= USD_LIMIT:
            return (TAG_LIMIT, op.usd), ()
        events.append(("request", 5, op.user, op.dest, op.usd, op.nonce, op.chain))
        if op.mode == "hash_error":
            return (TAG_RECOVER, ERROR_WORD), tuple(events)
        events.append(("recover", op.sig, HASH_VALUE))
        if op.mode == "recover_error":
            return (TAG_RECOVER, ERROR_WORD), tuple(events)
        if op.recovered != op.signer:
            return (TAG_MISMATCH,), tuple(events)
        status, voter = self.voter_of(op.signer)
        if status != TAG_OK:
            return (status, ERROR_TAIL), tuple(events)
        key = row_key(op.nonce, op.user)
        withdrawal = (op.usd, op.dest)
        if key not in self.rows or withdrawal not in self.rows[key]["inner"]:
            return (TAG_NO_ROW,), tuple(events)
        self.add_signature(key, withdrawal, voter, op.sig)
        return (TAG_OK,), tuple(events) + self.trim_events(len(self.rows))

    def apply_final(self, op):
        if op.usd >= USD_LIMIT:
            return (TAG_LIMIT, op.usd), ()
        status, voter = self.voter_of(op.signer)
        if status != TAG_OK:
            return (status, ERROR_TAIL), ()
        key = row_key(op.nonce, op.user)
        if key not in self.rows or (op.usd, op.dest) not in self.rows[key]["inner"]:
            return (TAG_NO_ROW,), ()
        winner = self.add_final(key, op.hash, voter)
        trim = self.trim_events(len(self.finals))
        if winner is None:
            return ((TAG_OK, 0) if op.kind == "final_core" else (TAG_OK,)), trim
        del self.rows[key]
        del self.finals[key]
        now = struct.pack("<QI", NOW_WORD, NOW_NANO)
        self.times[key] = now
        if op.kind == "final_core":
            return (TAG_OK, 1, winner), trim
        if op.dex_len == 0:
            raise Panicked("unwrap %#x" % TAG_NO_DEX)
        bits = to_bits(float(op.usd) / MICRO)
        return (TAG_OK,), trim + (("finished", bits, op.nonce, to_bits(float(self.scenario.dex_word) / MICRO), op.user, now, winner),)

    def snapshot(self):
        rows = {key: dict(winner=row["winner"], done=row["done"], inner={w: dict(v) for w, v in row["inner"].items()}) for key, row in self.rows.items()}
        finals = {key: dict(winner=row["winner"], done=row["done"], inner={h: set(v) for h, v in row["inner"].items()}) for key, row in self.finals.items()}
        return rows, finals, dict(self.times)


def spec_run(scenario):
    model = Model(scenario)
    trace = []
    for op in scenario.ops:
        try:
            view, events = model.apply(op)
        except Panicked as stop:
            trace.append(("panic", stop.args[0], ()))
            break
        trace.append((view, events, model.snapshot()))
    return trace


def key_rows(count):
    return [(row_key(NONCE + 1000 * index, USER), (USD, DEST)) for index in range(count)]


def final_keys(count):
    return [row_key(NONCE + 1000 * index, USER) for index in range(1, count + 1)]


def sign(who=V1, **fields):
    fields.setdefault("signer", who[1])
    return Op("sign", **fields)


def final(who=V1, **fields):
    fields.setdefault("signer", who[1])
    return Op("final", **fields)


MANY = tuple(validator(0x40 + index * 3) for index in range(30))


def named_scenarios():
    limit = USD_LIMIT
    wide = bytes(range(0x91, 0xA5))
    rows = [Scenario("sign_ok_first_vote", [sign()]),
            Scenario("sign_at_limit_minus_one", [sign(usd=limit - 1)], rows=[(row_key(NONCE, USER), (limit - 1, DEST))]),
            Scenario("sign_at_limit", [sign(usd=limit)], rows=[(row_key(NONCE, USER), (limit, DEST))]),
            Scenario("sign_reference_limit", [sign(usd=0xCCCCCCCCCCCCCCCC)]),
            Scenario("sign_u64_max", [sign(usd=MASK[8])]),
            Scenario("sign_hash_error", [sign(mode="hash_error")]),
            Scenario("sign_recover_error", [sign(mode="recover_error")]),
            Scenario("sign_signer_mismatch", [sign(recovered=address(0xE1))]),
            Scenario("sign_mismatch_last_byte", [sign(recovered=V1[1][:19] + b"\x12")]),
            Scenario("sign_mismatch_byte_16", [sign(recovered=V1[1][:16] + b"\x00" + V1[1][17:])]),
            Scenario("sign_outsider", [sign(signer=OUTSIDER)]),
            Scenario("sign_no_epoch", [sign()], has_epoch=False),
            Scenario("sign_empty_validators", [sign()], validators=()),
            Scenario("sign_no_row", [sign()], rows=()),
            Scenario("sign_other_usd", [sign(usd=USD + 1)]),
            Scenario("sign_other_destination", [sign(dest=address(0x7E))]),
            Scenario("sign_other_nonce", [sign(nonce=NONCE + 1000)]),
            Scenario("sign_other_user", [sign(user=address(0x3F))]),
            Scenario("sign_order_limit_before_hash", [sign(usd=limit, mode="hash_error", signer=OUTSIDER)]),
            Scenario("sign_order_hash_before_validator", [sign(mode="hash_error", signer=OUTSIDER)]),
            Scenario("sign_order_mismatch_before_validator", [sign(signer=OUTSIDER, recovered=address(0xE1))]),
            Scenario("sign_order_validator_before_row", [sign(signer=OUTSIDER)], rows=()),
            Scenario("sign_chain_zero", [sign(chain=0)]),
            Scenario("sign_chain_two", [sign(chain=2)]),
            Scenario("quorum_three_of_four", [sign(V1), sign(V2), sign(V3), sign(V4)]),
            Scenario("repeat_vote_overwrites", [sign(V1), sign(V1, sig=blob(0x52, 0x48)), sign(V2), sign(V2, sig=blob(0x53, 0x48))]),
            Scenario("after_quorum_vote_kept", [sign(V1), sign(V2), sign(V3), sign(V1, sig=blob(0x54, 0x48)), sign(V4)]),
            Scenario("exact_two_thirds_is_short", [sign(V1), sign(V2), sign(V3)], validators=(V1, V2, V3)),
            Scenario("weighted_exact_two_thirds", [sign(V1), sign(V2)], validators=(validator(0x11, 200), validator(0x22, 100))),
            Scenario("weighted_over_two_thirds", [sign(V1)], validators=(validator(0x11, 201), validator(0x22, 100))),
            Scenario("zero_stake_voter", [sign(V1), sign(V2)], validators=(validator(0x11, 0), validator(0x22, 3))),
            Scenario("finalize_three_of_four", [final(V1), final(V2), final(V3)]),
            Scenario("finalize_without_signatures_then_gone", [final(V1), final(V2), final(V3), final(V4), sign(V1)]),
            Scenario("finalize_after_signature_quorum", [sign(V1), sign(V2), sign(V3), final(V1), final(V2), final(V3)]),
            Scenario("finalize_split_hashes", [final(V1), final(V2, hash=HASH_B), final(V3), final(V4, hash=HASH_B), final(V4)]),
            Scenario("finalize_repeat_voter_counts_once", [final(V1), final(V1), final(V1), final(V2), final(V3)]),
            Scenario("finalize_same_voter_two_hashes", [final(V1), final(V1, hash=HASH_B), final(V2, hash=HASH_B), final(V3, hash=HASH_B)]),
            Scenario("finalize_at_limit_wrapper", [final(usd=limit)]),
            Scenario("finalize_limit_minus_one", [final(V1, usd=limit - 1), final(V2, usd=limit - 1), final(V3, usd=limit - 1)], rows=[(row_key(NONCE, USER), (limit - 1, DEST))], dex_word=(1 << 63) + 12345),
            Scenario("finalize_outsider", [final(signer=OUTSIDER)]),
            Scenario("finalize_no_epoch", [final()], has_epoch=False),
            Scenario("finalize_no_row", [final()], rows=()),
            Scenario("finalize_other_usd", [final(usd=USD + 1)]),
            Scenario("finalize_other_destination", [final(dest=address(0x7E))]),
            Scenario("finalize_other_user", [final(user=address(0x3F))]),
            Scenario("finalize_other_nonce", [final(nonce=NONCE - 1000)]),
            Scenario("finalize_no_dex_panics", [final(V1), final(V2), final(V3, dex_len=0)]),
            Scenario("finalize_no_dex_not_finished", [final(V1, dex_len=0)]),
            Scenario("core_direct_limit", [Op("final_core", signer=V1[1], usd=limit)]),
            Scenario("core_direct_no_event", [Op("final_core", signer=V1[1]), Op("final_core", signer=V2[1]), Op("final_core", signer=V3[1])]),
            Scenario("core_direct_outsider", [Op("final_core", signer=OUTSIDER)]),
            Scenario("create_then_sign", [Op("create", nonce=NONCE + 1000), sign(nonce=NONCE + 1000)]),
            Scenario("create_duplicate", [Op("create"), Op("create", usd=5)]),
            Scenario("create_first_row", [Op("create"), sign(V1), final(V1)], rows=()),
            Scenario("create_after_finish_time_overwritten", [final(V1), final(V2), final(V3), Op("create"), final(V1, hash=HASH_B), final(V2, hash=HASH_B), final(V3, hash=HASH_B)]),
            Scenario("create_other_user_low", [Op("create", user=address(0x01)), Op("create", user=address(0xFE))]),
            Scenario("create_nonce_low_high", [Op("create", nonce=5), Op("create", nonce=NONCE + 5)]),
            Scenario("tree_two_levels_hit", [sign(nonce=NONCE), sign(nonce=NONCE + 25000), sign(nonce=NONCE + 29000), final(nonce=NONCE + 10000)], rows=key_rows(30)),
            Scenario("tree_two_levels_miss", [sign(nonce=NONCE + 500), sign(nonce=NONCE + 900000), final(nonce=NONCE + 500), sign(user=address(0x3F))], rows=key_rows(30)),
            Scenario("no_trim_100_rows", [sign()], rows=key_rows(100)),
            Scenario("no_trim_101_rows", [sign(), sign(V2)], rows=key_rows(101)),
            Scenario("no_trim_110_rows", [sign()], rows=key_rows(110)),
            Scenario("final_map_100_rows", [final()], rows=key_rows(1), final_rows=final_keys(99)),
            Scenario("final_map_101_rows", [final(), final(V2)], rows=key_rows(1), final_rows=final_keys(100)),
            Scenario("final_map_101_rows_finish", [final(V1), final(V2), final(V3)], rows=key_rows(1), final_rows=final_keys(100)),
            Scenario("track_sign_no_voter", [Op("track_sign")]),
            Scenario("track_sign_non_member", [Op("track_sign", voter=blob(0x99, 32))]),
            Scenario("track_sign_absent_row", [Op("track_sign", voter=V1[0], nonce=NONCE + 7)]),
            Scenario("track_sign_absent_inner", [Op("track_sign", voter=V1[0], usd=USD + 9), Op("track_sign", voter=V2[0], usd=USD - 9), Op("track_sign", voter=V3[0], dest=wide)]),
            Scenario("track_sign_winner_output", [Op("track_sign", voter=V1[0]), Op("track_sign", voter=V2[0]), Op("track_sign", voter=V3[0]), Op("track_sign", voter=V4[0])]),
            Scenario("track_sign_empty_set_row", [Op("track_sign", voter=V1[0], nonce=3), Op("track_sign", voter=V1[0], nonce=3, usd=7), Op("track_sign", voter=V2[0], nonce=3, usd=7), Op("track_sign", voter=V3[0], nonce=3, usd=7)], rows=()),
            Scenario("track_sign_no_epoch", [Op("track_sign", voter=V1[0])], has_epoch=False),
            Scenario("track_final_no_voter", [Op("track_final")]),
            Scenario("track_final_non_member", [Op("track_final", voter=blob(0x99, 32))]),
            Scenario("track_final_winner_output", [Op("track_final", voter=V1[0]), Op("track_final", voter=V2[0]), Op("track_final", voter=V3[0]), Op("track_final", voter=V4[0]), Op("track_final", voter=V1[0], hash=HASH_B)]),
            Scenario("track_final_two_rows", [Op("track_final", voter=V1[0]), Op("track_final", voter=V1[0], nonce=4), Op("track_final", voter=V2[0], nonce=NONCE + 3), Op("track_final", voter=V2[0], user=address(0x01)), Op("track_final", voter=V2[0], user=address(0xFE))]),
            Scenario("track_final_hash_low_high", [Op("track_final", voter=V1[0], hash=blob(0x01, 32)), Op("track_final", voter=V1[0], hash=blob(0xFE, 32)), Op("track_final", voter=V2[0], hash=blob(0x77, 32))]),
            Scenario("track_final_no_epoch", [Op("track_final", voter=V1[0])], has_epoch=False),
            Scenario("weight_boundaries", [Op("weight", voters=(V1[0], V2[0])), Op("weight", voters=(V1[0], V2[0], V3[0])), Op("weight", voters=(V1[0], blob(0x99, 32))), Op("weight", voters=()), Op("weight", voters=(V1[0],), epoch=EPOCH + 1), Op("weight", voters=(V1[0],), epoch=EPOCH - 1)]),
            Scenario("weight_two_to_one", [Op("weight", voters=(V1[0],)), Op("weight", voters=(V2[0],)), Op("weight", voters=(V1[0], V2[0]))], validators=(validator(0x11, 2), validator(0x22, 1))),
            Scenario("weight_saturates", [Op("weight", voters=(V1[0], V2[0])), Op("weight", voters=(V1[0],))], validators=(validator(0x11, 1 << 63), validator(0x22, (1 << 63) - 1))),
            Scenario("weight_total_overflow", [Op("weight", voters=(V1[0],))], validators=(validator(0x11, MASK[8]), validator(0x22, 1))),
            Scenario("weight_zero_total", [Op("weight", voters=(V1[0],))], validators=(validator(0x11, 0),)),
            Scenario("weight_no_validators", [Op("weight", voters=(V1[0],)), Op("weight", voters=())], validators=()),
            Scenario("weight_no_epoch", [Op("weight", voters=(V1[0],))], has_epoch=False),
            Scenario("wide_set_two_levels", [sign(MANY[0]), sign(MANY[14]), sign(MANY[29]), final(MANY[3]), final(MANY[16]), Op("weight", voters=[row[0] for row in MANY[:20]]), Op("weight", voters=[row[0] for row in MANY[:21]])], validators=MANY),
            Scenario("wide_quorum_signatures", [sign(row) for row in MANY[:11]], validators=MANY[:16]),
            Scenario("wide_quorum_final", [final(row) for row in MANY[:11]], validators=MANY[:16]),
            Scenario("weight_high_128", [Op("weight", voters=(V1[0],)), Op("weight", voters=(V2[0],))], validators=(validator(0x11, (1 << 63) + 7), validator(0x22, (1 << 62) + 3)))]
    return rows


def lcg(seed):
    value = seed
    while True:
        value = (value * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield value >> 33


def vector_scenarios(count):
    source = lcg(0x1403)
    out = []
    users = (USER, address(0x20), address(0xC0))
    hashes = (HASH_A, HASH_B)
    for index in range(count):
        size = 3 + next(source) % 3
        stakes = tuple(validator(0x11 * (at + 1), 1 + next(source) % 5) for at in range(size))
        ops = []
        for _ in range(10):
            pick = next(source) % 8
            nonce = NONCE + 1000 * (next(source) % 3)
            user = users[next(source) % 3]
            usd = USD + next(source) % 2
            who = stakes[next(source) % size] if next(source) % 7 else (blob(0xF0, 32), OUTSIDER, 0)
            if pick == 0:
                ops.append(Op("create", nonce=nonce, user=user, usd=usd))
            elif pick < 4:
                ops.append(sign(who, nonce=nonce, user=user, usd=usd))
            else:
                ops.append(final(who, nonce=nonce, user=user, usd=usd, hash=hashes[next(source) % 8 == 0]))
        out.append(Scenario("vector_%d" % index, ops, validators=stakes))
    return out


def describe(trace):
    """One short line per operation of a run."""
    parts = []
    for step in trace:
        if step[0] == "panic":
            parts.append("panic " + step[1])
            continue
        view, events, _ = step
        text = "%#x" % view[0]
        if len(view) > 1 and isinstance(view[1], int) and view[1] in (0, 1) and view[0] == TAG_OK:
            text += "/%d" % view[1]
        kinds = [event[0] for event in events if event[0] in ("alloc", "finished")]
        parts.append(text + ("(" + "+".join(kinds) + ")" if kinds else ""))
    return " ".join(parts)


def check_all(harness, scenarios):
    done = []
    for scenario in scenarios:
        got = harness.run(scenario)
        want = spec_run(scenario)
        if got != want:
            for left, right, op in zip(got, want, scenario.ops):
                if left != right:
                    raise EvidenceError("scenario %s op %s differs:\n%r\n%r" % (scenario.name, op, left[:2], right[:2]))
            raise EvidenceError("scenario %s length differs" % scenario.name)
        done.append((scenario, got))
    return done


def direct_sites(image, targets):
    start, text = image.text_bytes()
    wanted = set(targets)
    hits = collections.defaultdict(list)
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 <= len(text):
            target = start + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in wanted:
                hits[target].append(start + at)
    return hits


def slot_sites(image, slots):
    start, text = image.text_bytes()
    wanted = set(slots)
    hits = collections.defaultdict(list)
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text):
            slot = start + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
            if slot in wanted:
                hits[slot].append(start + at)
    return hits


def slot_rows(image, through):
    relative = image.relative()
    named = ((SLOT_REQUEST, "request builder", HELPER_REQUEST), (SLOT_RECOVER, "signature recover", HELPER_RECOVER), (SLOT_VOTER, "voter of signer", VOTER), (SLOT_MEMBER, "member test", MEMBER),
             (SLOT_CORE, "finalize core", CORE), (SLOT_EVENT, "event sink", HELPER_EVENT))
    rows = []
    for slot, role, target in named:
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        rows.append(("%#x" % slot, role, "%#x" % target, len(through[slot])))
    return rows


def site_rows(image, through):
    direct = direct_sites(image, TARGETS)
    rows = []
    for target in TARGETS:
        sites = through[{MEMBER: SLOT_MEMBER, CORE: SLOT_CORE}[target]] if target in (MEMBER, CORE) else direct[target]
        owners = sorted({image.fde(site)[0] for site in sites})
        rows.append(("%#x" % target, NAMES[target], len(sites), len(owners), " ".join("%#x" % owner for owner in owners[:6])))
    return rows


COPIES = (0x4D0F050, 0x4D0F300)


def copy_rows(image):
    """The two other hosts of the finalize core, compared row by row with the wrapper read here."""
    first = decode_range(image, *image.exact_fde(WRAP))
    rows = []
    for copy in COPIES:
        start, stop = image.exact_fde(copy)
        table = decode_range(image, start, stop)
        differing = sum(1 for left, right in zip(first, table) if left.op != right.op or (left.data != right.data and left.op not in ("call", "calli", "jcc", "jmp", "lea") and left.rip_at is None))
        rows.append(("%#x" % copy, stop - start, len(table), len(first), differing))
    return rows


LIMIT_BYTES = struct.pack("<Q", USD_LIMIT)


def limit_rows(image):
    rows = []
    for target in (SIGN_ARM, CORE, WRAP):
        start, stop = image.exact_fde(target)
        data = bytes(image.blob[image.offset(start):image.offset(stop)])
        sites = [start + match.start() - 2 for match in re.finditer(re.escape(LIMIT_BYTES), data)]
        if len(sites) != 1:
            raise EvidenceError("limit sites in %#x" % target)
        at = sites[0]
        rows.append(("%#x" % target, "%#x" % at, data[at - start:at - start + 16].hex(), "%#x" % USD_LIMIT, USD_LIMIT, MASK[8] // 2 // 10 == USD_LIMIT))
    if image.blob.find(struct.pack("<Q", 0xCCCCCCCCCCCCCCCD), image.offset(SIGN_ARM), image.offset(SIGN_ARM) + 0x500) >= 0:
        raise EvidenceError("the longer limit appears in the arm")
    return rows


def note_rows(image):
    """The two size tests, and the fact that nothing but a free follows the first-100 collect."""
    rows = []
    for target, take, take_site, free_site in ((TRACK_SIGN, TAKE_SIGN, 0x39437EB, 0x3943805), (TRACK_FINAL, TAKE_FINAL, 0x394514D, 0x3945167)):
        table = decode_range(image, *image.exact_fde(target))
        index = next(at for at, row in enumerate(table) if row.va == take_site)
        if table[index].target != take:
            raise EvidenceError("take call moved")
        tail = table[index + 1:index + 8]
        if tail[-1].va != free_site or tail[-1].op != "calli" or tail[-1].a[4] != SLOT_FREE or [row for row in tail[:-1] if row.op in ("call", "calli")]:
            raise EvidenceError("take tail changed")
        compare = [row for row in table if row.op == "cmp" and row.b[0] == "i" and row.b[1] == ROW_NOTE + 1]
        stored = [row for row in table if row.op == "mov" and row.b and row.b[0] == "i" and row.b[1] == ROW_NOTE and row.a[0] == "m"]
        writes = [row for row in tail[:-1] if row.a and row.a[0] == "m" and row.a[1] not in (RSP,)]
        if len(compare) != 1 or len(stored) != 1 or writes:
            raise EvidenceError("note rows changed")
        rows.append(("%#x" % target, "%#x" % compare[0].va, "%#x" % stored[0].va, "%#x" % take_site, "%#x" % free_site, " ".join(row.op for row in tail)))
    return rows


FIELD_SITES = ((0x2215638, 0x2215656, "eth_id_to_deposit_votes", 0), (0x2215675, 0x2215693, "finished_deposits_data", 0x100), (0x22156B6, 0x22156D4, "withdrawal_signatures", 0x40),
               (0x22156F4, 0x2215712, "withdrawal_finalized_votes", 0x70), (0x2215732, 0x2215750, "finished_withdrawal_to_time", 0x118))
SERIALIZER = 0x22155C0
RODATA_REF = bytes.fromhex("488d35")


def field_rows(image):
    rows = []
    start, stop = image.exact_fde(SERIALIZER)
    for key_at, field_at, name, offset in FIELD_SITES:
        if not start <= key_at < field_at < stop:
            raise EvidenceError("field row outside the serializer")
        at = image.offset(key_at)
        if bytes(image.blob[at:at + 3]) != RODATA_REF:
            raise EvidenceError("key load moved")
        text = key_at + 7 + struct.unpack_from("<i", image.blob, at + 3)[0]
        size = struct.unpack_from("<I", image.blob, at + 8)[0]
        read = bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")
        code = bytes(image.blob[image.offset(field_at):image.offset(field_at) + 7])
        if read != name:
            raise EvidenceError("key text")
        if offset == 0:
            if code[:6] != bytes.fromhex("4889e74c89fe"):
                raise EvidenceError("first field shape")
        elif code[:3] == bytes.fromhex("498db7") and struct.unpack_from("<I", code, 3)[0] == offset:
            pass
        elif code[:3] == bytes.fromhex("498d77") and code[3] == offset:
            pass
        else:
            raise EvidenceError("field lea %#x" % field_at)
        rows.append(("%#x" % key_at, "%#x" % field_at, name, "%#x" % offset))
    return rows


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag in STATUS_TAGS:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 96])
        at = data.find(b"\x48\x8d\x35")
        if at >= 0 and data[at + 7] == 0xBA:
            text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
            size = struct.unpack_from("<I", data, at + 8)[0]
            rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")))
            continue
        at = data.find(b"\x48\x8d\x15")
        if at < 0:
            rows.append(("%#x" % tag, "%#x" % arm, "not a plain text arm"))
            continue
        piece = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        offset = image.offset(piece)
        size = image.blob[offset]
        rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[offset + 1:offset + 1 + size]).decode("latin1").encode("ascii", "replace").decode() + "{}"))
    return rows


def layout_rows():
    return [(row.name, "%#x" % row.key_at, "%#x" % row.key_size, "%#x" % row.val_at, "%#x" % row.val_size, "%#x" % row.parent, "%#x" % row.index, "%#x" % row.count, "%#x" % row.size) for row in LAYOUTS]


def stack_argument_reads(image):
    """Rows of the signature tracker that read its second stack argument, the literal 1 of the caller."""
    table = decode_range(image, *image.exact_fde(TRACK_SIGN))
    frame = 0x308 + 6 * 8 + 8
    second = frame + 8
    return sum(1 for row in table for operand in (row.a, row.b) if operand and operand[0] == "m" and operand[1] == RSP and operand[4] == second)


def edits_for(image, rows, seen, full):
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
        if full:
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


def first_failure(harness, scenarios, wants):
    for scenario, want in zip(scenarios, wants):
        try:
            if harness.run(scenario) != want:
                return scenario
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error):
            return scenario
    return None


# Scenario name prefixes run against the edits of each function; the wide and generated runs stay out to bound the time.
FOCUS = {SIGN_ARM: ("sign_", "no_trim_100"), CORE: ("finalize_", "core_", "create_after"), WRAP: ("finalize_", "core_"), CREATE: ("create_", "tree_"),
         TRACK_SIGN: ("track_sign", "quorum_", "repeat_", "after_quorum", "tree_", "no_trim", "exact_"), TRACK_FINAL: ("track_final", "finalize_split", "finalize_repeat", "final_map", "finalize_three"),
         QUORUM_SIGN: ("quorum_", "exact_", "track_sign"), QUORUM_FINAL: ("finalize_three", "track_final"), REMOVE_SIGN: ("finalize_", "tree_", "create_after"), REMOVE_FINAL: ("finalize_", "final_map", "create_after"),
         WEIGHT: ("weight", "exact_", "wide_set", "zero_"), MEMBER: ("track_", "quorum_", "wide_set", "weight")}


def run_mutants(image, table, seen, scenarios):
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, scenarios, [spec_run(scenario) for scenario in scenarios]) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    results = []
    IMAGE_FDE.update({target: image.exact_fde(target) for target in MUTATED})
    for target in MUTATED:
        chosen = [scenario for scenario in scenarios if scenario.name.startswith(FOCUS[target])]
        wants = [spec_run(scenario) for scenario in chosen]
        for va, kind, patch in edits_for(image, table[target], seen, target in (SIGN_ARM, CORE, WRAP)):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            hit = first_failure(harness, chosen, wants)
            results.append((va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else survivor_reason(va)))
    return results


def survivor_reason(va):
    for target, text in SURVIVORS:
        start, stop = IMAGE_FDE[target]
        if start <= va < stop:
            return text
    return "UNEXPLAINED"


IMAGE_FDE = {}
LOOP = "class: search loop step, clone, drop or stub argument with no effect on the compared state in the chosen scenarios"
SURVIVORS = ((SIGN_ARM, "class: output of a dropped record or argument of a stub"), (CORE, "class: argument of a stub or tail of a copied record"), (WRAP, "class: limit low byte, panic argument or event buffer size not read by the stub"),
             (CREATE, "class: search loop step or zeroed word of an empty value"), (TRACK_SIGN, LOOP), (TRACK_FINAL, LOOP), (QUORUM_SIGN, "class: second tree iterator, which is empty"), (QUORUM_FINAL, "class: second tree iterator, which is empty"),
             (REMOVE_SIGN, "class: walk of a removed value, which only reaches drops and stubs"), (REMOVE_FINAL, "class: walk of a removed value, which only reaches drops and stubs"), (WEIGHT, "class: tree walk step for a deeper tree, drop argument or saturation"), (MEMBER, "class: drop argument"))


def analyse(image, mutate=True, vectors=150):
    harness = Harness(image)
    scenarios = named_scenarios()
    named = check_all(harness, scenarios)
    check_all(harness, vector_scenarios(vectors))
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for target in TARGETS}
    through = slot_sites(image, (SLOT_REQUEST, SLOT_RECOVER, SLOT_VOTER, SLOT_MEMBER, SLOT_CORE, SLOT_EVENT))
    result = dict(table=table, named=named, scenarios=scenarios, vector_count=vectors, unreached=unreached, slots=slot_rows(image, through), sites=site_rows(image, through), copies=copy_rows(image), limits=limit_rows(image), notes=note_rows(image),
                  fields=field_rows(image), statuses=status_rows(image), layouts=layout_rows(), stack_reads=stack_argument_reads(image), steps=harness.machine.steps)
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, scenarios)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("path.tsv", ("function", "name", "bytes", "instructions", "unreached_rows"),
        [("%#x" % target, NAMES[target], sum(row.size for row in result["table"][target]), len(result["table"][target]), len(result["unreached"][target])) for target in TARGETS])
    tsv("unreached.tsv", ("function", "row"), [("%#x" % target, "%#x" % va) for target in TARGETS for va in result["unreached"][target]])
    tsv("slots.tsv", ("slot", "role", "relative_target", "call_sites"), result["slots"])
    tsv("call-sites.tsv", ("function", "name", "sites", "caller_functions", "first_callers"), result["sites"])
    tsv("wrapper-copies.tsv", ("function", "bytes", "instructions", "wrapper_instructions", "rows_differing"), result["copies"])
    tsv("limits.tsv", ("function", "at", "bytes", "limit_hex", "limit", "is_i64_max_over_10"), result["limits"])
    tsv("row-count-note.tsv", ("function", "compare_at", "take_count_at", "take_call", "free_call", "rows_after_take"), result["notes"])
    tsv("fields.tsv", ("key_at", "field_at", "key", "offset"), result["fields"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("node-layouts.tsv", ("tree", "key_at", "key_size", "value_at", "value_size", "parent_at", "parent_index_at", "count_at", "leaf_size"), result["layouts"])
    tsv("scenarios.tsv", ("scenario", "operations", "outcome"), [(scenario.name, " ".join(op.kind for op in scenario.ops), describe(trace)) for scenario, trace in result["named"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(TARGETS), "instructions": sum(len(result["table"][target]) for target in TARGETS),
        "named_scenarios": len(result["scenarios"]), "named_operations": sum(len(scenario.ops) for scenario in result["scenarios"]), "vector_scenarios": result["vector_count"],
        "reads_of_tracker_second_stack_argument": result["stack_reads"], "unreached_rows": sum(len(rows) for rows in result["unreached"].values()),
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
