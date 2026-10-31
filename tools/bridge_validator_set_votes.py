#!/usr/bin/env python3
"""Pin the node #94 validator set update votes from ELF bytes.

Arm 29 stores one signature per voter in `validator_set_signatures` under the epoch of the action, arm 45
stores voters in `validator_set_finalized_votes`, and a strict `3 * voted > 2 * total` stake test on arm 45
moves the current epoch to the action epoch and removes older signature rows. The real bytes of 29 functions
run under recording stubs, a separately written rule list predicts every status, stub event and tree state,
and reached conditional rows are mutated. No objdump or readelf output is parsed and the binary is never
executed. Standard library only.

    python3 tools/bridge_validator_set_votes.py --out <dir>
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



WRAP_SIGN = 0x1E642E0
WRAP_FINAL = 0x1E64CB0
ARM_SIGN = 0x374E620
ARM_FINAL = 0x374F930
AMOUNTS = 0x37A1230
COMPARE = 0x3369DB0
TRACK_SIGN = 0x3945250
TRACK_FINAL = 0x3945A20
QUORUM_SIGN = 0x3941240
QUORUM_FINAL = 0x3940D60
WEIGHT = 0x3366B60
VOTER = 0x33690C0
MEMBER = 0x3367530
TAKE = 0x3BD21A0
PUT_VOTE = 0x339B0D0
PUT_VOTER = 0x339E610
VACANT_SIGN_ROW = 0x33C1260
VACANT_SIGN_BUCKET = 0x33C1E70
VACANT_FINAL_ROW = 0x33C0700
VACANT_FINAL_BUCKET = 0x33BF330
PRUNE = 0x3942A90
SPLIT = 0x2FB3980
SPLIT_COUNT = 0x2FB2BA0
SPLIT_FIX = 0x2FB18B0
COLLECT = 0x3BCA2B0
DRAIN = 0x3BE5020
DYING_NEXT = 0x33AE9E0
ROW_DROP = 0x3941820
NEXT_SIGN = 0x330FD70
NEXT_FINAL = 0x330FE30
NAMES = {WRAP_SIGN: "sign_wrapper_arm_29", WRAP_FINAL: "final_wrapper_arm_45", ARM_SIGN: "sign_core", ARM_FINAL: "final_core", AMOUNTS: "amount_limits", COMPARE: "set_compare", TRACK_SIGN: "tracker_sign", TRACK_FINAL: "tracker_final",
         QUORUM_SIGN: "quorum_sign", QUORUM_FINAL: "quorum_final", WEIGHT: "stake_threshold", MEMBER: "is_member", TAKE: "first_100", PUT_VOTE: "signature_insert", PUT_VOTER: "voter_insert", VACANT_SIGN_ROW: "vacant_sign_row",
         VACANT_SIGN_BUCKET: "vacant_sign_bucket", VACANT_FINAL_ROW: "vacant_final_row", VACANT_FINAL_BUCKET: "vacant_final_bucket", PRUNE: "prune_signatures", SPLIT: "tree_split", SPLIT_COUNT: "split_count", SPLIT_FIX: "split_fix_edge", COLLECT: "collect_removed", DRAIN: "drain_removed",
         DYING_NEXT: "dying_next", ROW_DROP: "removed_row_drop", NEXT_SIGN: "second_map_next_sign", NEXT_FINAL: "second_map_next_final"}
TARGETS = tuple(sorted(NAMES))
MUTATED = (WRAP_SIGN, WRAP_FINAL, ARM_SIGN, ARM_FINAL, AMOUNTS, COMPARE, TRACK_SIGN, TRACK_FINAL, QUORUM_SIGN, PRUNE, DRAIN, ROW_DROP, COLLECT)

SLOT_ARM_SIGN = 0x57731A8
SLOT_ARM_FINAL = 0x57731B8
SLOT_AMOUNTS = 0x5775E30
SLOT_SET = 0x5775C78
SLOT_REQUEST = 0x5775DA8
SLOT_RECOVER = 0x576FE58
SLOT_VOTER = 0x5773148
SLOT_MEMBER = 0x5773D38
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_ALLOC_ERROR = 0x576E020
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_NONE = 0x576E470
SLOT_OVERFLOW = 0x576E118
SLOT_ONCE = 0x576E8B8
HELPER_SET = 0x3366580
HELPER_REQUEST = 0x358EA60
HELPER_RECOVER = 0x14C6F50
HASH_HELPER = 0x37F2940
HASH_ERROR = 0x365EB00
STAKE_MAP = 0x3364ED0
STATUS_DROP = 0x3379490
SET_SIGN = 0x3BB29C0
SET_FINAL = 0x3BB2DC0
CLONE_ACTION = 0x28A20D0
CLONE_SET = 0x33E5B90
CLONE_SIGN_A = 0x33E79F0
CLONE_SIGN_B = 0x33E59E0
CLONE_FINAL_A = 0x33E9610
CLONE_FINAL_B = 0x33E4600
DROPS = (0x33F1ED0, 0x33F7F10, 0x33FA3C0, 0x33F3FC0, 0x33F2530, 0x33F5A00, 0x33F1200, 0x3401150)
LEAF_SIGN_ROW = 0x2F3BC80
LEAF_FINAL_ROW = 0x2F3E690
LEAF_SIGN_BUCKET = 0x2F35070
LEAF_FINAL_BUCKET = 0x2F37FB0
LEAF_VOTE = 0x2F95400
LEAF_VOTER = 0x2F8BAD0
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_LIMIT = 0x13F
TAG_RECOVER = 0x7A
TAG_MISMATCH = 0x11F
TAG_SET = 0x35
TAG_NO_EPOCH = 0x97
TAG_NOT_VALIDATOR = 0x2A
OUTCOME_OK = 0xD
OUTCOME_ERROR = 0xE
STATUS_TABLE = 0x59A8D0
STATUS_TAGS = (TAG_LIMIT, TAG_RECOVER, TAG_MISMATCH, TAG_SET, TAG_NO_EPOCH, TAG_NOT_VALIDATOR)
AMOUNT_LIMIT = 0x0CCCCCCCCCCCCCCC
ROW_NOTE = 0x64

S_BRIDGE = 0x3398
S_CTX = 0x3840
S_CHAIN = 0x8F2
B_SIGN = 0xA0
B_FINAL = 0xD0
TRACKER_MAP = 0x18
C_ROOT = 0x30
C_EPOCH = 0x48
REQUEST_KIND = 4

Layout = collections.namedtuple("Layout", "name key_at key_size val_at val_size parent index count size")
ROWS = Layout("vote rows, signatures and finalize", 0x168, 8, 0, 0x20, 0x160, 0x1C0, 0x1C2, 0x1C8)
BUCKET = Layout("unit-key bucket", 0, 0, 0, 0x30, 0x210, 0x218, 0x21A, 0x220)
VOTES = Layout("signature votes", 0, 0x20, 0x168, 0x48, 0x160, 0x480, 0x482, 0x488)
VOTERS = Layout("voter set", 0, 0x20, 0, 0, 0x160, 0x168, 0x16A, 0x170)
EPOCHS = Layout("epochs", 8, 8, 0x60, 0x28, 0, 0x218, 0x21A, 0x220)
VALIDATORS = Layout("validators", 0x2C0, 0x20, 0, 0x40, 0x420, 0x428, 0x42A, 0x430)
STAKES = Layout("stake map", 0, 0x20, 0x168, 8, 0x160, 0x1C0, 0x1C2, 0x1C8)
ENTRIES = Layout("validator set entries", 0, 0x30, 0, 0, 0x210, 0x218, 0x21A, 0x220)
LAYOUTS = (ROWS, BUCKET, VOTES, VOTERS, EPOCHS, VALIDATORS, STAKES, ENTRIES)
V_SIGNER = 0x18
V_COLD = 0x2C

ARENA = HEAP_BASE + 0x1000
USED = 0x80000
ARENA_END = HEAP_BASE + 0x70000
OUT = HEAP_BASE + 0x100
TEMP = HEAP_BASE + 0x300
ACTION = HEAP_BASE + 0x600
SIGNER = HEAP_BASE + 0x700
EPOCH = 7


def address(tag):
    return blob(tag, 20)


def blob(tag, size):
    """Distinct bytes, so that a shifted copy never matches by accident."""
    return bytes((tag + index) & 0xFF for index in range(size))


def entry_key(item):
    return struct.pack("<Q", item[0]) + item[1] + item[2]


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(TARGETS)
        statics = machine.memory.statics
        statics[SLOT_MEMBER] = MEMBER
        statics[SLOT_ARM_SIGN] = ARM_SIGN
        statics[SLOT_ARM_FINAL] = ARM_FINAL
        statics[SLOT_AMOUNTS] = AMOUNTS
        table = {SLOT_VOTER: self.on_voter, SLOT_SET: self.on_set, SLOT_REQUEST: self.on_request, SLOT_RECOVER: self.on_recover, SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_FAIL: self.on_stop, SLOT_ALLOC_ERROR: self.on_stop,
                 SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_memcpy, SLOT_MEMMOVE: self.on_memcpy, SLOT_MEMCMP: self.on_memcmp, SLOT_NONE: self.on_none, SLOT_OVERFLOW: self.on_overflow, SLOT_ONCE: self.on_nothing}
        for slot, hook in table.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        calls = {HASH_HELPER: self.on_hash, HASH_ERROR: self.on_hash_error, STAKE_MAP: self.on_stakes, STATUS_DROP: self.on_nothing, SET_SIGN: self.on_set_sign, SET_FINAL: self.on_set_final,
                 CLONE_ACTION: self.on_clone_entries, CLONE_SET: self.on_clone_entries, CLONE_SIGN_A: self.on_clone, CLONE_SIGN_B: self.on_clone, CLONE_FINAL_A: self.on_clone, CLONE_FINAL_B: self.on_clone,
                 LEAF_SIGN_ROW: self.leaf_row, LEAF_FINAL_ROW: self.leaf_row, LEAF_SIGN_BUCKET: self.on_stop, LEAF_FINAL_BUCKET: self.on_stop, LEAF_VOTE: self.leaf(VOTES), LEAF_VOTER: self.leaf(VOTERS)}
        for drop in DROPS:
            calls[drop] = self.on_nothing
        machine.calls = calls
        self.events = []
        self.top = ARENA
        self.mode = "ok"
        self.lengths = {}

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
        self.put(machine.regs[RDI], self.data(machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = machine.regs[RDI]

    def on_memcmp(self, machine):
        size = machine.regs[RDX]
        left, right = self.data(machine.regs[RDI], size), self.data(machine.regs[RSI], size)
        machine.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]

    def on_none(self, machine):
        raise Panicked("option none")

    def on_overflow(self, machine):
        raise Panicked("add overflow")

    def on_request(self, machine):
        at = machine.regs[RSI]
        self.events.append(("request", self.read(at, 1), self.entries(at + 8), self.read(at + 0x20), machine.regs[RDX] & 0xFF))
        self.write(machine.regs[RDI], 0)
        self.put(machine.regs[RDI] + 8, blob(0x77, 0x30))

    def entries(self, at):
        root, height, count = self.read(at), self.read(at + 8), self.read(at + 0x10)
        if not count:
            return ()
        keys = [key for key, _ in self.walk(ENTRIES, root, height)]
        self.expect(len(keys) == count, "entry count")
        return tuple((struct.unpack_from("<Q", key)[0], key[8:28], key[28:48]) for key in keys)

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
        epoch = self.read(self.ctx + C_EPOCH)
        self.expect(machine.regs[RSI] == self.ctx and machine.regs[RCX] == epoch, "voter lookup arguments")
        validators = self.scenario.epochs.get(epoch)
        hits = [key for key, who, _ in validators or () if who == signer]
        if validators is None or not hits:
            self.write(out, TAG_NOT_VALIDATOR if validators is not None else TAG_NO_EPOCH, 2)
            self.put(out + 2, ERROR_TAIL)
        else:
            self.write(out, TAG_OK, 2)
            self.put(out + 2, hits[0])

    def on_set(self, machine):
        out, nonce = machine.regs[RDI], machine.regs[RDX]
        self.expect(machine.regs[RSI] == self.ctx, "set lookup context")
        wanted = self.scenario.sets.get(nonce, TAG_NO_EPOCH)
        if isinstance(wanted, int):
            self.write(out, wanted, 2)
            self.put(out + 2, ERROR_TAIL)
            return
        self.write(out, TAG_OK, 2)
        self.place_entries(out + 8, wanted)
        self.write(out + 0x20, self.scenario.echo.get(nonce, nonce))

    def place_entries(self, at, items):
        keys = sorted(items, key=entry_key)
        root = self.build(ENTRIES, [(entry_key(item), b"") for item in keys]) if keys else 0
        self.write(at, root)
        self.write(at + 8, self.height(keys))
        self.write(at + 0x10, len(keys))
        self.lengths[root] = len(keys)

    def on_clone_entries(self, machine):
        out, root = machine.regs[RDI], machine.regs[RSI]
        self.write(out, root)
        self.write(out + 8, machine.regs[RDX])
        self.write(out + 0x10, self.lengths[root])

    def on_stakes(self, machine):
        out, value = machine.regs[RDI], machine.regs[RSI]
        epoch = self.values.get(value)
        self.expect(epoch == self.read(self.ctx + C_EPOCH), "stake map of the wrong epoch")
        items = sorted((key, stake) for key, _, stake in self.scenario.epochs[epoch])
        root = self.build(STAKES, [(key, struct.pack("<Q", stake)) for key, stake in items]) if items else 0
        self.write(out, root)
        self.write(out + 8, self.height(items))
        self.write(out + 0x10, len(items))

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

    def leaf(self, layout):
        def hook(machine):
            out, handle = machine.regs[RDI], machine.regs[RSI]
            self.insert(layout, out, handle, self.data(machine.regs[RDX], layout.key_size), self.data(machine.regs[RCX], layout.val_size))
        return hook

    def leaf_row(self, machine):
        self.insert(ROWS, machine.regs[RDI], machine.regs[RSI], struct.pack("<Q", machine.regs[RDX]), self.data(machine.regs[RCX], ROWS.val_size))

    def insert(self, layout, out, handle, key, value):
        node, height, index = self.read(handle), self.read(handle + 8), self.read(handle + 0x10)
        self.expect(height == 0, "leaf insert above a leaf")
        count = self.read(node + layout.count, 2)
        self.expect(count < 11, "leaf overflow in a fixture")
        for size, base, data in ((layout.key_size, layout.key_at, key), (layout.val_size, layout.val_at, value)):
            if not size:
                continue
            if count > index:
                self.put(node + base + (index + 1) * size, self.data(node + base + index * size, (count - index) * size))
            self.put(node + base + index * size, data)
        self.write(node + layout.count, count + 1, 2)
        self.write(out, node)
        self.write(out + 8, 0)
        self.write(out + 0x10, index)

    def build(self, layout, items):
        """Build a tree of height 0 or 1 in the fixture arena; items are sorted (key bytes, value bytes)."""
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
        self.lengths = {0: 0}
        self.recovered = bytes(20)
        self.state = HEAP_BASE + 0x70000
        memory.put_bytes(self.state, bytes(0x4000))
        self.bridge = self.state + S_BRIDGE
        self.ctx = self.state + S_CTX
        self.write(self.ctx + C_EPOCH, scenario.current)
        self.values = {}
        known = sorted(set(scenario.epochs) | {scenario.current - 2, scenario.current + 40} - ({scenario.current} if not scenario.has_epoch else set()))
        cells = []
        for epoch in known:
            validators = scenario.epochs.get(epoch)
            if validators is None:
                cells.append((epoch, bytes(0x28)))
                continue
            items = sorted((key, blob(0xBB, V_SIGNER) + signer + address(0xD0) + bytes(0x40 - V_COLD - 20)) for key, signer, _ in validators)
            root = self.build(VALIDATORS, items) if items else 0
            cells.append((epoch, struct.pack("<QQQ", root, self.height(items), len(items)) + bytes(0x10)))
        root = self.build(EPOCHS, [(struct.pack("<Q", epoch), value) for epoch, value in cells])
        self.write(self.ctx + C_ROOT, root)
        self.write(self.ctx + C_ROOT + 8, 0)
        for index, (epoch, _) in enumerate(cells):
            self.values[root + EPOCHS.val_at + index * EPOCHS.val_size] = epoch
        for keys, offset in ((scenario.sign_rows, B_SIGN), (scenario.final_rows, B_FINAL)):
            if keys:
                items = [(struct.pack("<Q", key), self.fixture_row()) for key in sorted(keys)]
                at = self.bridge + offset + TRACKER_MAP
                self.write(at, self.build(ROWS, items))
                self.write(at + 8, self.height(items))
                self.write(at + 0x10, len(items))

    def fixture_row(self):
        bucket = self.build(BUCKET, [(b"", bytes(0x30))])
        return struct.pack("<QQQ", bucket, 0, 1) + b"\x00\x01" + bytes(6)

    def dump_rows(self, offset, voters_only):
        at = self.bridge + offset + TRACKER_MAP
        rows = {}
        for key, value in self.walk(ROWS, self.read(at), self.read(at + 8)) if self.read(at + 0x10) else ():
            buckets = self.walk(BUCKET, self.read(value), self.read(value + 8)) if self.read(value + 0x10) else []
            self.expect(len(buckets) <= 1, "unit-key map with two entries")
            votes = set() if voters_only else {}
            for _, bucket in buckets:
                self.expect(self.read(bucket + 0x18) == 0, "second map populated")
                root, height = self.read(bucket), self.read(bucket + 8)
                if voters_only:
                    votes = {voter for voter, _ in self.walk(VOTERS, root, height)} if self.read(bucket + 0x10) else set()
                else:
                    votes = {voter: self.data(vote, 0x48) for voter, vote in self.walk(VOTES, root, height)} if self.read(bucket + 0x10) else {}
            rows[struct.unpack_from("<Q", key)[0]] = dict(done=self.read(value + 0x18, 1), open=self.read(value + 0x19, 1), buckets=len(buckets), votes=votes)
        return rows

    def dump(self):
        return self.read(self.ctx + C_EPOCH), self.dump_rows(B_SIGN, False), self.dump_rows(B_FINAL, True)

    def outcome(self):
        tag = self.read(OUT, 1)
        if tag == OUTCOME_OK:
            return (tag,)
        status = self.read(OUT + 8, 2)
        view = [tag, status]
        if status in (TAG_LIMIT, TAG_RECOVER):
            view.append(self.read(OUT + 0x10))
        if status in (TAG_NO_EPOCH, TAG_NOT_VALIDATOR):
            view.append(self.data(OUT + 0xA, len(ERROR_TAIL)))
        return tuple(view)

    def perform(self, op):
        memory = self.machine.memory
        memory.put_bytes(OUT, bytes([0xEE]) * 0x70)
        self.events = []
        kind = op.kind
        if kind in ("sign", "final"):
            self.mode, self.recovered = op.mode, op.recovered
            self.put(SIGNER, op.signer)
            self.place_entries(ACTION, op.entries)
            self.write(ACTION + 0x18, op.nonce)
            self.put(ACTION + 0x20, op.sig)
            self.write(self.state + S_CHAIN, op.chain, 1)
            self.machine.run(WRAP_SIGN if kind == "sign" else WRAP_FINAL, {RDI: OUT, RSI: ACTION, RDX: SIGNER, RCX: self.state})
            return self.outcome(), tuple(self.events)
        if kind in ("track_sign", "track_final"):
            memory.put_bytes(TEMP + 0x80, bytes([1 if op.voter else 0]) + (op.voter or bytes(32)))
            if kind == "track_sign":
                self.put(TEMP + 0xC0, op.sig)
                self.machine.run(TRACK_SIGN, {RDI: OUT, RSI: self.bridge + B_SIGN, RDX: op.nonce, RCX: TEMP + 0x80, R8: TEMP + 0xC0, R9: self.ctx}, (1,))
            else:
                self.machine.run(TRACK_FINAL, {RDI: OUT, RSI: self.bridge + B_FINAL, RDX: op.nonce, RCX: TEMP + 0x80, R8: self.ctx, R9: 1})
            return (self.read(OUT),), tuple(self.events)
        if kind == "prune":
            self.machine.run(PRUNE, {RDI: OUT, RSI: self.bridge + B_SIGN, RDX: op.nonce, RCX: 1})
            count = self.read(OUT + 0x10)
            pointer = self.read(OUT + 8)
            return (tuple(self.read(pointer + 8 * index) for index in range(count)),), tuple(self.events)
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
        defaults = dict(nonce=EPOCH + 1, entries=NEXT, chain=3, mode="ok", sig=blob(0x51, 0x48), voter=None, signer=None)
        defaults.update(fields)
        self.__dict__.update(defaults)
        self.recovered = fields.get("recovered", self.signer)

    def __repr__(self):
        return self.kind


class Scenario:
    def __init__(self, name, ops, validators=None, epochs=None, sets=None, echo=None, current=EPOCH, has_epoch=True, sign_rows=(), final_rows=()):
        self.name = name
        self.ops = ops
        self.current = current
        self.has_epoch = has_epoch
        self.epochs = dict(epochs) if epochs is not None else {current: EQUAL if validators is None else validators}
        if not has_epoch:
            self.epochs.pop(current, None)
        self.sets = {EPOCH + 1: NEXT} if sets is None else dict(sets)
        self.echo = echo or {}
        self.sign_rows = tuple(sign_rows)
        self.final_rows = tuple(final_rows)


HASH_VALUE = blob(0xC3, 32)
ERROR_WORD = 0x1357
ERROR_TAIL = blob(0x30, 0x5E)


def validator(tag, stake=100):
    return (blob(tag, 32), address(tag), stake)


def entry(tag, stake=100):
    return (stake, address(tag), address(tag + 0x40))


EQUAL = (validator(0x11), validator(0x22), validator(0x33), validator(0x44))
V1, V2, V3, V4 = EQUAL
OUTSIDER = address(0xF0)
NEXT = (entry(0x11), entry(0x22), entry(0x33, 90))
OTHER_SET = (entry(0x11), entry(0x22), entry(0x33, 91))


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
        self.epoch = scenario.current
        self.signatures = {key: dict(done=0, open=1, buckets=1, votes={}) for key in scenario.sign_rows}
        self.finals = {key: dict(done=0, open=1, buckets=1, votes=set()) for key in scenario.final_rows}

    def validators(self):
        return self.scenario.epochs.get(self.epoch)

    def voter_of(self, signer):
        validators = self.validators()
        if validators is None:
            return TAG_NO_EPOCH, None
        hits = [key for key, who, _ in validators if who == signer]
        return (TAG_OK, hits[0]) if hits else (TAG_NOT_VALIDATOR, None)

    def member(self, voter):
        return any(key == voter for key, _, _ in self.validators() or ())

    def reached(self, voters):
        validators = self.validators()
        if validators is None:
            return False
        return spec_weight({key: stake for key, _, stake in validators}, voters)

    def trim_events(self, size):
        return (("alloc", 800), ("free", 800)) if size > ROW_NOTE else ()

    def vote(self, rows, nonce, voter, store, fresh):
        """One tracker step: member test, row, bucket, then the quorum move. Returns True on the move."""
        if voter is None or not self.member(voter):
            return False
        row = rows.setdefault(nonce, dict(done=0, open=1, buckets=1, votes=fresh()))
        if row["done"]:
            store(row["votes"])
            return False
        before = self.reached(row["votes"])
        store(row["votes"])
        if not before and self.reached(row["votes"]):
            row["done"], row["open"] = 1, 0
            return True
        return False

    def add_signature(self, nonce, voter, sig):
        return self.vote(self.signatures, nonce, voter, lambda votes: votes.__setitem__(voter, sig), dict)

    def add_final(self, nonce, voter):
        return self.vote(self.finals, nonce, voter, lambda votes: votes.add(voter), set)

    def amounts(self, entries, nonce):
        for item in sorted(entries, key=entry_key):
            if item[0] >= AMOUNT_LIMIT:
                return (OUTCOME_ERROR, TAG_LIMIT, item[0])
        if nonce >= AMOUNT_LIMIT:
            return (OUTCOME_ERROR, TAG_LIMIT, nonce)
        return None

    def compare(self, entries, nonce):
        wanted = self.scenario.sets.get(nonce, TAG_NO_EPOCH)
        if isinstance(wanted, int):
            return (OUTCOME_ERROR, wanted, ERROR_TAIL) if wanted in (TAG_NO_EPOCH, TAG_NOT_VALIDATOR) else (OUTCOME_ERROR, wanted)
        if sorted(wanted, key=entry_key) != sorted(entries, key=entry_key) or self.scenario.echo.get(nonce, nonce) != nonce:
            return (OUTCOME_ERROR, TAG_SET)
        return None

    def prune(self, nonce):
        removed = sorted(key for key in self.signatures if key < nonce)
        for key in removed:
            del self.signatures[key]
        return removed

    def apply(self, op):
        kind = op.kind
        if kind == "sign":
            return self.apply_sign(op)
        if kind == "final":
            return self.apply_final(op)
        if kind == "track_sign":
            won = self.add_signature(op.nonce, op.voter, op.sig)
            return (int(won),), self.trim_events(len(self.signatures))
        if kind == "track_final":
            won = self.add_final(op.nonce, op.voter)
            return (int(won),), self.trim_events(len(self.finals))
        if kind == "prune":
            return (tuple(self.prune(op.nonce)),), ()
        raise EvidenceError("unknown operation " + kind)

    def first_checks(self, op):
        status, voter = self.voter_of(op.signer)
        if status != TAG_OK:
            return (OUTCOME_ERROR, status, ERROR_TAIL), voter
        return self.amounts(op.entries, op.nonce), voter

    def apply_sign(self, op):
        stop, voter = self.first_checks(op)
        if stop:
            return stop, ()
        events = [("request", REQUEST_KIND, tuple(sorted(op.entries, key=entry_key)), op.nonce, op.chain)]
        if op.mode == "hash_error":
            return (OUTCOME_ERROR, TAG_RECOVER, ERROR_WORD), tuple(events)
        events.append(("recover", op.sig, HASH_VALUE))
        if op.mode == "recover_error":
            return (OUTCOME_ERROR, TAG_RECOVER, ERROR_WORD), tuple(events)
        if op.recovered != op.signer:
            return (OUTCOME_ERROR, TAG_MISMATCH), tuple(events)
        stop = self.compare(op.entries, op.nonce)
        if stop:
            return stop, tuple(events)
        self.add_signature(op.nonce, voter, op.sig)
        return (OUTCOME_OK,), tuple(events) + self.trim_events(len(self.signatures))

    def apply_final(self, op):
        stop, voter = self.first_checks(op)
        if stop:
            return stop, ()
        stop = self.compare(op.entries, op.nonce)
        if stop:
            return stop, ()
        if op.nonce <= self.epoch:
            return (OUTCOME_OK,), ()
        won = self.add_final(op.nonce, voter)
        events = self.trim_events(len(self.finals))
        if won:
            self.epoch = op.nonce
            self.prune(op.nonce)
        return (OUTCOME_OK,), events

    def snapshot(self):
        copy = lambda rows: {key: dict(row, votes=type(row["votes"])(row["votes"])) for key, row in rows.items()}
        return self.epoch, copy(self.signatures), copy(self.finals)


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


def sign(who=V1, **fields):
    fields.setdefault("signer", who[1])
    return Op("sign", **fields)


def final(who=V1, **fields):
    fields.setdefault("signer", who[1])
    return Op("final", **fields)


MANY = tuple(validator(0x40 + index * 3) for index in range(30))
WIDE_SET = tuple(entry(0x20 + index * 2, 1000 + index) for index in range(30))
NEXT_VALIDATORS = (validator(0x55, 10), validator(0x66, 10))


def named_scenarios():
    limit = AMOUNT_LIMIT
    n = EPOCH + 1
    return [Scenario("sign_ok_first_vote", [sign()]),
            Scenario("sign_outsider", [sign(signer=OUTSIDER)]),
            Scenario("sign_no_epoch", [sign()], has_epoch=False),
            Scenario("sign_empty_validators", [sign()], validators=()),
            Scenario("sign_stake_at_limit", [sign(entries=(entry(0x11, limit), entry(0x22, 5)))]),
            Scenario("sign_stake_limit_minus_one", [sign(entries=(entry(0x11, limit - 1),))], sets={n: (entry(0x11, limit - 1),)}),
            Scenario("sign_stake_first_over_limit_reported", [sign(entries=(entry(0x11, limit + 2), entry(0x22, limit + 1)))]),
            Scenario("sign_nonce_at_limit", [sign(nonce=limit)]),
            Scenario("sign_nonce_limit_minus_one", [sign(nonce=limit - 1)], sets={limit - 1: NEXT}),
            Scenario("sign_reference_limit_nonce", [sign(nonce=0xCCCCCCCCCCCCCCCC)]),
            Scenario("sign_stake_before_nonce", [sign(nonce=limit + 3, entries=(entry(0x11, limit + 7),))]),
            Scenario("sign_hash_error", [sign(mode="hash_error")]),
            Scenario("sign_recover_error", [sign(mode="recover_error")]),
            Scenario("sign_signer_mismatch", [sign(recovered=address(0xE1))]),
            Scenario("sign_mismatch_last_byte", [sign(recovered=V1[1][:19] + b"\x12")]),
            Scenario("sign_mismatch_byte_16", [sign(recovered=V1[1][:16] + b"\x00" + V1[1][17:])]),
            Scenario("sign_order_validator_before_limit", [sign(signer=OUTSIDER, nonce=limit)]),
            Scenario("sign_order_limit_before_hash", [sign(nonce=limit, mode="hash_error")]),
            Scenario("sign_order_hash_before_set", [sign(mode="hash_error", entries=OTHER_SET)]),
            Scenario("sign_order_mismatch_before_set", [sign(recovered=address(0xE1), entries=OTHER_SET)]),
            Scenario("sign_chain_zero", [sign(chain=0)]),
            Scenario("sign_chain_two", [sign(chain=2)]),
            Scenario("sign_set_other_stake", [sign(entries=OTHER_SET)]),
            Scenario("sign_set_other_hot", [sign(entries=(entry(0x11), entry(0x22), (90, address(0x3A), address(0x73))))]),
            Scenario("sign_set_other_cold", [sign(entries=(entry(0x11), entry(0x22), (90, address(0x33), address(0x7A))))]),
            Scenario("sign_set_one_cold_byte", [sign(entries=(entry(0x11), entry(0x22), (90, address(0x33), address(0x73)[:19] + b"\x00")))]),
            Scenario("sign_set_one_hot_byte", [sign(entries=(entry(0x11), entry(0x22), (90, address(0x33)[:19] + b"\x00", address(0x73))))]),
            Scenario("sign_set_extra_entry", [sign(entries=NEXT + (entry(0x77),))]),
            Scenario("sign_set_missing_entry", [sign(entries=NEXT[:2])]),
            Scenario("sign_set_empty_action", [sign(entries=())]),
            Scenario("sign_set_both_empty", [sign(entries=())], sets={n: ()}),
            Scenario("sign_set_lookup_failure", [sign()], sets={}),
            Scenario("sign_set_lookup_other_status", [sign()], sets={n: 0x55}),
            Scenario("sign_set_echo_differs", [sign()], echo={n: n + 1}),
            Scenario("sign_old_nonce_accepted", [sign(nonce=3), sign(V2, nonce=3), sign(V3, nonce=3), sign(V4, nonce=3)], sets={3: NEXT}),
            Scenario("sign_current_nonce_accepted", [sign(nonce=EPOCH)], sets={EPOCH: NEXT}),
            Scenario("sign_quorum_three_of_four", [sign(V1), sign(V2), sign(V3), sign(V4)]),
            Scenario("sign_repeat_vote_overwrites", [sign(V1), sign(V1, sig=blob(0x52, 0x48)), sign(V2), sign(V2, sig=blob(0x53, 0x48))]),
            Scenario("sign_after_quorum_kept", [sign(V1), sign(V2), sign(V3), sign(V1, sig=blob(0x54, 0x48)), sign(V4)]),
            Scenario("sign_exact_two_thirds_short", [sign(V1), sign(V2), sign(V3)], validators=(V1, V2, V3)),
            Scenario("sign_two_nonces_two_rows", [sign(nonce=n), sign(nonce=n + 1), sign(V2, nonce=n + 1), sign(V3, nonce=n - 1)], sets={n: NEXT, n + 1: NEXT, n - 1: NEXT}),
            Scenario("sign_nonce_order_rows", [sign(nonce=n + 5), sign(nonce=n - 3), sign(nonce=n + 2), sign(nonce=n)], sets={n + 5: NEXT, n - 3: NEXT, n + 2: NEXT, n: NEXT}),
            Scenario("sign_one_validator_first_vote_wins", [sign(V1)], validators=(V1,)),
            Scenario("final_one_validator_first_vote_moves", [final(V1)], validators=(V1,)),
            Scenario("final_three_of_four_moves_epoch", [final(V1), final(V2), final(V3)]),
            Scenario("final_two_of_four_no_move", [final(V1), final(V2)]),
            Scenario("final_exact_two_thirds_short", [final(V1), final(V2), final(V3)], validators=(V1, V2, V3)),
            Scenario("final_repeat_voter_counts_once", [final(V1), final(V1), final(V1), final(V2), final(V3)]),
            Scenario("final_after_signatures_keeps_row", [sign(V1), sign(V2), sign(V3), final(V1), final(V2), final(V3)]),
            Scenario("final_prunes_older_rows", [sign(nonce=n - 2), sign(nonce=n), sign(nonce=n + 1), final(V1), final(V2), final(V3)], sets={n - 2: NEXT, n: NEXT, n + 1: NEXT}),
            Scenario("final_keeps_equal_row", [sign(nonce=n), final(V1), final(V2), final(V3), sign(V2, nonce=n)], epochs={EPOCH: EQUAL, n: EQUAL}),
            Scenario("final_old_nonce_is_noop", [final(nonce=EPOCH), final(nonce=EPOCH - 3)], sets={EPOCH: NEXT, EPOCH - 3: NEXT}),
            Scenario("final_after_move_vote_is_noop", [final(V1), final(V2), final(V3), final(V4)], epochs={EPOCH: EQUAL, n: EQUAL}),
            Scenario("final_after_move_old_signer_refused", [final(V1), final(V2), final(V3), final(V4), sign(V1, nonce=n + 1), sign(NEXT_VALIDATORS[0], nonce=n + 1)], epochs={EPOCH: EQUAL, n: NEXT_VALIDATORS}, sets={n: NEXT, n + 1: NEXT}),
            Scenario("final_after_move_no_epoch_state", [final(V1), final(V2), final(V3), sign(V1)]),
            Scenario("final_skips_epochs", [final(V1, nonce=n + 5), final(V2, nonce=n + 5), final(V3, nonce=n + 5)], sets={n + 5: NEXT}, epochs={EPOCH: EQUAL, n + 5: EQUAL}),
            Scenario("final_lower_after_higher", [final(V1, nonce=n + 2), final(V1, nonce=n), final(V2, nonce=n + 2), final(V3, nonce=n + 2), final(V2, nonce=n), final(V3, nonce=n)], sets={n + 2: NEXT, n: NEXT}, epochs={EPOCH: EQUAL, n + 2: EQUAL}),
            Scenario("final_two_nonces_separate", [final(V1, nonce=n), final(V2, nonce=n + 1), final(V3, nonce=n)], sets={n: NEXT, n + 1: NEXT}),
            Scenario("final_row_kept_after_move", [final(V1, nonce=n), final(V2, nonce=n + 1), final(V2, nonce=n), final(V3, nonce=n), final(V1, nonce=n + 1), final(V3, nonce=n + 1)], sets={n: NEXT, n + 1: NEXT}, epochs={EPOCH: EQUAL, n: EQUAL}),
            Scenario("final_outsider", [final(signer=OUTSIDER)]),
            Scenario("final_no_epoch", [final()], has_epoch=False),
            Scenario("final_stake_at_limit", [final(entries=(entry(0x11, limit),))]),
            Scenario("final_nonce_at_limit", [final(nonce=limit)]),
            Scenario("final_nonce_limit_minus_one", [final(nonce=limit - 1)], sets={limit - 1: NEXT}),
            Scenario("final_set_empty_action", [final(entries=())]),
            Scenario("final_set_both_empty", [final(V1, entries=()), final(V2, entries=()), final(V3, entries=())], sets={n: ()}, epochs={EPOCH: EQUAL, n: EQUAL}),
            Scenario("final_set_differs", [final(entries=OTHER_SET)]),
            Scenario("final_set_differs_old_nonce", [final(nonce=EPOCH, entries=OTHER_SET)], sets={EPOCH: NEXT}),
            Scenario("final_set_lookup_failure", [final()], sets={}),
            Scenario("final_set_lookup_failure_old_nonce", [final(nonce=EPOCH)], sets={}),
            Scenario("final_set_echo_differs", [final()], echo={n: n + 1}),
            Scenario("final_order_validator_before_limit", [final(signer=OUTSIDER, nonce=limit)]),
            Scenario("final_order_limit_before_set", [final(nonce=limit, entries=OTHER_SET)]),
            Scenario("final_reads_no_signature", [final(sig=bytes(0x48), mode="recover_error")]),
            Scenario("wide_action_two_levels", [sign(entries=WIDE_SET), final(entries=WIDE_SET)], sets={n: WIDE_SET}),
            Scenario("wide_action_last_differs", [sign(entries=WIDE_SET[:-1] + (entry(0x7E, 1029),))], sets={n: WIDE_SET}),
            Scenario("wide_action_middle_differs", [sign(entries=WIDE_SET[:14] + (entry(0x7E, 1014),) + WIDE_SET[15:])], sets={n: WIDE_SET}),
            Scenario("wide_stake_over_limit_late", [sign(entries=WIDE_SET[:-1] + (entry(0x7E, limit),))], sets={n: WIDE_SET}),
            Scenario("wide_validators_vote", [sign(MANY[0]), sign(MANY[14]), sign(MANY[29]), final(MANY[3]), final(MANY[16])], validators=MANY),
            Scenario("wide_quorum_signatures", [sign(row) for row in MANY[:11]], validators=MANY[:16]),
            Scenario("wide_quorum_final", [final(row) for row in MANY[:11]], validators=MANY[:16]),
            Scenario("no_trim_100_rows", [sign()], sign_rows=[100 + i for i in range(99)]),
            Scenario("no_trim_101_rows", [sign(), sign(V2)], sign_rows=[100 + i for i in range(100)]),
            Scenario("no_trim_110_rows", [sign()], sign_rows=[100 + i for i in range(109)]),
            Scenario("final_map_100_rows", [final()], final_rows=[100 + i for i in range(99)]),
            Scenario("final_map_101_rows", [final(), final(V2)], final_rows=[100 + i for i in range(100)]),
            Scenario("final_map_101_rows_moves", [final(V1), final(V2), final(V3)], final_rows=[100 + i for i in range(100)]),
            Scenario("track_sign_no_voter", [Op("track_sign")]),
            Scenario("track_sign_non_member", [Op("track_sign", voter=blob(0x99, 32))]),
            Scenario("track_sign_winner_output", [Op("track_sign", voter=V1[0]), Op("track_sign", voter=V2[0]), Op("track_sign", voter=V3[0]), Op("track_sign", voter=V4[0])]),
            Scenario("track_sign_no_epoch", [Op("track_sign", voter=V1[0])], has_epoch=False),
            Scenario("track_sign_seeded_row", [Op("track_sign", voter=V1[0], nonce=5), Op("track_sign", voter=V2[0], nonce=5), Op("track_sign", voter=V3[0], nonce=5)], sign_rows=[3, 5, 9]),
            Scenario("track_final_no_voter", [Op("track_final")]),
            Scenario("track_final_non_member", [Op("track_final", voter=blob(0x99, 32))]),
            Scenario("track_final_winner_output", [Op("track_final", voter=V1[0]), Op("track_final", voter=V2[0]), Op("track_final", voter=V3[0]), Op("track_final", voter=V4[0])]),
            Scenario("track_final_no_epoch", [Op("track_final", voter=V1[0])], has_epoch=False),
            Scenario("track_final_two_rows", [Op("track_final", voter=V1[0], nonce=4), Op("track_final", voter=V1[0], nonce=9), Op("track_final", voter=V2[0], nonce=2)]),
            Scenario("prune_empty_map", [Op("prune", nonce=9)]),
            Scenario("prune_below_all", [Op("prune", nonce=2)], sign_rows=[3, 5, 9]),
            Scenario("prune_equal_first", [Op("prune", nonce=3)], sign_rows=[3, 5, 9]),
            Scenario("prune_between", [Op("prune", nonce=6)], sign_rows=[3, 5, 9]),
            Scenario("prune_equal_last", [Op("prune", nonce=9)], sign_rows=[3, 5, 9]),
            Scenario("prune_above_all", [Op("prune", nonce=10)], sign_rows=[3, 5, 9]),
            Scenario("prune_two_levels", [Op("prune", nonce=115)], sign_rows=[100 + i for i in range(30)]),
            Scenario("prune_two_levels_all", [Op("prune", nonce=1000)], sign_rows=[100 + i for i in range(30)]),
            Scenario("prune_two_levels_first_child", [Op("prune", nonce=104)], sign_rows=[100 + i for i in range(40)]),
            Scenario("prune_two_levels_separator", [Op("prune", nonce=110)], sign_rows=[100 + i for i in range(40)]),
            Scenario("prune_two_levels_last_child", [Op("prune", nonce=136)], sign_rows=[100 + i for i in range(40)]),
            Scenario("prune_two_levels_tail_only", [Op("prune", nonce=127)], sign_rows=[100 + i for i in range(30)]),
            Scenario("prune_two_levels_keep_one", [Op("prune", nonce=129)], sign_rows=[100 + i for i in range(30)]),
            Scenario("prune_voted_rows", [Op("track_sign", voter=V1[0], nonce=4), Op("track_sign", voter=V2[0], nonce=4), Op("track_sign", voter=V3[0], nonce=4), Op("track_sign", voter=V1[0], nonce=6), Op("prune", nonce=5)]),
            Scenario("prune_then_vote", [Op("prune", nonce=6), Op("track_sign", voter=V1[0], nonce=7), Op("track_sign", voter=V1[0], nonce=2)], sign_rows=[3, 5, 9])]


def lcg(seed):
    value = seed
    while True:
        value = (value * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield value >> 33


def vector_scenarios(count):
    source = lcg(0x1439)
    out = []
    for index in range(count):
        size = 3 + next(source) % 3
        stakes = tuple(validator(0x11 * (at + 1), 1 + next(source) % 5) for at in range(size))
        nonces = [EPOCH + delta for delta in (-1, 0, 1, 2, 3)]
        sets = {nonce: NEXT for nonce in nonces}
        epochs = {nonce: stakes for nonce in nonces[1:]}
        ops = []
        for _ in range(12):
            pick = next(source) % 8
            nonce = nonces[next(source) % 5]
            who = stakes[next(source) % size] if next(source) % 7 else (blob(0xF0, 32), OUTSIDER, 0)
            entries = NEXT if next(source) % 6 else OTHER_SET
            ops.append(sign(who, nonce=nonce, entries=entries) if pick < 3 else final(who, nonce=nonce, entries=entries))
        out.append(Scenario("vector_%d" % index, ops, epochs=epochs, sets=sets))
    return out


def describe(trace):
    """One short line per operation of a run: status, a marker for the 100-row step, and the epoch after it."""
    parts = []
    for step in trace:
        if step[0] == "panic":
            parts.append("panic " + step[1])
            continue
        view, events, state = step
        if isinstance(view[0], tuple):
            text = "removed[%s]" % ",".join(str(key) for key in view[0])
        else:
            text = "%#x" % (view[1] if view[0] == OUTCOME_ERROR and len(view) > 1 else view[0])
        kinds = [event[0] for event in events if event[0] == "alloc"]
        parts.append(text + ("(" + "+".join(kinds) + ")" if kinds else "") + ":e%d" % state[0])
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
    named = ((SLOT_ARM_SIGN, "sign core", ARM_SIGN), (SLOT_ARM_FINAL, "final core", ARM_FINAL), (SLOT_AMOUNTS, "amount limits", AMOUNTS), (SLOT_SET, "validator set at epoch", HELPER_SET), (SLOT_REQUEST, "request builder", HELPER_REQUEST),
             (SLOT_RECOVER, "signature recover", HELPER_RECOVER), (SLOT_VOTER, "voter of signer", VOTER), (SLOT_MEMBER, "member test", MEMBER))
    rows = []
    for slot, role, target in named:
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        rows.append(("%#x" % slot, role, "%#x" % target, len(through[slot])))
    return rows


def site_rows(image, through):
    direct = direct_sites(image, TARGETS)
    by_slot = {MEMBER: SLOT_MEMBER, ARM_SIGN: SLOT_ARM_SIGN, ARM_FINAL: SLOT_ARM_FINAL, AMOUNTS: SLOT_AMOUNTS}
    rows = []
    for target in TARGETS:
        sites = through[by_slot[target]] if target in by_slot else direct[target]
        owners = sorted({image.fde(site)[0] for site in sites})
        rows.append(("%#x" % target, NAMES[target], len(sites), len(owners), " ".join("%#x" % owner for owner in owners[:6])))
    return rows


COPIES = ((WRAP_SIGN, 0x46BD130), (WRAP_SIGN, 0x46BD270), (WRAP_FINAL, 0x46BDB40), (WRAP_FINAL, 0x46BDC30))


def copy_rows(image):
    """The other hosts of the two cores, compared row by row with the wrapper read here."""
    rows = []
    for wrapper, copy in COPIES:
        first = decode_range(image, *image.exact_fde(wrapper))
        start, stop = image.exact_fde(copy)
        table = decode_range(image, start, stop)
        differing = [left.va for left, right in zip(first, table) if left.op != right.op or (left.data != right.data and left.op not in ("call", "calli", "jcc", "jmp", "lea") and left.rip_at is None)]
        rows.append(("%#x" % wrapper, "%#x" % copy, stop - start, len(table), len(first), len(differing), " ".join("%#x" % va for va in differing[:6])))
    return rows


LIMIT_BYTES = struct.pack("<Q", AMOUNT_LIMIT)


def limit_rows(image):
    start, stop = image.exact_fde(AMOUNTS)
    data = bytes(image.blob[image.offset(start):image.offset(stop)])
    sites = [start + match.start() - 2 for match in re.finditer(re.escape(LIMIT_BYTES), data)]
    if len(sites) != 1:
        raise EvidenceError("limit sites")
    table = decode_range(image, start, stop)
    compares = [row for row in table if row.op == "cmp" and row.a[0] == "r" and row.b[0] == "r" and RDX in (row.a[1], row.b[1])]
    if len(compares) != 2:
        raise EvidenceError("limit compares")
    at = sites[0]
    return [("%#x" % at, data[at - start:at - start + 10].hex(), "%#x" % AMOUNT_LIMIT, AMOUNT_LIMIT, MASK[8] // 2 // 10 == AMOUNT_LIMIT, " ".join("%#x" % row.va for row in compares))]


def note_rows(image):
    """The two size tests, and the fact that nothing but a free follows the first-100 collect."""
    rows = []
    for target, take_site, free_site in ((TRACK_SIGN, 0x394592F, 0x394594F), (TRACK_FINAL, 0x394603F, 0x394605F)):
        table = decode_range(image, *image.exact_fde(target))
        index = next(at for at, row in enumerate(table) if row.va == take_site)
        if table[index].target != TAKE:
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


# key_load, its helper or None, field lea in the serializer, the key text, field offset
FIELD_SITES = ((0x22156B6, 0x22156D4, "withdrawal_signatures", 0x40), (0x22156F4, 0x2215712, "withdrawal_finalized_votes", 0x70), (0x2215732, 0x2215750, "finished_withdrawal_to_time", 0x118),
               (0x22BDBB1, 0x221576C, "validator_set_signatures", 0xA0), (0x22BD851, 0x2215788, "validator_set_finalized_votes", 0xD0))
HELPER_CALLS = {0xA0: (0x2215779, 0x22BDBA0), 0xD0: (0x2215795, 0x22BD840)}
SERIALIZER = 0x22155C0


def field_rows(image):
    rows = []
    for key_at, field_at, name, offset in FIELD_SITES:
        at = image.offset(key_at)
        if bytes(image.blob[at:at + 3]) != bytes.fromhex("488d35"):
            raise EvidenceError("key load moved")
        text = key_at + 7 + struct.unpack_from("<i", image.blob, at + 3)[0]
        size = struct.unpack_from("<I", image.blob, at + 8)[0]
        if bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii") != name:
            raise EvidenceError("key text")
        code = bytes(image.blob[image.offset(field_at):image.offset(field_at) + 7])
        if code[:3] == bytes.fromhex("498db7") or code[:3] == bytes.fromhex("498d97"):
            found = struct.unpack_from("<I", code, 3)[0]
        elif code[:3] == bytes.fromhex("498d77"):
            found = code[3]
        else:
            raise EvidenceError("field lea %#x" % field_at)
        if found != offset:
            raise EvidenceError("field offset %#x" % field_at)
        if offset in HELPER_CALLS:
            site, helper = HELPER_CALLS[offset]
            if image.blob[image.offset(site)] != 0xE8 or site + 5 + struct.unpack_from("<i", image.blob, image.offset(site) + 1)[0] != helper or image.exact_fde(helper)[0] != helper or not helper <= key_at < image.exact_fde(helper)[1]:
                raise EvidenceError("field helper %#x" % helper)
        rows.append(("%#x" % key_at, "%#x" % field_at, name, "%#x" % offset))
    return rows


# Rows quoted by the README: the bytes are read here so that a moved row fails the run.
KEY_ROWS = ((ARM_FINAL, 0x374FA27, "action epoch against current epoch", "cmp"), (ARM_FINAL, 0x374FA2A, "not newer: leave with success", "jcc"), (ARM_FINAL, 0x374FAC4, "store action epoch as current epoch", "mov"),
            (ARM_FINAL, 0x374FACF, "prune output", "lea"), (ARM_FINAL, 0x374FADF, "prune the signature map", "call"), (ARM_SIGN, 0x374EAAB, "set compare after recovery", "call"), (ARM_SIGN, 0x374E733, "amount limits before the hash", "calli"),
            (ARM_SIGN, 0x374E8FF, "request kind 4", "mov"), (TRACK_SIGN, 0x3945418, "row key is one u64", "cmp"), (TRACK_FINAL, 0x3945BC8, "row key is one u64", "cmp"), (TRACK_SIGN, 0x394566D, "row move: done 1, open 0", "mov"), (TRACK_FINAL, 0x3945E0E, "row move: done 1, open 0", "mov"),
            (TRACK_SIGN, 0x394550B, "new row: done 0, open 1", "mov"), (TRACK_FINAL, 0x3945CB9, "new row: done 0, open 1", "mov"), (PRUNE, 0x3942ACF, "split at the action epoch", "call"), (DRAIN, 0x3BE50F4, "removed key stored in the output", "mov"), (COMPARE, 0x3369E05, "length compare", "cmp"), (COMPARE, 0x336A2DE, "epoch echo compare", "cmp"))


def key_rows(image, table):
    rows = []
    for target, va, text, op in KEY_ROWS:
        row = next((item for item in table[target] if item.va == va), None)
        if row is None or row.op != op:
            raise EvidenceError("row %#x" % va)
        rows.append(("%#x" % target, "%#x" % va, row.data.hex(), op, text))
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


def stack_argument_reads(image):
    """Rows of the signature tracker that read its stack argument, the literal 1 of the caller."""
    table = decode_range(image, *image.exact_fde(TRACK_SIGN))
    frame = 0x228 + 6 * 8 + 8
    return sum(1 for row in table for operand in (row.a, row.b) if operand and operand[0] == "m" and operand[1] == RSP and operand[4] == frame)


# Scenario name prefixes run against the edits of each function; the generated runs stay out to bound the time.
FOCUS = {WRAP_SIGN: ("sign_ok", "sign_outsider", "sign_hash", "sign_chain", "sign_set_empty", "sign_set_both", "sign_stake_at", "sign_set_lookup", "sign_set_echo", "sign_mismatch_last"), WRAP_FINAL: ("final_three", "final_outsider", "final_set_empty", "final_set_both", "final_stake_at", "final_set_differs", "final_set_lookup"),
         ARM_SIGN: ("sign_",), ARM_FINAL: ("final_",), AMOUNTS: ("sign_stake", "sign_nonce", "sign_reference", "wide_stake", "wide_action_two", "final_stake", "final_nonce"), COMPARE: ("sign_set", "wide_action", "final_set"),
         TRACK_SIGN: ("track_sign", "sign_one", "sign_quorum", "sign_repeat", "sign_after", "sign_two", "sign_nonce_order", "no_trim", "prune_voted"), TRACK_FINAL: ("track_final", "final_one", "final_repeat", "final_map", "final_three", "final_two", "final_row"),
         QUORUM_SIGN: ("sign_quorum", "sign_exact", "track_sign"), PRUNE: ("prune_", "final_prunes", "final_keeps"), DRAIN: ("prune_",), ROW_DROP: ("prune_",), COLLECT: ("prune_",)}
FULL = (WRAP_SIGN, WRAP_FINAL, ARM_SIGN, ARM_FINAL, COMPARE, PRUNE)


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
        for va, kind, patch in edits_for(image, table[target], seen, target in FULL):
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
SURVIVORS = ((WRAP_SIGN, "class: tail of a copied record or a stub argument"), (WRAP_FINAL, "class: tail of a copied record or a stub argument"), (ARM_SIGN, "class: copy of a dropped record or a stub argument"), (ARM_FINAL, "class: copy of a dropped record or a stub argument"),
             (AMOUNTS, "class: tree walk step for a deeper tree"), (COMPARE, "class: tree walk step for a deeper tree or a copied error tail"), (TRACK_SIGN, LOOP), (TRACK_FINAL, LOOP), (QUORUM_SIGN, "class: second tree iterator, which is empty"),
             (PRUNE, "class: iterator word read only by the real walk of an empty remainder"), (DRAIN, "class: copied value word or a walk word of the dying iterator"), (ROW_DROP, "class: second tree iterator, which is empty"), (COLLECT, "class: capacity arithmetic for sizes the fixtures do not reach"))


def analyse(image, mutate=True, vectors=200):
    harness = Harness(image)
    scenarios = named_scenarios()
    named = check_all(harness, scenarios)
    check_all(harness, vector_scenarios(vectors))
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for target in TARGETS}
    through = slot_sites(image, (SLOT_ARM_SIGN, SLOT_ARM_FINAL, SLOT_AMOUNTS, SLOT_SET, SLOT_REQUEST, SLOT_RECOVER, SLOT_VOTER, SLOT_MEMBER))
    result = dict(table=table, named=named, scenarios=scenarios, vector_count=vectors, unreached=unreached, slots=slot_rows(image, through), sites=site_rows(image, through), copies=copy_rows(image), limits=limit_rows(image), notes=note_rows(image),
                  fields=field_rows(image), statuses=status_rows(image), layouts=layout_rows(), stack_reads=stack_argument_reads(image), keys=key_rows(image, table))
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
    tsv("wrapper-copies.tsv", ("wrapper", "copy", "bytes", "instructions", "wrapper_instructions", "rows_differing", "first_differing_rows"), result["copies"])
    tsv("limits.tsv", ("at", "bytes", "limit_hex", "limit", "is_i64_max_over_10", "compares"), result["limits"])
    tsv("row-count-note.tsv", ("function", "compare_at", "take_count_at", "take_call", "free_call", "rows_after_take"), result["notes"])
    tsv("fields.tsv", ("key_at", "field_at", "key", "offset"), result["fields"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("node-layouts.tsv", ("tree", "key_at", "key_size", "value_at", "value_size", "parent_at", "parent_index_at", "count_at", "leaf_size"), result["layouts"])
    tsv("key-rows.tsv", ("function", "at", "bytes", "operation", "note"), result["keys"])
    tsv("scenarios.tsv", ("scenario", "operations", "outcome"), [(scenario.name, " ".join(op.kind for op in scenario.ops), describe(trace)) for scenario, trace in result["named"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(TARGETS), "instructions": sum(len(result["table"][target]) for target in TARGETS),
        "named_scenarios": len(result["scenarios"]), "named_operations": sum(len(scenario.ops) for scenario in result["scenarios"]), "vector_scenarios": result["vector_count"],
        "reads_of_tracker_stack_argument": result["stack_reads"], "unreached_rows": sum(len(rows) for rows in result["unreached"].values()),
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
