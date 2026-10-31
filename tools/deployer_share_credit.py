#!/usr/bin/env python3
"""Pin the node #94 spot deployer share function 0x3c01bf0 from ELF bytes.

The function takes a token and an amount and returns the token deployer with a credit. A token listed
in SpotMeta.quote_token_to_status earns 0; any other token earns amount * (share / 100000) as f64,
truncated, when share / 100000 <= 1.01. The real bytes run over real table and B-tree layouts, a
separately written specification predicts every run, the factor gate is split over all u64 shares and
the rows after the multiply over all 2^64 f64 bit patterns. No objdump or readelf output is parsed and
the binary is never executed. Standard library only.

    python3 tools/deployer_share_credit.py --out <dir>
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








TARGET = 0x3C01BF0
SLOT_TARGET = 0x5774A90
SLOT_PANIC = 0x576E470
PANIC_LOCATION = 0x56F21F0
IMPORT_MARK = 0xF00000000000
TAIL_START = 0x3C01CEC
TAIL_END = 0x3C01D96
GATE_START = 0x3C01D56
GATE_END = 0x3C01D94
GATE_BRANCH = 0x3C01D8E
SPOT_META_SERIALIZER = 0x375A520
TOKEN_SERIALIZER = 0x375AD80
ONE_E5 = 0x20A9E8
ONE_POINT_ZERO_ONE = 0x20A528
CONSTANTS = (("positive infinity", 0x20A4B0, "000000000000f07f"), ("2^64", 0x20A510, "000000000000f043"),
             ("2^63", 0x20A7F0, "000000000000e043"), ("largest f64 below 2^64", 0x20A218, "ffffffffffffef43"),
             ("share denominator 100000.0", ONE_E5, "00000000006af840"), ("factor limit 1.01", ONE_POINT_ZERO_ONE, "295c8fc2f528f03f"),
             ("high word exponents for the u64 lanes", 0x203E80, "00003043000030450000000000000000"),
             ("lane offsets 2^52 and 2^84", 0x202EA0, "00000000000030430000000000003045"))

TOKEN_STRIDE = 0xE8
FIELD_SHARE = 0xA8
FIELD_DEPLOYER = 0xD2
LEN_FIELD = 0x188
PTR_FIELD = 0x180
ROOT_FIELD = 0x250
HEIGHT_FIELD = 0x258
ALIGNED_FIELD = 0x220
LEAF_SIZE = 0x70
INTERNAL_SIZE = 0xD0
KEYS_AT = 8
LEN_AT = 0x62
PARENT_INDEX_AT = 0x60
VALUES_AT = 0x64
EDGES_AT = 0x70
LEAF_CAPACITY = 11

META = HEAP_BASE + 0x1000
TOKENS = HEAP_BASE + 0x2000
NODES = HEAP_BASE + 0x8000
DECOY_NODE = HEAP_BASE + 0xF000
OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x30
USED = 0x10000
FILL = 0x77
ADDRESS = bytes(range(0x31, 0x45))
MAX_U64 = MASK[8]
TWO_64 = 2.0 ** 64
LIMIT_BELOW = 18446744073709549568.0


def fdiv(left, right):
    return left / right


def spec_saturate(value):
    """Truncate to u64: NaN and +inf give 0, negative gives 0, above the largest double below 2^64 gives MAX."""
    if value != value or value == math.inf:
        return 0
    if value < 0 or value == -math.inf:
        return 0
    if value > LIMIT_BELOW:
        return MAX_U64
    return int(value)


def spec_credit(share, amount):
    factor = fdiv(float(share), 100000.0)
    if not 1.01 >= factor:
        return 0
    return spec_saturate(factor * float(amount))


def spec_run(case):
    """Expected panic location, or the full 0x30 output bytes."""
    if case.token >= case.length:
        return ("panic", PANIC_LOCATION)
    out = bytearray([FILL]) * OUT_SIZE
    if not case.flag & 1:
        out[0:8] = bytes(8)
        return ("value", bytes(out))
    out[0:8] = struct.pack("<Q", 1)
    out[8:28] = ADDRESS
    credit = 0 if case.token in case.keys else spec_credit(case.share, case.amount)
    out[0x20:0x28] = struct.pack("<Q", credit)
    return ("value", bytes(out))


def reference_share(has_deployer, active, share, amount):
    """The published reference rule, written from its text: the aligned entry must be active."""
    if not has_deployer or not active:
        return 0
    return spec_credit(share, amount)


class Case:
    """One call: token index, amount, stored share, deployer byte, table length, status keys, tree shape."""

    def __init__(self, name="", **fields):
        self.name = name
        self.token = 5
        self.amount = 1000000000
        self.share = 30000
        self.flag = 1
        self.length = 40
        self.keys = (2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32)
        self.shape = "two"
        self.aligned = ()
        self.__dict__.update(fields)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        relative = image.relative()
        target = relative.get(SLOT_PANIC, IMPORT_MARK + SLOT_PANIC)
        machine.memory.statics[SLOT_PANIC] = target
        machine.slots = {target: self.on_panic}
        self.next_node = NODES

    def on_panic(self, machine):
        raise Panicked(machine.regs[RDI])

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def node(self, keys, children, stale, base=None):
        """One real node: live keys, the searched key left in the dead slots, a status byte per key."""
        size = INTERNAL_SIZE if children else LEAF_SIZE
        if base is None:
            base = self.next_node
            self.next_node += size
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * size)
        self.word(base, 0)
        for slot in range(LEAF_CAPACITY):
            self.word(base + KEYS_AT + 8 * slot, keys[slot] if slot < len(keys) else stale)
        self.word(base + PARENT_INDEX_AT, 0, 2)
        self.word(base + LEN_AT, len(keys), 2)
        for slot in range(LEAF_CAPACITY):
            self.word(base + VALUES_AT + slot, slot & 3, 1)
        if children:
            for slot in range(12):
                self.word(base + EDGES_AT + 8 * slot, children[slot] if slot < len(children) else 0x7777777777777777)
        return base

    def tree(self, keys, shape, stale):
        if shape == "none":
            return 0, 0x7777777777777777
        if shape == "empty":
            return self.node((), None, stale), 0
        if shape == "leaf":
            return self.node(keys, None, stale), 0
        step = max(1, min(LEAF_CAPACITY, (len(keys) + 2) // 3))
        cuts = keys[step::step + 1][:2]
        leaves = []
        low = 0
        for cut in cuts:
            high = keys.index(cut)
            leaves.append(self.node(keys[low:high], None, stale))
            low = high + 1
        leaves.append(self.node(keys[low:], None, stale))
        return self.node(cuts, leaves, stale), 1

    def install(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        self.next_node = NODES
        memory.put_bytes(META, bytes([FILL]) * 0x300)
        memory.put_bytes(TOKENS, bytes([FILL]) * (TOKEN_STRIDE * 40))
        memory.put_bytes(OUT, bytes([FILL]) * OUT_SIZE)
        self.word(META + PTR_FIELD, TOKENS)
        self.word(META + LEN_FIELD, case.length)
        # The neighbour map holds the opposite membership, so reading it instead changes every result.
        opposite = tuple(key for key in range(40) if key not in case.keys)[:LEAF_CAPACITY]
        decoy = (case.token,) if case.token not in case.keys else ()
        self.word(META + ALIGNED_FIELD, self.node(tuple(sorted(set(decoy + opposite[:10]))), None, 0x55, DECOY_NODE))
        self.word(META + ALIGNED_FIELD + 8, 0)
        root, height = self.tree(case.keys, case.shape, case.token)
        self.word(META + ROOT_FIELD, root)
        self.word(META + HEIGHT_FIELD, height)
        for index in range(min(case.length, 40)):
            record = TOKENS + index * TOKEN_STRIDE
            here = index == case.token
            self.word(record + FIELD_SHARE, case.share if here else 0x5555)
            self.word(record + FIELD_DEPLOYER, case.flag if here else case.flag ^ 1, 1)
            memory.put_bytes(record + FIELD_DEPLOYER + 1, ADDRESS if here else bytes(20))

    def run(self, case):
        self.install(case)
        memory = self.machine.memory
        before = bytes(memory.heap[:USED])
        try:
            value = self.machine.run(TARGET, {RDI: OUT, RSI: META, RDX: case.token, RCX: case.amount})
        except Panicked as error:
            return ("panic", error.args[0])
        if value != OUT:
            raise Halt("result register is not the output pointer")
        after = bytes(memory.heap[:USED])
        if before[:OUT - HEAP_BASE] != after[:OUT - HEAP_BASE] or before[OUT - HEAP_BASE + OUT_SIZE:] != after[OUT - HEAP_BASE + OUT_SIZE:]:
            raise Halt("write outside the output record")
        return ("value", after[OUT - HEAP_BASE:OUT - HEAP_BASE + OUT_SIZE])

    def tail(self, bits):
        """Run the rows after the multiply on one bit pattern; return the decision record and the result."""
        machine = self.machine
        machine.regs = [POISON] * 16
        machine.xmm = [POISON | POISON << 64] * 16
        machine.xmm[0] = bits | POISON << 64
        pc = TAIL_START
        trace = []
        for _ in range(100):
            if pc == TAIL_END:
                return tuple(trace), machine.regs[RCX]
            row = machine.cache.get(pc)
            if row is None:
                row = decode(machine.read_code, pc)
                machine.cache[pc] = row
            if row.op in ("jcc", "cmov"):
                trace.append((row.va, machine.condition(row.cc)))
            pc = machine.step(row)
            if row.op == "ucomisd":
                trace.append((row.va, machine.cf, machine.zf, machine.pf))
            elif row.op == "cvttsd2si":
                trace.append((row.va, machine.regs[row.a[1]] == 1 << 63))
        raise Halt("tail did not end")

    def gate(self, share):
        """Whole run with the amount at 1 for token not in the map; the branch taken at the factor compare."""
        machine = self.machine
        original = machine.step
        seen = []

        def step(row):
            if row.va == GATE_BRANCH:
                seen.append(machine.condition(row.cc))
            return original(row)

        machine.step = step
        try:
            self.run(Case(share=share, amount=1, keys=(), shape="none"))
        finally:
            del machine.step
        return tuple(seen)


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    # A renamed stack slot says little: one half of a spill can move and still agree with the other.
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None



FLOAT_SEEDS = ((0, 0x7FEFFFFFFFFFFFFF), (0x7FF0000000000000, 0x7FF0000000000000), (0x7FF0000000000001, (1 << 63) - 1),
               (1 << 63, (1 << 63) | 0x7FEFFFFFFFFFFFFF), ((1 << 63) | 0x7FF0000000000000, (1 << 63) | 0x7FF0000000000000),
               ((1 << 63) | 0x7FF0000000000001, MASK[8]))
INTERIOR_POINTS = 8


def interior(lo, hi):
    return [lo + (hi - lo) * index // (INTERIOR_POINTS + 1) for index in range(1, INTERIOR_POINTS + 1)]


def merge(found):
    found.sort(key=lambda row: row[0])
    merged = []
    for lo, hi, trace in found:
        if merged and merged[-1][2] == trace and merged[-1][1] + 1 == lo:
            merged[-1] = (merged[-1][0], hi, trace)
        else:
            merged.append((lo, hi, trace))
    return merged


def split(run, seed):
    """Halve a range until both ends share one decision record."""
    stack = [seed]
    found = []
    runs = 0
    while stack:
        lo, hi = stack.pop()
        first = run(lo)
        last = run(hi) if hi != lo else first
        runs += 2
        if first == last:
            found.append((lo, hi, first))
            continue
        middle = (lo + hi) // 2
        stack.append((middle + 1, hi))
        stack.append((lo, middle))
    return merge(found), runs


def refine_tail(harness):
    rows = []
    runs = 0
    for seed in FLOAT_SEEDS:
        pieces, count = split(lambda bits: harness.tail(bits)[0], seed)
        runs += count
        for lo, hi, trace in pieces:
            for bits in [lo, hi] + (interior(lo, hi) if hi > lo else []):
                got = harness.tail(bits)
                if got[0] != trace:
                    raise EvidenceError("interior point left its piece: %#x" % bits)
                if got[1] != spec_saturate(to_float(bits)):
                    raise EvidenceError("tail mismatch at %#x: %#x" % (bits, got[1]))
            rows.append((lo, hi, harness.tail(lo)[1], harness.tail(hi)[1], len(trace)))
    return rows, runs


def refine_gate(harness):
    pieces, runs = split(harness.gate, (0, MAX_U64))
    for lo, hi, trace in pieces:
        for share in interior(lo, hi):
            if harness.gate(share) != trace:
                raise EvidenceError("interior share left its piece: %#x" % share)
    return [(lo, hi, "admitted" if trace == (True,) else "refused") for lo, hi, trace in pieces], runs


def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state


ALL_KEYS = tuple(range(1, 34, 2))
NAMED = (
    Case("not in the status map, share 30000", keys=()),
    Case("no map root", keys=(), shape="none"),
    Case("empty root leaf", keys=(), shape="empty"),
    Case("deployer byte 0", flag=0),
    Case("deployer byte 0, token in the map", flag=0, keys=(5, 7)),
    Case("deployer byte 2: only bit 0 counts", flag=2),
    Case("deployer byte 3: only bit 0 counts", flag=3, keys=(1, 2)),
    Case("token at the last index", token=39, keys=()),
    Case("token one past the end", token=40),
    Case("token far past the end", token=1 << 63),
    Case("empty table", length=0, token=0),
    Case("token in the map, share 30000", keys=(5,), shape="leaf"),
    Case("token in the map, share 0", keys=(5,), shape="leaf", share=0),
    Case("token in the map, share above the limit", keys=(5,), shape="leaf", share=200000),
    Case("token in the map, amount 0", keys=(5,), shape="leaf", amount=0),
    Case("token first of a full leaf", token=5, keys=tuple(range(5, 16)), shape="leaf"),
    Case("token last of a full leaf", token=15, keys=tuple(range(5, 16)), shape="leaf"),
    Case("token above every key of a full leaf", token=16, keys=tuple(range(5, 16)), shape="leaf"),
    Case("token below every key of a full leaf", token=4, keys=tuple(range(5, 16)), shape="leaf"),
    Case("token at the root key", token=ALL_KEYS[6], keys=ALL_KEYS),
    Case("token at the second root key", token=ALL_KEYS[13], keys=ALL_KEYS),
    Case("token in the first leaf", token=1, keys=ALL_KEYS),
    Case("token in the middle leaf", token=ALL_KEYS[9], keys=ALL_KEYS),
    Case("token in the last leaf", token=33, keys=ALL_KEYS),
    Case("token between keys, first leaf", token=2, keys=ALL_KEYS),
    Case("token between keys, last leaf", token=32, keys=ALL_KEYS),
    Case("token above every key", token=38, keys=ALL_KEYS),
    Case("token 0 below every key", token=0, keys=ALL_KEYS),
    Case("share 0, not in the map", keys=(), share=0),
    Case("share 1, amount 99999: truncates to 0", keys=(), share=1, amount=99999),
    Case("share 100000: factor exactly 1", keys=(), share=100000),
    Case("share 101000: last admitted", keys=(), share=101000),
    Case("share 101001: first refused", keys=(), share=101001),
    Case("share u64 max: refused", keys=(), share=MAX_U64),
    Case("share 2^63: refused", keys=(), share=1 << 63),
    Case("amount 0", keys=(), amount=0),
    Case("amount u64 max, share 100000", keys=(), share=100000, amount=MAX_U64),
    Case("amount 2^64-1025, share 100000", keys=(), share=100000, amount=2 ** 64 - 1025),
    Case("amount 2^64-1024, share 100000", keys=(), share=100000, amount=2 ** 64 - 1024),
    Case("amount 2^63, share 1", keys=(), share=1, amount=1 << 63),
    Case("amount u64 max, share 101000: product above 2^64", keys=(), share=101000, amount=MAX_U64),
)


def vector_cases(count=2500):
    random = lcg(0x3C01BF0)
    shares = (0, 1, 2, 3, 7, 10, 100, 2500, 5000, 30000, 33333, 50000, 66667, 99999, 100000, 100001, 100999, 101000, 101001, 200000, 1 << 32,
              (1 << 53) + 1, 1 << 63, MAX_U64)
    cases = []
    for index in range(count):
        word = next(random)
        form = index % 5
        share = shares[next(random) % len(shares)] if form != 4 else next(random) >> (next(random) % 64)
        amount = word >> (next(random) % 64) if form else 100000 * (word >> 40)
        token = next(random) % 40
        keys = tuple(sorted({next(random) % 40 for _ in range(next(random) % 16)}))
        shape = "two" if len(keys) > 3 else "leaf"
        if len(keys) > 3 and len(keys[len(keys) // 3:]) > 11:
            shape = "two"
        cases.append(Case(token=token, amount=amount, share=share, keys=keys, shape=shape))
    return cases


def check_cases(harness, cases):
    rows = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("mismatch for %s" % (case.name or (case.token, case.amount, case.share, case.keys)))
        rows.append(got)
    return rows


def serde_fields(image, start):
    """Pairs of field offset and serde key in one serializer, from two fixed byte shapes."""
    low, high = image.exact_fde(start)
    base = image.offset(low)
    code = image.blob[base:base + (high - low)]
    found = []

    def key_from(blob, at, va):
        """lea key(%rip),%rsi at index `at`, then mov $len,%edx within the next 12 bytes."""
        target = va + 7 + struct.unpack_from("<i", blob, at + 3)[0]
        window = blob[at + 7:at + 19]
        mark = window.find(b"\xba")
        if mark < 0:
            return None
        size = struct.unpack_from("<I", window, mark + 1)[0]
        offset = image.offset(target)
        return target, bytes(image.blob[offset:offset + size]).decode("latin1")

    for mark in re.finditer(rb"\x48\x8d\x8b", code):
        at = mark.start()
        if code[at + 7:at + 10] == b"\x48\x8d\x35":
            pair = key_from(code, at + 7, low + at + 7)
            if pair:
                found.append((low + at, struct.unpack_from("<i", code, at + 3)[0], pair[0], pair[1]))
    # A key written before the field: lea key,%rsi; mov %rsp,%rdi; mov $len,%edx; call; ... lea field(%rbx),reg.
    for mark in re.finditer(rb"\x48\x8d\x35....\x48\x89\xe7\xba....\xe8", code, re.S):
        at = mark.start()
        if code[at - 7:at - 4] == b"\x48\x8d\x8b":
            continue
        pair = key_from(code, at, low + at)
        late =re.search(rb"\x48\x8d[\xb3\xbb]", code[at + 20:at + 56])
        if pair and late and b"\x48\x8d\x35" not in code[at + 20:at + 20 + late.start()]:
            found.append((low + at, struct.unpack_from("<i", code, at + 20 + late.start() + 3)[0], pair[0], pair[1]))
    for mark in re.finditer(rb"\x48\x8d\xb3", code):
        at = mark.start()
        tail = code[at + 7:at + 19]
        call = tail.find(b"\xe8")
        if call < 0:
            continue
        helper = low + at + 7 + call + 5 + struct.unpack_from("<i", tail, call + 1)[0]
        offset = image.offset(helper)
        head = bytes(image.blob[offset:offset + 0x30])
        lea = head.find(b"\x48\x8d\x35")
        if lea < 0:
            continue
        pair = key_from(head, lea, helper + lea)
        if pair:
            found.append((low + at, struct.unpack_from("<i", code, at + 3)[0], pair[0], pair[1]))
    return sorted(found)


def calls_through(image, slot):
    """call and jmp rows through one slot, by byte pattern."""
    base, text = image.text_bytes()
    found = []
    for pattern in (b"\xff\x15", b"\xff\x25"):
        at = text.find(pattern)
        while 0 <= at <= len(text) - 6:
            if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
                found.append(base + at)
            at = text.find(pattern, at + 1)
    return sorted(found)


def direct_to(image, target):
    base, text = image.text_bytes()
    found = []
    for opcode in (0xE8, 0xE9):
        pattern = bytes([opcode])
        at = text.find(pattern)
        while 0 <= at <= len(text) - 5:
            if base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
                found.append(base + at)
            at = text.find(pattern, at + 1)
    return sorted(found)


def pair_sites(image):
    """divsd 1e5(%rip),%xmm0 followed at once by movsd 1.01(%rip),%xmm1."""
    base, text = image.text_bytes()
    found = []
    at = text.find(b"\xf2\x0f\x5e\x05")
    while at >= 0:
        here = base + at
        if here + 8 + struct.unpack_from("<i", text, at + 4)[0] == ONE_E5 and text[at + 8:at + 12] == b"\xf2\x0f\x10\x0d":
            if here + 16 + struct.unpack_from("<i", text, at + 12)[0] == ONE_POINT_ZERO_ONE:
                found.append(here)
        at = text.find(b"\xf2\x0f\x5e\x05", at + 1)
    return found


def constant_rows(image):
    rows = []
    for name, va, expected in CONSTANTS:
        offset = image.offset(va)
        data = bytes(image.blob[offset:offset + len(expected) // 2])
        if data.hex() != expected:
            raise EvidenceError("constant changed at %#x" % va)
        rows.append((va, name, data.hex()))
    return rows


def edge_rows(harness):
    rows = []
    points = [(100000, 2 ** 64 - 1025), (100000, 2 ** 64 - 1024), (100000, MAX_U64), (101000, 0)]
    low, high = 1, MAX_U64
    while low < high:
        middle = (low + high) // 2
        if spec_credit(101000, middle) == MAX_U64:
            high = middle
        else:
            low = middle + 1
    points += [(101000, low - 1), (101000, low), (101000, 1000000), (100001, 1000000), (1, 99999), (1, 100000), (3, 33334), (99999, 3),
               (100000, 9007199254740993), (50000, 9007199254740993)]
    for share, amount in points:
        case = Case(keys=(), share=share, amount=amount)
        got = harness.run(case)
        credit = struct.unpack_from("<Q", got[1], 0x20)[0]
        if credit != spec_credit(share, amount):
            raise EvidenceError("edge mismatch")
        rows.append((share, amount, credit, amount * share // 100000, credit - amount * share // 100000, credit > amount))
    return rows


def rounding_rows():
    """Where the f64 product differs from the integer floor(amount*share/100000)."""
    random = lcg(0x20A9E8)
    tally = collections.Counter()
    first = {}
    for index in range(20000):
        share = 1 + next(random) % 101000
        amount = next(random) >> (next(random) % 64)
        credit = spec_credit(share, amount)
        exact = amount * share // 100000
        band = "below 2^53" if amount < 1 << 53 else "2^53 and above"
        key = (band, "lower" if credit < exact else "higher" if credit > exact else "same")
        tally[key] += 1
        first.setdefault(key, (share, amount, credit, exact))
    return [key + (tally[key],) + first[key] for key in sorted(tally)]


def reference_rows(harness):
    rows = []
    for member in (False, True):
        for active in (False, True):
            case = Case(keys=(5,) if member else (), shape="leaf" if member else "none")
            got = struct.unpack_from("<Q", harness.run(case)[1], 0x20)[0]
            want = reference_share(True, active, case.share, case.amount)
            rows.append((member, active, got, want, got == want))
    return rows


NO_CREDIT = "token in the status map: every path through this row gives a zero factor or a zero credit, so the result cannot change"
EXPECTED_SURVIVORS = {
    (0x3C01C9B, "immediate"): NO_CREDIT, (0x3C01C9B, "displacement"): NO_CREDIT, (0x3C01CA3, "condition"): NO_CREDIT,
    (0x3C01CAD, "operation"): NO_CREDIT, (0x3C01CAD, "constant"): NO_CREDIT, (0x3C01CB5, "constant"): NO_CREDIT, (0x3C01CC1, "condition"): NO_CREDIT,
    (0x3C01D2D, "immediate"): "sign mask 62 instead of 63: it differs only for x at or above 2^62, whose lane words have bit 0 clear, so the or gives the same word",
}


def edits_for(image, rows, seen):
    edits = []
    for row in rows:
        if row.va not in seen:
            continue
        data = image.blob[image.offset(row.va):image.offset(row.va) + row.size]
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("addsd", "mulsd", "divsd", "subsd"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            other = {0x58: 0x5C, 0x5C: 0x58, 0x59: 0x5E, 0x5E: 0x59}[data[at]]
            edits.append((row.va, "operation", {row.va + at: other}))
        if row.rip_at is not None and row.op not in ("calli", "lea"):
            edits.append((row.va, "constant", {row.va + row.rip_at: data[row.rip_at] ^ 8}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def mutant_cases():
    return list(NAMED) + vector_cases(160)


def first_failure(harness, cases):
    for case in cases:
        try:
            if harness.run(case) != spec_run(case):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError) as error:
            return case
    return None


def tail_killed(harness):
    points = (0, 1, to_bits(0.5), to_bits(1.0), to_bits(LIMIT_BELOW), to_bits(TWO_64), to_bits(2.0 ** 63), to_bits(2.0 ** 63 + 2048), to_bits(math.inf),
              to_bits(-math.inf), to_bits(-1.0), to_bits(-0.5), 0x7FF8000000000000, to_bits(1e300), to_bits(-1e300), 1 << 63)
    for bits in points:
        try:
            if harness.tail(bits)[1] != spec_saturate(to_float(bits)):
                return True
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError):
            return True
    return False


def run_mutants(image, rows, seen):
    results = []
    cases = mutant_cases()
    for va, kind, patch in edits_for(image, rows, seen):
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        if first_failure(harness, cases) is not None:
            results.append((va, kind, "killed", "whole run"))
        elif TAIL_START <= va < TAIL_END and tail_killed(harness):
            results.append((va, kind, "killed", "tail domain outside the reachable product"))
        else:
            results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True):
    low, high = image.exact_fde(TARGET)
    rows = decode_range(image, low, high)
    constants = constant_rows(image)
    relative = image.relative()
    if relative.get(SLOT_TARGET) != TARGET:
        raise EvidenceError("slot does not hold the function")
    callers = calls_through(image, SLOT_TARGET)
    direct = direct_to(image, TARGET)
    location = image.location(PANIC_LOCATION, relative)
    token_fields = serde_fields(image, TOKEN_SERIALIZER)
    meta_fields = serde_fields(image, SPOT_META_SERIALIZER)
    harness = Harness(image)
    named = list(NAMED)
    outcomes = check_cases(harness, named)
    vectors = vector_cases()
    check_cases(harness, vectors)
    tails, tail_runs = refine_tail(harness)
    gates, gate_runs = refine_gate(harness)
    edges = edge_rows(harness)
    reference = reference_rows(harness)
    seen = set(harness.machine.seen)
    unreached = [row.va for row in rows if row.va not in seen and row.op not in ("int3", "nop")]
    result = dict(fde=(low, high), rows=rows, constants=constants, callers=callers, direct=direct, location=location, token_fields=token_fields,
                  meta_fields=meta_fields, named=named, outcomes=outcomes, vector_count=len(vectors), tails=tails, tail_runs=tail_runs,
                  gates=gates, gate_runs=gate_runs, edges=edges, reference=reference, unreached=unreached, sites=pair_sites(image),
                  rounding=rounding_rows())
    if mutate:
        result["mutations"] = run_mutants(image, rows, seen)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(outcome):
    if outcome[0] == "panic":
        return "panic", "%#x" % outcome[1], "", ""
    data = outcome[1]
    word = struct.unpack_from("<Q", data, 0)[0]
    if word == 0:
        return "none", "", "", ""
    return "some", "", data[8:28].hex(), struct.unpack_from("<Q", data, 0x20)[0]


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("address", "size", "bytes", "operation"),
        [("%#x" % row.va, row.size, row.data.hex(), row.op) for row in result["rows"]])
    tsv("constants.tsv", ("address", "name", "bytes"), [("%#x" % a, n, b) for a, n, b in result["constants"]])
    tsv("serde-fields.tsv", ("struct", "row", "field_offset", "key_address", "key"),
        [("token", "%#x" % a, "%#x" % b, "%#x" % c, d) for a, b, c, d in result["token_fields"]]
        + [("spot_meta", "%#x" % a, "%#x" % b, "%#x" % c, d) for a, b, c, d in result["meta_fields"]])
    tsv("outcomes.tsv", ("case", "token", "amount", "share", "deployer_byte", "token_in_status_map", "result", "panic_location", "address", "credit"),
        [(case.name, case.token, case.amount, case.share, case.flag, case.token in case.keys) + describe(outcome)
         for case, outcome in zip(result["named"], result["outcomes"])])
    tsv("gate-pieces.tsv", ("share_lo", "share_hi", "decision"), result["gates"])
    tsv("tail-pieces.tsv", ("bits_lo", "bits_hi", "result_at_lo", "result_at_hi", "decisions"),
        [("%#x" % lo, "%#x" % hi, "%#x" % a, "%#x" % b, n) for lo, hi, a, b, n in result["tails"]])
    tsv("credit-edges.tsv", ("share", "amount", "credit", "integer_floor", "credit_minus_floor", "credit_above_amount"), result["edges"])
    tsv("rounding.tsv", ("amount_band", "credit_against_floor", "count", "first_share", "first_amount", "first_credit", "first_floor"), result["rounding"])
    tsv("reference-compare.tsv", ("token_in_status_map", "reference_aligned_active", "credit_real_bytes", "credit_reference_rule", "same"), result["reference"])
    tsv("pair-sites.tsv", ("divsd_row",), [("%#x" % va,) for va in result["sites"] if result["fde"][0] <= va < result["fde"][1]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "function": "%#x" % TARGET,
        "fde": ["%#x" % result["fde"][0], "%#x" % result["fde"][1], result["fde"][1] - result["fde"][0]],
        "instructions": len(result["rows"]), "unreached_rows": ["%#x" % va for va in result["unreached"]],
        "slot": "%#x" % SLOT_TARGET, "calls_through_slot": ["%#x" % va for va in result["callers"]],
        "direct_calls": ["%#x" % va for va in result["direct"]],
        "panic_location": "%s:%d:%d" % result["location"],
        "named_cases": len(result["named"]), "vector_cases": result["vector_count"],
        "tail_pieces": len(result["tails"]), "tail_runs": result["tail_runs"], "gate_pieces": len(result["gates"]), "gate_runs": result["gate_runs"],
        "pair_sites": len(result["sites"]),
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
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
