#!/usr/bin/env python3
"""Reconstruct the node #115 funding premium body 0x44d9060 from the ELF bytes and prove it against a written rule list.

The body takes the output record, the funding owner object, an asset id, the oracle word, the book and the perp metadata. It checks the asset
against the metadata (dex index and local index), reads the size-decimals byte, scales the oracle, picks the impact notional (per-asset
override or default), asks the book for the two impact prices, forms either an impact-gap premium or a mid premium, divides it by 100 for
assets in the hl-only set and clamps it to a band. The real bytes of the body run in a small x86-64 evaluator; the hash 0x47172c0, the
probe 0x3ed2180, the book walk 0x46a6370 and the panic and once slots are recording stubs. A separately written bit level rule list predicts
every output word and every stub call, named wrong readings must be refused, and every reached condition, immediate and field displacement of
the body is edited. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/funding_premium115.py --out <dir>
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

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

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
        if rela["size"] % 24:
            raise EvidenceError("truncated RELA section")
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
        for marker in ("/l1/", "/library/", "/z_vendor/"):
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
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd",
                  (0x14, True): "punpcklqdq", (0x59, True): "mulpd", (0x5F, True): "maxpd"}
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
            if op in ("addsd", "divsd", "subsd", "mulsd"):
                self.set_low(row.a[1], sse_arith(op[:3], self.low(row.a), self.low(row.b)))
                return
            if op == "minsd":
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
        elif op in ("addpd", "divpd", "mulpd", "maxpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                if op == "maxpd":
                    lanes.append(to_bits(one if one > two else two))
                else:
                    lanes.append(sse_arith({"addpd": "add", "divpd": "div", "mulpd": "mul"}[op], to_bits(one), to_bits(two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target not in (2, 5):
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                x, y = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                if (x <= y) if row.target == 2 else not x < y:
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




def sse_arith(op, a, b):
    """Scalar double add/sub/mul/div on raw bits with the x86 NaN rules: the first NaN operand wins and is quieted, a new NaN is the indefinite value."""
    quiet = 1 << 51
    for bits in (a, b):
        if (bits >> 52) & 0x7FF == 0x7FF and bits & ((1 << 52) - 1):
            return bits | quiet
    x, y = to_float(a), to_float(b)
    if op == "add":
        r = x + y
    elif op == "sub":
        r = x - y
    elif op == "mul":
        r = x * y
    else:
        r = fdiv(x, y)
    return 0xFFF8000000000000 if r != r else to_bits(r)


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


# ---------------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------------
# Subject: the funding premium body and the stubs around it.

PREMIUM = 0x44D9060
RATE_BODY = 0x44D8590                  # sibling body (previous packet); only its owner-field accesses are compared here
HASH = 0x47172C0
FIND = 0x3ED2180
IMPACT = 0x46A6370
SLOT_LOCAL = 0x64DF830                 # panic: asset does not belong to the metadata
SLOT_DECIMALS = 0x64DF848              # panic: 6 - size decimals underflows
SLOT_BOUNDS = 0x64DF620                # panic: index map entry out of range
SLOT_ONCE = 0x64DF9F0                  # std Once slow path
LOC_LOCAL = 0x64768A8
LOC_DECIMALS = 0x6478258
LOC_BOUNDS = 0x6493B30
ONCE_WORD = 0x64F01D8
ONCE_CLOSURE_A, ONCE_CLOSURE_B, ONCE_CLOSURE_C = 0x63FE250, 0x63FE278, 0x64F01C0
MARK_BASE = 0x7700000000

OUT = HEAP_BASE + 0x100
OUT_SENTINEL = (0x6B6B6B6B6B6B6B6B, 0x6C6C6C6C6C6C6C6C, 0x6D6D6D6D6D6D6D6D)
BOOK = HEAP_BASE + 0x200
SELF = HEAP_BASE + 0x1000
SELF_SIZE = 0x170
META = HEAP_BASE + 0x1200
META_SIZE = 0x60
ROWS = HEAP_BASE + 0x1300
ARENA = HEAP_BASE + 0x2000
USED = 0x8000
SIDE_FIRST, SIDE_SECOND = 0xA8, 0xC8

# tracker (owner) fields read by the body
T_ENTRIES, T_COUNT, T_HASH_A, T_HASH_B, T_DEFAULT, T_ROOT, T_HEIGHT, T_FLAG = 0x08, 0x10, 0x38, 0x40, 0x148, 0x150, 0x158, 0x168
# metadata fields
M_ROWS, M_COUNT, M_DEX = 0x08, 0x10, 0x50
ROW_STRIDE, ROW_DECIMALS = 0x20, 0x1D

CONSTANTS = (
    (0x7BB520, "scale_table", 56), (0x459490, "half", 8), (0x459420, "negative_half", 8), (0x459498, "hundred", 8),
    (0x458DC8, "negative_one", 8), (0x4559C0, "sign_mask", 16), (0x450180, "abs_mask", 16), (0x455220, "finite_limit", 16),
    (0x451960, "half_pair", 16), (0x451210, "convert_high_a", 16), (0x450170, "convert_bias_a", 16),
    (0x456790, "convert_low_mask", 16), (0x454DC0, "convert_low_or", 16), (0x452030, "convert_high_or", 16), (0x452040, "convert_bias_b", 16),
)


def constant_bits(image):
    out = {}
    for va, name, size in CONSTANTS:
        at = image.offset(va)
        out[name] = bytes(image.blob[at:at + size])
    return out


def scale_of(k, index):
    if index < 0:
        return 10.0 ** index
    return to_float(int.from_bytes(k["scale_table"][8 * index:8 * index + 8], "little"))


def one(k, name):
    return to_float(int.from_bytes(k[name][:8], "little"))


def word(k, name):
    return int.from_bytes(k[name][:8], "little")


# --- written rule list (no instruction decoding) -------------------------------------------------------------------------------

class Case:
    __slots__ = ("name", "asset", "oracle", "dex", "count", "decimals", "flag", "default", "overrides", "bad_index", "hl_set",
                 "height", "chunks", "impact", "once_word", "stale")

    def __init__(self, name, asset, oracle, dex, count, decimals, flag, default, overrides, impact, hl_set=(), bad_index=False,
                 height=0, chunks=None, once_word=0, stale=False):
        self.name, self.asset, self.oracle, self.dex, self.count, self.decimals, self.flag = name, asset, oracle, dex, count, decimals, flag
        self.default, self.overrides, self.impact, self.hl_set = default, overrides, impact, tuple(sorted(hl_set))
        self.bad_index, self.height, self.chunks, self.once_word = bad_index, height, chunks, once_word
        self.stale = stale


def hash_of(key):
    return (key * 0x9E3779B97F4A7C15 + 0x1234) & MASK[8]


def spec_premium(case, k, flags=frozenset()):
    """Return (outcome, log): outcome is ("panic", why) or ("ret", w0, w1, w2) with the three output words after the call."""
    log = []
    dex, local = divmod(case.asset, 10000)
    limit_ok = local <= case.count if "local_check_le" in flags else local < case.count
    if "dex_not_checked" in flags:
        belongs = limit_ok
    else:
        belongs = limit_ok and dex == case.dex
    if not belongs:
        return ("panic", "local %#x" % LOC_LOCAL), log
    decimals = case.decimals
    if decimals >= (8 if "decimals_limit_8" in flags else 7):
        return ("panic", "decimals %#x" % LOC_DECIMALS), log
    scale = 1e6 if "decimals_unused" in flags else scale_of(k, 6 - decimals)
    oracle_int = case.oracle
    if "oracle_signed" in flags and oracle_int >> 63:
        oracle_int -= 1 << 64
    oracle = float(oracle_int) / scale
    none = ("ret", OUT_SENTINEL[0], 0, OUT_SENTINEL[2])
    if oracle == 0.0:
        if case.once_word or "once_always" in flags:
            log.append(("once", ONCE_WORD))
        if "oracle_zero_is_zero_premium" in flags:
            return ("ret", 0, 0, OUT_SENTINEL[2]), log
        return none, log
    # impact notional: per-asset override else default
    notional = case.default
    table = case.overrides
    if table and "override_ignored" not in flags:
        if len(table) == 1 or "first_entry_only" in flags:
            if table[0][0] == case.asset:
                notional = table[0][1]
        else:
            log.append(("hash", case.asset))
            log.append(("find", case.asset))
            if case.bad_index:
                return ("panic", "bounds %d of %d" % (len(table), len(table))), log
            for key, value in table:
                if key == case.asset:
                    notional = value
                    break
    if "override_zero_uses_default" in flags and notional == 0:
        notional = case.default
    first = case.impact[0]
    second = case.impact[1]
    if "sides_swapped" in flags:
        first, second = second, first
    log.append(("impact", SIDE_FIRST, notional))
    if not ("second_skipped_when_first_zero" in flags and first == 0):
        log.append(("impact", SIDE_SECOND, notional))
    if first == 0 or second == 0:
        if "none_clears_all_words" in flags:
            return ("ret", 0, 0, 0), log
        return none, log
    first_f, second_f = float(first) / scale, float(second) / scale
    binance = bool(case.flag) != ("flag_inverted" in flags)
    if binance:
        up = first_f - oracle
        down = -(second_f - oracle)
        if "binance_no_floor" not in flags:
            up = up if up > 0.0 else 0.0
            down = down if down > 0.0 else 0.0
        premium = (up - down) / oracle
    else:
        limit = to_float(int.from_bytes(k["finite_limit"][:8], "little"))
        if abs(first_f) <= limit and abs(second_f) <= limit:
            mid = (first_f + second_f) * one(k, "half")
        else:
            mid = first_f * one(k, "half") + second_f * one(k, "half")
        if "mid_not_halved" in flags:
            mid = first_f + second_f
        if "mid_minus_oracle_first" in flags:
            premium = (mid - oracle) / oracle
        else:
            premium = mid / oracle + one(k, "negative_one")
    member = case.asset in case.hl_set
    if "hl_only_ignored_on_binance" in flags and binance:
        member = False
    divisor = 10.0 if "hl_divisor_10" in flags else one(k, "hundred")
    low, high = one(k, "negative_half"), one(k, "half")
    if "clamp_wider" in flags:
        low, high = -1.0, 1.0
    if "hl_after_clamp" in flags:
        premium = clamp_value(premium, low, high, "no_clamp" in flags)
        if member:
            premium = premium / divisor
    else:
        if member and "hl_divide_skipped" not in flags:
            premium = premium / divisor
        premium = clamp_value(premium, low, high, "no_clamp" in flags)
    words = (to_bits(premium), first, second)
    if "words_swapped" in flags:
        words = (words[0], second, first)
    return ("ret",) + words, log


def clamp_value(value, low, high, off):
    if off or value != value or abs(value) == math.inf:
        return value
    if low > value:
        value = low
    if high < value:
        value = high
    return value


VARIANTS = (
    "mid_minus_oracle_first", "hl_after_clamp", "hl_divide_skipped", "no_clamp", "clamp_wider", "oracle_zero_is_zero_premium",
    "decimals_unused", "flag_inverted", "binance_no_floor", "sides_swapped", "second_skipped_when_first_zero", "override_ignored",
    "override_zero_uses_default", "first_entry_only", "words_swapped", "none_clears_all_words", "dex_not_checked", "local_check_le",
    "decimals_limit_8", "hl_divisor_10", "oracle_signed", "mid_not_halved", "hl_only_ignored_on_binance", "once_always",
)


# --- evaluator harness ---------------------------------------------------------------------------------------------------------

class Arena:
    def __init__(self, memory):
        self.memory, self.top = memory, ARENA

    def alloc(self, size):
        at = self.top
        self.top = (self.top + size + 15) & ~15
        if self.top > HEAP_BASE + USED:
            raise Halt("arena exhausted")
        return at


def split_tree(sorted_items, height, chunks):
    """Shape of a B-tree set of the given height: (separators, child shapes), or (items, None) for a leaf."""
    if height == 0:
        return sorted_items, None
    parts = max(2, min(len(sorted_items) + 1, chunks.pop(0) if chunks else 3))
    size = max(1, (len(sorted_items) - (parts - 1)) // parts)
    children, seps, at = [], [], 0
    for index in range(parts):
        last = index == parts - 1
        take = len(sorted_items) - at if last else min(size, max(0, len(sorted_items) - at - (parts - 1 - index)))
        children.append(split_tree(sorted_items[at:at + take], height - 1, chunks))
        at += take
        if not last and at < len(sorted_items):
            seps.append(sorted_items[at])
            at += 1
    return seps, children


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.calls[HASH] = self.on_hash
        machine.calls[FIND] = self.on_find
        machine.calls[IMPACT] = self.on_impact
        statics = machine.memory.statics
        for slot, hook in ((SLOT_LOCAL, self.on_local), (SLOT_DECIMALS, self.on_decimals), (SLOT_BOUNDS, self.on_bounds),
                           (SLOT_ONCE, self.on_once)):
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.case, self.log = None, []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_hash(self, machine):
        regs, mem = machine.regs, machine.memory
        self.expect(regs[RDI] == mem.read(SELF + T_HASH_A, 8) and regs[RSI] == mem.read(SELF + T_HASH_B, 8), "hasher words")
        self.expect(regs[RDX] == self.case.asset, "hash key")
        self.log.append(("hash", regs[RDX]))
        regs[RAX] = hash_of(regs[RDX])

    def on_find(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == SELF, "probe table")
        self.expect(regs[RSI] == hash_of(self.case.asset), "probe hash")
        key = machine.memory.read(regs[RDX], 8)
        self.expect(key == self.case.asset, "probe key")
        self.log.append(("find", key))
        table = self.case.overrides
        found = [index for index, (stored, _) in enumerate(table) if stored == key]
        if self.case.bad_index:
            regs[RAX], regs[RDX] = 1, len(table)
        elif found:
            regs[RAX], regs[RDX] = 1, found[0]
        else:
            regs[RAX], regs[RDX] = 0, 0
        machine.keep_rdx = True

    def on_impact(self, machine):
        regs, mem = machine.regs, machine.memory
        self.expect(regs[RDI] == BOOK, "book argument")
        side = regs[RDX] - BOOK
        self.expect(side in (SIDE_FIRST, SIDE_SECOND), "book side")
        notional = mem.read(regs[RSI], 8)
        self.log.append(("impact", side, notional))
        regs[RAX] = self.case.impact[0 if side == SIDE_FIRST else 1]

    def on_local(self, machine):
        self.expect(machine.regs[RDI] == LOC_LOCAL, "local panic location")
        raise Panicked("local %#x" % LOC_LOCAL)

    def on_decimals(self, machine):
        self.expect(machine.regs[RDI] == LOC_DECIMALS, "decimals panic location")
        raise Panicked("decimals %#x" % LOC_DECIMALS)

    def on_bounds(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == LOC_BOUNDS, "bounds panic location")
        raise Panicked("bounds %d of %d" % (regs[RDI], regs[RSI]))

    def on_once(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == ONCE_WORD and regs[RSI] & MASK[4] == 1, "once arguments")
        self.expect(regs[RCX] == ONCE_CLOSURE_A and regs[R8] == ONCE_CLOSURE_B, "once closure tables")
        inner = machine.memory.read(regs[RDX], 8)
        self.expect(machine.memory.read(inner, 8) == ONCE_CLOSURE_C, "once closure chain")
        self.log.append(("once", regs[RDI]))

    def build_tree(self, arena, shape, height):
        memory = self.machine.memory
        keys, children = shape
        node = arena.alloc(0xD0)
        memory.put_bytes(node, bytes(0xD0 * [0xC3]))
        for index, key in enumerate(keys):
            memory.write(node + 8 + 8 * index, 8, key)
        if self.case.stale and len(keys) < 11:
            memory.write(node + 8 + 8 * len(keys), 8, self.case.asset)      # stale slot past the length: never a member
        memory.write(node + 0x62, 2, len(keys))
        if children is not None:
            for index, child in enumerate(children):
                memory.write(node + 0x68 + 8 * index, 8, self.build_tree(arena, child, height - 1))
        return node

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.statics[ONCE_WORD] = case.once_word
        memory.put_bytes(HEAP_BASE, bytes((index * 29 + 5) & 0xFF for index in range(0x1000)))
        memory.put_bytes(SELF, bytes((0x37 + 3 * index) & 0xFF for index in range(SELF_SIZE)))
        memory.put_bytes(META, bytes((0x91 + 5 * index) & 0xFF for index in range(META_SIZE)))
        for index, value in enumerate(OUT_SENTINEL):
            memory.write(OUT + 8 * index, 8, value)
        self.case, self.log = case, []
        arena = Arena(memory)
        table = case.overrides
        ptr = arena.alloc(24 * max(1, len(table)) + 16)
        for index, (key, value) in enumerate(table):
            memory.write(ptr + 24 * index, 8, 0x5A5A000000000000 + index)
            memory.write(ptr + 24 * index + 8, 8, key)
            memory.write(ptr + 24 * index + 16, 8, value)
        memory.write(SELF + T_ENTRIES, 8, ptr)
        memory.write(SELF + T_COUNT, 8, len(table))
        memory.write(SELF + T_HASH_A, 8, 0x0F0F0F0F00000001)
        memory.write(SELF + T_HASH_B, 8, 0x7070707000000002)
        memory.write(SELF + T_DEFAULT, 8, case.default)
        memory.write(SELF + T_FLAG, 1, case.flag)
        if case.hl_set:
            shape = split_tree(list(case.hl_set), case.height, list(case.chunks or ()))
            memory.write(SELF + T_ROOT, 8, self.build_tree(arena, shape, case.height))
            memory.write(SELF + T_HEIGHT, 8, case.height)
        else:
            memory.write(SELF + T_ROOT, 8, 0)
            memory.write(SELF + T_HEIGHT, 8, 0x77)
        memory.write(META + M_COUNT, 8, case.count)
        memory.write(META + M_DEX, 8, case.dex)
        local = case.asset % 10000
        rows = arena.alloc(ROW_STRIDE * min(max(case.count, 1), 40) + 32)
        memory.write(META + M_ROWS, 8, rows)
        for index in range(min(case.count, 40)):
            memory.put_bytes(rows + ROW_STRIDE * index, bytes((0x40 + index + 7 * j) & 0x7F for j in range(ROW_STRIDE)))
        if local < min(case.count, 40):
            memory.write(rows + ROW_STRIDE * local + ROW_DECIMALS, 1, case.decimals)
        elif local == 0 and case.count == 0:
            pass
        memory.put_bytes(BOOK, bytes((0x11 + index) & 0xFF for index in range(0x100)))
        return bytes(memory.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        try:
            outcome = self.drive(case)
        except Panicked as panic:
            outcome = ("panic", str(panic))
        after = bytes(machine.memory.heap[:USED])
        window = slice(OUT - HEAP_BASE, OUT - HEAP_BASE + 24)
        if after[:window.start] + after[window.stop:] != before[:window.start] + before[window.stop:]:
            raise Halt("the body wrote outside the output record")
        return before, (outcome, self.log)

    def drive(self, case):
        machine = self.machine
        returned = machine.run(PREMIUM, {RDI: OUT, RSI: SELF, RDX: case.asset, RCX: case.oracle, R8: BOOK, R9: META})
        if returned != OUT:
            raise Halt("returned pointer is not the output record")
        mem = machine.memory
        return ("ret",) + tuple(mem.read(OUT + 8 * index, 8) for index in range(3))


# --- case generation ----------------------------------------------------------------------------------------------------------------

def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11


U64_SPECIAL = (0, 1, 2, 3, 999999, 1000000, 1000001, (1 << 53) - 1, 1 << 53, (1 << 53) + 1, (1 << 63) - 1, 1 << 63, (1 << 63) + 1,
               (1 << 64) - 1, 12345678901234567, 250000, 5000000)


def draw_u64(stream, special_rate=5):
    pick = next(stream) % 100
    if pick < special_rate * 5:
        return U64_SPECIAL[next(stream) % len(U64_SPECIAL)]
    bits = 1 + next(stream) % 64
    return next(stream) % (1 << bits)


def near(stream, oracle, scale_digits):
    """An impact price close to the oracle in raw units, above or below, sometimes exactly equal."""
    base = max(oracle, 1)
    delta = next(stream) % (base // 50 + 3)
    pick = next(stream) % 5
    if pick == 0:
        return base
    value = base + delta if pick in (1, 2) else max(0, base - delta)
    return min(value, MASK[8])


def named_cases():
    big = (1 << 64) - 1
    mk = Case
    return [
        mk("mid-basic", 20007, 1000000, 2, 9, 1, 0, 100000000, [], (1010000, 1020000)),
        mk("binance-basic", 20007, 1000000, 2, 9, 1, 1, 100000000, [], (1010000, 1020000)),
        mk("oracle-zero-once-zero", 20007, 0, 2, 9, 1, 0, 5, [], (1, 1)),
        mk("oracle-zero-once-live", 20007, 0, 2, 9, 1, 0, 5, [], (1, 1), once_word=3),
        mk("dex-mismatch", 20007, 1000000, 3, 9, 1, 0, 5, [], (1, 1)),
        mk("local-equals-count", 20009, 1000000, 2, 9, 1, 0, 5, [], (1, 1)),
        mk("decimals-seven", 20007, 1000000, 2, 9, 7, 0, 5, [], (1, 1)),
        mk("hl-only-large-gap", 20007, 1000000, 2, 9, 1, 0, 5, [], (1500000, 1500000), hl_set=[20007]),
        mk("clamp-high", 20007, 1000, 2, 9, 6, 0, 5, [], (big, big)),
        mk("clamp-low-binance", 20007, 1000000, 2, 9, 0, 1, 5, [], (1, 1)),
        mk("first-zero", 20007, 1000000, 2, 9, 2, 0, 5, [], (0, 7)),
        mk("second-zero", 20007, 1000000, 2, 9, 2, 0, 5, [], (7, 0)),
        mk("override-one-match", 20007, 1000000, 2, 9, 3, 0, 5, [(20007, 77)], (1010000, 990000)),
        mk("override-one-miss", 20007, 1000000, 2, 9, 3, 0, 5, [(20008, 77)], (1010000, 990000)),
        mk("override-many-found-last", 20007, 1000000, 2, 9, 3, 1, 5, [(1, 11), (2, 22), (20007, 77)], (1010000, 990000)),
        mk("override-many-miss", 20007, 1000000, 2, 9, 3, 1, 5, [(1, 11), (2, 22), (3, 33)], (1010000, 990000)),
        mk("override-bad-index", 20007, 1000000, 2, 9, 3, 1, 5, [(1, 11), (2, 22)], (1010000, 990000), bad_index=True),
        mk("stale-key-past-length", 20007, 1000000, 2, 9, 1, 0, 5, [], (1500000, 1500000), hl_set=[1, 2, 3], stale=True),
        mk("max-asset", big, 1000000, big // 10000, 1700, 3, 0, 5, [], (1, 1)),
    ]


def random_cases(count, seed=0xA11CE5ED):
    stream = lcg(seed)
    for index in range(count):
        r = lambda n: next(stream) % n
        dex = draw_u64(stream, 3) % (1 << 40) if r(4) == 0 else r(30)
        total = 1 + r(24) if r(8) else 0
        local = r(max(total, 1)) if total else r(10)
        asset = dex * 10000 + local
        shape = r(12)
        if shape == 0:
            dex_meta = dex + 1 + r(3)
        elif shape == 1 and total:
            local = total + r(5)
            asset = dex * 10000 + local
            dex_meta = dex
        else:
            dex_meta = dex
        decimals = 7 + r(3) if r(11) == 0 else r(7)
        oracle = draw_u64(stream)
        if r(15) == 0:
            oracle = 0
        flag = r(2) if r(9) else 2 + r(250)
        default = draw_u64(stream, 3)
        size = r(6)
        table = []
        used = set()
        while len(table) < size:
            key = draw_u64(stream, 2) if r(3) else asset + 1 + r(5)
            if key not in used and key != asset:
                used.add(key)
                table.append((key, draw_u64(stream, 3)))
        if size and r(10) < 5:
            hit = r(size)
            table[hit] = (asset, table[hit][1])
        bad = size >= 2 and r(18) == 0
        if r(5) == 0:
            first, second = draw_u64(stream), draw_u64(stream)
        else:
            first, second = near(stream, oracle if oracle else 1000, decimals), near(stream, oracle if oracle else 1000, decimals)
        if r(14) == 0:
            first = 0
        if r(14) == 0:
            second = 0
        members = []
        height, chunks = 0, None
        n = r(4) and r(31)
        if n:
            seen = set()
            while len(members) < n:
                key = asset + 1 + r(40) if r(2) else draw_u64(stream, 2)
                if key != asset and key not in seen:
                    seen.add(key)
                    members.append(key)
            if r(5) < 2:
                members[r(len(members))] = asset
            height = 0 if n <= 11 else 1 if n <= 24 else 2
            if n > 6 and r(4) == 0:
                height = min(2, height + 1)
            if height:
                chunks = [2 + r(4) for _ in range(5)]
        once_word = 0 if r(3) else 1 + r(255)
        stale = r(6) == 0
        yield Case("r%d" % index, asset, oracle, dex_meta, total, decimals, flag, default, table, (first, second), members, bad, height,
                   chunks, once_word, stale)


def digest(outcome, log):
    return hashlib.sha256(repr((outcome, log)).encode()).hexdigest()[:16]


def hexbits(value):
    return "0x%016x" % value


def run_case(harness, case):
    harness.machine.seen = set()
    try:
        _, (got, log) = harness.run(case)
    except (Halt, EvidenceError, IndexError, KeyError, ValueError, OverflowError, struct.error) as problem:
        got, log = ("halt", type(problem).__name__), []
    return got, log


def check_stream(harness, cases, k, variants=(), keep=0, hits=None):
    """One real run per case, compared with the rule list and every named deviation; only the sample rows are kept."""
    stats = {"cases": 0, "mismatches": 0, "first_mismatch": None, "kinds": collections.Counter()}
    caught = {name: [0, None] for name in variants}
    rows = []
    for index, case in enumerate(cases):
        got, log = run_case(harness, case)
        expected, expected_log = spec_premium(case, k)
        stats["cases"] += 1
        arm = expected[0] if expected[0] == "panic" else "none" if expected[2] == 0 else "premium"
        stats["kinds"][(case.flag and "binance" or "mid", arm if arm != "panic" else expected[1].split()[0])] += 1
        if (got, log) != (expected, expected_log):
            stats["mismatches"] += 1
            if stats["first_mismatch"] is None:
                stats["first_mismatch"] = (index, case.name, got, expected)
        for name in variants:
            if spec_premium(case, k, frozenset((name,))) != (got, log):
                caught[name][0] += 1
                if caught[name][1] is None:
                    caught[name][1] = index
        if hits is not None:
            hits.update(harness.machine.seen)
        if keep and index % keep == 0:
            detail = hexbits(expected[1]) if expected[0] == "ret" else expected[1]
            rows.append((index, case.name, case.asset, case.decimals, int(bool(case.flag)), arm, detail, len(harness.machine.seen),
                         digest(got, log)))
    return stats, caught, rows


# --- byte level controls --------------------------------------------------------------------------------------------------------------

def mutants_of(image, reached):
    """One edit for every reached conditional jump, immediate and structure field displacement of the body."""
    out = []
    start, end = image.exact_fde(PREMIUM)
    for row in decode_range(image, start, end):
        if row.va not in reached:
            continue
        data = row.data
        if row.op == "jcc":
            at = 0 if 0x70 <= data[0] <= 0x7F else 1
            out.append((row.va, "condition", row.va + at, data[at], data[at] ^ 1))
            continue
        if row.imm_at is not None and row.imm_size in (1, 4) and row.op not in ("call", "jmp"):
            out.append((row.va, "immediate", row.va + row.imm_at, data[row.imm_at], data[row.imm_at] ^ 1))
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] is not None and 0x10 <= abs(operand[4]) < 0x200:
                disp = operand[4]
                packed = struct.pack("<i", disp) if abs(disp) >= 128 else struct.pack("<b", disp)
                spot = bytes(data).find(packed)
                if spot >= 0 and bytes(data).count(packed) == 1:
                    out.append((row.va, "displacement", row.va + spot, data[spot], data[spot] ^ 8))
    return out


def run_mutants(image, mutants, cases, k):
    rows = []
    for va, kind, at, old, new in mutants:
        harness = Harness(image, {at: new})
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        killed, first = False, ""
        for index, case in enumerate(cases):
            got, log = run_case(harness, case)
            if (got, log) != spec_premium(case, k):
                killed, first = True, "%d" % index
                break
        rows.append((va, kind, at, old, new, killed, first))
    return rows


def structural_controls(image, harness, k, cases):
    """Each entry: (name, detected, how)."""
    out = []

    def raises(name, thunk, *errors):
        try:
            thunk()
        except errors or (EvidenceError,) as problem:
            out.append((name, True, type(problem).__name__))
            return
        out.append((name, False, "no error"))

    raises("wrong image digest", lambda: load_image(BINARY, "0" * 64), EvidenceError)
    raises("mid-function address is not an FDE start", lambda: image.exact_fde(PREMIUM + 1), EvidenceError)
    raises("address in a NOBITS section has no file bytes", lambda: image.offset(image.named[".bss"]["address"] + 8), EvidenceError)
    raises("decoder refuses a window that ends inside the body", lambda: decode_range(image, PREMIUM, image.exact_fde(PREMIUM)[1] - 1), EvidenceError)
    raises("truncated section table", lambda: Image(bytes(image.blob[:48])), Exception)

    wide = next(case for case in cases if len(case.overrides) >= 2 and not case.bad_index and spec_premium(case, k)[0][0] == "ret"
                and spec_premium(case, k)[0][2] != 0)
    stripped = Harness(image)
    del stripped.machine.calls[HASH]
    raises("hash call without a model", lambda: stripped.run(wide), Halt)
    stripped = Harness(image)
    del stripped.machine.calls[IMPACT]
    raises("book walk call without a model", lambda: stripped.run(wide), Halt)
    trapped = Harness(image, {PREMIUM: 0xCC})
    raises("entry byte replaced by int3", lambda: trapped.run(wide), Halt)

    plain = Case("plain", 20007, 1000000, 2, 9, 1, 0, 100000000, [], (1010000, 1020000))
    changed = dict(k, half=int(to_bits(0.25)).to_bytes(8, "little"))
    out.append(("tampered half constant", run_case(harness, plain) != spec_premium(plain, changed), "mismatch"))
    changed = dict(k, negative_one=int(to_bits(-2.0)).to_bytes(8, "little"))
    out.append(("tampered negative-one constant", run_case(harness, plain) != spec_premium(plain, changed), "mismatch"))
    gap = Case("gap", 20007, 1000000, 2, 9, 1, 0, 5, [], (1500000, 1500000), hl_set=[20007])
    changed = dict(k, hundred=int(to_bits(10.0)).to_bytes(8, "little"))
    out.append(("tampered hundred constant", run_case(harness, gap) != spec_premium(gap, changed), "mismatch"))
    table = bytearray(k["scale_table"])
    table[40:48] = int(to_bits(99.0)).to_bytes(8, "little")
    changed = dict(k, scale_table=bytes(table))
    out.append(("tampered scale table entry", run_case(harness, plain) != spec_premium(plain, changed), "mismatch"))

    # out-of-range inputs the body must not accept silently
    wrong = Case("wrong", 20007, 1000000, 2, 9, 1, 0, 5, [], (1, 1))
    bad_local = Case("bad-local", 20007, 1000000, 2, 5, 1, 0, 5, [], (1, 1))
    out.append(("local index beyond the row count panics", run_case(harness, bad_local)[0][0] == "panic", "panic"))
    bad_decimals = Case("bad-decimals", 20007, 1000000, 2, 9, 9, 0, 5, [], (1, 1))
    out.append(("size decimals above six panics", run_case(harness, bad_decimals)[0][0] == "panic", "panic"))
    out.append(("rule list for the same input does not accept a wrong dex", spec_premium(Case("w", 20007, 1, 3, 9, 1, 0, 5, [], (1, 1)), k)[0][0] == "panic", "panic"))
    return out


# --- evidence tables -----------------------------------------------------------------------------------------------------------------

def constant_rows(image, k):
    refs = collections.defaultdict(list)
    wanted = [va for va, _, _ in CONSTANTS]
    for row in decode_range(image, *image.exact_fde(PREMIUM)):
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[4] in wanted:
                refs[operand[4]].append(row.va)
    rows = []
    for va, name, size in CONSTANTS:
        raw = k[name]
        shown = repr(to_float(int.from_bytes(raw[:8], "little"))) if name in ("half", "negative_half", "hundred", "negative_one") else ""
        rows.append((hexbits(va), name, size, raw.hex(), shown, " ".join("%#x" % r for r in refs[va])))
    return rows


def field_rows(image):
    """Every (base register, displacement) memory operand of the two funding bodies, so the shared owner layout is read from bytes."""
    names = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
    rows = collections.defaultdict(set)
    for entry, label in ((PREMIUM, "premium"), (RATE_BODY, "rate")):
        for row in decode_range(image, *image.exact_fde(entry)):
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] is not None and operand[1] != RSP and operand[2] is None and 0x08 <= operand[4] < 0x200:
                    rows[(label, names[operand[1]], operand[4])].add("%s/%d" % (row.op, row.width))
    return [(label, reg, "%#x" % disp, ";".join(sorted(ops))) for (label, reg, disp), ops in sorted(rows.items())]


def location_rows(image):
    relative = image.relative()
    rows = []
    for slot, role in ((LOC_LOCAL, "asset not in metadata"), (LOC_DECIMALS, "six minus size decimals"), (LOC_BOUNDS, "index map entry")):
        path, line, column = image.location(slot, relative)
        rows.append((hexbits(slot), role, path, line, column))
    return rows


def slot_rows(image):
    rows = []
    targets = (PREMIUM, RATE_BODY, HASH, FIND, IMPACT)
    for slot, kind, addend, _ in image.relocations():
        if kind == 8 and addend in targets:
            section = next((s["name"] for s in image.sections if s["address"] <= slot < s["address"] + s["size"] and s["type"] != 8), "?")
            rows.append((hexbits(slot), "%#x" % addend, section))
    return sorted(rows)


def direct_callers(image, targets):
    rows = []
    start_text, text = image.text_bytes()
    for target in targets:
        for at in range(len(text) - 5):
            if text[at] in (0xE8, 0xE9) and start_text + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
                owner = bisect.bisect_right(image.starts, start_text + at) - 1
                rows.append(("%#x" % (start_text + at), "call" if text[at] == 0xE8 else "jmp", "%#x" % target, "%#x" % image.starts[owner]))
    return sorted(rows)


def function_rows(image, hits):
    rows = []
    start, end = image.exact_fde(PREMIUM)
    for row in decode_range(image, start, end):
        rows.append(("%#x" % PREMIUM, "%#x" % row.va, row.size, row.op, hits.get(row.va, 0)))
    return rows


def analyse(count=14000, mutate=True, mutant_cases=2500, image=None):
    image = image or load_image()
    k = constant_bits(image)
    harness = Harness(image)
    reached = collections.Counter()
    cases = list(named_cases()) + list(random_cases(count))
    stats, caught, sample = check_stream(harness, cases, k, VARIANTS, keep=3, hits=reached)
    result = {"image": image, "k": k, "stats": stats, "caught": caught, "sample": sample, "reached": reached, "cases": len(cases)}
    result["structural"] = structural_controls(image, harness, k, cases)
    result["mutants"] = []
    if mutate:
        named = len(named_cases())
        picked = cases[:named] + cases[named::max(1, count // mutant_cases)]
        result["mutants"] = run_mutants(image, mutants_of(image, reached), picked, k)
    return result


def render(result):
    image, k, stats = result["image"], result["k"], result["stats"]
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(x) for x in row) for row in rows]) + "\n"

    tsv("constants.tsv", ("address", "role", "bytes", "raw", "double", "referenced_by"), constant_rows(image, k))
    tsv("owner-fields.tsv", ("body", "base_register", "displacement", "accesses"), field_rows(image))
    tsv("panic-locations.tsv", ("location", "role", "path", "line", "column"), location_rows(image))
    tsv("pointer-slots.tsv", ("slot", "addend", "section"), slot_rows(image))
    tsv("direct-callers.tsv", ("site", "kind", "target", "owner"), direct_callers(image, (PREMIUM, FIND, IMPACT)))
    tsv("function-rows.tsv", ("function", "address", "size", "op", "cases_reaching"), function_rows(image, result["reached"]))
    tsv("outcomes.tsv", ("formula", "outcome", "cases"), [(s, o, n) for (s, o), n in sorted(stats["kinds"].items())])
    tsv("cases-sample.tsv", ("index", "name", "asset", "decimals", "binance", "outcome", "detail", "distinct_insns", "digest"), result["sample"])
    tsv("variants.tsv", ("deviation", "cases_refused", "first_refusing_case"),
        [(name, n, "" if first is None else first) for name, (n, first) in sorted(result["caught"].items())])
    tsv("structural-controls.tsv", ("control", "detected", "how"), [(n, int(d), h) for n, d, h in result["structural"]])
    tsv("mutants.tsv", ("address", "kind", "edited_byte_at", "old", "new", "killed", "first_case"),
        [("%#x" % va, kind, "%#x" % at, old, new, int(killed), first) for va, kind, at, old, new, killed, first in result["mutants"]])
    controls = len(result["caught"]) + len(result["structural"])
    detected = sum(1 for n, first in result["caught"].values() if n) + sum(1 for _, d, _ in result["structural"] if d)
    killed = sum(1 for row in result["mutants"] if row[5])
    evidence = {
        "binary_sha256": SHA256, "function": "%#x" % PREMIUM,
        "stubbed": {"hash": "%#x" % HASH, "probe": "%#x" % FIND, "book_walk": "%#x" % IMPACT},
        "cases": stats["cases"], "mismatches": stats["mismatches"], "first_mismatch": stats["first_mismatch"],
        "instructions_reached": len(result["reached"]), "mutants": len(result["mutants"]), "mutants_killed": killed,
    }
    files["evidence.json"] = json.dumps(evidence, indent=1, sort_keys=True, default=str) + "\n"
    files["measure.json"] = json.dumps({"cases": stats["cases"], "negative_controls": controls, "negative_detected": detected,
                                        "mismatches": stats["mismatches"], "mutants": len(result["mutants"]), "mutants_killed": killed},
                                       indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--cases", type=int, default=14000)
    parser.add_argument("--no-mutants", action="store_true")
    args = parser.parse_args(argv)
    result = analyse(args.cases, not args.no_mutants)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = render(result)
    for name, text in files.items():
        (out / name).write_text(text)
    print(files["measure.json"], end="")
    return 0 if result["stats"]["mismatches"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
