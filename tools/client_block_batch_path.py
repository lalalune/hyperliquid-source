#!/usr/bin/env python3
"""Run node #94 non-validator client block path from bytes: round gate, tx join, buffer, batch verify and commit proof.

The real rows of 0x4548050, 0x4360000, 0x4547690, two helpers and the round gate of the forward poll run under named
stubs, a separate rule list predicts every outcome, every state word and the ordered trace, and every reached
conditional row and immediate is mutated. Call sites, pins and slots come from fixed bytes. No objdump or readelf
output is parsed and the binary is never executed. Standard library only.

    python3 tools/client_block_batch_path.py --out <dir>
"""

import argparse
import bisect
import collections
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
STACK_SIZE = 0x10000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x80000
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
        elif byte not in (0x2E, 0xF0):
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
        if two in (0xB0, 0xB1):
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), 1 if two == 0xB0 else width)
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
        self.left = 0
        self.stops = frozenset()
        self.stopped = None

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
        self.left = self.step_limit
        self.loop(entry)
        if self.regs[RSP] != top + 8:
            raise Halt("unbalanced stack")
        for reg, value in saved.items():
            if self.regs[reg] != value:
                raise Halt("callee-saved register changed")
        return self.regs[RAX]

    def loop(self, entry):
        pc = entry
        cache = self.cache
        stops = self.stops
        while pc != RETURN_SENTINEL:
            if pc in stops:
                self.stopped = pc
                return
            self.left -= 1
            if self.left < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
            self.steps += 1
            pc = self.step(row)

    def call_real(self, entry, args):
        """Run a real function from inside a stub, on the stack below the caller."""
        regs, keep = list(self.regs), list(self.xmm)
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = (regs[RSP] - 0x1000) & ~15
        self.push(RETURN_SENTINEL)
        self.loop(entry)
        self.regs, self.xmm = regs, keep

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
            source = self.get(row.b, width)
            product = (source - (1 << (8 * width)) if source & SIGN[width] else source) * row.target
            self.put(row.a, width, product)
            self.of = self.cf = not -SIGN[width] <= product < SIGN[width]
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            product = (left - (1 << 64) if left & SIGN[8] else left) * (right - (1 << 64) if right & SIGN[8] else right)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
        elif op == "cmpxchg":
            current = self.get(row.a, width)
            self.add_sub(self.regs[RAX] & MASK[width], current, 0, width, True)
            if self.zf:
                self.put(row.a, width, self.get(row.b, width))
            else:
                self.put(("r", RAX), width, current)
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
SLOT_MEMCPY = 0x576DFE0
SLOT_ALLOC = 0x576DFD8
SLOT_DEALLOC = 0x576E010
SLOT_ALLOC_ERROR = 0x576DFB8
SLOT_LOG = 0x576E978
SLOT_PRINT = 0x576E968
SLOT_NOW = 0x576E8A0
SLOT_LOCK_SLOW = 0x576EF30
SLOT_UNLOCK_SLOW = 0x576EF38
SLOT_KECCAK_UPDATE = 0x576E1D8
SLOT_KECCAK_FINAL = 0x576E1E0
SLOT_ARC_BLOCK = 0x57730A8
SLOT_ARC_BODY = 0x57730B0
SLOT_ARC_TX = 0x5773008
SLOT_GROW = 0x5775098
SLOT_BUFFER = 0x5776668
SLOT_LAZY = 0x576F488
ONCE_WORDS = (0x577AB98, 0x577AB68, 0x577AB88, 0x577AB90, 0x577AB58)
JOIN = 0x4548050
BUFFER = 0x4360000
VERIFY_BATCH = 0x4547690
GROW = 0x454EE00
DROP_ITER = 0x44C6E70
POLL = 0x4759970
LAZY = 0x14385C0
VERIFY_SIGNED = 0x454B700
DIGEST = 0x454C050
VERIFY_QC = 0x4758D70
PUSH = 0x4B47B10
GROW_INNER = 0x454F420
DROP_VALUE = 0x4735B80
DROP_ERROR = 0x453EA10
GATE_ENTRY = 0x475A3AA
STOP_DROP = 0x475B407
STOP_DONE = 0x475B434
STOP_GAP = 0x475A680
STOP_BOOTSTRAP = 0x475AC83
STOPS = frozenset((STOP_DROP, STOP_DONE, STOP_GAP, STOP_BOOTSTRAP))
STATIC_FUNCTIONS = (JOIN, BUFFER, VERIFY_BATCH, GROW, DROP_ITER, POLL)
ROLES = {JOIN: "tx join: tx rows of a block from the local map", BUFFER: "buffer, batch verify, flush", VERIFY_BATCH: "batch rule and commit proof", GROW: "pending vector growth",
         DROP_ITER: "drop of the unsent rest of a flush", POLL: "forward_client_blocks poll body; only the round gate rows 0x475a3aa.. run here"}
STUBS = {VERIFY_SIGNED: "signed block check, covered by the block admission packet; outcome from the fixture", DIGEST: "block digest, fixture block key as the 32 byte word", VERIFY_QC: "QC check, covered by the block admission packet; outcome from the fixture",
         PUSH: "channel push, row recorded", GROW_INNER: "vector reallocation", DROP_VALUE: "drop of the unsent row, recorded", DROP_ERROR: "drop of a temporary error value, no effect"}
SLOT_STUBS = {SLOT_MEMCMP: "memcmp", SLOT_MEMCPY: "memcpy", SLOT_ALLOC: "fixture bump allocator", SLOT_DEALLOC: "dealloc, no effect", SLOT_ALLOC_ERROR: "panic, capacity overflow", SLOT_LOG: "warning log, format address recorded", SLOT_PRINT: "print to stderr, format address recorded",
              SLOT_NOW: "wall clock, fixture time", SLOT_LOCK_SLOW: "mutex slow lock", SLOT_UNLOCK_SLOW: "mutex slow unlock", SLOT_KECCAK_UPDATE: "hasher update; the rate and delimiter words are checked here, Keccak itself is not modelled", SLOT_KECCAK_FINAL: "hasher finish, SHA-256 of the input as the fixture digest",
              SLOT_ARC_BLOCK: "last block Arc gone, recorded", SLOT_ARC_BODY: "last body Arc gone, recorded", SLOT_ARC_TX: "last tx Arc gone, recorded"}
NONE_TAG = 1 << 63
OK_TAG = NONE_TAG + 0x2A
OUTER_OK = NONE_TAG + 0x40
OUTER_ROUND = NONE_TAG + 0x2C
OUTER_TEXT = NONE_TAG + 0x2A
OUTER_SEND = NONE_TAG + 0x35
JOIN_MISSING = NONE_TAG + 0x1C
STATE = HEAP_BASE + 0x1000
STATE_SIZE = 0x3000
CHANNEL = HEAP_BASE + 0x4000
SENDER = HEAP_BASE + 0x4400
LOCK = HEAP_BASE + 0x4440
WAKE_VTABLE = HEAP_BASE + 0x4480
INPUT = HEAP_BASE + 0x44C0
MAP = HEAP_BASE + 0x4500
OUT = HEAP_BASE + 0x4600
ITEM_COPY = HEAP_BASE + 0x4700
NODES = HEAP_BASE + 0x5000
USED = HEAP_SIZE
NODE_SIZE = 0x228
BLOCK_SIZE = 0x340
GATE_RSP = STACK_TOP - 0xA000
NOW = (20000, 7, 8)
PEER = 0x0102030405
BOOTSTRAP_NAME = 0x6FBECD
TIMEOUT_300 = 0x4072C00000000000
FLUSH_LIMIT = 100
MAX_ROUND = 0xFFFFFFFFFFFFFFFF


def word_bytes(value):
    return value.to_bytes(32, "big")


def tx_digest(data):
    return int.from_bytes(hashlib.sha256(data).digest(), "big")


class Child:
    """Commit proof: child block and the QC over it."""

    def __init__(self, key, round, qc_hash, proof_hash, bad=False, proof_bad=False, proof_round=7, qc_round=0):
        self.key, self.round, self.qc_hash, self.proof_hash, self.bad, self.proof_bad = key, round, qc_hash, proof_hash, bad, proof_bad
        self.proof_round, self.qc_round = proof_round, qc_round


class Block:
    def __init__(self, key, round, qc_round, qc_hash, hashes=(), time=(1, 2, 3), child=None, bad=False):
        self.key, self.round, self.qc_round, self.qc_hash, self.hashes, self.time, self.child, self.bad = key, round, qc_round, qc_hash, list(hashes), time, child, bad


class Step:
    """One client block off the stream: rows None means no body, the tx join reads the local map."""

    def __init__(self, block, rows=None, time=None):
        self.block, self.rows, self.time = block, rows, block.time if time is None else time


class Case:
    def __init__(self, name, steps, **extra):
        self.name, self.steps = name, list(steps)
        self.last_recv = 1000
        self.confirmed = 1000
        self.bootstrapped = False
        self.direct = False
        self.lock_held = False
        self.lock_parked = False
        self.closed_after = None
        self.waker = False
        self.tx_map = {}
        self.empty_batch = False
        self.batch = False
        self.__dict__.update(extra)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        hooks = {SLOT_MEMCMP: self.on_memcmp, SLOT_MEMCPY: self.on_memcpy, SLOT_ALLOC: self.on_alloc, SLOT_DEALLOC: self.on_nothing, SLOT_ALLOC_ERROR: self.on_alloc_error, SLOT_LOG: self.on_log, SLOT_PRINT: self.on_print, SLOT_NOW: self.on_now,
                 SLOT_LOCK_SLOW: self.on_lock_slow, SLOT_UNLOCK_SLOW: self.on_unlock_slow, SLOT_KECCAK_UPDATE: self.on_keccak_update, SLOT_KECCAK_FINAL: self.on_keccak_final, SLOT_ARC_BLOCK: self.on_arc_block, SLOT_ARC_BODY: self.on_arc_body, SLOT_ARC_TX: self.on_arc_tx}
        for index, (slot, hook) in enumerate(sorted(hooks.items())):
            mark = MARK_BASE + index * 16
            memory.statics[slot] = mark
            machine.slots[mark] = hook
        self.wake_mark = MARK_BASE + 0x1010
        machine.slots[self.wake_mark] = self.on_wake
        memory.statics[SLOT_GROW] = GROW
        memory.statics[SLOT_BUFFER] = BUFFER
        memory.statics[SLOT_LAZY] = LAZY
        for word in ONCE_WORDS:
            memory.statics[word] = 0
        machine.real = frozenset((JOIN, BUFFER, VERIFY_BATCH, GROW, DROP_ITER, LAZY))
        machine.calls = {VERIFY_SIGNED: self.on_signed, DIGEST: self.on_digest, VERIFY_QC: self.on_qc, PUSH: self.on_push, GROW_INNER: self.on_grow, DROP_VALUE: self.on_drop_value, DROP_ERROR: self.on_nothing}
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

    def on_alloc(self, machine):
        machine.regs[RAX] = self.alloc(machine.regs[RDI])

    def on_alloc_error(self, machine):
        raise Panicked("capacity overflow")

    def on_memcmp(self, machine):
        left = machine.memory.bytes_at(machine.regs[RDI], machine.regs[RDX])
        right = machine.memory.bytes_at(machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = 0 if left == right else (1 if left > right else MASK[4])

    def on_memcpy(self, machine):
        machine.memory.copy(machine.regs[RDI], machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = machine.regs[RDI]

    def on_log(self, machine):
        self.trace.append(("log", machine.regs[RSI]))

    def on_print(self, machine):
        self.trace.append(("print", machine.regs[RDI]))

    def on_now(self, machine):
        machine.memory.put_bytes(machine.regs[RDI], struct.pack("<iII", *NOW))

    def on_lock_slow(self, machine):
        self.expect(machine.regs[RDI] == LOCK + 0x10 and machine.regs[RDX] == 1000000000, "lock arguments")
        self.trace.append(("lock slow",))
        machine.memory.write(LOCK + 0x10, 1, 3 if self.case.lock_parked else 1)

    def on_unlock_slow(self, machine):
        self.expect(machine.regs[RDI] == LOCK + 0x10 and machine.regs[RSI] & 0xFF == 0, "unlock arguments")
        self.trace.append(("unlock slow",))
        machine.memory.write(LOCK + 0x10, 1, 0)

    def on_keccak_update(self, machine):
        memory = machine.memory
        state = machine.regs[RDI]
        self.expect(memory.read(state + 0xD0, 8) == 0x88 and memory.read(state + 0xD8, 2) == 1, "keccak rate and delimiter")
        self.expect(memory.bytes_at(state, 0xD0) == bytes(0xD0), "fresh hasher")
        self.pending_hash = memory.bytes_at(machine.regs[RSI], machine.regs[RDX])
        self.trace.append(("keccak", self.pending_hash))

    def on_keccak_final(self, machine):
        self.expect(machine.regs[RDX] == 32, "digest size")
        machine.memory.put_bytes(machine.regs[RSI], hashlib.sha256(self.pending_hash).digest())

    def object_of(self, slot):
        return self.machine.memory.read(slot, 8)

    def on_arc_block(self, machine):
        self.trace.append(("block gone", self.blocks[self.object_of(machine.regs[RDI])].key))

    def on_arc_body(self, machine):
        self.trace.append(("body gone", self.bodies[self.object_of(machine.regs[RDI])]))

    def on_arc_tx(self, machine):
        self.trace.append(("tx gone", self.txs[self.object_of(machine.regs[RDI])]))

    def on_wake(self, machine):
        self.expect(machine.regs[RDI] == 0x5A5A, "waker data")
        self.trace.append(("wake",))

    def on_signed(self, machine):
        memory = machine.memory
        out, at, table = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.expect(table == LOCK + 0x18 and memory.read(LOCK + 0x10, 1) & 1, "verifier table under its lock")
        block, child = self.signed.get(at, (None, None))
        self.expect(block is not None, "signed block address")
        self.trace.append(("signed", child.key if child else block.key))
        bad = child.bad if child else block.bad
        if bad:
            for index, word in enumerate(error_words(child.key if child else block.key)):
                memory.write(out + 8 * index, 8, word)
        else:
            memory.write(out, 8, OK_TAG)

    def on_digest(self, machine):
        memory = machine.memory
        out, query = machine.regs[RDI], machine.regs[RSI]
        self.expect(memory.read(query, 8) == 0, "digest variant 0")
        at = memory.read(query + 8, 8)
        block, child = self.signed.get(at, (None, None))
        self.expect(block is not None, "digest of a block")
        key = child.key if child else block.key
        self.trace.append(("digest", key))
        memory.put_bytes(out, word_bytes(key))

    def on_qc(self, machine):
        memory = machine.memory
        out, at, table = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.expect(table == LOCK + 0x18, "verifier table")
        child = self.proofs.get(at)
        self.expect(child is not None, "proof QC address")
        self.trace.append(("qc", child.key))
        if child.proof_bad:
            for index, word in enumerate(error_words(child.key + 1)):
                memory.write(out + 8 * index, 8, word)
        else:
            memory.write(out, 8, OK_TAG)

    def on_push(self, machine):
        memory = machine.memory
        self.expect(machine.regs[RDI] == CHANNEL + 0x80, "channel queue")
        at = machine.regs[RSI]
        block = self.blocks[memory.read(at, 8)]
        body = self.bodies[memory.read(at + 8, 8)]
        self.trace.append(("send", block.key, body, struct.unpack("<III", memory.bytes_at(at + 16, 12))))
        self.sends += 1
        if self.case.closed_after == self.sends:
            memory.write(CHANNEL + 0x1C0, 8, memory.read(CHANNEL + 0x1C0, 8) | 1)

    def on_drop_value(self, machine):
        self.trace.append(("unsent", self.blocks[machine.memory.read(machine.regs[RDI], 8)].key))

    def on_grow(self, machine):
        memory = machine.memory
        out, count, old, capacity, align, size = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX], machine.regs[R8], machine.regs[R9]
        self.expect(align == 8 and size == 0x20, "element layout")
        new = self.alloc(capacity * size)
        if count:
            memory.copy(new, old, count * size)
        memory.write(out, 8, 0)
        memory.write(out + 8, 8, new)
        self.trace.append(("grow", capacity))

    def set_block(self, memory, at, block):
        """Block record at at: tx hash vector, QC at +0x18, round +0x88, time +0x90."""
        hashes = self.alloc(32 * max(len(block.hashes), 1))
        for index, value in enumerate(block.hashes):
            memory.put_bytes(hashes + 32 * index, word_bytes(value))
        memory.write(at, 8, len(block.hashes))
        memory.write(at + 8, 8, hashes)
        memory.write(at + 0x10, 8, block.count if hasattr(block, "count") else len(block.hashes))
        memory.write(at + 0x40, 8, block.qc_round)
        memory.put_bytes(at + 0x48, word_bytes(block.qc_hash))
        memory.write(at + 0x88, 8, block.round)
        memory.put_bytes(at + 0x90, struct.pack("<III", *block.time))

    def make_block(self, block):
        memory = self.machine.memory
        at = self.alloc(BLOCK_SIZE)
        memory.write(at, 8, 1)
        memory.write(at + 8, 8, 1)
        self.set_block(memory, at + 0x10, block)
        self.blocks[at] = block
        self.signed[at + 0x10] = (block, None)
        child = block.child
        if child is None:
            memory.write(at + 0x108, 8, NONE_TAG)
        else:
            fields = Block(child.key, child.round, child.qc_round, child.qc_hash, [0x51])
            self.set_block(memory, at + 0x108, fields)
            memory.write(at + 0x200 + 0x28, 8, child.proof_round)
            memory.put_bytes(at + 0x230, word_bytes(child.proof_hash))
            self.signed[at + 0x108] = (block, child)
            self.proofs[at + 0x200] = child
        return at

    def make_tx(self, identity, data):
        memory = self.machine.memory
        bytes_at = self.alloc(max(len(data), 1))
        memory.put_bytes(bytes_at, data)
        at = self.alloc(0x28)
        memory.write(at, 8, 1)
        memory.write(at + 8, 8, 1)
        memory.write(at + 0x10, 8, len(data))
        memory.write(at + 0x18, 8, bytes_at)
        memory.write(at + 0x20, 8, len(data))
        self.txs[at] = identity
        return at

    def make_body(self, block, rows):
        memory = self.machine.memory
        table = self.alloc(0x28 * max(len(rows), 1))
        for index, (hash_value, data) in enumerate(rows):
            memory.put_bytes(table + 0x28 * index, word_bytes(hash_value))
            memory.write(table + 0x28 * index + 0x20, 8, self.make_tx(hash_value, data))
        at = self.alloc(0x28)
        memory.write(at, 8, 1)
        memory.write(at + 8, 8, 1)
        memory.write(at + 0x10, 8, len(rows))
        memory.write(at + 0x18, 8, table)
        memory.write(at + 0x20, 8, len(rows))
        self.bodies[at] = block.key
        return at

    def make_leaf(self, keys, values):
        memory = self.machine.memory
        at = self.alloc(NODE_SIZE)
        for index, key in enumerate(keys):
            memory.put_bytes(at + 32 * index, word_bytes(key))
            memory.write(at + 0x168 + 8 * index, 8, values[key])
        memory.write(at + 0x1C2, 2, len(keys))
        return at

    def make_map(self, case):
        """Local tx map at MAP: root at +0x20, height at +0x28; one or two levels."""
        memory = self.machine.memory
        keys = sorted(case.tx_map)
        values = {key: self.make_tx(key, case.tx_map[key]) for key in keys}
        self.map_values = values
        if not keys:
            memory.write(MAP + 0x20, 8, 0)
            memory.write(MAP + 0x28, 8, 0)
            return
        if len(keys) <= 11:
            memory.write(MAP + 0x20, 8, self.make_leaf(keys, values))
            memory.write(MAP + 0x28, 8, 0)
            return
        parts, tops = [], []
        rest = keys
        while rest:
            parts.append(rest[:5])
            if len(rest) > 5:
                tops.append(rest[5])
            rest = rest[6:]
        if len(parts) > len(tops) + 1 or not parts[-1]:
            parts = [part for part in parts if part]
        root = self.make_leaf(tops, values)
        for index, part in enumerate(parts):
            memory.write(root + 0x1C8 + 8 * index, 8, self.make_leaf(part, values))
        memory.write(MAP + 0x20, 8, root)
        memory.write(MAP + 0x28, 8, 1)

    def set_state(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        self.bump = NODES
        self.case = case
        self.trace = []
        self.blocks, self.bodies, self.txs, self.signed, self.proofs = {}, {}, {}, {}, {}
        self.sends = 0
        machine.seen_steps = 0
        memory.put_bytes(STATE, bytes(STATE_SIZE))
        memory.write(STATE, 8, 0)
        memory.write(STATE + 8, 8, 8)
        memory.write(STATE + 0x10, 8, 0)
        memory.write(STATE + 0xC8, 8, CHANNEL)
        memory.write(STATE + 0xD0, 8, SENDER)
        memory.write(STATE + 0xF0, 8, LOCK)
        memory.write(STATE + 0x108, 8, case.last_recv)
        memory.write(STATE + 0x110, 8, case.confirmed)
        memory.write(STATE + 0x118, 1, int(case.bootstrapped))
        memory.write(STATE + 0x25D, 1, 0xEE)
        memory.put_bytes(LOCK, bytes(0x40))
        memory.write(LOCK + 0x10, 1, 1 if case.lock_held else 0)
        memory.put_bytes(CHANNEL, bytes(0x400))
        memory.put_bytes(SENDER, bytes(0x40))
        if case.waker:
            memory.write(WAKE_VTABLE + 8, 8, self.wake_mark)
            memory.write(CHANNEL + 0x100, 8, WAKE_VTABLE)
            memory.write(CHANNEL + 0x108, 8, 0x5A5A)
        if case.closed_after == 0:
            memory.write(CHANNEL + 0x1C0, 8, 1)
        self.make_map(case)

    def run_join(self, step):
        machine = self.machine
        memory = machine.memory
        block_at = self.make_block(step.block)
        body_at = 0 if step.rows is None else self.make_body(step.block, step.rows)
        memory.write(INPUT, 8, block_at)
        memory.write(INPUT + 8, 8, body_at)
        memory.put_bytes(INPUT + 0x10, struct.pack("<III", *step.time))
        machine.run(JOIN, {RDI: OUT, RSI: INPUT, RDX: MAP})
        tag = memory.read(OUT, 8)
        if tag != OK_TAG:
            return None, ("err", tag - NONE_TAG, int.from_bytes(memory.bytes_at(OUT + 8, 32), "big"))
        body = memory.read(OUT + 0x10, 8)
        if body not in self.bodies:
            self.bodies[body] = step.block.key
            count = len(step.block.hashes)
            self.expect(memory.read(body, 8) == 1 and memory.read(body + 8, 8) == 1, "new Arc counts")
            self.expect(memory.read(body + 0x10, 8) == count and memory.read(body + 0x20, 8) == count, "new row vector")
            self.expect(count or memory.read(body + 0x18, 8) == 8, "empty row vector pointer")
        return (memory.read(OUT + 8, 8), body, memory.bytes_at(OUT + 0x18, 12)), None

    def put_item(self, at, item):
        memory = self.machine.memory
        memory.write(at, 8, item[0])
        memory.write(at + 8, 8, item[1])
        memory.put_bytes(at + 0x10, item[2])
        memory.write(at + 0x1C, 4, 0xC0C0C0C0)

    def run_gate(self, item):
        """Poll rows from the three way round compare on; the rows stop at the arm's exits."""
        machine = self.machine
        memory = machine.memory
        self.put_item(STATE + 0x1D8, item)
        machine.regs = [POISON] * 16
        machine.regs[RSP] = GATE_RSP
        machine.regs[R13] = STATE
        machine.regs[R12] = STATE + 0x1B8
        machine.regs[RAX] = STATE
        machine.regs[R14] = PEER
        machine.regs[R15] = NONE_TAG
        machine.regs[RBX] = POISON
        machine.stops = STOPS
        machine.left = machine.step_limit
        machine.loop(GATE_ENTRY)
        machine.stops = frozenset()
        stop = machine.stopped
        if stop == STOP_GAP:
            return ("gap",)
        if stop == STOP_BOOTSTRAP:
            start, end = memory.read(STATE + 0x218, 8), memory.read(STATE + 0x220, 8)
            self.expect(memory.read(STATE + 0x208, 8) == BOOTSTRAP_NAME and memory.read(STATE + 0x210, 8) == 14, "bootstrap name")
            self.expect(memory.read(STATE + 0xFC0, 8) == TIMEOUT_300, "bootstrap timeout")
            self.expect(memory.read(STATE + 0x250, 8) == STATE, "bootstrap state pointer")
            self.expect(memory.read(STATE + 0x25D, 1) == 0 and memory.read(STATE + 0x25E, 4) == PEER & MASK[4] and memory.read(STATE + 0x262, 1) == PEER >> 32, "bootstrap peer")
            return ("bootstrap", start, end)
        if stop == STOP_DROP:
            self.expect(machine.regs[R14] == OUTER_OK, "old block outcome")
            block_at = memory.read(STATE + 0x1B8, 8)
            return ("old", self.blocks[block_at].key)
        return self.outer_result(machine.regs[RSP] + 0xAC0, machine.regs[R14])

    def outer_result(self, at, tag):
        memory = self.machine.memory
        if tag == OUTER_OK:
            return ("ok",)
        if tag == OUTER_ROUND:
            return ("err", 0x2C, memory.read(at + 8, 8))
        if tag == OUTER_TEXT:
            return ("text", memory.bytes_at(memory.read(at + 0x10, 8), memory.read(at + 0x18, 8)).decode(), memory.read(at + 8, 8))
        if tag == OUTER_SEND:
            return ("err", 0x35)
        code = tag - NONE_TAG
        if code == 0x15:
            return ("err", code, memory.read(at + 8, 8), memory.read(at + 0x10, 8))
        if code == 0x16:
            return ("err", code, int.from_bytes(memory.bytes_at(at + 8, 32), "big"), int.from_bytes(memory.bytes_at(at + 0x28, 32), "big"))
        if code == 0x17:
            return ("err", code, int.from_bytes(memory.bytes_at(at + 8, 32), "big"))
        if code == 1:
            return ("err", code) + tuple(memory.read(at + 8 * index, 8) for index in range(1, 10))
        return ("err", code)

    def run_direct(self, item):
        machine = self.machine
        self.put_item(ITEM_COPY, item)
        machine.run(BUFFER, {RDI: OUT, RSI: STATE, RDX: ITEM_COPY})
        return self.outer_result(OUT, machine.memory.read(OUT, 8))

    def run_empty(self):
        machine = self.machine
        machine.run(VERIFY_BATCH, {RDI: OUT, RSI: STATE, RDX: 0, RCX: 0, R8: LOCK + 0x18})
        return self.outer_result(OUT, machine.memory.read(OUT, 8))

    def run_batch(self, case):
        """The verifier alone, for the two rules its only caller cannot reach."""
        machine = self.machine
        memory = machine.memory
        memory.write(LOCK + 0x10, 1, 1)
        table = self.alloc(32 * len(case.steps))
        for index, step in enumerate(case.steps):
            self.put_item(table + 32 * index, (self.make_block(step.block), self.make_body(step.block, step.rows), struct.pack("<III", *step.time)))
        machine.run(VERIFY_BATCH, {RDI: OUT, RSI: table, RDX: len(case.steps), RCX: case.confirmed, R8: LOCK + 0x18})
        if memory.read(OUT, 8) == OK_TAG:
            return ("verified",)
        return self.outer_result(OUT, memory.read(OUT, 8))

    def run(self, case):
        machine = self.machine
        self.set_state(case)
        machine.xmm = [POISON | POISON << 64] * 16
        results = []
        if case.batch:
            results.append(self.run_batch(case))
            return self.observe(results)
        try:
            if case.empty_batch:
                results.append(self.run_empty())
            for step in case.steps:
                item, failure = self.run_join(step)
                if failure:
                    results.append(failure)
                    break
                result = self.run_direct(item) if case.direct else self.run_gate(item)
                results.append(result)
                if result[0] not in ("ok", "old", "bootstrap"):
                    break
        except Panicked as error:
            results.append(("panic", str(error)))
        return self.observe(results)

    def observe(self, results):
        memory = self.machine.memory
        pending = []
        at = memory.read(STATE + 8, 8)
        for index in range(memory.read(STATE + 0x10, 8)):
            pending.append(self.blocks[memory.read(at + 32 * index, 8)].key)
        strong = {block.key: memory.read(at, 8) for at, block in sorted(self.blocks.items())}
        tx_strong = {key: memory.read(at, 8) for key, at in sorted(self.map_values.items())}
        return dict(results=results, trace=list(self.trace), last_recv=memory.read(STATE + 0x108, 8), confirmed=memory.read(STATE + 0x110, 8), bootstrapped=memory.read(STATE + 0x118, 1), pending=pending, capacity_word=memory.read(STATE, 8),
                    strong=strong, tx_strong=tx_strong, sender=memory.read(SENDER + 0x10, 8), channel=memory.read(CHANNEL + 0x1C0, 8), channel_flag=memory.read(CHANNEL + 0x110, 8), dangling=memory.read(STATE, 8) != 0 or memory.read(STATE + 8, 8) == 8, lock=memory.read(LOCK + 0x10, 1), wake_slot=memory.read(CHANNEL + 0x100, 8))


def error_words(key):
    return [NONE_TAG + 1] + [(key + index) & MASK[8] for index in range(1, 10)]


LOG_VERIFY_FAILED = 0x20249E
LOG_OLD_BLOCK = 0x1E8BB4
PRINT_SEND_FAILED = 0x1F58F8
TOO_MANY = "Too many unconfirmed blocks"
ROW_LIMIT = 0x333333333333333


def next_round(value):
    return MAX_ROUND if value == MAX_ROUND else value + 1


def spec_batch(pending, confirmed, trace):
    """Rule list of 0x4547690; pending rows are Spec rows. Returns the error tuple or None."""
    previous_round, previous_hash = confirmed, None
    for index, row in enumerate(pending):
        block = row.block
        if block.child is not None and index != len(pending) - 1:
            return ("err", 0x1A)
        if block.qc_round != previous_round:
            return ("err", 0x15, block.qc_round, previous_round)
        if previous_hash is not None and block.qc_hash != previous_hash:
            return ("err", 0x16, block.qc_hash, previous_hash)
        trace.append(("signed", block.key))
        if block.bad:
            return ("err", 1) + tuple(error_words(block.key)[1:])
        for hash_value, data in row.tx_rows:
            trace.append(("keccak", data))
            if tx_digest(data) != hash_value:
                return ("err", 0x17, hash_value)
        if [hash_value for hash_value, _ in row.tx_rows] != block.hashes:
            return ("err", 0x18)
        if row.time != block.time:
            return ("err", 0x19)
        previous_round = block.round
        trace.append(("digest", block.key))
        previous_hash = block.key
    last = pending[-1].block
    child = last.child
    if child is None:
        return ("err", 0x1B)
    trace.append(("digest", last.key))
    trace.append(("signed", child.key))
    if child.bad:
        return ("err", 1) + tuple(error_words(child.key)[1:])
    trace.append(("qc", child.key))
    if child.proof_bad:
        return ("err", 1) + tuple(error_words(child.key + 1)[1:])
    if child.qc_hash != last.key:
        return ("err", 0x1D)
    trace.append(("digest", child.key))
    if child.proof_hash != child.key:
        trace.append(("digest", child.key))
        return ("err", 0x1E)
    if child.round != next_round(last.round):
        return ("err", 0x1F)
    return None


class Row:
    def __init__(self, block, tx_rows, time):
        self.block, self.tx_rows, self.time = block, tx_rows, time


def drop_row(want, row):
    want["trace"].append(("block gone", row.block.key))
    want["strong"][row.block.key] = 0
    want["trace"].append(("body gone", row.block.key))


def spec_buffer(case, want, pending, row, grown):
    """Rule list of 0x4360000 for one row; returns the step result."""
    block, trace = row.block, want["trace"]
    if block.qc_round != want["last_recv"]:
        drop_row(want, row)
        return ("err", 0x2C, block.qc_round)
    want["last_recv"] = block.round
    if len(pending) == grown[0]:
        grown[0] = 4 if grown[0] * 2 < 5 else grown[0] * 2
        trace.append(("grow", grown[0]))
    pending.append(row)
    if block.child is None:
        if len(pending) > FLUSH_LIMIT:
            return ("text", TOO_MANY, 0x1B)
        return ("ok",)
    if want["lock_state"]:
        trace.append(("lock slow",))
        want["lock_state"] = False
    want["lock"] = 0
    error = spec_batch(pending, want["confirmed"], trace)
    if error:
        trace.append(("log", LOG_VERIFY_FAILED))
        if case.lock_parked:
            trace.append(("unlock slow",))
        return error
    if case.lock_parked:
        trace.append(("unlock slow",))
    want["confirmed"] = want["last_recv"]
    rows = list(pending)
    del pending[:]
    grown[0] = 0
    for index, item in enumerate(rows):
        if case.closed_after is not None and want["sent"] >= case.closed_after:
            trace.append(("unsent", item.block.key))
            trace.append(("print", PRINT_SEND_FAILED))
            for rest in rows[index + 1:]:
                drop_row(want, rest)
            return ("err", 0x35)
        want["sender"] += 1
        want["channel"] += 2
        trace.append(("send", item.block.key, item.block.key, item.time))
        want["sent"] += 1
        if case.closed_after == want["sent"]:
            want["channel"] += 1
        if want["wake"]:
            trace.append(("wake",))
            want["wake"] = False
    return ("ok",)


def spec_join(want, step, case):
    """Rule list of 0x4548050: Row, or the error tuple of the first hash missing from the local map."""
    if step.rows is not None:
        return Row(step.block, step.rows, step.time), None
    rows = []
    for hash_value in step.block.hashes:
        if hash_value not in case.tx_map:
            drop_row_join(want, step)
            return None, ("err", 0x1C, hash_value)
        rows.append((hash_value, case.tx_map[hash_value]))
        want["tx_strong"][hash_value] += 1
    return Row(step.block, rows, step.time), None


def drop_row_join(want, step):
    want["tx_strong"].update({key: 1 for key in want["tx_strong"]} if not want["tx_held"] else {})
    want["trace"].append(("block gone", step.block.key))
    want["strong"][step.block.key] = 0


def spec_run(case):
    """Separate rule list of the whole path: returns (outcome label, expected observation)."""
    want = dict(results=[], trace=[], last_recv=case.last_recv, confirmed=case.confirmed, bootstrapped=int(case.bootstrapped), strong={}, tx_strong={key: 1 for key in case.tx_map},
                sender=0, channel=1 if case.closed_after == 0 else 0, lock=int(case.lock_held), wake=case.waker, sent=0, lock_state=case.lock_held, tx_held=False)
    pending, grown = [], [0]
    label = "empty"
    if case.batch:
        rows = [Row(step.block, step.rows, step.time) for step in case.steps]
        want["strong"] = {step.block.key: 1 for step in case.steps}
        want["lock"] = 1
        error = spec_batch(rows, case.confirmed, want["trace"])
        want["results"].append(error or ("verified",))
        label = "check %#x" % error[1] if error else "verified"
        for name in ("wake", "sent", "lock_state", "tx_held"):
            del want[name]
        want.update(pending=[], capacity_word=0, wake_slot=0, channel_flag=0, dangling=True)
        return label, want
    if case.empty_batch:
        want["results"].append(("err", 0x14))
        label = "check 0x14"
    for step in case.steps:
        block = step.block
        want["strong"][block.key] = 1
        if step.rows is None and getattr(block, "count", 0) > ROW_LIMIT:
            want["results"].append(("panic", "capacity overflow"))
            label = "panic row limit"
            break
        held = dict(want["tx_strong"])
        row, failure = spec_join(want, step, case)
        if failure:
            want["tx_strong"] = held
            want["results"].append(failure)
            label = "check 0x1c"
            break
        if not case.direct:
            if block.qc_round < want["last_recv"]:
                want["trace"].append(("log", LOG_OLD_BLOCK))
                want["results"].append(("old", block.key))
                label = "old block"
                continue
            if block.qc_round > want["last_recv"]:
                if want["bootstrapped"]:
                    want["results"].append(("gap",))
                    label = "gap after start"
                    break
                want["results"].append(("bootstrap", next_round(want["last_recv"]), block.qc_round))
                label = "bootstrap"
                continue
            want["bootstrapped"] = 1
        result = spec_buffer(case, want, pending, row, grown)
        want["results"].append(result)
        if result[0] == "ok":
            label = "buffered" if pending else "flushed"
            continue
        label = "text too many" if result[0] == "text" else "check %#x" % result[1]
        break
    want["pending"] = [row.block.key for row in pending]
    want["capacity_word"] = grown[0]
    want["channel_flag"] = 0
    want["dangling"] = True
    want["wake_slot"] = 0 if case.waker and want["sent"] else (WAKE_VTABLE if case.waker else 0)
    for name in ("wake", "sent", "lock_state", "tx_held"):
        del want[name]
    return label, want


def same(got, want):
    return [key for key in want if got[key] != want[key]]


TIME = (1, 2, 3)
TX_A = b"tx one"
TX_B = b"second tx bytes"
HASH_A = tx_digest(TX_A)
HASH_B = tx_digest(TX_B)
GOOD_ROWS = [(HASH_A, TX_A), (HASH_B, TX_B)]


def ok_block(key=0xB1, round=1001, qc_round=1000, qc_hash=0x77, **extra):
    fields = dict(hashes=[HASH_A, HASH_B], time=TIME, child=None, bad=False)
    fields.update(extra)
    return Block(key, round, qc_round, qc_hash, fields["hashes"], fields["time"], fields["child"], fields["bad"])


def proof_for(block, **extra):
    fields = dict(key=block.key + 0x1000, round=block.round + 1, qc_hash=block.key, proof_hash=block.key + 0x1000)
    fields.update(extra)
    return Child(**fields)


def chain(count, start=1000, gap=1, **extra):
    """count linked blocks over confirmed round start; only the last has a proof when the keyword says so."""
    blocks = []
    round, previous = start, 0x77
    for index in range(count):
        block = ok_block(key=0xB1 + index, round=round + gap, qc_round=round, qc_hash=previous)
        blocks.append(block)
        round, previous = block.round, block.key
    if extra.get("proof", True) and blocks:
        blocks[-1].child = proof_for(blocks[-1])
    return blocks


def steps_of(blocks, rows=None):
    return [Step(block, list(GOOD_ROWS) if rows is None else rows) for block in blocks]


def named_cases():
    cases = [Case("one block with a proof flushes", steps_of(chain(1))),
             Case("three blocks flush on the third", steps_of(chain(3))),
             Case("no proof stays buffered", steps_of(chain(3, proof=False))),
             Case("round gaps inside a batch pass", steps_of(chain(3, gap=7))),
             Case("empty batch", [], empty_batch=True),
             Case("first block needs no hash link", steps_of(chain(1))),
             Case("one hundred unconfirmed pass", steps_of(chain(100, proof=False)), direct=True),
             Case("one hundred and one fail", steps_of(chain(101, proof=False)), direct=True),
             Case("a proof on block one hundred and one is read", steps_of(chain(101)), direct=True),
             Case("waker fires once", steps_of(chain(3)), waker=True),
             Case("held lock", steps_of(chain(2)), lock_held=True),
             Case("parked unlock", steps_of(chain(2)), lock_held=True, lock_parked=True),
             Case("channel closed at once", steps_of(chain(3)), closed_after=0),
             Case("channel closes after one", steps_of(chain(3)), closed_after=1),
             Case("channel closes after two", steps_of(chain(3)), closed_after=2),
             Case("two flushes in a row", steps_of(chain(2) + [ok_block(key=0xC1, round=1003, qc_round=1002, qc_hash=0xB2)])),
             ]
    early = chain(3)
    early[0].child = proof_for(early[0])
    cases.append(Case("batch alone: proof on an early block", steps_of(early), batch=True))
    early = chain(2)
    early[0].child = proof_for(early[0])
    early[1].child = None
    cases.append(Case("batch alone: proof only on an early block", steps_of(early), batch=True))
    cases.append(Case("batch alone: no proof", steps_of(chain(2, proof=False)), batch=True))
    cases.append(Case("batch alone: good", steps_of(chain(2)), batch=True))
    cases.append(Case("outer round mismatch", steps_of([ok_block(qc_round=999)]), direct=True))
    cases.append(Case("outer round over", steps_of([ok_block(qc_round=1001)]), direct=True))
    cases.append(Case("outer round second step", steps_of([chain(2, proof=False)[0], ok_block(key=0xB9, qc_round=2000)]), direct=True))
    cases.append(Case("gate old block", steps_of([ok_block(qc_round=999)]), bootstrapped=True))
    cases.append(Case("gate old block before start", steps_of([ok_block(qc_round=999)])))
    cases.append(Case("gate equal starts", steps_of(chain(1, proof=False))))
    cases.append(Case("gate gap after start", steps_of([ok_block(qc_round=1005)]), bootstrapped=True))
    cases.append(Case("gate gap of one after start", steps_of([ok_block(qc_round=1001)]), bootstrapped=True))
    cases.append(Case("gate gap before start asks bootstrap", steps_of([ok_block(qc_round=1005)])))
    cases.append(Case("gate gap of one before start", steps_of([ok_block(qc_round=1001)])))
    cases.append(Case("gate saturated bootstrap start", steps_of([ok_block(qc_round=MAX_ROUND, round=MAX_ROUND)]), last_recv=MAX_ROUND - 1))
    cases.append(Case("gate last round maximum equal", steps_of([ok_block(qc_round=MAX_ROUND, round=MAX_ROUND)]), last_recv=MAX_ROUND, confirmed=MAX_ROUND, bootstrapped=True))
    cases.append(Case("confirmed differs from last received", steps_of(chain(1)), confirmed=999))
    cases.append(Case("second block round mismatch", steps_of([ok_block(key=0xB1), ok_block(key=0xB2, round=1003, qc_round=1001, qc_hash=0xB1, child=None)])))
    block_a, block_b = ok_block(key=0xB1), ok_block(key=0xB2, round=1002, qc_round=1001, qc_hash=0xB0)
    block_b.child = proof_for(block_b)
    cases.append(Case("second block hash mismatch", steps_of([block_a, block_b])))
    bad_first = chain(2)
    bad_first[0].bad = True
    cases.append(Case("first block check fails", steps_of(bad_first)))
    bad_last = chain(2)
    bad_last[1].bad = True
    cases.append(Case("last block check fails", steps_of(bad_last)))
    early = chain(2)
    early[0].child = proof_for(early[0])
    cases.append(Case("early proof flushes alone", steps_of(early)))
    body = chain(1)
    cases.append(Case("tx bytes differ", [Step(body[0], [(HASH_A, TX_A), (HASH_B, b"other")])]))
    cases.append(Case("first tx bytes differ", [Step(chain(1)[0], [(HASH_A, b"other"), (HASH_B, TX_B)])]))
    cases.append(Case("row count short", [Step(chain(1)[0], [(HASH_A, TX_A)])]))
    cases.append(Case("row count long", [Step(chain(1)[0], GOOD_ROWS + [(tx_digest(b"3"), b"3")])]))
    cases.append(Case("row order differs", [Step(chain(1)[0], [(HASH_B, TX_B), (HASH_A, TX_A)])]))
    cases.append(Case("no rows no hashes", [Step(Block(0xB1, 1001, 1000, 0x77, [], TIME, Child(0x10B1, 1002, 0xB1, 0x10B1)), [])]))
    no_rows = chain(1)
    cases.append(Case("no rows some hashes", [Step(no_rows[0], [])]))
    for index, value in enumerate(((9, 2, 3), (1, 9, 3), (1, 2, 9))):
        cases.append(Case("time word %d differs" % index, [Step(chain(1)[0], list(GOOD_ROWS), value)]))
    for name, edit in (("child hash differs", dict(qc_hash=0x99)), ("child check fails", dict(bad=True)), ("proof QC check fails", dict(proof_bad=True)), ("proof QC hash differs", dict(proof_hash=0x98)),
                       ("child round skips", dict(round=1003)), ("child round repeats", dict(round=1001)), ("child round below", dict(round=1000))):
        block = ok_block()
        block.child = proof_for(block, **edit)
        cases.append(Case(name, steps_of([block])))
    for name, edit in (("child and QC fail, child first", dict(bad=True, proof_bad=True)), ("QC and hash fail, QC first", dict(proof_bad=True, qc_hash=0x99)), ("hash and proof hash fail, hash first", dict(qc_hash=0x99, proof_hash=0x98)), ("proof hash and round fail, proof hash first", dict(proof_hash=0x98, round=1007))):
        block = ok_block()
        block.child = proof_for(block, **edit)
        cases.append(Case(name, steps_of([block])))
    block = ok_block(round=MAX_ROUND)
    block.child = proof_for(block, round=MAX_ROUND)
    cases.append(Case("saturated child round passes", steps_of([block])))
    block = ok_block(round=MAX_ROUND)
    block.child = proof_for(block, round=0)
    cases.append(Case("wrapped child round fails", steps_of([block])))
    block = ok_block()
    block.child = proof_for(block)
    block.child.proof_round = 5
    block.child.qc_round = 77
    cases.append(Case("proof QC round and child QC round are not read", steps_of([block])))
    tx = {HASH_A: TX_A, HASH_B: TX_B}
    cases.append(Case("tx join from the local map", [Step(chain(1)[0])], tx_map=dict(tx)))
    cases.append(Case("tx join empty map", [Step(chain(1)[0])]))
    cases.append(Case("tx join first hash missing", [Step(chain(1)[0])], tx_map={HASH_B: TX_B}))
    cases.append(Case("tx join second hash missing", [Step(chain(1)[0])], tx_map={HASH_A: TX_A}))
    cases.append(Case("tx join no hashes", [Step(Block(0xB1, 1001, 1000, 0x77, [], TIME, Child(0x10B1, 1002, 0xB1, 0x10B1)))]))
    large = {tx_digest(b"t%d" % index): b"t%d" % index for index in range(30)}
    ordered = sorted(large)
    for pick in (0, 5, 6, 11, 17, 29):
        block = ok_block(hashes=[ordered[pick], ordered[(pick + 7) % 30]])
        block.child = proof_for(block)
        cases.append(Case("tx join two level map %d" % pick, [Step(block)], tx_map=dict(large)))
    block = ok_block(hashes=[ordered[3], 0x1234])
    block.child = proof_for(block)
    cases.append(Case("tx join two level map miss", [Step(block)], tx_map=dict(large)))
    block = ok_block(hashes=[HASH_A, HASH_B, HASH_A, 0x4321])
    cases.append(Case("tx join miss after three rows", [Step(block)], tx_map=dict(tx)))
    block = ok_block(hashes=[HASH_A, HASH_A])
    block.child = proof_for(block)
    cases.append(Case("tx join repeated hash", [Step(block)], tx_map=dict(tx)))
    block = ok_block(hashes=[HASH_A, HASH_B])
    block.child = proof_for(block)
    cases.append(Case("tx join does not read a given body", steps_of([block]), tx_map={HASH_A: b"map bytes differ"}))
    block = ok_block(hashes=[HASH_A])
    block.child = proof_for(block)
    cases.append(Case("map bytes under a hash are rechecked", [Step(block)], tx_map={HASH_A: b"map bytes differ"}))
    huge = ok_block(hashes=[])
    huge.count = 1 << 60
    cases.append(Case("hash count over the row limit", [Step(huge)]))
    return cases


def stream(seed):
    return hashlib.sha256(b"client blocks %d" % seed).digest()


def vector_cases(count):
    cases = []
    for seed in range(count):
        data = stream(seed)
        pick = iter(data)
        size = 1 + next(pick) % 4
        gap = 1 + next(pick) % 3
        blocks = chain(size, gap=gap, proof=next(pick) % 4 != 0)
        rows = [list(GOOD_ROWS) for _ in blocks]
        times = [TIME for _ in blocks]
        fault = next(pick) % 16
        at = next(pick) % size
        block = blocks[at]
        tail = blocks[-1]
        if fault == 0:
            block.qc_round += 1
        elif fault == 1:
            block.qc_hash ^= 1
        elif fault == 2:
            block.bad = True
        elif fault == 3:
            rows[at] = rows[at][:1]
        elif fault == 4:
            rows[at] = [(HASH_A, b"x"), (HASH_B, TX_B)]
        elif fault == 5:
            times[at] = (1, 2, 4)
        elif fault == 6 and at != size - 1:
            block.child = proof_for(block)
        elif fault == 7 and tail.child:
            tail.child.qc_hash ^= 1
        elif fault == 8 and tail.child:
            tail.child.proof_hash ^= 1
        elif fault == 9 and tail.child:
            tail.child.round += 1
        elif fault == 10 and tail.child:
            tail.child.bad = True
        elif fault == 11 and tail.child:
            tail.child.proof_bad = True
        steps = [Step(item, rows[index], times[index]) for index, item in enumerate(blocks)]
        extra = dict(direct=next(pick) % 3 == 0, bootstrapped=next(pick) % 2 == 0, waker=next(pick) % 3 == 0, lock_held=next(pick) % 3 == 0)
        extra["lock_parked"] = extra["lock_held"] and next(pick) % 2 == 0
        closed = next(pick) % 5
        if closed < size and next(pick) % 3 == 0:
            extra["closed_after"] = closed
        shift = next(pick) % 8
        if shift == 0:
            extra["last_recv"] = 999
        elif shift == 1:
            extra["last_recv"] = 1001
        elif shift == 2:
            extra["confirmed"] = 1001
        cases.append(Case("vector %d" % seed, steps, **extra))
    return cases


def check_all(harness, cases):
    rows = []
    for case in cases:
        label, want = spec_run(case)
        got = harness.run(case)
        wrong = same(got, want)
        if wrong:
            raise EvidenceError("case %s differs on %s: %s against %s" % (case.name, wrong, [got[key] for key in wrong], [want[key] for key in wrong]))
        rows.append((case, label, got))
    return rows


PINS = (
    ('poll', 0x475a3f5, '488b4950', 'QC round load'),
    ('poll', 0x475a400, '488b9008010000', 'last_recv_round load'),
    ('poll', 0x475a407, '4839d1', 'compare'),
    ('poll', 0x475a40a, '0f83a7000000', 'jae'),
    ('poll', 0x475a4b7, '0f85b6010000', 'jne'),
    ('poll', 0x475a4bd, 'c6801801000001', 'set bootstrapped'),
    ('poll', 0x475a502, 'ff1560c10101', 'call slot 0x5776668'),
    ('poll', 0x475a67a, '0f848d050000', 'gap arm: bootstrapped set'),
    ('poll', 0x475a833, '4d8d772c', 'outer tag 0x2c'),
    ('poll', 0x475ac0d, '48ffc2', 'start round + 1'),
    ('poll', 0x475ac17, '480f45f2', 'saturate'),
    ('poll', 0x475ac40, '4989b518020000', 'start'),
    ('poll', 0x475ac47, '49898d20020000', 'end'),
    ('poll', 0x475ac72, '48b80000000000c07240', '300.0 bits'),
    ('join', 0x4548071, '4885c0', 'body test'),
    ('join', 0x45480b6, '48b83333333333333303', 'row bound'),
    ('join', 0x45481f4, '440fb7a5c2010000', 'node length +0x1c2'),
    ('join', 0x4548225, 'ff155d622201', 'memcmp slot'),
    ('join', 0x4548257, '0f82ca000000', 'height out: missing'),
    ('join', 0x454825d, '488bacddc8010000', 'child +0x1c8'),
    ('join', 0x45482a4, '488b84dd68010000', 'value +0x168'),
    ('join', 0x45482ac, 'f048ff00', 'Arc clone'),
    ('join', 0x454835d, '48be1c00000000000080', 'tag 0x1c'),
    ('join', 0x454845b, 'bf28000000', 'body Arc 0x28'),
    ('buffer', 0x436001e, '483b8e08010000', 'expected round'),
    ('buffer', 0x4360025, '0f85c7000000', 'outer round branch'),
    ('buffer', 0x4360035, '48898e08010000', 'store round'),
    ('buffer', 0x4360099, '0f8597000000', 'proof branch'),
    ('buffer', 0x436009f, '4983fc64', '100'),
    ('buffer', 0x43600a3, '0f866c020000', 'jbe'),
    ('buffer', 0x43600d2, '4983c52a', 'text tag'),
    ('buffer', 0x43600fc, '4883ca2c', 'tag 0x2c'),
    ('buffer', 0x4360141, '498b8e10010000', 'start round argument'),
    ('buffer', 0x4360150, 'f0410fb05010', 'lock'),
    ('buffer', 0x436016b, 'e820751e00', 'call verifier'),
    ('buffer', 0x4360198, '49898610010000', 'confirmed store'),
    ('buffer', 0x4360252, '0f85ab010000', 'closed bit'),
    ('buffer', 0x4360291, 'e87a787e00', 'push'),
    ('buffer', 0x43602de, 'ff5008', 'wake'),
    ('buffer', 0x4360315, '4983c540', 'tag 0x40'),
    ('buffer', 0x4360535, '4983c535', 'tag 0x35'),
    ('buffer', 0x4360567, 'ba00ca9a3b', 'lock wait argument'),
    ('batch', 0x45476a7, '0f846e030000', 'empty'),
    ('batch', 0x45476fe, '4939bd08010000', 'proof word'),
    ('batch', 0x4547712, '0f8464030000', 'proof position'),
    ('batch', 0x4547718, '498b4d50', 'QC round'),
    ('batch', 0x454771c, '4c39f9', 'round compare'),
    ('batch', 0x4547727, '7436', 'first block skip'),
    ('batch', 0x4547729, 'f3410f6f4558', 'QC hash low'),
    ('batch', 0x4547759, '0f8590030000', 'hash branch'),
    ('batch', 0x4547773, 'e8883f0000', 'verify block'),
    ('batch', 0x454784e, '48c784246002000088000000', 'Keccak rate 0x88'),
    ('batch', 0x454785a, '66c78424680200000100', 'delimiter 0x01'),
    ('batch', 0x454786f, 'ff1563692201', 'hasher update'),
    ('batch', 0x4547893, 'ff1547692201', 'hasher finish'),
    ('batch', 0x45478d1, '0f84d9feffff', 'tx hash branch'),
    ('batch', 0x45478ff, '0f8556010000', 'count'),
    ('batch', 0x4547966, '74b8', 'row hash branch'),
    ('batch', 0x4547981, '0f85a8010000', 'time word 0'),
    ('batch', 0x4547992, '0f8597010000', 'time word 1'),
    ('batch', 0x45479a3, '0f8586010000', 'time word 2'),
    ('batch', 0x45479a9, '4d8bbd98000000', 'round'),
    ('batch', 0x45479d1, 'e87a460000', 'block digest'),
    ('batch', 0x4547a0f, '0f8523010000', 'last proof'),
    ('batch', 0x4547b6d, 'e8de440000', 'digest of the last block'),
    ('batch', 0x4547b87, 'e8743b0000', 'verify child'),
    ('batch', 0x4547bac, 'e8bf112100', 'verify QC'),
    ('batch', 0x4547bf0, '7421', 'child hash branch'),
    ('batch', 0x4547c2e, 'e81d440000', 'digest of the child'),
    ('batch', 0x4547c68, '7439', 'proof hash branch'),
    ('batch', 0x4547c6a, 'ff1518782201', 'clock read'),
    ('batch', 0x4547ca3, '49ffc7', 'round + 1'),
    ('batch', 0x4547cad, '490f45c7', 'saturate'),
    ('batch', 0x4547cb1, '49398690010000', 'child round'),
    ('batch', 0x4547cb8, '7513', 'consecutive branch'),
)
SLOTS = ((0x5776668, 0x4360000, "seven call sites in callers.tsv"), (0x5775098, 0x454EE00, "called at 0x4360062"), (0x57730A8, 0x4761900, "last block Arc gone"), (0x57730B0, 0x4761470, "last body Arc gone"), (0x5773008, 0x4760F80, "last tx Arc gone"), (0x576E1D8, 0x4F59A10, "hasher update at 0x454786f"), (0x576E1E0, 0x4F59E40, "hasher finish at 0x4547893"), (0x576F488, 0x14385C0, "clock read at 0x4547c6a"), (0x576E978, 0x143D010, "warning log"), (0x576E968, 0x4EDBA50, "stderr print"), (0x576EF30, 0x4E0F640, "mutex slow lock"), (0x576EF38, 0x4E0F2C0, "mutex slow unlock"))


TAGS = ((0x14, 0x4547A25, "NoClientBlocks", 0x6FBAB0, "batch length 0"), (0x15, 0x4547A82, "ClientBlockQcRound", 0x6FBABE, "QC round of the block differs from the previous round: QC round, expected"),
        (0x16, 0x4547B26, "ClientBlockQcHash", 0x6FBAD0, "QC hash of the block differs from the digest of the previous block: QC hash, expected"), (0x17, 0x4547A51, "ClientBlockTx", 0x6FBAE1, "digest of the tx bytes differs from the row hash: row hash"),
        (0x18, 0x4547A5B, "ClientBlockTxHashes", 0x6FBAEE, "tx rows differ from the block hash vector in count or at one index"), (0x19, 0x4547B2F, "ClientBlockTime", 0x6FBB01, "12 byte row time differs from block +0x90"),
        (0x1A, 0x4547A7C, "ClientBlockUnexpectedCommitProof", 0x20C540, "proof on a block that is not last; the flush rule makes this unreachable from 0x4360000"), (0x1B, 0x4547A15, "ClientBlockMissingCommitProof", 0x6FBB10, "last block has no proof; the flush rule makes this unreachable from 0x4360000"),
        (0x1C, 0x454835D, "ClientBlockMissingTx", 0x6FBB2D, "a block hash is not in the local tx map: hash"), (0x1D, 0x4547BFC, "CommitProofChildQc", 0x6FBB41, "QC hash in the child differs from the digest of the last block"),
        (0x1E, 0x4547C9A, "CommitProofGrandchildQc", 0x6FBB53, "hash of the second QC differs from the digest of the child"), (0x1F, 0x4547CD7, "CommitProofConsecutive", 0x6FBB6A, "child round differs from last round + 1, saturating"))
OUTER_TAGS = ((0x2A, 0x43600D2, "27 byte owned text `Too many unconfirmed blocks`"), (0x2C, 0x43600FC, "QC round differs from the expected round: QC round; also built by the poll at 0x475a833"), (0x35, 0x4360535, "channel closed during a flush"), (0x40, 0x4360315, "success value, not an error"))
GATES = (("poll", 1, 0x475A40A, "QC round < state +0x108 `last_recv_round`: warning `received old client block`, block dropped, success", "next row", "old block"),
         ("poll", 2, 0x475A4B7, "QC round == last_recv_round: set state +0x118 `bootstrapped`, call the buffer", "next row", "buffered"),
         ("poll", 3, 0x475A67A, "QC round over last_recv_round with bootstrapped set: `unexpected client block round`, outer tag 0x2c", "next row", "gap after start"),
         ("poll", 4, 0x475AC0D, "QC round over last_recv_round with bootstrapped clear: node_bootstrap future for rounds last_recv_round + 1 (saturating) to QC round, 300.0 s", "", "bootstrap"),
         ("join", 5, 0x4548071, "body word present: rows pass through, no lookup", "next row", ""),
         ("join", 6, 0x45480C3, "hash count <= 0x333333333333333, the 0x28 byte row bound", "panic", "panic row limit"),
         ("join", 7, 0x4548257, "each hash in block order is in the local tx map; repeats are kept", "tag 0x1c, built rows dropped", "check 0x1c"),
         ("join", 8, 0x4548460, "rows go to a new 0x28 byte Arc: strong 1, weak 1, cap, ptr, len", "", ""),
         ("buffer", 9, 0x4360025, "QC round == state +0x108", "outer tag 0x2c, both Arcs dropped; the poll compares first, so only 0x4389070 can reach it", "check 0x2c"),
         ("buffer", 10, 0x4360035, "state +0x108 = block round, before any check of the block", "", ""),
         ("buffer", 11, 0x4360062, "pending vector full: growth 0x454ee00, capacity doubled, at least 4", "", ""),
         ("buffer", 12, 0x4360099, "proof word None: no verify", "verify", ""),
         ("buffer", 13, 0x43600A3, "no proof: pending length <= 100 is success", "owned text, pending and state stay", "text too many"),
         ("buffer", 14, 0x4360150, "mutex at state +0xf0 +0x10; slow path 0x4e0f640 with 1000000000", "", ""),
         ("buffer", 15, 0x436016B, "batch verify: whole pending vector, state +0x110 as the start round, table at the mutex object +0x18", "", ""),
         ("buffer", 16, 0x436017C, "verify failed: warning `failed to verify client block batch`, unlock, error returned; pending and state +0x108 stay", "", ""),
         ("buffer", 17, 0x4360198, "verify passed: state +0x110 = state +0x108, pending vector taken", "", "flushed"),
         ("buffer", 18, 0x4360252, "channel word +0x1c0 bit 0 set: row dropped, line `client block send failed`, the rest dropped, outer tag 0x35; state +0x110 keeps its new value", "word + 2, push", "check 0x35"),
         ("buffer", 19, 0x43602DE, "waker at channel +0x100 fires once when the channel flag word was 0", "", ""),
         ("batch", 20, 0x45476A7, "batch length != 0", "tag 0x14", "check 0x14"),
         ("batch", 21, 0x4547712, "proof word None or this is the last block", "tag 0x1a", "check 0x1a"),
         ("batch", 22, 0x454771F, "QC round == previous round; start round for the first block", "tag 0x15", "check 0x15"),
         ("batch", 23, 0x4547727, "from the second block on: QC hash == digest of the previous block; the first block has no hash check", "tag 0x16", "check 0x16"),
         ("batch", 24, 0x4547773, "0x454b700 on the block", "its error", "check 0x1"),
         ("batch", 25, 0x45478D1, "each tx row: Keccak-256 of the tx bytes == row hash; rate 0x88, delimiter 0x01", "tag 0x17", "check 0x17"),
         ("batch", 26, 0x45478FF, "row count == block hash count", "tag 0x18", "check 0x18"),
         ("batch", 27, 0x4547966, "row hashes equal the block hash vector, in order", "tag 0x18", "check 0x18"),
         ("batch", 28, 0x4547981, "12 byte row time == block +0x90, word by word", "tag 0x19", "check 0x19"),
         ("batch", 29, 0x45479D1, "previous round = block round, previous hash = digest of this block; no rule on rounds moving by 1", "", ""),
         ("batch", 30, 0x4547A0F, "last block has a proof", "tag 0x1b", "check 0x1b"),
         ("batch", 31, 0x4547B87, "0x454b700 on the child at block +0x108", "its error", ""),
         ("batch", 32, 0x4547BAC, "0x4758d70 on the QC at block +0x200", "its error", ""),
         ("batch", 33, 0x4547BF0, "QC hash inside the child == digest of the last block", "tag 0x1d", "check 0x1d"),
         ("batch", 34, 0x4547C68, "hash of the block +0x200 QC == digest of the child", "tag 0x1e after a clock read 0x14385c0 and a second digest, both unused", "check 0x1e"),
         ("batch", 35, 0x4547CB8, "child round == last block round + 1, saturating at u64 max", "tag 0x1f", "check 0x1f"),
         ("batch", 36, 0x4547CBE, "tag 0x2a is success; the round in the +0x200 QC and the QC round in the child are never read", "", "flushed"))
LAYOUT = (("item", 0x0, 8, "Arc of the client block", 0x4360017), ("item", 0x8, 8, "Arc of the tx rows, 0 before the join", 0x4548069), ("item", 0x10, 0xC, "time words compared with block +0x90", 0x4547976),
          ("client block Arc", 0x10, 0xF8, "signed block", 0x4547764), ("client block Arc", 0x18, 8, "block tx hash pointer", 0x4547909), ("client block Arc", 0x20, 8, "block tx hash count", 0x45478E9), ("client block Arc", 0x50, 8, "QC round", 0x4547718),
          ("client block Arc", 0x58, 0x20, "QC hash", 0x4547729), ("client block Arc", 0x98, 8, "block round", 0x45479A9), ("client block Arc", 0xA0, 0xC, "block time words", 0x454797A), ("client block Arc", 0x108, 0xF8, "child block; word 0 None means no proof", 0x4547B3B),
          ("client block Arc", 0x150, 0x20, "QC hash inside the child", 0x4547BC4), ("client block Arc", 0x190, 8, "child round", 0x4547CB1), ("client block Arc", 0x200, 0x50, "QC over the child", 0x4547B9A), ("client block Arc", 0x230, 0x20, "hash of that QC", 0x4547C3C),
          ("tx rows Arc", 0x18, 8, "row pointer", 0x4547798), ("tx rows Arc", 0x20, 8, "row count", 0x45477A1), ("tx row", 0x0, 0x20, "hash", 0x45477BD), ("tx row", 0x20, 8, "Arc of the tx bytes", 0x45477D4), ("tx Arc", 0x18, 8, "bytes pointer", 0x4547864), ("tx Arc", 0x20, 8, "bytes length", 0x4547868),
          ("local tx map node", 0x0, 0x160, "32 byte keys", 0x4548215), ("local tx map node", 0x168, 0x58, "tx Arcs", 0x45482A4), ("local tx map node", 0x1C2, 2, "length", 0x45481F4), ("local tx map node", 0x1C8, 0x60, "children", 0x454825D),
          ("stream state", 0x0, 0x18, "pending vector: cap, ptr, len; row 0x20", 0x436005A), ("stream state", 0xC8, 8, "channel", 0x436023D), ("stream state", 0xD0, 8, "sender count object", 0x4360231), ("stream state", 0xF0, 8, "mutex object", 0x436013A),
          ("stream state", 0x108, 8, "last_recv_round", 0x436001E), ("stream state", 0x110, 8, "last confirmed round", 0x4360141), ("stream state", 0x118, 1, "bootstrapped", 0x475A4BD))
STRINGS = ((0x6F13B5, "Too many unconfirmed blocks"), (0x20249F, "failed to verify client block batch: "), (0x1F590A, "client block send failed: "), (0x1E8BB5, "received old client block, is peer behind? @@ [parent_round: "), (0x1E2CB6, "unexpected client block round @@ [round: "),
           (0x1E2CFB, "self.last_recv_round: "), (0x1E2D18, "self.bootstrapped: "), (0x6FBECD, "node_bootstrap")) + tuple((row[3], row[2]) for row in TAGS)
LOCATIONS = ((0x436039E, 0x571D240, "failed verify warning"), (0x475A483, 0x572F088, "old client block warning"))
PIN_SITES = ()
BATCH_CALLER = 0x436016B
BUFFER_SLOT_SITES = ((0x43899E1, 0x4389070, "bootstrap loop"), (0x439CCF8, 0x439BAF0, "forward poll, other copy"), (0x439D6BC, 0x439BAF0, "forward poll, other copy"), (0x475A502, 0x4759970, "forward poll: QC round equal arm"), (0x475B34A, 0x4759970, "forward poll: after the bootstrap future"), (0x4B3D6BD, 0x4B3C880, "forward poll, other copy"), (0x4B3DF46, 0x4B3C880, "forward poll, other copy"))
LOG_NOTE = "field of a log or print record, the stub reads only the format"
SIZE_NOTE = "size or capacity word handed to the dealloc or alloc stub, not observed"
SURVIVOR_NOTES = ((0x4360362, 0x4360381, LOG_NOTE), (0x4360424, 0x4360496, LOG_NOTE), (0x475A410, 0x475A435, LOG_NOTE), (0x4360521, 0x4360527, "time format buffer drop"), (0x43600A9, 0x43600B4, SIZE_NOTE), (0x44C6ED2, 0x44C6EDB, SIZE_NOTE), (0x45483D5, 0x45483E0, SIZE_NOTE),
                  (0x4360258, 0x436025C, "sender count limit panic, not modelled"), (0x436026F, 0x4360271, "compare and swap retry, one thread here"), (0x436030B, 0x436030F, "length is 0 after a flush, so this compare never fires"), (0x454EE11, 0x454EE15, "growth starts at capacity 0 and doubles from 4, so doubled capacity is 0 or at least 8"),
                  (0x45480B6, 0x45480C0, "one word under the bound still panics through the allocation failure"), (0x454828B, 0x4548295, "tag of a temporary error value that goes to the drop stub"),
                  (0x43602D0, 0x43602D9, "clearing one more flag bit: no case holds another bit in the word"), (0x454811E, 0x4548127, "row count word, rewritten before any read on the reached paths"), (0x454845B, 0x4548460, SIZE_NOTE),
                  (0x475AC10, 0x475AC17, "saturation needs last_recv_round at u64 max under a higher QC round, which no u64 can be"))
POLL_WINDOWS = ((0x475A3AA, 0x475A530), (0x475A673, 0x475A680), (0x475A830, 0x475A837), (0x475AC0D, 0x475AC83))


def survivor_reason(va, kind):
    for low, high, text in SURVIVOR_NOTES:
        if low <= va < high:
            return text
    return "not classified"


def text_rows(image, start):
    """Rows of a whole FDE; of the 27 KB poll only the windows of the round gate, each from a known row start."""
    if start == POLL:
        return {row.va: row for begin, end in POLL_WINDOWS for row in decode_range(image, begin, end)}
    begin, end = image.exact_fde(start)
    return {row.va: row for row in decode_range(image, begin, end)}


def scan_call_sites(image, target):
    """Every e8 or e9 rel32 inside .text that lands on target; one opcode byte plus a checked displacement."""
    start, data = image.text_bytes()
    sites = []
    for match in re.finditer(rb"[\xe8\xe9]", data):
        at = match.start()
        if at + 5 <= len(data) and start + at + 5 + struct.unpack_from("<i", data, at + 1)[0] == target:
            sites.append(start + at)
    return sites


def scan_slot_sites(image, slot):
    """Every ff 15 or ff 25 rip relative row inside .text that reads slot."""
    start, data = image.text_bytes()
    sites = []
    for match in re.finditer(rb"\xff[\x15\x25]", data):
        at = match.start()
        if at + 6 <= len(data) and start + at + 6 + struct.unpack_from("<i", data, at + 2)[0] == slot:
            sites.append(start + at)
    return sites


def scan_callers(image):
    direct = scan_call_sites(image, VERIFY_BATCH)
    if direct != [BATCH_CALLER]:
        raise EvidenceError("batch verifier call sites differ: %s" % direct)
    if VERIFY_BATCH in image.relative().values():
        raise EvidenceError("a relocation names the batch verifier")
    if image.relative().get(SLOT_BUFFER) != BUFFER:
        raise EvidenceError("buffer slot differs")
    if [slot for slot, target in image.relative().items() if target == BUFFER] != [SLOT_BUFFER]:
        raise EvidenceError("another slot names the buffer")
    sites = scan_slot_sites(image, SLOT_BUFFER)
    if sites != [row[0] for row in BUFFER_SLOT_SITES]:
        raise EvidenceError("buffer call sites differ: %s" % sites)
    for site, host, _ in BUFFER_SLOT_SITES:
        if image.fde(site)[0] != host:
            raise EvidenceError("call site owner differs at %#x" % site)
    return [(site, host, text) for site, host, text in BUFFER_SLOT_SITES]


def check_pins(image):
    for _, va, text, _ in PINS:
        want = bytes.fromhex(text)
        at = image.offset(va)
        if bytes(image.blob[at:at + len(want)]) != want:
            raise EvidenceError("pin differs at %#x" % va)
    return len(PINS)


def check_slots(image):
    relative = image.relative()
    rows = []
    for slot, target, use in SLOTS:
        if relative.get(slot) != target:
            raise EvidenceError("slot differs at %#x" % slot)
        rows.append((slot, target, use))
    return rows


def check_strings(image):
    for va, text in STRINGS:
        at = image.offset(va)
        if bytes(image.blob[at:at + len(text)]) != text.encode():
            raise EvidenceError("string differs at %#x" % va)
    return STRINGS


def check_locations(image):
    relative = image.relative()
    rows = []
    for site, slot, use in LOCATIONS:
        path, line, column = image.location(slot, relative)
        rows.append(("%#x" % site, "%#x" % slot, path, line, column, use))
    return rows


def check_gate_sites(image):
    """Every site named in a table starts a row inside its FDE, decoded from bytes."""
    rows = {}
    for va in [row[2] for row in GATES] + [row[4] for row in LAYOUT] + [row[1] for row in TAGS] + [row[1] for row in OUTER_TAGS]:
        host = image.fde(va)[0]
        if host not in rows:
            rows[host] = text_rows(image, host)
        if va not in rows[host]:
            raise EvidenceError("gate site is not a row start: %#x" % va)
    return sum(len(item) for item in rows.values())


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
            if same(got, spec_run(case)[1]):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, TypeError, UnicodeDecodeError, struct.error):
            return case
    return None


MUTANT_CAP = 40
NAMED_STEP_LIMIT = 20000


def reach_table(image, cases):
    """For each case the rows it reaches and its step count, on the unedited image; cheap cases come first."""
    harness = Harness(image)
    rows = []
    for case in cases:
        harness.machine.seen = set()
        before = harness.machine.steps
        harness.run(case)
        rows.append((harness.machine.steps - before, len(rows), case, frozenset(harness.machine.seen), spec_run(case)[0]))
    rows.sort(key=lambda row: row[:2])
    return rows


def sample(table, va):
    """Cases reaching a row, one outcome at a time, cheapest first: a row that fails most cheap cases still sees the rest."""
    groups = {}
    named = []
    for row in table:
        if va in row[3]:
            groups.setdefault(row[4], []).append(row[2])
            if not row[2].name.startswith("vector") and row[0] < NAMED_STEP_LIMIT:
                named.append(row[2])
    chosen = list(named)
    depth = 0
    while len(chosen) < MUTANT_CAP + len(named) and any(depth < len(rows) for rows in groups.values()):
        for label in sorted(groups):
            if depth < len(groups[label]) and len(chosen) < MUTANT_CAP + len(named):
                chosen.append(groups[label][depth])
        depth += 1
    return chosen


def run_mutants(image, cases, rows):
    """Each edit runs only on cases that reach its row, at most MUTANT_CAP of them."""
    table = reach_table(image, cases)
    results = []
    harness = Harness(image)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    for va, kind, patch in edits_for(image, rows):
        chosen = sample(table, va)
        harness.machine.patches = patch
        for address in {va + index for index in range(16)} | set(patch):
            harness.machine.cache.pop(address, None)
        hit = first_failure(harness, chosen)
        harness.machine.patches = {}
        for address in {va + index for index in range(16)} | set(patch):
            harness.machine.cache.pop(address, None)
        host = image.fde(va)[0]
        if hit is not None:
            results.append((host, va, kind, "killed", hit.name))
        else:
            results.append((host, va, kind, "survived", survivor_reason(va, kind)))
    return results


def analyse(image, mutate=True, vectors=400):
    callers = scan_callers(image)
    pins = check_pins(image)
    slots = check_slots(image)
    strings = check_strings(image)
    locations = check_locations(image)
    decoded = check_gate_sites(image)
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
    labels = collections.Counter(label for _, label, _ in rows)
    result = dict(callers=callers, pins=pins, slots=slots, strings=strings, locations=locations, cases=cases, rows=rows, reached=reached, vector_count=vectors, labels=labels, decoded=decoded)
    for row in GATES:
        if row[5] and row[5] not in labels:
            raise EvidenceError("gate outcome never reached: %s" % row[5])
    if mutate:
        result["mutations"] = run_mutants(image, cases, selected)
    return result


def render(result, image):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    labels = result["labels"]

    def count(label):
        return labels[label] if label else "-"
    tsv("gates.tsv", ("group", "order", "site", "rule", "otherwise", "outcome_label", "cases"), [(group, order, "%#x" % va, rule, other or "-", label or "-", count(label)) for group, order, va, rule, other, label in GATES])
    tsv("error-tags.tsv", ("tag_low_byte", "site", "name", "name_address", "meaning", "cases"), [("%#x" % tag, "%#x" % va, name, "%#x" % at, meaning, labels["check %#x" % tag]) for tag, va, name, at, meaning in TAGS])
    tsv("outer-tags.tsv", ("tag_low_byte", "site", "meaning"), [("%#x" % tag, "%#x" % va, meaning) for tag, va, meaning in OUTER_TAGS])
    tsv("functions.tsv", ("function", "end", "bytes", "reached_bytes", "role"), [("%#x" % start, "%#x" % image.exact_fde(start)[1], image.exact_fde(start)[1] - start, result["reached"][start], ROLES[start]) for start in STATIC_FUNCTIONS])
    tsv("stubs.tsv", ("target", "kind", "what"), [("%#x" % key, "direct call", text) for key, text in sorted(STUBS.items())] + [("%#x" % key, "data slot", text) for key, text in sorted(SLOT_STUBS.items())])
    tsv("callers.tsv", ("site", "host", "context"), [("%#x" % site, "%#x" % host, text) for site, host, text in result["callers"]])
    tsv("layouts.tsv", ("record", "offset", "size", "field", "site"), [(record, "%#x" % offset, "%#x" % size, field, "%#x" % site) for record, offset, size, field, site in LAYOUT])
    tsv("pins.tsv", ("group", "address", "bytes", "meaning"), [(group, "%#x" % va, text, meaning) for group, va, text, meaning in PINS])
    tsv("slots.tsv", ("slot", "target", "use"), [("%#x" % slot, "%#x" % target, use) for slot, target, use in result["slots"]])
    tsv("strings.tsv", ("address", "text"), [("%#x" % va, text) for va, text in result["strings"]])
    tsv("locations.tsv", ("site", "data", "path", "line", "column", "use"), result["locations"])
    tsv("outcomes.tsv", ("outcome", "cases"), sorted(labels.items()))
    rows = []
    for case, label, got in result["rows"]:
        rows.append((case.name, label, len(case.steps), len(got["pending"]), got["last_recv"], got["confirmed"], got["bootstrapped"], sum(1 for row in got["trace"] if row[0] == "send")))
    tsv("cases.tsv", ("case", "outcome", "steps", "pending_after", "last_recv_after", "confirmed_after", "bootstrapped_after", "sends"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("function", "address", "kind", "outcome", "detail"), [("%#x" % host, "%#x" % va, kind, outcome, detail) for host, va, kind, outcome, detail in result["mutations"]])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "cases": len(result["cases"]), "vector_cases": result["vector_count"], "named_cases": len(result["cases"]) - result["vector_count"], "functions_run": len(STATIC_FUNCTIONS),
               "reached_bytes": sum(result["reached"].values()), "whole_function_bytes": sum(image.exact_fde(start)[1] - start for start in STATIC_FUNCTIONS if start != POLL), "pins": result["pins"], "call_sites": len(result["callers"]), "gates": len(GATES), "rows_decoded": result["decoded"]}
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
