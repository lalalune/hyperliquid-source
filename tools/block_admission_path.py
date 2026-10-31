#!/usr/bin/env python3
"""Run node #94 block admission 0x44b8410 from bytes: verify_block, quorum, the QC and TC checks, and what registers a block.

The real rows of the admission body and fourteen helpers run under named stubs with real B-tree fixtures, a separate
rule list predicts every outcome and every state write, and every reached conditional row and immediate is mutated.
Call sites, pins and slots come from fixed bytes. No objdump or readelf output is parsed and the binary is never
executed. Standard library only.

    python3 tools/block_admission_path.py --out <dir>
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
        while pc != RETURN_SENTINEL:
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
SLOT_MEMMOVE = 0x576E0E0
SLOT_ALLOC = 0x576DFD8
SLOT_DEALLOC = 0x576E010
SLOT_BTREE_PANIC = 0x576E470
SLOT_LOG = 0x576E978
SLOT_FORMAT = 0x576E040
SLOT_RECOVER = 0x576FE58
SLOT_VERIFY_BLOCK = 0x5776A20
SLOT_LEADER = 0x5773628
SLOT_QUORUM = 0x5776AE8
SLOT_NEWER_FORK = 0x576E098
SLOT_ADD_OVERFLOW = 0x576E118
SLOT_ASSERT = 0x576E108
SLOT_WORKER = 0x5773298
ONCE_WORD = 0x577AB98
REGISTER = 0x44B8410
VERIFY_SIGNED = 0x454B700
VERIFY_BLOCK = 0x47B01B0
VERIFY_QC = 0x4758D70
VERIFY_TC = 0x47594F0
VERIFY_TIMEOUT = 0x454AA10
QUORUM = 0x4AD90D0
SET_LOOKUP = 0x42C9930
SET_RANGE = 0x42BA100
MISSING = 0x47BFCF0
ANCESTORS = 0x44B9800
SIGNER_SET = 0x44518A0
VOTER_SET = 0x4451690
BULK = 0x428D080
BALANCE = 0x42730A0
LEADER = 0x4B31E70
STATIC_FUNCTIONS = (REGISTER, VERIFY_SIGNED, VERIFY_BLOCK, VERIFY_QC, VERIFY_TC, VERIFY_TIMEOUT, QUORUM, SET_LOOKUP, SET_RANGE, MISSING, ANCESTORS, SIGNER_SET, VOTER_SET, BULK, BALANCE)
ROLES = {REGISTER: "block admission: verify, round floor, duplicate, same round, register", VERIFY_SIGNED: "stake table, block checks, proposer signature", VERIFY_BLOCK: "proposer, QC, QC round, TC",
         VERIFY_QC: "vote signatures, quorum, version pair", VERIFY_TC: "vote rounds, highest QC, signatures, quorum", VERIFY_TIMEOUT: "one timeout vote, its QC only when asked", QUORUM: "strict 2/3 of stake",
         SET_LOOKUP: "stake set for a round", SET_RANGE: "range walk of the stake table", MISSING: "block hashes absent from the tx map", ANCESTORS: "uncommitted ancestor walk, its hashes as a set",
         SIGNER_SET: "QC signers to a sorted unique set", VOTER_SET: "timeout voters to a sorted unique set", BULK: "bulk build with duplicate removal", BALANCE: "right edge fix after a bulk build"}
STUBS = {0x454C050: "signing digest: SHA-256 of fixture fields per variant, real digest bytes not modelled", 0x4B1A270: "drop of an error value, no effect", 0x47328A0: "drop of an error value, no effect", 0x49478B0: "set drain ends at once, node free only",
         0x4929600: "ancestor set leaf insert in key order", 0x49AC240: "drop of a set, no effect", 0x4913410: "sort of 20 byte rows, Python sort", 0x4768F80: "parallel loop, runs real 0x454aa10 with flag 0 for each vote in index order, first error wins",
         0x4E17630: "worker registry cell", 0x4945960: "request row removal, key checked, row taken from the fixture", 0x49B4C00: "drop of a removed request row, recorded", 0x47085B0: "verify_block ok log", 0x4706810: "verify_block err log", 0x4707580: "register_block unknown tx hashes log",
         0x4958C40: "tx map vacant entry insert in one leaf", 0x4959AC0: "block map vacant entry insert in one leaf", 0x4B46310: "channel push, row recorded", 0x4732E40: "closed channel row drop, row recorded", 0x44C52B0: "block clone, byte copy of 0xb0", 0x454A910: "to_string of a block, fixture text of round and proposer",
         0x447E5C0: "drop of a signed block, no effect", 0x4480730: "drop of a block value, no effect", 0x454F5D0: "pointer vector growth"}
SLOT_STUBS = {SLOT_MEMCMP: "memcmp", SLOT_MEMCPY: "memcpy", SLOT_MEMMOVE: "memcpy", SLOT_ALLOC: "fixture bump allocator", SLOT_DEALLOC: "dealloc, no effect", SLOT_BTREE_PANIC: "panic", SLOT_LOG: "warning log, format address recorded", SLOT_FORMAT: "format, empty string",
              SLOT_RECOVER: "signature recover: signer named in the fixture when its digest matches, another address when not, error on a bad flag", SLOT_LEADER: "proposer rule: fixture address or fixture error", SLOT_NEWER_FORK: "panic, newer hardfork", SLOT_ADD_OVERFLOW: "panic, stake add overflow", SLOT_ASSERT: "panic, replaced block"}
NONE_TAG = 1 << 63
PLACEHOLDER_TAG = NONE_TAG + 1
OK_TAG = NONE_TAG + 0x2A
TAG_SKEW = NONE_TAG + 0
STATE = HEAP_BASE + 0x1000
STATE_SIZE = 0x300
TABLE = HEAP_BASE + 0x1400
BLOCK_IN = HEAP_BASE + 0x1500
CHANNEL = HEAP_BASE + 0x1800
SENDER = HEAP_BASE + 0x1A00
REG_CELL = HEAP_BASE + 0x1A40
REG_OBJECT = HEAP_BASE + 0x1A80
REG_POOL = HEAP_BASE + 0x1C00
ERROR_OBJECT = HEAP_BASE + 0x1E40
ERROR_VTABLE = HEAP_BASE + 0x1E60
WAKE_VTABLE = HEAP_BASE + 0x1E80
OUT = HEAP_BASE + 0x1EA0
NODES = HEAP_BASE + 0x2000
USED = HEAP_SIZE
TX_VALUE = 0x58
BLOCK_VALUE = 0xF8
STATE_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(STATE_SIZE))
LOW_ROUNDS = 200
RECENT_SPAN = 2000
NEVER = 0xFFFFFFFFFFFFFFFF


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, pidx_at, len_at, edges_at):
        self.key_at, self.key_size, self.val_at, self.val_size = key_at, key_size, val_at, val_size
        self.parent_at, self.pidx_at, self.len_at, self.edges_at = parent_at, pidx_at, len_at, edges_at
        self.size = edges_at + 12 * 8


TX_LAYOUT = Layout(0, 32, 0x168, TX_VALUE, 0x160, 0x530, 0x532, 0x538)
BLOCK_LAYOUT = Layout(0, 32, 0x168, BLOCK_VALUE, 0x160, 0xC10, 0xC12, 0xC18)
SEEN_LAYOUT = Layout(0, 32, 0x16C, 1, 0x160, 0x168, 0x16A, 0x178)
ANCESTOR_LAYOUT = Layout(0, 32, 0x168, 0, 0x160, 0x168, 0x16A, 0x170)
STAKE_LAYOUT = Layout(0x60, 20, 8, 8, 0, 0x13C, 0x13E, 0x140)
TABLE_LAYOUT = Layout(8, 8, 0x60, 0x18, 0, 0x168, 0x16A, 0x170)


def word_bytes(value):
    return value.to_bytes(32, "big")


def addr_bytes(value):
    return value.to_bytes(20, "big")


class Sig:
    """Signature fixture: by = address it recovers to, good = bound to the right digest, broken = recover fails."""

    def __init__(self, by=None, good=True, broken=False):
        self.by, self.good, self.broken = by, good, broken


class Qc:
    def __init__(self, version=2, start=100, round=999, hash=0x77, votes=()):
        self.version, self.start, self.round, self.hash, self.votes = version, start, round, hash, list(votes)


class Vote:
    def __init__(self, qc, round, signer, sig=None):
        self.qc, self.round, self.signer, self.sig = qc, round, signer, sig or Sig()


class Tc:
    def __init__(self, round, votes=()):
        self.round, self.votes = round, list(votes)


class Block:
    def __init__(self, key, round, proposer, hashes, qc, tc=None, sig=None):
        self.key, self.round, self.proposer, self.hashes, self.qc, self.tc, self.sig = key, round, proposer, list(hashes), qc, tc, sig or Sig()


class Case:
    def __init__(self, name, block, **extra):
        self.name, self.block = name, block
        self.stakes = {0: {1: 10, 2: 10, 3: 10, 4: 10}}
        self.base = 0
        self.version, self.start = 2, 100
        self.valid_until = 10 ** 9
        self.leader = 1
        self.leader_error = None
        self.committed = 500
        self.stored = []
        self.txs = []
        self.seen = []
        self.rows = []
        self.forward_off = False
        self.closed = False
        self.waker = False
        self.now = (20000, 7, 8)
        self.__dict__.update(extra)


def digest_block(block):
    return hashlib.sha256(b"0" + addr_bytes(block.proposer) + block.round.to_bytes(8, "little")).digest()


def digest_qc(qc):
    return hashlib.sha256(b"1" + word_bytes(qc.hash) + struct.pack("<QQQ", qc.version, qc.start, qc.round)).digest()


def digest_vote(vote):
    return hashlib.sha256(b"2" + vote.round.to_bytes(8, "little") + vote.qc.round.to_bytes(8, "little") + addr_bytes(vote.signer)).digest()


def signature_bytes(sig, digest, claimed):
    data = bytearray(0x48)
    data[0:20] = addr_bytes(claimed if sig.by is None else sig.by)
    data[20:52] = digest if sig.good else bytes(32)
    data[52] = 1 if sig.broken else 0
    return bytes(data)


def other_address(data):
    return hashlib.sha256(b"other" + data).digest()[:20]


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        hooks = {SLOT_MEMCMP: self.on_memcmp, SLOT_MEMCPY: self.on_memcpy, SLOT_MEMMOVE: self.on_memcpy, SLOT_ALLOC: self.on_alloc, SLOT_DEALLOC: self.on_nothing, SLOT_BTREE_PANIC: self.on_panic, SLOT_LOG: self.on_log, SLOT_FORMAT: self.on_format,
                 SLOT_RECOVER: self.on_recover, SLOT_LEADER: self.on_leader, SLOT_NEWER_FORK: self.on_newer_fork, SLOT_ADD_OVERFLOW: self.on_overflow, SLOT_ASSERT: self.on_panic, SLOT_WORKER: self.on_refuse}
        for index, (slot, hook) in enumerate(sorted(hooks.items())):
            mark = MARK_BASE + index * 16
            memory.statics[slot] = mark
            machine.slots[mark] = hook
        self.error_mark = MARK_BASE + 0x1000
        machine.slots[self.error_mark] = self.on_error_drop
        self.wake_mark = MARK_BASE + 0x1010
        machine.slots[self.wake_mark] = self.on_wake
        memory.statics[SLOT_VERIFY_BLOCK] = VERIFY_BLOCK
        memory.statics[SLOT_QUORUM] = QUORUM
        memory.statics[ONCE_WORD] = 0
        machine.real = frozenset(STATIC_FUNCTIONS)
        machine.calls = {0x454C050: self.on_digest, 0x4B1A270: self.on_nothing, 0x47328A0: self.on_nothing, 0x49478B0: self.on_drain, 0x4929600: self.on_ancestor_add, 0x49AC240: self.on_nothing, 0x4913410: self.on_sort,
                         0x4768F80: self.on_parallel, 0x4E17630: self.on_worker, 0x4945960: self.on_request_gone, 0x49B4C00: self.on_row_drop, 0x47085B0: self.on_log_ok, 0x4706810: self.on_log_err, 0x4707580: self.on_log_unknown,
                         0x4958C40: self.on_tx_insert, 0x4959AC0: self.on_block_insert, 0x4B46310: self.on_send, 0x4732E40: self.on_closed, 0x44C52B0: self.on_clone, 0x454A910: self.on_text, 0x447E5C0: self.on_nothing, 0x4480730: self.on_nothing, 0x454F5D0: self.on_reserve}
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

    def on_refuse(self, machine):
        raise Halt("edge the fixtures must not reach")

    def on_panic(self, machine):
        raise Panicked("panic")

    def on_newer_fork(self, machine):
        self.expect(machine.regs[RDI] == 0x1E6910, "newer hardfork text")
        raise Panicked("newer hardfork")

    def on_overflow(self, machine):
        raise Panicked("stake overflow")

    def on_alloc(self, machine):
        machine.regs[RAX] = self.alloc(machine.regs[RDI])

    def on_memcmp(self, machine):
        regs = machine.regs
        left = machine.memory.bytes_at(regs[RDI], regs[RDX])
        right = machine.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else 0x7 if left > right else (-5) & MASK[4]

    def on_memcpy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_reserve(self, machine):
        regs, memory = machine.regs, machine.memory
        vector = regs[RDI]
        cap, pointer = memory.read(vector, 8), memory.read(vector + 8, 8)
        new = max(4, cap * 2)
        at = self.alloc(new * regs[R8])
        memory.copy(at, pointer, cap * regs[R8])
        memory.write(vector, 8, new)
        memory.write(vector + 8, 8, at)

    def on_format(self, machine):
        machine.memory.write(machine.regs[RDI], 8, 0)

    def on_log(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] in (0x1E8C48, 0x1E2D6A), "log text")
        self.trace.append(("log", "high round" if regs[RSI] == 0x1E8C48 else "proposer"))

    def on_recover(self, machine):
        regs, memory = machine.regs, machine.memory
        out = regs[RDI]
        data = memory.bytes_at(regs[RSI], 0x48)
        digest = memory.bytes_at(regs[RDX], 32)
        if data[52]:
            memory.write(out, 1, 1)
            memory.write(out + 8, 8, ERROR_OBJECT)
            return
        memory.write(out, 1, 0)
        memory.put_bytes(out + 1, data[:20] if data[20:52] == digest else other_address(data))

    def on_error_drop(self, machine):
        self.expect(machine.regs[RDI] == ERROR_OBJECT, "error object")

    def on_wake(self, machine):
        self.expect(machine.regs[RDI] == 0x5151, "waker data")
        self.wakes += 1

    def on_leader(self, machine):
        regs, memory = machine.regs, machine.memory
        case = self.case
        self.expect(regs[RSI] == TABLE and regs[RDX] == case.block.round, "proposer rule arguments")
        out = regs[RDI]
        if case.leader_error is not None:
            memory.write(out, 8, case.leader_error)
            memory.write(out + 8, 8, 0x1234)
            return
        memory.write(out, 8, OK_TAG)
        memory.put_bytes(out + 8, addr_bytes(case.leader))

    def on_digest(self, machine):
        regs, memory = machine.regs, machine.memory
        kind = memory.read(regs[RSI], 8)
        at = memory.read(regs[RSI] + 8, 8)
        if kind == 0:
            data = b"0" + memory.bytes_at(at + 0x9C, 20) + memory.bytes_at(at + 0x88, 8)
        elif kind == 1:
            data = b"1" + memory.bytes_at(at, 0x38)
        else:
            self.expect(kind == 2, "digest variant")
            data = b"2" + memory.bytes_at(at + 0x50, 8) + memory.bytes_at(at + 0x28, 8) + memory.bytes_at(at + 0x58, 20)
        memory.put_bytes(regs[RDI], hashlib.sha256(data).digest())

    def on_drain(self, machine):
        machine.memory.write(machine.regs[RDI], 8, 0)

    def on_ancestor_add(self, machine):
        regs, memory = machine.regs, machine.memory
        layout = ANCESTOR_LAYOUT
        key = memory.bytes_at(regs[RSI], 32)
        root = memory.read(regs[RDI], 8)
        if not root:
            root = self.alloc(layout.size)
            memory.put_bytes(root, bytes(layout.size))
            memory.write(regs[RDI], 8, root)
        count = memory.read(root + layout.len_at, 2)
        keys = [memory.bytes_at(root + 32 * index, 32) for index in range(count)]
        if key not in keys:
            keys.append(key)
            keys.sort()
            self.expect(len(keys) <= 11, "ancestor set stays one leaf")
            for index, item in enumerate(keys):
                memory.put_bytes(root + 32 * index, item)
            memory.write(root + layout.len_at, 2, len(keys))
            memory.write(regs[RDI] + 16, 8, len(keys))

    def on_sort(self, machine):
        regs, memory = machine.regs, machine.memory
        rows = sorted(memory.bytes_at(regs[RDI] + 20 * index, 20) for index in range(regs[RSI]))
        memory.put_bytes(regs[RDI], b"".join(rows))

    def on_worker(self, machine):
        machine.regs[RAX] = REG_CELL

    def on_parallel(self, machine):
        regs, memory = machine.regs, machine.memory
        out, count, votes = regs[RDI], regs[RSI], regs[R9]
        self.expect(regs[RDX] == 0 and regs[R8] == 1, "parallel split arguments")
        self.expect(memory.read(regs[RSP] + 8, 8) == count, "parallel count")
        consumer = memory.read(regs[RSP] + 16, 8)
        table = memory.read(memory.read(consumer + 0x18, 8), 8)
        temp = regs[RSP] - 0x200
        first = None
        for index in range(count):
            memory.write(temp, 8, 0)
            machine.call_real(VERIFY_TIMEOUT, {RDI: temp, RSI: votes + 0xB8 * index, RDX: table, RCX: 0})
            if memory.read(temp, 8) != OK_TAG and first is None:
                first = memory.bytes_at(temp, 0x50)
        if first is None:
            memory.write(out, 8, OK_TAG)
        else:
            memory.put_bytes(out, first)

    def on_request_gone(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == STATE + 0x1D0, "request map")
        key = memory.bytes_at(regs[RDX], 0x21)
        self.expect(key[0] == 0, "request key tag")
        hash_value = int.from_bytes(key[1:], "big")
        self.trace.append(("request gone", hash_value))
        if hash_value in self.rows:
            self.rows.remove(hash_value)
            memory.write(regs[RDI] + 0x24, 1, 0)
        else:
            memory.write(regs[RDI] + 0x24, 1, 2)

    def on_row_drop(self, machine):
        self.trace.append(("row dropped",))

    def text_at(self, pair):
        memory = self.machine.memory
        return memory.bytes_at(memory.read(pair, 8), memory.read(pair + 8, 8)).decode()

    def on_log_ok(self, machine):
        regs, memory = machine.regs, machine.memory
        at = regs[RDX]
        self.expect(regs[RSI] == STATE + 0xA8 and self.text_at(at) == "verify_block" and self.text_at(at + 0x30) == "ok", "ok log")
        self.trace.append(("ok", int.from_bytes(memory.bytes_at(at + 0x10, 32), "big")))

    def on_log_err(self, machine):
        regs, memory = machine.regs, machine.memory
        at = regs[RDX]
        self.expect(regs[RSI] == STATE + 0xA8 and self.text_at(at) == "verify_block" and self.text_at(at + 0x10) == "err", "err log")
        self.trace.append(("err", int.from_bytes(memory.bytes_at(at + 0x20, 32), "big"), memory.read(memory.read(at + 0x40, 8), 8) - NONE_TAG))

    def on_log_unknown(self, machine):
        regs, memory = machine.regs, machine.memory
        at = regs[RDX]
        self.expect(regs[RSI] == STATE + 0xA8 and self.text_at(at) == "register_block unknown tx hashes", "unknown log")
        vector = memory.read(at + 0x10, 8)
        pointer, count = memory.read(vector + 8, 8), memory.read(vector + 16, 8)
        self.trace.append(("unknown", [int.from_bytes(memory.bytes_at(memory.read(pointer + 8 * index, 8), 32), "big") for index in range(count)]))

    def vacant(self, machine, layout, value_size, root_at, count_at):
        regs, memory = machine.regs, machine.memory
        entry = regs[RSI]
        self.expect(memory.read(entry, 8) == STATE + root_at, "entry map")
        key = memory.bytes_at(entry + 8, 32)
        node, height, index = memory.read(entry + 0x28, 8), memory.read(entry + 0x30, 8), memory.read(entry + 0x38, 8)
        self.expect(height == 0, "entry at a leaf")
        if not node:
            node = self.alloc(layout.size)
            memory.put_bytes(node, bytes(layout.size))
            memory.write(STATE + root_at, 8, node)
            index = 0
        count = memory.read(node + layout.len_at, 2)
        self.expect(count < 11, "leaf has room")
        self.expect(index <= count, "entry index")
        for at in range(count, index, -1):
            memory.copy(node + 32 * at, node + 32 * (at - 1), 32)
            memory.copy(node + layout.val_at + value_size * at, node + layout.val_at + value_size * (at - 1), value_size)
        memory.put_bytes(node + 32 * index, key)
        memory.copy(node + layout.val_at + value_size * index, regs[RDX], value_size)
        memory.write(node + layout.len_at, 2, count + 1)
        memory.write(STATE + count_at, 8, memory.read(STATE + count_at, 8) + 1)

    def on_tx_insert(self, machine):
        self.vacant(machine, TX_LAYOUT, TX_VALUE, 0x1A0, 0x1B0)

    def on_block_insert(self, machine):
        self.vacant(machine, BLOCK_LAYOUT, BLOCK_VALUE, 0x1B8, 0x1C8)

    def sent_row(self, at):
        memory = self.machine.memory
        box = memory.read(at + 8, 8)
        return memory.read(at, 8) - NONE_TAG, memory.read(box + 0x88, 8), int.from_bytes(memory.bytes_at(at + 0x10, 32), "big")

    def on_send(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == CHANNEL + 0x80, "channel row list")
        self.trace.append(("send",) + self.sent_row(regs[RSI]))

    def on_closed(self, machine):
        self.trace.append(("closed",) + self.sent_row(machine.regs[RDI]))

    def on_clone(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], 0xB0)
        regs[RAX] = regs[RDI]

    def on_text(self, machine):
        regs, memory = machine.regs, machine.memory
        text = b"%d:%s" % (memory.read(regs[RSI] + 0x88, 8), memory.bytes_at(regs[RSI] + 0x9C, 20).hex().encode())
        at = self.alloc(len(text))
        memory.put_bytes(at, text)
        memory.write(regs[RDI], 8, 0)
        memory.write(regs[RDI] + 8, 8, at)
        memory.write(regs[RDI] + 16, 8, len(text))
        regs[RAX] = regs[RDI]

    def build(self, layout, items):
        """Write sorted (key bytes, value bytes) rows as one leaf or one root over leaves; returns (root, height)."""
        if not items:
            return 0, 0
        memory = self.machine.memory

        def node(rows, edges=()):
            at = self.alloc(layout.size)
            memory.put_bytes(at, b"\xee" * layout.size)
            memory.write(at + layout.parent_at, 8, 0)
            memory.write(at + layout.len_at, 2, len(rows))
            for index, (key, value) in enumerate(rows):
                memory.put_bytes(at + layout.key_at + layout.key_size * index, key)
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

    def signature_vector(self, votes, stride, write_row):
        at = self.alloc(max(len(votes), 1) * stride)
        for index, vote in enumerate(votes):
            write_row(at + stride * index, vote)
        return at

    def write_qc(self, at, qc):
        memory = self.machine.memory

        def row(address, pair):
            signer, sig = pair
            memory.put_bytes(address, b"\xbb" * 0x60)
            memory.put_bytes(address, addr_bytes(signer))
            memory.put_bytes(address + 0x18, signature_bytes(sig, digest_qc(qc), signer))
        votes = self.signature_vector(qc.votes, 0x60, row)
        memory.put_bytes(at, struct.pack("<QQQQQQ", len(qc.votes), votes, len(qc.votes), qc.version, qc.start, qc.round))
        memory.put_bytes(at + 0x30, word_bytes(qc.hash))

    def write_block(self, at, block):
        memory = self.machine.memory
        hashes = self.alloc(max(len(block.hashes), 1) * 32)
        for index, key in enumerate(block.hashes):
            memory.put_bytes(hashes + 32 * index, word_bytes(key))
        memory.put_bytes(at, b"\xcc" * BLOCK_VALUE)
        memory.put_bytes(at, struct.pack("<QQQ", len(block.hashes), hashes, len(block.hashes)))
        self.write_qc(at + 0x18, block.qc)
        if block.tc is None:
            memory.write(at + 0x68, 8, NONE_TAG)
        else:
            def row(address, vote):
                memory.put_bytes(address, b"\xbc" * 0xB8)
                self.write_qc(address, vote.qc)
                memory.write(address + 0x50, 8, vote.round)
                memory.put_bytes(address + 0x58, addr_bytes(vote.signer))
                memory.put_bytes(address + 0x70, signature_bytes(vote.sig, digest_vote(vote), vote.signer))
            votes = self.signature_vector(block.tc.votes, 0xB8, row)
            memory.put_bytes(at + 0x68, struct.pack("<QQQQ", len(block.tc.votes), votes, len(block.tc.votes), block.tc.round))
        memory.write(at + 0x88, 8, block.round)
        memory.put_bytes(at + 0x90, b"\x11" * 12)
        memory.put_bytes(at + 0x9C, addr_bytes(block.proposer))
        memory.put_bytes(at + 0xB0, signature_bytes(block.sig, digest_block(block), block.proposer))

    def set_state(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        self.bump = NODES
        self.trace, self.wakes = [], 0
        self.rows = list(case.rows)
        self.case = case
        memory.put_bytes(STATE, STATE_FILL)

        def word(offset, value):
            memory.write(STATE + offset, 8, value)
        word(0x198, case.committed)
        rows = sorted(case.txs)
        tx_rows = []
        for key in rows:
            value = bytearray(b"\xdd" * TX_VALUE)
            value[0:12] = struct.pack("<iII", 5, 6, 7)
            struct.pack_into("<Q", value, 0x10, 0x55)
            tx_rows.append((word_bytes(key), bytes(value)))
        root, height = self.build(TX_LAYOUT, tx_rows)
        word(0x1A0, root)
        word(0x1A8, height)
        word(0x1B0, len(rows))
        block_rows = []
        for block in sorted(case.stored, key=lambda item: item.key):
            temp = self.alloc(BLOCK_VALUE)
            self.write_block(temp, block)
            block_rows.append((word_bytes(block.key), memory.bytes_at(temp, BLOCK_VALUE)))
        root, height = self.build(BLOCK_LAYOUT, block_rows)
        word(0x1B8, root)
        word(0x1C0, height)
        word(0x1C8, len(block_rows))
        word(0x1D0, 0)
        word(0x1D8, 0)
        word(0x1E0, len(case.rows))
        root, height = self.build(SEEN_LAYOUT, [(word_bytes(key), b"\x01") for key in sorted(case.seen)])
        word(0x58, root)
        word(0x60, height)
        word(0x68, len(case.seen))
        memory.write(STATE + 0x230, 1, 1 if case.forward_off else 0)
        word(0x158, CHANNEL)
        word(0x160, SENDER)
        memory.put_bytes(CHANNEL, bytes(0x200))
        memory.write(CHANNEL + 0x1C0, 8, 1 if case.closed else 8)
        memory.write(CHANNEL + 0x100, 8, WAKE_VTABLE if case.waker else 0)
        memory.write(CHANNEL + 0x108, 8, 0x5151)
        memory.write(WAKE_VTABLE + 8, 8, self.wake_mark)
        memory.write(SENDER + 0x10, 8, 5)
        memory.write(REG_CELL, 8, REG_OBJECT)
        memory.write(REG_OBJECT + 0x110, 8, REG_POOL)
        memory.write(REG_POOL + 0x208, 8, 4)
        memory.write(ERROR_OBJECT, 8, ERROR_VTABLE)
        memory.write(ERROR_VTABLE, 8, self.error_mark)
        table_rows = []
        for start in sorted(case.stakes):
            items = [(addr_bytes(key), value.to_bytes(8, "little")) for key, value in sorted(case.stakes[start].items())]
            root, height = self.build(STAKE_LAYOUT, items)
            table_rows.append((start.to_bytes(8, "little"), struct.pack("<QQQ", root, height, len(items))))
        root, height = self.build(TABLE_LAYOUT, table_rows)
        memory.put_bytes(TABLE, b"\xab" * 0x60)
        memory.put_bytes(TABLE, struct.pack("<QQQ", case.base, root, height))
        memory.put_bytes(TABLE + 0x40, struct.pack("<QQ", case.version, case.start))
        memory.write(TABLE + 0x58, 8, case.valid_until)
        self.write_block(BLOCK_IN, case.block)
        memory.put_bytes(OUT, b"\xef" * 0x50)

    def time_row(self):
        return STATE + 0x2F0

    def run(self, case):
        machine = self.machine
        memory = machine.memory
        self.set_state(case)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(self.time_row(), struct.pack("<iII", *case.now))
        hash_at = HEAP_BASE + 0x1F00
        memory.put_bytes(hash_at, word_bytes(case.block.key))
        before = memory.bytes_at(STATE, STATE_SIZE)
        panicked = None
        try:
            machine.run(REGISTER, {RDI: OUT, RSI: STATE, RDX: self.time_row(), RCX: hash_at, R8: BLOCK_IN, R9: TABLE})
        except Panicked as error:
            panicked = str(error)
        return self.observe(before, panicked)

    def keys_of(self, root_at, height_at, layout):
        memory = self.machine.memory
        keys = []

        def walk(node, depth):
            count = memory.read(node + layout.len_at, 2)
            for index in range(count):
                if depth:
                    walk(memory.read(node + layout.edges_at + 8 * index, 8), depth - 1)
                keys.append(int.from_bytes(memory.bytes_at(node + 32 * index, 32), "big"))
            if depth:
                walk(memory.read(node + layout.edges_at + 8 * count, 8), depth - 1)
        root = memory.read(STATE + root_at, 8)
        if root:
            walk(root, memory.read(STATE + height_at, 8))
        return keys

    def tx_rows(self):
        """Key to (time, tag) of every tx row after the run."""
        memory = self.machine.memory
        layout = TX_LAYOUT
        rows = {}

        def walk(node, depth):
            count = memory.read(node + layout.len_at, 2)
            for index in range(count):
                at = node + layout.val_at + TX_VALUE * index
                rows[int.from_bytes(memory.bytes_at(node + 32 * index, 32), "big")] = (struct.unpack("<iII", memory.bytes_at(at, 12)), memory.read(at + 0x10, 8))
            if depth:
                for index in range(count + 1):
                    walk(memory.read(node + layout.edges_at + 8 * index, 8), depth - 1)
        root = memory.read(STATE + 0x1A0, 8)
        if root:
            walk(root, memory.read(STATE + 0x1A8, 8))
        return rows

    def result(self):
        memory = self.machine.memory
        tag = memory.read(OUT, 8)
        if tag == OK_TAG:
            return ("ok",)
        code = tag - NONE_TAG
        if code in (3, 0x0F):
            return ("err", code, memory.read(OUT + 8, 8), memory.read(OUT + 16, 8))
        if code == 6:
            return ("err", code, int.from_bytes(memory.bytes_at(OUT + 8, 32), "big"))
        if code == 0x0C:
            return ("err", code, memory.bytes_at(OUT + 8, 20), memory.bytes_at(OUT + 0x1C, 20))
        if code == 0x0E:
            texts = []
            for at in (OUT + 8, OUT + 0x20):
                texts.append(memory.bytes_at(memory.read(at + 8, 8), memory.read(at + 16, 8)).decode())
            return ("err", code) + tuple(texts)
        if code == 0:
            return ("err", code) + tuple(memory.read(OUT + 8 + 8 * index, 8) for index in range(4))
        if code == 0x28:
            return ("err", code, memory.read(OUT + 8, 8))
        return ("err", code)

    def observe(self, before, panicked):
        memory = self.machine.memory
        after = memory.bytes_at(STATE, STATE_SIZE)
        changed = sorted({index & ~7 for index in range(0, STATE_SIZE) if before[index] != after[index] and index < 0x2F0}) if before != after else []
        result = ("panic", panicked) if panicked else self.result()
        return dict(result=result, trace=list(self.trace), changed=changed, txs=self.tx_rows(), blocks=self.keys_of(0x1B8, 0x1C0, BLOCK_LAYOUT), rows=sorted(self.rows), wakes=self.wakes, sender=memory.read(SENDER + 0x10, 8), channel=memory.read(CHANNEL + 0x1C0, 8))


class SpecPanic(Exception):
    pass


def spec_set(case, round):
    """The stake set for a round: the last table key at or under the bound."""
    if not case.stakes:
        return None
    limit = min(case.base + RECENT_SPAN, NEVER)
    bound = case.base if round < limit else max(case.base, (round - LOW_ROUNDS) & MASK[8])
    keys = [key for key in case.stakes if key <= bound]
    return case.stakes[max(keys)] if keys else None


def spec_quorum(stakes, signers):
    signed = 0
    for address in sorted(set(signers)):
        signed += stakes.get(address, 0)
        if signed > NEVER:
            raise SpecPanic("stake overflow")
    total = 0
    for value in stakes.values():
        total += value
        if total > NEVER:
            raise SpecPanic("stake overflow")
    return 3 * signed > 2 * total


def recovered(sig, claimed, digest):
    """None for a recover error, else the address the fixture recovers to."""
    if sig.broken:
        return None
    if not sig.good:
        return other_address(signature_bytes(sig, digest, claimed))
    return addr_bytes(claimed if sig.by is None else sig.by)


def spec_qc(case, qc, trace):
    if qc.round > case.valid_until:
        trace.append(("log", "high round"))
    stakes = spec_set(case, qc.round)
    good = False
    if stakes is None:
        result = ("err", 0x28, qc.round)
    else:
        result = None
        for signer, sig in qc.votes:
            got = recovered(sig, signer, digest_qc(qc))
            if signer not in stakes or got != addr_bytes(signer):
                result = ("err", 2)
                break
        if result is None:
            good = spec_quorum(stakes, [signer for signer, _ in qc.votes])
            result = ("ok",) if good else ("err", 9)
    if (qc.version, qc.start) == (case.version, case.start):
        if qc.round < case.start:
            return ("err", 7)
        if qc.round == case.start:
            return ("ok",) if qc.hash == 0 and not qc.votes else ("err", 8)
        return result
    if qc.version > case.version and good:
        raise SpecPanic("newer hardfork")
    return ("err", 0, qc.version, qc.start, case.version, case.start)


def spec_timeout(case, vote, with_qc, trace):
    if vote.round > case.valid_until:
        trace.append(("log", "high round"))
    stakes = spec_set(case, vote.round)
    if stakes is None:
        return ("err", 0x28, vote.round)
    if with_qc:
        result = spec_qc(case, vote.qc, trace)
        if result != ("ok",):
            return result
    if vote.signer in stakes and recovered(vote.sig, vote.signer, digest_vote(vote)) == addr_bytes(vote.signer):
        return ("ok",)
    return ("err", 1)


def spec_tc(case, tc, trace):
    if tc.round > case.valid_until:
        trace.append(("log", "high round"))
    stakes = spec_set(case, tc.round)
    if stakes is None:
        return ("err", 0x28, tc.round)
    if not tc.votes:
        return ("err", 0x0B)
    for vote in tc.votes:
        if vote.round != tc.round:
            return ("err", 0x0F, vote.round, tc.round)
    best = tc.votes[0]
    for vote in tc.votes[1:]:
        if vote.qc.round >= best.qc.round:
            best = vote
    result = spec_timeout(case, best, True, trace)
    if result != ("ok",):
        return result
    first = None
    for vote in tc.votes:
        result = spec_timeout(case, vote, False, trace)
        if result != ("ok",) and first is None:
            first = result
    if first is not None:
        return first
    return ("ok",) if spec_quorum(stakes, [vote.signer for vote in tc.votes]) else ("err", 0x0A)


def spec_block(case, block, trace):
    if case.leader_error is not None:
        code = case.leader_error - NONE_TAG
        return ("err", code, 0x1234) if code == 0x28 else ("err", code)
    if block.proposer != case.leader:
        trace.append(("log", "proposer"))
        return ("err", 0x0C, addr_bytes(block.proposer), addr_bytes(case.leader))
    result = spec_qc(case, block.qc, trace)
    if result != ("ok",):
        return result
    if block.qc.round >= block.round:
        return ("err", 4)
    if block.tc is None:
        return ("ok",)
    if block.tc.round != (block.round - 1) & MASK[8]:
        return ("err", 5)
    return spec_tc(case, block.tc, trace)


def spec_signed(case, block, trace):
    if block.round > case.valid_until:
        trace.append(("log", "high round"))
    stakes = spec_set(case, block.round)
    if stakes is None:
        return ("err", 0x28, block.round)
    result = spec_block(case, block, trace)
    if result != ("ok",):
        return result
    if block.proposer in stakes and recovered(block.sig, block.proposer, digest_block(block)) == addr_bytes(block.proposer):
        return ("ok",)
    return ("err", 1)


def block_text(block):
    return "%d:%s" % (block.round, addr_bytes(block.proposer).hex())


def spec_run(case):
    """The rule list: outcome label and every observation, with no instruction rows."""
    block = case.block
    trace = []
    want = dict(txs={key: ((5, 6, 7), 0x55) for key in case.txs}, blocks=sorted(item.key for item in case.stored), rows=sorted(case.rows), wakes=0, sender=5, channel=1 if case.closed else 8, changed=[])
    try:
        result = spec_signed(case, block, trace)
    except SpecPanic as error:
        want.update(result=("panic", str(error)), trace=trace)
        return "panic " + str(error), want
    label = None
    if result == ("ok",):
        same_round = sorted(item.key for item in case.stored if item.round == block.round)
        if block.round < case.committed:
            result, label = ("err", 3, block.round, case.committed), "below committed"
        elif any(item.key == block.key for item in case.stored):
            result, label = ("err", 6, block.key), "duplicate hash"
        elif same_round:
            old = next(item for item in case.stored if item.key == same_round[0])
            result, label = ("err", 0x0E, block_text(old), block_text(block)), "same round"
    else:
        label = "check %#x" % result[1]
    if result != ("ok",):
        code = result[1]
        trace.append(("err", block.key, code))
        want.update(result=result, trace=trace)
        return label, want
    trace.append(("ok", block.key))
    trace.append(("request gone", block.key))
    changed = set()
    if block.key in case.rows:
        want["rows"] = sorted(key for key in case.rows if key != block.key)
        trace.append(("row dropped",))
    unknown = [key for key in block.hashes if key not in case.txs]
    if unknown:
        trace.append(("unknown", unknown))
        for key in unknown:
            if key not in want["txs"]:
                changed.add(0x1B0)
                if not case.txs:
                    changed.add(0x1A0)
            want["txs"][key] = (tuple(case.now), PLACEHOLDER_TAG)
    if not case.forward_off:
        want["sender"] = 6
        row = ("closed" if case.closed else "send", 0, block.round, block.key)
        trace.append(row)
        if case.closed:
            want["sender"] = 5
        else:
            want["channel"] = 10
            want["wakes"] = 1 if case.waker else 0
    want["blocks"] = sorted(want["blocks"] + [block.key])
    changed.add(0x1C8)
    if not case.stored:
        changed.add(0x1B8)
    want.update(result=("ok",), trace=trace, changed=sorted(changed))
    return "registered", want


def same(got, want):
    return [key for key in want if got[key] != want[key]]


def votes_for(hash_value=0x77, version=2, start=100, round=999, signers=(1, 2, 3), **extra):
    qc = Qc(version, start, round, hash_value)
    qc.votes = [(signer, extra.get("sigs", {}).get(signer) or Sig()) for signer in signers]
    return qc


def ok_block(**extra):
    fields = dict(key=0xB10C, round=1000, proposer=1, hashes=[0x21, 0x22], qc=votes_for(), tc=None, sig=None)
    fields.update(extra)
    return Block(fields["key"], fields["round"], fields["proposer"], fields["hashes"], fields["qc"], fields["tc"], fields["sig"])


def stored(key, round, parent=0x77, hashes=()):
    return Block(key, round, 2, hashes, Qc(2, 100, round - 1, parent))


def tc_for(round=999, qc_rounds=(990, 991, 992), signers=(1, 2, 3), **extra):
    votes = []
    for index, signer in enumerate(signers):
        votes.append(Vote(votes_for(round=qc_rounds[index % len(qc_rounds)], hash_value=0x70 + index), round, signer))
    return Tc(round, votes)


def many(count, stake=10):
    return {index + 1: stake for index in range(count)}


def named_cases():
    cases = []

    def add(name, block=None, **extra):
        cases.append(Case(name, block or ok_block(), **extra))

    # Registration, the plain path.
    add("register plain", txs=[0x21, 0x22])
    add("register no hashes", ok_block(hashes=[]))
    add("register one unknown", txs=[0x21])
    add("register all unknown")
    add("register unknown repeated", ok_block(hashes=[0x31, 0x31, 0x32]))
    add("register known repeated", ok_block(hashes=[0x21, 0x21]), txs=[0x21])
    add("register unknown past leaf end", ok_block(hashes=[0xFF0]), txs=[0x21, 0x22, 0x23])
    add("register unknown between keys", ok_block(hashes=[0x22]), txs=[0x21, 0x23])
    add("register two level tx map", ok_block(hashes=[0x31, 0x24, 0x33, 0x26]), txs=[0x20 + index * 2 for index in range(16)])
    add("register two level tx map found then missing", ok_block(hashes=[0x24, 0x20, 0x35, 0x22]), txs=[0x20 + index * 2 for index in range(16)])
    add("register no tx map unknown second", ok_block(hashes=[0x40, 0x41, 0x42, 0x43, 0x44, 0x45]))
    add("register two level tx map found", ok_block(hashes=[0x24, 0x22]), txs=[0x20 + index * 2 for index in range(16)])
    add("register forward off", txs=[0x21, 0x22], forward_off=True)
    add("register closed channel", txs=[0x21, 0x22], closed=True)
    add("register with waker", txs=[0x21, 0x22], waker=True)
    add("register drops request row", txs=[0x21, 0x22], rows=[0xB10C, 0x999])
    add("register other request row", txs=[0x21, 0x22], rows=[0x999])
    add("register at committed round", ok_block(round=1000), committed=1000, txs=[0x21, 0x22])
    add("register seen tx", ok_block(), txs=[0x21, 0x22], seen=[0x21, 0x5])
    add("register seen other", ok_block(), txs=[0x21, 0x22], seen=[0x1, 0x5, 0xFFF])
    add("register seen tx missing from tx map", ok_block(hashes=[0x31]), seen=[0x31])
    add("register with parent stored", ok_block(), stored=[stored(0x77, 999, 0x76, [0x21, 0x22])], txs=[0x21, 0x22])
    add("register with chain stored", ok_block(), stored=[stored(0x77, 999, 0x76, [0x21]), stored(0x76, 998, 0x75, [0x90]), stored(0x75, 501, 0x74)], txs=[0x21, 0x22])
    add("register chain reaches committed", ok_block(), stored=[stored(0x77, 999, 0x76, [0x21]), stored(0x76, 500, 0x75)], txs=[0x21, 0x22])
    add("register chain below committed", ok_block(), stored=[stored(0x77, 999, 0x76, [0x21]), stored(0x76, 400, 0x75)], txs=[0x21, 0x22])
    add("register ancestor holds same hash", ok_block(hashes=[0x21]), stored=[stored(0x77, 999, 0x76, [0x21])], txs=[0x21])
    add("register ancestor and seen", ok_block(hashes=[0x21, 0x40]), stored=[stored(0x77, 999, 0x76, [0x21, 0x40, 0x50])], seen=[0x21], txs=[0x21])
    add("register over gap", ok_block(round=1005), stored=[stored(0x77, 999, 0x76)], txs=[0x21, 0x22])
    add("register first in empty map", ok_block(), txs=[0x21, 0x22])
    add("register map of other rounds", ok_block(key=0xB000), stored=[stored(0x8000 + index, 900 + index) for index in range(5)], txs=[0x21, 0x22])
    add("register two level block map", ok_block(key=0xB000), stored=[stored(0xA000 + index * 2, 800 + index) for index in range(16)], txs=[0x21, 0x22])
    add("register many other rounds", ok_block(key=0xA000 + 2 * 15 + 1), stored=[stored(0xA000 + index * 2, 800 + index) for index in range(16)], txs=[0x21, 0x22])

    # Round floor, duplicate and same round.
    add("below committed by one", ok_block(round=1000), committed=1001)
    add("far below committed", ok_block(round=1000), committed=5000)
    add("duplicate hash", ok_block(), stored=[stored(0xB10C, 1000)])
    add("duplicate hash other round", ok_block(), stored=[stored(0xB10C, 777)])
    add("duplicate hash in two level map", ok_block(key=0xA000 + 2 * 3), stored=[stored(0xA000 + index * 2, 800 + index) for index in range(16)])
    add("same round other hash", ok_block(), stored=[stored(0xB10D, 1000)])
    add("same round other hash low key", ok_block(), stored=[stored(0xB10B, 1000)])
    add("same round in two level map", ok_block(key=0xFFFF), stored=[stored(0xA000 + index * 2, 1000 if index == 9 else 800 + index) for index in range(16)])
    add("same round first of two", ok_block(key=0xFFFF), stored=[stored(0xA000, 1000), stored(0xA002, 1000)])
    add("below committed wins over duplicate", ok_block(round=1000), committed=1001, stored=[stored(0xB10C, 1000)])
    add("duplicate wins over same round", ok_block(), stored=[stored(0xB10C, 1000), stored(0xB10D, 1000)])
    add("bad block wins over duplicate", ok_block(proposer=2), stored=[stored(0xB10C, 1000)])

    # Proposer and block signature.
    add("wrong proposer", ok_block(proposer=2))
    add("proposer rule error", leader_error=NONE_TAG + 0x28)
    add("proposer rule other error", leader_error=NONE_TAG + 0x10)
    add("proposer not staked", ok_block(proposer=9), leader=9)
    add("block signature broken", ok_block(sig=Sig(broken=True)))
    add("block signature stale digest", ok_block(sig=Sig(good=False)))
    add("block signature other signer", ok_block(sig=Sig(by=2)))
    add("proposer last of two level set", ok_block(proposer=13), leader=13, stakes={0: many(13)}, )
    add("proposer in left leaf of two level set", ok_block(proposer=1), leader=1, stakes={0: many(13)})
    add("proposer on root of two level set", ok_block(proposer=7), leader=7, stakes={0: many(13)})
    add("proposer absent two level set", ok_block(proposer=99), leader=99, stakes={0: many(13)})
    add("signature checked after QC", ok_block(sig=Sig(broken=True), qc=votes_for(round=1500)))
    add("signature checked after TC", ok_block(sig=Sig(broken=True), tc=Tc(999, [])))

    # Stake table lookup.
    add("no stake table", stakes={})
    add("round high warns", valid_until=999, txs=[0x21, 0x22])
    add("round equal limit quiet", valid_until=1000, txs=[0x21, 0x22])
    add("qc round high warns", ok_block(round=1000, qc=votes_for(round=999)), valid_until=998, txs=[0x21, 0x22])
    add("table base over round", base=5000, stakes={5000: many(4)}, committed=0)
    add("lag picks older set", ok_block(round=3000, qc=votes_for(round=2999)), stakes={0: many(4), 2801: {7: 1}}, committed=0, txs=[0x21, 0x22])
    add("lag edge exact", ok_block(round=3000, qc=votes_for(round=2999)), stakes={0: many(4), 2800: many(4)}, committed=0, txs=[0x21, 0x22])
    add("lag edge new set used", ok_block(round=3000, qc=votes_for(round=2999, signers=(1, 2, 3))), stakes={0: {8: 1}, 2800: many(4)}, committed=0, txs=[0x21, 0x22])
    add("qc round one under lag edge", ok_block(round=3000, qc=votes_for(round=2999)), stakes={0: many(4), 2799: {8: 1}}, committed=0, leader=1)
    add("inside recent span uses base", ok_block(round=1999, qc=votes_for(round=1998)), stakes={0: many(4), 1500: {8: 1}}, committed=0, txs=[0x21, 0x22])
    add("span edge first lagged round", ok_block(round=2000, qc=votes_for(round=1999)), stakes={0: many(4), 1800: {8: 1}}, committed=0)
    add("span edge one under lag key", ok_block(round=2000, qc=votes_for(round=1999)), stakes={0: many(4), 1801: {8: 1}}, committed=0, txs=[0x21, 0x22])
    add("base high round low", ok_block(round=3000, qc=votes_for(round=2999)), base=2000, stakes={2000: many(4), 2900: {8: 1}}, committed=0, txs=[0x21, 0x22])
    add("base saturated span", ok_block(round=1000), base=NEVER - 10, stakes={NEVER - 10: many(4)}, committed=0)
    add("base near span end", ok_block(round=NEVER - 5, qc=votes_for(round=NEVER - 6)), base=NEVER - 1000, stakes={NEVER - 1000: many(4)}, committed=0, txs=[0x21, 0x22])
    add("base exactly at saturation edge", ok_block(round=1000), base=(1 << 64) - 2000, stakes={(1 << 64) - 2000: many(4), NEVER - 100: {8: 1}}, committed=0, txs=[0x21, 0x22])
    add("base one under saturation edge", ok_block(round=1000), base=(1 << 64) - 2001, stakes={(1 << 64) - 2001: many(4), NEVER - 100: {8: 1}}, committed=0, txs=[0x21, 0x22])
    add("base top round top", ok_block(round=NEVER, qc=votes_for(round=NEVER - 1)), base=NEVER - 100, stakes={NEVER - 100: many(4)}, committed=0, txs=[0x21, 0x22])
    add("table first key over bound", ok_block(round=3000, qc=votes_for(round=2999)), base=0, stakes={2900: many(4)}, committed=0)
    add("table single key equal bound", ok_block(round=3000, qc=votes_for(round=2999)), base=0, stakes={2800: many(4)}, committed=0, txs=[0x21, 0x22])
    add("table many keys", ok_block(round=30000, qc=votes_for(round=29999)), stakes={index * 1000: many(4) for index in range(14)} | {29500: many(4)}, committed=0, txs=[0x21, 0x22])
    add("table many keys second leaf", ok_block(round=12205, qc=votes_for(round=12204)), stakes={index * 1000: {8: 1} for index in range(14)} | {12000: many(4)}, committed=0, txs=[0x21, 0x22])
    add("table many keys root key", ok_block(round=7200, qc=votes_for(round=7199)), stakes={index * 1000: {8: 1} for index in range(14)} | {7000: many(4)}, committed=0, txs=[0x21, 0x22])
    add("table many keys bound on leaf end", ok_block(round=6200, qc=votes_for(round=6199)), stakes={index * 1000: {8: 1} for index in range(14)} | {5999: many(4)}, committed=0, txs=[0x21, 0x22])

    # QC checks.
    add("qc two of three short", ok_block(qc=votes_for(signers=(1, 2))), stakes={0: many(3)}, committed=0)
    add("qc exact two thirds fails", ok_block(qc=votes_for(signers=(1, 2))), stakes={0: {1: 10, 2: 10, 3: 10}})
    add("qc one over two thirds", ok_block(qc=votes_for(signers=(1, 2))), stakes={0: {1: 11, 2: 10, 3: 10}}, txs=[0x21, 0x22])
    add("qc all signers", ok_block(qc=votes_for(signers=(1, 2, 3, 4))), txs=[0x21, 0x22])
    add("qc no signers", ok_block(qc=votes_for(signers=())))
    add("qc repeated signer counts once", ok_block(qc=votes_for(signers=(1, 2, 1, 2, 1))), stakes={0: many(3)})
    add("qc repeated signer reaches quorum", ok_block(qc=votes_for(signers=(3, 1, 3, 2))), txs=[0x21, 0x22])
    add("qc single signer", ok_block(qc=votes_for(signers=(1,))), stakes={0: {1: 10}}, txs=[0x21, 0x22])
    add("qc signer not staked", ok_block(qc=votes_for(signers=(1, 2, 9))))
    add("qc broken signature", ok_block(qc=votes_for(sigs={2: Sig(broken=True)})))
    add("qc stale digest", ok_block(qc=votes_for(sigs={3: Sig(good=False)})))
    add("qc signature of other signer", ok_block(qc=votes_for(sigs={2: Sig(by=4)})))
    add("qc stake weights", ok_block(qc=votes_for(signers=(1,))), stakes={0: {1: 300, 2: 50, 3: 50}}, txs=[0x21, 0x22])
    add("qc weight one short", ok_block(qc=votes_for(signers=(2, 3))), stakes={0: {1: 300, 2: 50, 3: 50}})
    add("qc huge stakes no wrap", ok_block(qc=votes_for(signers=(1, 2, 3))), stakes={0: {1: 1 << 61, 2: 1 << 61, 3: 1 << 61, 4: 1 << 60}}, txs=[0x21, 0x22])
    add("qc huge stakes short", ok_block(qc=votes_for(signers=(1, 2))), stakes={0: {1: 1 << 61, 2: 1 << 61, 3: 1 << 61, 4: 1 << 60}})
    add("qc double of total past 2^64", ok_block(qc=votes_for(signers=(1, 2, 3, 4))), stakes={0: {1: (1 << 62), 2: (1 << 62), 3: (1 << 62), 4: 5}}, txs=[0x21, 0x22])
    add("qc doubled total carry kept", ok_block(qc=votes_for(signers=(1, 2, 3))), stakes={0: {1: 1 << 62, 2: 1 << 62, 3: 1 << 62, 4: 5}}, txs=[0x21, 0x22])
    add("qc signed sum overflow", ok_block(qc=votes_for(signers=(1, 2))), stakes={0: {1: 1 << 63, 2: 1 << 63}})
    add("qc total overflow", ok_block(qc=votes_for(signers=(1,))), stakes={0: {1: 1 << 62, 2: 1 << 63, 3: 1 << 63}})
    add("qc zero total stake", ok_block(qc=votes_for(signers=(1,))), stakes={0: {1: 0, 2: 0}}, proposer=1)
    add("qc many signers two level", ok_block(qc=votes_for(signers=tuple(range(1, 14)))), stakes={0: many(13)}, txs=[0x21, 0x22])
    add("qc twelve of thirteen", ok_block(qc=votes_for(signers=tuple(range(2, 14)))), stakes={0: many(13)}, leader=2, block2=None)
    add("qc nine of thirteen short", ok_block(qc=votes_for(signers=tuple(range(1, 9)))), stakes={0: many(13)})
    add("qc nine of thirteen pass", ok_block(qc=votes_for(signers=tuple(range(1, 10)))), stakes={0: many(13)}, txs=[0x21, 0x22])
    add("qc round equals block", ok_block(qc=votes_for(round=1000)))
    add("qc round over block", ok_block(qc=votes_for(round=1500)))
    add("qc round far under block", ok_block(qc=votes_for(round=600)), txs=[0x21, 0x22])
    add("qc no stake set", ok_block(round=3000, qc=votes_for(round=150)), stakes={2800: many(4)}, committed=0, base=2500)
    add("qc no stake set same version start edge", ok_block(round=3000, qc=votes_for(version=2, start=150, round=150, hash_value=0, signers=())), stakes={2800: many(4)}, committed=0, base=2500, start=150, txs=[0x21, 0x22])

    # QC version pair.
    add("genesis qc", ok_block(qc=votes_for(round=100, hash_value=0, signers=())), txs=[0x21, 0x22])
    add("genesis qc with hash", ok_block(qc=votes_for(round=100, hash_value=5, signers=())))
    add("genesis qc high hash word", ok_block(qc=votes_for(round=100, hash_value=5 << 200, signers=())))
    add("genesis qc with votes", ok_block(qc=votes_for(round=100, hash_value=0)))
    add("qc under start", ok_block(qc=votes_for(round=99)))
    add("qc one over start", ok_block(qc=votes_for(round=101)), txs=[0x21, 0x22])
    add("qc one over start bad votes", ok_block(qc=votes_for(round=101, signers=(1,))))
    add("older version", ok_block(qc=votes_for(version=1)))
    add("older version start differs", ok_block(qc=votes_for(version=1, start=7)))
    add("same version other start", ok_block(qc=votes_for(start=101)))
    add("same version other start low", ok_block(qc=votes_for(start=99)))
    add("newer version good votes panics", ok_block(qc=votes_for(version=3)))
    add("newer version short votes", ok_block(qc=votes_for(version=3, signers=(1,))))
    add("newer version bad signature", ok_block(qc=votes_for(version=3, sigs={2: Sig(broken=True)})))
    add("newer version no stake set", ok_block(round=3000, qc=votes_for(version=3, round=150)), stakes={2800: many(4)}, committed=0, base=2500)
    add("same version start higher good votes", ok_block(qc=votes_for(start=500)))

    # TC checks.
    add("tc good", ok_block(qc=votes_for(round=990), tc=tc_for()), txs=[0x21, 0x22])
    add("tc two qc rounds tie", ok_block(qc=votes_for(round=990), tc=tc_for(qc_rounds=(990, 990, 990))), txs=[0x21, 0x22])
    add("tc four votes", ok_block(qc=votes_for(round=990), tc=tc_for(signers=(1, 2, 3, 4), qc_rounds=(1, 900, 3, 2))), txs=[0x21, 0x22], stakes={0: many(4)})
    add("tc five votes", ok_block(qc=votes_for(round=990), tc=tc_for(signers=(1, 2, 3, 4, 1), qc_rounds=(1, 2, 950, 4, 3))), txs=[0x21, 0x22])
    add("tc round not previous", ok_block(qc=votes_for(round=990), tc=tc_for(round=998)))
    add("tc round equals block", ok_block(qc=votes_for(round=990), tc=tc_for(round=1000)))
    add("tc empty", ok_block(qc=votes_for(round=990), tc=Tc(999, [])))
    add("tc vote round differs first", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(votes_for(round=990), 998, 1)])))
    good = votes_for(round=991)
    add("tc vote round differs last", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1), Vote(good, 999, 2), Vote(good, 1000, 3)])))
    add("tc no quorum", ok_block(qc=votes_for(round=990), tc=tc_for(signers=(1, 2))), stakes={0: many(3)})
    add("tc repeated voter counts once", ok_block(qc=votes_for(round=990), tc=tc_for(signers=(1, 2, 1, 2))), stakes={0: many(3)})
    add("tc voter not staked", ok_block(qc=votes_for(round=990), tc=tc_for(signers=(1, 2, 9))))
    add("tc voter signature broken", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1), Vote(good, 999, 2, Sig(broken=True)), Vote(good, 999, 3)])))
    add("tc voter stale digest", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1, Sig(good=False)), Vote(good, 999, 2), Vote(good, 999, 3)])))
    add("tc voter other signer", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1), Vote(good, 999, 2), Vote(good, 999, 3, Sig(by=4))])))
    bad = votes_for(round=995, signers=(1,))
    low_bad = votes_for(round=900, signers=(1,))
    add("tc highest qc bad", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1), Vote(bad, 999, 2), Vote(good, 999, 3)])))
    add("tc lower qc bad is ignored", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1), Vote(low_bad, 999, 2), Vote(good, 999, 3)])), txs=[0x21, 0x22])
    tie_bad = votes_for(round=991, signers=(1,))
    add("tc tie takes the later vote", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(tie_bad, 999, 1), Vote(good, 999, 2), Vote(good, 999, 3)])), txs=[0x21, 0x22])
    add("tc tie later vote bad", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1), Vote(good, 999, 2), Vote(tie_bad, 999, 3)])))
    add("tc pair tie later bad", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1), Vote(tie_bad, 999, 2)])), stakes={0: {1: 10, 2: 10}})
    add("tc pair tie first bad", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(tie_bad, 999, 1), Vote(good, 999, 2)])), stakes={0: {1: 10, 2: 10}}, txs=[0x21, 0x22])
    add("tc single vote", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1)])), stakes={0: {1: 10}}, txs=[0x21, 0x22])
    add("tc single vote bad qc", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(bad, 999, 1)])), stakes={0: {1: 10}})
    add("tc high round warns", ok_block(qc=votes_for(round=990), tc=tc_for()), valid_until=998, txs=[0x21, 0x22])
    add("tc no stake set", ok_block(round=3000, qc=votes_for(round=2000), tc=Tc(2999, [Vote(good, 2999, 1)])), stakes={2800: many(4)}, base=2500, committed=0)
    add("tc with qc round after tc round", ok_block(qc=votes_for(round=999), tc=tc_for()), txs=[0x21, 0x22])
    add("no tc qc gap", ok_block(qc=votes_for(round=700)), txs=[0x21, 0x22])
    add("tc older version in highest qc", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1), Vote(votes_for(round=996, version=1), 999, 2), Vote(good, 999, 3)])))
    add("tc newer version in highest qc panics", ok_block(qc=votes_for(round=990), tc=Tc(999, [Vote(good, 999, 1), Vote(votes_for(round=996, version=3), 999, 2), Vote(good, 999, 3)])))
    return cases


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 33


def vector_cases(count):
    """Deterministic mixes: each draws a stake table, a quorum set, a QC, an optional TC and a stored map."""
    numbers = lcg(0x44B8410)

    def pick(limit):
        return next(numbers) % limit

    cases = []
    for index in range(count):
        size = 3 + pick(5)
        stakes = {address + 1: 1 + pick(20) for address in range(size)}
        chosen = [address for address in stakes if pick(5)]
        if pick(4) == 0:
            chosen = chosen + chosen[:1]
        round = 1000 + pick(50)
        version = (2, 2, 2, 2, 1, 3)[pick(6)]
        qc_round = (round - 1 - pick(3), round - 1 - pick(3), round, 101, 100)[pick(5)]
        sigs = {}
        if pick(6) == 0 and chosen:
            sigs[chosen[pick(len(chosen))]] = (Sig(broken=True), Sig(good=False))[pick(2)]
        qc = votes_for(round=qc_round, version=version, signers=tuple(chosen), hash_value=pick(4) or 0x77, sigs=sigs)
        tc = None
        if pick(3) == 0:
            base_round = round - 1 - pick(2 if pick(4) == 0 else 1)
            votes = []
            for voter in chosen:
                vote_qc = votes_for(round=900 + pick(4), signers=tuple(stakes), hash_value=0x60 + voter)
                sig = Sig(broken=True) if pick(10) == 0 else None
                votes.append(Vote(vote_qc, base_round if pick(9) else base_round + 1, voter, sig))
            tc = Tc(base_round, votes)
        hashes = [0x20 + pick(9) for _ in range(pick(4))]
        rows = []
        map_keys = sorted({0xA000 + pick(40) for _ in range(pick(6))})
        for key in map_keys:
            rows.append(stored(key, 950 + pick(100), (0x77, 0xA000 + pick(40))[pick(2)], (0x20 + pick(9),)))
        leader = 1 if pick(8) else 2
        block = Block((0xA000 + pick(40)) if pick(3) == 0 else 0xB000 + index, round, 1, hashes, qc, tc, (None, None, None, None, Sig(broken=True), Sig(good=False))[pick(6)])
        cases.append(Case("vector %d" % index, block, stakes={0: stakes}, leader=leader, committed=(500, 990, round, round + 1)[pick(4)] if pick(3) == 0 else 500, stored=rows, txs=sorted({0x20 + pick(9) for _ in range(pick(7))}), seen=sorted({0x20 + pick(9) for _ in range(pick(3))}),
                          forward_off=pick(5) == 0, closed=pick(9) == 0, waker=pick(3) == 0, rows=[0xB000 + index] if pick(4) == 0 else [], valid_until=10 ** 9 if pick(5) else round - 2))
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
    ('arm', 0x44af43e, 'e80dcc0900', 'digest variant 0 gives the block hash'),
    ('arm', 0x44af46d, 'e8fe982a00', 'verify_qc before admission'),
    ('arm', 0x44af484, '0f85310f0000', 'failure skips the QC record'),
    ('arm', 0x44af4f3, 'e868c0ffff', 'call 0x44ab560'),
    ('arm', 0x44b0421, 'e8ea7f0000', 'admission'),
    ('arm', 0x44b0f6c, 'e89f740000', 'admission in the list loop'),
    ('arm', 0x44b1802, 'e869a1ffff', 'commit attempt on the shared tail'),
    ('register', 0x44b8445, 'e8b6320900', 'call 0x454b700: verify first'),
    ('register', 0x44b8463, '4d8b8e88000000', 'load block round'),
    ('register', 0x44b846a, '488b8598010000', 'load committed round'),
    ('register', 0x44b8471, '4939c1', 'compare'),
    ('register', 0x44b8474, '0f83f0000000', 'jae: equal passes'),
    ('register', 0x44b847a, '498d4c24d9', 'tag 3'),
    ('register', 0x44b864c, '498d4424dc', 'tag 6'),
    ('register', 0x44b86a7, '4c69c5f8000000', 'block row stride 0xf8'),
    ('register', 0x44b86ba, '4e398c02f0010000', 'round compare at row +0x88'),
    ('register', 0x44b8927, '498d4424e4', 'tag 0xe'),
    ('register', 0x44b888f, 'e86c0f0000', 'call 0x44b9800'),
    ('register', 0x44b920e, '498b4610', 'lookup loop start'),
    ('register', 0x44b9416, '49bc2a00000000000080', 'lookup loop end, success word'),
    ('register', 0x44b8a2c, 'c68424c000000000', 'request key tag byte 0'),
    ('register', 0x44b8a4b, 'e810cf4800', 'call 0x4945960'),
    ('register', 0x44b8ad0, 'e81b723000', 'call 0x47bfcf0'),
    ('register', 0x44b8b52, '498d4424d7', 'placeholder tag'),
    ('register', 0x44b8e10, '80bd3002000000', 'forward flag'),
    ('register', 0x44b8f12, '0f85dd000000', 'closed bit'),
    ('register', 0x44b8f31, '498d4424d6', 'channel row word'),
    ('register', 0x44b91d5, 'e8e6084a00', 'call 0x4959ac0'),
    ('verify_signed', 0x454b72a, '7673', 'jbe past the warning'),
    ('verify_signed', 0x454b7b4, '0f8455010000', 'none: tag 0x28'),
    ('verify_signed', 0x454b7ef, 'ff152bb22201', 'call slot 0x5776a20'),
    ('verify_signed', 0x454b81b, 'e830080000', 'digest variant 0'),
    ('verify_signed', 0x454b96a, 'ff15e8442201', 'recover slot'),
    ('verify_signed', 0x454b9cb, '3dffff0000', 'all 20 bytes'),
    ('verify_signed', 0x454ba25, '4983c6d9', 'tag 1'),
    ('verify_block', 0x47b01e3, 'ff153f34fc00', 'proposer rule slot'),
    ('verify_block', 0x47b0265, '3dffff0000', 'all 20 bytes'),
    ('verify_block', 0x47b039d, '4983c5e2', 'tag 0xc'),
    ('verify_block', 0x47b0405, 'e86689faff', 'call verify_qc'),
    ('verify_block', 0x47b0410, '4d396640', 'QC round compare'),
    ('verify_block', 0x47b0414, '736a', 'jae: strict'),
    ('verify_block', 0x47b041a, '49394668', 'TC None test'),
    ('verify_block', 0x47b0420, '49ffcc', 'block round - 1'),
    ('verify_block', 0x47b0423, '4d39a680000000', 'TC round compare'),
    ('verify_block', 0x47b0439, 'e8b290faff', 'call verify_tc'),
    ('verify_block', 0x47b0480, '4983c5da', 'tag 4'),
    ('verify_block', 0x47b0489, '4983c5db', 'tag 5'),
    ('verify_qc', 0x4758da6, '483b4258', 'high round compare'),
    ('verify_qc', 0x4758f26, '48c744243001000000', 'digest variant 1'),
    ('verify_qc', 0x4759045, 'ff150d6e0101', 'recover slot'),
    ('verify_qc', 0x47590bd, 'e8de87cfff', 'signer set'),
    ('verify_qc', 0x47590ca, 'ff1518da0101', 'quorum slot'),
    ('verify_qc', 0x4759195, '498d47e1', 'tag 9'),
    ('verify_qc', 0x47591b9, '498d47da', 'tag 2'),
    ('verify_qc', 0x47591d8, '498b4c2440', 'pair word 0'),
    ('verify_qc', 0x47591dd, '498b442448', 'pair word 1'),
    ('verify_qc', 0x47591f9, '751b', 'pair branch'),
    ('verify_qc', 0x47591fb, '48398424b0000000', 'start round compare'),
    ('verify_qc', 0x4759205, '4983c7df', 'tag 7'),
    ('verify_qc', 0x4759216, '4839ca', 'first word only'),
    ('verify_qc', 0x4759219, '400f97c7', 'seta'),
    ('verify_qc', 0x4759220, '0f85e6000000', 'to the panic'),
    ('verify_qc', 0x4759226, '4983c7d8', 'tag 0'),
    ('verify_qc', 0x4759283, '3dffff0000', 'hash all zero'),
    ('verify_qc', 0x475928a, '48837b1000', 'no votes'),
    ('verify_qc', 0x47592fa, '4983c7e0', 'tag 8'),
    ('verify_qc', 0x4759366, 'ff152c4d0101', 'panic call'),
    ('verify_tc', 0x47595e8, '0f8485000000', 'no votes'),
    ('verify_tc', 0x4759605, '4c39f1', 'vote round compare'),
    ('verify_tc', 0x4759600, '498b4c0450', 'vote round at +0x50'),
    ('verify_tc', 0x47596d1, '4d0f47cf', 'tie keeps the later'),
    ('verify_tc', 0x475971b, '4c0f46f8', 'last odd vote'),
    ('verify_tc', 0x475974a, 'b901000000', 'flag 1'),
    ('verify_tc', 0x475974f, 'e8bc12dfff', 'call 0x454aa10'),
    ('verify_tc', 0x475982b, 'e850f70000', 'parallel loop'),
    ('verify_tc', 0x4759855, 'e8367ecfff', 'voter set'),
    ('verify_tc', 0x4759865, 'ff157dd20101', 'quorum slot'),
    ('verify_tc', 0x475993f, '4983c4e0', 'tag 0xa'),
    ('verify_tc', 0x4759673, '4983c4e1', 'tag 0xb'),
    ('verify_tc', 0x4759689, '4883c0e5', 'tag 0xf'),
    ('verify_timeout', 0x454aaf3, '4084ed', 'flag'),
    ('verify_timeout', 0x454ab03, 'e868e22000', 'call verify_qc'),
    ('verify_timeout', 0x454aae5, '48c744243002000000', 'digest variant 2'),
    ('verify_timeout', 0x454ac3e, 'ff1514522201', 'recover slot'),
    ('quorum', 0x4ad93ca, '4c0354d808', 'add stake'),
    ('quorum', 0x4ad944f, '4a034cda08', 'add total'),
    ('quorum', 0x4ad9612, 'ba03000000', '3'),
    ('quorum', 0x4ad961a, '48f7e2', 'mul signed'),
    ('quorum', 0x4ad961d, '4801c9', 'double total'),
    ('quorum', 0x4ad9620, '4839c1', 'low'),
    ('quorum', 0x4ad9623, '4819d6', 'high'),
    ('quorum', 0x4ad9626, '0f92c0', 'setb'),
    ('stake_set', 0x42c9947, '4881fa30f8ffff', 'near the top'),
    ('stake_set', 0x42c9953, '4881c1d0070000', 'add 2000'),
    ('stake_set', 0x42c9967, '4c8d82d0070000', 'add 2000'),
    ('stake_set', 0x42c996e, '488d8838ffffff', 'round - 200'),
    ('stake_set', 0x42c9978, '480f47ca', 'max with base'),
    ('stake_set', 0x42c997f, '480f42ca', 'under limit: base'),
    ('stake_set', 0x42c998c, 'e86f07ffff', 'range walk'),
)
SLOTS = ((0x5776A20, 0x47B01B0, "called at 0x454b7ef"), (0x5776AE8, 0x4AD90D0, "called at 0x47590ca and 0x4759865"), (0x5773628, 0x4B31E70, "called at 0x47b01e3"), (0x576FE58, 0x14C6F50, "called at 0x454b96a, 0x4759045, 0x454ac3e"), (0x576E978, 0x143D010, "warning log, returns"))


TAGS = ((0x00, 0x4759226, "QC version pair differs: QC pair, then node pair, payload four words"), (0x01, 0x454BA25, "block or timeout signature: signer unknown, recover failed, or recovered other address; payload text"), (0x02, 0x47591B9, "a QC vote: signer unknown, recover failed, or recovered other address"),
        (0x03, 0x44B847A, "block round under committed round: block round, committed round"), (0x04, 0x47B0480, "QC round at or over block round"), (0x05, 0x47B0489, "TC round is not block round minus one"), (0x06, 0x44B864C, "block hash already in the block map: hash"),
        (0x07, 0x4759205, "QC at the node pair under the start round"), (0x08, 0x47592FA, "QC at the start round is not the empty genesis QC"), (0x09, 0x4759195, "QC votes short of quorum"), (0x0A, 0x475993F, "TC voters short of quorum"), (0x0B, 0x4759673, "TC with no votes"),
        (0x0C, 0x47B039D, "proposer differs from the rule's proposer: block proposer, expected proposer"), (0x0E, 0x44B8927, "another block at this round: stored block text, this block text"), (0x0F, 0x4759689, "TC vote round differs: vote round, TC round"), (0x28, 0x454B914, "no stake set for the round: round"), (0x2A, 0x47B01C9, "success value, not an error"))
GATES = (("verify_signed", 1, 0x454B72A, "block round over table +0x58: warning `Querying stakes for high round`, then go on", "no stop", ""),
         ("verify_signed", 2, 0x454B7B4, "stake set lookup for the block round", "tag 0x28", "check 0x28"),
         ("verify_block", 3, 0x47B0208, "proposer rule for the block round succeeds", "its error, unchanged", "check 0x10"),
         ("verify_block", 4, 0x47B026A, "block +0x9c equals the rule's proposer, all 20 bytes", "warning, tag 0x0c", "check 0xc"),
         ("verify_block", 5, 0x47B040E, "QC at block +0x18 verifies", "its error, unchanged", "check 0x9"),
         ("verify_block", 6, 0x47B0414, "QC round is strictly under block round; no lower bound, a gap passes", "tag 4", "check 0x4"),
         ("verify_block", 7, 0x47B041E, "no TC: success here, so a QC gap needs no TC", "", ""),
         ("verify_block", 8, 0x47B042A, "TC round == block round - 1", "tag 5", "check 0x5"),
         ("verify_block", 9, 0x47B0442, "TC verifies", "its error, unchanged", "check 0xa"),
         ("verify_signed", 10, 0x454B8E4, "proposer found in the stake set of the block round", "tag 1", "check 0x1"),
         ("verify_signed", 11, 0x454B974, "recover of signature +0xb0 over digest variant 0 succeeds", "tag 1", "check 0x1"),
         ("verify_signed", 12, 0x454B9DF, "recovered address equals the proposer", "tag 1", "check 0x1"),
         ("register", 13, 0x44B8474, "block round >= state +0x198; equal passes", "tag 3", "below committed"),
         ("register", 14, 0x44B85F8, "block hash not in the block map at state +0x1b8", "tag 6", "duplicate hash"),
         ("register", 15, 0x44B86C2, "no stored block has this round; rows are read in key order and the first hit is named", "tag 0x0e with both block texts", "same round"),
         ("register", 16, 0x44B888F, "ancestor walk 0x44b9800 from the block's QC hash, then a loop over the block's hashes at 0x44b9284 that looks in the seen map and the walk's set; neither result is used", "no stop", ""),
         ("register", 17, 0x44B8A4B, "request row (tag byte 0, block hash) leaves the map at state +0x1d0", "no stop", ""),
         ("register", 18, 0x44B8AD0, "hashes absent from the tx map are collected in block order, repeats kept", "no stop", ""),
         ("register", 19, 0x44B8BFA, "each unknown hash gets a tx row: event time, tag 0x8000000000000001; a repeat rewrites the same row", "no stop", ""),
         ("register", 20, 0x44B8E17, "state +0x230 clear: block clone goes to the channel at state +0x158 as a row with word 0x8000000000000000, box, hash", "skip", ""),
         ("register", 21, 0x44B8F12, "channel word +0x1c0 bit 0 set: row dropped and sender count returned", "row pushed, word + 2, waker fired once", ""),
         ("register", 22, 0x44B91D5, "block goes into the map under the caller's hash; the assertion text at 0x44b9141 guards a second insert", "", "registered"))
QC_GATES = (("verify_qc", 1, 0x4758DAA, "QC round over table +0x58: warning, go on", "no stop", ""),
            ("verify_qc", 2, 0x4758E56, "stake set for the QC round; none skips the signature loop and holds tag 0x28", "held tag 0x28", ""),
            ("verify_qc", 3, 0x4758F46, "digest variant 1 over 0x38 bytes: QC hash +0x30, pair +0x18, round +0x28", "", ""),
            ("verify_qc", 4, 0x4758FFC, "vote signer in the stake set", "held tag 2, loop ends", "check 0x2"),
            ("verify_qc", 5, 0x4759050, "recover of the vote signature at row +0x18", "held tag 2, loop ends", "check 0x2"),
            ("verify_qc", 6, 0x4759085, "recovered address equals the row's signer", "held tag 2, loop ends", "check 0x2"),
            ("verify_qc", 7, 0x47590CA, "signers go to a sorted unique set, quorum 0x4ad90d0 over it", "held tag 9", "check 0x9"),
            ("verify_qc", 8, 0x47591F9, "QC pair +0x18,+0x20 against table +0x40,+0x48; both words", "next rows", ""),
            ("verify_qc", 9, 0x4759220, "pair differs, first word higher and quorum passed: panic `observed qc for newer hardfork, crashing`", "tag 0 with both pairs, any held result dropped", "panic newer hardfork"),
            ("verify_qc", 10, 0x4759203, "pair equal, QC round under the start round", "tag 7", "check 0x7"),
            ("verify_qc", 11, 0x4759288, "pair equal, QC round == start round: QC hash all zero and 0 votes", "tag 8", "check 0x8"),
            ("verify_qc", 12, 0x475928F, "same: success with no quorum read, the held result is dropped", "", ""),
            ("verify_qc", 13, 0x475929F, "pair equal, QC round over start round: the held result is the answer", "", ""),
            ("verify_tc", 14, 0x4759519, "TC round over table +0x58: warning, go on", "no stop", ""),
            ("verify_tc", 15, 0x47595AC, "stake set for the TC round", "tag 0x28", ""),
            ("verify_tc", 16, 0x47595E8, "at least one vote", "tag 0x0b", "check 0xb"),
            ("verify_tc", 17, 0x4759608, "every vote round +0x50 equals the TC round, first mismatch named", "tag 0x0f", "check 0xf"),
            ("verify_tc", 18, 0x47596E3, "highest vote QC round +0x28 is chosen; the later vote wins a tie", "", ""),
            ("verify_tc", 19, 0x4759754, "0x454aa10 flag 1 on that vote: only this QC is verified", "its error", ""),
            ("verify_tc", 20, 0x475982B, "0x4768f80: every vote through 0x454aa10 flag 0 (site 0x476f448)", "its error", "check 0x1"),
            ("verify_tc", 21, 0x4759939, "voters go to a sorted unique set, quorum 0x4ad90d0", "tag 0x0a", "check 0xa"),
            ("verify_timeout", 22, 0x454AAF6, "flag set: QC at vote +0 verifies before the signature", "its error", ""),
            ("verify_timeout", 23, 0x454ACCC, "vote signer +0x58 in the set, recover of +0x70 over digest variant 2, same address", "tag 1", "check 0x1"),
            ("quorum", 24, 0x4AD93CA, "each set address found in the stake tree adds its stake; a missing one adds nothing; carry panics", "panic", "panic stake overflow"),
            ("quorum", 25, 0x4AD944F, "all stakes in the tree add up; carry panics", "panic", "panic stake overflow"),
            ("quorum", 26, 0x4AD9623, "3 * signed > 2 * total on 128 bit values, strict", "false", "check 0x9"),
            ("stake_set", 27, 0x42C9947, "limit = table +0 + 2000, saturating", "", ""),
            ("stake_set", 28, 0x42C997F, "round < limit: bound = table +0; otherwise bound = max(table +0, round - 200)", "", ""),
            ("stake_set", 29, 0x42C998C, "answer = the last table key at or under bound", "none", "check 0x28"))
LAYOUT = (("signed block", 0x0, 0x18, "tx hash vector: cap, ptr, len", 0x44B8A82), ("signed block", 0x18, 0x50, "QC", 0x47B03FB), ("signed block", 0x68, 0x20, "TC, None when word +0x68 is 0x8000000000000000", 0x47B041A), ("signed block", 0x88, 8, "round", 0x44B8463),
          ("signed block", 0x9C, 0x14, "proposer", 0x47B023E), ("signed block", 0xB0, 0x48, "signature", 0x454B83A),
          ("QC", 0x0, 0x18, "vote vector: cap, ptr, len; row 0x60", 0x4758E82), ("QC", 0x18, 0x10, "pair: version word, start round word", 0x47591E2), ("QC", 0x28, 8, "round", 0x4758D92), ("QC", 0x30, 0x20, "block hash", 0x4758EC4),
          ("QC vote row", 0x0, 0x14, "signer", 0x4758F5D), ("QC vote row", 0x18, 0x48, "signature", 0x4758F83),
          ("TC", 0x0, 0x18, "vote vector: cap, ptr, len; row 0xb8", 0x47595E1), ("TC", 0x18, 8, "round", 0x475950A),
          ("timeout vote", 0x0, 0x50, "QC", 0x454AB03), ("timeout vote", 0x50, 8, "round", 0x454AA2C), ("timeout vote", 0x58, 0x14, "signer", 0x454AB3E), ("timeout vote", 0x70, 0x48, "signature", 0x454AB49),
          ("stake table", 0x0, 8, "base round", 0x42C9944), ("stake table", 0x8, 0x10, "tree root, height: round to stake tree", 0x42C9937), ("stake table", 0x40, 0x10, "node pair: version word, start round word", 0x47591D8), ("stake table", 0x58, 8, "estimated_stakes_valid_until", 0x4758DA6),
          ("stake tree node", 0x8, 0x58, "stake u64 values", 0x4AD93CA), ("stake tree node", 0x60, 0xDC, "20 byte address keys", 0x4AD930A), ("stake tree node", 0x13E, 2, "length", 0x4AD9313), ("stake tree node", 0x140, 0x60, "children", 0x4AD93AA),
          ("address set node", 0x8, 0xDC, "20 byte keys", 0x4AD92FC), ("address set node", 0xE6, 2, "length", 0x4AD913A), ("address set node", 0xE8, 0x60, "children", 0x4AD9180),
          ("state", 0x198, 8, "committed round", 0x44B846A), ("state", 0x1A0, 0x18, "tx map root, height, length", 0x44B8A99), ("state", 0x1B8, 0x18, "block map root, height, length", 0x44B8574), ("state", 0x1D0, 0x18, "request map", 0x44B8A34), ("state", 0x230, 1, "forward off flag", 0x44B8E10), ("state", 0x158, 0x10, "channel, sender count object", 0x44B8EE9))
STRINGS = ((0x6F4E1D, "verify_block"), (0x6F4E29, "err"), (0x6F4E2C, "ok"), (0x20CCA0, "register_block unknown tx hashes"), (0x6F4E2E, "assertion failed: self.block_hash_to_block.insert(block_hash, signed_block).is_none()"),
           (0x1E8C49, "Querying stakes for high round, is execution behind?"), (0X1E8C90, "self.estimated_stakes_valid_until"), (0x1E2D6B, "Unexpected proposer for block. Is execution behind?"), (0x1E6911, "observed qc for newer hardfork, crashing. current="), (0x1FD736, "payload="))
LOCATIONS = ((0x44B9148, 0x5720078, "block_hash_to_block assertion"), (0x47B035D, 0x572FB30, "unexpected proposer warning"), (0x454B785, 0x5738668, "high round warning"), (0x475935A, 0x572EF98, "newer hardfork panic"))
TRIGGERS = ((0x44B0421, 0x44ADFA0, "block event arm: block hash from digest variant 0 at 0x44af43e, verify_qc at 0x44af46d, 0x44ab560 only if that passes, then this call whatever it returned"),
            (0x44B0F6C, 0x44ADFA0, "loop over a list of 0x130 byte rows; an error here is logged at 0x44b0fe9 and the loop goes on"))
PIN_SITES = ()
SURVIVOR_LOOP = (0x44B920E, 0x44B9416)
SURVIVOR_WALK = (0x44B9800, 0x44B9A4A)
SURVIVOR_CALL = (0x44B888F, 0x44B88B9)


def survivor_reason(va, kind):
    if any(low <= va < high for low, high in (SURVIVOR_LOOP, SURVIVOR_WALK, SURVIVOR_CALL)):
        return "row of the lookup loop whose result is unused"
    return "not classified"


def text_rows(image, start):
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


def scan_triggers(image):
    sites = scan_call_sites(image, REGISTER)
    if sites != [row[0] for row in TRIGGERS]:
        raise EvidenceError("call sites differ: %s" % sites)
    if REGISTER in image.relative().values():
        raise EvidenceError("a relocation names the admission body")
    return sites


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
    for va in [row[2] for group in (GATES, QC_GATES) for row in group] + [row[4] for row in LAYOUT] + [row[1] for row in TAGS]:
        for _ in (0,):
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
    for row in table:
        if va in row[3]:
            groups.setdefault(row[4], []).append(row[2])
    chosen = []
    depth = 0
    while len(chosen) < MUTANT_CAP and any(depth < len(rows) for rows in groups.values()):
        for label in sorted(groups):
            if depth < len(groups[label]) and len(chosen) < MUTANT_CAP:
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


def analyse(image, mutate=True, vectors=300):
    triggers = scan_triggers(image)
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
    result = dict(triggers=triggers, pins=pins, slots=slots, strings=strings, locations=locations, cases=cases, rows=rows, reached=reached, vector_count=vectors, labels=labels, decoded=decoded)
    for group in (GATES, QC_GATES):
        for _, _, _, _, _, label in group:
            if label and label not in labels:
                raise EvidenceError("gate outcome never reached: %s" % label)
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
    tsv("qc-tc-gates.tsv", ("group", "order", "site", "rule", "otherwise", "outcome_label", "cases"), [(group, order, "%#x" % va, rule, other or "-", label or "-", count(label)) for group, order, va, rule, other, label in QC_GATES])
    tsv("error-tags.tsv", ("tag_low_byte", "site", "meaning", "cases"), [("%#x" % tag, "%#x" % va, meaning, sum(value for name, value in labels.items() if name == "check %#x" % tag)) for tag, va, meaning in TAGS])
    tsv("functions.tsv", ("function", "end", "bytes", "reached_bytes", "role"), [("%#x" % start, "%#x" % image.exact_fde(start)[1], image.exact_fde(start)[1] - start, result["reached"][start], ROLES[start]) for start in STATIC_FUNCTIONS])
    tsv("stubs.tsv", ("target", "kind", "what"), [("%#x" % key, "direct call", text) for key, text in sorted(STUBS.items())] + [("%#x" % key, "data slot", text) for key, text in sorted(SLOT_STUBS.items())])
    tsv("triggers.tsv", ("site", "host", "context"), [("%#x" % site, "%#x" % host, text) for site, host, text in TRIGGERS])
    tsv("layouts.tsv", ("record", "offset", "size", "field", "site"), [(record, "%#x" % offset, "%#x" % size, field, "%#x" % site) for record, offset, size, field, site in LAYOUT])
    tsv("pins.tsv", ("group", "address", "bytes", "meaning"), [(group, "%#x" % va, text, meaning) for group, va, text, meaning in PINS])
    tsv("slots.tsv", ("slot", "target", "use"), [("%#x" % slot, "%#x" % target, use) for slot, target, use in result["slots"]])
    tsv("strings.tsv", ("address", "text"), [("%#x" % va, text) for va, text in result["strings"]])
    tsv("locations.tsv", ("site", "data", "path", "line", "column", "use"), result["locations"])
    tsv("outcomes.tsv", ("outcome", "cases"), sorted(labels.items()))
    rows = []
    for case, label, got in result["rows"]:
        rows.append((case.name, label, case.block.round, case.block.qc.round, "%d" % len(case.block.qc.votes), "-" if case.block.tc is None else len(case.block.tc.votes), len(got["blocks"]), len(got["txs"])))
    tsv("cases.tsv", ("case", "outcome", "block_round", "qc_round", "qc_votes", "tc_votes", "blocks_after", "txs_after"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("function", "address", "kind", "outcome", "detail"), [("%#x" % host, "%#x" % va, kind, outcome, detail) for host, va, kind, outcome, detail in result["mutations"]])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "cases": len(result["cases"]), "vector_cases": result["vector_count"], "named_cases": len(result["cases"]) - result["vector_count"], "functions_run": len(STATIC_FUNCTIONS),
               "reached_bytes": sum(result["reached"].values()), "function_bytes": sum(image.exact_fde(start)[1] - start for start in STATIC_FUNCTIONS), "pins": result["pins"], "call_sites": len(result["triggers"]), "gates": len(GATES) + len(QC_GATES), "rows_decoded": result["decoded"]}
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[3] == "killed"), "survived": sum(1 for r in rows if r[3] == "survived"), "lookup_loop_survivors": sum(1 for r in rows if r[3] == "survived" and r[4].startswith("row of the lookup"))}
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
