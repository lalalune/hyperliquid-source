#!/usr/bin/env python3
"""Pin the node #94 gossip priority bid handler gates and its IPv4 parser from ELF bytes.

0x2727bc0 takes a slot id, an optional gas limit and a parsed IPv4 word. It refuses a disabled auction
list and a slot past its end, asks the auction for its price, compares the price with the limit, then
requires hold + price <= total of the user's gas token, wrap included. 0x2206560 runs the charge and
stores the bidder's IPv4 as the slot's `cw` word. 0x1573af0 is the dotted decimal parser. The real bytes
run under recording stubs over real B-tree nodes, a separately written rule list predicts every run
including all fixture bytes, and every reached conditional row is mutated. No objdump or readelf output
is parsed and the binary is never executed. Standard library only.

    python3 tools/gossip_bid_gates.py --out <dir>
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


HANDLER = 0x2727BC0
CHARGE = 0x2206560
PARSER = 0x1573AF0
TARGETS = (HANDLER, CHARGE, PARSER)
NAMES = {HANDLER: "bid_handler", CHARGE: "charge_wrapper", PARSER: "ipv4_parser"}

SLOT_PRICE = 0x57739B8
SLOT_USER = 0x5773170
PRICE_TARGET = 0x325CCB0
INFO = 0x3987CB0
DROP_DISABLED = 0x277EBA0
DROP_SLOT = 0x3C1ADA0
CHARGE_CORE = 0x26C79D0
CLOSURE = 0x22155A0
SERIALIZER_CW = 0x2205C79
SERIALIZER_PW = 0x2205CA4
NULL_TEST = 0x2970E0E
NULL_WRITE = 0x2970E2B
STATUS_TABLE = 0x59A8D0
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_DISABLED = 0x181
TAG_SLOT = 0x182
TAG_MAX = 0x178
TAG_FUNDS = 0x179
TEXT_ARMS = (TAG_DISABLED, TAG_SLOT, TAG_MAX, TAG_FUNDS)
TAG_ERROR = 0x176

C_INFO_B = 0x8
C_INFO_A = 0x28
C_CLOCK = 0x60
C_USERS = 0x80
C_CHAIN = 0x8F2
C_CAP = 0x3610
C_PTR = 0x3618
C_LEN = 0x3620
STRIDE = 0x50
A_TOKEN = 0x30
A_CW = 0x40
NONE_CAP = 1 << 63

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
ADDR = HEAP_BASE + 0x500
CTX = HEAP_BASE + 0x1000
CTX_SIZE = 0x3700
AUCTIONS = HEAP_BASE + 0x5000
REC = HEAP_BASE + 0x5800
NODES = HEAP_BASE + 0x6000
NODE_STRIDE = 0x280
TEXT = HEAP_BASE + 0x7A00
SLICE = HEAP_BASE + 0x7900
COMPARED = 0x8000
USED = 0x8000
FILL = 0xCC
WHO = bytes(range(0x41, 0x55))
INFO_BYTES = bytes(range(0x90, 0xB0))
ZERO_INFO = bytes(0x20)
ERROR_BYTES = struct.pack("<H", TAG_ERROR) + bytes((index * 11 + 3) & 0xFF for index in range(OUT_SIZE - 2))
LEN_AT, EDGE_AT, SLOT_AT, KEY_AT, VAL_AT = 0x16A, 0x170, 0x168, 0x8, 0x60


class Case:
    FIELDS = dict(word=1, cap=8, length=4, slot=1, flag=0, limit=0, price=1000, price_err=False, token=150, shape="leaf", row=(5000, 100), near=(-1, 1), core_err=False, ip=(10, 0, 0, 7), chain=3, info_a=0x7777, info_b=0x8888)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.FIELDS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.FIELDS:
                raise EvidenceError("field " + key)
            setattr(self, key, value)


def blank():
    return bytes((index * 7 + 0x40) & 0xFF for index in range(OUT_SIZE))


def ip_word(ip):
    return bytes(ip)[0] << 8 | bytes(ip)[1] << 16 | bytes(ip)[2] << 24 | bytes(ip)[3] << 32


def spec_run(case, before):
    """Predict one handler run from the rule list, written apart from the bytes under test."""
    image = bytearray(before)
    events = []

    def put(addr, data):
        at = addr - HEAP_BASE
        image[at:at + len(data)] = data

    def done(tag):
        put(OUT, struct.pack("<H", tag))
        return "done", tuple(events), bytes(image)

    def refuse(tag, price):
        put(OUT, struct.pack("<H", tag))
        put(OUT + 8, struct.pack("<QQ", price, case.token) + b"\0")
        return "done", tuple(events), bytes(image)

    info = ZERO_INFO
    if case.word & MASK[4] == 1:
        events.append(("info", case.chain, case.info_a, case.info_b, 0))
        info = INFO_BYTES
    if case.cap == NONE_CAP:
        return done(TAG_DISABLED)
    events.append(("drop_disabled", TAG_DISABLED))
    if case.slot >= case.length:
        return done(TAG_SLOT)
    auction = AUCTIONS + case.slot * STRIDE
    events.append(("drop_slot", TAG_SLOT))
    events.append(("price", auction, CTX + C_CLOCK))
    if case.price_err:
        put(OUT, ERROR_BYTES)
        return "done", tuple(events), bytes(image)
    price = case.price
    if case.flag & 1 and price > case.limit:
        return refuse(TAG_MAX, price)
    events.append(("user",))
    total, hold = case.row if case.row is not None and case.shape != "none" else (0, 0)
    if price + hold > MASK[8] or price + hold > total:
        return refuse(TAG_FUNDS, price)
    events.append(("charge", CTX, ADDR, struct.pack("<QQ", price, case.token) + b"\0", info, auction, CLOSURE))
    if case.core_err:
        put(OUT, ERROR_BYTES)
        return "done", tuple(events), bytes(image)
    put(auction + A_CW, b"\0" + bytes(case.ip))
    return done(TAG_OK)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((CHARGE,))
        statics = machine.memory.statics
        hooks = {SLOT_PRICE: self.on_price, SLOT_USER: self.on_user}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        machine.calls = {INFO: self.on_info, DROP_DISABLED: self.on_drop(DROP_DISABLED), DROP_SLOT: self.on_drop(DROP_SLOT), CHARGE_CORE: self.on_core}
        self.events = []
        self.case = None
        self.before = None
        self.next_node = NODES

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def bytes_at(self, addr, size):
        return self.machine.memory.bytes_at(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def on_info(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == regs[RSP] + 8 + 0x100, "info out")
        self.events.append(("info", regs[RSI], regs[RDX], regs[RCX], regs[R8]))
        machine.memory.put_bytes(regs[RDI], INFO_BYTES)

    def on_drop(self, which):
        name = "drop_disabled" if which == DROP_DISABLED else "drop_slot"

        def hook(machine):
            regs = machine.regs
            self.expect(regs[RDI] == regs[RSP] + 8 + 0x10, "drop place")
            self.events.append((name, struct.unpack("<H", self.bytes_at(regs[RDI], 2))[0]))
        return hook

    def on_price(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == regs[RSP] + 0x10, "price out")
        self.events.append(("price", regs[RSI], regs[RDX]))
        if self.case.price_err:
            machine.memory.put_bytes(regs[RDI], ERROR_BYTES)
            return
        machine.memory.put_bytes(regs[RDI], struct.pack("<H", TAG_OK) + b"\x5A" * 6 + struct.pack("<QQ", self.case.price, 0x9999))

    def on_user(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == CTX + C_USERS, "user map")
        self.expect(self.bytes_at(regs[RSI], 20) == WHO, "user key")
        self.events.append(("user",))
        regs[RAX] = REC

    def on_core(self, machine):
        regs = machine.regs
        top = regs[RSP]
        self.expect(regs[RDI] == top + 0x18, "core out")
        self.expect(regs[R9] == 0, "core r9")
        auction, closure = struct.unpack("<2Q", self.bytes_at(top + 8, 16))
        self.events.append(("charge", regs[RSI], regs[RDX], self.bytes_at(regs[RCX], 17), self.bytes_at(regs[R8], 32), auction, closure))
        if self.case.core_err:
            machine.memory.put_bytes(regs[RDI], ERROR_BYTES)
        else:
            machine.memory.put_bytes(regs[RDI], struct.pack("<H", TAG_OK) + b"\x5A" * 14)

    def node(self, items, children, stale_key):
        base = self.next_node
        self.next_node += NODE_STRIDE
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * NODE_STRIDE)
        for at in range(11):
            key, value = items[at] if at < len(items) else (stale_key, (0xFEFEFEFE, 0x0F0F0F0F))
            memory.write(base + KEY_AT + 8 * at, 8, key)
            memory.put_bytes(base + VAL_AT + 0x18 * at, struct.pack("<2Q", *value) + b"\xEE" * 8)
        self.word(base + LEN_AT, len(items), 2)
        self.word(base, 0)
        self.word(base + SLOT_AT, 0, 2)
        for at, child in enumerate(children):
            self.word(base + EDGE_AT + 8 * at, child)
        return base

    def build(self, case):
        items = [((case.token + step) & MASK[8], (0x11110000 + index, 0x2222 + index)) for index, step in enumerate(case.near)]
        if case.row is not None:
            items.append((case.token, tuple(case.row)))
        items.sort()
        root, height = 0, 0
        if case.shape == "leaf":
            root = self.node(items, (), case.token)
        elif case.shape == "deep":
            half = len(items) // 2
            left = self.node(items[:half], (), case.token)
            right = self.node(items[half + 1:], (), case.token)
            root, height = self.node(items[half:half + 1], (left, right), case.token), 1
        elif case.shape == "tall":
            third = len(items) // 3
            parts = [items[:third], items[third + 1:2 * third + 1], items[2 * third + 2:]]
            leaves = [self.node(part, (), case.token) for part in parts]
            inner = self.node(items[third:third + 1] + items[2 * third + 1:2 * third + 2], leaves, case.token)
            right = self.node([], (), case.token)
            root, height = self.node([(MASK[8], (1, 2))], (inner, right), case.token), 2
        elif case.shape == "two_step":
            leaf = self.node(items, (), case.token)
            inner = self.node([(MASK[8], (1, 2))], (leaf, leaf), case.token)
            root, height = self.node([(MASK[8], (3, 4))], (inner, inner), case.token), 2
        self.word(REC + 0x10, root)
        self.word(REC + 0x18, height)

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(HEAP_BASE, bytes([FILL]) * COMPARED)
        memory.put_bytes(OUT, blank())
        memory.put_bytes(ADDR, WHO)
        self.word(CTX, case.word)
        self.word(CTX + C_INFO_B, case.info_b)
        self.word(CTX + C_INFO_A, case.info_a)
        self.word(CTX + C_CHAIN, case.chain, 1)
        self.word(CTX + C_CAP, case.cap)
        self.word(CTX + C_PTR, AUCTIONS)
        self.word(CTX + C_LEN, case.length)
        for index in range(8):
            base = AUCTIONS + index * STRIDE
            memory.put_bytes(base, bytes([0x30 + index]) * STRIDE)
            self.word(base + A_TOKEN, case.token if index == min(case.slot, 7) else case.token ^ 0x4000 + index)
        self.next_node = NODES
        self.build(case)
        self.events = []
        self.case = case
        self.before = memory.bytes_at(HEAP_BASE, COMPARED)

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        memory.write(STACK_TOP - 0x100, 8, case.limit)
        try:
            self.machine.run(HANDLER, {RDI: OUT, RSI: CTX, RDX: ADDR, RCX: ip_word(case.ip), R8: case.slot, R9: case.flag})
        except Panicked as stop:
            return "panic", stop.args[0], tuple(self.events)
        data = bytearray(memory.bytes_at(HEAP_BASE, COMPARED))
        at = OUT - HEAP_BASE
        if struct.unpack_from("<H", data, at)[0] in (TAG_MAX, TAG_FUNDS):
            start = blank()
            data[at + 2:at + 8] = start[2:8]
            data[at + 0x19:at + OUT_SIZE] = start[0x19:]
        return "done", tuple(self.events), bytes(data)

    def parse(self, text):
        """Run the parser on `text`; digits follow the slice end, so a read past it changes the result."""
        memory = self.machine.memory
        memory.put_bytes(TEXT, b"7" * 0x40)
        memory.put_bytes(TEXT, text)
        memory.put_bytes(SLICE, struct.pack("<2Q", TEXT, len(text)))
        value = self.machine.run(PARSER, {RDI: SLICE})
        pointer, rest = struct.unpack("<2Q", memory.bytes_at(SLICE, 16))
        if value & 0xFF == 0:
            if (pointer, rest) != (TEXT, len(text)):
                raise Halt("failed parse moved the slice")
            return None
        if value & 0xFF != 1 or value >> 40:
            raise Halt("parser word %#x" % value)
        return bytes(value.to_bytes(5, "little")[1:]), pointer - TEXT, rest


def spec_parse(text):
    """Four dotted decimal octets from the start; the text after the last digit is left to the caller."""
    at = 0
    octets = []
    for index in range(4):
        if index:
            if at >= len(text) or text[at] != 0x2E:
                return None
            at += 1
        first = at
        while at < len(text) and at - first < 4 and 0x30 <= text[at] <= 0x39:
            at += 1
        count = at - first
        if count == 0 or count > 3:
            return None
        if count > 1 and text[first] == 0x30:
            return None
        value = int(text[first:at])
        if value > 255:
            return None
        octets.append(value)
    return bytes(octets), at, len(text) - at


TOP = MASK[8]
HIGH = 1 << 63
HANDLER_NAMED = (
    ("plain", {}), ("info_word_zero", dict(word=0)), ("info_word_two", dict(word=2)), ("info_word_top_bits", dict(word=1 << 32 | 1)), ("info_word_high", dict(word=0x100)), ("chain_byte_one", dict(chain=1)), ("chain_byte_top", dict(chain=0xFF)),
    ("disabled", dict(cap=NONE_CAP)), ("disabled_no_info", dict(cap=NONE_CAP, word=0)), ("cap_one_above_none", dict(cap=NONE_CAP + 1)), ("cap_one_below_none", dict(cap=NONE_CAP - 1)), ("cap_zero_len_zero", dict(cap=0, length=0, slot=0)), ("cap_top", dict(cap=TOP)),
    ("slot_zero", dict(slot=0)), ("slot_last", dict(slot=3)), ("slot_len", dict(slot=4)), ("slot_above", dict(slot=5)), ("slot_top", dict(slot=TOP)), ("slot_high", dict(slot=HIGH)), ("len_one", dict(length=1, slot=0)), ("len_zero", dict(length=0, slot=0)), ("len_eight_last", dict(length=8, slot=7)),
    ("no_limit_above", dict(flag=0, limit=10, price=1000)), ("limit_equal", dict(flag=1, limit=1000)), ("limit_one_above", dict(flag=1, limit=1001)), ("limit_one_below", dict(flag=1, limit=999)), ("limit_zero", dict(flag=1, limit=0)), ("limit_zero_price_zero", dict(flag=1, limit=0, price=0)),
    ("flag_two", dict(flag=2, limit=10)), ("flag_three", dict(flag=3, limit=10)), ("flag_high_byte", dict(flag=0x100, limit=10)), ("flag_top_bit", dict(flag=HIGH | 1, limit=10)), ("flag_ff", dict(flag=0xFE, limit=10)), ("limit_high", dict(flag=1, limit=HIGH, price=HIGH, row=(HIGH, 0))), ("limit_high_over", dict(flag=1, limit=HIGH - 1, price=HIGH, row=(HIGH, 0))),
    ("limit_before_funds", dict(flag=1, limit=1, row=(0, 0))), ("limit_low_word", dict(flag=1, limit=1 << 32, price=(1 << 32) + 1, row=(TOP, 0))), ("limit_high_word", dict(flag=1, limit=(1 << 32) + 1, price=(2 << 32), row=(TOP, 0))),
    ("price_error", dict(price_err=True)), ("price_error_no_info", dict(price_err=True, word=0)), ("price_error_over_limit", dict(price_err=True, flag=1, limit=0)),
    ("funds_exact", dict(row=(1100, 100))), ("funds_over", dict(row=(1099, 100))), ("funds_no_hold", dict(row=(1000, 0))), ("funds_no_hold_over", dict(row=(999, 0))), ("funds_hold_equal_total", dict(row=(5000, 5000))), ("funds_hold_above_total", dict(row=(5, 10), price=0)), ("funds_hold_equal_price_zero", dict(row=(5, 5), price=0)), ("funds_zero_all", dict(row=(0, 0), price=0)),
    ("wrap_exact", dict(row=(TOP, TOP), price=1)), ("wrap_to_small", dict(row=(TOP, TOP - 1), price=3)), ("wrap_top", dict(row=(TOP, HIGH), price=HIGH)), ("no_wrap_top", dict(row=(TOP, HIGH), price=HIGH - 1)), ("top_exact", dict(row=(TOP, 1), price=TOP - 1)), ("top_over", dict(row=(TOP - 1, 1), price=TOP - 1)), ("price_top", dict(row=(TOP, 0), price=TOP)), ("wrap_low_sum", dict(row=(50, TOP - 9), price=20)),
    ("high_words", dict(row=((5 << 32) + 3, 2 << 32), price=(3 << 32) + 3)), ("high_words_over", dict(row=((5 << 32) + 3, 2 << 32), price=(3 << 32) + 4)),
    ("no_tree", dict(shape="none")), ("no_tree_price_zero", dict(shape="none", price=0)), ("no_row_low", dict(row=None, near=(-1,))), ("no_row_high", dict(row=None, near=(1,))), ("no_row_gap", dict(row=None, near=(-1, 1))), ("no_row_price_zero", dict(row=None, price=0)), ("empty_leaf", dict(row=None, near=())), ("empty_leaf_price_zero", dict(row=None, near=(), price=0)),
    ("row_only", dict(near=())), ("row_first", dict(near=(1, 2, 3))), ("row_last", dict(near=(-1, -2, -3))), ("row_full_leaf", dict(near=(-5, -4, -3, -2, -1, 1, 2, 3, 4, 5))), ("row_full_leaf_first", dict(near=tuple(range(1, 11)))), ("row_full_leaf_last", dict(near=tuple(range(-10, 0)))), ("no_row_full_leaf", dict(row=None, near=(-5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6))), ("no_row_full_high", dict(row=None, near=tuple(range(-11, 0)))),
    ("token_zero", dict(token=0, near=(1, 2))), ("token_top", dict(token=TOP, near=(-1, -2))), ("token_high", dict(token=HIGH, near=(-1, 1))), ("token_high_missing", dict(token=HIGH, row=None, near=(-1, 1))), ("token_above_lanes", dict(token=(1 << 32) + 7, near=(-(1 << 32), 1 << 32))), ("token_high_near", dict(token=5, near=(HIGH,))), ("token_high_near_row", dict(token=HIGH + 5, near=(-HIGH,))),
    ("deep_root", dict(shape="deep", near=(-2, -1, 1, 2))), ("deep_left", dict(shape="deep", near=(1, 2, 3, 4))), ("deep_right", dict(shape="deep", near=(-1, -2, -3, -4))), ("deep_missing_left", dict(shape="deep", row=None, near=(1, 2, 3))), ("deep_missing_right", dict(shape="deep", row=None, near=(-1, -2, -3))), ("deep_missing_mid", dict(shape="deep", row=None, near=(-2, -1, 1, 2))),
    ("tall_first", dict(shape="tall", near=(1, 2, 3, 4, 5, 6, 7, 8))), ("tall_last", dict(shape="tall", near=(-1, -2, -3, -4, -5, -6, -7, -8))), ("tall_inner", dict(shape="tall", near=(-5, -4, -3, -2, -1, 1, 2, 3))), ("tall_missing", dict(shape="tall", row=None, near=(-4, -3, -2, -1, 1, 2, 3, 4))), ("two_step", dict(shape="two_step", near=(-1, 1))), ("two_step_missing", dict(shape="two_step", row=None)),
    ("core_error", dict(core_err=True)), ("core_error_no_info", dict(core_err=True, word=0)), ("core_error_keeps_winner", dict(core_err=True, slot=2)),
    ("ip_low", dict(ip=(0, 0, 0, 0))), ("ip_top", dict(ip=(255, 255, 255, 255))), ("ip_first", dict(ip=(1, 0, 0, 0))), ("ip_last", dict(ip=(0, 0, 0, 1))), ("ip_each", dict(ip=(0x12, 0x34, 0x56, 0x78), slot=0)), ("ip_last_slot", dict(ip=(0xA1, 0xB2, 0xC3, 0xD4), slot=3)),
)


def named_cases():
    return [Case(name, **fields) for name, fields in HANDLER_NAMED]


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11 ^ state


def vector_cases(count):
    source = lcg(0x2727)
    rows = []
    for index in range(count):
        word = next(source)
        total = next(source) >> (word & 63)
        hold = next(source) >> (word >> 6 & 63) if word >> 12 & 1 else 0
        price = (total - hold + (word >> 13 & 3) - 1) & MASK[8] if word >> 15 & 3 else next(source) >> (word >> 17 & 63)
        limit = (price + (word >> 23 & 3) - 1) & MASK[8] if word >> 25 & 3 else next(source) >> (word >> 27 & 63)
        fields = dict(price=price, limit=limit, flag=word >> 33 & 1, row=(total, hold) if word >> 34 & 7 else None, slot=word >> 37 & 7, length=1 + (word >> 40 & 7), word=word >> 43 & 1, token=next(source) >> (word >> 44 & 63), shape=("leaf", "deep", "leaf", "none")[word >> 50 & 3],
                      core_err=word >> 52 & 7 == 0, ip=tuple(next(source).to_bytes(8, "little")[:4]))
        fields["near"] = tuple(step for step in (-2, -1, 1, 2) if 0 <= fields["token"] + step <= MASK[8])
        rows.append(Case("v%d" % index, **fields))
    return rows


SEPARATOR_TEXT = b"123.123.123.123"
EDGE_OCTETS = (b"", b"0", b"00", b"01", b"09", b"000", b"001", b"010", b"099", b"9", b"10", b"19", b"20", b"25", b"99", b"100", b"199", b"200", b"249", b"250", b"255", b"256", b"259", b"260", b"299", b"300", b"999", b"1000", b"2550", b"0000", b"12a", b"a", b"/", b":")


def with_octet(position, octet):
    parts = [b"1", b"2", b"3", b"4"]
    parts[position] = octet
    return b".".join(parts)


def octet_texts():
    """Every decimal string of one to three digits in each of the four positions."""
    rows = []
    for position in range(4):
        for size in (1, 2, 3):
            for value in range(10 ** size):
                rows.append((position, size, with_octet(position, b"%0*d" % (size, value))))
    return rows


def edge_texts():
    rows = [with_octet(position, octet) for position in range(4) for octet in EDGE_OCTETS]
    rows += [b"", b".", b"1", b"1.", b"1.2", b"1.2.", b"1.2.3", b"1.2.3.", b"1.2.3.4.", b"1.2.3.4x", b"1.2.3.4 ", b" 1.2.3.4", b"1.2.3.4.5", b"1..3.4", b"255.255.255.255", b"0.0.0.0", b"1.2.3.255x", b"1.2.3.256x", b"1.2.3.25", b"1.2.3.04x", b"1.2.3.0x"]
    rows += [b"1.2.3.4" + bytes([byte]) for byte in (0x2F, 0x30, 0x39, 0x3A)]
    rows += [b"1.2.3.123" + bytes([byte]) for byte in (0x2F, 0x30, 0x39, 0x3A)]
    return rows


def separator_texts():
    """Every byte value at each position of a maximal address."""
    return [SEPARATOR_TEXT[:at] + bytes([byte]) + SEPARATOR_TEXT[at + 1:] for at in range(len(SEPARATOR_TEXT)) for byte in range(256)]


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
    if image.relative().get(SLOT_PRICE) != PRICE_TARGET:
        raise EvidenceError("price slot")
    return [("%#x" % SLOT_PRICE, "auction price", "%#x" % PRICE_TARGET, len(slot_sites(image, SLOT_PRICE)))]


def call_rows(image):
    rows = []
    for target, name in ((HANDLER, "bid_handler"), (CHARGE, "charge_wrapper"), (PARSER, "ipv4_parser")):
        rows.append((name, "%#x" % target, len(direct_to(image, target))))
    if [row[2] for row in rows[:2]] != [1, 1]:
        raise EvidenceError("direct call counts %r" % rows)
    return rows


def rip_target(image, va, size=7):
    data = bytes(image.blob[image.offset(va):image.offset(va) + size])
    return va + size + struct.unpack_from("<i", data, size - 4)[0]


def name_rows(image):
    """Field offsets of the winner words from the bytes before each key lea, and the action keys."""
    rows = []
    for at, form, shift, want, offset in ((SERIALIZER_CW, b"\x48\x8d\x4b\x40", 4, "cw", 0x40), (SERIALIZER_PW, b"\x48\x83\xc3\x45", 4, "pw", 0x45)):
        data = bytes(image.blob[image.offset(at):image.offset(at) + 11])
        if data[:len(form)] != form or data[shift:shift + 3] != b"\x48\x8d\x35":
            raise EvidenceError("serializer row %#x" % at)
        target = rip_target(image, at + shift)
        text = bytes(image.blob[image.offset(target):image.offset(target) + 2]).decode("ascii")
        if text != want:
            raise EvidenceError("key %#x %r" % (at, text))
        rows.append(("%#x" % at, "%#x" % offset, "%#x" % target, text))
    return rows


def null_rows(image):
    """The field serializer prints JSON null when the first byte is 2."""
    data = bytes(image.blob[image.offset(NULL_TEST):image.offset(NULL_TEST) + 4])
    word = bytes(image.blob[image.offset(NULL_WRITE):image.offset(NULL_WRITE) + 7])
    if data != b"\x41\x80\x3e\x02" or word[-4:] != b"null":
        raise EvidenceError("null row")
    return [("%#x" % NULL_TEST, data.hex(), 2, "%#x" % NULL_WRITE, word[-4:].decode("ascii"))]


def text_rows(image):
    """Offsets of the action field keys and struct name in .rodata bytes."""
    rows = []
    blob = bytes(image.blob)
    for text in (b"slotIdipmaxGas", b"struct GossipPriorityBidAction with 3 elements", b"gossipPriorityBid", b"struct GossipPriorityGasAuction with 3 elements"):
        hits = [match.start() for match in re.finditer(re.escape(text), blob)]
        if not hits:
            raise EvidenceError("text %r" % text)
        rows.append((text.decode("ascii"), len(hits), "%#x" % hits[0]))
    return rows


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
        rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")))
    return rows


def piece_rows(harness):
    """Both ends of each price piece for a fixed row and limit: same status and same reached rows."""
    rows = []
    machine = harness.machine
    fixtures = (("funds", dict(row=(1000, 100)), ((0, 900), (901, TOP - 100), (TOP - 99, TOP))),
                ("limit", dict(row=(TOP, 0), flag=1, limit=500), ((0, 500), (501, TOP))),
                ("no_row", dict(row=None), ((0, 0), (1, TOP))))
    for name, fields, ranges in fixtures:
        for low, high in ranges:
            walked, results = [], []
            for value in (low, high):
                case = Case("%s_%#x" % (name, value), price=value, **fields)
                saved = machine.seen
                machine.seen = set()
                got = harness.run(case)
                walked.append(machine.seen)
                machine.seen = saved | walked[-1]
                if got != spec_run(case, harness.before):
                    raise EvidenceError("piece end %#x" % value)
                results.append(struct.unpack_from("<H", got[2], OUT - HEAP_BASE)[0])
            if results[0] != results[1]:
                raise EvidenceError("piece %#x..%#x has two statuses" % (low, high))
            if walked[0] != walked[1]:
                raise EvidenceError("piece %#x..%#x has two paths" % (low, high))
            rows.append((name, low, high, "%#x" % results[0]))
    return rows


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case, harness.before)
        if got != want:
            if got[0] == "done" and want[0] == "done":
                diff = [hex(HEAP_BASE + at) for at in range(COMPARED) if got[2][at] != want[2][at]][:12]
                raise EvidenceError("case %s: events %r != %r diff %s" % (case.name, got[1], want[1], diff))
            raise EvidenceError("case %s: %r != %r" % (case.name, got[:2], want[:2]))
        outcomes.append(got)
    return outcomes


def check_parser(harness):
    """All digit strings, every edge string and every byte at each place; returns the accepted counts."""
    table = {}
    for position, size, text in octet_texts():
        got = harness.parse(text)
        if got != spec_parse(text):
            raise EvidenceError("parser text %r: %r" % (text, got))
        key = (position, size)
        row = table.setdefault(key, [0, 0])
        row[0] += 1
        row[1] += 1 if got is not None else 0
    for text in edge_texts():
        if harness.parse(text) != spec_parse(text):
            raise EvidenceError("parser text %r" % text)
    accepted = 0
    for text in separator_texts():
        got = harness.parse(text)
        if got != spec_parse(text):
            raise EvidenceError("parser text %r: %r" % (text, got))
        accepted += got is not None
    rows = [(position, size, tried, passed) for (position, size), (tried, passed) in sorted(table.items())]
    return rows, accepted


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
            if harness.run(case) != spec_run(case, harness.before):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error):
            return case
    return None


def first_parser_failure(harness, texts):
    for text in texts:
        try:
            if harness.parse(text) != spec_parse(text):
                return text
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, struct.error):
            return text
    return None


FOURTH = "fourth character of octet 1, 2 or 3: a dot must follow in any case, and a dot is outside the digit class under either value"
ZEROED = "the flag register was cleared on the row before, so testing it with bit 0 or with no bit reads the same"
ENDED = "the text ended inside octet 1, 2 or 3, so the parse fails on the missing dot whichever way this flag falls"
DEAD = "start pointer of the octet: it is replaced on success, and on failure the caller's slice is restored without reading it"
OVERWRITTEN = "this store is on a failure path only, and the restore at 0x1573e5b writes both words again"
EXPECTED_SURVIVORS = {
    (0x1573B65, "immediate"): FOURTH, (0x1573B69, "immediate"): FOURTH, (0x1573C51, "immediate"): FOURTH, (0x1573C55, "immediate"): FOURTH, (0x1573D3A, "immediate"): FOURTH, (0x1573D3D, "immediate"): FOURTH,
    (0x1573B78, "immediate"): ZEROED, (0x1573C5E, "immediate"): ZEROED,
    (0x1573B87, "immediate"): ENDED, (0x1573B8B, "condition"): ENDED, (0x1573C6C, "immediate"): ENDED, (0x1573C70, "condition"): ENDED, (0x1573D4A, "immediate"): ENDED, (0x1573D4E, "condition"): ENDED,
    (0x1573BED, "displacement"): DEAD, (0x1573CD2, "displacement"): DEAD,
    (0x1573E30, "displacement"): OVERWRITTEN,
}


def run_mutants(image, table, seen, cases):
    results = []
    texts = edge_texts()
    for target in TARGETS:
        control = Harness(image)
        control.machine.step_limit = MUTANT_STEP_LIMIT
        if target == PARSER:
            if first_parser_failure(control, texts) is not None:
                raise EvidenceError("an unedited image fails on the parser texts")
        elif first_failure(control, cases) is not None:
            raise EvidenceError("an unedited image fails under the mutant step limit")
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            failed = first_parser_failure(harness, texts) if target == PARSER else first_failure(harness, cases)
            if failed is not None:
                results.append((va, kind, "killed", "whole run"))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True, vectors=600):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    check_cases(harness, vector_cases(vectors))
    pieces = piece_rows(harness)
    octets, separators = check_parser(harness)
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, slots=slot_rows(image), calls=call_rows(image), names=name_rows(image), texts=text_rows(image),
                  statuses=status_rows(image), nulls=null_rows(image), pieces=pieces, octets=octets, separators=separators, separator_runs=len(separator_texts()), edge_runs=len(edge_texts()))
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
    return "%#x" % tag, data[at:at + 8].hex(), ",".join(str(event[0]) for event in outcome[1]), hashlib.sha256(data).hexdigest()[:16]


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("slots.tsv", ("slot", "role", "relative_target", "indirect_call_sites"), result["slots"])
    tsv("direct-calls.tsv", ("function", "address", "direct_call_sites"), result["calls"])
    tsv("winner-fields.tsv", ("site", "offset", "key_address", "key"), result["names"])
    tsv("winner-null.tsv", ("test_site", "bytes", "null_tag", "write_site", "text"), result["nulls"])
    tsv("rodata-text.tsv", ("text", "hits", "first_offset"), result["texts"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("price-pieces.tsv", ("fixture", "low", "high", "status"), result["pieces"])
    tsv("parser-octets.tsv", ("position", "digits", "strings", "accepted"), result["octets"])
    tsv("outcomes.tsv", ("case", "status", "out_head", "events", "state_digest"),
        [(case.name,) + describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"], "parser_edge_strings": result["edge_runs"], "parser_separator_strings": result["separator_runs"], "parser_separator_accepted": result["separators"],
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
