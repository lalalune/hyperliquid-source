#!/usr/bin/env python3
"""Pin the node #94 cWithdraw gate and pending withdrawal queue from ELF bytes.

0x3993110 refuses a live staking lock, sums delegated stake (0x3c0f050) and compares the amount with
what is left after earlier pending withdrawals. 0x3c13000 caps a user at five rows, compares again with
the undelegated word, bumps the user total (0x33bac00) and files (amount, user) under an unlock time of
now + 7 days, or 300 seconds on chain bytes 1 and 2. The real bytes run under recording stubs over
real B-tree nodes, a separately written rule list predicts every run including all fixture bytes, and
every reached conditional row is mutated. No objdump or readelf output is parsed and the binary is
never executed. Standard library only.

    python3 tools/cwithdraw_queue.py --out <dir>
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


GATE = 0x3993110
QUEUE = 0x3C13000
TOTAL = 0x3C0F050
ENTRY = 0x33BAC00
TARGETS = (GATE, QUEUE, TOTAL, ENTRY)
NAMES = {GATE: "gate", QUEUE: "queue", TOTAL: "delegated_total", ENTRY: "total_entry"}

SLOT_GATE = 0x5774D40
SLOT_TOTAL = 0x5774900
SLOT_COMPARE = 0x576E488
SLOT_TIME = 0x576EFB8
SLOT_GROW = 0x57744D0
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAIL = 0x576E020
TOTAL_INSERT = 0x2F90CA0
QUEUE_INSERT = 0x33BFF70
SECONDS_TABLE = 0x2039F0
STATUS_TABLE = 0x59A8D0
SERIALIZER_SITES = ((0x238D993, 0x168, "delegations"), (0x238DB03, 0x1F8, "user_states"), (0x238DB1B, 0x210, "pending_withdrawals"))
QUEUE_STRUCT = 0x276A8D0
SUMMARY_STRUCT = 0x2A3F830
SUMMARY_KEYS = ("delegated", "undelegated", "totalPendingWithdrawal", "nPendingWithdrawals")
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_LOCKED = 0x12C
TAG_FUNDS = 0x12D
TAG_MANY = 0x12E
TAG_ADD = 0xBE
TEXT_ARMS = (TAG_LOCKED, TAG_FUNDS, TAG_MANY, TAG_ADD)

S_DELEGATIONS = 0x168
S_USERS = 0x1F8
S_QUEUE = 0x210
S_TOTALS = 0x228

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
USER_AT = HEAP_BASE + 0x500
NOW_AT = HEAP_BASE + 0x520
NEW_TOTAL = HEAP_BASE + 0x600
NEW_QUEUE = HEAP_BASE + 0x640
NEW_ROWS = HEAP_BASE + 0x700
ROOT_NODE = HEAP_BASE + 0x800
NODES = HEAP_BASE + 0x1000
NODE_STRIDE = 0x280
ROWS = HEAP_BASE + 0x6000
ROW_BLOCK = 0x200
STATE = HEAP_BASE + 0x8000
COMPARED = 0xA000
USED = 0x10000
FILL = 0xCC
WHO = bytes(range(0x41, 0x55))


def near(first=0, last=0):
    return bytes([(WHO[0] + first) & 0xFF]) + WHO[1:19] + bytes([(WHO[19] + last) & 0xFF])


class Layout:
    def __init__(self, key_size, val_size, val_at, key_at, len_at, edge_at, parent_at, slot_at):
        self.key_size, self.val_size, self.val_at, self.key_at = key_size, val_size, val_at, key_at
        self.len_at, self.edge_at, self.parent_at, self.slot_at = len_at, edge_at, parent_at, slot_at


USER_MAP = Layout(0x14, 0x18, 8, 0x110, 0x1EE, 0x1F0, 0, 0x1EC)
TOTAL_MAP = Layout(0x14, 0x10, 0, 0xB8, 0x196, 0x198, 0xB0, 0x194)
TIME_MAP = Layout(0x0C, 0x18, 8, 0x110, 0x196, 0x198, 0, 0x194)


def pack_time(value):
    return struct.pack("<iII", *value)


class Case:
    FIELDS = dict(x=1000, y=0, mode=3, now=(20000, 100, 5), v0=9000, lock=(0, 0, 0), total=None, delegated=(), s_shape="leaf", t_shape="leaf", q_shape="leaf", d_shape="leaf", s_near=((-1, 0), (1, 0)), t_near=((-1, 0), (1, 0)), q_near=(), d_near=((-1, 0), (1, 0)), d_present=True, d_tree="leaf", d_tall=False,
                  unlock=(20007, 100, 5), rows=None, alloc_fail=False)

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


def checked_total(amounts):
    total = 0
    for amount in amounts:
        total += amount
        if total > MASK[8]:
            return 0
    return total


def place(where, name, key):
    """Leaf and slot where a missing key goes, for the insert stubs."""
    keys, nodes, shape = where[name]
    at = bisect.bisect_left(keys, key)
    if shape == "leaf":
        return nodes[0], at
    half = len(keys) // 2
    if at <= half:
        return nodes[1], at
    return nodes[2], at - half - 1


def spec_run(case, before, where):
    """Predict one run from the rule list, written apart from the bytes under test."""
    image = bytearray(before)
    events = []

    def put(addr, data):
        at = addr - HEAP_BASE
        image[at:at + len(data)] = data

    def done(tag):
        put(OUT, struct.pack("<H", tag))
        return "done", tuple(events), bytes(image)

    x, y = case.x, case.y
    if case.kind == GATE:
        found = case.v0 is not None and case.s_shape != "none"
        if found:
            if case.lock[0] != 0 and tuple(case.now) < tuple(case.lock):
                return done(TAG_LOCKED)
            put(where["user"] + 8, bytes(4))
        if x + y > MASK[8]:
            return done(TAG_FUNDS)
        v0 = case.v0 if found else 0
        held = checked_total(case.delegated) if case.d_shape != "none" and case.d_present else 0
        total = held + v0
        if total > MASK[8]:
            room = 0
        else:
            pending = case.total[0] if case.total is not None and case.t_shape != "none" else 0
            room = max(total - pending, 0)
        if x + y > room:
            return done(TAG_FUNDS)
    else:
        v0 = case.v0
    return queue_spec(case, x, v0, events, put, done, where, before)


def queue_spec(case, x, v0, events, put, done, where, before):
    found = case.total is not None and case.t_shape != "none"
    if found:
        pending, count = case.total
        if count > 4:
            return done(TAG_MANY)
        if pending + x > MASK[8] or v0 < pending + x:
            return done(TAG_FUNDS)
    else:
        if v0 < x:
            return done(TAG_FUNDS)
        pending, count = 0, 0
    if found:
        slot = where["total"]
    elif case.t_shape == "none":
        events.append(("alloc",))
        if case.alloc_fail:
            events.append(("alloc_fail",))
            return "panic", "alloc", tuple(events)
        slot = ROOT_NODE
        put(ROOT_NODE + 0xB0, bytes(8))
        put(ROOT_NODE, bytes(0x10))
        put(ROOT_NODE + 0xB8, WHO)
        put(ROOT_NODE + 0x196, struct.pack("<H", 1))
        put(STATE + S_TOTALS, struct.pack("<2Q", ROOT_NODE, 0))
        put(STATE + S_TOTALS + 0x10, struct.pack("<Q", where["totals_len"] + 1))
    else:
        leaf, at = place(where, "totals", WHO)
        events.append(("total_insert", leaf, at, WHO))
        slot = NEW_TOTAL
        put(STATE + S_TOTALS + 0x10, struct.pack("<Q", where["totals_len"] + 1))
    put(slot, struct.pack("<2Q", pending + x, min(count + 1, MASK[8])))
    seconds = 300.0 if case.mode & 0xFF in (1, 2) else 604800.0
    events.append(("time", pack_time(case.now), struct.pack("<d", seconds)))
    key = pack_time(case.unlock)
    if case.rows is not None and case.q_shape != "none":
        vec = where["vec"]
        cap, length = case.rows[1], case.rows[0]
        pointer = where["row_block"]
    else:
        leaf, at = (0, 0) if case.q_shape == "none" else place(where, "queue", tuple(case.unlock))
        events.append(("queue_insert", leaf, at, key))
        vec = NEW_QUEUE + 8
        cap, length, pointer = 0, 0, 8
        put(NEW_QUEUE, bytes(8) + struct.pack("<3Q", 0, 8, 0))
    if length == cap:
        events.append(("grow", cap))
        cap = max(4, cap * 2)
        at = pointer - HEAP_BASE if length else 0
        if length:
            put(NEW_ROWS, before[at:at + length * 0x20])
        pointer = NEW_ROWS
        put(vec, struct.pack("<2Q", cap, pointer))
    put(pointer + length * 0x20, struct.pack("<Q", x) + WHO)
    put(vec + 0x10, struct.pack("<Q", length + 1))
    return done(TAG_OK)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((QUEUE, TOTAL, ENTRY))
        statics = machine.memory.statics
        statics[SLOT_TOTAL] = TOTAL
        hooks = {SLOT_COMPARE: self.on_compare, SLOT_TIME: self.on_time, SLOT_GROW: self.on_grow, SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_FAIL: self.on_alloc_fail}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        machine.calls = {TOTAL_INSERT: self.on_total_insert, QUEUE_INSERT: self.on_queue_insert}
        self.events = []
        self.case = None
        self.before = None
        self.where = None
        self.next_node = NODES
        self.next_rows = ROWS

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def bytes_at(self, addr, size):
        return self.machine.memory.bytes_at(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def on_compare(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 0x14, "compare length")
        left, right = self.bytes_at(regs[RDI], 0x14), self.bytes_at(regs[RSI], 0x14)
        result = 0 if left == right else 0x1234 if left > right else -0x1234
        regs[RAX] = (0x5A5A5A5A << 32) | result & MASK[4]

    def on_time(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == NOW_AT, "time input")
        self.events.append(("time", self.bytes_at(regs[RSI], 12), struct.pack("<Q", machine.xmm[0] & MASK[8])))
        machine.memory.put_bytes(regs[RDI], pack_time(self.case.unlock))

    def on_grow(self, machine):
        regs = machine.regs
        vec = regs[RDI]
        cap, pointer, length = struct.unpack("<3Q", self.bytes_at(vec, 24))
        self.expect(cap == length, "grow when full")
        self.events.append(("grow", cap))
        if length:
            machine.memory.put_bytes(NEW_ROWS, self.bytes_at(pointer, length * 0x20))
        self.word(vec, max(4, cap * 2))
        self.word(vec + 8, NEW_ROWS)

    def on_alloc(self, machine):
        self.expect(machine.regs[RDI] == 0x198, "alloc size")
        self.events.append(("alloc",))
        machine.regs[RAX] = 0 if self.case.alloc_fail else ROOT_NODE

    def on_alloc_fail(self, machine):
        self.expect(machine.regs[RDI] == 8 and machine.regs[RSI] == 0x198, "alloc failure layout")
        self.events.append(("alloc_fail",))
        raise Panicked("alloc")

    def on_total_insert(self, machine):
        regs = machine.regs
        self.expect(regs[RCX] == 0 and regs[R8] == 0, "default value")
        leaf, height, at = struct.unpack("<3Q", self.bytes_at(regs[RSI], 24))
        self.expect(height == 0, "leaf height")
        self.expect(struct.unpack("<Q", self.bytes_at(regs[R9], 8))[0] == STATE + S_TOTALS, "map holder")
        self.events.append(("total_insert", leaf, at, self.bytes_at(regs[RDX], 20)))
        self.expect(self.bytes_at(regs[R9] + 0x20, 20) == WHO, "held key")
        self.expect(struct.unpack("<3Q", self.bytes_at(regs[R9] + 8, 24)) == (leaf, height, at), "held entry")
        machine.memory.put_bytes(NEW_TOTAL, bytes(0x10))
        self.word(regs[RDI], NEW_TOTAL - 0x10)
        self.word(regs[RDI] + 0x10, 1)

    def on_queue_insert(self, machine):
        regs = machine.regs
        words = struct.unpack("<6Q", self.bytes_at(regs[RSI], 48))
        self.expect(words[0] == STATE + S_QUEUE and words[2] == 0, "queue entry")
        self.expect(words[4] >> 32 == struct.unpack("<3I", pack_time(self.case.unlock))[1] and words[5] >> 32 == 0, "queue key words")
        self.expect(struct.unpack("<3Q", self.bytes_at(regs[RDX], 24)) == (0, 8, 0), "queue vector")
        self.events.append(("queue_insert", words[1], words[3] if words[1] else 0, self.bytes_at(regs[RSI] + 0x20, 12)))
        machine.memory.put_bytes(NEW_QUEUE, struct.pack("<Q", 0) + struct.pack("<3Q", 0, 8, 0))
        self.word(regs[RDI], NEW_QUEUE - 0x18)
        self.word(regs[RDI] + 0x10, 1)

    def node(self, layout, items, children, stale_key, parent=0, slot=0):
        base = self.next_node
        self.next_node += NODE_STRIDE
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

    def tree(self, layout, items, shape, stale_key):
        items = sorted(items)
        if shape == "leaf":
            base, spots = self.node(layout, items, (), stale_key)
            return base, 0, spots, (base,)
        half = len(items) // 2
        left, one = self.node(layout, items[:half], (), stale_key)
        right, two = self.node(layout, items[half + 1:], (), stale_key)
        base, spots = self.node(layout, items[half:half + 1], (left, right), stale_key)
        self.word(left + layout.parent_at, base)
        self.word(right + layout.parent_at, base)
        self.word(right + layout.slot_at, 1, 2)
        spots.update(one)
        spots.update(two)
        return base, 1, spots, (base, left, right)

    def tall(self, items):
        """Fifteen rows in a tree of height 2: four leaves of three, two inner nodes, one root."""
        stale = b"\xFE" * 20
        leaves = [self.node(USER_MAP, items[at:at + 3], (), stale)[0] for at in (0, 4, 8, 12)]
        low = self.node(USER_MAP, items[3:4], leaves[:2], stale)[0]
        high = self.node(USER_MAP, items[11:12], leaves[2:], stale)[0]
        root = self.node(USER_MAP, items[7:8], (low, high), stale)[0]
        for parent, children in ((low, leaves[:2]), (high, leaves[2:]), (root, (low, high))):
            for slot, child in enumerate(children):
                self.word(child + USER_MAP.parent_at, parent)
                self.word(child + USER_MAP.slot_at, slot, 2)
        return root, 2

    def map_at(self, at, built, count):
        self.word(at, built[0] if built else 0)
        self.word(at + 8, built[1] if built else 0)
        self.word(at + 0x10, count)

    def users_map(self, case, where):
        items = [(near(*step), struct.pack("<Q", 1 + index) + pack_time((7, 7, 7)) + bytes(4)) for index, step in enumerate(case.s_near)]
        if case.v0 is not None:
            items.append((WHO, struct.pack("<Q", case.v0) + pack_time(case.lock) + b"\xEE" * 4))
        if case.s_shape == "none":
            self.map_at(STATE + S_USERS, None, 0)
            return
        built = self.tree(USER_MAP, items, case.s_shape, WHO)
        self.map_at(STATE + S_USERS, built, len(items))
        where["user"] = built[2].get(WHO)

    def delegation_map(self, case):
        if case.d_shape == "none":
            self.map_at(STATE + S_DELEGATIONS, None, 0)
            return
        inner = [(bytes([index + 1]) * 20, struct.pack("<Q", amount) + b"\xDD" * 16) for index, amount in enumerate(case.delegated)]
        if inner:
            shape = "deep" if len(inner) > 11 else "leaf"
            built = self.tall(inner) if case.d_tall else self.tree(USER_MAP, inner, shape, b"\xFE" * 20)
            value = struct.pack("<3Q", built[0], built[1], len(inner))
        else:
            value = struct.pack("<3Q", 0, 0, 0)
        lone = self.tree(USER_MAP, [(b"\x07" * 20, struct.pack("<Q", 7777) + b"\xDD" * 16)], "leaf", b"\xFE" * 20)
        items = [(near(*step), struct.pack("<3Q", lone[0], 0, 1)) for step in case.d_near]
        if case.d_present:
            items.append((WHO, value))
        built = self.tree(USER_MAP, items, case.d_tree, WHO)
        self.map_at(STATE + S_DELEGATIONS, built, len(items))

    def totals_map(self, case, where):
        items = [(near(*step), struct.pack("<2Q", 3 + index, 9)) for index, step in enumerate(case.t_near)]
        if case.total is not None:
            items.append((WHO, struct.pack("<2Q", *case.total)))
        where["totals_len"] = len(items)
        if case.t_shape == "none":
            where["totals_len"] = 0
            self.map_at(STATE + S_TOTALS, None, 0)
            return
        built = self.tree(TOTAL_MAP, items, case.t_shape, WHO)
        self.map_at(STATE + S_TOTALS, built, len(items))
        where["total"] = built[2].get(WHO)
        where["totals"] = ([key for key, _ in sorted(items)], built[3], case.t_shape)

    def queue_map(self, case, where):
        key = pack_time(case.unlock)
        items = []
        block = ROWS
        for step in case.q_near:
            items.append(((tuple(a + b for a, b in zip(case.unlock, step))), None))
        if case.rows is not None:
            items.append((tuple(case.unlock), None))
        if case.q_shape == "none":
            self.map_at(STATE + S_QUEUE, None, 0)
            return
        items.sort()
        packed = []
        for stamp, _ in items:
            length, cap = (case.rows if stamp == tuple(case.unlock) else (1, 1))
            for index in range(cap):
                self.machine.memory.put_bytes(block + index * 0x20, bytes([0x60 + index]) * 0x20)
            packed.append((pack_time(stamp), struct.pack("<3Q", cap, block, length)))
            if stamp == tuple(case.unlock):
                where["row_block"] = block
            block += ROW_BLOCK
        built = self.queue_tree(packed, case.q_shape, key)
        self.map_at(STATE + S_QUEUE, built, len(items))
        where["vec"] = built[2].get(key)
        where["queue"] = ([stamp for stamp, _ in items], built[3], case.q_shape)

    def queue_tree(self, packed, shape, stale):
        if shape == "leaf":
            base, spots = self.node(TIME_MAP, packed, (), stale)
            return base, 0, spots, (base,)
        half = len(packed) // 2
        left, one = self.node(TIME_MAP, packed[:half], (), stale)
        right, two = self.node(TIME_MAP, packed[half + 1:], (), stale)
        base, spots = self.node(TIME_MAP, packed[half:half + 1], (left, right), stale)
        spots.update(one)
        spots.update(two)
        return base, 1, spots, (base, left, right)

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(HEAP_BASE, bytes([FILL]) * COMPARED)
        memory.put_bytes(OUT, blank())
        memory.put_bytes(USER_AT, WHO)
        memory.put_bytes(NOW_AT, pack_time(case.now))
        where = {}
        self.next_node = NODES
        self.users_map(case, where)
        self.delegation_map(case)
        self.totals_map(case, where)
        self.queue_map(case, where)
        self.where = where
        self.events = []
        self.case = case
        self.before = memory.bytes_at(HEAP_BASE, COMPARED)

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        memory.write(STACK_TOP - 0x100, 8, NOW_AT)
        try:
            if case.kind == GATE:
                self.machine.run(GATE, {RDI: OUT, RSI: STATE, RDX: case.mode, RCX: USER_AT, R8: case.x, R9: case.y})
            else:
                self.machine.run(QUEUE, {RDI: OUT, RSI: STATE + S_QUEUE, RDX: case.mode, RCX: USER_AT, R8: case.x, R9: case.v0})
        except Panicked as stop:
            return "panic", stop.args[0], tuple(self.events)
        return "done", tuple(self.events), memory.bytes_at(HEAP_BASE, COMPARED)


LOCK = (20000, 100, 5)
FULL_TOTAL = dict(s_near=((-2, 0), (-1, 0), (1, 0), (2, 0)), t_near=((-2, 0), (-1, 0), (1, 0), (2, 0)))
QK = ((-1, 0, 0), (0, -1, 0), (0, 0, -1), (0, 0, 1), (0, 1, 0), (1, 0, 0))
GATE_NAMED = (
    ("plain", {}), ("exact_undelegated", dict(x=9000)), ("over_undelegated", dict(x=9001)), ("zero_amount", dict(x=0)), ("zero_all", dict(x=0, v0=0)),
    ("mode_local", dict(mode=0)), ("mode_sandbox", dict(mode=1)), ("mode_testnet", dict(mode=2)), ("mode_mainnet", dict(mode=3)), ("mode_four", dict(mode=4)), ("mode_high_bits", dict(mode=0x102)), ("mode_top", dict(mode=0xFF)),
    ("no_user_state", dict(v0=None)), ("no_user_tree", dict(s_shape="none", v0=None)), ("no_user_zero", dict(v0=None, x=0)), ("no_user_tree_zero", dict(s_shape="none", v0=None, x=0)),
    ("lock_absent_date_zero", dict(lock=(0, 500, 7))), ("lock_future_date", dict(lock=(20001, 0, 0))), ("lock_past_date", dict(lock=(19999, 0xFFFFFFFF, 9))), ("lock_future_secs", dict(lock=(20000, 101, 0))), ("lock_past_secs", dict(lock=(20000, 99, 9))),
    ("lock_future_frac", dict(lock=(20000, 100, 6))), ("lock_equal", dict(lock=(20000, 100, 5))), ("lock_past_frac", dict(lock=(20000, 100, 4))), ("lock_top_secs", dict(now=(5, 0x80000000, 0), lock=(5, 0x80000001, 0))), ("lock_top_secs_past", dict(now=(5, 0x80000001, 0), lock=(5, 0x80000000, 0))),
    ("lock_top_frac", dict(now=(5, 1, 0x80000000), lock=(5, 1, 0x80000001))), ("lock_top_frac_past", dict(now=(5, 1, 0x80000001), lock=(5, 1, 0x80000000))),
    ("lock_negative_now", dict(now=(-5, 1, 1), lock=(3, 0, 0))), ("lock_negative_stored", dict(now=(3, 1, 1), lock=(-5, 0, 0))), ("lock_before_funds", dict(lock=(20001, 0, 0), x=MASK[8], y=MASK[8])), ("lock_cleared_on_funds", dict(lock=(19000, 0, 0), x=9001)), ("lock_cleared_on_wrap", dict(lock=(19000, 0, 0), x=MASK[8], y=2)),
    ("extra_ok", dict(x=4000, y=5000)), ("extra_over", dict(x=4000, y=5001)), ("extra_wrap", dict(x=MASK[8], y=1)), ("extra_wrap_big", dict(x=1 << 63, y=1 << 63)), ("extra_top", dict(x=1, y=MASK[8] - 1, v0=MASK[8], total=None)),
    ("delegated_extends", dict(x=2000, y=11000, delegated=(5000,), v0=9000)), ("delegated_extends_over", dict(x=2000, y=14001, delegated=(5000,), v0=9000)), ("delegated_two", dict(x=1000, y=1000, delegated=(1, 2), v0=2000 - 3)), ("delegated_two_ok", dict(x=500, y=1500, delegated=(1, 2), v0=1997)),
    ("delegated_only", dict(x=0, y=3, v0=None, delegated=(1, 2))), ("delegated_above_x", dict(v0=None, delegated=(5000,), x=1)), ("delegated_all_zero", dict(delegated=(0, 0, 0))), ("delegated_eleven", dict(delegated=tuple(range(1, 12)))), ("delegated_deep", dict(delegated=tuple(range(1, 16)))), ("delegated_deep_max", dict(delegated=tuple(range(1, 24)))),
    ("delegated_wrap_gives_zero", dict(delegated=(MASK[8], 2), x=5000, v0=9000)), ("delegated_wrap_sum_room", dict(delegated=(MASK[8], 2), x=9000, y=1)), ("delegated_wrap_exact", dict(delegated=(MASK[8], 1), v0=5, x=5)), ("delegated_top", dict(delegated=(MASK[8], 0), v0=0, x=0)), ("delegated_top_y", dict(delegated=(MASK[8],), v0=0, x=0, y=MASK[8])),
    ("sum_wrap_room_zero", dict(delegated=(MASK[8],), v0=1, x=1)), ("sum_wrap_room_zero_ok", dict(delegated=(MASK[8],), v0=1, x=0, y=0)), ("sum_wrap_with_pending", dict(delegated=(MASK[8],), v0=1, x=0, y=0, total=(7, 1))), ("sum_wrap_one_more", dict(delegated=(MASK[8], 0), v0=2, x=0, y=1)), ("sum_top", dict(delegated=(MASK[8] - 1,), v0=1, x=1)),
    ("no_user_above_all", dict(v0=None, s_near=((-1, 0),), x=1)), ("no_user_above_all_delegated", dict(v0=None, s_near=((-1, 0),), delegated=(5000,), x=1)), ("no_user_extra_one", dict(v0=None, x=0, y=1)),
    ("no_delegation_above_all", dict(d_present=False, d_near=((-1, 0),))), ("no_delegation_exact", dict(d_present=False, x=1000, y=8000)), ("no_delegation_over", dict(d_present=False, x=1000, y=8001)), ("no_user_above_all_extra", dict(v0=None, s_near=((-1, 0),), x=0, y=1)), ("delegated_tall_exact", dict(delegated=tuple(range(1, 16)), d_tall=True, x=1000, y=8120)), ("delegated_tall_over", dict(delegated=tuple(range(1, 16)), d_tall=True, x=1000, y=8121)), ("delegated_deep_exact", dict(delegated=tuple(range(1, 16)), x=1000, y=8120)), ("delegated_deep_max_exact", dict(delegated=tuple(range(1, 24)), x=1000, y=8276)),
    ("delegations_deep_root", dict(d_tree="deep", d_near=((-2, 0), (-1, 0), (1, 0), (2, 0)), delegated=(5000,), x=1000, y=13000)), ("delegations_deep_left", dict(d_tree="deep", d_near=((1, 0), (2, 0), (3, 0), (4, 0)), delegated=(5000,), x=1000, y=13000)), ("delegations_deep_right", dict(d_tree="deep", d_near=((-1, 0), (-2, 0), (-3, 0), (-4, 0)), delegated=(5000,), x=1000, y=13000)),
    ("delegations_deep_missing_left", dict(d_tree="deep", d_present=False, d_near=((1, 0), (2, 0), (3, 0)), x=1000, y=8000)), ("delegations_deep_missing_right", dict(d_tree="deep", d_present=False, d_near=((-1, 0), (-2, 0), (-3, 0)), x=1000, y=8000)),
    ("no_delegation_tree", dict(d_shape="none")), ("no_delegation_row", dict(d_near=(), delegated=())),
    ("pending_room", dict(total=(1000, 1), x=8000)), ("pending_over", dict(total=(1000, 1), x=8001)), ("pending_above_total", dict(total=(9500, 1), x=1)), ("pending_above_total_zero", dict(total=(9500, 1), x=0, y=0)), ("pending_equal_total", dict(total=(9000, 1), x=1)), ("pending_equal_zero", dict(total=(9000, 1), x=0)),
    ("pending_room_delegated", dict(total=(1000, 1), x=7000, y=1000, delegated=(0,), v0=9000)), ("pending_queue_only", dict(total=(1000, 1), x=8001, delegated=(100,))), ("pending_extra_room", dict(total=(1000, 2), x=1000, y=8000)),
    ("count_four", dict(total=(1, 4), x=1)), ("count_five", dict(total=(1, 5), x=1)), ("count_six", dict(total=(1, 6), x=1)), ("count_top", dict(total=(1, MASK[8]), x=1)), ("count_zero", dict(total=(1, 0), x=1)), ("count_before_funds", dict(total=(100, 5), x=8901)),
    ("no_totals_tree", dict(t_shape="none")), ("no_totals_tree_alloc_fails", dict(t_shape="none", alloc_fail=True)), ("no_totals_row_low", dict(t_near=((-1, 0),))), ("no_totals_row_high", dict(t_near=((1, 0),))), ("no_totals_empty_leaf", dict(t_near=())),
    ("users_deep_root", dict(s_shape="deep", **FULL_TOTAL)), ("users_deep_left", dict(s_shape="deep", s_near=((1, 0), (2, 0), (3, 0), (4, 0)))), ("users_deep_right", dict(s_shape="deep", s_near=((-1, 0), (-2, 0), (-3, 0), (-4, 0)))), ("users_deep_gap", dict(s_shape="deep", v0=None, s_near=((-2, 0), (-1, 0), (1, 0), (2, 0), (3, 0)))),
    ("users_last_byte", dict(s_near=((0, -1), (0, 1)))), ("users_deep_missing_left", dict(s_shape="deep", v0=None, s_near=((1, 0), (2, 0), (3, 0)))), ("users_deep_missing_right", dict(s_shape="deep", v0=None, s_near=((-1, 0), (-2, 0), (-3, 0)))),
    ("totals_deep_root", dict(t_shape="deep", total=(5, 1), t_near=((-2, 0), (-1, 0), (1, 0), (2, 0)))), ("totals_deep_left", dict(t_shape="deep", total=(5, 1), t_near=((1, 0), (2, 0), (3, 0), (4, 0)))), ("totals_deep_right", dict(t_shape="deep", total=(5, 1), t_near=((-1, 0), (-2, 0), (-3, 0), (-4, 0)))),
    ("totals_deep_missing_left", dict(t_shape="deep", t_near=((1, 0), (2, 0), (3, 0)))), ("totals_deep_missing_right", dict(t_shape="deep", t_near=((-1, 0), (-2, 0), (-3, 0)))), ("totals_deep_missing_mid", dict(t_shape="deep", t_near=((-2, 0), (-1, 0), (1, 0), (2, 0)))), ("totals_last_byte", dict(total=(5, 1), t_near=((0, -1), (0, 1)))),
    ("queue_no_tree", dict(q_shape="none")), ("queue_empty_leaf", dict(q_near=())), ("queue_key_present", dict(rows=(2, 4))), ("queue_key_full", dict(rows=(4, 4))), ("queue_key_empty_vec", dict(rows=(0, 0))), ("queue_key_empty_room", dict(rows=(0, 3))),
    ("queue_near_all", dict(q_near=QK)), ("queue_near_all_present", dict(q_near=QK, rows=(1, 2))), ("queue_near_date", dict(q_near=((-1, 0, 0), (1, 0, 0)), rows=(1, 2))), ("queue_near_secs", dict(q_near=((0, -1, 0), (0, 1, 0)), rows=(1, 2))), ("queue_near_frac", dict(q_near=((0, 0, -1), (0, 0, 1)), rows=(1, 2))),
    ("queue_only_below", dict(q_near=((-3, 0, 0), (-2, 0, 0), (-1, 0, 0)))), ("queue_only_above", dict(q_near=((1, 0, 0), (2, 0, 0), (3, 0, 0)))), ("queue_date_negative", dict(unlock=(-1, 9, 9), q_near=((-5, 0, 0), (5, 0, 0)), rows=(1, 1))), ("queue_date_negative_missing", dict(unlock=(-1, 9, 9), q_near=((-5, 0, 0), (5, 0, 0)))),
    ("queue_secs_top", dict(unlock=(7, 0x80000000, 3), q_near=((0, -1, 0), (0, 1, 0)), rows=(1, 2))), ("queue_frac_top", dict(unlock=(7, 3, 0x80000000), q_near=((0, 0, -1), (0, 0, 1)), rows=(1, 2))),
    ("queue_deep_root", dict(q_shape="deep", q_near=((-2, 0, 0), (-1, 0, 0), (1, 0, 0), (2, 0, 0)), rows=(1, 2))), ("queue_deep_left", dict(q_shape="deep", q_near=((1, 0, 0), (2, 0, 0), (3, 0, 0), (4, 0, 0)), rows=(1, 2))), ("queue_deep_right", dict(q_shape="deep", q_near=((-1, 0, 0), (-2, 0, 0), (-3, 0, 0), (-4, 0, 0)), rows=(1, 2))),
    ("queue_deep_missing_left", dict(q_shape="deep", q_near=((1, 0, 0), (2, 0, 0), (3, 0, 0)))), ("queue_deep_missing_right", dict(q_shape="deep", q_near=((-1, 0, 0), (-2, 0, 0), (-3, 0, 0)))), ("queue_deep_missing_mid", dict(q_shape="deep", q_near=((-2, 0, 0), (-1, 0, 0), (1, 0, 0), (2, 0, 0)))),
    ("amount_top", dict(x=MASK[8], v0=MASK[8])), ("amount_above_lanes", dict(x=(1 << 33) + 5, v0=(1 << 34))), ("v0_above_x_low_word", dict(x=(1 << 32) + 1, v0=1 << 33)), ("v0_low_word_only", dict(x=(1 << 32) + 1, v0=5)),
)
QUEUE_NAMED = (
    ("direct_plain", {}), ("direct_exact", dict(x=9000)), ("direct_over", dict(x=9001)), ("direct_pending_exact", dict(total=(1000, 1), x=8000)), ("direct_pending_over", dict(total=(1000, 1), x=8001)), ("direct_wrap", dict(total=(2, 1), x=MASK[8], v0=MASK[8])),
    ("direct_wrap_top", dict(total=(MASK[8], 1), x=1, v0=MASK[8])), ("direct_wrap_low", dict(total=(MASK[8], 1), x=2, v0=0)), ("direct_top_exact", dict(total=(MASK[8] - 1, 1), x=1, v0=MASK[8])), ("direct_count_five_wrap", dict(total=(MASK[8], 5), x=1, v0=0)), ("direct_count_four", dict(total=(1, 4), x=1)),
    ("direct_absent_zero", dict(x=0, v0=0)), ("direct_absent_no_tree_over", dict(t_shape="none", x=9001)), ("direct_absent_no_tree_exact", dict(t_shape="none", x=9000)), ("direct_absent_deep_over", dict(t_shape="deep", t_near=((-1, 0), (-2, 0), (-3, 0)), x=9001)), ("direct_absent_deep_exact", dict(t_shape="deep", t_near=((1, 0), (2, 0), (3, 0)), x=9000)),
    ("direct_count_top", dict(total=(0, 3), x=0, v0=0)), ("direct_zero_x_pending", dict(total=(5, 2), x=0, v0=5)), ("direct_zero_x_short", dict(total=(5, 2), x=0, v0=4)),
    ("direct_deep_left_over", dict(t_shape="deep", total=(5, 1), t_near=((1, 0), (2, 0), (3, 0), (4, 0)), x=8996)), ("direct_deep_right_over", dict(t_shape="deep", total=(5, 1), t_near=((-1, 0), (-2, 0), (-3, 0), (-4, 0)), x=8996)),
)


def named_cases():
    return [Case(name, GATE, **fields) for name, fields in GATE_NAMED] + [Case(name, QUEUE, **fields) for name, fields in QUEUE_NAMED]


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11 ^ state


def vector_cases(count):
    source = lcg(0x3F93)
    rows = []
    for index in range(count):
        word = next(source)
        v0 = next(source) >> (word & 63)
        held = [next(source) >> (word >> 6 & 63) for _ in range(word >> 12 & 3)]
        pending = next(source) >> (word >> 14 & 63)
        total = v0 + sum(held) if v0 + sum(held) <= MASK[8] else 0
        room = max(total - pending, 0)
        y = next(source) >> (word >> 20 & 63) if word >> 26 & 1 else 0
        x = (room - y + (word >> 27 & 3) - 1) & MASK[8] if word >> 29 & 3 else next(source) >> (word >> 31 & 63)
        fields = dict(x=x, y=y, v0=v0 if word >> 37 & 7 else None, delegated=tuple(held), total=(pending, word >> 40 & 7) if word >> 43 & 3 else None, mode=word >> 45 & 3, rows=(1, 1 + (word >> 47 & 1)) if word >> 48 & 1 else None,
                      lock=(20000, 100 + (word >> 49 & 3) - 1, 5) if word >> 51 & 1 else (0, 0, 0))
        rows.append(Case("v%d" % index, GATE, **fields))
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
    named = ((SLOT_GATE, "gate", GATE), (SLOT_TOTAL, "delegated total", TOTAL))
    rows = []
    for slot, role, target in named:
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        rows.append(("%#x" % slot, role, "%#x" % target, len(slot_sites(image, slot))))
    return rows


def site_rows(image):
    """Each indirect call of the gate, and the state fields loaded just before it, from fixed bytes."""
    start, text = image.text_bytes()
    rows = []
    forms = ((b"\x48\x8d\xb1\xf8\x08\x00\x00\x0f\xb6\x91\xf2\x08\x00\x00", 0x8F8, 0x8F2), (b"\x49\x8d\xb6\x78\x13\x00\x00\x41\x0f\xb6\x96\x72\x13\x00\x00", 0x1378, 0x1372))
    for site in sorted(slot_sites(image, SLOT_GATE)):
        window = text[site - start - 0x70:site - start]
        hits = [(staking, chain) for data, staking, chain in forms if data in window]
        if len(hits) != 1:
            raise EvidenceError("gate call shape at %#x" % site)
        rows.append(("%#x" % site, "%#x" % hits[0][0], "%#x" % hits[0][1]))
    if [row[1] for row in rows] != ["0x8f8", "0x8f8", "0x1378"]:
        raise EvidenceError("gate call rows %r" % rows)
    direct = direct_to(image, GATE)
    gate_calls = direct_to(image, QUEUE)
    if direct != [] or gate_calls != [0x39935A2]:
        raise EvidenceError("direct calls %r %r" % (direct, gate_calls))
    return rows


def constant_rows(image):
    first, second = struct.unpack_from("<2d", image.blob, image.offset(SECONDS_TABLE))
    if (first, second) != (604800.0, 300.0):
        raise EvidenceError("seconds table")
    rows = [("%#x" % SECONDS_TABLE, 0, first), ("%#x" % (SECONDS_TABLE + 8), 1, second)]
    return rows


def key_at(image, va, stop):
    """First `lea key,%rsi` followed by `mov $len,%edx` in the window; returns the key text."""
    data = bytes(image.blob[image.offset(va):image.offset(va) + stop])
    for match in re.finditer(b"\x48\x8d\x35", data):
        at = match.start()
        if data[at + 7] == 0xBA:
            target = va + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
            size = struct.unpack_from("<I", data, at + 8)[0]
            return target, bytes(image.blob[image.offset(target):image.offset(target) + size]).decode("ascii")
    raise EvidenceError("no key at %#x" % va)


def name_rows(image):
    rows = []
    for site, offset, name in SERIALIZER_SITES:
        data = bytes(image.blob[image.offset(site - 0x10):image.offset(site) + 5])
        if b"\x48\x8d\xb3" + struct.pack("<i", offset) not in data[:0x10] or data[0x10] != 0xE8:
            raise EvidenceError("serializer row %#x" % site)
        callee = site + 5 + struct.unpack_from("<i", data, 0x11)[0]
        target, text = key_at(image, callee, 0x40)
        if text != name:
            raise EvidenceError("key %#x: %r" % (site, text))
        rows.append(("%#x" % site, "%#x" % offset, "%#x" % target, text))
    data = bytes(image.blob[image.offset(QUEUE_STRUCT):image.offset(QUEUE_STRUCT) + 0xD0])
    found = []
    for match in re.finditer(b"\x48\x8d\x35", data):
        at = match.start()
        tail = data[at + 7:at + 19]
        size = re.search(b"\xba(.)\x00\x00\x00", tail, re.S)
        if size:
            target = QUEUE_STRUCT + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
            found.append((target, bytes(image.blob[image.offset(target):image.offset(target) + size[1][0]]).decode("ascii")))
    if [text for _, text in found[:2]] != ["queue", "user_to_total_withdrawal"]:
        raise EvidenceError("queue struct keys %r" % found)
    for index, (target, text) in enumerate(found[:2]):
        rows.append(("%#x" % QUEUE_STRUCT, "pending_withdrawals key %d" % index, "%#x" % target, text))
    data = bytes(image.blob[image.offset(SUMMARY_STRUCT):image.offset(SUMMARY_STRUCT) + 0xE0])
    found = []
    for match in re.finditer(b"\x48\x8d\x35(.{4})\x48\x89\xe7\xba(.{4})", data, re.S):
        target = SUMMARY_STRUCT + match.start() + 7 + struct.unpack("<i", match[1])[0]
        found.append((target, bytes(image.blob[image.offset(target):image.offset(target) + struct.unpack("<I", match[2])[0]]).decode("ascii")))
    if tuple(text for _, text in found) != SUMMARY_KEYS:
        raise EvidenceError("summary keys %r" % found)
    for index, (target, text) in enumerate(found):
        rows.append(("%#x" % SUMMARY_STRUCT, "summary word %d" % index, "%#x" % target, text))
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


def mode_rows(harness):
    """Every low byte of the mode word on the same queue run; high bits set to prove they are ignored."""
    groups = {}
    for byte in range(256):
        case = Case("m", GATE, mode=0xA5A500 | byte, v0=9000)
        got = harness.run(case)
        if got != spec_run(case, harness.before, harness.where):
            raise EvidenceError("mode byte %#x" % byte)
        seconds = next(event[2] for event in got[1] if event[0] == "time")
        groups.setdefault(struct.unpack("<d", seconds)[0], []).append(byte)
    rows = []
    for seconds, bytes_seen in sorted(groups.items()):
        rows.append((seconds, len(bytes_seen), " ".join("%#x" % byte for byte in bytes_seen[:4])))
    if [row[1] for row in rows] != [2, 254]:
        raise EvidenceError("mode groups %r" % rows)
    return rows


def piece_rows(harness):
    """Both ends of each amount piece for fixed rows: undelegated U, delegated D, pending P, extra Y."""
    rows = []
    machine = harness.machine
    top = MASK[8]
    fixtures = (("funds_by_gate", dict(v0=3000, delegated=(1000,), total=(1000, 1), y=2000), ((0, 1000), (1001, top - 2000), (top - 1999, top))),
                ("funds_by_queue", dict(v0=3000, delegated=(5000,), total=(1000, 1), y=0), ((0, 2000), (2001, 7000), (7001, top))),
                ("no_pending", dict(v0=3000, delegated=(), total=None, y=0), ((0, 3000), (3001, top))))
    for name, fields, ranges in fixtures:
        for low, high in ranges:
            walked, results = [], []
            for value in (low, high):
                case = Case("%s_%#x" % (name, value), GATE, x=value, **fields)
                saved = machine.seen
                machine.seen = set()
                got = harness.run(case)
                walked.append(machine.seen)
                machine.seen = saved | walked[-1]
                if got != spec_run(case, harness.before, harness.where):
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
        want = spec_run(case, harness.before, harness.where)
        if got != want:
            if got[0] == "done" and want[0] == "done":
                diff = [hex(HEAP_BASE + at) for at in range(COMPARED) if got[2][at] != want[2][at]][:12]
                raise EvidenceError("case %s: events %r != %r diff %s" % (case.name, got[1], want[1], diff))
            raise EvidenceError("case %s: %r != %r" % (case.name, got[:2], want[:2]))
        outcomes.append(got)
    return outcomes


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
EXPECTED_SURVIVORS = {
    (0x3C131AA, "immediate"): "the saturation constant for the row count: the count is at most 4 at this row, so the add never wraps",
    (0x3C0F1D5, "immediate"): EIGHT, (0x3C0F2B8, "immediate"): EIGHT,
    (0x3C0F232, "displacement"): "first leaf length at slot 0: only tested against 0, and any leaf reached with rows left holds a row, so a nonzero stale word reads the same",
    (0x33BACD6, "immediate"): "a fresh node has length 0, so the capacity test passes for either bound",
    (0x33BAD02, "immediate"): "the value slot index of a fresh node is 0, so the shift count has no effect",
}


def run_mutants(image, table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    for target in TARGETS:
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            if first_failure(harness, cases) is not None:
                results.append((va, kind, "killed", "whole run"))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True, vectors=600):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    check_cases(harness, vector_cases(vectors))
    modes = mode_rows(harness)
    pieces = piece_rows(harness)
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, slots=slot_rows(image), sites=site_rows(image), constants=constant_rows(image), names=name_rows(image),
                  statuses=status_rows(image), modes=modes, pieces=pieces)
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
    tsv("gate-call-sites.tsv", ("site", "staking_offset", "chain_byte_offset"), result["sites"])
    tsv("seconds-table.tsv", ("address", "index", "seconds"), result["constants"])
    tsv("field-names.tsv", ("site", "offset", "key_address", "key"), result["names"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("mode-bytes.tsv", ("seconds", "low_bytes", "first_values"), result["modes"])
    tsv("amount-pieces.tsv", ("fixture", "low", "high", "status"), result["pieces"])
    tsv("outcomes.tsv", ("entry", "case", "status", "out_head", "events", "state_digest"),
        [("%#x" % case.kind, case.name) + describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
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
