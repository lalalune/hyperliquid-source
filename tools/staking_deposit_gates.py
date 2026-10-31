#!/usr/bin/env python3
"""Pin the node #94 staking deposit amount gates from ELF bytes.

0x2734840 and its copies 0x4d40eb0 and 0x4d44e60 move an amount of the native token into staking:
input cap, native token presence, zero, room in the balance row (hold + x <= total), the staking
call, the debit, and the ledger event with the amount as a float over 10^wei. The real bytes run
under recording stubs over real B-tree nodes, a separately written rule list predicts every run
including all fixture bytes, and every reached conditional row is mutated. No objdump or readelf
output is parsed and the binary is never executed. Standard library only.

    python3 tools/staking_deposit_gates.py --out <dir>
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


def fdiv(left, right):
    if right == 0:
        if left != left or left == 0:
            return math.nan
        return math.copysign(math.inf, left) * math.copysign(1.0, right)
    return left / right


COPIES = (0x2734840, 0x4D40EB0, 0x4D44E60)
TARGETS = COPIES
NAMES = {COPIES[0]: "core_a", COPIES[1]: "core_b", COPIES[2]: "core_c"}
CALLERS = (0x2731F50, 0x4D408C0, 0x4D3B850)

SLOT_HOLDER = 0x5773170
SLOT_STAKE = 0x5774B30
SLOT_DEBIT = 0x5774730
SLOT_TIMER = 0x5774910
SLOT_NAME = 0x57746B8
SLOT_EVENT = 0x5774738
SLOT_EVENT_DEX = 0x5776AD0
SLOT_AFTER_DEX = 0x5776B10
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAIL = 0x576E020
SLOT_INDEX_PANIC = 0x576E470
PANIC_LOCATION = 0x56F21F0
ADD_ENTRY = 0x371D120
LEDGER = 0x3987CB0
POW10 = 0x584B08
MARK_BASE = 0x7700000000
STATUS_DROPS = {COPIES[0]: 0x277EBA0, COPIES[1]: 0x4DAF4A0, COPIES[2]: 0x4DAF4A0}
SHIFT = {COPIES[0]: 0, COPIES[1]: 0, COPIES[2]: 0xA80}

TAG_OK = 0x186
TAG_NUMBER = 0x13F
TAG_NO_NATIVE = 0xFB
TAG_ZERO = 0x2F
TAG_FUNDS = 0x2C
STATUS_TABLE = 0x59A8D0
TEXT_ARMS = (TAG_NUMBER, TAG_NO_NATIVE, TAG_ZERO, TAG_FUNDS)
CAP = 0xCCCCCCCCCCCCCCC
EVENT_WORD = 0x8000000000000016

S_MODE = 0x00
S_LEDGER_FIRST = 0x08
S_LEDGER_SECOND = 0x28
S_DEPTH = 0x58
S_NOW = 0x60
S_NATIVE_SOME = 0x80
S_NATIVE = 0x88
S_BALANCES = 0x80
S_NAMES = 0x90
S_TOKENS_PTR = 0x210
S_TOKENS_LEN = 0x218
S_BYTE = 0x8F2
S_EVENT_OWNER = 0x8F3
S_STAKING = 0x8F8
S_TIMERS = 0x3380
S_THIRD_OWNER = 0x5B8
TOKEN_STRIDE = 0xE8
FIELD_WEI = 0x49

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
USER_AT = HEAP_BASE + 0x500
USER_COPY = HEAP_BASE + 0x520
HOLDER = HEAP_BASE + 0x600
USER_VEC = HEAP_BASE + 0x700
NODES = HEAP_BASE + 0x1000
NODE_STRIDE = 0x200
TOKENS = HEAP_BASE + 0x3000
STATE = HEAP_BASE + 0x8000
STATE_SIZE = 0x4800
COMPARED = 0xD000
USED = 0x10000
FILL = 0xCC
CAPACITY = 11
USER = bytes(range(0x31, 0x45))
NAME_WORDS = (0x1111, 0x2222, 0x3333)
LEDGER_WORDS = bytes(range(0x90, 0xB0))
TIMER_MARK = 0xABCDEF


class Case:
    FIELDS = dict(x=1000, native_some=1, native=7, shape="leaf", balances=None, stake_tag=None, debit_ok=True, alloc_fail=False, mode=0, ledger=(11, 22), wei=8, tokens=8, depth=5, byte=0x5B, now=(20000, 100, 5))

    def __init__(self, name, kind, **fields):
        self.name = name
        self.kind = kind
        for key, value in self.FIELDS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.FIELDS:
                raise EvidenceError("field " + key)
            setattr(self, key, value)
        if self.balances is None:
            self.balances = {3: (9, 9, 0), 7: (5000, 1000, 0), 9: (1, 1, 0)}

    def funds(self):
        if self.shape == "none":
            return None
        return self.balances.get(self.native)


def blank():
    return bytes((index * 7 + 0x40) & 0xFF for index in range(OUT_SIZE))


def failure_body(tag):
    data = bytearray((index * 11 + 3) & 0xFF for index in range(OUT_SIZE))
    data[0:2] = struct.pack("<H", tag)
    return bytes(data)


def spec_run(case, before, table):
    """Predict one run from the rule list, written apart from the bytes under test."""
    image = bytearray(before)
    shift = SHIFT[case.kind]
    events = []

    def put(addr, data):
        at = addr - HEAP_BASE
        image[at:at + len(data)] = data

    def finish(tag=None, word=None):
        depth = min(case.depth + 1, MASK[8])
        put(STATE + S_DEPTH, struct.pack("<Q", max(depth - 1, 0)))
        if tag is not None:
            put(OUT, struct.pack("<H", tag))
        if word is not None:
            put(OUT + 8, struct.pack("<Q", word))
        return "done", tuple(events), bytes(image)

    if case.x >= CAP:
        return finish(TAG_NUMBER, case.x)
    if not case.native_some & 0xFF:
        return finish(TAG_NO_NATIVE)
    events.append(("drop", TAG_NO_NATIVE))
    if case.x == 0:
        return finish(TAG_ZERO)
    events.append(("holder",))
    total, hold = 0, 0
    found = case.funds()
    if found is not None:
        total, hold = found[0], found[1]
    wanted = hold + case.x
    if wanted > MASK[8] or wanted > total:
        return finish(TAG_FUNDS)
    events.append(("stake", case.x, case.now))
    if case.stake_tag is not None:
        put(OUT, failure_body(case.stake_tag))
        return finish()
    events.append(("debit", case.native, case.x))
    if not case.debit_ok:
        return finish(TAG_FUNDS)
    events.append(("timer", case.native))
    events.append(("add", case.native, 1, case.x, TIMER_MARK))
    events.append(("alloc",))
    if case.alloc_fail:
        events.append(("alloc_fail",))
        return "panic", "alloc", tuple(events)
    put(USER_VEC, USER)
    if case.mode == 1:
        events.append(("ledger", case.byte, case.ledger[0], case.ledger[1]))
    events.append(("name", case.native))
    if case.native >= case.tokens:
        return "panic", "index", tuple(events)
    amount = float(case.x) / table[case.wei]
    if shift:
        events.append(("event_dex", USER, case.now, case.mode == 1, NAME_WORDS, struct.pack("<d", amount)))
        events.append(("after_dex", case.x, case.native, USER, case.byte))
    else:
        events.append(("event", USER, case.now, case.mode == 1, NAME_WORDS, struct.pack("<d", amount)))
    return finish(TAG_OK)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        self.table = struct.unpack_from("<20d", image.blob, image.offset(POW10))
        statics = machine.memory.statics
        hooks = {SLOT_HOLDER: self.on_holder, SLOT_STAKE: self.on_stake, SLOT_DEBIT: self.on_debit, SLOT_TIMER: self.on_timer, SLOT_NAME: self.on_name, SLOT_EVENT: self.on_event,
                 SLOT_EVENT_DEX: self.on_event, SLOT_AFTER_DEX: self.on_after_dex, SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_FAIL: self.on_alloc_fail, SLOT_INDEX_PANIC: self.on_index}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        machine.calls = {ADD_ENTRY: self.on_add, LEDGER: self.on_ledger}
        for target in STATUS_DROPS.values():
            machine.calls[target] = self.on_drop
        self.events = []
        self.case = None
        self.before = None

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def bytes_at(self, addr, size):
        return self.machine.memory.bytes_at(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def on_drop(self, machine):
        self.events.append(("drop", struct.unpack("<H", self.bytes_at(machine.regs[RDI], 2))[0]))

    def on_holder(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + S_BALANCES, "balance map")
        self.expect(self.bytes_at(regs[RSI], 20) == USER, "holder key")
        self.events.append(("holder",))
        regs[RAX] = HOLDER

    def on_stake(self, machine):
        regs = machine.regs
        case = self.case
        self.expect(regs[RSI] == STATE + SHIFT[case.kind] + S_STAKING, "staking state")
        self.expect(self.bytes_at(regs[RDX], 20) == USER, "stake user")
        self.events.append(("stake", regs[RCX], struct.unpack("<III", self.bytes_at(regs[R8], 12))))
        machine.memory.put_bytes(regs[RDI], failure_body(case.stake_tag if case.stake_tag is not None else TAG_OK))

    def on_debit(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + S_BALANCES, "debit map")
        self.expect(self.bytes_at(regs[RSI], 20) == USER, "debit user")
        self.events.append(("debit", regs[RDX], regs[RCX]))
        regs[RAX] = 1 if self.case.debit_ok else 0xFFFFFF00

    def on_timer(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + S_BALANCES, "timer map")
        self.expect(regs[RDX] == STATE + SHIFT[self.case.kind] + S_TIMERS, "timer state")
        self.events.append(("timer", regs[RSI]))
        regs[RAX] = TIMER_MARK

    def on_add(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + S_BALANCES, "add map")
        self.expect(self.bytes_at(regs[RSI], 20) == USER, "add user")
        self.events.append(("add", regs[RDX], regs[RCX], regs[R8], regs[R9]))

    def on_alloc(self, machine):
        self.expect(machine.regs[RDI] & MASK[4] == 20, "alloc size")
        self.events.append(("alloc",))
        machine.regs[RAX] = 0 if self.case.alloc_fail else USER_VEC

    def on_alloc_fail(self, machine):
        self.expect(machine.regs[RDI] & MASK[4] == 1 and machine.regs[RSI] & MASK[4] == 20, "alloc failure layout")
        self.events.append(("alloc_fail",))
        raise Panicked("alloc")

    def on_index(self, machine):
        self.expect(machine.regs[RDI] == PANIC_LOCATION, "panic location")
        raise Panicked("index")

    def on_ledger(self, machine):
        regs = machine.regs
        self.expect(regs[R8] & MASK[4] == 0, "ledger flag")
        self.events.append(("ledger", regs[RSI] & 0xFF, regs[RCX], regs[RDX]))
        machine.memory.put_bytes(regs[RDI], LEDGER_WORDS)

    def on_name(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == STATE + S_NAMES, "name state")
        self.events.append(("name", regs[RSI]))
        machine.memory.put_bytes(regs[RDI], struct.pack("<3Q", *NAME_WORDS))

    def on_event(self, machine):
        regs = machine.regs
        case = self.case
        shift = SHIFT[case.kind]
        self.expect(regs[RDI] == (STATE + S_THIRD_OWNER if shift else STATE + S_EVENT_OWNER), "event owner")
        vec = struct.unpack("<3Q", self.bytes_at(regs[RSI], 24))
        self.expect(vec == (1, USER_VEC, 1), "user vector")
        now = struct.unpack("<III", self.bytes_at(regs[RDX], 12))
        ledger = self.bytes_at(regs[RCX], 32)
        self.expect(ledger == (LEDGER_WORDS if case.mode == 1 else bytes(32)), "ledger bytes")
        event = self.bytes_at(regs[R8], 0x30)
        self.expect(struct.unpack_from("<Q", event, 0)[0] == EVENT_WORD, "event word")
        self.expect(event[0x28] == 1, "event byte")
        self.events.append(("event_dex" if shift else "event", self.bytes_at(USER_VEC, 20), now, case.mode == 1, struct.unpack_from("<3Q", event, 8), event[0x20:0x28]))

    def on_after_dex(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + S_THIRD_OWNER, "after owner")
        data = self.bytes_at(regs[RSI], 0x38)
        self.expect(struct.unpack_from("<Q", data, 0)[0] == STATE, "after state")
        self.expect(struct.unpack_from("<Q", data, 8)[0] == STATE + S_NAMES, "after names")
        self.events.append(("after_dex", struct.unpack_from("<Q", data, 0x10)[0], struct.unpack_from("<Q", data, 0x18)[0], data[0x20:0x34], data[0x34]))

    def node(self, index, keys, values, children, stale):
        base = NODES + index * NODE_STRIDE
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * 0x1D0)
        for at in range(CAPACITY):
            key = keys[at] if at < len(keys) else stale
            self.word(base + 8 + 8 * at, key)
            total, hold, third = values[at] if at < len(values) else (MASK[8], MASK[8], MASK[8])
            self.word(base + 0x60 + 0x18 * at, total)
            self.word(base + 0x68 + 0x18 * at, hold)
            self.word(base + 0x70 + 0x18 * at, third)
        self.word(base + 0x16A, len(keys), 2)
        for at, child in enumerate(children):
            self.word(base + 0x170 + 8 * at, NODES + child * NODE_STRIDE)
        return base

    def tree(self, case):
        items = sorted(case.balances.items())
        self.word(HOLDER + 0x10, 0)
        self.word(HOLDER + 0x18, 0)
        if case.shape == "none":
            return
        keys = [key for key, _ in items]
        values = [value for _, value in items]
        if case.shape == "leaf":
            root = self.node(0, keys, values, (), case.native)
            height = 0
        else:
            half = len(keys) // 2
            self.node(1, keys[:half], values[:half], (), case.native)
            self.node(2, keys[half + 1:], values[half + 1:], (), case.native)
            root = self.node(0, keys[half:half + 1], values[half:half + 1], (1, 2), case.native)
            height = 1
        self.word(HOLDER + 0x10, root)
        self.word(HOLDER + 0x18, height)

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        shift = SHIFT[case.kind]
        memory.put_bytes(HEAP_BASE, bytes([FILL]) * COMPARED)
        memory.put_bytes(OUT, blank())
        memory.put_bytes(USER_AT, USER)
        self.word(STATE + S_MODE, case.mode, 4)
        self.word(STATE + S_LEDGER_FIRST, case.ledger[0])
        self.word(STATE + S_LEDGER_SECOND, case.ledger[1])
        self.word(STATE + S_DEPTH, case.depth)
        memory.put_bytes(STATE + S_NOW, struct.pack("<III", *case.now))
        memory.write(STATE + S_NATIVE_SOME, 1, case.native_some)
        self.word(STATE + S_NATIVE, case.native)
        self.word(STATE + S_TOKENS_PTR, TOKENS)
        self.word(STATE + S_TOKENS_LEN, case.tokens)
        memory.write(STATE + shift + S_BYTE, 1, case.byte)
        for index in range(16):
            memory.write(TOKENS + index * TOKEN_STRIDE + FIELD_WEI, 1, case.wei)
            memory.write(TOKENS + index * TOKEN_STRIDE + FIELD_WEI - 1, 1, 17)
            memory.write(TOKENS + index * TOKEN_STRIDE + FIELD_WEI + 1, 1, 15)
        self.tree(case)
        self.events = []
        self.case = case
        self.before = memory.bytes_at(HEAP_BASE, COMPARED)

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        try:
            self.machine.run(case.kind, {RDI: OUT, RSI: USER_AT, RDX: case.x, RCX: STATE})
        except Panicked as stop:
            return "panic", stop.args[0], tuple(self.events)
        return "done", tuple(self.events), memory.bytes_at(HEAP_BASE, COMPARED)


LADDER = {1: (1, 0, 0), 3: (9, 0, 0), 5: (9, 8, 0), 7: (5000, 1000, 0), 9: (1, 1, 0), 11: (MASK[8], 0, 0), 13: (0, 0, 0)}
NAMED = (
    ("plain", {}), ("mode_one", dict(mode=1)), ("mode_two", dict(mode=2)), ("mode_high_bits", dict(mode=0x101)),
    ("cap_minus_one", dict(x=CAP - 1, balances={7: (MASK[8], 0, 0)})), ("at_cap", dict(x=CAP)), ("above_cap", dict(x=CAP + 1)), ("top", dict(x=MASK[8])), ("top_bit", dict(x=1 << 63)),
    ("cap_before_native", dict(x=CAP, native_some=0)), ("no_native", dict(native_some=0)), ("no_native_zero", dict(native_some=0, x=0)), ("native_tag_two", dict(native_some=2)), ("native_high_bit", dict(native_some=0x80)),
    ("zero", dict(x=0)), ("zero_no_tree", dict(x=0, shape="none")), ("no_tree", dict(shape="none")),
    ("exact_room", dict(x=4000)), ("over_by_one", dict(x=4001)), ("one_under", dict(x=3999)), ("no_room", dict(balances={7: (1000, 1000, 0)}, x=1)), ("hold_above_total", dict(balances={7: (5, 900, 0)}, x=1)),
    ("sum_wraps", dict(balances={7: (MASK[8], MASK[8], 0)}, x=1)), ("sum_wraps_to_zero_room", dict(balances={7: (MASK[8], MASK[8] - 2, 0)}, x=3)), ("sum_at_top", dict(balances={7: (MASK[8], MASK[8] - 2, 0)}, x=2)),
    ("key_missing_low", dict(balances={9: (5000, 0, 0)})), ("key_missing_high", dict(balances={3: (5000, 0, 0)})), ("key_first", dict(balances={7: (5000, 0, 0), 9: (1, 0, 0)})), ("key_last", dict(balances={1: (1, 0, 0), 7: (5000, 0, 0)})),
    ("key_top_bit", dict(native=7, balances={3: (1, 0, 0), 7: (5000, 0, 0), (1 << 63) + 7: (1, 0, 0)})),
    ("tree_root", dict(shape="deep", balances=LADDER, native=7)), ("tree_left", dict(shape="deep", balances=LADDER, native=3, x=9)), ("tree_left_full", dict(shape="deep", balances=LADDER, native=5, x=1)), ("tree_right", dict(shape="deep", balances=LADDER, native=11, x=9, tokens=12, wei=2)),
    ("tree_right_last", dict(shape="deep", balances=LADDER, native=13, x=1, tokens=14)), ("tree_gap", dict(shape="deep", balances=LADDER, native=4)), ("tree_gap_high", dict(shape="deep", balances=LADDER, native=20)),
    ("tree_gap_low", dict(shape="deep", balances=LADDER, native=0)), ("tree_gap_right", dict(shape="deep", balances=LADDER, native=10)),
    ("stake_fails", dict(stake_tag=0xBE)), ("stake_fails_12c", dict(stake_tag=0x12C)), ("stake_fails_high_byte", dict(stake_tag=0x286)), ("debit_refuses", dict(debit_ok=False)), ("alloc_fails", dict(alloc_fail=True)),
    ("wei_zero", dict(wei=0)), ("wei_two", dict(wei=2, x=4000)), ("wei_eighteen", dict(wei=18, x=3333)), ("big_float", dict(x=(1 << 59) + 1, balances={7: (MASK[8], 0, 0)})), ("float_lanes", dict(x=(1 << 33) + 5, balances={7: (MASK[8], 0, 0)})),
    ("token_at_bound", dict(native=7, tokens=7)), ("token_in_bound", dict(native=7, tokens=8)), ("token_mode_one_bound", dict(tokens=7, mode=1)),
    ("depth_zero", dict(depth=0)), ("depth_top", dict(depth=MASK[8])), ("depth_top_minus", dict(depth=MASK[8] - 1)), ("depth_top_cap", dict(depth=MASK[8], x=CAP)), ("depth_zero_fail", dict(depth=0, x=4001)),
    ("now_words", dict(now=(0xFFFFFFF0, 0x80000001, 0x7FFFFFFF))),
)


def named_cases(kind):
    return [Case(name, kind, **fields) for name, fields in NAMED]


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11 ^ state


def vector_cases(count):
    source = lcg(0x77A7)
    rows = []
    for index in range(count):
        word = next(source)
        total = next(source) >> (word & 63)
        hold = next(source) >> (word >> 6 & 63)
        x = (total - hold) & MASK[8] if word >> 12 & 1 and total >= hold else next(source) >> (word >> 13 & 63)
        x += (word >> 19 & 3) - 1
        fields = dict(x=x & MASK[8], balances={3: (1, 1, 0), 7: (total, hold, 0), 9: (2, 2, 0)}, mode=word >> 21 & 1, depth=next(source), wei=word >> 22 & 15, debit_ok=bool(word >> 26 & 7), native_some=1 if word >> 29 & 7 else 0, shape="leaf" if word >> 32 & 7 else "none")
        rows.append(Case("v%d" % index, COPIES[index % 3], **fields))
    return rows


def direct_to(image, target):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 <= len(text) and start + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            hits.append(start + at)
    return hits


def calls_through(image, slot):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text) and start + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            hits.append(start + at)
    return hits


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


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case, harness.before, harness.table)
        if got != want:
            raise EvidenceError("case %s of %#x: %r != %r" % (case.name, case.kind, got[:2], want[:2]))
        outcomes.append(got)
    return outcomes


def slot_rows(image):
    relative = image.relative()
    named = ((SLOT_HOLDER, "balance holder", 0x371B3A0), (SLOT_STAKE, "staking deposit", 0x39964D0), (SLOT_DEBIT, "balance debit", 0x371B140), (SLOT_TIMER, "timer value", 0x371CF40),
             (SLOT_NAME, "token name", 0x3C0D6E0), (SLOT_EVENT, "ledger event", 0x3576710), (SLOT_EVENT_DEX, "ledger event, third copy", 0x4855A50), (SLOT_AFTER_DEX, "after event, third copy", 0x4856460))
    rows = []
    for slot, role, target in named:
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        rows.append(("%#x" % slot, role, "%#x" % target))
    return rows


def site_rows(image):
    rows = []
    for name, copy, caller in zip(("core_a", "core_b", "core_c"), COPIES, CALLERS):
        sites = direct_to(image, copy)
        owners = sorted({image.fde(site)[0] for site in sites})
        if owners != [caller] or len(sites) != 3:
            raise EvidenceError("callers of %#x" % copy)
        rows.append(("%#x" % copy, name, len(sites), " ".join("%#x" % site for site in sorted(sites)), "%#x" % caller))
    return rows


def constant_rows(image):
    rows = []
    for copy, name in zip(COPIES, ("core_a", "core_b", "core_c")):
        start, stop = image.exact_fde(copy)
        data = bytes(image.blob[image.offset(start):image.offset(stop)])
        cap_at = data.index(struct.pack("<Q", CAP))
        word_at = data.index(struct.pack("<Q", EVENT_WORD))
        rows.append((name, "%#x" % (start + cap_at - 2), "%#x" % CAP, "%#x" % (start + word_at - 2), "%#x" % EVENT_WORD))
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
    """Run both ends of each amount piece on every copy with one balance row (total T, hold H)."""
    rows = []
    machine = harness.machine
    total, hold = 5000, 1000
    balances = {7: (total, hold, 0)}
    for low, high in ((0, 0), (1, total - hold), (total - hold + 1, CAP - 1), (CAP, MASK[8])):
        for copy in COPIES:
            walked = []
            results = []
            for value in (low, high):
                case = Case("x_%#x" % value, copy, x=value, balances=balances)
                saved = machine.seen
                machine.seen = set()
                got = harness.run(case)
                walked.append(machine.seen)
                machine.seen = saved | walked[-1]
                if got != spec_run(case, harness.before, harness.table):
                    raise EvidenceError("piece end %#x" % value)
                results.append(struct.unpack_from("<H", got[2], OUT - HEAP_BASE)[0])
            if results[0] != results[1]:
                raise EvidenceError("piece %#x..%#x has two statuses" % (low, high))
            same = walked[0] == walked[1]
            rows.append(("%#x" % copy, low, high, "%#x" % results[0], len(walked[0]), len(walked[1]), same))
    return rows


def first_failure(harness, cases):
    for case in cases:
        try:
            if harness.run(case) != spec_run(case, harness.before, harness.table):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError):
            return case
    return None


NO_ROW = "this branch runs only with no balance row: the words are 0, so the sum cannot wrap, and an amount above 0 is refused on either arm"
EXPECTED_SURVIVORS = {(0x27349AA, "condition"): NO_ROW, (0x2734C24, "condition"): NO_ROW, (0x4D4101A, "condition"): NO_ROW, (0x4D41294, "condition"): NO_ROW, (0x4D44FBA, "condition"): NO_ROW, (0x4D4526E, "condition"): NO_ROW}


def run_mutants(image, table, seen, lists):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    for copy in COPIES:
        if first_failure(control, lists[copy]) is not None:
            raise EvidenceError("an unedited image fails under the mutant step limit")
    for target in TARGETS:
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            if first_failure(harness, lists[target]) is not None:
                results.append((va, kind, "killed", "whole run"))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True, vectors=600):
    harness = Harness(image)
    lists = {copy: named_cases(copy) for copy in COPIES}
    outcomes = {copy: check_cases(harness, lists[copy]) for copy in COPIES}
    check_cases(harness, vector_cases(vectors))
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, lists=lists, outcomes=outcomes, vector_count=vectors, unreached=unreached, slots=slot_rows(image), sites=site_rows(image), constants=constant_rows(image),
                  statuses=status_rows(image), pieces=piece_rows(harness))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, lists)
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
    return "%#x" % tag, data[at:at + 0x10].hex(), ",".join(str(event[0]) for event in outcome[1]), hashlib.sha256(data).hexdigest()[:16]


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("slots.tsv", ("slot", "role", "relative_target"), result["slots"])
    tsv("call-sites.tsv", ("function", "name", "sites", "addresses", "caller_fde"), result["sites"])
    tsv("constants.tsv", ("copy", "cap_at", "cap", "event_word_at", "event_word"), result["constants"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("input-pieces.tsv", ("copy", "low", "high", "status", "rows_at_low", "rows_at_high", "same_rows"), result["pieces"])
    tsv("outcomes.tsv", ("function", "case", "status", "out_head", "events", "state_digest"),
        [("%#x" % copy, case.name) + describe(case, outcome) for copy in COPIES for case, outcome in zip(result["lists"][copy], result["outcomes"][copy])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": sum(len(rows) for rows in result["lists"].values()), "vector_cases": result["vector_count"],
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
