#!/usr/bin/env python3
"""Pin the node #94 deposit votes from ELF bytes.

Arm 44 votes with a validator key and arm 84 votes with a listed 20-byte address, both into one row of
`eth_id_to_deposit_votes`. A row finishes when stake passes 2/3 and a ratio of listed votes passes the f64 `q`
of the tracker; then the key moves to `finished_deposits_data`, and `bal` rises only for an amount of at least
5,000,000. Real bytes run under recording stubs, a separately written rule list predicts every status, stub
event and tree state, and reached conditional rows are mutated. No objdump or readelf output is parsed and the
binary is never executed. Standard library only.

    python3 tools/bridge_deposit_votes.py --out <dir>
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



WRAP_VALIDATOR = 0x1E5FEB0
WRAP_LISTED = 0x1E646C0
CORE = 0x374E2E0
TRACK = 0x3947510
FIND_FINISHED = 0x2FDD5D0
FIND_ROW = 0x2FDD750
PUT_FINISHED = 0x33A0310
FINISH_ROW = 0x3942480
QUORUM = 0x3940EA0
RATIO = 0x3BDE1F0
WEIGHT = 0x3366B60
MEMBER = 0x3367530
PUT_VOTER = 0x339E610
PUT_LISTED = 0x339BFC0
VACANT_ROW = 0x33C2950
VACANT_BUCKET = 0x33C1500
TAKE = 0x3BD09C0
NEXT_FINAL = 0x330FE30
DYING_NEXT = 0x33AE9E0
NAMES = {WRAP_VALIDATOR: "arm_44_wrapper", WRAP_LISTED: "arm_84_wrapper", CORE: "deposit_core", TRACK: "deposit_tracker", FIND_FINISHED: "find_finished", FIND_ROW: "find_row", PUT_FINISHED: "finished_insert", FINISH_ROW: "remove_row",
         QUORUM: "quorum", RATIO: "listed_ratio", WEIGHT: "stake_threshold", MEMBER: "is_member", PUT_VOTER: "voter_insert", PUT_LISTED: "listed_insert", VACANT_ROW: "vacant_row", VACANT_BUCKET: "vacant_bucket", TAKE: "first_100", DYING_NEXT: "dying_next"}
TARGETS = tuple(sorted(NAMES))
MUTATED = (WRAP_VALIDATOR, WRAP_LISTED, CORE, TRACK, FIND_FINISHED, FIND_ROW, QUORUM, RATIO, FINISH_ROW)

SLOT_RATIO = 0x5776230
SLOT_CORE = 0x5774A00
SLOT_VOTER = 0x5773148
SLOT_MEMBER = 0x5773D38
SLOT_RECORDER = 0x5773190
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
VOTER = 0x33690C0
HELPER_RECORDER = 0x358DCD0
CREDIT = 0x27123D0
STAKE_MAP = 0x3364ED0
STATUS_DROP = 0x3379490
SET_FINAL = 0x3BB2DC0
SET_LISTED = 0x3BB6560
REMOVE_ROW = 0x33AC830
MISSING = 0x3BAD4B0
DRAIN_SET = 0x33B1E80
CLONE_VOTERS = 0x33E9610
CLONE_LISTED = 0x33E31F0
DROPS = (0x33F3FC0, 0x33F3A90, 0x33F6800, 0x33F4CF0, 0x33F1200, 0x3401150, 0x33F7F10, 0x33F2530)
LEAF_ROW = 0x2F963C0
LEAF_BUCKET = 0x2F9FD70
LEAF_FINISHED = 0x2F8E060
LEAF_VOTER = 0x2F8BAD0
LEAF_LISTED = 0x2F513D0
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_LIMIT = 0x13F
TAG_FINISHED = 0x2D
TAG_PRUNED = 0x2E
TAG_NOT_LISTED = 0x2B
TAG_KIND = 0x37
TAG_NO_EPOCH = 0x97
TAG_NOT_VALIDATOR = 0x2A
OUTCOME_OK = 0xD
OUTCOME_ERROR = 0xE
STATUS_TABLE = 0x59A8D0
STATUS_TAGS = (TAG_LIMIT, TAG_FINISHED, TAG_PRUNED, TAG_NOT_LISTED, TAG_KIND, TAG_NO_EPOCH, TAG_NOT_VALIDATOR)
AMOUNT_LIMIT = 0x0CCCCCCCCCCCCCCC
MINIMUM = 0x4C4B40
ROW_NOTE = 0x64

S_BRIDGE = 0x3398
S_CTX = 0x3840
S_LISTED = 0x36A0
S_NOW = 0x60
B_Q = 0x18
B_I = 0x20
B_ROWS = 0x28
B_FINISHED = 0x100
B_BAL = 0x130
B_PRUNED = 0x138
C_ROOT = 0x30
C_EPOCH = 0x48

Layout = collections.namedtuple("Layout", "name key_at key_size val_at val_size parent index count size")
ROWS = Layout("deposit vote rows", 0, 0x40, 0x2C8, 0x48, 0x2C0, 0x5E0, 0x5E2, 0x5E8)
INNER = Layout("rows inner, amount and user", 0, 0x20, 0x160, 0x30, 0x370, 0x378, 0x37A, 0x380)
VOTERS = Layout("voter set", 0, 0x20, 0, 0, 0x160, 0x168, 0x16A, 0x170)
LISTED = Layout("20-byte set", 8, 0x14, 0, 0, 0, 0xE4, 0xE6, 0xE8)
FINISHED = Layout("finished deposits", 0, 0x40, 0x2C8, 0x28, 0x2C0, 0x480, 0x482, 0x488)
EPOCHS = Layout("epochs", 8, 8, 0x60, 0x28, 0, 0x218, 0x21A, 0x220)
VALIDATORS = Layout("validators", 0x2C0, 0x20, 0, 0x40, 0x420, 0x428, 0x42A, 0x430)
STAKES = Layout("stake map", 0, 0x20, 0x168, 8, 0x160, 0x1C0, 0x1C2, 0x1C8)
LAYOUTS = (ROWS, INNER, VOTERS, LISTED, FINISHED, EPOCHS, VALIDATORS, STAKES)
V_SIGNER = 0x18

ARENA = HEAP_BASE + 0x1000
USED = 0x80000
ARENA_END = HEAP_BASE + 0x70000
OUT = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x300
VOTE_ARG = HEAP_BASE + 0x500
SIGNER = HEAP_BASE + 0x600
HOLDER = HEAP_BASE + 0x640
TIME_AT = HEAP_BASE + 0x680
EPOCH = 7
NOW = bytes(range(0xA0, 0xAC))


def address(tag):
    return blob(tag, 20)


def blob(tag, size):
    """Distinct bytes, so that a shifted copy never matches by accident."""
    return bytes((tag + index) & 0xFF for index in range(size))


def row_order(key):
    words = struct.unpack_from("<QQQ", key)
    return (words[0], words[1], key[0x38], words[2], key[0x18:0x38])


def deposit_key(block, index=2, third=3, digest=None, kind=0):
    return struct.pack("<QQQ", block, index, third) + (digest or blob(0x90, 32)) + bytes([kind]) + blob(0x60, 7)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(TARGETS)
        statics = machine.memory.statics
        statics[SLOT_MEMBER] = MEMBER
        statics[SLOT_RATIO] = RATIO
        statics[SLOT_CORE] = CORE
        table = {SLOT_VOTER: self.on_voter, SLOT_RECORDER: self.on_recorder, SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_FAIL: self.on_stop, SLOT_ALLOC_ERROR: self.on_stop, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_memcpy,
                 SLOT_MEMMOVE: self.on_memcpy, SLOT_MEMCMP: self.on_memcmp, SLOT_NONE: self.on_none, SLOT_OVERFLOW: self.on_overflow, SLOT_ONCE: self.on_nothing}
        for slot, hook in table.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        calls = {STAKE_MAP: self.on_stakes, STATUS_DROP: self.on_nothing, SET_FINAL: self.on_set_voters, SET_LISTED: self.on_set_listed, REMOVE_ROW: self.on_remove, MISSING: self.on_missing, DRAIN_SET: self.on_drain, CLONE_VOTERS: self.on_clone, CLONE_LISTED: self.on_clone,
                 CREDIT: self.on_credit, LEAF_ROW: self.leaf(ROWS), LEAF_BUCKET: self.leaf(INNER), LEAF_FINISHED: self.leaf(FINISHED), LEAF_VOTER: self.leaf(VOTERS), LEAF_LISTED: self.leaf_listed}
        for drop in DROPS:
            calls[drop] = self.on_nothing
        machine.calls = calls
        self.events = []
        self.top = ARENA

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

    def on_recorder(self, machine):
        self.events.append(("recorder",))

    def on_voter(self, machine):
        out, signer = machine.regs[RDI], self.data(machine.regs[RDX], 20)
        self.expect(machine.regs[RSI] == self.ctx and machine.regs[RCX] == EPOCH, "voter lookup arguments")
        validators = self.scenario.validators if self.scenario.has_epoch else None
        hits = [key for key, who, _ in validators or () if who == signer]
        if validators is None or not hits:
            self.write(out, TAG_NOT_VALIDATOR if validators is not None else TAG_NO_EPOCH, 2)
            self.put(out + 2, ERROR_TAIL)
        else:
            self.write(out, TAG_OK, 2)
            self.put(out + 2, hits[0])

    def on_stakes(self, machine):
        out = machine.regs[RDI]
        self.expect(machine.regs[RSI] == self.epoch_value, "stake map of the wrong epoch")
        items = sorted((key, stake) for key, _, stake in self.scenario.validators)
        root = self.build(STAKES, [(key, struct.pack("<Q", stake)) for key, stake in items]) if items else 0
        self.write(out, root)
        self.write(out + 8, self.height(items))
        self.write(out + 0x10, len(items))

    def key_set(self, machine, source_layout, built_layout):
        out, source = machine.regs[RDI], machine.regs[RSI]
        root, height, count = self.read(source + 0x10), self.read(source + 0x18), self.read(source + 0x40)
        keys = [key for key, _ in self.walk(source_layout, root, height)] if self.read(source) else []
        self.expect(len(keys) == count, "set source length")
        built = self.build(built_layout, [(key, b"") for key in sorted(keys)]) if keys else 0
        self.write(out, built)
        self.write(out + 8, self.height(keys))
        self.write(out + 0x10, len(keys))

    def on_set_voters(self, machine):
        self.key_set(machine, VOTERS, VOTERS)

    def on_set_listed(self, machine):
        self.key_set(machine, LISTED, LISTED)

    def on_clone(self, machine):
        out = machine.regs[RDI]
        self.write(out, machine.regs[RSI])
        self.write(out + 8, machine.regs[RDX])
        self.write(out + 0x10, 0)

    def on_drain(self, machine):
        self.write(machine.regs[RDI], 0)

    def on_missing(self, machine):
        out = machine.regs[RDI]
        self.write(out, 0)
        self.write(out + 8, HEAP_BASE)
        self.write(out + 0x10, 0)

    def on_remove(self, machine):
        out, map_at, key_at = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        wanted = self.data(key_at, 0x40)
        for node, index in self.positions(ROWS, self.read(map_at), self.read(map_at + 8)):
            if self.data(node + index * 0x40, 0x40) == wanted:
                value = self.data(node + ROWS.val_at + index * ROWS.val_size, ROWS.val_size)
                count = self.read(node + ROWS.count, 2)
                tail = count - index - 1
                if tail:
                    self.put(node + index * 0x40, self.data(node + (index + 1) * 0x40, tail * 0x40))
                    self.put(node + ROWS.val_at + index * ROWS.val_size, self.data(node + ROWS.val_at + (index + 1) * ROWS.val_size, tail * ROWS.val_size))
                self.write(node + ROWS.count, count - 1, 2)
                self.write(map_at + 0x10, self.read(map_at + 0x10) - 1)
                self.put(out, value)
                self.events.append(("removed",))
                return
        self.write(out, 2)

    def on_credit(self, machine):
        out, state, votes, action = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX]
        self.expect(state == self.state, "credit state")
        self.events.append(("credit_call", self.data(votes + 1, 32) if self.read(votes, 1) else None, self.data(votes + 0x22, 20) if self.read(votes + 0x21, 1) else None, self.read(action), self.data(action + 8, 0x40), self.data(action + 0x48, 20)))
        self.write(out, self.credit_status, 2)
        self.put(out + 2, ERROR_TAIL[:0x5E])

    def leaf(self, layout):
        def hook(machine):
            self.insert(layout, machine.regs[RDI], machine.regs[RSI], self.data(machine.regs[RDX], layout.key_size), self.data(machine.regs[RCX], layout.val_size))
        return hook

    def leaf_listed(self, machine):
        self.insert(LISTED, machine.regs[RDI], machine.regs[RSI], self.data(machine.regs[RDX], 20), b"")

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

    def tree(self, at, layout, items):
        tree = self.build(layout, items) if items else 0
        self.write(at, tree)
        self.write(at + 8, self.height(items))
        self.write(at + 0x10, len(items))

    def fresh(self, scenario):
        memory = self.machine.memory
        memory.reset(USED)
        self.top = ARENA
        self.events = []
        self.scenario = scenario
        self.credit_status = TAG_OK
        self.state = HEAP_BASE + 0x70000
        memory.put_bytes(self.state, bytes(0x4000))
        self.put(self.state + S_NOW, NOW)
        self.bridge = self.state + S_BRIDGE
        self.ctx = self.state + S_CTX
        self.write(self.ctx + C_EPOCH, EPOCH)
        self.write(self.bridge + B_Q, struct.unpack("<Q", struct.pack("<d", scenario.q))[0])
        self.write(self.bridge + B_I, struct.unpack("<Q", struct.pack("<d", scenario.i))[0])
        self.write(self.bridge + B_BAL, scenario.bal)
        self.write(self.bridge + B_PRUNED, scenario.pruned)
        cells = [(EPOCH - 2, bytes(0x28)), (EPOCH + 2, bytes(0x28))]
        if scenario.has_epoch:
            items = sorted((key, blob(0xBB, V_SIGNER) + signer + bytes(0x40 - V_SIGNER - 20)) for key, signer, _ in scenario.validators)
            root = self.build(VALIDATORS, items) if items else 0
            cells.insert(1, (EPOCH, struct.pack("<QQQ", root, self.height(items), len(items)) + bytes(0x10)))
        root = self.build(EPOCHS, [(struct.pack("<Q", epoch), value) for epoch, value in cells])
        self.write(self.ctx + C_ROOT, root)
        self.write(self.ctx + C_ROOT + 8, 0)
        self.epoch_value = root + EPOCHS.val_at + EPOCHS.val_size
        self.tree(self.state + S_LISTED, LISTED, [(item, b"") for item in sorted(scenario.listed)])
        self.write(HOLDER, self.state + S_LISTED)
        self.put(TIME_AT, NOW)
        if scenario.finished:
            self.tree(self.bridge + B_FINISHED, FINISHED, [(key, bytes(0x28)) for key in sorted(scenario.finished, key=row_order)])
        if scenario.rows:
            items = []
            for key in sorted(scenario.rows, key=row_order):
                items.append((key, struct.pack("<Q", 1) + bytes(0x20) + struct.pack("<QQQ", 0, 0, 0) + bytes(8)))
            self.tree(self.bridge + B_ROWS, ROWS, items)

    def dump(self):
        rows = {}
        at = self.bridge + B_ROWS
        for key, value in self.walk(ROWS, self.read(at), self.read(at + 8)) if self.read(at + 0x10) else ():
            inner = {}
            for ikey, bucket in self.walk(INNER, self.read(value + 0x28), self.read(value + 0x30)) if self.read(value + 0x38) else ():
                voters = {voter for voter, _ in self.walk(VOTERS, self.read(bucket), self.read(bucket + 8))} if self.read(bucket + 0x10) else set()
                listed = {item for item, _ in self.walk(LISTED, self.read(bucket + 0x18), self.read(bucket + 0x20))} if self.read(bucket + 0x28) else set()
                inner[(struct.unpack_from("<Q", ikey)[0], ikey[8:28])] = (voters, listed)
            winner = (self.read(value + 8), self.data(value + 0x10, 20)) if self.read(value) == 0 else None
            rows[key] = dict(winner=winner, done=self.read(value + 0x40, 1), inner=inner)
        finished = {}
        at = self.bridge + B_FINISHED
        for key, value in self.walk(FINISHED, self.read(at), self.read(at + 8)) if self.read(at + 0x10) else ():
            finished[key] = (self.read(value), self.data(value + 8, 12), self.data(value + 0x14, 20))
        return rows, finished, self.read(self.bridge + B_BAL)

    def perform(self, op):
        memory = self.machine.memory
        memory.put_bytes(OUT, bytes([0xEE]) * 0x70)
        self.events = []
        self.put(ACTION, struct.pack("<Q", op.usd) + op.key + op.user + bytes(0x10))
        if op.kind == "core":
            voter = bytes([1]) + op.voter if op.voter else bytes(33)
            listed = bytes([1]) + op.listed if op.listed else bytes(21)
            self.put(VOTE_ARG, voter + listed)
            self.machine.run(CORE, {RDI: OUT, RSI: self.bridge, RDX: ACTION, RCX: VOTE_ARG, R8: self.ctx, R9: HOLDER}, (TIME_AT,))
            tag = self.read(OUT, 2)
            view = [tag]
            if tag == TAG_LIMIT:
                view.append(self.read(OUT + 8))
            if tag == TAG_OK:
                view.append(self.read(OUT + 2, 1))
            return tuple(view), tuple(self.events)
        self.put(SIGNER, op.signer)
        self.credit_status = op.credit
        self.machine.run(WRAP_VALIDATOR if op.kind == "arm_44" else WRAP_LISTED, {RDI: OUT, RSI: ACTION, RDX: SIGNER, RCX: self.state})
        tag = self.read(OUT, 1)
        if tag == OUTCOME_OK:
            return (tag,), tuple(self.events)
        status = self.read(OUT + 8, 2)
        return (tag, status) + ((self.data(OUT + 0xA, 0x5E),) if status in (TAG_NO_EPOCH, TAG_NOT_VALIDATOR, op.credit) else ()), tuple(self.events)

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


USER = bytes(range(0x31, 0x45))
USD = 12345678
KEY_COMPARED = 0x39
KEY = deposit_key(1000)
ERROR_TAIL = blob(0x30, 0x5E)


class Op:
    def __init__(self, kind, **fields):
        self.kind = kind
        defaults = dict(usd=USD, key=KEY, user=USER, voter=None, listed=None, signer=None, credit=TAG_OK)
        defaults.update(fields)
        self.__dict__.update(defaults)

    def __repr__(self):
        return self.kind


class Scenario:
    def __init__(self, name, ops, validators=None, listed=(), q=0.0, i=0.0, bal=500, pruned=10, has_epoch=True, finished=(), rows=()):
        self.name = name
        self.ops = ops
        self.validators = EQUAL if validators is None else validators
        self.listed = tuple(listed)
        self.q, self.i, self.bal, self.pruned, self.has_epoch = q, i, bal, pruned, has_epoch
        self.finished = tuple(finished)
        self.rows = tuple(rows)


def validator(tag, stake=100):
    return (blob(tag, 32), address(tag), stake)


EQUAL = (validator(0x11), validator(0x22), validator(0x33), validator(0x44))
V1, V2, V3, V4 = EQUAL
OUTSIDER = address(0xF0)
L1, L2, L3, L4 = address(0xA1), address(0xB2), address(0xC3), address(0xD4)
LIST4 = (L1, L2, L3, L4)


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
        self.rows = {key: dict(winner=None, done=0, inner={}) for key in scenario.rows}
        self.finished = {key: (0, bytes(12), bytes(20)) for key in scenario.finished}
        self.bal = scenario.bal

    def members(self):
        return self.scenario.validators if self.scenario.has_epoch else ()

    def stake_ok(self, voters):
        if not self.scenario.has_epoch:
            return False
        return spec_weight({key: stake for key, _, stake in self.scenario.validators}, voters)

    def ratio_ok(self, listed):
        q = self.scenario.q
        if q == 0.0:
            return True
        hits = sum(1 for item in listed if item in self.scenario.listed)
        return float(hits) > q * float(len(self.scenario.listed))

    def quorum(self, bucket):
        return self.stake_ok(bucket[0]) and self.ratio_ok(bucket[1])

    def step(self, op, store):
        row = self.rows.setdefault(op.key, dict(winner=None, done=0, inner={}))
        bucket = row["inner"].setdefault((op.usd, op.user), (set(), set()))
        if row["done"]:
            store(bucket)
            return False
        before = self.quorum(bucket)
        store(bucket)
        if not before and self.quorum(bucket):
            row["done"], row["winner"] = 1, (op.usd, op.user)
            return True
        return False

    def tracker(self, op):
        won = False
        if op.voter is not None and any(key == op.voter for key, _, _ in self.members()):
            won = self.step(op, lambda bucket: bucket[0].add(op.voter)) or won
        if op.listed is not None and op.listed in self.scenario.listed:
            won = self.step(op, lambda bucket: bucket[1].add(op.listed)) or won
        return won

    def core(self, op):
        if op.usd >= AMOUNT_LIMIT:
            return (TAG_LIMIT, op.usd), ()
        if any(key[:KEY_COMPARED] == op.key[:KEY_COMPARED] for key in self.finished):
            return (TAG_FINISHED,), ()
        if struct.unpack_from("<Q", op.key)[0] <= self.scenario.pruned:
            return (TAG_PRUNED,), ()
        won = self.tracker(op)
        events = (("alloc", 800), ("free", 800)) if len(self.rows) > ROW_NOTE else ()
        if not won:
            return (TAG_OK, 0), events
        self.finished[op.key] = (op.usd, NOW, op.user)
        del self.rows[op.key]
        events += (("removed",),)
        if op.usd >= MINIMUM:
            total = self.bal + op.usd
            if total > MASK[8]:
                events += (("recorder",),)
                total = MASK[8]
            self.bal = total
            return (TAG_OK, 1), events
        return (TAG_OK, 0), events

    def apply(self, op):
        if op.kind == "core":
            return self.core(op)
        if op.kind == "arm_44":
            if not self.scenario.has_epoch:
                return (OUTCOME_ERROR, TAG_NO_EPOCH, ERROR_TAIL), ()
            hits = [key for key, who, _ in self.scenario.validators if who == op.signer]
            if not hits:
                return (OUTCOME_ERROR, TAG_NOT_VALIDATOR, ERROR_TAIL), ()
            return self.outcome(op, hits[0], None)
        if op.signer not in self.scenario.listed:
            return (OUTCOME_ERROR, TAG_NOT_LISTED), ()
        return self.outcome(op, None, op.signer)

    def outcome(self, op, voter, listed):
        event = ("credit_call", voter, listed, op.usd, op.key, op.user)
        if op.credit == TAG_OK:
            return (OUTCOME_OK,), (event,)
        return (OUTCOME_ERROR, op.credit, ERROR_TAIL), (event,)

    def snapshot(self):
        rows = {key: dict(winner=row["winner"], done=row["done"], inner={item: (set(pair[0]), set(pair[1])) for item, pair in row["inner"].items()}) for key, row in self.rows.items()}
        return rows, dict(self.finished), self.bal


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


def core(who=None, listed=None, **fields):
    return Op("core", voter=who[0] if who else None, listed=listed, **fields)


def many_keys(count):
    return [deposit_key(2000 + index) for index in range(count)]


def named_scenarios():
    limit = AMOUNT_LIMIT
    other = deposit_key(1001)
    wins = [core(V1), core(V2), core(V3)]
    return [Scenario("core_first_vote", [core(V1)]),
            Scenario("core_three_of_four_finish", wins),
            Scenario("core_vote_after_finish_refused", wins + [core(V4)]),
            Scenario("core_exact_two_thirds_short", [core(V1), core(V2), core(V3)], validators=(V1, V2, V3)),
            Scenario("core_at_limit", [core(V1, usd=limit)]),
            Scenario("core_limit_minus_one", [core(V1, usd=limit - 1)]),
            Scenario("core_finished_key", [core(V1)], finished=[KEY]),
            Scenario("core_finished_before_pruned", [core(V1)], finished=[KEY], pruned=2000),
            Scenario("core_limit_before_finished", [core(V1, usd=limit)], finished=[KEY]),
            Scenario("core_finished_other_key", [core(V1)], finished=[other, deposit_key(1000, 3), deposit_key(999)]),
            Scenario("core_finished_key_other_word_1", [core(V1)], finished=[deposit_key(1000, 3)]),
            Scenario("core_finished_key_other_word_2", [core(V1)], finished=[deposit_key(1000, 2, 4)]),
            Scenario("core_finished_key_other_hash", [core(V1)], finished=[deposit_key(1000, digest=blob(0x91, 32))]),
            Scenario("core_finished_key_other_kind", [core(V1)], finished=[deposit_key(1000, kind=1)]),
            Scenario("core_finished_key_other_tail", [core(V1, key=deposit_key(1000)[:0x39] + bytes(7))], finished=[KEY]),
            Scenario("core_pruned_equal", [core(V1)], pruned=1000),
            Scenario("core_pruned_above", [core(V1)], pruned=1001),
            Scenario("core_pruned_below", [core(V1)], pruned=999),
            Scenario("core_no_voter_at_all", [core()]),
            Scenario("core_non_member", [Op("core", voter=blob(0x99, 32))]),
            Scenario("core_no_epoch", [core(V1)], has_epoch=False),
            Scenario("core_repeat_voter_counts_once", [core(V1), core(V1), core(V2), core(V2), core(V3)]),
            Scenario("core_split_amounts", [core(V1), core(V2, usd=USD + 1), core(V3), core(V4, usd=USD + 1), core(V4)]),
            Scenario("core_split_users", [core(V1), core(V2, user=address(0x3F)), core(V3), core(V4)]),
            Scenario("core_two_keys", [core(V1), core(V2, key=other), core(V3), core(V4, key=other), core(V1, key=other), core(V4)]),
            Scenario("core_two_rows_word_1", [core(V1), core(V2, key=deposit_key(1000, 1)), core(V3, key=deposit_key(1000, 3)), core(V4)]),
            Scenario("core_two_rows_word_2", [core(V1), core(V2, key=deposit_key(1000, 2, 2)), core(V3, key=deposit_key(1000, 2, 4)), core(V4)]),
            Scenario("core_two_rows_kind", [core(V1, key=deposit_key(1000, kind=2)), core(V2, key=deposit_key(1000, kind=1)), core(V3, key=deposit_key(1000, kind=3)), core(V4, key=deposit_key(1000, kind=2))]),
            Scenario("core_two_rows_hash", [core(V1), core(V2, key=deposit_key(1000, digest=blob(0x80, 32))), core(V3, key=deposit_key(1000, digest=blob(0xA0, 32))), core(V4)]),
            Scenario("core_two_rows_word_0", [core(V1), core(V2, key=deposit_key(999)), core(V3, key=deposit_key(1001)), core(V4)]),
            Scenario("core_split_buckets_amount_order", [core(V1), core(V2, usd=USD - 5), core(V3, usd=USD + 5), core(V4, usd=USD - 5), core(V1, usd=USD + 5), core(V2, usd=USD + 5), core(V4, usd=USD + 5)]),
            Scenario("core_split_buckets_user_order", [core(V1), core(V2, user=address(0x05)), core(V3, user=address(0xE0)), core(V4, user=address(0x05)), core(V1, user=address(0xE0)), core(V2, user=address(0xE0))]),
            Scenario("core_below_minimum_finishes_no_bal", [core(V1, usd=MINIMUM - 1), core(V2, usd=MINIMUM - 1), core(V3, usd=MINIMUM - 1)]),
            Scenario("core_at_minimum_raises_bal", [core(V1, usd=MINIMUM), core(V2, usd=MINIMUM), core(V3, usd=MINIMUM)]),
            Scenario("core_zero_amount", [core(V1, usd=0), core(V2, usd=0), core(V3, usd=0)]),
            Scenario("core_bal_saturates", [core(V1), core(V2), core(V3)], bal=MASK[8] - 5),
            Scenario("core_bal_exact_top", [core(V1), core(V2), core(V3)], bal=MASK[8] - USD),
            Scenario("core_second_deposit_after_first", wins + [core(V1, key=other), core(V2, key=other), core(V3, key=other)]),
            Scenario("ratio_zero_needs_no_listed", wins, listed=LIST4, q=0.0),
            Scenario("ratio_blocks_stake_quorum", wins + [core(V4)], listed=LIST4, q=0.5),
            Scenario("ratio_half_of_four_needs_three", wins + [core(listed=L1), core(listed=L2), core(listed=L3)], listed=LIST4, q=0.5),
            Scenario("ratio_exact_is_short", wins + [core(listed=L1), core(listed=L2)], listed=LIST4, q=0.5),
            Scenario("ratio_listed_first_then_stake", [core(listed=L1), core(listed=L2), core(listed=L3), core(V1), core(V2), core(V3)], listed=LIST4, q=0.5),
            Scenario("ratio_small_q", wins + [core(listed=L1)], listed=LIST4, q=0.001),
            Scenario("ratio_q_one_all_listed_short", wins + [core(listed=item) for item in LIST4], listed=LIST4, q=1.0),
            Scenario("ratio_negative_q", wins, listed=LIST4, q=-0.5),
            Scenario("ratio_negative_q_empty_list", wins, listed=(), q=-0.5),
            Scenario("ratio_nan_q", wins + [core(listed=L1)], listed=LIST4, q=float("nan")),
            Scenario("ratio_empty_list", wins, listed=(), q=0.5),
            Scenario("ratio_i_word_not_a_gate", wins, listed=LIST4, q=0.0, i=0.5),
            Scenario("ratio_i_word_with_q", wins + [core(listed=L1), core(listed=L2), core(listed=L3)], listed=LIST4, q=0.5, i=0.5),
            Scenario("listed_not_in_set", [core(listed=address(0x09))], listed=LIST4),
            Scenario("listed_repeat_counts_once", wins + [core(listed=L1), core(listed=L1), core(listed=L1), core(listed=L2), core(listed=L2)], listed=LIST4, q=0.25),
            Scenario("listed_both_in_one_call", [core(V1, listed=L1), core(V2, listed=L2), core(V3, listed=L3)], listed=LIST4, q=0.5),
            Scenario("listed_both_second_wins", [core(V1), core(V2), core(V3), core(V4, listed=L1)], listed=LIST4, q=0.2),
            Scenario("listed_order_low_high", [core(listed=L4), core(listed=L1), core(listed=L3), core(listed=L2)], listed=LIST4, q=0.9),
            Scenario("no_trim_100_rows", [core(V1)], rows=many_keys(99)),
            Scenario("no_trim_101_rows", [core(V1), core(V2)], rows=many_keys(100)),
            Scenario("no_trim_101_rows_finish", [core(V1), core(V2), core(V3)], rows=many_keys(100)),
            Scenario("wide_rows_two_levels", [core(V1, key=many_keys(30)[7]), core(V2, key=many_keys(30)[22]), core(V3, key=many_keys(30)[10])], rows=many_keys(30)),
            Scenario("wide_finished_two_levels", [core(V1, key=many_keys(30)[7]), core(V1, key=many_keys(30)[10]), core(V1, key=deposit_key(5000))], finished=many_keys(30)),
            Scenario("arm_44_ok", [Op("arm_44", signer=V1[1])]),
            Scenario("arm_44_outsider", [Op("arm_44", signer=OUTSIDER)]),
            Scenario("arm_44_no_epoch", [Op("arm_44", signer=V1[1])], has_epoch=False),
            Scenario("arm_44_credit_status", [Op("arm_44", signer=V2[1], credit=0x55)]),
            Scenario("arm_84_ok", [Op("arm_84", signer=L2)], listed=LIST4),
            Scenario("arm_84_low_high", [Op("arm_84", signer=L1), Op("arm_84", signer=L4), Op("arm_84", signer=L3)], listed=LIST4),
            Scenario("arm_84_not_listed", [Op("arm_84", signer=OUTSIDER)], listed=LIST4),
            Scenario("arm_84_validator_not_listed", [Op("arm_84", signer=V1[1])], listed=LIST4),
            Scenario("arm_84_empty_list", [Op("arm_84", signer=L1)]),
            Scenario("arm_84_credit_status", [Op("arm_84", signer=L2, credit=0x55)], listed=LIST4),
            Scenario("arm_84_wide_list", [Op("arm_84", signer=address(0x20 + 3 * 17)), Op("arm_84", signer=address(0x20 + 3 * 2 + 1))], listed=[address(0x20 + 3 * index) for index in range(30)])]


def lcg(seed):
    value = seed
    while True:
        value = (value * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield value >> 33


def vector_scenarios(count):
    source = lcg(0x1441)
    out = []
    keys = (KEY, deposit_key(1001), deposit_key(1000, 7))
    for index in range(count):
        size = 3 + next(source) % 3
        stakes = tuple(validator(0x11 * (at + 1), 1 + next(source) % 5) for at in range(size))
        q = (0.0, 0.25, 0.5, 0.75)[next(source) % 4]
        ops = []
        for _ in range(14):
            key = keys[next(source) % 3]
            usd = USD + next(source) % 2
            who = stakes[next(source) % size] if next(source) % 7 else (blob(0xF0, 32), OUTSIDER, 0)
            mark = next(source) % 3
            item = (LIST4 + (OUTSIDER,))[next(source) % 5]
            ops.append(core(who if mark != 1 else None, item if mark != 0 else None, key=key, usd=usd))
        out.append(Scenario("vector_%d" % index, ops, validators=stakes, listed=LIST4, q=q, bal=next(source)))
    return out


def describe(trace):
    """One short line per operation: status, result byte, and the marks of the finish."""
    parts = []
    for step in trace:
        if step[0] == "panic":
            parts.append("panic " + step[1])
            continue
        view, events, state = step
        text = "%#x" % (view[1] if view[0] == OUTCOME_ERROR and len(view) > 1 else view[0])
        if view[0] == TAG_OK and len(view) > 1:
            text += "/%d" % view[1]
        marks = [event[0] for event in events if event[0] in ("alloc", "removed", "recorder")]
        parts.append(text + ("(" + "+".join(marks) + ")" if marks else ""))
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
    named = ((SLOT_CORE, "deposit core", CORE), (SLOT_RATIO, "listed ratio", RATIO), (SLOT_VOTER, "voter of signer", VOTER), (SLOT_MEMBER, "member test", MEMBER), (SLOT_RECORDER, "overflow recorder", HELPER_RECORDER))
    rows = []
    for slot, role, target in named:
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        rows.append(("%#x" % slot, role, "%#x" % target, len(through[slot])))
    return rows


def site_rows(image, through):
    direct = direct_sites(image, TARGETS)
    by_slot = {MEMBER: SLOT_MEMBER, CORE: SLOT_CORE, RATIO: SLOT_RATIO}
    rows = []
    for target in TARGETS:
        sites = through[by_slot[target]] if target in by_slot else direct[target]
        owners = sorted({image.fde(site)[0] for site in sites})
        rows.append(("%#x" % target, NAMES[target], len(sites), len(owners), " ".join("%#x" % owner for owner in owners[:6])))
    return rows


def constant_rows(image, table):
    """The limit and the level in the core, read as bytes at their rows."""
    rows = []
    limit = [row for row in table[CORE] if row.va == 0x374E327]
    low = [row for row in table[CORE] if row.va in (0x374E51F, 0x374E542)]
    if len(limit) != 1 or len(low) != 2 or struct.unpack_from("<Q", limit[0].data, 2)[0] != AMOUNT_LIMIT:
        raise EvidenceError("core constants moved")
    rows.append(("%#x" % limit[0].va, limit[0].data.hex(), "amount limit", "%#x" % AMOUNT_LIMIT, AMOUNT_LIMIT))
    for row in low:
        value = struct.unpack_from("<I", row.data, len(row.data) - 4)[0]
        rows.append(("%#x" % row.va, row.data.hex(), "minimum level", "%#x" % value, value))
    if struct.unpack_from("<I", low[1].data, len(low[1].data) - 4)[0] != MINIMUM or struct.unpack_from("<I", low[0].data, len(low[0].data) - 4)[0] != MINIMUM - 1:
        raise EvidenceError("level changed")
    return rows


def note_rows(image):
    """The size test, and the fact that nothing but a free follows the first-100 collect."""
    table = decode_range(image, *image.exact_fde(TRACK))
    take_site, free_site = 0x3948166, 0x3948186
    index = next(at for at, row in enumerate(table) if row.va == take_site)
    if table[index].target != TAKE:
        raise EvidenceError("take call moved")
    tail = table[index + 1:index + 8]
    if tail[-1].va != free_site or tail[-1].op != "calli" or tail[-1].a[4] != SLOT_FREE or [row for row in tail[:-1] if row.op in ("call", "calli")]:
        raise EvidenceError("take tail changed")
    compare = [row for row in table if row.op == "cmp" and row.b[0] == "i" and row.b[1] == ROW_NOTE + 1]
    stored = [row for row in table if row.op == "mov" and row.b and row.b[0] == "i" and row.b[1] == ROW_NOTE and row.a[0] == "m"]
    if len(compare) != 1 or len(stored) != 1:
        raise EvidenceError("note rows changed")
    return [("%#x" % TRACK, "%#x" % compare[0].va, "%#x" % stored[0].va, "%#x" % take_site, "%#x" % free_site, " ".join(row.op for row in tail))]


def text_at(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def lea_text(image, site, size):
    at = image.offset(site)
    if bytes(image.blob[at:at + 3]) != bytes.fromhex("488d35"):
        raise EvidenceError("key load moved %#x" % site)
    return text_at(image, site + 7 + struct.unpack_from("<i", image.blob, at + 3)[0], size)


# (key load, size, key, field or word, reader row)
FIELD_ROWS = ((0x2215638, 23, "eth_id_to_deposit_votes", "bridge +0x0", 0x221565F), (0x2215675, 22, "finished_deposits_data", "bridge +0x100", 0x2215693),
              (0x23277BF, 4, "name", "tracker +0x0, a string", 0x23277B0), (0x23277F8, 3, "hsc", "tracker +0x18", 0x2327812), (0x2327832, 1, "i", "tracker +0x28, the row map", 0x232784C),
              (0x22044DF, 1, "q", "hsc +0x0, f64, the ratio", 0x22044D3), (0x220451E, 1, "i", "hsc +0x8, f64", 0x2204511))


def field_rows(image):
    rows = []
    for site, size, key, field, reader in FIELD_ROWS:
        if lea_text(image, site, size) != key:
            raise EvidenceError("key text %#x" % site)
        rows.append(("%#x" % site, "%#x" % reader, key, field))
    return rows


KEY_ROWS = ((CORE, 0x374E334, "amount limit test", "jcc"), (CORE, 0x374E36B, "finished lookup", "call"), (CORE, 0x374E38B, "block word against last pruned", "cmp"), (CORE, 0x374E392, "at or below: 0x2e", "jcc"), (CORE, 0x374E3DF, "tracker", "call"),
            (CORE, 0x374E4D7, "finished insert", "call"), (CORE, 0x374E510, "row removal", "call"), (CORE, 0x374E532, "bal plus amount", "add"), (CORE, 0x374E549, "result byte: amount at or over the level", "set"), (TRACK, 0x394788F, "row lookup", "call"), (TRACK, 0x3947C7B, "row finished byte", "cmp"),
            (TRACK, 0x3947E1B, "quorum before the insert", "call"), (TRACK, 0x3947E81, "quorum after the insert", "call"), (TRACK, 0x3947E93, "row finished", "mov"), (QUORUM, 0x3940F26, "stake test", "call"), (QUORUM, 0x3941023, "both tests", "and"), (RATIO, 0x3BDE208, "q against zero", "ucomisd"), (RATIO, 0x3BDE591, "hits against q times list", "ucomisd"),
            (WRAP_LISTED, 0x1E6482B, "status 0x2b", "mov"), (WRAP_LISTED, 0x1E647A9, "listed vote tag", "mov"), (WRAP_VALIDATOR, 0x1E5FF19, "voter vote tag", "mov"))


def key_rows(image, table):
    rows = []
    for target, va, text, op in KEY_ROWS:
        row = next((item for item in table[target] if item.va == va), None)
        if row is None or row.op != op:
            raise EvidenceError("row %#x is %s" % (va, row.op if row else None))
        rows.append(("%#x" % target, "%#x" % va, row.data.hex(), op, text))
    return rows


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag in STATUS_TAGS:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 160])
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




# Scenario name prefixes run against the edits of each function; the generated runs stay out to bound the time.
FOCUS = {WRAP_VALIDATOR: ("arm_44",), WRAP_LISTED: ("arm_84",), CORE: ("core_",), TRACK: ("core_three", "core_repeat", "core_split", "core_two", "core_no_voter", "core_non_member", "listed_", "ratio_half", "ratio_listed", "no_trim", "wide_rows"), FIND_FINISHED: ("core_finished", "wide_finished"), FIND_ROW: ("core_two", "core_split", "wide_rows", "no_trim_100"),
         QUORUM: ("ratio_", "core_exact", "core_three"), RATIO: ("ratio_", "listed_"), FINISH_ROW: ("core_three", "core_second", "ratio_listed", "ratio_i_word", "listed_both_second")}
FULL = (WRAP_VALIDATOR, WRAP_LISTED, CORE)


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
SURVIVORS = ((WRAP_VALIDATOR, "class: tail of a copied record or a stub argument"), (WRAP_LISTED, "class: tail of a copied record or a stub argument"), (CORE, "class: copy of a dropped record or a stub argument"), (TRACK, LOOP), (FIND_FINISHED, "class: search loop step for a deeper tree or an unused word of the result"),
             (FIND_ROW, "class: search loop step for a deeper tree or an unused word of the result"), (QUORUM, "class: iterator word read only by a stub"), (RATIO, "class: tree walk step for a deeper tree"), (FINISH_ROW, "class: rows whose results reach only frees"))


def analyse(image, mutate=True, vectors=200):
    harness = Harness(image)
    scenarios = named_scenarios()
    named = check_all(harness, scenarios)
    check_all(harness, vector_scenarios(vectors))
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for target in TARGETS}
    through = slot_sites(image, (SLOT_CORE, SLOT_RATIO, SLOT_VOTER, SLOT_MEMBER, SLOT_RECORDER))
    result = dict(table=table, named=named, scenarios=scenarios, vector_count=vectors, unreached=unreached, slots=slot_rows(image, through), sites=site_rows(image, through), constants=constant_rows(image, table), notes=note_rows(image),
                  fields=field_rows(image), statuses=status_rows(image), layouts=layout_rows(), keys=key_rows(image, table))
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
    tsv("constants.tsv", ("at", "bytes", "role", "hex", "value"), result["constants"])
    tsv("row-count-note.tsv", ("function", "compare_at", "take_count_at", "take_call", "free_call", "rows_after_take"), result["notes"])
    tsv("fields.tsv", ("key_at", "field_at", "key", "field"), result["fields"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("node-layouts.tsv", ("tree", "key_at", "key_size", "value_at", "value_size", "parent_at", "parent_index_at", "count_at", "leaf_size"), result["layouts"])
    tsv("key-rows.tsv", ("function", "at", "bytes", "operation", "note"), result["keys"])
    tsv("scenarios.tsv", ("scenario", "operations", "outcome"), [(scenario.name, " ".join(op.kind for op in scenario.ops), describe(trace)) for scenario, trace in result["named"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(TARGETS), "instructions": sum(len(result["table"][target]) for target in TARGETS),
        "named_scenarios": len(result["scenarios"]), "named_operations": sum(len(scenario.ops) for scenario in result["scenarios"]), "vector_scenarios": result["vector_count"],
        "unreached_rows": sum(len(rows) for rows in result["unreached"].values()),
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
