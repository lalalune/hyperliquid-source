#!/usr/bin/env python3
"""Static interpreter and evidence for the node 94 jailed-signer set deletion path.

The x86 decoder and interpreter are adapted from the repository's MIT-licensed
tools/staking_stake_accounting.py; tree fixtures are adapted from a related
independent deletion study, with this target layout and checks.
No target process or external program is started.
"""
import argparse
import bisect
import collections
import csv
import hashlib
import json
import pathlib
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
HEAP_SIZE = 0x400000
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
SHIFTS = {0: "rol", 1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
        elif byte == 0xF0:
            pass
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
            if op != "mov" and any(operand and operand[0] == "r" and 4 <= operand[1] <= 7 for operand in (a, b)):
                raise EvidenceError("high byte register at %#x" % va)
            if a and a[0] == "r" and 4 <= a[1] <= 7:
                a = ("h", a[1] - 4)
            if b and b[0] == "r" and 4 <= b[1] <= 7:
                b = ("h", b[1] - 4)

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
    if byte == 0x98:
        return finish("cdqe" if wide else "cwde")
    if byte == 0xA9:
        value = immediate(4)
        return finish("test", ("r", RAX), ("i", value), width)
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
    if byte == 0x87:
        reg, rm = modrm()
        return finish("xchg", rm, ("r", reg), width)
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
        if two == 0x72 and opsize:
            reg, rm = modrm(True)
            if reg & 7 not in (4, 6):
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrad" if reg & 7 == 4 else "pslld", rm, ("i", value), 16)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xAB:
            reg, rm = modrm()
            return finish("btsr", rm, ("r", reg), width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("btr", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
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
        if two in (0x10, 0x11) and rep:
            reg, rm = modrm(True)
            if rm[0] == "x":
                raise EvidenceError("movss between registers at %#x" % va)
            if two == 0x10:
                return finish("movss", ("x", reg), rm, 4)
            return finish("movss", rm, ("x", reg), 4)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0xDF, True): "pandn", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
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
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two == 0x16 and not opsize:
            reg, rm = modrm(True)
            return finish("movhps", ("x", reg), rm, 8)
        if two == 0x12 and not opsize and not rep and not repne:
            reg, rm = modrm(True)
            return finish("movlps", ("x", reg), rm, 8)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movdout", rm, ("x", reg), 4)
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
            return finish("shrd", rm, ("r", reg), width, target=value)
        if two == 0xB1:
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), width)
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
        self.edges = set()
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
        if kind == "h":
            return self.regs[operand[1]] >> 8 & 0xFF
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "h":
            self.regs[operand[1]] = (self.regs[operand[1]] & ~0xFF00) | value << 8
            return
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
            old_pc = pc
            pc = self.step(row)
            if row.op == "jcc":
                self.edges.add((old_pc, pc))
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
        elif op == "cmpxchg":
            current = self.get(row.a, width)
            wanted = self.regs[RAX] & MASK[width]
            self.add_sub(wanted, current, 0, width, True)
            if wanted == current:
                self.put(row.a, width, self.get(row.b, width))
            else:
                self.put(("r", RAX), width, current)
        elif op == "xchg":
            first, second = self.get(row.a, width), self.get(row.b, width)
            self.put(row.a, width, second)
            self.put(row.b, width, first)
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
        elif op == "btsr":
            bit = self.get(row.b, width) & (8 * width - 1)
            value = self.get(row.a, width)
            self.cf = bool(value >> bit & 1)
            self.put(row.a, width, value | 1 << bit)
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
        elif op == "movsx":
            value = self.get(row.b, row.cc)
            self.put(row.a, width, value - (1 << (8 * row.cc)) if value & SIGN[row.cc] else value)
        elif op == "ror":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) & MASK[width])
        elif op == "rol":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) & MASK[width])
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
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            left -= (left >> 63) << 64
            right -= (right >> 63) << 64
            product = left * right
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            bits = 8 * width
            left, right = self.get(row.b, width), row.target & MASK[width]
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
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
        elif op == "cwde":
            self.regs[RAX] = ((self.regs[RAX] & 0xFFFF) ^ 0x8000) - 0x8000 & MASK[4]
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            bits = 8 * width
            left, right = self.get(row.a, width), self.get(row.b, width)
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
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
            count = (row.target if row.target is not None else self.regs[RCX]) & 63
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
        if op == "movss":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.memory.read(self.address(row.b), 4)
            else:
                self.memory.write(self.address(row.a), 4, self.xmm[row.b[1]] & MASK[4])
            return
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
        elif op == "movhps":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | self.get(row.b, 8) << 64
        elif op == "movlps":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 << 64 | self.get(row.b, 8)
        elif op == "movdout":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op in ("pslld", "psrad"):
            value, lanes = self.xmm[row.a[1]], 0
            for shift in (0, 32, 64, 96):
                lane = (value >> shift) & MASK[4]
                if op == "pslld":
                    lane = (lane << row.b[1]) & MASK[4]
                else:
                    lane = ((lane - (1 << 32) if lane & SIGN[4] else lane) >> row.b[1]) & MASK[4]
                lanes |= lane << shift
            self.xmm[row.a[1]] = lanes
        elif op == "pandn":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] ^ ((1 << 128) - 1)) & self.vector(row.b)
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


# Each function is an unwind-described range, never a claim of a full census.
FUNCTIONS = {
    "jail_cursor": 0x2fd9460,
    "jail_leaf": 0x2fc8680,
    "jail_merge": 0x2faebf0,
    "jail_borrow_right": 0x2fa9270,
}
LAYOUTS = {
    "jail": dict(key=8, value=8, width=0, parent=0, pos=0xe4, count=0xe6, edge=0xe8, leaf=0xe8, inner=0x148, outcursor=0x18),
}
LEFT_BORROW = 0x2fa5270

class PriorWorkBoundary(Exception):
    pass

MARK_BASE = 0x7700000000
SLOT_COPY = (0x576DFE0, 0x576E0E0)
SLOT_FREE = 0x576E010
STOP_SLOTS = (0x576E470, 0x576E098, 0x576E108, 0x576E020, 0x576E2E0, 0x576E468, 0x576E118)
NODE_BASE = HEAP_BASE + 0x10000
OUT = HEAP_BASE + 0x100
CURSOR = HEAP_BASE + 0x400
FLAG = HEAP_BASE + 0x500

class Fixture:
    def __init__(self, image, layout, patches=None):
        self.spec = LAYOUTS[layout]
        self.machine = Machine(image, patches)
        self.machine.real = frozenset(FUNCTIONS.values())
        self.machine.calls[LEFT_BORROW] = self.prior_work_boundary
        self.machine.memory.statics = dict(image.relative())
        for slot in SLOT_COPY + (SLOT_FREE,) + STOP_SLOTS:
            self.machine.memory.statics[slot] = MARK_BASE + slot
        for slot in SLOT_COPY:
            self.machine.slots[MARK_BASE + slot] = self.copy
        self.machine.slots[MARK_BASE + SLOT_FREE] = self.free
        for slot in STOP_SLOTS:
            self.machine.slots[MARK_BASE + slot] = self.panic
        self.machine.memory.heap[:] = bytes(HEAP_SIZE)
        self.alloc = NODE_BASE
        self.live = {}
        self.frees = []
        self.layout = layout

    def prior_work_boundary(self, m):
        raise PriorWorkBoundary("left sibling transfer is covered by the open profile packet")

    def copy(self, m):
        dst, src, n = m.regs[RDI], m.regs[RSI], m.regs[RDX]
        if n: m.memory.copy(dst, src, n)
        m.regs[RAX] = dst

    def free(self, m):
        addr, size = m.regs[RDI], m.regs[RSI]
        if addr not in self.live or self.live[addr] != size:
            raise Halt('free of unknown block or wrong size')
        del self.live[addr]
        self.frees.append((addr, size))

    def panic(self, m):
        raise Panicked('target panic sink')

    def node(self, keys, children=()):
        spec = self.spec
        addr = self.alloc
        size = spec['inner'] if children else spec['leaf']
        self.alloc += 0x400
        self.live[addr] = size
        mem = self.machine.memory
        mem.write(addr + spec['count'], 2, len(keys))
        for i, k in enumerate(keys):
            mem.put_bytes(addr + spec['key'] + 20 * i, k.to_bytes(20, 'big'))
            mem.put_bytes(addr + spec['value'] + spec['width'] * i, bytes([k & 255]) * spec['width'])
        if children:
            if len(children) != len(keys) + 1: raise ValueError('children count')
            for i, child in enumerate(children):
                mem.write(addr + spec['edge'] + 8*i, 8, child)
                mem.write(child + spec['parent'], 8, addr)
                mem.write(child + spec['pos'], 2, i)
        return addr

    def run(self, node, height, index, flag=0):
        mem=self.machine.memory
        mem.write(CURSOR,8,node);mem.write(CURSOR+8,8,height);mem.write(CURSOR+16,8,index)
        mem.write(FLAG,1,flag)
        self.machine.run(FUNCTIONS[self.layout+'_cursor'], {RDI:OUT,RSI:CURSOR,RDX:FLAG})
        return (mem.bytes_at(OUT,20).hex(), mem.bytes_at(OUT+24,self.spec['width']).hex(),
                mem.read(OUT+self.spec['outcursor'],8), mem.read(OUT+self.spec['outcursor']+8,8),
                mem.read(OUT+self.spec['outcursor']+16,8), mem.read(FLAG,1))

    def walk(self, node, height, parent=0, pos=0):
        s=self.spec;m=self.machine.memory
        if node not in self.live: raise Halt('node not live')
        if m.read(node+s['parent'],8)!=parent: raise Halt('bad parent pointer')
        if parent and m.read(node+s['pos'],2)!=pos: raise Halt('bad parent index')
        n=m.read(node+s['count'],2)
        if n>11: raise Halt('node over capacity')
        if parent and n < 5: raise Halt('non-root node underfull')
        rows=[]
        for i in range(n):
            if height: rows.extend(self.walk(m.read(node+s['edge']+8*i,8),height-1,node,i))
            k=int.from_bytes(m.bytes_at(node+s['key']+20*i,20),'big')
            v=m.bytes_at(node+s['value']+s['width']*i,s['width'])
            rows.append((k,v))
        if height: rows.extend(self.walk(m.read(node+s['edge']+8*n,8),height-1,node,n))
        return rows


def row(k, width):
    return k, bytes([k & 255]) * width


def successor(fixture, node, height, index):
    """Read the returned gap as the next in-order key, following parent links."""
    m, s = fixture.machine.memory, fixture.spec
    while True:
        if node not in fixture.live: raise Halt('cursor points to freed node')
        n = m.read(node + s['count'], 2)
        if index > n: raise Halt('cursor index past node end')
        if height:
            node = m.read(node + s['edge'] + 8 * index, 8)
            height -= 1
            index = 0
            continue
        if index < n:
            return int.from_bytes(m.bytes_at(node + s['key'] + 20 * index, 20), 'big')
        parent = m.read(node + s['parent'], 8)
        if not parent: return None
        index = m.read(node + s['pos'], 2)
        node = parent
        # Having exhausted the child, the next item is its parent separator.
        while True:
            n = m.read(node + s['count'], 2)
            if index < n:
                return int.from_bytes(m.bytes_at(node + s['key'] + 20 * index, 20), 'big')
            if index != n: raise Halt('parent index past end')
            parent = m.read(node + s['parent'], 8)
            if not parent: return None
            index = m.read(node + s['pos'], 2)
            node = parent


def case_specs():
    for n in range(1, 12):
        for i in range(n):
            yield ('single', n, 0, 'leaf', i)
    for left in range(5, 12):
        for right in range(5, 12):
            for side, size in (('left', left), ('right', right)):
                for index in range(size):
                    yield ('pair', left, right, side, index)
            yield ('pair', left, right, 'root', 0)
    yield ('deep', 5, 5, 'leftmost', 2)
    yield ('deep', 5, 5, 'rightmost', 2)
    yield ('deep', 5, 5, 'middle', 2)
    yield ('deep', 5, 5, 'root', 0)
    yield ('deep', 5, 5, 'inner', 2)
    yield ('deep3', 5, 5, 'leftmost', 2)
    yield ('deep3', 5, 5, 'rightmost', 2)
    yield ('deep3', 5, 5, 'middle', 2)
    yield ('deep3', 5, 5, 'root', 0)
    yield ('deep_borrow', 5, 7, 'leftmost', 2)
    yield ('deep_borrow', 7, 5, 'rightmost', 2)
    for left in range(5,12):
        for right in range(5,12):
            for side in ('leftmost','middleleft','rightmost','middleright'):
                yield ('matrix2',left,right,side,2)


def build_case(image, layout, spec, patches=None):
    family, a, b, side, index = spec
    h = Fixture(image, layout, patches)
    if family == 'single':
        root = h.node(list(range(10, 10+a)))
        target, height, rootheight = root, 0, 0
    elif family == 'pair':
        left = h.node(list(range(10, 10+a)))
        right = h.node(list(range(110, 110+b)))
        root = h.node([80], [left, right])
        target, height = {'left': (left,0), 'right': (right,0), 'root': (root,1)}[side]
        rootheight = 1
    elif family == 'deep':
        # Both internal children have five separators and six five-row leaves.
        children = []
        for block in range(12):
            first = block * 10 + 1
            children.append(h.node(list(range(first, first+5))))
        lkeys = [block*10+8 for block in range(5)]
        rkeys = [block*10+8 for block in range(6,11)]
        left = h.node(lkeys, children[:6]); right = h.node(rkeys,children[6:])
        root = h.node([58],[left,right]); rootheight=2
        target, height = {'leftmost':(children[0],0), 'rightmost':(children[-1],0),
                          'root':(root,2), 'inner':(left,1), 'middle':(children[2],0)}[side]
    elif family == 'matrix2':
        keygen=iter(range(1,10000)); leaves=[]
        def matrix_inner(n):
            kids=[]; keys=[]
            for i in range(n+1):
                node=h.node([next(keygen) for _ in range(5)]); leaves.append(node); kids.append(node)
                if i<n: keys.append(next(keygen))
            return h.node(keys,kids)
        left=matrix_inner(a); rootkey=next(keygen); right=matrix_inner(b)
        root=h.node([rootkey],[left,right]); rootheight=2
        positions={'leftmost':0, 'middleleft':a//2, 'rightmost':len(leaves)-1,
                   'middleright':a+1+b//2}
        target,height=leaves[positions[side]],0
    elif family == 'deep_borrow':
        keygen=iter(range(1, 10000)); leaves=[]
        def inner(n):
            kids=[];keys=[]
            for i in range(n+1):
                node=h.node([next(keygen) for _ in range(5)]); leaves.append(node);kids.append(node)
                if i<n: keys.append(next(keygen))
            return h.node(keys,kids)
        left=inner(a); rootkey=next(keygen); right=inner(b)
        root=h.node([rootkey],[left,right]);rootheight=2
        target,height=(leaves[0],0) if side=='leftmost' else (leaves[-1],0)
    elif family == 'deep3':
        keygen=iter(range(1, 10000))
        leaves=[]
        def subtree(level):
            if level == 0:
                node=h.node([next(keygen) for _ in range(5)])
                leaves.append(node)
                return node
            child=[subtree(level-1)]
            keys=[]
            for _ in range(5):
                keys.append(next(keygen));child.append(subtree(level-1))
            return h.node(keys,child)
        left=subtree(2); root_key=next(keygen); right=subtree(2)
        root=h.node([root_key],[left,right]);rootheight=3
        target,height={'leftmost':(leaves[0],0),'rightmost':(leaves[-1],0),'middle':(leaves[2],0),'root':(root,3)}[side]
    else: raise ValueError('unknown case family')
    return h, root, rootheight, target, height, index


def run_case(image, layout, spec, patches=None):
    h, root, rh, target, height, index = build_case(image,layout,spec,patches)
    before=h.walk(root,rh)
    leaf_before=h.machine.memory.bytes_at(root,h.spec['leaf']) if spec[0]=='single' else None
    key=int.from_bytes(h.machine.memory.bytes_at(target+h.spec['key']+20*index,20),'big')
    assert before == sorted(before) and len({x[0] for x in before}) == len(before)
    expected=[r for r in before if r[0]!=key]
    successor_expected=next((k for k,_ in before if k>key),None)
    result=h.run(target,height,index)
    removed_key=int(result[0],16)
    removed_value=bytes.fromhex(result[1])
    after=h.walk(root,rh)
    if leaf_before is not None:
        projected=bytearray(leaf_before); n=spec[1]; ix=spec[4]
        for base,width in ((h.spec['key'],20),(h.spec['value'],h.spec['width'])):
            projected[base+ix*width:base+(n-1)*width]=leaf_before[base+(ix+1)*width:base+n*width]
        struct.pack_into('<H',projected,h.spec['count'],n-1)
        if h.machine.memory.bytes_at(root,h.spec['leaf'])!=bytes(projected):
            raise EvidenceError('leaf byte projection mismatch')
    got_next=successor(h,*result[2:5])
    if removed_key!=key or removed_value != row(key,h.spec['width'])[1] or after!=expected or got_next!=successor_expected:
        raise EvidenceError('tree or cursor mismatch for %s %r' % (layout,spec))
    family,a,b,side,_ = spec
    if family == 'single':
        expected_flag, expected_frees = 0, 0
    elif family in ('deep','deep3'):
        expected_flag, expected_frees = 1, 3 if family == 'deep3' else 2
    elif family == 'deep_borrow':
        expected_flag, expected_frees = 0, 1
    elif family == 'matrix2':
        n,sibling=(a,b) if side in ('leftmost','middleleft') else (b,a)
        expected_flag=int(n==5 and sibling<=6)
        expected_frees=1+expected_flag
    else:
        n, sibling = (b, a) if side == 'right' else (a, b)
        expected_flag = int(n == 5 and sibling <= 6)
        expected_frees = expected_flag
    if result[5] != expected_flag or len(h.frees) != expected_frees:
        raise EvidenceError('repair flag or free count mismatch')
    return {'family':spec[0], 'a':spec[1], 'b':spec[2], 'side':spec[3], 'index':spec[4],
            'removed':key,'next':got_next,'root_flag':result[5], 'frees':len(h.frees),
            'rows_after':len(after), 'reached': sorted(k for k,v in FUNCTIONS.items() if v in h.machine.seen),
            'seen':h.machine.seen, 'edges':h.machine.edges, 'rows_digest':hashlib.sha256(b''.join(k.to_bytes(20, 'big')+v for k,v in after)).hexdigest()}



def file_bytes(image, va, n, patches=None):
    if n < 0: raise EvidenceError('negative range')
    found=[s for s in image.sections if s['type'] != 8 and
           s['address'] <= va and va+n <= s['address']+s['size']]
    if len(found)!=1: raise EvidenceError('range is not uniquely file-backed')
    s=found[0]; offset=s['offset'] + va - s['address']
    raw=bytearray(image.blob[offset:offset+n])
    for at,value in (patches or {}).items():
        if va <= at < va+n: raw[at-va]=value
    return bytes(raw),offset


def guard_case(image, layout, direction, failure):
    h=Fixture(image,layout)
    if direction=='left':
        nl,nr=(1,11) if failure=='capacity' else (0,1)
    else:
        nl,nr=(11,1) if failure=='capacity' else (1,0)
    left=h.node(list(range(1,nl+1)));right=h.node(list(range(100,100+nr)))
    root=h.node([50],[left,right]); m=h.machine.memory
    for i,x in enumerate((root,1,0,left,0,right,0)): m.write(CURSOR+8*i,8,x)
    before=m.bytes_at(left,h.spec['leaf'])+m.bytes_at(right,h.spec['leaf'])+m.bytes_at(root,h.spec['inner'])
    try:
        h.machine.run(FUNCTIONS[layout+'_borrow_'+direction],{RDI:CURSOR,RSI:1})
    except Panicked:
        after=m.bytes_at(left,h.spec['leaf'])+m.bytes_at(right,h.spec['leaf'])+m.bytes_at(root,h.spec['inner'])
        if before!=after: raise EvidenceError('guard changed fixture before panic')
        return h.machine.seen
    raise EvidenceError('corrupt transfer did not panic')


def flag_case(image, layout, spec, flag):
    if flag not in (0,1,2,255): raise ValueError('unsupported flag control')
    fixture,root,height,node,node_height,index=build_case(image,layout,spec)
    before=fixture.walk(root,height)
    key=int.from_bytes(fixture.machine.memory.bytes_at(node+fixture.spec['key']+20*index,20),'big')
    result=fixture.run(node,node_height,index,flag)
    expected=1 if spec[0]=='pair' and spec[1:4]==(5,5,'left') else flag
    if result[-1]!=expected or fixture.walk(root,height)!=[r for r in before if r[0]!=key]:
        raise EvidenceError('flag preservation or tree mismatch')
    return result[-1]


def transfer_specs():
    for layout in LAYOUTS:
        for direction in ('right',):
            for height in (0,1):
                for dst in range(5,12):
                    for src in range(5,12):
                        for amount in range(1,6):
                            if src-amount >= 5 and dst+amount <= 11:
                                yield layout,direction,height,dst,src,amount


def transfer_case(image, spec, patches=None):
    layout,direction,height,dst,src,amount=spec
    if not (layout in LAYOUTS and direction in ('left','right') and height in (0,1)
            and 5<=src-amount<=11 and 5<=dst+amount<=11 and 1<=amount<=5):
        raise ValueError('invalid synthetic transfer fixture')
    h=Fixture(image,layout,patches); keygen=iter(range(1,10000))
    def tree(n):
        if not height: return h.node([next(keygen) for _ in range(n)])
        kids=[];keys=[]
        for i in range(n+1):
            kids.append(h.node([next(keygen) for _ in range(5)]))
            if i<n: keys.append(next(keygen))
        return h.node(keys,kids)
    left=tree(src if direction=='left' else dst)
    sep=next(keygen)
    right=tree(dst if direction=='left' else src)
    root=h.node([sep],[left,right]);before=h.walk(root,height+1)
    mem=h.machine.memory
    for i,x in enumerate((root,height+1,0,left,height,right,height)):
        mem.write(CURSOR+8*i,8,x)
    h.machine.run(FUNCTIONS[layout+'_borrow_'+direction],{RDI:CURSOR,RSI:amount})
    after=h.walk(root,height+1)
    lcount=mem.read(left+h.spec['count'],2);rcount=mem.read(right+h.spec['count'],2)
    expected=(src-amount,dst+amount) if direction=='left' else (dst+amount,src-amount)
    if (lcount,rcount)!=expected or before!=after or h.frees:
        raise EvidenceError('transfer changed rows, counts, or allocation')
    if mem.read(root+h.spec['count'],2)!=1:
        raise EvidenceError('transfer changed parent occupancy')
    new_separator=int.from_bytes(mem.bytes_at(root+h.spec['key'],20),'big')
    return {'separator_before':sep,'separator_after':new_separator,'left_after':lcount,
            'right_after':rcount,'rows':len(after),'seen':h.machine.seen,'edges':h.machine.edges,
            'digest':hashlib.sha256(b''.join(k.to_bytes(20,'big')+v for k,v in after)).hexdigest()}


# Expected full body digests prevent an interpreter or fixture from silently
# analyzing a different function even when an FDE starts at the same address.
BODY_HASHES = {
    'jail_cursor': 'b80fa7beb3036a1ecd2043e846878736ca68ab2acf18525a4dee5bd97d08c2e9',
    'jail_leaf': '2bb3c6aca3d624cfc5ab1b0acf55773845e86b87a304ce139743fb6c1e98a9a3',
    'jail_merge': '7118210d0c51d721a762e622d0c73d1e4e84a6ee407b9eaa50403cf9a1d4ba60',
    'jail_borrow_right': '06978b95d23aaa23b22d75b08dfea35d0dd28bf04f3c50b203835e42d4f87347',
}
PINS = (
    ('context_profile_remove',0x3995e50,'e89b74a1ff'),
    ('context_cursor_call',0x33ad3e8,'e873c0c2ff'),
    ('cursor_height_gate',0x2fd9476,'4885ff0f84c3010000'),
    ('cursor_predecessor_last',0x2fd9565,'48ffc8'),
    ('cursor_predecessor_leaf',0x2fd9583,'e8f8f0feff'),
    ('cursor_leaf',0x2fd965d,'e81ef0feff'),
    ('leaf_key_stride',0x2fc86ab,'488d0492498d7c8508'),
    ('leaf_decrement',0x2fc86ed,'8d43ff66418985e6000000'),
    ('leaf_minimum',0x2fc8718,'6683f8040f8789010000'),
    ('leaf_left_choice',0x2fc878e,'83fb0c0f8396000000'),
    ('leaf_right_choice',0x2fc880f,'83fb0c73'),
    ('leaf_merge',0x2fc8826,'e8c563feff'),
    ('leaf_external_left',0x2fc883a,'e831cafdff'),
    ('leaf_borrow_right',0x2fc8859,'e8120afeff'),
    ('merge_slot_guard',0x2faec1d,'4839c10f8724030000'),
    ('merge_capacity_guard',0x2faec39,'4983f80c0f8320030000'),
    ('borrow_capacity_guard',0x2fa928e,'4883f80c0f8391020000'),
    ('borrow_donor_guard',0x2fa92a8,'4929f50f8291020000'),
)


def verify_subjects(image, patches=None):
    records = []
    for name,start in FUNCTIONS.items():
        _,end=image.exact_fde(start)
        data,offset=file_bytes(image,start,end-start,patches)
        text=[sec for sec in image.sections if sec['type'] != 8 and sec['flags'] & 4
              and sec['address'] <= start and end <= sec['address']+sec['size']]
        if len(text)!=1 or hashlib.sha256(data).hexdigest()!=BODY_HASHES[name]:
            raise EvidenceError('subject body mismatch: '+name)
        records.append((name,hex(start),hex(end),hex(offset),len(data),
                        hashlib.sha256(data).hexdigest()))
    return records


def verify_pins(image,patches=None):
    rows=[]
    for name,va,expected in PINS:
        raw,off=file_bytes(image,va,len(bytes.fromhex(expected)),patches)
        if raw.hex()!=expected:
            raise EvidenceError('pin mismatch: '+name)
        rows.append((name,hex(va),hex(off),raw.hex()))
    return rows


def merge_guard(image,failure):
    h=Fixture(image,'jail')
    left=h.node(list(range(1,7)))
    right=h.node(list(range(100,106)))
    root=h.node([50],[left,right]); mem=h.machine.memory
    for i,x in enumerate((root,1,0,left,0,right,0)):
        mem.write(CURSOR+i*8,8,x)
    before=mem.bytes_at(left,0xe8)+mem.bytes_at(right,0xe8)+mem.bytes_at(root,0x148)
    # With the selected destination, an index above six fails first; an index
    # in range exposes the 6 + 6 + separator capacity guard.
    index=7 if failure=='index' else 0
    if failure not in ('index','capacity'):
        raise ValueError('unknown merge guard')
    try:
        h.machine.run(FUNCTIONS['jail_merge'],{RDI:OUT,RSI:CURSOR,RDX:0,RCX:index})
    except Panicked:
        after=mem.bytes_at(left,0xe8)+mem.bytes_at(right,0xe8)+mem.bytes_at(root,0x148)
        if before!=after:
            raise EvidenceError('merge guard wrote fixture before panic')
        site={'index':0x2faec20,'capacity':0x2faec3d}[failure]
        branch=decode(h.machine.read_code,site)
        if (site,branch.target) not in h.machine.edges:
            raise EvidenceError('wrong merge guard')
        return site,branch.target
    raise EvidenceError('corrupt merge did not reach panic boundary')


def mutation_case(image,name,va,value,spec):
    run_case(image,'jail',spec)
    try:
        run_case(image,'jail',spec,{va:value})
    except (Halt,Panicked,EvidenceError) as exc:
        if any(t in str(exc) for t in ('step limit','unmodelled','undecodable')):
            raise EvidenceError('invalid mutation control: '+name)
        return type(exc).__name__
    except PriorWorkBoundary:
        return 'prior-work boundary reached unexpectedly'
    raise EvidenceError('mutation survived: '+name)


MUTATIONS = (
    ('underflow_threshold',0x2fc871b,5,('pair',6,5,'left',0)),
    ('right_merge_threshold',0x2fc8811,11,('pair',5,6,'left',0)),
    ('predecessor_index',0x2fd9567,0xc0,('pair',7,5,'root',0)),
    ('leaf_count',0x2fc86ef,0xfe,('single',8,0,'leaf',3)),
    ('merge_capacity',0x2faec3c,11,('pair',5,6,'left',0)),
)

TRANSFER_MUTATIONS = (
    ('borrow_capacity',0x2fa9291,11,('jail','right',0,10,6,1)),
    ('borrow_donor_branch',0x2fa92ac,0x83,('jail','right',1,5,7,1)),
    ('borrow_donor_count',0x2fa92a9,0x01,('jail','right',0,5,7,1)),
)


def transfer_mutation_case(image,name,va,value,spec):
    transfer_case(image,spec)
    try:
        transfer_case(image,spec,{va:value})
    except (Halt,Panicked,EvidenceError) as exc:
        if any(t in str(exc) for t in ('step limit','unmodelled','undecodable')):
            raise EvidenceError('invalid transfer mutation: '+name)
        return type(exc).__name__
    raise EvidenceError('transfer mutation survived: '+name)



def write_tsv(path,header,rows):
    with path.open('w',encoding='utf-8',newline='') as out:
        writer=csv.writer(out,delimiter='\t',lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(image,out):
    subjects=verify_subjects(image)
    pins=verify_pins(image)
    decoded=[]; calls=[]; branch_records=[]
    for name,start in FUNCTIONS.items():
        _,end=image.exact_fde(start)
        rows=decode_range(image,start,end)
        starts={r.va for r in rows}
        for row in rows:
            if row.op=='jcc' and row.target not in starts:
                raise EvidenceError('conditional target outside selected instruction starts')
            offset=file_bytes(image,row.va,row.size)[1]
            decoded.append((name,row,offset))
            if row.op=='call':
                scope='subject' if row.target in FUNCTIONS.values() else 'external'
                calls.append((name,hex(row.va),'direct',hex(row.target),scope))
            elif row.op=='calli':
                if row.a[0]=='m' and row.a[1] is None and row.a[2] is None:
                    calls.append((name,hex(row.va),'slot',hex(row.a[4]),'external'))
                else:
                    calls.append((name,hex(row.va),'register','','unresolved'))
    case_rows=[]; reached=collections.Counter(); edges=collections.Counter()
    prior_count=0
    for spec in case_specs():
        try:
            result=run_case(image,'jail',spec)
        except PriorWorkBoundary:
            prior_count+=1
            case_rows.append((*spec,'prior_work_boundary','','','','','',''))
            continue
        for va in result.pop('seen'): reached[va]+=1
        for edge in result.pop('edges'): edges[edge]+=1
        case_rows.append((*spec,'matched',result['removed'],
                          '' if result['next'] is None else result['next'],
                          result['root_flag'],result['frees'],result['rows_after'],result['rows_digest']))
    transfer_rows=[]; tr_edges=collections.Counter();tr_reached=collections.Counter()
    for spec in transfer_specs():
        result=transfer_case(image,spec)
        for va in result['seen']:tr_reached[va]+=1
        for edge in result['edges']:tr_edges[edge]+=1
        transfer_rows.append((*spec,result['separator_before'],result['separator_after'],
                              result['left_after'],result['right_after'],result['rows'],result['digest']))
    for name,row,_ in decoded:
        if row.op=='jcc':
            branch_records.append((name,hex(row.va),row.data.hex(),hex(row.target),hex(row.next),
                                   edges[(row.va,row.target)],edges[(row.va,row.next)],
                                   tr_edges[(row.va,row.target)],tr_edges[(row.va,row.next)]))
    controls=[]
    for failure,site in (('capacity',0x2fa9292),('donor',0x2fa92ab)):
        seen=guard_case(image,'jail','right',failure)
        row=decode(lambda a,n:file_bytes(image,a,n)[0],site)
        if row.op!='jcc' or row.target not in seen:
            raise EvidenceError('wrong borrow guard')
        controls.append(('borrow_'+failure,hex(site),hex(row.target),'panic before fixture writes'))
    for failure in ('index','capacity'):
        site,target=merge_guard(image,failure)
        controls.append(('merge_'+failure,hex(site),hex(target),'panic before fixture writes'))
    flag_rows=[]
    for case in (('single',1,0,'leaf',0),('pair',6,5,'left',2),('pair',5,5,'left',2)):
        for flag in (0,1,2,255):
            flag_rows.append((*case,flag,flag_case(image,'jail',case,flag)))
    mutant_rows=[]
    for name,va,value,spec in MUTATIONS:
        old=file_bytes(image,va,1)[0][0]
        if old==value:raise EvidenceError('mutation did not change byte')
        reason=mutation_case(image,name,va,value,spec)
        mutant_rows.append((name,hex(va),f'{old:02x}',f'{value:02x}',repr(spec),reason))
    for name,va,value,spec in TRANSFER_MUTATIONS:
        old=file_bytes(image,va,1)[0][0]
        if old==value:raise EvidenceError('mutation did not change byte')
        reason=transfer_mutation_case(image,name,va,value,spec)
        mutant_rows.append((name,hex(va),f'{old:02x}',f'{value:02x}',repr(spec),reason))
    out.mkdir(parents=True,exist_ok=True)
    write_tsv(out/'functions.tsv',('function','start_va','end_va','file_offset','bytes','sha256'),subjects)
    write_tsv(out/'anchors.tsv',('name','va','file_offset','bytes'),pins)
    write_tsv(out/'instructions.tsv',('function','va','file_offset','bytes','operation','direct_target','cases_reached','transfer_cases_reached'),
              [(name,hex(r.va),hex(off),r.data.hex(),r.op,
                hex(r.target) if r.op in ('jcc','jmp','call') and r.target is not None else '',
                reached[r.va],tr_reached[r.va]) for name,r,off in decoded])
    write_tsv(out/'branches.tsv',('function','va','bytes','taken_va','fallthrough_va','taken_cases','fallthrough_cases','transfer_taken_cases','transfer_fallthrough_cases'),branch_records)
    write_tsv(out/'calls.tsv',('function','site_va','form','target_or_slot','scope'),calls)
    write_tsv(out/'cases.tsv',('family','left_size','right_size','side','index','result','removed_key','next_key','root_flag','frees','rows_after','rows_sha256'),case_rows)
    write_tsv(out/'transfers.tsv',('layout','direction','height','destination_before','source_before','amount','separator_before','separator_after','left_after','right_after','rows','rows_sha256'),transfer_rows)
    write_tsv(out/'controls.tsv',('control','branch_va','failure_va','result'),controls)
    write_tsv(out/'flags.tsv',('family','left_size','right_size','side','index','input','output'),flag_rows)
    write_tsv(out/'mutations.tsv',('name','va','old','new','fixture','detected_by'),mutant_rows)
    summary={'artifact_sha256':SHA256,'selected_fde_ranges':len(subjects),
             'subject_bytes':sum(x[4] for x in subjects),'decoded_instruction_rows':len(decoded),
             'subject_rows_reached':sum(bool(reached[r.va]) for _,r,_ in decoded),
             'subject_rows_reached_including_transfers':sum(bool(reached[r.va] or tr_reached[r.va]) for _,r,_ in decoded),
             'conditional_branches':len(branch_records),
             'branches_both_edges_observed':sum(r[5]>0 and r[6]>0 for r in branch_records),
             'branches_both_edges_including_transfers':sum((r[5]>0 or r[7]>0) and (r[6]>0 or r[8]>0) for r in branch_records),
             'normal_cases_matched':len(case_rows)-prior_count,
             'prior_work_boundaries':prior_count,'right_transfer_cases':len(transfer_rows),
             'failure_controls':len(controls),'flag_controls':len(flag_rows),
             'targeted_mutations_detected':len(mutant_rows),
             'limits':'Synthetic fixtures; left transfer and allocator/panic implementations are external. No target execution or Rust identity comparison.'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    args=parser.parse_args()
    image=load_image()
    generate(image,args.out)

if __name__=='__main__':
    main()
