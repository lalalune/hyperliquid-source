#!/usr/bin/env python3
"""Reconstruct the node #115 consensus quorum rule 0x595bc40: stake precheck, then a clamped validator-count fraction.

The body 0x595bc40 runs as real bytes in an interpreter inside this tool, over real B-tree set fixtures of 20 byte keys. The stake quorum
0x4d3e1a0 behind GOT slot 0x64e6a98 and memcmp are recording stubs; a separately written rule list predicts the result byte and the ordered
call log. No disassembler output is parsed and the binary is never executed. Standard library only.

    python3 tools/re8_quorum_count115.py --out <dir>
"""
import argparse
import bisect
import collections
import hashlib
import itertools
import json
import multiprocessing
import pathlib
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
STACK_SIZE = 0x10000
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
        self.overlay = None

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
        if self.overlay is not None and OVERLAY_LOW <= addr and addr + count <= OVERLAY_LOW + 0x60:
            return self.overlay, addr - OVERLAY_LOW
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



class Real:
    """Every code address runs for real, but for the skipped stub targets."""

    def __init__(self, low, high):
        self.low, self.high, self.skip = low, high, set()

    def __contains__(self, va):
        return self.low <= va < self.high and va not in self.skip


OVERLAY_LOW = 0x64EFC80
MARK_BASE = 0x7700000000


# ---------------------------------------------------------------------------------------------
# Node #115 consensus quorum 0x595bc40: stake precheck, then a clamped validator-count fraction.
# ---------------------------------------------------------------------------------------------

QUORUM = 0x595BC40
STAKE_QUORUM = 0x4D3E1A0
PRECHECK_SLOT = 0x64E6A98
MEMCMP_SLOT = 0x64DFB50
PANIC_SLOTS = (0x64DF830, 0x64DF520)
CONFIG_AT = HEAP_BASE + 0x3000
STAKES_AT = HEAP_BASE + 0x3200
SIGNERS_AT = HEAP_BASE + 0x3400
ARENA_AT = HEAP_BASE + 0x30000
ARENA_END_AT = HEAP_BASE + 0x3F0000
HEAP_USED = 0x3F0000
FILL = 0xA5
SET = dict(ksz=20, vsz=0, koff=8, voff=0, parent=0, pidx=0xE4, length=0xE6, edges=0xE8, leaf=0xE8, internal=0x148)
STAKE_TREE = dict(ksz=20, vsz=8, koff=0x60, voff=8, parent=0, pidx=0x13C, length=0x13E, edges=0x140, leaf=0x140, internal=0x1A0)
OFFSETS = dict(fraction=0x88, stake_root=0x20, stake_height=0x28, stake_total=0x30, signer_root=0, signer_height=8, signer_len=0x10)
CLAMP_MAX = 0.7
NONFINITE_FRACTION = 1.0
MAX_FINITE_BITS = 0x7FEFFFFFFFFFFFFF
M64 = MASK[8]


def capacity(height):
    return 11 if height == 0 else 12 * capacity(height - 1) + 11


def minimum(height):
    return 1 if height == 0 else 1 + 2 * minimum(height - 1)


def tree_height(count):
    height = 0
    while count > capacity(height):
        height += 1
    return height


def address(seed):
    return bytes([0x30 + (seed * 7 & 0x3F)]) + bytes(15) + bytes([seed >> 8 & 255, seed & 255, (seed * 5 + 1) & 255, seed % 251 + 1])


class Stream:
    """xorshift64: the same numbers on every Python version."""

    def __init__(self, seed):
        self.state = (seed * 0x9E3779B97F4A7C15 + 0x1234567) & M64 or 1

    def next(self, bound):
        x = self.state
        x ^= x << 13 & M64
        x ^= x >> 7
        x ^= x << 17 & M64
        self.state = x
        return x % bound


def memcmp_result(left, right):
    """What the libc call reports: the difference of the first differing bytes, as a 32 bit word."""
    for a, b in zip(left, right):
        if a != b:
            return (a - b) & MASK[4]
    return 0


def signed32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


class Quorum:
    """Machine plus the fixture of one call; the stake precheck and memcmp are recording stubs, the body runs as bytes."""

    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = self.machine = Machine(image, patches)
        text = image.named[".text"]
        machine.real = Real(text["address"], text["address"] + text["size"])
        machine.real.skip.add(STAKE_QUORUM)
        machine.step_limit = 400000
        machine.memory.statics = dict(image.relative())
        for slot, hook in ((PRECHECK_SLOT, self.on_precheck), (MEMCMP_SLOT, self.on_memcmp)) + tuple((s, self.on_panic) for s in PANIC_SLOTS):
            fake = MARK_BASE + slot
            machine.memory.statics[slot] = fake
            machine.slots[fake] = hook
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.original = image.relative()[PRECHECK_SLOT]
        self.log, self.top, self.stream, self.pre, self.vrange, self.slog = [], ARENA_AT, Stream(5), 1, (0, 0), []

    def on_panic(self, machine):
        raise Panicked("panic path reached")

    def on_precheck(self, machine):
        self.log.append(("pre", machine.regs[RDI], machine.regs[RSI]))
        machine.regs[RAX] = self.pre

    def on_memcmp(self, machine):
        left = self.data(machine.regs[RDI], machine.regs[RDX])
        right = self.data(machine.regs[RSI], machine.regs[RDX])
        if self.vrange[0] <= machine.regs[RSI] < self.vrange[1]:
            self.log.append(("cmp", left, right))
        else:
            self.slog.append((left, right))
        machine.regs[RAX] = memcmp_result(left, right)

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def write(self, at, value, size=8):
        self.machine.memory.write(at, size, value)

    def data(self, at, size):
        return self.machine.memory.bytes_at(at, size)

    def put(self, at, data):
        self.machine.memory.put_bytes(at, data)

    def alloc(self, size):
        at = self.top
        self.top += (size + 15) & ~15
        if self.top > ARENA_END_AT:
            raise Halt("fixture arena full")
        self.put(at, bytes([FILL]) * ((size + 15) & ~15))
        return at

    def build_set(self, keys, geom=None, values=None):
        """B-tree set of sorted 20 byte keys in the node layout SET; returns (root, height, shape) with shape = (keys, children)."""
        g = geom or SET
        count = len(keys)
        if count == 0:
            return 0, 0, None
        height = tree_height(count)

        def node(items, level):
            at = self.alloc(g["leaf"] if level == 0 else g["internal"])
            self.put(at + g["koff"], bytes(g["ksz"] * 11))
            if level == 0:
                chosen, kids, shapes = items, [], []
            else:
                smallest = max(2, -(-(len(items) + 1) // (capacity(level - 1) + 1)))
                largest = min(12, (len(items) + 1) // (minimum(level - 1) + 1))
                fan = smallest + self.stream.next(largest - smallest + 1)
                room = len(items) - (fan - 1)
                sizes = [room // fan + (1 if index < room % fan else 0) for index in range(fan)]
                chosen, kids, shapes, cursor = [], [], [], 0
                for index, size in enumerate(sizes):
                    kid, shape = node(items[cursor:cursor + size], level - 1)
                    kids.append(kid)
                    shapes.append(shape)
                    cursor += size
                    if index < fan - 1:
                        chosen.append(items[cursor])
                        cursor += 1
            for index, key in enumerate(chosen):
                self.put(at + g["koff"] + g["ksz"] * index, key)
                if g["vsz"]:
                    self.put(at + g["voff"] + g["vsz"] * index, values[key])
            self.write(at + g["length"], len(chosen), 2)
            for index, kid in enumerate(kids):
                self.write(at + g["edges"] + 8 * index, kid)
                self.write(kid + g["parent"], at)
                self.write(kid + g["pidx"], index, 2)
            return at, (tuple(chosen), tuple(shapes))
        root, shape = node(list(keys), height)
        return root, height, shape

    def check_set(self, root, height, keys):
        """Walk a fixture tree through its own fields; the in-order keys must be the sorted input."""
        out = []

        def walk(at, level, parent, index):
            if parent is not None and (self.read(at + SET["parent"]) != parent or self.read(at + SET["pidx"], 2) != index):
                raise EvidenceError("parent link of node %#x" % at)
            length = self.read(at + SET["length"], 2)
            if length > 11 or (level and length == 0):
                raise EvidenceError("node length %d" % length)
            for slot in range(length + 1 if level else length):
                if level:
                    walk(self.read(at + SET["edges"] + 8 * slot), level - 1, at, slot)
                if slot < length:
                    out.append(self.data(at + SET["koff"] + SET["ksz"] * slot, SET["ksz"]))
        if root:
            walk(root, height, None, 0)
        if out != list(keys):
            raise EvidenceError("tree keys are not the sorted input")

    def build_ring(self, entries, head, spare):
        """Ring buffer of 32 byte elements (key, pad, value at +0x18); returns (cap, buf, head, len)."""
        count = len(entries)
        cap = count + spare
        buf = self.alloc(max(1, cap) * 32)
        for index, (key, value) in enumerate(entries):
            self.put(buf + ((head + index) % cap) * 32, key + bytes([0x77]) * 4 + struct.pack("<Q", value))
        return cap, buf, (head % cap if cap else 0), count

    def prepare(self, world):
        machine = self.machine
        machine.memory.reset(HEAP_USED)
        self.log, self.slog, self.top, self.stream = [], [], ARENA_AT, Stream(world["shape"])
        self.pre = world["pre"]
        real = bool(world.get("stake_map") is not None)
        machine.real.skip = set() if real else {STAKE_QUORUM}
        machine.memory.statics[PRECHECK_SLOT] = self.original if real else MARK_BASE + PRECHECK_SLOT
        for at in (CONFIG_AT, STAKES_AT, SIGNERS_AT):
            self.put(at, bytes([FILL]) * 0x100)
        signers, stakes = list(world["A"]), list(world["B"])
        a_root, a_height, self.shape_a = self.build_set(signers)
        low = self.top
        b_root, b_height, self.shape_b = self.build_set(stakes)
        self.vrange = (low, self.top)
        self.check_set(a_root, a_height, signers)
        self.check_set(b_root, b_height, stakes)
        if real:
            entries = sorted(world["stake_map"])
            if world["stake_form"] == "tree":
                root, height, _ = self.build_set([k for k, _ in entries], STAKE_TREE, {k: struct.pack("<Q", v) for k, v in entries})
                header = (1 << 63, root, height, len(entries))
            else:
                header = self.build_ring(entries, world["ring_head"], world["ring_spare"])
            for index, word in enumerate(header):
                self.write(STAKES_AT + 8 * index, word)
        if world.get("a_null"):
            a_root, a_height = 0, world["a_null"] & 7
        self.write(CONFIG_AT + OFFSETS["fraction"], world["frac"])
        self.write(STAKES_AT + OFFSETS["stake_root"], b_root)
        self.write(STAKES_AT + OFFSETS["stake_height"], b_height)
        self.write(STAKES_AT + OFFSETS["stake_total"], world["total"])
        self.write(SIGNERS_AT + OFFSETS["signer_root"], a_root)
        self.write(SIGNERS_AT + OFFSETS["signer_height"], a_height)
        self.write(SIGNERS_AT + OFFSETS["signer_len"], world.get("alen", len(signers)))
        return (self.data(CONFIG_AT, 0x100), self.data(STAKES_AT, 0x100), self.data(SIGNERS_AT, 0x100), self.data(ARENA_AT, self.top - ARENA_AT))

    def run(self, world):
        before = self.prepare(world)
        got = self.machine.run(QUORUM, {RDI: CONFIG_AT, RSI: STAKES_AT, RDX: SIGNERS_AT}) & 0xFF
        after = (self.data(CONFIG_AT, 0x100), self.data(STAKES_AT, 0x100), self.data(SIGNERS_AT, 0x100), self.data(ARENA_AT, self.top - ARENA_AT))
        if after != before:
            raise Halt("the quorum wrote into its arguments")
        return got, tuple(self.log)


# ---------------------------------------------------------------------------------------------
# The separately written rule list.
# ---------------------------------------------------------------------------------------------

def effective_fraction(bits):
    """The configured fraction after the clamp: None when the stored double is zero (the count test is skipped)."""
    if bits & 0x7FFFFFFFFFFFFFFF > MAX_FINITE_BITS:
        return NONFINITE_FRACTION
    x = to_float(bits)
    low = 0.0 if 0.0 > x else x
    clamped = CLAMP_MAX if CLAMP_MAX < low else low
    return None if clamped == 0.0 else clamped


def search(shape, key, log):
    keys, kids = shape
    while True:
        index = 0
        while index < len(keys):
            log.append(("cmp", key, keys[index]))
            if key == keys[index]:
                return True
            if key < keys[index]:
                break
            index += 1
        if not kids:
            return False
        shape = kids[index]
        keys, kids = shape


def in_order(shape):
    keys, kids = shape
    if not kids:
        return list(keys)
    out = []
    for index, kid in enumerate(kids):
        out += in_order(kid)
        if index < len(keys):
            out.append(keys[index])
    return out


def saturating_sum(values, flaw=None):
    total = 0
    for value in values:
        total = total + value if flaw == "wrapping_sums" else min(M64, total + value)
        total &= M64 if flaw == "wrapping_sums" else M64
    return total


def stake_quorum(world, shape_a, flaw=None):
    """The 2/3 stake test behind slot 0x64e6a98: saturating u64 sums, 3 * signed > 2 * total on 128 bits."""
    stakes = dict(world["stake_map"])
    signers = in_order(shape_a) if shape_a is not None and not world.get("a_null") else []
    signed = saturating_sum((stakes[key] for key in signers if key in stakes), flaw)
    total = saturating_sum(stakes.values(), flaw)
    if flaw == "at_least_two_thirds":
        return 3 * signed >= 2 * total
    if flaw == "one_half":
        return 2 * signed > total
    if flaw == "count_not_stake":
        return 3 * len([k for k in signers if k in stakes]) > 2 * len(stakes)
    return 3 * signed > 2 * total


def spec_quorum(world, shape_a, shape_b, flaw=None):
    """Returns (result, ordered call log); `flaw` injects one deliberate mistake for the negative controls."""
    real = world.get("stake_map") is not None
    log = [] if real else [("pre", STAKES_AT, SIGNERS_AT)]
    if real:
        if flaw != "precheck_ignored" and not stake_quorum(world, shape_a, flaw):
            return 0, tuple(log)
    elif flaw != "precheck_ignored" and world["pre"] & 0xFF == 0:
        return 0, tuple(log)
    bits = world["frac"]
    nonfinite = bits & 0x7FFFFFFFFFFFFFFF > MAX_FINITE_BITS
    fraction = effective_fraction(bits)
    if flaw == "nan_is_zero" and nonfinite:
        return 1, tuple(log)
    if flaw == "no_upper_clamp" and not nonfinite:
        fraction = to_float(bits) if to_float(bits) > 0 else None
    if flaw == "clamp_two_thirds" and fraction not in (None, NONFINITE_FRACTION):
        fraction = min(fraction, 2 / 3)
    if flaw == "nonfinite_as_clamp" and nonfinite:
        fraction = CLAMP_MAX
    if flaw == "zero_not_special" and fraction is None:
        fraction = 0.0
    if fraction is None:
        return 1, tuple(log)
    signers = in_order(shape_a) if shape_a is not None and not world.get("a_null") else []
    signed = 0
    if shape_b is not None:
        for key in signers:
            if search(shape_b, key, log):
                signed += 1
    if flaw == "count_all_signers":
        signed = len(signers)
    total = world["total"]
    if flaw == "total_is_tree_size":
        total = len(world["B"])
    if flaw == "total_32_bit":
        total &= MASK[4]
    left, right = float(signed), fraction * float(total)
    if flaw == "float32_total":
        right = fraction * struct.unpack("<f", struct.pack("<f", float(total)))[0]
    if flaw == "at_least":
        return int(left >= right), tuple(log)
    if flaw == "fraction_of_signers":
        left, right = float(total), fraction * float(len(signers))
    return int(left > right), tuple(log)


# ---------------------------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------------------------

FRACTION_BITS = (
    0x0000000000000000, 0x8000000000000000, 0x0000000000000001, 0x8000000000000001, 0x000FFFFFFFFFFFFF, 0x0010000000000000,
    0x3C90000000000000, 0x3F847AE147AE147B, 0x3FB999999999999A, 0x3FD0000000000000, 0x3FE0000000000000, 0x3FE3333333333333,
    0x3FE5555555555555, 0x3FE6666666666666, 0x3FE6666666666667, 0x3FE6666666666665, 0x3FE8000000000000, 0x3FECCCCCCCCCCCCD,
    0x3FF0000000000000, 0x3FF0000000000001, 0x4000000000000000, 0x7E37E43C8800759C, 0x7FEFFFFFFFFFFFFF, 0xFFEFFFFFFFFFFFFF,
    0xBFE0000000000000, 0xBFF0000000000000, 0xC000000000000000, 0xFE37E43C8800759C, 0x7FF0000000000000, 0xFFF0000000000000,
    0x7FF8000000000000, 0xFFF8000000000000, 0x7FF0000000000001, 0x7FFFFFFFFFFFFFFF, 0xFFF0000000000001, 0xFFFFFFFFFFFFFFFF,
    0x3C6A36E2EB1C432D, 0x3BC79CA10C924223, 0x3FE6666666666664, 0x3FE6666666666668,
)
PRE_VALUES = (1, 0xFF, 0x101, 0xFE01, 0x0, 0x100, 0xAA00, 0xFFFFFFFFFFFFFF00)
TOTALS = (0, 1, 2, 3, 5, 7, 10, 11, 12, 13, 100, 143, 1000, 1 << 32, (1 << 32) - 1, 1 << 53, (1 << 53) + 1, (1 << 53) + 3, 1 << 60,
          (1 << 63) - 1, 1 << 63, (1 << 63) + 513, (1 << 64) - 1)
COUNTS = (0, 1, 2, 3, 5, 11, 12, 13, 24, 60)
TREE_COUNTS = (0, 1, 3, 10, 11, 12, 20, 40, 143, 144, 200)


def make_world(serial, signed, extra_signers, stakes, frac, total, pre=1):
    """`signed` of the signers are stakeholders, `extra_signers` are not; keys are spread over the stake range."""
    stream = Stream(serial)
    stakeholders = sorted(address(20000 + serial * 977 + n * 13 + stream.next(11)) for n in range(stakes))
    stakeholders = sorted(set(stakeholders))
    stride = max(1, len(stakeholders) // max(1, signed))
    chosen = [stakeholders[(n * stride + stream.next(stride)) % len(stakeholders)] for n in range(signed)] if stakeholders else []
    outsiders = [address(700000 + serial * 977 + n * 17 + stream.next(13)) for n in range(extra_signers)]
    signers = sorted(set(chosen) | set(k for k in outsiders if k not in stakeholders))
    return dict(shape=serial, A=tuple(signers), B=tuple(stakeholders), frac=frac, total=total, pre=pre)


def boundary_totals(signed, bits):
    value = effective_fraction(bits)
    totals = {0, 1, 2}
    if value is not None and value > 1e-17:
        centre = int(signed / value)
        for delta in (-2, -1, 0, 1, 2):
            if 0 <= centre + delta < (1 << 64):
                totals.add(centre + delta)
    return sorted(totals)


def all_cases():
    serial = 0
    for bits in FRACTION_BITS:
        for signed in (0, 1, 2, 5, 7):
            for total in sorted(set(boundary_totals(signed, bits)) | set(TOTALS[::3])):
                serial += 1
                yield "fraction_grid", make_world(serial, signed, 2, 9 if signed < 6 else 14, bits, total)
    for index in range(7200):
        serial += 1
        stream = Stream(serial)
        stakes = TREE_COUNTS[stream.next(len(TREE_COUNTS))]
        signers = COUNTS[stream.next(len(COUNTS))]
        signed = min(stakes, stream.next(signers + 1)) if stakes else 0
        bits = FRACTION_BITS[stream.next(len(FRACTION_BITS))] if stream.next(3) else to_bits(stream.next(1000001) / 1000000.0)
        total = stakes if stream.next(4) else TOTALS[stream.next(len(TOTALS))]
        yield "random_trees", make_world(serial, signed, signers - signed, stakes, bits, total, PRE_VALUES[stream.next(3)])
    for pre in PRE_VALUES:
        for stakes in (0, 1, 12, 40):
            for bits in FRACTION_BITS[::4]:
                serial += 1
                yield "precheck_value", make_world(serial, min(stakes, 3), 1, stakes, bits, stakes, pre)
    for index in range(60):
        serial += 1
        stream = Stream(serial)
        stakes = TREE_COUNTS[stream.next(len(TREE_COUNTS))]
        world = make_world(serial, min(stakes, 4), 2, stakes, FRACTION_BITS[stream.next(len(FRACTION_BITS))], TOTALS[stream.next(len(TOTALS))])
        yield "signer_root_null", dict(world, a_null=1 + stream.next(7), alen=1 + stream.next(40))
    for index in range(120):
        serial += 1
        stream = Stream(serial)
        yield "stake_root_null", make_world(serial, 0, 1 + stream.next(30), 0, FRACTION_BITS[stream.next(len(FRACTION_BITS))], TOTALS[stream.next(len(TOTALS))])
    for big in (1 << 53, (1 << 53) + 1, 1 << 60, (1 << 60) + 3, (1 << 64) - 1, 10 ** 19, (1 << 63) + 513):
        for signed in (1, 3, 6, 7):
            for tweak in range(-2, 3):
                value = (signed - 0.5 + 0.5 * (tweak // 2 + 1)) / float(big)
                bits = to_bits(value) + (tweak if tweak in (-1, 1) else 0)
                serial += 1
                yield "u64_rounding", make_world(serial, signed, 1, 9, bits, big)
    yield from stake_cases(serial + 1000)


def stake_world(serial, form, mode):
    stream = Stream(serial * 7 + 3)
    keys = sorted(set(address(40000 + serial * 211 + n * 7 + stream.next(5)) for n in range(2 + stream.next(40))))
    count = len(keys)
    pick = [k for i, k in enumerate(keys) if stream.next(3) == 0]
    outsiders = [address(900000 + serial * 211 + n) for n in range(stream.next(4))]
    world = make_world(serial, 0, 0, 6, FRACTION_BITS[stream.next(len(FRACTION_BITS))], 6)
    signers = sorted(set(pick) | set(outsiders))
    if mode == "boundary":
        small = 1 + stream.next(5)
        value, other = 2 * (1 + stream.next(4)), 1 + stream.next(4)
        signed_keys = keys[:small]
        rest = keys[small:]
        # signed * 1 = 2 * outsider_total: signed = small * value; make the outsiders weigh signed / 2
        entries = [(k, value) for k in signed_keys] + [(k, 0) for k in rest]
        target = small * value
        if rest:
            share, extra_ = divmod(target, 2 * len(rest))
            entries = [(k, value) for k in signed_keys] + [(k, share + (1 if i < extra_ else 0)) for i, k in enumerate(rest)]
        bump = stream.next(5) - 2
        entries[-1] = (entries[-1][0], max(0, entries[-1][1] + bump))
        signers = sorted(signed_keys)
    else:
        pool = (0, 1, 2, 3, 100, 1 << 32, 1 << 62, 1 << 63, (1 << 63) + 5, (1 << 64) - 1, (1 << 64) - 2)
        entries = [(k, pool[stream.next(len(pool))] if mode == "wide" else 1 + stream.next(1000)) for k in keys]
    return dict(world, A=tuple(signers), B=tuple(sorted(set(pick) | set(keys[:3]))), stake_map=tuple(entries), stake_form=form,
                ring_head=stream.next(7), ring_spare=stream.next(4), total=count, frac=(0 if stream.next(2) else FRACTION_BITS[stream.next(len(FRACTION_BITS))]))


def stake_cases(start):
    serial = start
    for form in ("tree", "ring"):
        for mode, amount in (("boundary", 450), ("wide", 450), ("small", 300)):
            for _ in range(amount):
                serial += 1
                yield "stake_quorum_" + form + "_" + mode, stake_world(serial, form, mode)


def run_case(lookup, world):
    try:
        got = lookup.run(world)
    except Panicked:
        return ("panic",), ("panic",)
    return got, spec_quorum(world, lookup.shape_a, lookup.shape_b)


# ---------------------------------------------------------------------------------------------
# Runner, byte edits and controls
# ---------------------------------------------------------------------------------------------

SCOPE = {
    QUORUM: ("quorum_count_fraction", "real"),
    STAKE_QUORUM: ("stake_quorum_precheck", "real"),
    0x4E44C00: ("signed_stake_sum", "real"),
    0x4E406F0: ("total_stake_sum", "real"),
    0x5138730: ("set_iterator_next", "real"),
    0x57F54E0: ("ring_key_search", "real"),
}
STATE = {}
LOCAL = {}
MUTANT_CASES = 64
WORKERS = 4
SAMPLE_EVERY = 5
FLAWS = ("precheck_ignored", "nan_is_zero", "no_upper_clamp", "clamp_two_thirds", "nonfinite_as_clamp", "zero_not_special",
         "count_all_signers", "wrapping_sums", "at_least_two_thirds", "one_half", "count_not_stake", "total_is_tree_size", "total_32_bit", "float32_total", "at_least", "fraction_of_signers")


def fraction_class(bits):
    if bits & 0x7FFFFFFFFFFFFFFF > MAX_FINITE_BITS:
        return "nonfinite"
    value = effective_fraction(bits)
    if value is None:
        return "zero"
    return "clamped" if to_float(bits) > CLAMP_MAX else "plain"


def case_shape(kind, world, label):
    height = tree_height(len(world["B"])) if world["B"] else -1
    return (kind, label, height, fraction_class(world["frac"]), world["pre"] & 0xFF != 0, world.get("stake_form"))


def case_task(index):
    """One case through the bytes: (index, ok, label, steps, memcmp calls, reached addresses)."""
    lookup = LOCAL.get("lookup")
    if lookup is None:
        lookup = LOCAL["lookup"] = Quorum(STATE["image"])
    kind, world = STATE["cases"][index]
    lookup.machine.seen = set()
    lookup.machine.steps = 0
    got, want = run_case(lookup, world)
    label = "panic" if got[0] == "panic" else ("true" if got[0] else "false")
    calls = sum(1 for item in got[1] if item[0] == "cmp") if got[0] != "panic" else 0
    return index, got == want, label, lookup.machine.steps, calls, frozenset(lookup.machine.seen)


def edits_for(image, rows):
    edits = []
    for row in rows:
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
        elif row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
        elif row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
    return edits


def round_robin(by_kind):
    queues = [list(by_kind[kind]) for kind in sorted(by_kind, key=lambda kind: hashlib.sha256(str(kind).encode()).hexdigest())]
    picked = []
    while queues and len(picked) < MUTANT_CASES:
        for queue in list(queues):
            picked.append(queue.pop(0))
            if not queue:
                queues.remove(queue)
            if len(picked) == MUTANT_CASES:
                break
    return picked


CAUGHT = (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, struct.error, TypeError)


def mutant_task(job):
    va, kind, patch = job
    state = STATE
    picked = state["reach"].get(va, [])
    lookup = Quorum(state["image"], patch, state["cache"])
    lookup.machine.step_limit = 60000
    for index in picked:
        case_kind, world = state["cases"][index]
        try:
            got, want = run_case(lookup, world)
        except CAUGHT:
            return va, kind, "killed", "%s:%d" % (case_kind, index)
        if got != want:
            return va, kind, "killed", "%s:%d" % (case_kind, index)
    return va, kind, "survived", "equal on %d picked cases" % len(picked)


def damaged_layout():
    rows = [("set", field) for field in ("koff", "length", "edges", "pidx", "parent")]
    rows += [("argument", field) for field in sorted(OFFSETS)]
    return rows


def layout_task(job):
    group, field = job
    table = SET if group == "set" else OFFSETS
    saved = dict(table)
    try:
        table[field] += 8
        lookup = Quorum(STATE["image"])
        lookup.machine.step_limit = 60000
        for index in STATE["layout_cases"]:
            kind, world = STATE["cases"][index]
            try:
                got, want = run_case(lookup, world)
            except CAUGHT:
                return group, field, True
            if got != want:
                return group, field, True
        return group, field, False
    finally:
        table.update(saved)


def flaw_rows(cases, image):
    rows = []
    lookup = Quorum(image)
    shapes = {}
    for flaw in FLAWS:
        detected, where = False, ""
        for index, (kind, world) in enumerate(cases):
            if index not in shapes:
                lookup.prepare(world)
                shapes[index] = (lookup.shape_a, lookup.shape_b)
            sa, sb = shapes[index]
            if spec_quorum(world, sa, sb, flaw) != spec_quorum(world, sa, sb):
                detected, where = True, "%s:%d" % (kind, index)
                break
        rows.append((flaw, detected, where))
        if len(shapes) > 6000:
            shapes.clear()
    return rows


def range_controls(image):
    rows = []

    def attempt(name, action):
        try:
            action()
        except (EvidenceError, Halt, Panicked, IndexError, KeyError, ValueError, struct.error):
            rows.append((name, True))
        else:
            rows.append((name, False))
    attempt("digest of the wrong file", lambda: load_image(BINARY, "0" * 64))
    attempt("address inside a function, not an FDE start", lambda: image.exact_fde(QUORUM + 1))
    attempt("address outside every FDE", lambda: image.fde(0x100))
    attempt("address outside every file-backed section", lambda: image.offset(0x10))
    world = make_world(3, 2, 1, 9, 0x3FE0000000000000, 9)

    def tiny_limit():
        small = Quorum(image)
        small.machine.step_limit = 20
        small.run(world)
    attempt("step limit of 20 instructions", tiny_limit)

    def small_arena():
        global ARENA_END_AT
        old = ARENA_END_AT
        ARENA_END_AT = ARENA_AT + 0x100
        try:
            Quorum(image).run(world)
        finally:
            ARENA_END_AT = old
    attempt("fixture arena too small", small_arena)

    def other_world():
        lookup = Quorum(image)
        got, want = run_case(lookup, world)
        other = dict(world, frac=0x3FD0000000000000, total=4)
        if got != spec_quorum(other, lookup.shape_a, lookup.shape_b):
            raise EvidenceError("different fraction and total give a different answer")
    attempt("rule list asked about another fraction", other_world)

    def unsorted_keys():
        Quorum(image).check_set(0, 0, [b"b" * 20, b"a" * 20])
    attempt("key list that is not the tree contents", unsorted_keys)
    return rows


def function_rows(image, reached):
    table = {}
    for target in sorted(SCOPE):
        if SCOPE[target][1] != "real":
            continue
        low, high = image.exact_fde(target)
        rows = [row for row in decode_range(image, low, high) if row.va in reached]
        for row in rows:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        table[target] = rows
    return table


def analyse(image, workers=WORKERS):
    cases = list(all_cases())
    STATE.update(image=image, cases=cases)
    result = dict(case_count=len(cases))
    reached, groups = set(), collections.Counter()
    kept = collections.defaultdict(lambda: collections.defaultdict(list))
    seen_count = collections.Counter()
    sample, layout_cases, steps_total = [], [], 0
    with multiprocessing.get_context("fork").Pool(workers) as pool:
        for index, ok, label, steps, calls, seen in pool.imap(case_task, range(len(cases)), 16):
            kind, world = cases[index]
            if not ok:
                raise EvidenceError("case %d (%s) disagrees with the rule list" % (index, kind))
            groups[(kind, label)] += 1
            steps_total += steps
            shape = case_shape(kind, world, label)
            for va in seen:
                seen_count[(va, shape)] += 1
                if seen_count[(va, shape)] <= 3:
                    kept[va][shape].append(index)
            reached |= seen
            if index % 17 == 0 and len(layout_cases) < 300:
                layout_cases.append(index)
            if index % SAMPLE_EVERY == 0:
                sample.append((index, kind, len(world["A"]), len(world["B"]), "%#018x" % world["frac"], world["total"], "%#x" % world["pre"], label, steps, calls))
    result.update(sample=sample, groups=groups, steps=steps_total)
    STATE["reach"] = {va: round_robin(by_kind) for va, by_kind in kept.items()}
    STATE["cache"] = Quorum(image).machine.cache
    STATE["layout_cases"] = layout_cases
    probe = Quorum(image)
    probe.run(cases[0][1])
    STATE["cache"] = probe.machine.cache
    result["reached"] = reached
    result["table_rows"] = function_rows(image, reached)
    edit_jobs = []
    for target, rows in sorted(result["table_rows"].items()):
        edit_jobs += edits_for(image, rows)
    with multiprocessing.get_context("fork").Pool(workers) as pool:
        mutants = pool.map(mutant_task, edit_jobs, 4)
        layouts = pool.map(layout_task, damaged_layout())
    result["mutants"], result["layouts"] = mutants, layouts
    result["flaws"] = flaw_rows(cases, image)
    result["ranges"] = range_controls(image)
    result["edit_count"] = len(edit_jobs)
    return result


def render(result, image):
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]) + "\n"

    sizes = {target: image.exact_fde(target)[1] - target for target in SCOPE}
    reached_rows = result["table_rows"]
    tsv("path.tsv", ("name", "address", "role", "body_bytes", "reached_rows", "reached_bytes"),
        [(SCOPE[target][0], "%#x" % target, SCOPE[target][1], sizes[target], len(reached_rows.get(target, ())), sum(row.size for row in reached_rows.get(target, ()))) for target in sorted(SCOPE)])
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [(SCOPE[target][0], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in sorted(reached_rows) for row in reached_rows[target]])
    constants = []
    for target in sorted(reached_rows):
        for row in reached_rows[target]:
            if row.op in ("call", "jmp", "jcc", "push", "pop", "ret"):
                continue
            for operand in (row.a, row.b):
                if operand is not None and operand[0] == "i":
                    constants.append((SCOPE[target][0], "%#x" % row.va, bytes(row.data).hex(), row.op, "%#x" % operand[1]))
    tsv("constants.tsv", ("function", "address", "bytes", "operation", "immediate"), constants)
    tsv("layouts.tsv", ("structure", "field", "offset", "meaning"), LAYOUT_ROWS)
    tsv("fractions.tsv", ("bits", "class", "effective_fraction"),
        [("%#018x" % bits, fraction_class(bits), "-" if effective_fraction(bits) is None else repr(effective_fraction(bits))) for bits in FRACTION_BITS])
    tsv("cases.tsv", ("case", "group", "signers", "stakeholders", "fraction_bits", "total", "precheck_rax", "result", "steps", "memcmp_calls"), result["sample"])
    tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutants"]])
    controls = []
    for group, field, detected in result["layouts"]:
        controls.append(("layout_field_moved", "%s %s +8" % (group, field), detected, ""))
    for flaw, detected, where in result["flaws"]:
        controls.append(("rule_list_flaw", flaw, detected, where))
    for va, kind, outcome, detail in result["mutants"]:
        if outcome == "killed":
            controls.append(("byte_edit", "%#x %s" % (va, kind), True, detail))
    for name, detected in result["ranges"]:
        controls.append(("out_of_range", name, detected, ""))
    tsv("controls.tsv", ("control", "what", "detected", "first_witness"), controls)
    survivors = [item for item in result["mutants"] if item[2] == "survived"]
    detected = sum(1 for item in controls if item[2])
    summary = {
        "binary": "artifacts/node/115/hl-node", "sha256": SHA256,
        "functions_real": sum(1 for v in SCOPE.values() if v[1] == "real"), "functions_stubbed": sum(1 for v in SCOPE.values() if v[1] == "stub"),
        "cases": result["case_count"], "instructions_executed": result["steps"],
        "case_groups": {"%s/%s" % key: count for key, count in sorted(result["groups"].items())},
        "instructions_reached": sum(len(rows) for rows in reached_rows.values()),
        "byte_edits_possible": result["edit_count"], "byte_edits_killed": sum(1 for item in result["mutants"] if item[2] == "killed"), "byte_edits_survived": len(survivors),
        "controls": len(controls), "controls_detected": detected,
    }
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps({"cases": result["case_count"], "negative_controls": len(controls), "negative_detected": detected,
                                        "byte_edits_survived": len(survivors)}, indent=1, sort_keys=True) + "\n"
    return files


LAYOUT_ROWS = (
    ("argument 1 (config)", "fraction", "+0x88", "f64; non-finite means 1.0, otherwise clamped to [0, 0.7]; a stored zero skips the count test"),
    ("argument 2 (stakes)", "tree root / height / length", "+0x20 / +0x28 / +0x30", "set of 20 byte stakeholder keys; the length word is the count the fraction applies to"),
    ("argument 3 (signers)", "tree root / height / length", "+0x00 / +0x08 / +0x10", "set of 20 byte signer keys; a null root means no signers whatever the length word says"),
    ("set node", "parent / keys / parent index / length / edges", "+0 / +8 / +0xe4 / +0xe6 / +0xe8", "20 byte keys, no values; leaf 0xe8 bytes, internal 0x148 bytes"),
    ("call 0x64e6a98", "stake quorum 0x4d3e1a0", "rdi=stakes rsi=signers", "al false means false at once, before any other read"),
    ("call 0x64dfb50", "memcmp", "rdi=sought rsi=node key rdx=20", "sign of the result steers the node scan: greater continues, equal is found, less descends"),
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image), image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
