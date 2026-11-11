#!/usr/bin/env python3
"""Reconstruct the node #115 signer admission gate: action class table, validator and listed-signer tests, known-user resolution.

The three gate copies 0x2bdb230, 0x4d907c0 and 0x4d909b0, the class getter 0x36c2030, the listed-signer B-tree search 0x149e4b0 and the
user map reader 0x4716b00 run as real bytes in an interpreter inside this tool. The validator lookup, the hashers, the hash table finders
and the two user helpers are stubs with checked arguments. A separately written rule list predicts every output byte, every stub call and
every key compare. No disassembler output is parsed and the binary is never executed. Standard library only.

    python3 tools/staking_admission_gate115.py --out <dir>

    python3 tools/staking_vote_quorum.py --out <dir>
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


OVERLAY_LOW = 0x64EFC80
MARK_BASE = 0x7700000000


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




# ---------------------------------------------------------------------------------------------
# Node #115 signer admission gate: fixture, rule list, cases, byte edits.
# ---------------------------------------------------------------------------------------------

GATES = (0x2BDB230, 0x4D907C0)
GATE_NAMES = {0x2BDB230: "gate_inline_user", 0x4D907C0: "gate_outlined"}
CLASS_GETTER = 0x36C2030
CLASS_SLOT = 0x64E7860
CLASS_TABLE = 0x79DD60
CLASS_COUNT = 92
RAW_BASE = 0x86
RAW_NICHE_INDEX = 0x14
JUMP_TABLES = {0x2BDB230: 0x60A070, 0x4D907C0: 0x914E98}
VALIDATOR_SLOT = 0x64E4E38
ONCE_SLOT = 0x64DF9F0
MEMCMP_SLOT = 0x64DFB50
PANIC_SLOTS = (0x64DF620, 0x64DF4C0, 0x64DF830)
LOCK_SLOTS = {"chain3": 0x64DFFF8, "other": 0x64E0000}
LOCK_BASE = {"chain3": 0x64EFC80, "other": 0x64EFCB0}
BTREE_SEARCH = 0x149E4B0
USER_GET = 0x4716B00
HASH = 0x4717440
FIND_ROW = 0x3EE6740
FIND_SECOND = 0x3EE69C0
HELPER = {0x4D907C0: 0x55FEDB0}
STUB_TARGETS = (HASH, FIND_ROW, FIND_SECOND, USER_GET)
OTHER_LISTED_AT = (0x464946, 0x46495A, 0x46496E)
STATUS_OK = 0x1A2
STATUS_NOT_VALIDATOR = 0x7F
STATUS_REFUSED = 0x81
STATUS_UNKNOWN_USER = 0x5B
HEAP_USED_GATE = 0x80000
EX_AT = HEAP_BASE + 0x20000
ACTION_AT = HEAP_BASE + 0x3000
SIGNER_AT = HEAP_BASE + 0x3200
OUT_AT = HEAP_BASE + 0x3400
WORD_AT = HEAP_BASE + 0x3600
ARENA_AT = HEAP_BASE + 0x30000
ARENA_END_AT = HEAP_BASE + 0x70000
OUT_SIZE = 0x80
OUT_FILL = 0xC3
OFFSETS = {
    0x2BDB230: dict(validator=0x3F08, chain=0xB9A),
    0x4D907C0: dict(validator=0x3F08, chain=0xB9A),
}
ROW_STRIDE = 0x510
POISON_BYTE = 0xA5
STACK_MARK_BYTE = 0xA5


class Real:
    """Every code address runs for real, but for the named stub targets."""

    def __init__(self, low, high):
        self.low, self.high, self.skip = low, high, set(STUB_TARGETS)

    def __contains__(self, va):
        return self.low <= va < self.high and va not in self.skip


def sig(seed):
    return bytes([0x70 + (seed & 15)] * 19) + bytes([seed & 255])


def tag4(data):
    return data.hex()[-4:]


class Gate:
    """Machine plus the fixture and the stubs of one gate run; every stub checks its arguments."""

    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = self.machine = Machine(image, patches)
        text = image.named[".text"]
        machine.real = Real(text["address"], text["address"] + text["size"])
        machine.step_limit = 400000
        machine.memory.overlay = bytearray(0x60)
        statics = machine.memory.statics = dict(image.relative())
        self.fakes = {}
        for slot, hook in ((VALIDATOR_SLOT, self.on_validator), (ONCE_SLOT, self.on_once), (MEMCMP_SLOT, self.on_compare)):
            self.slot_hook(statics, slot, hook)
        for slot in PANIC_SLOTS:
            self.slot_hook(statics, slot, self.on_panic)
        for va, hook in ((HASH, self.on_hash), (FIND_ROW, self.on_find_row), (FIND_SECOND, self.on_find_second), (USER_GET, self.on_user_get)):
            machine.calls[va] = hook
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.world, self.log, self.top, self.entry, self.compares, self.rows_at, self.cell, self.entries = None, [], ARENA_AT, 0, 0, 0, 0, 0

    def slot_hook(self, statics, slot, hook):
        fake = MARK_BASE + slot
        statics[slot] = fake
        self.machine.slots[fake] = hook

    def expect(self, condition, text):
        if not condition:
            raise Halt("fixture check failed: " + text)

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def write(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8] if size == 8 else value)

    def data(self, at, size):
        return self.machine.memory.bytes_at(at, size)

    def put(self, at, data):
        self.machine.memory.put_bytes(at, data)

    def alloc(self, size):
        at = self.top
        self.top += (size + 15) & ~15
        if self.top > ARENA_END_AT:
            raise Halt("fixture arena full")
        return at

    # ---- stubs -------------------------------------------------------------------------------
    def on_validator(self, machine):
        offsets = OFFSETS[self.entry]
        self.expect(machine.regs[RDI] == EX_AT + offsets["validator"], "validator state pointer")
        key = self.data(machine.regs[RSI], 20)
        self.log.append(("validator", tag4(key)))
        machine.regs[RAX] = 1 if key in self.world["validators"] else 0

    def on_once(self, machine):
        lock = machine.regs[RDI] - 0x28
        name = next((n for n, base in LOCK_BASE.items() if base == lock), None)
        self.expect(name is not None, "once lock address")
        self.expect(machine.regs[RSI] == 1, "once ignore-poison flag")
        self.log.append(("once", name))
        self.install(name, self.world["locks"][name][1])
        self.write(lock + 0x28, 0, 4)

    def on_compare(self, machine):
        self.expect(machine.regs[RDX] == 20, "compare length")
        left, right = self.data(machine.regs[RDI], 20), self.data(machine.regs[RSI], 20)
        self.compares += 1
        machine.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]

    def on_panic(self, machine):
        raise Panicked("panic path reached")

    def on_hash(self, machine):
        key = self.data(machine.regs[RDX], 20)
        self.log.append(("hash", tag4(key), machine.regs[RDI] & 0xFFFF, machine.regs[RSI] & 0xFFFF))
        machine.regs[RAX] = 0x5000 + sum(key)

    def check_token(self, machine, key):
        self.expect(machine.regs[RSI] == 0x5000 + sum(key), "hash token passed to the lookup")

    def closure_key(self, machine):
        closure = machine.regs[RDX]
        return self.data(self.read(closure), 20), closure

    def on_find_row(self, machine):
        key, closure = self.closure_key(machine)
        self.check_token(machine, key)
        table = machine.regs[RDI]
        row = (table - 0x78 - self.rows_at) // ROW_STRIDE
        self.log.append(("row_find", row, tag4(key)))
        self.expect(self.read(closure + 16) == self.world["rows"][row][0], "row length in the closure")
        machine.regs[RAX] = self.cell if key in self.world["rows"][row][1] else 0

    def on_find_second(self, machine):
        key, closure = self.closure_key(machine)
        self.check_token(machine, key)
        self.expect(machine.regs[RDI] == EX_AT + 0x408, "second table address")
        self.log.append(("second_find", tag4(key)))
        self.expect(self.read(closure + 16) == self.world["second"][0], "second length in the closure")
        machine.regs[RAX] = self.cell if key in self.world["second"][1] else 0

    def on_user_get(self, machine):
        self.expect(machine.regs[RDI] == EX_AT + 0x3B80, "user map pointer")
        key = self.data(machine.regs[RSI], 20)
        self.log.append(("user_get", tag4(key)))
        hit = next((i for i, (k, _) in enumerate(self.world["users"]) if k == key), None)
        machine.regs[RAX] = 0 if hit is None else self.entries + 0x30 * hit + 0x1C

    # ---- fixture -----------------------------------------------------------------------------
    def build_set(self, keys):
        """B-tree set of 20 byte keys: a leaf up to 11 keys, else a root of separators over leaves."""
        keys = sorted(keys)
        if not keys:
            return 0, 0

        def node(items, edges):
            size = 0xE8 + 8 * 12
            at = self.alloc(size)
            self.put(at, bytes([POISON_BYTE]) * size)
            for index, key in enumerate(items):
                self.put(at + 8 + 20 * index, key)
            self.write(at + 0xE6, len(items), 2)
            for index, edge in enumerate(edges):
                self.write(at + 0xE8 + 8 * index, edge)
            return at
        if len(keys) <= 11:
            return node(keys, []), 0
        separators = max(1, min(11, (len(keys) - 1) // 6))
        leaves_total = len(keys) - separators
        parts, cursor, chosen = separators + 1, 0, []
        sizes = [leaves_total // parts + (1 if index < leaves_total % parts else 0) for index in range(parts)]
        leaves = []
        for index, size in enumerate(sizes):
            leaves.append(node(keys[cursor:cursor + size], []))
            cursor += size
            if index < separators:
                chosen.append(keys[cursor])
                cursor += 1
        return node(chosen, leaves), 1

    def install(self, name, keys):
        root, height = self.build_set(keys)
        base = LOCK_BASE[name] - OVERLAY_LOW
        overlay = self.machine.memory.overlay
        overlay[base:base + 0x18] = struct.pack("<QQQ", root, height, len(keys))

    def prepare(self, world, entry):
        machine = self.machine
        machine.memory.reset(HEAP_USED_GATE)
        self.world, self.entry, self.log, self.compares = world, entry, [], 0
        self.top = ARENA_AT
        memory = machine.memory
        overlay = memory.overlay
        overlay[:] = bytes(0x60)
        offsets = OFFSETS[entry]
        self.put(EX_AT, bytes([POISON_BYTE]) * 0x6000)
        self.write(EX_AT + offsets["chain"], world["chain"], 1)
        for name in ("chain3", "other"):
            state, keys = world["locks"][name]
            if state == 0:
                self.install(name, keys)
            self.write(LOCK_BASE[name] + 0x28, state, 4)
        self.cell = self.alloc(32) + 8
        self.users(world)
        self.put(ACTION_AT, bytes(0x20))
        self.write(ACTION_AT, world["tag"])
        self.put(SIGNER_AT, world["signer"])
        self.put(OUT_AT, bytes([OUT_FILL]) * OUT_SIZE)

    def users(self, world):
        users = world["users"]
        self.entries = self.alloc(0x30 * max(1, len(users)))
        for index, (key, value) in enumerate(users):
            self.put(self.entries + 0x30 * index + 8, key + value)
        rows = world["rows"]
        self.rows_at = self.alloc(ROW_STRIDE * max(1, len(rows)))
        self.write(EX_AT + 0x7C8, self.rows_at)
        self.write(EX_AT + 0x7D0, len(rows))
        for index, (length, members, key) in enumerate(rows):
            row = self.rows_at + ROW_STRIDE * index
            self.write(row + 0x70, length)
            self.write(row + 0x98, 0x3000 + index)
            self.write(row + 0xA0, 0x4000 + index)
            holder = self.alloc(0xB0)
            self.put(holder + 0x80, key + bytes(12))
            self.write(row + 0x68, holder)
        second = world["second"]
        self.write(EX_AT + 0x400, second[0])
        holder = self.alloc(0xB0)
        self.put(holder + 0x58, second[2] + bytes(12))
        self.write(EX_AT + 0x3F8, holder)
        self.write(EX_AT + 0x428, 0x5555)
        self.write(EX_AT + 0x430, 0x6666)

    def run_class(self, word):
        self.machine.memory.reset(HEAP_USED_GATE)
        self.write(WORD_AT, word)
        return self.machine.run(CLASS_GETTER, {RDI: WORD_AT}) & 0xFF

    def run_search(self, world):
        """The B-tree search called directly: found flag, node, remaining height and edge index of its result record."""
        machine = self.machine
        machine.memory.reset(HEAP_USED_GATE)
        self.top, self.compares = ARENA_AT, 0
        keys, key = world["keys"], world["key"]
        root, height = self.build_set(keys)
        self.put(SIGNER_AT, key)
        self.put(OUT_AT, bytes([OUT_FILL]) * OUT_SIZE)
        machine.run(BTREE_SEARCH, {RDI: OUT_AT, RSI: root, RDX: height, RCX: SIGNER_AT})
        flag, node, left, index = (self.read(OUT_AT + 8 * n) for n in range(4))
        length = self.read(node + 0xE6, 2)
        first = self.data(node + 8, 20) if length else b""
        return ("btree", (), self.compares, flag, left, index, length, first)

    def run(self, world, entry):
        self.prepare(world, entry)
        got = self.machine.run(entry, {RDI: OUT_AT, RSI: ACTION_AT, RDX: SIGNER_AT, RCX: EX_AT})
        if got != OUT_AT:
            raise Halt("return pointer is not the out record")
        return self.data(OUT_AT, OUT_SIZE), tuple(self.log), self.compares



# ---------------------------------------------------------------------------------------------
# The separately written rule list: every output byte, every stub call and the key compares.
# ---------------------------------------------------------------------------------------------

def layout(keys):
    """Nested (items, children) form of the B-tree set the fixture builds for these keys."""
    keys = sorted(keys)
    if len(keys) <= 11:
        return (keys, []), 0
    separators = max(1, min(11, (len(keys) - 1) // 6))
    total = len(keys) - separators
    parts = separators + 1
    sizes = [total // parts + (1 if index < total % parts else 0) for index in range(parts)]
    leaves, picked, cursor = [], [], 0
    for index, size in enumerate(sizes):
        leaves.append((keys[cursor:cursor + size], []))
        cursor += size
        if index < separators:
            picked.append(keys[cursor])
            cursor += 1
    return (picked, leaves), 1


def tree_search(keys, key):
    """Found flag and the number of key compares of a node-by-node linear search."""
    if not keys:
        return None, 0
    node, height = layout(keys)
    compares = 0
    while True:
        items, children = node
        for index, item in enumerate(items):
            compares += 1
            if key == item:
                return True, compares
            if key < item:
                break
        else:
            index = len(items)
        if height == 0:
            return False, compares
        node, height = children[index], height - 1


def spec_class(word, table):
    return table[RAW_NICHE_INDEX if word < RAW_BASE else word - RAW_BASE]


def spec_gate(entry, world, table):
    """Returns (out bytes, ordered stub log, compares) or ("panic", log, compares)."""
    word, signer = world["tag"], world["signer"]
    out = bytearray([OUT_FILL]) * OUT_SIZE
    log, compares = [], 0

    def done(status, payload=None):
        out[0:2] = struct.pack("<H", status)
        if payload is not None:
            out[2:22] = payload
        return bytes(out), tuple(log), compares

    kind = spec_class(word, table)
    if kind in (0, 1):
        log.append(("validator", tag4(signer)))
        if signer in world["validators"]:
            return done(STATUS_OK, signer)
        if kind == 0:
            return done(STATUS_NOT_VALIDATOR)
        name = "chain3" if world["chain"] == 3 else "other"
        state, keys = world["locks"][name]
        if state:
            log.append(("once", name))
        if not keys:
            return done(STATUS_NOT_VALIDATOR)
        found, compares = tree_search(keys, signer)
        return done(STATUS_OK, signer) if found else done(STATUS_NOT_VALIDATOR)
    if kind == 2:
        return done(STATUS_OK, signer)
    if kind == 4:
        return done(STATUS_REFUSED)
    if kind != 3:
        raise EvidenceError("class byte outside 0..4")
    log.append(("user_get", tag4(signer)))
    value = next((val for key, val in world["users"] if key == signer), None)
    if value is not None:
        return done(STATUS_OK, value)
    for index, (length, members, key) in enumerate(world["rows"]):
        if length == 0:
            continue
        if length == 1:
            found = key == signer
        else:
            log.append(("hash", tag4(signer), 0x3000 + index, 0x4000 + index))
            log.append(("row_find", index, tag4(signer)))
            found = signer in members
        if found:
            return done(STATUS_OK, signer)
    length, members, key = world["second"]
    if length == 1:
        found = key == signer
    elif length == 0:
        found = False
    else:
        log.append(("hash", tag4(signer), 0x5555, 0x6666))
        log.append(("second_find", tag4(signer)))
        found = signer in members
    if found:
        return done(STATUS_OK, signer)
    result = done(STATUS_UNKNOWN_USER, signer)
    if entry != GATES[0]:
        # the outlined gate copies the helper's whole 0x70 byte record; its tail is untouched stack
        tail = bytearray(result[0])
        tail[22:0x70] = bytes([STACK_MARK_BYTE]) * (0x70 - 22)
        return bytes(tail), result[1], result[2]
    return result


def spec_search(world):
    """Result record of the node by node search: flag (0 found, 1 not found), remaining height, edge index, node length and first key."""
    keys, key = sorted(world["keys"]), world["key"]
    node, height = layout(keys)
    compares = 0
    while True:
        items, children = node
        index = len(items)
        for position, item in enumerate(items):
            compares += 1
            if key == item:
                return ("btree", (), compares, 0, height, position, len(items), items[0])
            if key < item:
                index = position
                break
        if height == 0:
            return ("btree", (), compares, 1, 0, index, len(items), items[0])
        node, height = children[index], height - 1


# ---------------------------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------------------------

class Stream:
    """xorshift64: the same numbers on every Python version."""

    def __init__(self, seed):
        self.state = (seed * 0x9E3779B97F4A7C15 + 0x1234567) & MASK[8] or 1

    def next(self, bound):
        x = self.state
        x ^= x << 13 & MASK[8]
        x ^= x >> 7
        x ^= x << 17 & MASK[8]
        self.state = x
        return x % bound


def blank_world(tag, signer, chain=0):
    return dict(tag=tag, signer=signer, chain=chain, validators=frozenset(), locks={"chain3": (0, ()), "other": (0, ())},
                users=[], bad_index=None, rows=[], second=(0, frozenset(), sig(0xEE)))


def lock_keys(mode, signer, base):
    if mode == "empty":
        return ()
    if mode == "in":
        return tuple(base) + (signer,)
    return tuple(base)


def tag_list(table):
    edge = [0, 1, RAW_BASE - 1]
    return edge + [RAW_BASE + index for index in range(CLASS_COUNT)]


def class_sweep_cases(table, listed_other):
    signer = sig(5)
    foreign = tuple(sig(0x20 + n) for n in range(3))
    for entry in GATES:
        for tag in tag_list(table):
            for is_validator in (True, False):
                for chain in (3, 2, 0):
                    for mode3 in ("in", "out", "empty"):
                        for mode_other in ("in", "out", "empty"):
                            for state in (0, 1):
                                if state == 1 and mode3 != mode_other:
                                    continue
                                world = blank_world(tag, signer, chain)
                                world["validators"] = frozenset([signer]) if is_validator else frozenset()
                                world["locks"] = {"chain3": (state, lock_keys(mode3, signer, foreign)), "other": (state, lock_keys(mode_other, signer, listed_other))}
                                yield ("class_sweep", entry, world)


def tree_cases(table, listed_other):
    stream = Stream(11)
    tag = RAW_BASE + 20
    for entry in GATES:
        for size in (3, 11, 12, 20, 41, 100):
            for place in ("first", "middle", "last", "absent", "between"):
                keys = sorted(set(bytes([0x10]) + bytes(18) + bytes([2 * n + 1 + 0x20 * (n // 100)]) + bytes(0) for n in range(size)))
                keys = sorted(set(bytes([0x40 + (n >> 4)]) + bytes(17) + bytes([n & 255, 2 * n & 255]) for n in range(size)))
                members = keys
                target = {"first": members[0], "middle": members[len(members) // 2], "last": members[-1],
                          "absent": bytes([0x7F]) * 20, "between": bytes([0x40]) + bytes(17) + bytes([0, 1])}[place]
                for chain in (3, 0):
                    world = blank_world(tag, target, chain)
                    name = "chain3" if chain == 3 else "other"
                    world["locks"][name] = (stream.next(2), tuple(members))
                    yield ("tree", entry, world)
    tall = tuple(bytes([0x40 + (n >> 4)]) + bytes(17) + bytes([n & 255, 2 * n & 255]) for n in range(40))
    short = tuple(bytes([0x60]) + bytes(17) + bytes([n, 1]) for n in range(3))
    for entry in GATES:
        for chain in (3, 0):
            for tall_on in ("chain3", "other"):
                for pick in (0, 7, 39, 41):
                    keys_tall, keys_short = tall, short
                    signer = tall[pick] if pick < 40 else short[pick - 40 if pick - 40 < 3 else 0]
                    world = blank_world(tag, signer, chain)
                    world["locks"] = {"chain3": (0, keys_tall if tall_on == "chain3" else keys_short), "other": (0, keys_tall if tall_on == "other" else keys_short)}
                    yield ("tree_mixed", entry, world)
                    world = blank_world(tag, short[1], chain)
                    world["locks"] = dict(world["locks"], **{"chain3": (0, keys_tall if tall_on == "chain3" else keys_short), "other": (0, keys_tall if tall_on == "other" else keys_short)})
                    yield ("tree_mixed", entry, world)


def user_cases(table):
    tag = RAW_BASE + 0
    signer = sig(9)
    other = [sig(0x30 + n) for n in range(8)]
    value = bytes(range(0xA0, 0xB4))
    for entry, count in itertools.product(GATES, (0, 1, 2, 3, 5, 7)):
        for place in ("miss", "first", "middle", "last"):
            if count == 0 and place != "miss":
                continue
            for rows_mode in ("none", "len0", "len1_hit", "len1_miss", "multi_hit", "multi_miss", "mixed"):
                for second_mode in ("zero", "zero_stale", "one_hit", "one_miss", "many_hit", "many_miss"):
                    users = [(other[n], bytes([n + 1]) * 20) for n in range(count)]
                    if place != "miss":
                        users[{"first": 0, "middle": count // 2, "last": count - 1}[place]] = (signer, value)
                    world = blank_world(tag, signer)
                    world["users"] = users
                    rows = {"none": [], "len0": [(0, frozenset(), other[0])], "len1_hit": [(1, frozenset(), signer)],
                            "len1_miss": [(1, frozenset(), other[1])], "multi_hit": [(0, frozenset(), other[0]), (3, frozenset([other[2], signer]), other[1])],
                            "multi_miss": [(2, frozenset([other[2]]), other[0]), (5, frozenset([other[3]]), other[1])],
                            "mixed": [(1, frozenset(), other[4]), (0, frozenset(), other[0]), (2, frozenset([signer]), other[2])]}[rows_mode]
                    world["rows"] = rows
                    world["second"] = {"zero": (0, frozenset(), other[5]), "zero_stale": (0, frozenset([signer]), signer), "one_hit": (1, frozenset(), signer), "one_miss": (1, frozenset(), other[5]),
                                       "many_hit": (4, frozenset([signer, other[5]]), other[5]), "many_miss": (4, frozenset([other[5]]), other[5])}[second_mode]
                    yield ("user_inline", entry, world)


def search_cases():
    for size in (1, 2, 5, 11, 12, 13, 17, 23, 40, 64, 100):
        for style in ("dense", "sparse", "prefix"):
            if style == "dense":
                keys = [bytes(18) + bytes([n >> 8, n & 255]) for n in range(1, size + 1)]
            elif style == "sparse":
                keys = [bytes([n * 2 + 1]) + bytes(18) + bytes([n & 255]) for n in range(size)]
            else:
                keys = [bytes([0x55] * 18) + bytes([(n * 3 + 1) >> 8, (n * 3 + 1) & 255]) for n in range(size)]
            ordered = sorted(keys)
            picks = sorted(set([0, size // 3, size // 2, (2 * size) // 3, size - 1]))
            probes = [ordered[index] for index in picks]
            probes += [bytes(20), b"\xff" * 20, ordered[0][:19] + bytes([ordered[0][19] ^ 1])]
            probes += [ordered[index][:19] + bytes([(ordered[index][19] + 1) & 255]) for index in picks[1:3]]
            for probe in probes:
                yield ("btree_direct", BTREE_SEARCH, dict(keys=tuple(keys), key=probe))


def all_cases(table, listed_other):
    yield from class_sweep_cases(table, listed_other)
    yield from tree_cases(table, listed_other)
    yield from user_cases(table)
    yield from search_cases()



# ---------------------------------------------------------------------------------------------
# Runner, parallel checking, byte edits and controls
# ---------------------------------------------------------------------------------------------

RULES = {0: "validator signer only, else 0x7f", 1: "validator signer or listed address, else 0x7f", 2: "any signer",
         3: "known user, resolved by the user map, the rows or the second map, else 0x5b", 4: "refused, 0x81"}
SCOPE = {
    0x2BDB230: ("gate_inline_user", "real"), 0x4D907C0: ("gate_outlined", "real"), 0x55FEDB0: ("user_stage_helper", "real"),
    CLASS_GETTER: ("class_getter", "real"), BTREE_SEARCH: ("listed_btree_search", "real"),
    HASH: ("hash_stub", "stub"), FIND_ROW: ("row_find_stub", "stub"), FIND_SECOND: ("second_find_stub", "stub"), USER_GET: ("user_get_stub", "stub"),
}
STATE = {}
MUTANT_CASES = 24
WORKERS = 4


def run_case(gate, entry, world, table, flaw=None):
    if entry == BTREE_SEARCH:
        return gate.run_search(world), spec_search(world)
    try:
        got = gate.run(world, entry)
    except Panicked:
        got = ("panic", tuple(gate.log), gate.compares)
    return got, spec_gate(entry, world, table)


def case_label(got):
    if got[0] == "btree":
        return "found" if got[3] == 0 else "absent"
    return "panic" if got[0] == "panic" else "%#x" % struct.unpack_from("<H", got[0])[0]


def class_sweep(gate, table):
    """The class getter on every raw word of the table plus the niche and the words around its edges."""
    got = []
    words = list(range(0, RAW_BASE + CLASS_COUNT + 4))
    for word in words:
        value = gate.run_class(word)
        if word < RAW_BASE + CLASS_COUNT:
            if value != spec_class(word, table):
                raise EvidenceError("class getter word %#x: %d" % (word, value))
        got.append((word, value))
    return got


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


def spread(items, count):
    if len(items) <= count:
        return items
    step = len(items) / count
    return [items[int(index * step)] for index in range(count)]


def round_robin(by_kind):
    """Picked case ids for one site: the (group, class, result) shapes that reach it take turns."""
    queues = [list(by_kind[kind]) for kind in sorted(by_kind)]
    picked = []
    while queues and len(picked) < MUTANT_CASES:
        for queue in list(queues):
            picked.append(queue.pop(0))
            if not queue:
                queues.remove(queue)
            if len(picked) == MUTANT_CASES:
                break
    return picked


def mutant_task(job):
    va, kind, patch = job
    state = STATE
    picked = state["reach"].get(va, [])
    gate = Gate(state["image"], patch, state["cache"])
    gate.machine.step_limit = 60000
    for index in picked:
        case_kind, entry, world = state["cases"][index]
        try:
            got, want = run_case(gate, entry, world, state["table"])
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, struct.error, TypeError):
            return va, kind, "killed", "%s:%d" % (case_kind, index)
        if got != want:
            return va, kind, "killed", "%s:%d" % (case_kind, index)
    return va, kind, "survived", "equal on %d picked cases" % len(picked)


def flawed_gate(entry, world, table, flaw):
    """The rule list with one deliberate mistake; it must disagree with the bytes somewhere."""
    word = world["tag"]
    signer = world["signer"]
    kind = spec_class(word, table)
    good = spec_gate(entry, world, table)
    if good[0] == "panic":
        return good
    out, log, compares = good
    status = struct.unpack_from("<H", out)[0]
    mutable = bytearray(out)
    if flaw == "not_validator_status" and status == STATUS_NOT_VALIDATOR:
        mutable[0:2] = struct.pack("<H", 0x7E)
    elif flaw == "refused_status" and status == STATUS_REFUSED:
        mutable[0:2] = struct.pack("<H", 0x82)
    elif flaw == "unknown_user_status" and status == STATUS_UNKNOWN_USER:
        mutable[0:2] = struct.pack("<H", 0x5A)
    elif flaw == "ok_status" and status == STATUS_OK:
        mutable[0:2] = struct.pack("<H", 0x1A3)
    elif flaw == "class0_listed" and kind == 0 and status == STATUS_NOT_VALIDATOR:
        name = "chain3" if world["chain"] == 3 else "other"
        if signer in world["locks"][name][1]:
            mutable[0:2] = struct.pack("<H", STATUS_OK)
            mutable[2:22] = signer
    elif flaw == "class1_no_listed" and kind == 1 and status == STATUS_OK and signer not in world["validators"]:
        mutable[0:2] = struct.pack("<H", STATUS_NOT_VALIDATOR)
    elif flaw == "chain_swapped" and kind == 1 and signer not in world["validators"] and entry == entry:
        name = "other" if world["chain"] == 3 else "chain3"
        found = signer in world["locks"][name][1]
        mutable[0:2] = struct.pack("<H", STATUS_OK if found else STATUS_NOT_VALIDATOR)
        if found:
            mutable[2:22] = signer
    elif flaw == "payload_zero" and status == STATUS_OK:
        mutable[2:22] = bytes(20)
    elif flaw == "niche_class_two" and word < RAW_BASE:
        return spec_gate(entry, dict(world, tag=RAW_BASE + 1), table)
    elif flaw == "once_unlogged":
        log = tuple(item for item in log if item[0] != "once")
    elif flaw == "validator_unlogged":
        log = tuple(item for item in log if item[0] != "validator")
    elif flaw == "compare_count" and compares:
        compares += 1
    elif flaw == "second_map_skipped" and entry == GATES[0] and kind == 3 and status == STATUS_OK and not world["users"]:
        if not any(length and (signer in members or key == signer) for length, members, key in world["rows"]):
            mutable[0:2] = struct.pack("<H", STATUS_UNKNOWN_USER)
    elif flaw == "helper_tail_dropped" and entry != GATES[0] and kind == 3 and status == STATUS_UNKNOWN_USER:
        mutable[22:0x70] = bytes([OUT_FILL]) * (0x70 - 22)
    elif flaw == "raw_threshold" and word == RAW_BASE - 1:
        return spec_gate(entry, dict(world, tag=RAW_BASE + 0), table)
    return bytes(mutable), log, compares


MODEL_FLAWS = ("not_validator_status", "refused_status", "unknown_user_status", "ok_status", "class0_listed", "class1_no_listed",
               "chain_swapped", "payload_zero", "niche_class_two", "once_unlogged", "validator_unlogged", "compare_count",
               "second_map_skipped", "helper_tail_dropped", "raw_threshold")


def damage_task(index):
    table = list(STATE["table"])
    table[index] = (table[index] + 1) % 5
    swept = STATE["sweep"]
    for word, value in swept:
        if word < RAW_BASE + CLASS_COUNT and value != spec_class(word, table):
            return index, True, "word %#x" % word
    return index, False, ""


def range_controls(image):
    """Inputs outside the claimed domain; each must be refused or contradicted."""
    rows = []

    def attempt(name, action):
        try:
            action()
        except (EvidenceError, Halt, Panicked, IndexError, KeyError, ValueError, struct.error):
            rows.append((name, True))
        else:
            rows.append((name, False))
    attempt("digest of the wrong file", lambda: load_image(BINARY, "0" * 64))
    attempt("address inside a function, not an FDE start", lambda: image.exact_fde(GATES[0] + 1))
    attempt("address outside every FDE", lambda: image.fde(0x100))
    attempt("address outside every file-backed section", lambda: image.offset(0x10))
    gate = Gate(image)
    attempt("class word far beyond the table", lambda: gate.run_class(0x7000000000000000))

    def far_tag():
        world = blank_world(RAW_BASE + 90000, sig(1))
        got, want = run_case(gate, GATES[0], world, [0] * 5000)
        if got != want:
            raise EvidenceError("table too short")
    attempt("rule list asked for a tag past its table", far_tag)
    attempt("class byte past the jump table", lambda: spec_gate(GATES[0], blank_world(RAW_BASE, sig(1)), [9] * CLASS_COUNT))
    return rows



# ---------------------------------------------------------------------------------------------
# Analysis and files
# ---------------------------------------------------------------------------------------------

SAMPLE_EVERY = 7


def read_table(image):
    start = image.offset(CLASS_TABLE)
    table = list(image.blob[start:start + CLASS_COUNT])
    if max(table) > 4:
        raise EvidenceError("class table byte above 4")
    return table


def read_listed(image):
    rows = []
    for at in OTHER_LISTED_AT:
        start = image.offset(at)
        rows.append(bytes(image.blob[start:start + 20]))
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
    table = read_table(image)
    listed = read_listed(image)
    cases = list(all_cases(table, listed))
    STATE.update(image=image, table=table, cases=cases)
    result = dict(table=table, listed=listed, case_count=len(cases))
    scenarios, reached, groups = [], set(), collections.Counter()
    gate = Gate(image)
    sweep = class_sweep(gate, table)
    result["sweep"] = sweep
    STATE["sweep"] = sweep
    seen_count, kept = collections.Counter(), collections.defaultdict(lambda: collections.defaultdict(list))
    for index, (kind, entry, world) in enumerate(cases):
        gate.machine.seen = set()
        before = gate.machine.steps
        got, want = run_case(gate, entry, world, table)
        if got != want:
            raise EvidenceError("case %d (%s): %r against %r" % (index, kind, got, want))
        label = case_label(got)
        groups[(kind, label)] += 1
        shape = (kind, "-" if entry == BTREE_SEARCH else spec_class(world["tag"], table), label)
        for va in gate.machine.seen:
            seen_count[(va, shape)] += 1
            if seen_count[(va, shape)] <= 1:
                kept[va][shape].append(index)
        reached |= gate.machine.seen
        if index % SAMPLE_EVERY == 0:
            if entry == BTREE_SEARCH:
                scenarios.append((index, kind, "listed_btree_search", "keys %d" % len(world["keys"]), "-", "-", label, 0, got[2]))
            else:
                scenarios.append((index, kind, GATE_NAMES[entry], "%#x" % world["tag"], spec_class(world["tag"], table), world["chain"], label, len(got[1]), got[2]))
    result["scenarios"], result["groups"] = scenarios, groups
    STATE["reach"] = {va: round_robin(by_kind) for va, by_kind in kept.items()}
    STATE["cache"] = gate.machine.cache
    result["reached"] = reached
    result["table_rows"] = function_rows(image, reached)
    edit_jobs = []
    for target, rows in sorted(result["table_rows"].items()):
        edit_jobs += edits_for(image, rows)
    with multiprocessing.get_context("fork").Pool(workers) as pool:
        mutants = pool.map(mutant_task, edit_jobs, 4)
        damage = pool.map(damage_task, range(CLASS_COUNT))
    flaw_rows = []
    for flaw in MODEL_FLAWS:
        detected, where = False, ""
        for index, (kind, entry, world) in enumerate(cases):
            if entry == BTREE_SEARCH:
                continue
            if flawed_gate(entry, world, table, flaw) != spec_gate(entry, world, table):
                detected, where = True, "%s:%d" % (kind, index)
                break
        flaw_rows.append((flaw, detected, where))
    result["mutants"], result["damage"], result["flaws"] = mutants, damage, flaw_rows
    result["ranges"] = range_controls(image)
    result["edit_count"] = len(edit_jobs)
    return result


def render(result, image):
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]) + "\n"

    table = result["table"]
    tsv("class-table.tsv", ("index", "raw_word", "class", "rule"),
        [("niche", "<%#x" % RAW_BASE, table[RAW_NICHE_INDEX], RULES[table[RAW_NICHE_INDEX]])] +
        [(index, "%#x" % (RAW_BASE + index), value, RULES[value]) for index, value in enumerate(table)])
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
    tsv("listed.tsv", ("slot", "address", "bytes", "meaning"),
        [(index, "%#x" % at, key.hex(), "other-chain listed address %d, 20 bytes in .rodata" % index) for index, (at, key) in enumerate(zip(OTHER_LISTED_AT, result["listed"]))])
    tsv("scenarios.tsv", ("case", "group", "gate", "word", "class", "chain", "result", "stub_calls", "key_compares"), result["scenarios"])
    tsv("class-sweep.tsv", ("word", "class_byte"), result["sweep"])
    tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutants"]])
    controls = []
    for index, detected, where in result["damage"]:
        controls.append(("table_byte_damaged", "index %d" % index, detected, where))
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
    groups = result["groups"]
    summary = {
        "binary": "artifacts/node/115/hl-node", "sha256": SHA256,
        "functions_real": sum(1 for v in SCOPE.values() if v[1] == "real"), "functions_stubbed": sum(1 for v in SCOPE.values() if v[1] == "stub"),
        "cases": result["case_count"], "class_sweep_words": len(result["sweep"]),
        "case_groups": {"%s/%s" % key: count for key, count in sorted(groups.items())},
        "instructions_reached": sum(len(rows) for rows in reached_rows.values()),
        "byte_edits_possible": result["edit_count"], "byte_edits_killed": sum(1 for item in result["mutants"] if item[2] == "killed"), "byte_edits_survived": len(survivors),
        "controls": len(controls), "controls_detected": detected,
    }
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps({"cases": result["case_count"] + len(result["sweep"]), "negative_controls": len(controls), "negative_detected": detected,
                                        "byte_edits_survived": len(survivors)}, indent=1, sort_keys=True) + "\n"
    return files


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
