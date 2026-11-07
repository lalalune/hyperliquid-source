#!/usr/bin/env python3
"""Reconstruct the node #115 validator snapshot lookup: epoch match in a ring or B-tree store, then the signer address scan.

The lookup 0x36c8430, the ring epoch search 0x4551810 and the B-tree iterator step 0x37c5530 run as real bytes in an interpreter inside
this tool. The status drop 0x36dae30 is a recording stub. A separately written rule list predicts the result byte and every status
drop. No disassembler output is parsed and the binary is never executed. Standard library only.

    python3 tools/staking_validator_snapshot115.py --out <dir>
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
# Node #115 validator snapshot lookup: fixture, rule list, cases, byte edits.
# ---------------------------------------------------------------------------------------------

VALIDATOR = 0x36C8430
DEQUE_SEARCH = 0x4551810
ITER_NEXT = 0x37C5530
STATUS_DROP = 0x36DAE30
PANIC_SLOTS = (0x64DF620, 0x64DF4C0, 0x64DF830)
FREE_SLOT = 0x64DF4A0
DROP_TABLES = ((0x79B9C0, 0x3D, 0x9B), (0x79BC30, 0xF0, 0x19))
DROP_LADDER = {0x160: 0x36DAFCC, 0x16F: 0x36DAF09, 0x17D: 0x36DAF09, 0x188: 0x36DAEF5}
DROP_EXIT = 0x36DAFEA
STATUS_AT = HEAP_BASE + 0x3500
OWNED_AT = HEAP_BASE + 0x100000
NICHE = 1 << 63
S_AT = HEAP_BASE + 0x3000
SIGNER_AT = HEAP_BASE + 0x3200
EPOCH_AT = HEAP_BASE + 0x3300
ITER_AT = HEAP_BASE + 0x3400
ARENA_AT = HEAP_BASE + 0x30000
ARENA_END_AT = HEAP_BASE + 0x3F0000
HEAP_USED = 0x3F0000
STATUS_NO_SNAPSHOT = 0x9B
STATUS_NOT_MEMBER = 0x2B
INNER = dict(ksz=32, vsz=0x48, koff=0, voff=0x168, parent=0x160, pidx=0x480, length=0x482, edges=0x488, leaf=0x488, internal=0x4E8)
OUTER = dict(ksz=8, vsz=0x30, koff=0x218, voff=0, parent=0x210, pidx=0x270, length=0x272, edges=0x278, leaf=0x278, internal=0x2D8)
VEC_ELEMENT = 0x68
VEC_ADDRESS_AT = 0x40
TREE_ADDRESS_AT = 0x20
RING_ELEMENT = 0x38
FILL = 0xA5


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
    return bytes([0x30 + (seed * 7 & 0x3F)]) + bytes(15) +bytes([seed >> 8 & 255, seed & 255, (seed * 5 + 1) & 255, seed % 251 + 1])


class Watch:
    """Every code address runs for real; entering the status drop is reported to a callback."""

    def __init__(self, low, high, enter):
        self.low, self.high, self.enter = low, high, enter

    def __contains__(self, va):
        if va == STATUS_DROP:
            self.enter()
        return self.low <= va < self.high


class Lookup:
    """Machine plus the fixture of one lookup; the status drop is a recording stub, everything else runs as bytes."""

    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = self.machine = Machine(image, patches)
        text = image.named[".text"]
        machine.real = Watch(text["address"], text["address"] + text["size"], self.on_drop)
        machine.step_limit = 600000
        machine.memory.statics = dict(image.relative())
        fake = MARK_BASE + FREE_SLOT
        machine.memory.statics[FREE_SLOT] = fake
        machine.slots[fake] = self.on_free
        for slot in PANIC_SLOTS:
            fake = MARK_BASE + slot
            machine.memory.statics[slot] = fake
            machine.slots[fake] = self.on_panic
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.log, self.top, self.stream, self.info = [], ARENA_AT, Stream(5), None

    def on_panic(self, machine):
        raise Panicked("panic path reached")

    def on_free(self, machine):
        self.log.append(("free", machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]))

    def on_drop(self):
        machine = self.machine
        word = self.read(machine.regs[RDI], 2)
        if word == STATUS_NO_SNAPSHOT:
            self.log.append(("drop", word, self.read(machine.regs[RDI] + 8)))
        else:
            self.log.append(("drop", word))

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

    # ---- fixtures ---------------------------------------------------------------------------
    def build_tree(self, entries, geom, height=None):
        """B-tree of (key bytes, value bytes) pairs in the node layout `geom`; returns (root, height)."""
        count = len(entries)
        if count == 0:
            return 0, 0
        height = tree_height(count) if height is None else height

        def node(items, level):
            at = self.alloc(geom["leaf"] if level == 0 else geom["internal"])
            self.put(at + geom["koff"], bytes(geom["ksz"] * 11))
            if level == 0:
                chosen = items
                kids = []
            else:
                smallest = max(2, -(-(len(items) + 1) // (capacity(level - 1) + 1)))
                largest = min(12, (len(items) + 1) // (minimum(level - 1) + 1))
                fan = smallest + self.stream.next(largest - smallest + 1)
                room = len(items) - (fan - 1)
                sizes = [room // fan + (1 if index < room % fan else 0) for index in range(fan)]
                chosen, kids, cursor = [], [], 0
                for index, size in enumerate(sizes):
                    kids.append(node(items[cursor:cursor + size], level - 1))
                    cursor += size
                    if index < fan - 1:
                        chosen.append(items[cursor])
                        cursor += 1
            for index, (key, value) in enumerate(chosen):
                self.put(at + geom["koff"] + geom["ksz"] * index, key)
                self.put(at + geom["voff"] + geom["vsz"] * index, value)
            self.write(at + geom["length"], len(chosen), 2)
            for index, kid in enumerate(kids):
                self.write(at + geom["edges"] + 8 * index, kid)
                self.write(kid + geom["parent"], at)
                self.write(kid + geom["pidx"], index, 2)
            return at
        return node(entries, height), height

    def build_ring(self, elements, size, head, spare):
        """Ring buffer of equal sized elements starting at physical slot `head`; returns (cap, buf, head, len)."""
        count = len(elements)
        cap = count + spare
        buf = self.alloc(max(1, cap) * size)
        for index, element in enumerate(elements):
            self.put(buf + ((head + index) % cap) * size, element)
        return cap, buf, (head % cap if cap else 0), count

    def vec_value(self, snap):
        addrs = snap["addrs"]
        elements = [bytes([0x11 + n % 7]) * VEC_ADDRESS_AT + a + bytes([0x22]) * (VEC_ELEMENT - VEC_ADDRESS_AT - 20) for n, a in enumerate(addrs)]
        cap, buf, head, length = self.build_ring(elements, VEC_ELEMENT, snap["head"], snap["spare"])
        if cap == 0:
            cap = snap["spare"] or 0
        return struct.pack("<QQQQQQ", cap, buf, head, length, FILL * 0x0101010101010101, FILL * 0x0101010101010101)

    def tree_value(self, snap):
        addrs = snap["addrs"]
        entries = []
        for n, a in enumerate(addrs):
            key = (n + 1).to_bytes(4, "big") + bytes([0x44]) * 28
            value = bytes([0x55 + n % 3]) * TREE_ADDRESS_AT + a + bytes([0x66]) * (0x48 - TREE_ADDRESS_AT - 20)
            entries.append((key, value))
        root, height = self.build_tree(entries, INNER)
        return struct.pack("<QQQQQQ", NICHE, root, height, len(addrs), FILL * 0x0101010101010101, FILL * 0x0101010101010101)

    def snapshot_value(self, snap):
        return self.vec_value(snap) if snap["kind"] == "vec" else self.tree_value(snap)

    def prepare(self, world):
        machine = self.machine
        machine.memory.reset(HEAP_USED)
        self.log, self.top, self.stream = [], ARENA_AT, Stream(world["shape"])
        self.put(S_AT, bytes([FILL]) * 0x100)
        snaps = world["snaps"]
        values = [(struct.pack("<Q", snap["epoch"]), self.snapshot_value(snap)) for snap in snaps]
        if world["outer"] == "tree":
            root, height = self.build_tree([(k, v) for k, v in values], OUTER)
            self.write(S_AT, NICHE)
            self.write(S_AT + 8, root)
            self.write(S_AT + 0x10, height)
            self.write(S_AT + 0x18, len(snaps))
        else:
            elements = [k + v for k, v in values]
            cap, buf, head, length = self.build_ring(elements, RING_ELEMENT, world["head"], world["spare"])
            for offset, value in zip((0, 8, 0x10, 0x18), (cap, buf, head, length)):
                self.write(S_AT + offset, value)
        self.write(S_AT + 0x58, world["epoch"])
        self.put(SIGNER_AT, world["signer"])
        self.put(EPOCH_AT, struct.pack("<Q", world["epoch"]))
        return self.data(S_AT, 0x100)

    def run(self, world):
        before = self.prepare(world)
        got = self.machine.run(VALIDATOR, {RDI: S_AT, RSI: SIGNER_AT}) & 0xFF
        if self.data(S_AT, 0x100) != before:
            raise Halt("the lookup wrote into its argument")
        return got, tuple(self.log)

    def run_search(self, world):
        """The ring binary search called directly; returns (rax, rdx)."""
        self.prepare(dict(world, outer="ring"))
        got = self.machine.run(DEQUE_SEARCH, {RDI: S_AT, RSI: EPOCH_AT})
        return ("search", got, self.machine.regs[RDX])

    def run_status(self, word, mode):
        """The status drop called directly on a record of this word; returns whether the arm of the jump tables was entered."""
        machine = self.machine
        machine.memory.reset(HEAP_USED)
        self.log = []
        self.put(OWNED_AT, struct.pack("<Q", OWNED_AT + 0x800) * 0x100)
        owned = struct.pack("<Q", OWNED_AT + 0x800)
        if mode == "zero":
            payload = bytes(0x30)
        elif mode == "owned":
            payload = owned * 6
        else:
            tag = int(mode[1:])
            payload = struct.pack("<QQ", tag, tag * 3 + 1) + owned * 4
        self.put(STATUS_AT, struct.pack("<Q", word) + payload)
        machine.seen = set()
        machine.step_limit = 30000
        try:
            machine.run(STATUS_DROP, {RDI: STATUS_AT})
            outcome = "returned"
        except Panicked:
            outcome = "panic"
        except Halt as error:
            outcome = "halt"
            if str(error).startswith("fixture") or "unmodelled" in str(error):
                raise
        self.info = (outcome, tuple(self.log))
        return ("status", drop_arm(self.image, word) in machine.seen)

    def check_tree(self, root, height, geom, keys):
        """Walk a fixture B-tree through its own fields: lengths, parent and parent-index words must agree; returns the in-order keys."""
        out = []

        def walk(node, level, parent, index):
            if parent is not None and (self.read(node + geom["parent"]) != parent or self.read(node + geom["pidx"], 2) != index):
                raise EvidenceError("parent link of node %#x" % node)
            length = self.read(node + geom["length"], 2)
            if length > 11 or (level and length == 0):
                raise EvidenceError("node length %d" % length)
            for slot in range(length + 1 if level else length):
                if level:
                    walk(self.read(node + geom["edges"] + 8 * slot), level - 1, node, slot)
                if slot < length:
                    out.append(self.data(node + geom["koff"] + geom["ksz"] * slot, geom["ksz"]))
        if root:
            walk(root, height, None, 0)
        if out != list(keys):
            raise EvidenceError("tree keys are not the sorted input")
        return out

    def run_iter(self, world):
        """The B-tree iterator called len+1 times; returns the key and value bytes it yields."""
        machine = self.machine
        machine.memory.reset(HEAP_USED)
        self.top, self.log, self.stream = ARENA_AT, [], Stream(world["shape"])
        entries = world["entries"]
        root, height = self.build_tree(entries, INNER, world.get("height"))
        self.check_tree(root, height, INNER, [key for key, _ in entries])
        tag = 1 if root else 0
        state = struct.pack("<QQQQQQQQQ", tag, 0, root, height, tag, 0, root, height, len(entries))
        self.put(ITER_AT, state)
        out = []
        for _ in range(len(entries) + 1 + world.get("extra", 0)):
            got = machine.run(ITER_NEXT, {RDI: ITER_AT})
            if got == 0:
                out.append(None)
                continue
            out.append((self.data(got, 32), self.data(machine.regs[RDX], 0x48)))
        return ("iter", tuple(out), self.read(ITER_AT + 0x40))


# ---------------------------------------------------------------------------------------------
# The separately written rule list.
# ---------------------------------------------------------------------------------------------

def spec_lookup(world):
    """Returns (result byte, ordered drop log): the epoch must match a snapshot exactly and the signer must be in it."""
    snap = next((s for s in world["snaps"] if s["epoch"] == world["epoch"]), None)
    if snap is None:
        return 0, (("drop", STATUS_NO_SNAPSHOT, 0),)
    if world["signer"] in snap["addrs"]:
        return 1, ()
    return 0, (("drop", STATUS_NOT_MEMBER),)


def spec_search(world):
    epochs = [s["epoch"] for s in world["snaps"]]
    target = world["epoch"]
    if target in epochs:
        return ("search", 0, epochs.index(target))
    return ("search", 1, sum(1 for e in epochs if e < target))


def drop_arm(image, word):
    """Entry of the arm the status drop must take for this word, from the jump tables and compare ladder read as bytes."""
    if word <= 0xEF:
        table, bias, top = DROP_TABLES[0]
    elif word <= 0x15F:
        table, bias, top = DROP_TABLES[1]
    elif word in DROP_LADDER:
        return DROP_LADDER[word]
    else:
        return DROP_EXIT
    index = word - bias
    if not 0 <= index <= top:
        return DROP_EXIT
    return table + struct.unpack_from("<i", image.blob, image.offset(table + 4 * index))[0]


def spec_status(world):
    return ("status", True)


def spec_iter(world):
    entries = world["entries"]
    rows = tuple(entries) + (None,) * (1 + world.get("extra", 0))
    return ("iter", rows, 0)


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


STATUS_MODES = ("zero", "owned", "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7")
COUNTS = (0, 1, 2, 3, 5, 11, 12, 13, 24, 60)
TREE_COUNTS = (0, 1, 3, 10, 11, 12, 20, 40, 143, 144, 200)
SNAP_COUNTS = (0, 1, 2, 3, 6, 11, 12, 25, 60)


def make_snaps(stream, count, kinds, serial, tree_sizes):
    snaps, epoch = [], (1 << 40 if serial % 3 == 0 else 100) + stream.next(50)
    for index in range(count):
        epoch += 1 + stream.next(9)
        kind = kinds[stream.next(len(kinds))]
        size = tree_sizes[stream.next(len(tree_sizes))] if kind == "tree" else COUNTS[stream.next(len(COUNTS))]
        base = serial * 1000 + index * 300
        snaps.append(dict(epoch=epoch, kind=kind, head=stream.next(7), spare=stream.next(4),
                          addrs=tuple(address(base + n) for n in range(size))))
    return snaps


def lookup_world(shape, outer, snap_count, kinds, tree_sizes, target, probe):
    stream = Stream(shape)
    snaps = make_snaps(stream, snap_count, kinds, shape, tree_sizes)
    if snaps:
        pick = {"first": 0, "middle": len(snaps) // 2, "last": len(snaps) - 1}.get(target, 0)
        epoch = snaps[pick]["epoch"]
    else:
        epoch = 150
    if target == "below":
        epoch = snaps[0]["epoch"] - 1 if snaps else 99
    elif target == "above":
        epoch = snaps[-1]["epoch"] + 1 if snaps else 9999
    elif target == "between" and len(snaps) > 1:
        epoch = snaps[0]["epoch"] + 1 if snaps[1]["epoch"] - snaps[0]["epoch"] > 1 else snaps[0]["epoch"] + 0
    elif target == "far":
        epoch = (1 << 63) + 5
    elif target == "alias":
        epoch = (snaps[0]["epoch"] + (1 << 32)) if snaps else (1 << 32)
    snap = next((s for s in snaps if s["epoch"] == epoch), None)
    members = list(snap["addrs"]) if snap else []
    others = [a for s in snaps if s is not snap for a in s["addrs"]]
    if probe == "first" and members:
        signer = members[0]
    elif probe == "middle" and members:
        signer = members[len(members) // 2]
    elif probe == "last" and members:
        signer = members[-1]
    elif probe == "other" and others:
        signer = others[stream.next(len(others))]
    elif probe.startswith("near") and members:
        signer = bytearray(members[stream.next(len(members))])
        signer[{"near_first": 0, "near_mid": 15, "near_dword": 16, "near_last": 19}[probe]] ^= 1
        signer = bytes(signer)
    else:
        signer = address(60000 + shape)
    return dict(shape=shape, outer=outer, snaps=snaps, epoch=epoch, signer=signer, head=stream.next(5), spare=stream.next(4),
                target=target, probe=probe, kinds="".join(kind[0] for kind in kinds))


def swapped(world):
    """The same logical world in the other store forms: ring <-> tree outside, vec <-> tree inside. Membership must not change."""
    snaps = [dict(snap, kind="tree" if snap["kind"] == "vec" else "vec") for snap in world["snaps"]]
    return dict(world, outer="tree" if world["outer"] == "ring" else "ring", snaps=snaps,
                kinds="".join("t" if kind == "v" else "v" for kind in world["kinds"]))


def ring_flags(world):
    """0 = no wrap, 1 = wrapped ring and the epoch falls in the first slice, 2 = in the second slice."""
    count = len(world["snaps"])
    cap = count + world["spare"]
    if not cap:
        return 0
    head = world["head"] % cap
    if head + count <= cap:
        return 0
    epochs = [s["epoch"] for s in world["snaps"]]
    place = sum(1 for e in epochs if e < world["epoch"])
    return 2 if place >= cap - head else 1


TARGETS = ("first", "middle", "last", "below", "between", "above", "alias")
PROBES = ("first", "middle", "last", "other", "absent", "near_first", "near_mid", "near_dword", "near_last")


def all_cases(per_group=1):
    serial = 0
    for outer in ("ring", "tree"):
        for snap_count in SNAP_COUNTS:
            for kinds in (("vec",), ("tree",), ("vec", "tree")):
                for target in TARGETS:
                    for probe in PROBES:
                        for repeat in range(per_group):
                            serial += 1
                            sizes = TREE_COUNTS if snap_count <= 12 else (0, 1, 11, 12, 20)
                            yield ("lookup", VALIDATOR, lookup_world(serial, outer, snap_count, kinds, sizes, target, probe))
    for serial in range(1, 1 + 900):
        stream = Stream(serial + 7000)
        count = SNAP_COUNTS[stream.next(len(SNAP_COUNTS))]
        world = lookup_world(serial + 7000, "ring", count, ("vec", "tree"), (0, 2, 12), "middle", "absent")
        if world["snaps"]:
            epochs = [s["epoch"] for s in world["snaps"]]
            world["epoch"] = epochs[stream.next(len(epochs))] + stream.next(2)
        yield ("ring_search", DEQUE_SEARCH, world)
    for serial in range(1, 1 + 4000):
        stream = Stream(serial + 30000)
        count = SNAP_COUNTS[stream.next(len(SNAP_COUNTS))]
        base = lookup_world(serial + 30000, ("ring", "tree")[stream.next(2)], count, ("vec", "tree"), (0, 1, 12, 20),
                            TARGETS[stream.next(len(TARGETS))], PROBES[stream.next(len(PROBES))])
        yield ("form_pair", VALIDATOR, base)
        yield ("form_pair", VALIDATOR, swapped(base))
    exhaustive = 0
    for count in range(1, 8):
        for spare in range(0, 3):
            for head in range(0, count + spare):
                for pick in range(0, 2 * count + 1):
                    exhaustive += 1
                    base = lookup_world(40000 + exhaustive, "ring", count, ("vec",), (0,), "first", "absent")
                    for index, snap in enumerate(base["snaps"]):
                        snap["epoch"] = 10 + 2 * index
                    base["epoch"] = 9 + pick
                    base["head"], base["spare"] = head, spare
                    yield ("ring_exhaustive", DEQUE_SEARCH, base)
    for word in range(0, 0x200):
        for mode in STATUS_MODES:
            yield ("status_drop", STATUS_DROP, dict(word=word, mode=mode))
    for level in range(2, 10):
        for extra in (0, 7, 90):
            serial = level * 10 + extra
            size = minimum(level) + extra
            entries = [((n + 1).to_bytes(4, "big") + bytes([0x78]) * 28, bytes([0x41 + n % 5]) * 0x20 + address(serial * 900 + n) + bytes([0x32]) * 0x14) for n in range(size)]
            yield ("tree_deep", ITER_NEXT, dict(shape=serial + 12000, entries=tuple(entries), extra=0, height=level))
    for serial in range(1, 1 + 700):
        stream = Stream(serial + 9000)
        size = (0, 1, 2, 10, 11, 12, 13, 22, 23, 24, 60, 143, 144, 145, 300, 600)[stream.next(16)]
        entries = [((n + 1).to_bytes(4, "big") + bytes([0x77]) * 28, bytes([0x40 + n % 5]) * 0x20 + address(serial * 700 + n) + bytes([0x31]) * 0x14) for n in range(size)]
        yield ("tree_iter", ITER_NEXT, dict(shape=serial + 9000, entries=tuple(entries), extra=stream.next(2)))


# ---------------------------------------------------------------------------------------------
# Runner, byte edits and controls
# ---------------------------------------------------------------------------------------------

SCOPE = {
    VALIDATOR: ("validator_snapshot_lookup", "real"), DEQUE_SEARCH: ("ring_epoch_search", "real"),
    ITER_NEXT: ("btree_iter_next", "real"), STATUS_DROP: ("status_drop", "real"),
}
STATE = {}
MUTANT_CASES = 64
WORKERS = 4
SAMPLE_EVERY = 7


def run_case(lookup, entry, world):
    if entry == DEQUE_SEARCH:
        return lookup.run_search(world), spec_search(world)
    if entry == ITER_NEXT:
        return lookup.run_iter(world), spec_iter(world)
    if entry == STATUS_DROP:
        return lookup.run_status(world["word"], world["mode"]), spec_status(world)
    try:
        got = lookup.run(world)
    except Panicked:
        got = ("panic",)
    return got, spec_lookup(world)


def case_label(entry, got):
    if entry == DEQUE_SEARCH:
        return "found" if got[1] == 0 else "absent"
    if entry == ITER_NEXT:
        return "n%d" % min(len(got[1]) - 1, 3)
    if entry == STATUS_DROP:
        return "arm"
    if got[0] == "panic":
        return "panic"
    return "member" if got[0] == 1 else "status %#x" % got[1][0][1]


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


def mutant_task(job):
    va, kind, patch = job
    state = STATE
    picked = state["reach"].get(va, [])
    lookup = Lookup(state["image"], patch, state["cache"])
    lookup.machine.step_limit = 80000
    for index in picked:
        case_kind, entry, world = state["cases"][index]
        try:
            got, want = run_case(lookup, entry, world)
            if entry == STATUS_DROP and lookup.info != state["baseline"][index]:
                return va, kind, "killed", "%s:%d" % (case_kind, index)
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, struct.error, TypeError):
            return va, kind, "killed", "%s:%d" % (case_kind, index)
        if got != want:
            return va, kind, "killed", "%s:%d" % (case_kind, index)
    return va, kind, "survived", "equal on %d picked cases" % len(picked)


def flawed_lookup(world, flaw):
    """The rule list with one deliberate mistake; it must disagree with the bytes somewhere."""
    snaps = world["snaps"]
    epoch, signer = world["epoch"], world["signer"]
    good = spec_lookup(world)
    if flaw == "nearest_lower_epoch":
        lower = [s for s in snaps if s["epoch"] <= epoch]
        snap = lower[-1] if lower else None
        if snap is None:
            return 0, (("drop", STATUS_NO_SNAPSHOT, 0),)
        return (1, ()) if signer in snap["addrs"] else (0, (("drop", STATUS_NOT_MEMBER),))
    if flaw == "any_snapshot":
        if any(signer in s["addrs"] for s in snaps):
            return 1, ()
        return good
    if flaw == "first_16_bytes_only":
        snap = next((s for s in snaps if s["epoch"] == epoch), None)
        if snap and any(a[:16] == signer[:16] for a in snap["addrs"]):
            return 1, ()
        return good
    if flaw == "last_16_bytes_only":
        snap = next((s for s in snaps if s["epoch"] == epoch), None)
        if snap and any(a[4:] == signer[4:] for a in snap["addrs"]):
            return 1, ()
        return good
    if flaw == "swapped_status_codes":
        return good[0], tuple(("drop", 0x9B if item[1] == 0x2B else 0x2B) + item[2:3] if False else ("drop", 0x9B if item[1] == 0x2B else 0x2B) for item in good[1])
    if flaw == "no_snapshot_as_not_member":
        if good[1] and good[1][0][1] == STATUS_NO_SNAPSHOT:
            return 0, (("drop", STATUS_NOT_MEMBER),)
        return good
    if flaw == "no_drop_when_missing":
        return good[0], tuple(item for item in good[1] if item[1] != STATUS_NO_SNAPSHOT)
    if flaw == "no_drop_when_not_member":
        return good[0], tuple(item for item in good[1] if item[1] != STATUS_NOT_MEMBER)
    if flaw == "first_snapshot_only":
        if snaps and snaps[0]["epoch"] != epoch:
            return 0, (("drop", STATUS_NO_SNAPSHOT, 0),)
        return good
    if flaw == "epoch_low_32_bits":
        snap = next((s for s in snaps if s["epoch"] & MASK[4] == epoch & MASK[4]), None)
        if snap is None:
            return good
        return (1, ()) if signer in snap["addrs"] else (0, (("drop", STATUS_NOT_MEMBER),))
    if flaw == "stop_at_first_ten":
        snap = next((s for s in snaps if s["epoch"] == epoch), None)
        if snap and signer in snap["addrs"] and snap["addrs"].index(signer) >= 10:
            return 0, (("drop", STATUS_NOT_MEMBER),)
        return good
    if flaw == "dword_ignored":
        snap = next((s for s in snaps if s["epoch"] == epoch), None)
        if snap and any(a[:16] == signer[:16] for a in snap["addrs"]):
            return 1, ()
        return good
    if flaw == "empty_snapshot_member":
        snap = next((s for s in snaps if s["epoch"] == epoch), None)
        if snap is not None and not snap["addrs"]:
            return 1, ()
        return good
    return good


MODEL_FLAWS = ("nearest_lower_epoch", "any_snapshot", "first_16_bytes_only", "last_16_bytes_only", "swapped_status_codes",
               "no_snapshot_as_not_member", "no_drop_when_missing", "no_drop_when_not_member", "first_snapshot_only",
               "epoch_low_32_bits", "stop_at_first_ten", "empty_snapshot_member")


def damaged_geometry(image):
    """Fixture geometries with one field moved; the real bytes must contradict each."""
    rows = []
    for name, geom in (("inner", INNER), ("outer", OUTER)):
        for field in ("length", "edges", "voff", "koff", "parent", "pidx"):
            if name == "outer" and field == "pidx":
                continue
            rows.append((name, field))
    return rows


def geometry_task(job):
    name, key = job
    field = key
    geom = INNER if name == "inner" else OUTER
    state = STATE
    saved = dict(geom)
    try:
        geom[key] = geom[key] + 8
        lookup = Lookup(state["image"])
        lookup.machine.step_limit = 80000
        for index in state["geometry_cases"]:
            case_kind, entry, world = state["cases"][index]
            try:
                got, want = run_case(lookup, entry, world)
            except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, struct.error, TypeError):
                return name, field, True
            if got != want:
                return name, field, True
        return name, field, False
    finally:
        geom.update(saved)


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
    attempt("address inside a function, not an FDE start", lambda: image.exact_fde(VALIDATOR + 1))
    attempt("address outside every FDE", lambda: image.fde(0x100))
    attempt("address outside every file-backed section", lambda: image.offset(0x10))
    lookup = Lookup(image)

    def wrong_tag():
        # an iterator whose front state is neither lazy nor positioned must panic
        lookup.machine.memory.reset(HEAP_USED)
        lookup.put(ITER_AT, struct.pack("<QQQQQQQQQ", 2, 0, 0, 0, 2, 0, 0, 0, 5))
        lookup.machine.run(ITER_NEXT, {RDI: ITER_AT})
    attempt("iterator with a front state of 2 and items left", wrong_tag)

    def fixture_overflow():
        world = lookup_world(3, "ring", 3, ("tree",), (143,), "first", "absent")
        old = globals()["ARENA_END_AT"]
        globals()["ARENA_END_AT"] = ARENA_AT + 0x100
        try:
            lookup.run(world)
        finally:
            globals()["ARENA_END_AT"] = old
    attempt("fixture arena too small", fixture_overflow)

    def stuck_step_limit():
        small = Lookup(image)
        small.machine.step_limit = 20
        small.run(lookup_world(5, "ring", 6, ("vec",), (3,), "last", "absent"))
    attempt("step limit of 20 instructions", stuck_step_limit)

    def mismatch_spec():
        world = lookup_world(9, "ring", 6, ("vec",), (3,), "last", "first")
        got, want = run_case(lookup, VALIDATOR, world)
        if got != spec_lookup(dict(world, signer=address(1))):
            raise EvidenceError("different signer gives a different result")
    attempt("rule list asked about a different signer", mismatch_spec)
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
    scenarios, reached, groups = [], set(), collections.Counter()
    lookup = Lookup(image)
    seen_count, kept = collections.Counter(), collections.defaultdict(lambda: collections.defaultdict(list))
    geometry_cases, status_rows, baseline = [], [], {}
    for index, (kind, entry, world) in enumerate(cases):
        lookup.machine.seen = set()
        got, want = run_case(lookup, entry, world)
        if got != want:
            raise EvidenceError("case %d (%s): %r against %r" % (index, kind, got, want))
        if entry == STATUS_DROP:
            baseline[index] = lookup.info
        label = case_label(entry, got)
        groups[(kind, label)] += 1
        shape = (kind, label)
        if kind == "lookup":
            shape = (kind, label, world["outer"], world["kinds"], world["target"])
        elif kind in ("ring_search", "ring_exhaustive"):
            shape = (kind, label, ring_flags(world))
        elif kind == "status_drop":
            shape = (kind, world["mode"], world["word"] // 16)
        elif kind == "tree_deep":
            shape = (kind, label, world["height"])
        for va in lookup.machine.seen:
            seen_count[(va, shape)] += 1
            if seen_count[(va, shape)] <= 3:
                kept[va][shape].append(index)
        reached |= lookup.machine.seen
        if kind == "status_drop" and world["mode"] in ("zero", "owned") and drop_arm(image, world["word"]) != DROP_EXIT:
            status_rows.append((world["word"], world["mode"], "%#x" % drop_arm(image, world["word"]), lookup.info[0],
                                ",".join("%#x" % item[2] for item in lookup.info[1] if item[0] == "free") or "-"))
        if (kind == "lookup" and index % 11 == 0 or kind == "tree_iter" and index % 29 == 0) and len(geometry_cases) < 400:
            geometry_cases.append(index)
        if index % SAMPLE_EVERY == 0:
            if kind in ("lookup", "form_pair"):
                scenarios.append((index, kind, world["outer"], len(world["snaps"]), "%#x" % world["epoch"], label, len(got[1]), lookup.machine.steps))
            elif kind in ("ring_search", "ring_exhaustive"):
                scenarios.append((index, kind, "ring", len(world["snaps"]), "%#x" % world["epoch"], label, 0, 0))
            elif kind == "status_drop":
                scenarios.append((index, kind, world["mode"], "%#x" % world["word"], "%#x" % drop_arm(image, world["word"]), lookup.info[0], len(lookup.info[1]), 0))
            else:
                scenarios.append((index, kind, "tree", len(world["entries"]), "-", label, 0, 0))
    result["scenarios"], result["groups"], result["status_rows"] = scenarios, groups, status_rows
    STATE["reach"] = {va: round_robin(by_kind) for va, by_kind in kept.items()}
    STATE["cache"] = lookup.machine.cache
    STATE["geometry_cases"] = geometry_cases
    STATE["baseline"] = baseline
    result["reached"] = reached
    result["table_rows"] = function_rows(image, reached)
    edit_jobs = []
    for target, rows in sorted(result["table_rows"].items()):
        edit_jobs += edits_for(image, rows)
    geometry_jobs = damaged_geometry(image)
    with multiprocessing.get_context("fork").Pool(workers) as pool:
        mutants = pool.map(mutant_task, edit_jobs, 4)
        geometry = pool.map(geometry_task, geometry_jobs)
    flaw_rows = []
    for flaw in MODEL_FLAWS:
        detected, where = False, ""
        for index, (kind, entry, world) in enumerate(cases):
            if kind != "lookup":
                continue
            if flawed_lookup(world, flaw) != spec_lookup(world):
                detected, where = True, "%s:%d" % (kind, index)
                break
        flaw_rows.append((flaw, detected, where))
    result["mutants"], result["geometry"], result["flaws"] = mutants, geometry, flaw_rows
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
    tsv("status-drop.tsv", ("word", "payload", "arm", "outcome", "free_sizes"), result["status_rows"])
    tsv("layouts.tsv", ("structure", "field", "offset", "meaning"), LAYOUT_ROWS)
    tsv("scenarios.tsv", ("case", "group", "outer", "count", "epoch", "result", "drops", "steps"), result["scenarios"])
    tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutants"]])
    controls = []
    for name, field, detected in result["geometry"]:
        controls.append(("layout_field_moved", "%s %s +8" % (name, field), detected, ""))
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
        "cases": result["case_count"],
        "case_groups": {"%s/%s" % key: count for key, count in sorted(groups.items())},
        "instructions_reached": sum(len(rows) for rows in reached_rows.values()),
        "byte_edits_possible": result["edit_count"], "byte_edits_killed": sum(1 for item in result["mutants"] if item[2] == "killed"), "byte_edits_survived": len(survivors),
        "controls": len(controls), "controls_detected": detected,
    }
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps({"cases": result["case_count"], "negative_controls": len(controls), "negative_detected": detected,
                                        "byte_edits_survived": len(survivors)}, indent=1, sort_keys=True) + "\n"
    return files


LAYOUT_ROWS = (
    ("lookup argument", "cap or niche", "+0x00", "0x8000000000000000 selects the B-tree form, any other value is the ring capacity"),
    ("lookup argument", "buf or root", "+0x08", "ring buffer pointer, or B-tree root"),
    ("lookup argument", "head or height", "+0x10", "ring head slot, or B-tree height"),
    ("lookup argument", "length", "+0x18", "number of snapshots"),
    ("lookup argument", "epoch", "+0x58", "key compared with the snapshot epochs, by equality"),
    ("ring element", "size", "0x38", "u64 epoch then a 0x30 byte snapshot value"),
    ("snapshot value", "cap or niche", "+0x00", "niche selects an address B-tree, else a ring of 0x68 byte elements"),
    ("snapshot value", "buf or root", "+0x08", ""),
    ("snapshot value", "head or height", "+0x10", ""),
    ("snapshot value", "length", "+0x18", ""),
    ("vec element", "address", "+0x40", "20 bytes compared as 16 + 4"),
    ("tree value", "address", "+0x20", "20 bytes in a 0x48 byte value, 32 byte keys"),
    ("outer node", "keys / parent / len / edges", "+0x218 / +0x210 / +0x272 / +0x278", "u64 keys, 0x30 byte values at +0"),
    ("inner node", "vals / parent / len / edges", "+0x168 / +0x160 / +0x482 / +0x488", "32 byte keys at +0, 0x48 byte values"),
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
