#!/usr/bin/env python3
"""Reconstruct the node #115 listed signer set: a BTreeSet of 20 byte addresses, its two lazy builders, the vacant insert with node splits and the drop.

The builders 0x14c4020 (four addresses) and 0x14c4570 (one address), the vacant insert 0x156ea10 and its twin 0x156d9b0, the split capable
insert 0x148aae0 and the tree drop 0x1541a00 run as real bytes in an interpreter inside this tool. Only libc, the allocator and the panic
entries are recording stubs. A separately written B-tree rule list predicts every node byte the bytes leave behind. No disassembler output
is parsed and the binary is never executed. Standard library only.

    python3 tools/staking_listed_set115.py --out <dir>
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
# Node #115 listed-signer set: BTreeSet<[u8; 20]> insert, split, lazy builders and drop.
# ---------------------------------------------------------------------------------------------

BUILD_A, BUILD_B = 0x14C4020, 0x14C4570
VACANT, VACANT_TWIN = 0x156EA10, 0x156D9B0
INSERT, TREE_DROP = 0x148AAE0, 0x1541A00
STATIC_A, STATIC_B = 0x64EFCB0, 0x64EFC80
KEY_POOL_A = (0x464932, 0x464946, 0x46495A, 0x46496E)
KEY_POOL_B = (0x46491E,)
GOT_MALLOC, GOT_ALLOC_ERR, GOT_FREE = 0x64DF480, 0x64DF490, 0x64DF4A0
GOT_PANICS = (0x64DF4C0, 0x64DF570, 0x64DF620, 0x64DF730, 0x64DF830)
GOT_MEMCPY, GOT_MEMMOVE, GOT_MEMCMP = 0x64DF508, 0x64DF568, 0x64DFB50
LEAF, INTERNAL = 0xE8, 0x148
CAP = 11
KEY = 20
F_PARENT, F_KEYS, F_PIDX, F_LEN, F_EDGES = 0x00, 0x08, 0xE4, 0xE6, 0xE8
MAP_AT = HEAP_BASE + 0x100
ENTRY_AT = HEAP_BASE + 0x200
OUT_AT = HEAP_BASE + 0x300
KEYBUF_AT = HEAP_BASE + 0x400
ARENA = HEAP_BASE + 0x1000
ARENA_LIMIT = HEAP_BASE + 0x3E0000
USED = 0x60000
STALE = "stale"
FILL = 0xA5
FILLWORD = 0xA5A5A5A5A5A5A5A5
FILLKEY = bytes([0xA5]) * KEY


class DataMemory(Memory):
    """Memory with a byte overlay on read-only data, so a builder can be fed other key bytes."""

    data_patch = None

    def bytes_at(self, addr, count):
        raw = bytearray(Memory.bytes_at(self, addr, count))
        if self.data_patch:
            for index in range(count):
                value = self.data_patch.get(addr + index)
                if value is not None:
                    raw[index] = value
        return bytes(raw)


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


def key_of(value):
    """A 20 byte key ordered like its integer: 2 big-endian bytes then a hash tail."""
    return value.to_bytes(2, "big") + hashlib.sha256(b"k%d" % value).digest()[:KEY - 2]


class MNode:
    __slots__ = ("id", "internal", "parent", "pidx", "len", "keys", "edges")

    def __init__(self, nid, internal):
        self.id, self.internal = nid, internal
        self.parent, self.pidx, self.len = STALE, STALE, STALE
        self.keys = [FILLKEY] * CAP
        self.edges = [STALE] * 12

    def dump(self):
        return (self.id, self.internal, self.parent, self.pidx, self.len, tuple(self.keys), tuple(self.edges) if self.internal else ())


class MTree:
    """The Rust B-tree insert rules written from the node layout: 11 keys per node, split around the centre."""

    def __init__(self, flaws=()):
        self.nodes, self.root, self.height, self.length = [], None, 0, 0
        self.flaws = frozenset(flaws)
        self.allocs = []

    def alloc(self, internal):
        node = MNode(len(self.nodes), internal)
        self.nodes.append(node)
        self.allocs.append(INTERNAL if internal and "internal_size_as_leaf" not in self.flaws else LEAF)
        return node

    def new_leaf(self):
        node = self.alloc(False)
        node.parent, node.len = None, 0
        return node

    def new_internal(self):
        node = self.alloc(True)
        node.parent, node.len = None, 0
        return node

    def compare(self, a, b):
        if "reverse_order" in self.flaws:
            return (b > a) - (b < a)
        if "first_16_bytes" in self.flaws:
            a, b = a[:16], b[:16]
        return (a > b) - (a < b)

    def search(self, key):
        """('found', node, idx) or ('vacant', node, idx); node is None for an empty tree."""
        if self.root is None:
            return "vacant", None, 0
        node, level = self.nodes[self.root], self.height
        while True:
            idx = 0
            while idx < node.len and self.compare(key, node.keys[idx]) > 0:
                idx += 1
            if idx < node.len and self.compare(key, node.keys[idx]) == 0:
                return "found", node, idx
            if level == 0:
                return "vacant", node, idx
            node, level = self.nodes[node.edges[idx]], level - 1

    def slot_insert(self, node, idx, key, edge=None):
        count = node.len
        if node.internal:
            for i in range(count, idx, -1):
                node.keys[i] = node.keys[i - 1]
            node.keys[idx] = key
            for i in range(count + 1, idx + 1, -1):
                node.edges[i] = node.edges[i - 1]
            node.edges[idx + 1] = edge
            node.len = count + 1
            if "no_link_fix" not in self.flaws:
                for i in range(idx + 1, count + 2):
                    child = self.nodes[node.edges[i]]
                    child.parent, child.pidx = node.id, i
        else:
            for i in range(count, idx, -1):
                node.keys[i] = node.keys[i - 1]
            node.keys[idx] = key
            node.len = count + 1

    def split_point(self, idx):
        shift = 1 if "centre_low" in self.flaws else 0
        if idx < 5:
            return 4 - shift, ("left", idx)
        if idx == 5:
            return 5 - shift, ("left", idx)
        if idx == 6:
            return 5 - shift, ("right", 0)
        return 6 - shift, ("right", idx - (7 - shift))

    def split(self, node, mid):
        old = node.len
        right = self.new_internal() if node.internal else self.new_leaf()
        median = node.keys[mid]
        count = old - mid - 1
        for i in range(count):
            right.keys[i] = node.keys[mid + 1 + i]
        right.len = count
        node.len = mid
        if node.internal:
            for i in range(count + 1):
                right.edges[i] = node.edges[mid + 1 + i]
            for i in range(count + 1):
                child = self.nodes[right.edges[i]]
                child.parent, child.pidx = right.id, i
        if "median_kept_left" in self.flaws:
            node.len = mid + 1
        return median, right

    def insert_into(self, node, idx, key, edge):
        """Handle::insert of a leaf edge or an internal kv edge; returns (split or None, node, idx of the key)."""
        if node.len < CAP:
            self.slot_insert(node, idx, key, edge)
            return None, node, idx
        mid, (side, at) = self.split_point(idx)
        median, right = self.split(node, mid)
        target = node if side == "left" else right
        self.slot_insert(target, at, key, edge)
        return (node, median, right), target, at

    def insert_vacant(self, node, idx, key):
        """VacantEntry::insert; returns (node id, idx) of the inserted key."""
        if node is None:
            leaf = self.new_leaf()
            leaf.keys[0] = key
            leaf.len = 1
            self.root, self.height = leaf.id, 0
            self.length += 1
            return leaf.id, 0
        split, leaf, at = self.insert_into(node, idx, key, None)
        handle = (leaf.id, at)
        while split is not None:
            left, median, right = split
            parent = left.parent
            if parent is None:
                top = self.new_internal()
                top.edges[0] = left.id
                left.parent, left.pidx = top.id, 0
                top.keys[0], top.edges[1], top.len = median, right.id, 1
                right.parent, right.pidx = top.id, 1
                self.root = top.id
                self.height += 0 if "height_not_raised" in self.flaws else 1
                break
            holder = self.nodes[parent]
            split, _, _ = self.insert_into(holder, left.pidx, median, right.id)
        if "length_not_counted" not in self.flaws:
            self.length += 1
        return handle

    def insert(self, key):
        state, node, idx = self.search(key)
        if state == "found":
            return None
        return self.insert_vacant(node, idx, key)

    def dump(self):
        return (self.root, self.height, self.length, tuple(node.dump() for node in self.nodes))

    def post_order(self):
        """Node ids in the order the destructor frees them."""
        out = []

        def walk(nid, level):
            node = self.nodes[nid]
            if level:
                for i in range(node.len + 1):
                    walk(node.edges[i], level - 1)
            out.append(nid)
        if self.root is not None:
            walk(self.root, self.height)
        return out

    def in_order(self):
        out = []

        def walk(nid, level):
            node = self.nodes[nid]
            for i in range(node.len + 1 if level else node.len):
                if level:
                    walk(node.edges[i], level - 1)
                if i < node.len:
                    out.append(node.keys[i])
        if self.root is not None:
            walk(self.root, self.height)
        return out


def model_tree(count, order, seed, flaws=()):
    """Tree grown by the model from `count` even key values in the named order."""
    values = [2 * n + 2 for n in range(count)]
    if order == "desc":
        values.reverse()
    elif order == "shuffled":
        stream = Stream(seed + 1)
        for i in range(len(values) - 1, 0, -1):
            j = stream.next(i + 1)
            values[i], values[j] = values[j], values[i]
    elif order == "outside_in":
        values = [values[(i // 2) if i % 2 == 0 else -1 - i // 2] for i in range(count)]
    tree = MTree(flaws)
    for value in values:
        tree.insert(key_of(value))
    tree.allocs = []
    return tree


def r16(size):
    return (size + 15) & ~15


class SetRun:
    """Machine plus fixture: every code address runs as bytes; libc, the allocator and the panic entries are recording stubs."""

    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = self.machine = Machine(image, patches)
        memory = self.memory = DataMemory(image)
        machine.memory = memory
        text = image.named[".text"]
        machine.real = Real(text["address"], text["address"] + text["size"])
        machine.step_limit = 600000
        memory.statics = dict(image.relative())
        hooks = {GOT_MALLOC: self.h_malloc, GOT_ALLOC_ERR: self.h_alloc_error, GOT_FREE: self.h_free, GOT_MEMCPY: self.h_copy,
                 GOT_MEMMOVE: self.h_copy, GOT_MEMCMP: self.h_cmp}
        for slot in GOT_PANICS:
            hooks[slot] = self.h_panic
        for slot, hook in hooks.items():
            fake = MARK_BASE + slot
            memory.statics[slot] = fake
            machine.slots[fake] = hook
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.log, self.top, self.addr_of, self.ids = [], ARENA, [], {}
        self.cmp_mode, self.fail_at, self.mallocs = "sign", None, 0
        self.base_patches = dict(patches or {})

    # ---- stubs ------------------------------------------------------------------------------
    def h_malloc(self, machine):
        size = machine.regs[RDI]
        self.mallocs += 1
        if self.fail_at == self.mallocs:
            self.log.append(("malloc", size, -1))
            machine.regs[RAX] = 0
            return
        at = self.top
        self.top += r16(size)
        if self.top > ARENA_LIMIT:
            raise Halt("fixture arena full")
        self.memory.put_bytes(at, bytes([FILL]) * r16(size))
        self.ids[at] = len(self.addr_of)
        self.addr_of.append(at)
        self.log.append(("malloc", size, self.ids[at]))
        machine.regs[RAX] = at

    def h_alloc_error(self, machine):
        self.log.append(("alloc_error", machine.regs[RDI], machine.regs[RSI]))
        raise Panicked("allocation failure")

    def h_free(self, machine):
        self.log.append(("free", self.ids.get(machine.regs[RDI], -1), machine.regs[RSI], machine.regs[RDX]))

    def h_copy(self, machine):
        dst, src, count = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        if count:
            self.memory.put_bytes(dst, self.memory.bytes_at(src, count))
        machine.regs[RAX] = dst

    def h_cmp(self, machine):
        count = machine.regs[RDX]
        left, right = self.memory.bytes_at(machine.regs[RDI], count), self.memory.bytes_at(machine.regs[RSI], count)
        result = 0
        for a, b in zip(left, right):
            if a != b:
                result = (a > b) - (a < b) if self.cmp_mode == "sign" else a - b
                break
        machine.regs[RAX] = result & MASK[4]

    def h_panic(self, machine):
        raise Panicked("panic path reached")

    # ---- fixture ----------------------------------------------------------------------------
    def reset(self):
        self.machine.memory.reset(USED)
        self.log, self.top, self.addr_of, self.ids, self.mallocs = [], ARENA, [], {}, 0
        self.memory.data_patch = None

    def word_of(self, value):
        if value is None:
            return 0
        if value == STALE:
            return FILLWORD
        return self.addr_of[value]

    def place(self, tree):
        self.reset()
        for node in tree.nodes:
            size = INTERNAL if node.internal else LEAF
            at = self.top
            self.top += r16(size)
            self.memory.put_bytes(at, bytes([FILL]) * r16(size))
            self.ids[at] = len(self.addr_of)
            self.addr_of.append(at)
        write = self.memory.write
        for node in tree.nodes:
            at = self.addr_of[node.id]
            write(at + F_PARENT, 8, self.word_of(node.parent))
            write(at + F_PIDX, 2, 0xA5A5 if node.pidx == STALE else node.pidx)
            write(at + F_LEN, 2, 0xA5A5 if node.len == STALE else node.len)
            for i, key in enumerate(node.keys):
                self.memory.put_bytes(at + F_KEYS + KEY * i, key)
            if node.internal:
                for i, edge in enumerate(node.edges):
                    write(at + F_EDGES + 8 * i, 8, self.word_of(edge))
        write(MAP_AT, 8, 0 if tree.root is None else self.addr_of[tree.root])
        write(MAP_AT + 8, 8, tree.height)
        write(MAP_AT + 0x10, 8, tree.length)

    def id_of(self, word):
        if word == 0:
            return None
        if word == FILLWORD:
            return STALE
        return self.ids.get(word, ("raw", word))

    def dump(self):
        nodes = []
        for nid, at in enumerate(self.addr_of):
            internal = self.log_internal(nid)
            parent = self.id_of(self.memory.read(at + F_PARENT, 8))
            pidx = self.memory.read(at + F_PIDX, 2)
            length = self.memory.read(at + F_LEN, 2)
            keys = tuple(self.memory.bytes_at(at + F_KEYS + KEY * i, KEY) for i in range(CAP))
            edges = tuple(self.id_of(self.memory.read(at + F_EDGES + 8 * i, 8)) for i in range(12)) if internal else ()
            nodes.append((nid, internal, parent, STALE if pidx == 0xA5A5 else pidx, STALE if length == 0xA5A5 else length, keys, edges))
        root = self.id_of(self.memory.read(MAP_AT, 8))
        return (root, self.memory.read(MAP_AT + 8, 8), self.memory.read(MAP_AT + 0x10, 8), tuple(nodes))

    def log_internal(self, nid):
        return self.sizes.get(nid, False)

    def run_vacant(self, va, tree, node_id, idx, key, height=0):
        self.place(tree)
        self.sizes = {n.id: n.internal for n in tree.nodes}
        memory = self.memory
        memory.put_bytes(ENTRY_AT, bytes(0x40))
        memory.write(ENTRY_AT, 8, MAP_AT)
        memory.write(ENTRY_AT + 8, 8, 0 if node_id is None else self.addr_of[node_id])
        memory.write(ENTRY_AT + 0x10, 8, height)
        memory.write(ENTRY_AT + 0x18, 8, idx)
        memory.put_bytes(ENTRY_AT + 0x20, key)
        memory.put_bytes(OUT_AT, bytes(0x40))
        before = len(self.log)
        self.machine.run(va, {RDI: OUT_AT, RSI: ENTRY_AT})
        node = self.id_of(memory.read(OUT_AT, 8))
        handle = (node, memory.read(OUT_AT + 8, 8), memory.read(OUT_AT + 0x10, 8), memory.read(OUT_AT + 0x18, 8) == MAP_AT)
        for entry in self.log[before:]:
            if entry[0] == "malloc" and entry[2] >= 0:
                self.sizes[entry[2]] = entry[1] == INTERNAL
        return handle

    def original_key(self, group):
        key = bytearray(KEY)
        for at, width, offset in group:
            key[offset:offset + width] = self.memory.bytes_at(at, width)
        return bytes(key)

    def run_drop(self, tree):
        self.place(tree)
        self.machine.run(TREE_DROP, {RDI: MAP_AT})
        return tuple(self.log)

    def set_code_patch(self, extra):
        merged = dict(self.base_patches)
        merged.update(extra)
        stale = set(self.machine.patches) | set(merged)
        self.machine.patches = merged
        for va in stale:
            for back in range(16):
                self.machine.cache.pop(va - back, None)

    def run_builder(self, va, keys, pool, imms):
        self.reset()
        self.sizes = {}
        patch = {}
        code = {}
        for index, group in enumerate(imms):
            for at, width, offset in group:
                for i in range(width):
                    code[at + i] = keys[index][offset + i]
            if index:
                for i, byte in enumerate(keys[index]):
                    patch[pool[index - 1] + i] = byte
        self.set_code_patch(code)
        self.memory.data_patch = patch
        self.memory.put_bytes(OUT_AT, bytes(0x40))
        try:
            self.machine.run(va, {RDI: OUT_AT})
        finally:
            self.set_code_patch({})
        out = [self.memory.read(OUT_AT + 8 * i, 8) for i in range(5)]
        for entry in self.log:
            if entry[0] == "malloc" and entry[2] >= 0:
                self.sizes[entry[2]] = entry[1] == INTERNAL
        self.memory.write(MAP_AT, 8, out[0])
        self.memory.write(MAP_AT + 8, 8, out[1])
        self.memory.write(MAP_AT + 0x10, 8, out[2])
        return (self.id_of(out[0]), out[1], out[2], out[3], out[4]), self.dump()


IMM_A = (
    ((0x14C4073, 8, 0), (0x14C404A, 8, 8), (0x14C405B, 4, 16)),
    ((0x14C43CF, 8, 0), (0x14C439B, 8, 8), (0x14C43AC, 4, 16)),
    ((0x14C4432, 8, 0), (0x14C43FE, 8, 8), (0x14C440F, 4, 16)),
    ((0x14C4495, 8, 0), (0x14C4461, 8, 8), (0x14C4472, 4, 16)),
    ((0x14C44F8, 8, 0), (0x14C44C4, 8, 8), (0x14C44D5, 4, 16)),
)
IMM_B = (
    ((0x14C45C3, 8, 0), (0x14C459A, 8, 8), (0x14C45AB, 4, 16)),
    ((0x14C46C8, 8, 0), (0x14C4699, 8, 8), (0x14C46AA, 4, 16)),
)
ALPHA = (bytes(20), bytes(19) + b"\x01", bytes(10) + b"\x01" + bytes(9), b"\x01" + bytes(19), b"\x7f" + bytes(19), b"\x80" + bytes(18) + b"\x01", bytes([255]) * 20)
SHAPES = (0, 1, 2, 5, 9, 10, 11, 12, 13, 21, 22, 23, 24, 25, 34, 35, 36, 46, 47, 48, 60, 100, 131, 132, 133, 143, 144, 145, 150, 200)
ORDERS = ("asc", "desc", "shuffled", "outside_in")
SMALL = 36


def gap_list(count, seed):
    if count <= SMALL:
        return list(range(count + 1))
    stream = Stream(seed * 31 + count)
    picks = {0, 1, count - 1, count, count // 2, count // 2 + 1, count // 3, 2 * count // 3}
    while len(picks) < 22:
        picks.add(stream.next(count + 1))
    return sorted(picks)


def all_cases():
    out = []
    for count in SHAPES:
        for oi, order in enumerate(ORDERS):
            for gap in gap_list(count, oi):
                out.append(("insert", dict(count=count, order=order, seed=count + oi, gap=gap, va=VACANT)))
                out.append(("insert_twin", dict(count=count, order=order, seed=count + oi, gap=gap, va=VACANT_TWIN)))
    base = len(out)
    for index in range(0, base, 3):
        kind, params = out[index]
        tree = model_tree(params["count"], params["order"], params["seed"])
        tree.allocs = []
        state, node, idx = tree.search(key_of(2 * params["gap"] + 1))
        tree.insert_vacant(node, idx, key_of(2 * params["gap"] + 1))
        for fail in range(1, len(tree.allocs) + 1):
            out.append(("fault", dict(params, fail=fail)))
    for order in ("asc", "desc", "shuffled", "outside_in"):
        for seed in (1, 2):
            total = 150
            for step in range(total):
                out.append(("grow", dict(order=order, seed=seed, total=total, step=step, va=VACANT if (step + seed) % 2 else VACANT_TWIN)))
    for count in SHAPES:
        for order, seed in (("asc", 0), ("desc", 0), ("outside_in", 0)) + tuple(("shuffled", s) for s in range(1, 7)):
            out.append(("drop", dict(count=count, order=order, seed=seed)))
    for count in SHAPES[1:]:
        for order in ORDERS:
            out.append(("drop", dict(count=count, order=order, seed=3, delta=-1)))
    width = len(ALPHA)
    for a in range(width):
        for b in range(width):
            for c in range(width):
                for d in range(width):
                    for mode in ("sign", "diff"):
                        out.append(("builder_a", dict(keys=((a + 2 * b + 3 * c + d) % width, a, b, c, d), mode=mode)))
    for a in range(width):
        for b in range(width):
            for mode in ("sign", "diff"):
                out.append(("builder_b", dict(keys=(a, b), mode=mode)))
    for keys in ((0, 1, 2, 3, 4), (6, 5, 4, 3, 2), (3, 3, 3, 3, 3), (1, 0, 1, 0, 1)):
        for fail in (1, 2, 3):
            out.append(("builder_fault", dict(keys=keys, fail=fail)))
    out.append(("builder_real", dict(which="a")))
    out.append(("builder_real", dict(which="b")))
    return out


def grow_values(order, seed, total):
    values = list(range(1, total + 1))
    if order == "desc":
        values.reverse()
    elif order == "shuffled":
        stream = Stream(seed + 77)
        for i in range(len(values) - 1, 0, -1):
            j = stream.next(i + 1)
            values[i], values[j] = values[j], values[i]
    elif order == "outside_in":
        values = [values[(i // 2) if i % 2 == 0 else -1 - i // 2] for i in range(total)]
    return values


def free_expectation(tree, flaws=()):
    out = []
    order = tree.post_order()
    if "preorder_free" in flaws:
        order = list(reversed(order))
    for nid in order:
        internal = tree.nodes[nid].internal
        if "skip_internal_free" in flaws and internal:
            continue
        size = INTERNAL if internal and "internal_freed_as_leaf" not in flaws else LEAF
        out.append(("free", nid, size, 0))
    return tuple(out)


def builder_model(keys, flaws=()):
    tree = MTree(flaws)
    seq = list(keys)
    if "last_key_dropped" in flaws:
        seq.pop()
    for key in seq:
        if "no_dedupe" in flaws:
            state, node, idx = tree.search(key)
            tree.insert_vacant(node, idx, key)
        else:
            tree.insert(key)
    return tree


def alloc_sizes(tree):
    return tuple(tree.allocs)


def alloc_args(run):
    return tuple((entry[1], entry[2]) for entry in run.log if entry[0] == "alloc_error")


def execute(run, case, flaws=()):
    """Run one case on the bytes and on the rule list; returns (got, want)."""
    kind, p = case
    run.cmp_mode, run.fail_at = "sign", None
    if kind in ("insert", "insert_twin", "grow", "fault"):
        if kind == "grow":
            values = grow_values(p["order"], p["seed"], p["total"])
            tree = MTree(flaws)
            for value in values[:p["step"]]:
                tree.insert(key_of(value))
            key = key_of(values[p["step"]])
            va = p["va"]
        else:
            tree = model_tree(p["count"], p["order"], p["seed"], flaws)
            key = key_of(2 * p["gap"] + 1)
            va = p.get("va", VACANT)
        tree.allocs = []
        state, node, idx = tree.search(key)
        nid = None if node is None else node.id
        if kind == "fault":
            run.fail_at = p["fail"]
        try:
            got_handle = run.run_vacant(va, tree, nid, idx, key)
            outcome = "ok"
        except Panicked:
            got_handle, outcome = None, "alloc_error"
        got_dump = run.dump() if outcome == "ok" else None
        got_log = tuple(entry[1] for entry in run.log if entry[0] == "malloc")
        want_handle = tree.insert_vacant(node, idx, key)
        if kind == "fault" and p["fail"] <= len(tree.allocs):
            return (("alloc_error", got_log, alloc_args(run)),
                    ("alloc_error", tuple(tree.allocs[:p["fail"]]), ((8, tree.allocs[p["fail"] - 1]),)))
        return (outcome, got_handle, got_dump, got_log), ("ok", (want_handle[0], 0, want_handle[1], True), tree.dump(), tuple(tree.allocs))
    if kind == "drop":
        tree = model_tree(p["count"], p["order"], p["seed"], flaws)
        want_tree = tree
        if p.get("delta"):
            tree = model_tree(p["count"], p["order"], p["seed"], flaws)
            tree.length += p["delta"]
        got = run.run_drop(tree)
        tree = want_tree
        return ("drop", got), ("drop", free_expectation(tree, flaws))
    if kind in ("builder_a", "builder_b", "builder_fault", "builder_real"):
        which = p.get("which", "b" if kind == "builder_b" else "a")
        pool = KEY_POOL_B if which == "b" else KEY_POOL_A
        va = BUILD_B if which == "b" else BUILD_A
        imms = IMM_B if which == "b" else IMM_A
        if kind == "builder_real":
            keys = [run.original_key(group) for group in imms]
        else:
            keys = [ALPHA[i] for i in p["keys"]]
        run.cmp_mode = p.get("mode", "sign")
        if kind == "builder_fault":
            run.fail_at = p["fail"]
        model = builder_model(keys, flaws)
        try:
            if kind == "builder_real":
                record, dump = run.run_builder(va, keys, pool, ())
            else:
                record, dump = run.run_builder(va, keys, pool, imms)
            outcome = "ok"
        except Panicked:
            record, dump, outcome = None, None, "alloc_error"
        got_log = tuple(entry[1] for entry in run.log if entry[0] == "malloc")
        if kind == "builder_fault" and p["fail"] <= len(model.allocs):
            return (("alloc_error", got_log, alloc_args(run)),
                    ("alloc_error", tuple(model.allocs[:p["fail"]]), ((8, model.allocs[p["fail"] - 1]),)))
        want_record = (model.root, model.height, model.length, 1, 1)
        return (outcome, record, dump, got_log), ("ok", want_record, model.dump(), tuple(model.allocs))
    raise EvidenceError("unknown case kind " + kind)


SCOPE = {
    BUILD_A: ("listed_set_builder_four_addresses", "real"), BUILD_B: ("listed_set_builder_one_address", "real"),
    VACANT: ("btree_vacant_insert", "real"), VACANT_TWIN: ("btree_vacant_insert_twin", "real"),
    INSERT: ("btree_insert_recursing_split", "real"), TREE_DROP: ("btree_into_iter_drop", "real"),
}
STATE = {}
MUTANT_CASES = 48
WORKERS = 4
SAMPLE_EVERY = 7
STUBS = (
    (GOT_MALLOC, "malloc", "bump allocator, 0xa5 fill, optional failure of the k-th call"),
    (GOT_ALLOC_ERR, "alloc error handler", "records size and align, then stops"),
    (GOT_FREE, "sized free", "records node id, size and flags"),
    (GOT_MEMCPY, "memcpy", "copies, returns the destination"),
    (GOT_MEMMOVE, "memmove", "copies through a temporary, returns the destination"),
    (GOT_MEMCMP, "memcmp", "first differing byte as sign or as difference"),
) + tuple((slot, "panic entry", "stops the run") for slot in GOT_PANICS)


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


FAILURES = (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, struct.error, TypeError, AttributeError)


def run_checked(run, case):
    try:
        return execute(run, case)
    except Panicked:
        return ("panic",), None


def mutant_task(job):
    va, kind, patch = job
    state = STATE
    picked = state["reach"].get(va, [])
    run = SetRun(state["image"], patch, state["cache"])
    run.machine.step_limit = 90000
    for index in picked:
        case = state["cases"][index]
        try:
            got, want = execute(run, case)
        except FAILURES:
            return va, kind, "killed", "%s:%d" % (case[0], index)
        if got != want:
            return va, kind, "killed", "%s:%d" % (case[0], index)
    return va, kind, "survived", "equal on %d picked cases" % len(picked)


MODEL_FLAWS = (
    ("reverse_order", ("insert", "builder_a")), ("first_16_bytes", ("builder_a",)), ("no_link_fix", ("insert", "grow")),
    ("centre_low", ("insert", "grow")), ("median_kept_left", ("insert", "grow")), ("height_not_raised", ("insert", "grow")),
    ("length_not_counted", ("insert", "builder_a")), ("internal_size_as_leaf", ("insert", "grow")),
    ("preorder_free", ("drop",)), ("skip_internal_free", ("drop",)), ("internal_freed_as_leaf", ("drop",)),
    ("no_dedupe", ("builder_a",)), ("last_key_dropped", ("builder_a",)),
)
GEOMETRY_FIELDS = ("F_PARENT", "F_KEYS", "F_PIDX", "F_LEN", "F_EDGES")


def flaw_task(job):
    flaw, kinds = job
    for index, case in enumerate(STATE["cases"]):
        if case[0] not in kinds or index % 3:
            continue
        good_got, good = execute(STATE["flaw_run"], case)
        try:
            bad_got, bad = execute(STATE["flaw_run"], case, (flaw,))
        except FAILURES:
            return flaw, True, "%s:%d" % (case[0], index)
        if bad != good or good_got != good:
            return flaw, True, "%s:%d" % (case[0], index)
    return flaw, False, ""


def geometry_task(field):
    state = STATE
    saved = globals()[field]
    globals()[field] = saved + 8
    try:
        run = SetRun(state["image"])
        run.machine.step_limit = 90000
        for index in state["geometry_cases"]:
            try:
                got, want = execute(run, state["cases"][index])
            except FAILURES:
                return field, True
            if got != want:
                return field, True
        return field, False
    finally:
        globals()[field] = saved


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
    attempt("address inside a function, not an FDE start", lambda: image.exact_fde(INSERT + 1))
    attempt("address outside every FDE", lambda: image.fde(0x100))
    attempt("address outside every file-backed section", lambda: image.offset(0x10))
    run = SetRun(image)
    for count in (1, 5, 12, 40, 150):
        for delta in (1, 2):
            def drop_with_wrong_length(count=count, delta=delta):
                tree = model_tree(count, "shuffled", 3)
                tree.length += delta
                got = run.run_drop(tree)
                if got != free_expectation(model_tree(count, "shuffled", 3)):
                    raise EvidenceError("drop log differs from the rule list")
            attempt("drop of a %d key tree whose length word is %+d" % (count, delta), drop_with_wrong_length)

    def full_node_overflow():
        tree = model_tree(12, "asc", 1)
        node = tree.nodes[tree.root]
        node.len = 12
        run.run_vacant(VACANT, tree, node.id, 0, key_of(1))
    attempt("leaf whose length word is 12 given to the vacant insert", full_node_overflow)
    return rows


def function_rows(image, reached):
    table = {}
    for target in sorted(SCOPE):
        low, high = image.exact_fde(target)
        rows = [row for row in decode_range(image, low, high) if row.va in reached]
        for row in rows:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        table[target] = rows
    return table


def masked_twin(image):
    """The two vacant-insert bodies differ only in call/rip displacements."""
    (a0, a1), (b0, b1) = image.exact_fde(VACANT), image.exact_fde(VACANT_TWIN)
    rows_a, rows_b = decode_range(image, a0, a1), decode_range(image, b0, b1)
    same = len(rows_a) == len(rows_b)
    diffs = 0
    for x, y in zip(rows_a, rows_b):
        ba = bytes(image.blob[image.offset(x.va):image.offset(x.va) + x.size])
        bb = bytes(image.blob[image.offset(y.va):image.offset(y.va) + y.size])
        if ba != bb:
            diffs += 1
            if x.op != y.op or x.size != y.size:
                same = False
    return same, diffs, len(rows_a)


def analyse(image, workers=WORKERS):
    cases = all_cases()
    STATE.update(image=image, cases=cases)
    result = dict(case_count=len(cases))
    run = SetRun(image)
    scenarios, reached, groups = [], set(), collections.Counter()
    seen_count, kept = collections.Counter(), collections.defaultdict(lambda: collections.defaultdict(list))
    geometry_cases = []
    splits = collections.Counter()
    for index, case in enumerate(cases):
        run.machine.seen = set()
        got, want = execute(run, case)
        if got != want:
            raise EvidenceError("case %d (%s %r): %r against %r" % (index, case[0], case[1], got[:2], want[:2]))
        kind = case[0]
        label = got[0]
        if kind in ("insert", "insert_twin", "grow") and label == "ok":
            label = "splits_%d" % sum(1 for e in run.log if e[0] == "malloc")
        groups[(kind, label)] += 1
        size = case[1].get("count", case[1].get("step", 0))
        shape = (kind, label, 0 if size < 12 else 1 if size < 40 else 2 if size < 145 else 3)
        for va in run.machine.seen:
            seen_count[(va, shape)] += 1
            if seen_count[(va, shape)] <= 3:
                kept[va][shape].append(index)
        reached |= run.machine.seen
        if index % SAMPLE_EVERY == 0:
            p = case[1]
            if kind in ("insert", "insert_twin", "fault"):
                scenarios.append((index, kind, p["count"], p["order"], p["gap"], label, len(got[3]) if got[0] != "alloc_error" else len(got[1]), run.machine.steps))
            elif kind == "grow":
                scenarios.append((index, kind, p["step"], p["order"], "-", label, len(got[3]), run.machine.steps))
            elif kind == "drop":
                scenarios.append((index, kind, p["count"], p["order"], p["seed"], label, len(got[1]), run.machine.steps))
            else:
                scenarios.append((index, kind, "".join(str(i) for i in p.get("keys", ())) or p["which"], p.get("mode", "-"), "-", label, len(got[3]) if got[0] == "ok" else len(got[1]), run.machine.steps))
        if index % 17 == 0 and len(geometry_cases) < 300 and kind in ("insert", "grow", "drop", "builder_a"):
            geometry_cases.append(index)
    result["scenarios"], result["groups"] = scenarios, groups
    STATE["reach"] = {va: round_robin(by_kind) for va, by_kind in kept.items()}
    STATE["cache"] = run.machine.cache
    STATE["geometry_cases"] = geometry_cases
    STATE["flaw_run"] = SetRun(image, None, run.machine.cache)
    result["reached"] = reached
    result["table_rows"] = function_rows(image, reached)
    edit_jobs = []
    for target, rows in sorted(result["table_rows"].items()):
        edit_jobs += edits_for(image, rows)
    with multiprocessing.get_context("fork").Pool(workers) as pool:
        mutants = pool.map(mutant_task, edit_jobs, 4)
        geometry = pool.map(geometry_task, GEOMETRY_FIELDS)
        flaws = pool.map(flaw_task, MODEL_FLAWS)
    result["mutants"], result["geometry"], result["flaws"] = mutants, geometry, flaws
    result["ranges"] = range_controls(image)
    result["edit_count"] = len(edit_jobs)
    result["twin"] = masked_twin(image)
    return result


def render(result, image):
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]) + "\n"

    sizes = {target: image.exact_fde(target)[1] - target for target in SCOPE}
    reached_rows = result["table_rows"]
    tsv("path.tsv", ("name", "address", "role", "body_bytes", "reached_rows", "reached_bytes"),
        [(SCOPE[target][0], "%#x" % target, SCOPE[target][1], sizes[target], len(reached_rows.get(target, ())), sum(row.size for row in reached_rows.get(target, ()))) for target in sorted(SCOPE)])
    tsv("stubs.tsv", ("slot", "name", "behaviour"), [("%#x" % slot, name, text) for slot, name, text in STUBS])
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
    pool_rows = []
    probe = SetRun(image)
    for name, pool, groups in (("builder_a", KEY_POOL_A, IMM_A), ("builder_b", KEY_POOL_B, IMM_B)):
        for index, group in enumerate(groups):
            immediate = probe.original_key(group)
            slot = pool[index - 1] if index else 0
            stored = bytes(image.blob[image.offset(slot):image.offset(slot) + KEY]) if index else b""
            pool_rows.append((name, index, "%#x" % slot if index else "-", immediate.hex(), stored.hex() or "-", "yes" if index and stored == immediate else ("-" if not index else "NO")))
    tsv("listed-keys.tsv", ("builder", "insert_order", "compare_address", "inserted_key_from_immediates", "compare_key_bytes", "equal"), pool_rows)
    relative = image.relative()
    tsv("lazy-rows.tsv", ("static", "initializer", "builder"),
        [("%#x" % slot, "%#x" % relative[slot], SCOPE[relative[slot]][0]) for slot in (STATIC_B, STATIC_A)])
    tsv("scenarios.tsv", ("case", "group", "count", "order", "gap", "result", "log_entries", "steps"), result["scenarios"])
    tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutants"]])
    controls = []
    for field, detected in result["geometry"]:
        controls.append(("layout_field_moved", "%s +8" % field, detected, ""))
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
    same, diffs, total = result["twin"]
    summary = {
        "binary": "artifacts/node/115/hl-node", "sha256": SHA256,
        "functions_real": len(SCOPE), "cases": result["case_count"],
        "case_groups": {"%s/%s" % key: count for key, count in sorted(result["groups"].items())},
        "instructions_reached": sum(len(rows) for rows in reached_rows.values()),
        "byte_edits_possible": result["edit_count"], "byte_edits_killed": sum(1 for item in result["mutants"] if item[2] == "killed"), "byte_edits_survived": len(survivors),
        "controls": len(controls), "controls_detected": detected,
        "vacant_twin_same_shape": same, "vacant_twin_rows_that_differ": diffs, "vacant_twin_rows": total,
    }
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps({"cases": result["case_count"], "negative_controls": len(controls), "negative_detected": detected,
                                        "byte_edits_survived": len(survivors)}, indent=1, sort_keys=True) + "\n"
    return files


LAYOUT_ROWS = (
    ("set", "root", "+0x00", "node pointer, 0 for an empty set"),
    ("set", "height", "+0x08", "0 for a single leaf"),
    ("set", "length", "+0x10", "number of keys, raised by the vacant insert"),
    ("lazy value", "state words", "+0x18 / +0x20", "both written 1 after the set is built"),
    ("node", "parent", "+0x00", "pointer, 0 for the root; only written for a new node"),
    ("node", "keys", "+0x08", "11 keys of 20 bytes, compared with memcmp"),
    ("node", "parent index", "+0xe4", "u16, written when the node is attached to a parent"),
    ("node", "length", "+0xe6", "u16, at most 11"),
    ("internal node", "edges", "+0xe8", "12 child pointers; leaf is 0xe8 bytes, internal is 0x148"),
    ("vacant entry", "map / node / height / index / key", "+0x00 / +0x08 / +0x10 / +0x18 / +0x20", "key is 20 bytes, no value"),
    ("insert result", "node / height / index / map", "+0x00 / +0x08 / +0x10 / +0x18", "where the key landed"),
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
