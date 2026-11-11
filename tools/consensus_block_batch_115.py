#!/usr/bin/env python3
"""Reconstruct the node #115 consensus block batch filter 0x2705af0: known-hash lookup, round floor, signed block wrapper, in-place emit and drops.

The batch function 0x2705af0 (a map over an into-iter of 0x1b0 byte items) and the known-hash ring search 0x24c5ba0 run as real bytes in an
interpreter inside this tool, together with the signed block wrapper 0x2786870, the signer check 0x57e8bd0 and the ring search 0x57f54e0 it calls.
The stake set provider, the block rules, the signing digest, signature recovery, the certificate drop, the Arc slow drop, libc and the panic
entries are named contract stubs. A separately written rule list predicts every output byte, every Arc counter and the ordered stub calls.
No disassembler output is parsed and the binary is never executed. Standard library only.

    python3 tools/consensus_block_batch_115.py --out <dir>
"""
import argparse
import bisect
import collections
import hashlib
import itertools
import json
import multiprocessing
import pathlib
import re
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


# ---------------------------------------------------------------------------------------------
# Node #115 signed-message admission front ends (consensus): who may speak, then the certificate rules.
# ---------------------------------------------------------------------------------------------

FRONT, SIGNER, RING = 0x57E8970, 0x57E8BD0, 0x57F54E0
WRAP_BLOCK, WRAP_TV = 0x2786870, 0x2786A20
DIGEST, DROP_CERT, ITER_NEXT, QC_WRAP = 0x57E8D40, 0x2780350, 0x2448AA0, 0x595FD20
SLOT_STAKES, SLOT_SIGNER, SLOT_VERIFY, SLOT_RECOVER = 0x64E64B0, 0x64E64B8, 0x64E64C0, 0x64E0AD8
GOT_MALLOC, GOT_ALLOC_ERR, GOT_FREE = 0x64DF480, 0x64DF490, 0x64DF4A0
GOT_PANICS = (0x64DF4C0, 0x64DF570, 0x64DF620, 0x64DF730, 0x64DF830)
GOT_MEMCPY, GOT_MEMMOVE, GOT_MEMCMP = 0x64DF508, 0x64DF568, 0x64DFB50
MARK_BASE = 0x7700000000
SENT = 0x8000000000000001
MINW = 0x8000000000000000
OK_TAG = 0x2E
CAP = 11
KEY = 20
LEAF, INTERNAL = 0x140, 0x1A0
F_KEYS, F_PIDX, F_LEN, F_EDGES = 0x60, 0x13C, 0x13E, 0x140
ROW = 32
STATE_AT = HEAP_BASE + 0x100
BLOCK_AT = HEAP_BASE + 0x400
IN_AT = HEAP_BASE + 0x800
OUT_AT = HEAP_BASE + 0xA00
OUT_SIZE = 0x200
SETOBJ_AT = HEAP_BASE + 0x1000
ERRBOX_AT = HEAP_BASE + 0x1100
VT_AT = HEAP_BASE + 0x1180
ADDR_AT = HEAP_BASE + 0x1200
SIG_AT = HEAP_BASE + 0x1240
MSG_AT = HEAP_BASE + 0x1280
BOX_AT = HEAP_BASE + 0x12C0
VEC_AT = HEAP_BASE + 0x1400
FIX_AT = HEAP_BASE + 0x4000
ARENA = HEAP_BASE + 0x40000
ARENA_LIMIT = HEAP_BASE + 0x3E0000
USED = 0x60000
FILL = 0xA5
BLOCK_SIZE, TV_SIZE = 0x178, 0xE0


def r16(size):
    return (size + 15) // 16 * 16


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

    def bytes(self, count):
        return bytes(self.next(256) for _ in range(count))


def addr_of(value):
    """A 20 byte address ordered like its integer: 2 big-endian bytes then a hash tail."""
    return value.to_bytes(2, "big") + hashlib.sha256(b"a%d" % value).digest()[:KEY - 2]


def digest_of(variant, content):
    """The contract of the signing digest stub: 32 bytes fixed by the variant word and the message content."""
    return hashlib.sha256(struct.pack("<Q", variant) + content).digest()


# ---- the models: a set as the code finds an address in it -----------------------------------

class MNode:
    __slots__ = ("keys", "edges")

    def __init__(self, keys, edges=None):
        self.keys, self.edges = keys, edges


def build_tree(keys, height, stream):
    """Pack sorted keys into a B-tree of exactly this height; fan-out and fill are chosen by the stream."""
    if height == 0:
        return MNode(list(keys))
    count = len(keys)
    low_cap = 12 ** height - 1 if height > 0 else 0
    children_cap = 12 ** (height - 1) - 1 if height > 1 else CAP
    # at least 2 children, at most 12, every child must fit its share
    need = max(2, -(-(count + 1) // (children_cap + 1)))
    kids = min(12, need + stream.next(3))
    kids = max(2, min(kids, count + 1))
    seps = kids - 1
    rest = count - seps
    shares = [rest // kids] * kids
    for i in range(rest - sum(shares)):
        shares[stream.next(kids)] += 1
    out_keys, edges, at = [], [], 0
    for i in range(kids):
        share = shares[i]
        edges.append(build_tree(keys[at:at + share], height - 1, stream))
        at += share
        if i < seps:
            out_keys.append(keys[at])
            at += 1
    return MNode(out_keys, edges)


def tree_height_for(count):
    height = 0
    while 12 ** (height + 1) - 1 < count:
        height += 1
    return height


def memcmp_sign(a, b):
    return (a > b) - (a < b)


def tree_contains(root, height, addr, flaws=()):
    """The walk of 0x57e8bd0 / 0x57e8970: keys left to right, equal found, smaller descends, bigger moves on."""
    node, level = root, height
    while True:
        index = 0
        for key in node.keys:
            order = memcmp_sign(addr, key)
            if "tree_reverse" in flaws:
                order = -order
            if order == 0:
                return True
            if order < 0:
                break
            index += 1
        if "tree_first_key_only" in flaws and node.keys and index > 0:
            index = 0
        if level == 0 or node.edges is None:
            return False
        if "no_height_stop" in flaws and level == 0:
            return False
        node, level = node.edges[index], level - 1


def ring_search(rows, head, cap, key, flaws=()):
    """VecDeque<row>::binary_search_by(row.key.cmp(key)): front slice, back slice, size halving. -> (found, index)"""
    count = len(rows)
    ordered = list(rows)
    split = min(count, cap - head) if cap else 0
    front, back = ordered[:split], ordered[split:]

    def bsearch(items):
        size, base = len(items), 0
        if size == 0:
            return False, 0
        while size > 1:
            half = size // 2
            mid = base + half
            if "ring_ge_moves" in flaws:
                base = mid if memcmp_sign(items[mid][:KEY], key) >= 0 else base
            else:
                base = mid if memcmp_sign(items[mid][:KEY], key) <= 0 else base
            size -= half
        order = memcmp_sign(items[base][:KEY], key)
        if order == 0:
            return True, base
        return False, base + (order < 0)

    if back:
        order = memcmp_sign(back[0][:KEY], key)
        if order == 0:
            return True, len(front)
        if order < 0:
            found, idx = bsearch(back)
            return found, idx + len(front)
    return bsearch(front)


# ---- the fixture: machine memory, stub contracts, one run -----------------------------------

class Run:
    """Machine plus fixture: every code address runs as bytes, but libc, the allocator, the panic entries and the named contracts."""

    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = self.machine = Machine(image, patches)
        memory = self.memory = Memory(image)
        machine.memory = memory
        text = image.named[".text"]
        machine.real = Real(text["address"], text["address"] + text["size"])
        machine.real.skip.update({DIGEST, DROP_CERT, ITER_NEXT, QC_WRAP})
        machine.step_limit = 300000
        memory.statics = dict(image.relative())
        hooks = {GOT_MALLOC: self.h_malloc, GOT_ALLOC_ERR: self.h_alloc_error, GOT_FREE: self.h_free, GOT_MEMCPY: self.h_copy,
                 GOT_MEMMOVE: self.h_copy, GOT_MEMCMP: self.h_cmp, SLOT_STAKES: self.h_stakes, SLOT_VERIFY: self.h_verify,
                 SLOT_RECOVER: self.h_recover}
        for slot in GOT_PANICS:
            hooks[slot] = self.h_panic
        for slot, hook in hooks.items():
            fake = MARK_BASE + slot
            memory.statics[slot] = fake
            machine.slots[fake] = hook
        self.err_drop = MARK_BASE + 0x1
        machine.slots[self.err_drop] = self.h_err_drop
        machine.calls[DIGEST] = self.h_digest
        machine.calls[DROP_CERT] = self.h_drop_cert
        machine.calls[ITER_NEXT] = self.h_iter
        machine.calls[QC_WRAP] = self.h_qc
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.log, self.top, self.fix, self.mallocs = [], ARENA, FIX_AT, 0
        self.plan = {}
        self.fail_at = None

    # ---- stubs ------------------------------------------------------------------------------
    def rel(self, value):
        if STACK_TOP - STACK_SIZE <= value < STACK_TOP:
            return "stack"
        return value - HEAP_BASE if HEAP_BASE <= value < HEAP_BASE + HEAP_SIZE else value

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
        self.log.append(("malloc", size, self.rel(at)))
        machine.regs[RAX] = at

    def h_alloc_error(self, machine):
        self.log.append(("alloc_error", machine.regs[RDI], machine.regs[RSI]))
        raise Panicked("allocation failure")

    def h_free(self, machine):
        self.log.append(("free", self.rel(machine.regs[RDI]), machine.regs[RSI], machine.regs[RDX]))

    def h_copy(self, machine):
        dst, src, count = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.log.append(("copy", self.rel(dst), self.rel(src), count))
        if count:
            self.memory.put_bytes(dst, self.memory.bytes_at(src, count))
        machine.regs[RAX] = dst

    def h_cmp(self, machine):
        count = machine.regs[RDX]
        left, right = self.memory.bytes_at(machine.regs[RDI], count), self.memory.bytes_at(machine.regs[RSI], count)
        result = 0
        for a, b in zip(left, right):
            if a != b:
                result = a - b
                break
        machine.regs[RAX] = result & MASK[4]

    def h_panic(self, machine):
        raise Panicked("panic path reached")

    def record(self, tag, seed):
        """A 0x48 byte result record: tag byte then seeded bytes, or only the tag for the success tag."""
        if tag == OK_TAG:
            return bytes([tag])
        return bytes([tag]) + Stream(seed).bytes(0x47)

    def h_stakes(self, machine):
        out, state, rnd = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.log.append(("stakes", self.rel(state), rnd))
        tag, seed = self.plan["stakes"]
        if tag == OK_TAG:
            self.memory.put_bytes(out, bytes([OK_TAG]))
            self.memory.write(out + 8, 8, SETOBJ_AT)
        else:
            self.memory.put_bytes(out, self.record(tag, seed))

    def h_verify(self, machine):
        out, block, state = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.log.append(("verify", self.rel(out), self.rel(block), self.rel(state)))
        tag, seed = self.plan["verify"]
        self.memory.put_bytes(out, self.record(tag, seed))

    def h_qc(self, machine):
        out, tv = machine.regs[RDI], machine.regs[RSI]
        self.log.append(("qc", self.rel(out), self.rel(tv)))
        tag, seed = self.plan["qc"]
        self.memory.put_bytes(out, self.record(tag, seed))

    def h_digest(self, machine):
        out, msg = machine.regs[RDI], machine.regs[RSI]
        variant = self.memory.read(msg, 8)
        ptr = self.memory.read(msg + 8, 8)
        content = self.memory.bytes_at(ptr, 0x38) if variant == 2 else struct.pack("<Q", self.rel(ptr))
        digest = digest_of(variant, content)
        self.log.append(("digest", variant, content.hex()))
        self.memory.put_bytes(out, digest)

    def h_recover(self, machine):
        out, sig, digest = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        got = self.memory.bytes_at(digest, 32)
        self.log.append(("recover", self.rel(sig), self.memory.bytes_at(sig, 8).hex(), got.hex()))
        kind, who = self.plan["recover"]
        if kind == "ok":
            self.memory.put_bytes(out, bytes([0]) + who)
        else:
            self.memory.put_bytes(out, bytes([1]))
            self.memory.write(out + 8, 8, ERRBOX_AT)

    def h_err_drop(self, machine):
        self.log.append(("err_drop", self.rel(machine.regs[RDI])))

    def h_drop_cert(self, machine):
        self.log.append(("drop_cert", self.rel(machine.regs[RDI])))

    def h_iter(self, machine):
        out, it = machine.regs[RDI], machine.regs[RSI]
        words = tuple(self.memory.read(it + 8 * i, 8) for i in range(10))
        left = self.memory.read(it + 0x40, 8)
        self.log.append(("iter", self.rel(out), self.rel(it), tuple(self.rel(w) for w in words), left))
        if left:
            self.memory.write(it + 0x40, 8, left - 1)
            self.memory.write(out, 8, 1)
        else:
            self.memory.write(out, 8, 0)

    # ---- fixture ----------------------------------------------------------------------------
    def reset(self):
        self.memory.reset(USED)
        self.log, self.top, self.fix, self.mallocs = [], ARENA, FIX_AT, 0

    def fix_alloc(self, size):
        at = self.fix
        self.fix += r16(size)
        if self.fix > ARENA:
            raise Halt("fixture area full")
        return at

    def place_node(self, node, level, parent):
        at = self.fix_alloc(INTERNAL if node.edges is not None else LEAF)
        write = self.memory.write
        write(at, 8, parent)
        write(at + F_PIDX, 2, 0)
        write(at + F_LEN, 2, len(node.keys))
        for i, key in enumerate(node.keys):
            self.memory.put_bytes(at + F_KEYS + KEY * i, key)
        if node.edges is not None:
            for i, child in enumerate(node.edges):
                write(at + F_EDGES + 8 * i, 8, self.place_node(child, level - 1, at))
        return at

    def place_set(self, spec):
        kind = spec["kind"]
        write = self.memory.write
        if kind == "tree":
            root = spec["root"]
            at = self.place_node(root, spec["height"], 0) if root is not None else 0
            write(SETOBJ_AT, 8, MINW)
            write(SETOBJ_AT + 8, 8, at)
            write(SETOBJ_AT + 0x10, 8, spec["height"])
            write(SETOBJ_AT + 0x18, 8, spec["count"])
        else:
            cap, head, rows = spec["cap"], spec["head"], spec["rows"]
            buf = self.fix_alloc(max(1, cap) * ROW)
            for i, row in enumerate(rows):
                self.memory.put_bytes(buf + ((head + i) % cap) * ROW, row)
            write(SETOBJ_AT, 8, cap)
            write(SETOBJ_AT + 8, 8, buf)
            write(SETOBJ_AT + 0x10, 8, head)
            write(SETOBJ_AT + 0x18, 8, len(rows))

# ---- the rule list (written from the observations, never from the instruction rows) ---------

HEAP_REL = lambda va: va - HEAP_BASE
STATE_REL, BLOCK_REL, IN_REL, OUT_REL = HEAP_REL(STATE_AT), HEAP_REL(BLOCK_AT), HEAP_REL(IN_AT), HEAP_REL(OUT_AT)
VEC_REL, ERRBOX_REL, BOX_REL = HEAP_REL(VEC_AT), HEAP_REL(ERRBOX_AT), HEAP_REL(BOX_AT)
M64 = MASK[8]


def record_bytes(tag, seed):
    if tag == OK_TAG:
        return bytes([tag])
    return bytes([tag]) + Stream(seed).bytes(0x47)


def block_round(block):
    """Which certificate carries the round the stake set is asked for: +0x18 sentinel picks the one at +0x20."""
    a, b, (rx, ry, rz) = block["a"], block["b"], block["rounds"]
    if a == SENT:
        return rx          # certificate at +0x20, round word at +0x60
    return ry if b == SENT else rz   # certificate at +0x18 (round at +0x58) or at +0xa8 (round at +0xe8)


def set_contains(spec, addr, flaws=()):
    if spec["kind"] == "none":
        return False
    if spec["kind"] == "tree":
        if spec["root"] is None:
            return False
        return tree_contains(spec["root"], spec["height"], addr, flaws)
    found, _ = ring_search(spec["rows"], spec["head"], spec["cap"], addr, flaws)
    return found


def signer_events(plan, variant, content, sig_rel, sig8, addr, who_default=None, flaws=()):
    """Events of 0x57e8bd0 after the set found the address: digest, recover, error drop. -> (ok, events)"""
    digest = digest_of(variant, content)
    ev = [("digest", variant, content.hex()), ("recover", sig_rel, sig8.hex(), digest.hex())]
    kind, who = plan["recover"]
    if kind != "ok":
        if "err_not_dropped" not in flaws:
            ev.append(("err_drop", ERRBOX_REL))
        return False, ev
    if "recover_compare_skipped" in flaws:
        return True, ev
    return who == addr, ev

TREE_COUNTS = (0, 1, 2, 5, 10, 11, 12, 13, 22, 23, 30, 60, 100, 133, 143, 144, 145, 200, 400, 900, 1500)
RING_SHAPES = ((1, 0, 0), (1, 0, 1), (2, 1, 2), (3, 2, 3), (4, 1, 4), (5, 3, 5), (7, 6, 7), (8, 5, 3), (9, 8, 9), (12, 7, 12),
               (16, 15, 16), (16, 9, 11), (20, 13, 20), (33, 30, 33), (40, 21, 17))
STAKE_TAGS = (0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x28, 0x00, 0x2F)
VERIFY_TAGS = (0x2E, 0x2E, 0x0C, 0x0D, 0x29, 0x2A, 0x04, 0x05, 0x0F)
QC_TAGS = (0x2E, 0x2E, 0x02, 0x09, 0x07, 0x08)


def universe(count, stream):
    values = sorted({stream.next(60000) for _ in range(count * 2 + 4)})[:count]
    while len(values) < count:
        values.append(60000 + len(values))
    return [addr_of(v) for v in sorted(values)]


def make_set(kind, stream, shape):
    """-> (set spec, keys list). shape picks the size; a `damage` step breaks the sort order on some cases."""
    if kind == "none":
        return {"kind": "none"}, []
    if kind == "tree":
        count = TREE_COUNTS[shape % len(TREE_COUNTS)]
        keys = universe(count, stream)
        damage = stream.next(9) == 0 and count > 3
        walk = list(keys)
        if damage:
            i, j = stream.next(count), stream.next(count)
            walk[i], walk[j] = walk[j], walk[i]
        height = tree_height_for(count)
        root = build_tree(walk, height, stream) if count else None
        return {"kind": "tree", "root": root, "height": height, "count": count, "damage": damage}, keys
    cap, head, length = RING_SHAPES[shape % len(RING_SHAPES)]
    keys = universe(length, stream)
    walk = list(keys)
    damage = stream.next(8) == 0 and length > 2
    if damage:
        i, j = stream.next(length), stream.next(length)
        walk[i], walk[j] = walk[j], walk[i]
    rows = [key + Stream(len(key) + i).bytes(12) for i, key in enumerate(walk)]
    return {"kind": "ring", "cap": cap, "head": head, "rows": rows, "damage": damage}, keys


def pick_addr(stream, keys):
    """present at the front, middle or back; or absent below, between, above."""
    mode = stream.next(6) if keys else 3 + stream.next(3)
    if mode == 0:
        return keys[0]
    if mode == 1:
        return keys[stream.next(len(keys))]
    if mode == 2:
        return keys[-1]
    if mode == 3:
        return addr_of(0) if not keys or keys[0] != addr_of(0) else bytes(KEY)
    if mode == 4:
        base = keys[stream.next(len(keys))] if keys else addr_of(7)
        return base[:KEY - 1] + bytes([(base[-1] + 1) & 0xFF])
    return bytes([0xFF]) * KEY


def make_plan(stream, flavour):
    stakes = (STAKE_TAGS[stream.next(len(STAKE_TAGS))], stream.next(1 << 30))
    verify = (VERIFY_TAGS[stream.next(len(VERIFY_TAGS))], stream.next(1 << 30))
    qc = (QC_TAGS[stream.next(len(QC_TAGS))], stream.next(1 << 30))
    return {"stakes": stakes, "verify": verify, "qc": qc}


def make_recover(stream, addr):
    mode = stream.next(8)
    if mode == 0:
        return ("err", None)
    if mode == 1:
        wrong = bytearray(addr)
        wrong[stream.next(KEY)] ^= 1 << stream.next(8)
        return ("ok", bytes(wrong))
    return ("ok", addr)



# ---------------------------------------------------------------------------------------------
# Node #115 consensus block batch filter 0x2705af0: known-hash lookup, round floor, signed block wrapper, drops.
# ---------------------------------------------------------------------------------------------

BATCH, SEARCH = 0x2705AF0, 0x24C5BA0
ARENA = HEAP_BASE + 0x180000
USED = 0x190000
GOT_ARC = 0x64E4CB8
ITEM = 0x1B0
SEARCH_ROW = 0x198
K32 = 32
LEAF32, INTERNAL32 = 0x1198, 0x11F8
F_LEN32, F_EDGES32 = 0x1192, 0x1198
CERT_AT = HEAP_BASE + 0x1600
CERT_STRIDE = 0x80
ARC_AT = HEAP_BASE + 0x1900
STA_AT = HEAP_BASE + 0x1A80
CLO_AT = HEAP_BASE + 0x1D80
IT_AT = HEAP_BASE + 0x1DC0
ITEMS_AT = HEAP_BASE + 0x2000
BOUT_AT = HEAP_BASE + 0x2C00
BOUT_SIZE = 0x1000
MAX_ITEMS = 6
CERT_REL, ARC_REL, STA_REL, ITEMS_REL, BOUT_REL = (v - HEAP_BASE for v in (CERT_AT, ARC_AT, STA_AT, ITEMS_AT, BOUT_AT))
ACC_VALUE = 0x5A5A1234C0FFEE01
STAKE_TAGS_B = (0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x28, 0x00, 0x2F, 0x10, 0x20, 0x13)
VERIFY_TAGS_B = (0x2E, 0x2E, 0x2E, 0x0C, 0x0D, 0x29, 0x2A, 0x04, 0x10, 0x20, 0x13)
HCAPS = (0, 1, 3, 100, 1 << 40, SENT, MINW + 5, MINW)
CCAPS = (0, 1, 2, 3, 5, 1 << 59, MINW)
ITEM_COUNTS = (0, 1, 1, 2, 2, 3, 3, 4, 5, 6)
GARB = bytes([FILL]) * 0x48


def u64(data, at):
    return struct.unpack_from("<Q", data, at)[0]


def hash_of(value):
    """A 32 byte hash ordered like its integer: 4 big-endian bytes then a sha256 tail."""
    return value.to_bytes(4, "big") + hashlib.sha256(b"h%d" % value).digest()[:K32 - 4]


def rel_of(value):
    if STACK_TOP - STACK_SIZE <= value < STACK_TOP:
        return "stack"
    return value - HEAP_BASE if HEAP_BASE <= value < HEAP_BASE + HEAP_SIZE else value


def record_bytes_b(tag, seed):
    """A 0x48 byte result record: success tag alone, else the tag plus seeded bytes; error tags 0x10/0x20/0x13 own buffers whose capacity words the seed may zero."""
    if tag == OK_TAG:
        return bytes([tag])
    raw = bytearray(bytes([tag]) + Stream(seed).bytes(0x47))
    if tag in (0x10, 0x20, 0x13):
        if seed & 1:
            raw[8:16] = bytes(8)
        if seed & 2:
            raw[0x20:0x28] = bytes(8)
        raw[0x10:0x18] = struct.pack("<Q", 0x3000 + (seed >> 2 & 0xFF) * 16)
        raw[0x28:0x30] = struct.pack("<Q", 0x5000 + (seed >> 10 & 0xFF) * 16)
    return bytes(raw)


class BatchRun(Run):
    """Run with per-call plans for the wrapper contracts, a digest over the block bytes and the Arc drop entry."""

    def __init__(self, image, patches=None, cache=None):
        super().__init__(image, patches, cache)
        machine = self.machine
        fake = MARK_BASE + GOT_ARC
        self.memory.statics[GOT_ARC] = fake
        machine.slots[fake] = self.h_arc
        machine.real.skip.discard(ITER_NEXT)
        machine.real.skip.discard(QC_WRAP)
        machine.calls.pop(ITER_NEXT, None)
        machine.calls.pop(QC_WRAP, None)
        self.wcall = 0

    def reset(self):
        super().reset()
        self.wcall = 0

    def record(self, tag, seed):
        return record_bytes_b(tag, seed)

    def h_arc(self, machine):
        self.log.append(("arc_drop", self.rel(machine.regs[RDI])))

    def h_stakes(self, machine):
        out, state, rnd = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.log.append(("stakes", self.rel(state), rnd))
        self.wcall = (self.memory.read(IT_AT + 8, 8) - ITEMS_AT) // ITEM - 1
        tag, seed = self.plan["stakes"][self.wcall]
        if tag == OK_TAG:
            self.memory.put_bytes(out, bytes([OK_TAG]))
            self.memory.write(out + 8, 8, SETOBJ_AT)
        else:
            self.memory.put_bytes(out, self.record(tag, seed))

    def h_verify(self, machine):
        out, block, state = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.log.append(("verify", self.rel(out), self.rel(block), self.rel(state)))
        tag, seed = self.plan["verify"][self.wcall]
        self.memory.put_bytes(out, self.record(tag, seed))

    def h_digest(self, machine):
        out, msg = machine.regs[RDI], machine.regs[RSI]
        variant = self.memory.read(msg, 8)
        ptr = self.memory.read(msg + 8, 8)
        content = self.memory.bytes_at(ptr, BLOCK_SIZE)
        self.log.append(("digest", variant, content.hex()))
        self.memory.put_bytes(out, digest_of(variant, content))

    def h_recover(self, machine):
        out, sig, digest = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        got = self.memory.bytes_at(digest, 32)
        self.log.append(("recover", self.rel(sig), self.memory.bytes_at(sig, 8).hex(), got.hex()))
        kind, who = self.plan["recover"][self.wcall]
        if kind == "ok":
            self.memory.put_bytes(out, bytes([0]) + who)
        else:
            self.memory.put_bytes(out, bytes([1]))
            self.memory.write(out + 8, 8, ERRBOX_AT)

    def place_node32(self, node, level):
        at = self.fix_alloc(INTERNAL32 if node.edges is not None else LEAF32)
        write = self.memory.write
        write(at + F_LEN32, 2, len(node.keys))
        for i, key in enumerate(node.keys):
            self.memory.put_bytes(at + K32 * i, key)
        if node.edges is not None:
            for i, child in enumerate(node.edges):
                write(at + F_EDGES32 + 8 * i, 8, self.place_node32(child, level - 1))
        return at

    def place_known(self, spec):
        write = self.memory.write
        base = STA_AT + 0x208
        if spec["kind"] == "tree":
            root = spec["root"]
            at = self.place_node32(root, spec["height"]) if root is not None else 0
            write(base, 8, MINW)
            write(base + 8, 8, at)
            write(base + 0x10, 8, spec["height"])
            write(base + 0x18, 8, spec["count"])
        else:
            cap, head, rows = spec["cap"], spec["head"], spec["rows"]
            buf = self.fix_alloc(max(1, cap) * SEARCH_ROW)
            for i, row in enumerate(rows):
                self.memory.put_bytes(buf + ((head + i) % cap) * SEARCH_ROW, row)
            write(base, 8, cap)
            write(base + 8, 8, buf)
            write(base + 0x10, 8, head)
            write(base + 0x18, 8, len(rows))


# ---- the models -------------------------------------------------------------------------------

def ring_search_k(rows, head, cap, key, klen, flaws=()):
    """VecDeque<row>::binary_search_by on the first klen bytes: front slice, back slice, size halving."""
    count = len(rows)
    split = min(count, cap - head) if cap else 0
    front, back = list(rows[:split]), list(rows[split:])

    def bsearch(items):
        size, base = len(items), 0
        if size == 0:
            return False, 0
        while size > 1:
            half = size // 2
            mid = base + half
            keep = memcmp_sign(items[mid][:klen], key) >= 0 if "ring_ge_moves" in flaws else memcmp_sign(items[mid][:klen], key) <= 0
            base = mid if keep else base
            size -= half
        order = memcmp_sign(items[base][:klen], key)
        return (True, base) if order == 0 else (False, base + (order < 0))

    if back:
        order = memcmp_sign(back[0][:klen], key)
        if order == 0:
            return True, len(front)
        if order < 0:
            found, idx = bsearch(back)
            return found, idx + len(front)
    return bsearch(front)


def known_contains(spec, key, flaws=()):
    if spec["kind"] == "tree":
        return spec["root"] is not None and tree_contains(spec["root"], spec["height"], key, flaws)
    return ring_search_k(spec["rows"], spec["head"], spec["cap"], key, K32, flaws)[0]


def round_plus_one(block, flaws=()):
    """The round the floor test sees: +0x50 when the tag word at +0x18 is the sentinel, else +0xa0; plus one, saturating."""
    first, second = (block["t2"], block["t1"]) if "selector_swapped" in flaws else (block["t1"], block["t2"])
    value = first if block["a"] == SENT else second
    if "no_increment" in flaws:
        return value
    value = (value + 1) & M64
    if value == 0 and "wraps_to_zero" not in flaws:
        value = M64
    return value


def wrapper_model(c, i, flaws=()):
    """0x2786870 for item i: (output bytes or None, 0x48 record, events, label)."""
    it = c["items"][i]
    plan, block, addr = it["plan"], it["block"], it["addr"]
    ev = [("stakes", STATE_REL, block_round(block))]
    tag, seed = plan["stakes"]
    label = "stakes_error"
    if tag != OK_TAG:
        rec = record_bytes_b(tag, seed)
    elif not set_contains(c["set"], addr, flaws):
        rec, label = bytes([1]) + GARB[1:], "set_miss"
    else:
        ok, more = signer_events(plan, 0, block["bytes"], "stack", block["bytes"][0x130:0x138], addr, flaws=flaws)
        ev += more
        if not ok:
            rec, label = bytes([1]) + GARB[1:], "recover_error" if plan["recover"][0] != "ok" else "other_address"
        else:
            ev.append(("verify", "stack", "stack", STATE_REL))
            tag, seed = plan["verify"]
            if tag == OK_TAG:
                ev.append(("copy", "stack", "stack", BLOCK_SIZE))
                return block["bytes"], None, ev, "admitted"
            rec, label = record_bytes_b(tag, seed), "verify_error"
    rec = rec + GARB[len(rec):]
    if block["hcap"]:
        ev.append(("free", VEC_REL + 0x40 * i, block["hcap"] << 5 & M64, 0))
    ev.append(("drop_cert", "stack"))
    return None, rec, ev, label


def spec_batch(c, flaws=()):
    """-> ((rax, rdx), out bytes, arc counters, events, mask ranges, per item labels)"""
    ev, out, mask, pos, labels = [], bytearray([FILL]) * BOUT_SIZE, [], 0, []
    arcs = {(i, k): n for i, it in enumerate(c["items"]) for k, n in enumerate(it["arcs"])}
    floor = c["T"]

    def drop_arcs(i, it):
        if "arcs_kept" in flaws:
            return
        for k in range(it["clen"]):
            before = arcs[(i, k)]
            arcs[(i, k)] = before - 1 & M64
            if before == 1:
                ev.append(("arc_drop", CERT_REL + i * CERT_STRIDE + 0x20 + 0x28 * k))

    def free_certs(i, it):
        if it["ccap"]:
            ev.append(("free", CERT_REL + i * CERT_STRIDE, it["ccap"] * (8 if "cert_free_8x" in flaws else 40) & M64, 0))

    def free_hashes(i, it):
        hcap = it["block"]["hcap"]
        if hcap:
            ev.append(("free", VEC_REL + 0x40 * i, hcap if "hash_free_unshifted" in flaws else hcap << 5 & M64, 0))

    def emit(i, it, word0, rest):
        nonlocal pos
        if it["ccap"] == MINW and "niche_emitted" not in flaws:
            return
        out[pos:pos + 0x18] = struct.pack("<QQQ", it["ccap"], CERT_AT + i * CERT_STRIDE, it["clen"])
        out[pos + 0x18:pos + 0x20] = struct.pack("<Q", word0)
        if rest is None:
            mask.append((pos + 0x20, pos + 0x190))
        else:
            out[pos + 0x20:pos + 0x190] = rest
        out[pos + 0x190:pos + 0x1B0] = it["hash"]
        ev.append(("copy", BOUT_REL + pos + 0x20, "stack", 0x170))
        pos += ITEM

    def drop_record(rec):
        tag = rec[0]
        if "record_not_freed" in flaws:
            return
        if tag == 0x10:
            if u64(rec, 8):
                ev.append(("free", rel_of(u64(rec, 0x10)), u64(rec, 8), 0))
            if u64(rec, 0x20):
                ev.append(("free", rel_of(u64(rec, 0x28)), u64(rec, 0x20), 0))
        elif tag == 0x20 or (tag == 0x13 and "tag13_ignored" not in flaws):
            if u64(rec, 8):
                ev.append(("free", rel_of(u64(rec, 0x10)), u64(rec, 8), 0))

    for i, it in enumerate(c["items"]):
        ev.append(("copy", "stack", ITEMS_REL + i * ITEM, ITEM))
        ev.append(("copy", "stack", "stack", BLOCK_SIZE))
        known = False if "known_unchecked" in flaws else known_contains(c["known"], it["hash"], flaws)
        if known:
            free_hashes(i, it)
            ev.append(("drop_cert", "stack"))
            labels.append("known_kept" if it["ccap"] != MINW else "known_niche")
            emit(i, it, MINW + 1 if "known_emits_block" in flaws else MINW, it["block"]["bytes"][8:] if "known_emits_block" in flaws else None)
            continue
        value = round_plus_one(it["block"], flaws)
        if value < floor if "stale_strict" not in flaws else value <= floor:
            drop_arcs(i, it)
            free_certs(i, it)
            free_hashes(i, it)
            ev.append(("drop_cert", "stack"))
            labels.append("stale")
            continue
        ev.append(("copy", "stack", "stack", BLOCK_SIZE))
        wout, rec, wev, label = wrapper_model(c, i, flaws)
        ev += wev
        if wout is not None and u64(wout, 0) != MINW:
            ev.append(("copy", "stack", "stack", 0x170))
            emit(i, it, u64(wout, 0), wout[8:])
            labels.append("admitted" if it["ccap"] != MINW else "admitted_niche")
            continue
        if wout is not None:
            rec, label = wout[8:0x50], "niche_collision"
        drop_record(rec)
        drop_arcs(i, it)
        free_certs(i, it)
        labels.append(label)
    arc_list = tuple(arcs[(i, k)] for i, it in enumerate(c["items"]) for k in range(len(it["arcs"])))
    return (ACC_VALUE, BOUT_REL + pos), bytes(out), arc_list, ev, mask, labels


# ---- cases ------------------------------------------------------------------------------------

KNOWN_TREE_COUNTS = (0, 1, 2, 5, 10, 11, 12, 13, 23, 40, 100, 133, 150, 200)
TREE_COUNTS = (0, 1, 2, 5, 10, 11, 12, 13, 22, 23, 30, 60, 100, 133, 143, 144, 145, 200, 400)
KNOWN_RINGS = ((1, 0, 0), (1, 0, 1), (2, 1, 2), (3, 2, 3), (4, 1, 4), (5, 3, 5), (7, 6, 7), (8, 5, 3), (9, 8, 9), (12, 7, 12),
               (16, 15, 16), (16, 9, 11), (20, 13, 20), (33, 30, 33))


def make_known(stream):
    """The known-hash set at +0x208 of the first state: a B-tree of 32 byte keys or a ring of 0x198 byte rows."""
    kind = ("tree", "ring")[stream.next(2)]
    if kind == "tree":
        count = KNOWN_TREE_COUNTS[stream.next(len(KNOWN_TREE_COUNTS))]
        values = sorted({stream.next(90000) for _ in range(count * 2 + 4)})[:count]
        keys = [hash_of(v) for v in values]
        walk = list(keys)
        damage = stream.next(9) == 0 and count > 3
        if damage:
            a, b = stream.next(count), stream.next(count)
            walk[a], walk[b] = walk[b], walk[a]
        height = tree_height_for(count)
        root = build_tree(walk, height, stream) if count else None
        return {"kind": "tree", "root": root, "height": height, "count": count, "damage": damage}, keys
    cap, head, length = KNOWN_RINGS[stream.next(len(KNOWN_RINGS))]
    values = sorted({stream.next(90000) for _ in range(length * 2 + 4)})[:length]
    keys = [hash_of(v) for v in values]
    walk = list(keys)
    damage = stream.next(8) == 0 and length > 2
    if damage:
        a, b = stream.next(length), stream.next(length)
        walk[a], walk[b] = walk[b], walk[a]
    rows = [key + Stream(i + 17).bytes(SEARCH_ROW - K32) for i, key in enumerate(walk)]
    return {"kind": "ring", "cap": cap, "head": head, "rows": rows, "damage": damage}, keys


def pick_hash(stream, keys):
    mode = stream.next(7) if keys else 3 + stream.next(3)
    if mode in (0, 1) and keys:
        return keys[0] if mode == 0 else keys[stream.next(len(keys))]
    if mode == 2 and keys:
        return keys[-1]
    if mode == 3:
        return hash_of(0) if not keys or keys[0] != hash_of(0) else bytes(K32)
    if mode == 4:
        base = keys[stream.next(len(keys))] if keys else hash_of(7)
        return base[:K32 - 1] + bytes([(base[-1] + 1) & 0xFF])
    if mode == 5:
        return bytes([0xFF]) * K32
    return keys[stream.next(len(keys))] if keys else hash_of(91000 + stream.next(99))


def make_item(stream, i, c):
    keys = c["kkeys"]
    floor = c["T"]
    a = SENT if stream.next(3) else 0x1000 + stream.next(1 << 20)
    b = SENT if stream.next(2) else 0x2000 + stream.next(1 << 20)
    mode = stream.next(9)
    pick = (floor - 1, floor - 2, floor, floor + 7, 0, M64, M64 - 1, stream.next(1 << 40), floor + 1)[mode] & M64
    other = stream.next(1 << 40)
    t1, t2 = (pick, other) if a == SENT else (other, pick)
    rounds = tuple(stream.next(1 << 40) for _ in range(3))
    hcap = HCAPS[stream.next(len(HCAPS))] if stream.next(4) == 0 else (1, 3, 100)[stream.next(3)]
    block = {"a": a, "b": b, "t1": t1, "t2": t2, "rounds": rounds, "hcap": hcap, "sig": stream.bytes(0x41)}
    addr = pick_addr(stream, c["skeys"])
    plan = {"stakes": (STAKE_TAGS_B[stream.next(len(STAKE_TAGS_B))], stream.next(1 << 30)),
            "verify": (VERIFY_TAGS_B[stream.next(len(VERIFY_TAGS_B))], stream.next(1 << 30)), "recover": make_recover(stream, addr)}
    raw = bytearray(Stream(c["seed"] + 99 + i).bytes(BLOCK_SIZE))
    struct.pack_into("<QQQ", raw, 0, hcap, VEC_AT + 0x40 * i, 3)
    struct.pack_into("<Q", raw, 0x18, a)
    struct.pack_into("<Q", raw, 0x50, t1)
    struct.pack_into("<Q", raw, 0x58, rounds[1])
    struct.pack_into("<Q", raw, 0x60, rounds[0])
    struct.pack_into("<Q", raw, 0xA0, t2)
    struct.pack_into("<Q", raw, 0xA8, b)
    struct.pack_into("<Q", raw, 0xE8, rounds[2])
    raw[0x11C:0x130] = addr
    raw[0x130:0x171] = block["sig"]
    block["bytes"] = bytes(raw)
    ccap = CCAPS[stream.next(len(CCAPS))]
    clen = stream.next(4)
    arcs = tuple(1 + stream.next(2) for _ in range(clen))
    hsh = pick_hash(stream, keys)
    return {"block": block, "addr": addr, "plan": plan, "ccap": ccap, "clen": clen, "arcs": arcs, "hash": hsh}


def make_search_case(index):
    """A direct entry of the ring search 0x24c5ba0: a ring of 0x198 byte rows and a 32 byte key."""
    stream = Stream(index * 8 + 3)
    while True:
        known, keys = make_known(stream)
        if known["kind"] == "ring":
            break
    key = pick_hash(stream, keys)
    return {"entry": "search", "index": COUNT + index, "known": known, "kkeys": keys, "key": key, "seed": stream.next(1 << 30)}


def spec_search(c, flaws=()):
    spec = c["known"]
    found, index = ring_search_k(spec["rows"], spec["head"], spec["cap"], c["key"], K32, flaws)
    return (0 if found else 1, index)


def make_case(index):
    if index >= COUNT:
        return make_search_case(index - COUNT)
    stream = Stream(index * 8 + 6)
    c = {"index": index, "seed": stream.next(1 << 30)}
    c["T"] = (0, 1, 5, M64, M64 - 3)[stream.next(5)] if stream.next(5) == 0 else stream.next(1 << 40)
    c["known"], c["kkeys"] = make_known(stream)
    kind = ("tree", "tree", "ring", "ring", "none")[stream.next(5)]
    c["set"], c["skeys"] = make_set(kind, stream, stream.next(64))
    count = ITEM_COUNTS[stream.next(len(ITEM_COUNTS))]
    c["items"] = [make_item(stream, i, c) for i in range(count)]
    c["entry"] = "batch"
    return c


COUNT = 12000
SEARCH_COUNT = 3000
TOTAL = COUNT + SEARCH_COUNT
WORKERS = 4


def all_cases(start=0, stop=TOTAL):
    for index in range(start, stop):
        yield make_case(index)


# ---- one run -----------------------------------------------------------------------------------

def prepare(run, c):
    run.reset()
    run.plan = {"stakes": [it["plan"]["stakes"] for it in c["items"]], "verify": [it["plan"]["verify"] for it in c["items"]],
                "recover": [it["plan"]["recover"] for it in c["items"]]}
    run.fail_at = None
    memory = run.memory
    memory.put_bytes(BOUT_AT, bytes([FILL]) * BOUT_SIZE)
    memory.put_bytes(STATE_AT, Stream(c["seed"] + 7).bytes(0x100))
    memory.write(ERRBOX_AT, 8, VT_AT)
    memory.write(VT_AT, 8, run.err_drop)
    spec = c["set"]
    if spec["kind"] != "none":
        run.place_set(spec)
    else:
        memory.put_bytes(SETOBJ_AT, struct.pack("<QQQQ", 4, 0, 0, 0))
    memory.put_bytes(STA_AT, Stream(c["seed"] + 8).bytes(0x300))
    memory.write(STA_AT + 0x2C8, 8, c["T"])
    run.place_known(c["known"])
    memory.write(CLO_AT, 8, STA_AT)
    memory.write(CLO_AT + 8, 8, STATE_AT)
    memory.put_bytes(IT_AT, Stream(c["seed"] + 9).bytes(0x40))
    count = len(c["items"])
    memory.write(IT_AT + 8, 8, ITEMS_AT)
    memory.write(IT_AT + 0x18, 8, ITEMS_AT + count * ITEM)
    for i, it in enumerate(c["items"]):
        memory.put_bytes(ITEMS_AT + i * ITEM, it["block"]["bytes"] + struct.pack("<QQQ", it["ccap"], CERT_AT + i * CERT_STRIDE, it["clen"]) + it["hash"])
        for k, n in enumerate(it["arcs"]):
            element = CERT_AT + i * CERT_STRIDE + 0x28 * k
            memory.put_bytes(element, Stream(c["seed"] + 40 + 7 * i + k).bytes(0x20))
            memory.write(element + 0x20, 8, ARC_AT + (i * 3 + k) * 0x10)
            memory.write(ARC_AT + (i * 3 + k) * 0x10, 8, n)
    return {RDI: IT_AT, RSI: ACC_VALUE, RDX: BOUT_AT, RCX: CLO_AT}


def read_arcs(run, c):
    return tuple(run.memory.read(ARC_AT + (i * 3 + k) * 0x10, 8) for i, it in enumerate(c["items"]) for k in range(len(it["arcs"])))


def masked(data, ranges):
    out = bytearray(data)
    for low, high in ranges:
        out[low:high] = bytes(high - low)
    return bytes(out)


def execute_search(run, c, after_prepare=None, flaws=()):
    run.reset()
    memory = run.memory
    memory.put_bytes(STA_AT, Stream(c["seed"] + 8).bytes(0x300))
    run.place_known(c["known"])
    memory.put_bytes(ADDR_AT, c["key"])
    if after_prepare is not None:
        after_prepare(run)
    machine = run.machine
    machine.run(SEARCH, {RDI: STA_AT + 0x208, RSI: ADDR_AT})
    spec = c["known"]
    wrapped = spec["head"] + len(spec["rows"]) > spec["cap"]
    found = spec_search(c, flaws)[0] == 0
    c["_labels"] = ["%s_%s" % ("found" if found else "absent", "wrapped" if wrapped else "straight")]
    return (machine.regs[RAX] & M64, machine.regs[RDX] & M64), spec_search(c, flaws)


def execute(run, c, after_prepare=None, flaws=()):
    """-> (observed, predicted) as (return pair, out bytes, arc counters, events)."""
    if c["entry"] == "search":
        return execute_search(run, c, after_prepare, flaws)
    args = prepare(run, c)
    if after_prepare is not None:
        after_prepare(run)
    machine = run.machine
    machine.run(BATCH, args)
    ret = (machine.regs[RAX] & M64, machine.regs[RDX] - HEAP_BASE & M64)
    want_ret, want_out, want_arcs, want_log, ranges, labels = spec_batch(c, flaws)
    out = masked(run.memory.bytes_at(BOUT_AT, BOUT_SIZE), ranges)
    c["_labels"] = labels
    return (ret, out, read_arcs(run, c), tuple(run.log)), (want_ret, masked(want_out, ranges), want_arcs, tuple(want_log))


# ---- rows the rule list is pinned to ---------------------------------------------------------------

SCOPE = {
    BATCH: ("block_batch_filter", "real", "into-iter of 0x1b0 byte items: known-hash lookup, round floor, signed block wrapper, drops, in-place emit"),
    SEARCH: ("known_hash_ring_search", "real", "VecDeque of 0x198 byte rows keyed by 32 bytes: back slice first, size halving search"),
    WRAP_BLOCK: ("signed_block_validate_and_move", "real", "dependency run as bytes: stake set, signer, block rules, move or error plus drops"),
    SIGNER: ("signer_in_set_and_recovered", "real", "dependency run as bytes: slot 0x64e64b8"),
    RING: ("stake_ring_binary_search", "real", "dependency run as bytes: 20 byte keys in 32 byte rows"),
}
OWN = (BATCH, SEARCH)
CONTRACTS = (
    (SLOT_STAKES, "slot 0x64e64b0 -> 0x595e5c0", "stake set for a round: tag 0x2e plus set pointer at +8, or a seeded 0x48 byte error record; per wrapper call"),
    (SLOT_VERIFY, "slot 0x64e64c0 -> 0x59d6b80", "block rules: tag 0x2e writes only byte 0, any other tag a seeded 0x48 byte record; per wrapper call"),
    (SLOT_RECOVER, "GOT 0x64e0ad8", "signature recovery: tag 0 plus a planned 20 byte address, or tag 1 plus a boxed error; per wrapper call"),
    (DIGEST, "direct call", "signing digest: SHA-256 of the variant word and the 0x178 block bytes, written as 32 bytes"),
    (DROP_CERT, "direct call", "drop of the block certificates, recorded"),
    (GOT_ARC, "GOT 0x64e4cb8", "Arc slow drop entry called through r12 when a strong count reaches zero: recorded"),
    (GOT_FREE, "GOT", "sized free: records pointer, size, flags"),
    (GOT_MEMCPY, "GOT", "memcpy: records and copies"),
    (GOT_MEMCMP, "GOT", "memcmp: first differing byte difference"),
) + tuple((slot, "GOT", "panic entry: stops the run") for slot in GOT_PANICS)

RULES = (
    (BATCH, 0x2705B7D, "imm", ITEM, "item size 0x1b0 moved out of the iterator"),
    (BATCH, 0x2705BCB, "imm", BLOCK_SIZE, "block copy of 0x178 bytes"),
    (BATCH, 0x2705C05, "op", "cmp", "known set word 0 against the 0x8000000000000000 niche: tree, else ring"),
    (BATCH, 0x2705C2F, "op", "movzx", "tree node key count u16 at +0x1192"),
    (BATCH, 0x2705C59, "imm", K32, "tree walk compares 32 byte keys"),
    (BATCH, 0x2705C63, "slot", GOT_MEMCMP, "tree walk memcmp"),
    (BATCH, 0x2705CEB, "call", SEARCH, "ring form: binary search 0x24c5ba0"),
    (BATCH, 0x2705D4E, "op", "cmp", "round plus one against the floor word at +0x2c8"),
    (BATCH, 0x2705DB3, "op", "calli", "Arc slow drop through r12"),
    (BATCH, 0x2705E0A, "slot", GOT_FREE, "free of the block hash vector, 32 bytes a row"),
    (BATCH, 0x2705E52, "imm", 0x170, "emit moves 0x170 bytes of the block"),
    (BATCH, 0x2706020, "call", WRAP_BLOCK, "signed block wrapper 0x2786870"),
    (BATCH, 0x27060AA, "imm", 0x170, "success copies 0x170 bytes of the wrapper result"),
    (BATCH, 0x270612B, "slot", GOT_FREE, "error record buffer freed"),
    (BATCH, 0x27061C0, "slot", GOT_FREE, "certificate vector freed, 40 bytes an element"),
    (SEARCH, 0x24C5BD9, "imm", K32, "search compares 32 bytes"),
    (SEARCH, 0x24C5BE2, "slot", GOT_MEMCMP, "search memcmp"),
)


def check_rule(image, rule):
    function, site, kind, expected, _ = rule
    low, high = image.exact_fde(function)
    if not low <= site < high:
        raise EvidenceError("site outside the function: %#x" % site)
    rows = {row.va: row for row in decode_range(image, low, high)}
    row = rows.get(site)
    if row is None:
        raise EvidenceError("site is not an instruction start: %#x" % site)
    if kind == "call":
        ok = row.op == "call" and row.target == expected
    elif kind == "slot":
        ok = row.op == "calli" and row.a[0] == "m" and row.a[1] is None and row.a[4] == expected
    elif kind == "imm":
        ok = row.b is not None and row.b[0] == "i" and row.b[1] & MASK[8] == expected
    else:
        ok = row.op == expected
    if not ok:
        raise EvidenceError("row at %#x does not match the rule" % site)
    return row


# ---- classification, controls, analysis -------------------------------------------------------------

def case_class(c):
    labels = c["_labels"]
    if c["entry"] == "search":
        return "search/" + labels[0]
    return "%s/%s" % (c["known"]["kind"], "+".join(sorted(set(labels))) or "empty")


def digest_of_obs(obs):
    return hashlib.sha256(repr(obs).encode()).digest()[:10]


STATE = {}
MUTANT_CASES = 64
SEARCH_PICKS = 64
FAILURES = (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, struct.error, TypeError, AttributeError, ZeroDivisionError)


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


def mutant_task(job):
    function, va, kind, patch = job
    state = STATE
    run = BatchRun(state["image"], patch, state["cache"])
    run.machine.step_limit = 90000
    for c in state["picked"][function]:
        try:
            got, want = execute(run, c)
        except FAILURES:
            return function, va, kind, "killed", "case:%d" % c["index"]
        if got != want:
            return function, va, kind, "killed", "case:%d" % c["index"]
    return function, va, kind, "survived", "equal on %d picked cases" % len(state["picked"][function])


FLAWS = (
    "known_unchecked", "selector_swapped", "no_increment", "wraps_to_zero", "stale_strict", "known_emits_block", "arcs_kept",
    "record_not_freed", "tag13_ignored", "niche_emitted", "hash_free_unshifted", "cert_free_8x", "tree_reverse", "tree_first_key_only",
    "ring_ge_moves", "err_not_dropped", "recover_compare_skipped",
)


def flaw_chunk(job):
    flaw, start, stop = job
    digests = STATE["digests"]
    for index in range(start, stop):
        c = make_case(index)
        if c["entry"] == "search":
            want = spec_search(c, (flaw,))
        else:
            ret, out, arcs, log, ranges, _ = spec_batch(c, (flaw,))
            want = (ret, masked(out, ranges), arcs, tuple(log))
        if digest_of_obs(want) != digests[index]:
            return flaw, index
    return flaw, -1


def poke(address, mask=1):
    def action(run):
        run.memory.write(address, 1, run.memory.read(address, 1) ^ mask)
    return action


def selector_matters(c):
    """The first block's tag word is the sentinel and the other round word gives the opposite floor decision."""
    if not c["items"] or c["_labels"][0] in ("known_kept", "known_niche"):
        return False
    block = c["items"][0]["block"]
    if block["a"] != SENT:
        return False
    return (round_plus_one(block) < c["T"]) != (round_plus_one(dict(block, a=0)) < c["T"])


def poke_known_row(c):
    """Flip the first key byte of the ring row that holds the first item's hash."""
    key = c["items"][0]["hash"]
    index = next(j for j, row in enumerate(c["known"]["rows"]) if row[:K32] == key)

    def action(run):
        base = STA_AT + 0x208
        buf, head, cap = (run.memory.read(base + 8, 8), run.memory.read(base + 0x10, 8), run.memory.read(base, 8))
        at = buf + ((head + index) % cap) * SEARCH_ROW
        run.memory.write(at, 1, run.memory.read(at, 1) ^ 1)
    return action


CORRUPTIONS = (
    ("hash byte of a known first item", lambda c: poke(ITEMS_AT + 0x190), lambda c: c["_labels"][:1] == ["known_kept"]),
    ("key byte of the matching known row", lambda c: poke_known_row(c), lambda c: c["known"]["kind"] == "ring" and c["_labels"][:1] == ["known_kept"] and not c["known"]["damage"]),
    ("floor word of the first state, high bit", lambda c: poke(STA_AT + 0x2CF, 0x80),
     lambda c: bool(c["items"]) and c["_labels"][0] not in ("known_kept", "known_niche", "stale") and round_plus_one(c["items"][0]["block"]) < M64 and c["T"] < 1 << 63),
    ("tag word of the first block", lambda c: poke(ITEMS_AT + 0x18), selector_matters),
    ("signature byte of the first block", lambda c: poke(ITEMS_AT + 0x130), lambda c: c["_labels"][:1] == ["admitted"]),
    ("certificate length of the first item", lambda c: poke(ITEMS_AT + 0x188, 3), lambda c: c["_labels"][:1] == ["stale"] and c["items"][0]["clen"] in (1, 2)),
    ("iterator end word", lambda c: poke(IT_AT + 0x18, 0x40), lambda c: len(c["items"]) >= 2),
    ("block address byte of the first item", lambda c: poke(ITEMS_AT + 0x11C), lambda c: c["_labels"][:1] == ["admitted"]),
)
CORRUPT_PER_KIND = 6


def corrupt_task(job):
    label, index, which = job
    c = make_case(index)
    run = STATE["corrupt_run"]
    action = CORRUPTIONS[which][1](c)
    try:
        got, want = execute(run, c, after_prepare=action)
    except FAILURES:
        return label, index, True
    return label, index, got != want


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
    attempt("address inside a function, not an FDE start", lambda: image.exact_fde(BATCH + 1))
    attempt("address outside every FDE", lambda: image.fde(0x100))
    attempt("address outside every file-backed section", lambda: image.offset(0x10))
    for rule in RULES:
        function, site, kind, expected, text = rule
        attempt("rule %#x moved one byte" % site, lambda rule=rule: check_rule(image, (rule[0], rule[1] + 1) + rule[2:]))
        wrong = expected ^ 2 if isinstance(expected, int) else "mov"
        attempt("rule %#x with another expectation" % site, lambda rule=rule, wrong=wrong: check_rule(image, rule[:3] + (wrong,) + rule[4:]))
    return rows


SAMPLE_EVERY = 6


def function_rows(image, reached):
    table = {}
    for target in sorted(SCOPE):
        low, high = image.exact_fde(target)
        rows = decode_range(image, low, high)
        table[target] = (low, high, rows, [row for row in rows if row.va in reached])
    return table


def case_chunk(job):
    start, stop = job
    run = STATE["run"]
    tally, items, digests, classes, sample, mismatches = collections.Counter(), collections.Counter(), [], [], [], []
    steps = 0
    hits = collections.Counter()
    for c in all_cases(start, stop):
        run.machine.seen = set()
        got, want = execute(run, c)
        hits.update(run.machine.seen)
        steps = max(steps, run.machine.steps)
        index = c["index"]
        if got != want:
            mismatches.append(index)
        label = case_class(c)
        tally[label] += 1
        if c["entry"] != "search":
            for item in c["_labels"]:
                items[item] += 1
        digests.append(digest_of_obs(want))
        classes.append(label)
        if c["entry"] == "search":
            continue
        if index % SAMPLE_EVERY == 0:
            known = c["known"]
            size = known.get("count", len(known.get("rows", ())))
            sample.append((index, label, known["kind"], size, "damaged" if known.get("damage") else "sorted", len(c["items"]),
                           hex(got[0][1]), hashlib.sha256(got[1]).hexdigest()[:12], len(got[3])))
    return tally, items, digests, classes, sample, mismatches, hits


def analyse(image, workers=WORKERS):
    run = BatchRun(image)
    STATE.clear()
    STATE.update(image=image, run=run)
    context = multiprocessing.get_context("fork")
    step = 250
    jobs = [(a, min(a + step, TOTAL)) for a in range(0, TOTAL, step)]
    with context.Pool(workers) as pool:
        parts = pool.map(case_chunk, jobs)
    tally, items, digests, classes, sample, mismatches, hits = collections.Counter(), collections.Counter(), [], [], [], [], collections.Counter()
    for t, it, dg, cl, sa, mi, seen in parts:
        tally.update(t)
        items.update(it)
        digests += dg
        classes += cl
        sample += sa
        mismatches += mi
        hits.update(seen)
    reached = set(hits)
    STATE.update(cache=dict(run.machine.cache), digests=digests, corrupt_run=BatchRun(image, None, run.machine.cache))
    functions = function_rows(image, reached)
    picked = {}
    groups = collections.defaultdict(list)
    for index, label in enumerate(classes):
        groups[label].append(index)

    def spread(prefix, limit):
        queues = [groups[key][::max(1, len(groups[key]) // 4)] for key in sorted(groups) if key.startswith(prefix)]
        chosen = []
        while queues and len(chosen) < limit:
            for queue in list(queues):
                chosen.append(queue.pop(0))
                if not queue:
                    queues.remove(queue)
                if len(chosen) == limit:
                    break
        return chosen

    picked[BATCH] = [make_case(index) for index in sorted(set(spread("tree/", MUTANT_CASES // 2) + spread("ring/", MUTANT_CASES // 2)))]
    picked[SEARCH] = [make_case(index) for index in sorted(set(spread("ring/", MUTANT_CASES // 2) + spread("search/", MUTANT_CASES)))]
    STATE["picked"] = picked
    jobs = []
    for function in OWN:
        low, high, rows, _ = functions[function]
        for va, kind, patch in edits_for(image, [row for row in rows if row.va in reached]):
            jobs.append((function, va, kind, patch))
    corrupt_jobs = []
    for which, (label, _, ok) in enumerate(CORRUPTIONS):
        pool_cases = []
        for index in range(0, COUNT, 7):
            c = make_case(index)
            c["_labels"] = labels_of(index)
            if ok(c):
                pool_cases.append(index)
            if len(pool_cases) >= 60:
                break
        stride = max(1, len(pool_cases) // CORRUPT_PER_KIND)
        for index in pool_cases[::stride][:CORRUPT_PER_KIND]:
            corrupt_jobs.append((label, index, which))
    with context.Pool(workers) as pool:
        mutants = sorted(pool.map(mutant_task, jobs, chunksize=4))
        flaw_jobs = [(flaw, a, min(a + 2000, TOTAL)) for flaw in FLAWS for a in range(0, TOTAL, 2000)]
        flaw_parts = pool.map(flaw_chunk, flaw_jobs)
        corrupt = sorted(pool.map(corrupt_task, corrupt_jobs))
    flaws = []
    for flaw in FLAWS:
        found_at = [index for f, index in flaw_parts if f == flaw and index >= 0]
        flaws.append((flaw, bool(found_at), "case:%d" % min(found_at) if found_at else ""))
    ranges = range_controls(image)
    pins = [(rule, check_rule(image, rule)) for rule in RULES]
    return dict(total=TOTAL, tally=tally, items=items, sample=sorted(sample), mismatches=sorted(mismatches), reached=reached, functions=functions,
                mutants=mutants, flaws=flaws, corrupt=corrupt, ranges=ranges, pins=pins, steps=0, hits=hits)


def labels_of(index):
    """Item labels of a case, from the rule list alone."""
    c = make_case(index)
    return spec_batch(c)[5]


def scan_callers(image):
    """Every e8 / e9 rel32 to the two scope functions with the containing FDE."""
    base, text = image.text_bytes()
    direct = {BATCH, SEARCH}
    rows = []
    for match in re.finditer(rb"[\xe8\xe9]", text):
        at = match.start()
        if at + 5 > len(text):
            continue
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in direct:
            rows.append(("direct", base + at, "call" if text[at] == 0xE8 else "jmp", hex(target)))
    out = []
    for kind, site, what, target in sorted(rows):
        try:
            low, high = image.fde(site)
            home = "%#x..%#x" % (low, high)
        except EvidenceError:
            home = "none"
        out.append((kind, hex(site), what, target, home))
    return out


def tsv(header, rows):
    return "\n".join(["\t".join(header)] + ["\t".join(str(x) for x in row) for row in rows]) + "\n"


def render(result, image):
    files = {}
    rows = [("case", k, n) for k, n in sorted(result["tally"].items())] + [("item", k, n) for k, n in sorted(result["items"].items())]
    files["outcomes.tsv"] = tsv(("scope", "class", "count"), rows)
    rows = []
    for target in sorted(SCOPE):
        low, high, all_rows, hit = result["functions"][target]
        rows.append((hex(target), hex(high), high - low, len(all_rows), len(hit), SCOPE[target][0], SCOPE[target][2]))
    files["functions.tsv"] = tsv(("function", "end", "bytes", "instructions", "reached_instructions", "name", "role"), rows)
    files["stubs.tsv"] = tsv(("target", "kind", "contract"), [(hex(a), b, c) for a, b, c in CONTRACTS])
    files["gates.tsv"] = tsv(("function", "site", "kind", "expected", "rule"),
                             [(hex(r[0]), hex(r[1]), r[2], hex(r[3]) if isinstance(r[3], int) else r[3], r[4]) for r, _ in result["pins"]])
    rows = []
    for target in OWN:
        counts = collections.Counter()
        for row in result["functions"][target][2]:
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4] < 0x1400:
                    counts[operand[4]] += 1
        for disp in sorted(counts):
            rows.append((hex(target), hex(disp), counts[disp]))
    files["layouts.tsv"] = tsv(("function", "displacement", "rows"), rows)
    rows = []
    for target in OWN:
        for row in result["functions"][target][2]:
            rows.append((hex(target), hex(row.va), row.op, row.size, result["hits"].get(row.va, 0)))
    files["coverage.tsv"] = tsv(("function", "row", "op", "size", "cases_reaching_row"), rows)
    files["callers.tsv"] = tsv(("kind", "site", "what", "target", "containing_fde"), scan_callers(image))
    files["cases.tsv"] = tsv(("index", "class", "known", "size", "order", "items", "rdx", "out_sha256_12", "events"), result["sample"])
    files["mutations.tsv"] = tsv(("function", "row", "kind", "result", "witness"), [(hex(f), hex(v), k, r, w) for f, v, k, r, w in result["mutants"]])
    files["flaws.tsv"] = tsv(("flaw", "detected", "first_case"), [(f, "yes" if d else "NO", w) for f, d, w in result["flaws"]])
    controls = [(name, "yes" if ok else "NO") for name, ok in result["ranges"]]
    controls += [("%s, case %d" % (label, index), "yes" if ok else "NO") for label, index, ok in result["corrupt"]]
    files["controls.tsv"] = tsv(("control", "detected"), controls)
    killed = sum(1 for m in result["mutants"] if m[3] == "killed")
    detected = sum(1 for _, d, _ in result["flaws"] if d) + killed + sum(1 for r in result["corrupt"] if r[2]) + sum(1 for _, ok in result["ranges"] if ok)
    negatives = len(result["flaws"]) + killed + len(result["corrupt"]) + len(result["ranges"])
    reached_rows = sum(len(result["functions"][t][3]) for t in OWN)
    all_rows = sum(len(result["functions"][t][2]) for t in OWN)
    metrics = {"cases": result["total"], "mismatches": len(result["mismatches"]), "negative_controls": negatives, "negative_detected": detected,
               "mutants_run": len(result["mutants"]), "mutants_killed": killed, "mutants_survived": len(result["mutants"]) - killed,
               "instructions": all_rows, "instructions_reached": reached_rows, "flaws": len(result["flaws"]),
               "corruptions": len(result["corrupt"]), "range_controls": len(result["ranges"]), "rules": len(result["pins"])}
    files["measure.json"] = json.dumps({k: metrics[k] for k in ("cases", "negative_controls", "negative_detected")} | {"mismatches": metrics["mismatches"]},
                                       indent=1, sort_keys=True) + "\n"
    files["evidence.json"] = json.dumps({"binary_sha256": SHA256, "metrics": metrics}, indent=1, sort_keys=True) + "\n"
    return files, metrics


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    image = load_image()
    result = analyse(image)
    files, metrics = render(result, image)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (out / name).write_text(text)
    print(json.dumps(metrics, sort_keys=True))
    return 0 if metrics["mismatches"] == 0 and metrics["negative_detected"] == metrics["negative_controls"] else 1


if __name__ == "__main__":
    sys.exit(main())
