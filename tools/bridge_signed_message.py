#!/usr/bin/env python3
"""Evaluate the node #94 Bridge2 signed message from ELF bytes: payload arms, ABI words, the Bridge2 address, the Agent struct and the final EIP-712 digest.

`0x358ea60` turns a bridge payload into the phantom Agent request and `0x37f2940` turns that request into the digest that validators sign. The real bytes of both run in
a Python evaluator, down through the eight payload arms of `0x358de50`, the two set adapters, the token encoders, the ABI writer `0x1592160` and the Keccak sponge. A
separately written specification predicts every message, and conditions, immediates and offsets of the fresh functions are flipped to show the run can tell. No objdump or
readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import collections
import hashlib
import json
import math
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_BCMP = 0x576E378
SLOT_MEMCMP = 0x576E488
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMSET = 0x576E1C0
SLOT_REALLOC = 0x576E030
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576DFB8, 0x576E108, 0x576E020, 0x576E118, 0x576E1B0)

BUILD = 0x358EA60
PAYLOAD_HASH = 0x358DE50
ARMS = 0x58F650
DIGEST = 0x37F2940
TYPED_HASH = 0x38EFF30
ADDRESS_LOOKUP = 0x1405240
ENCODE_PAIR = 0x3814080
TEMPLATE = 0x200E12
PREFIX_1901 = 0x5A6048
ABSORB = 0x4F59A10
KECCAK_F = 0x4F59480
BOOK = 0x1405720
FILE_CHECK = 0x144A710
FILE_PARSE = 0x144E940
CONFIG = 0x577B288
OVERLAY_ONCE = 0x577AB98
NONE_LOCATION = 0x56EE700
SLOT_BUILD = 0x5775DA8
MODIFY_TEMPLATE = 0x1FC3DD
BUILD_CALLERS = ((0x374E916, 0x374E8FF, "c644241004"), (0x374ED3D, 0x374ED2B, "c6042405"))
BOOK_SITES = ((0x1405763, 0x140576A, 2, 12), (0x1405786, 0x140578D, 2, 14), (0x1405878, 0x140587F, 3, 14), (0x140589B, 0x14058A2, 3, 12))
MUTANT_STEP_LIMIT = 200000
MUTANT_CASES = 12
ARM_TEXT = (("modifyLocker or modifyFinalizer", "string, address, bool, uint"), ("changeDisputePeriodSeconds", "string, uint, uint"), ("changeBlockDurationMillis", "string, uint, uint"),
            ("changeLockerThreshold", "string, uint, uint"), ("updateValidatorSet", "string, uint, address[], address[], uint[]"), ("requestWithdrawal", "string, address, address, uint, uint"),
            ("unlock", "string, uint, address[], address[], uint[], uint"), ("invalidateWithdrawals", "string, bytes32[], uint"))
MUTATED = ((BUILD, "request builder"), (PAYLOAD_HASH, "payload hash, eight arms"), (0x37DB5D0, "arm 4 hash"), (0x37DB0D0, "set adapter, reverse walk into three lists"),
           (0x3C97DE0, "arm 0 tokens"), (0x3C97A70, "arms 1 to 3 tokens"), (0x3C99DF0, "arm 4 tokens"), (0x3C9A570, "arm 5 tokens"), (0x3C9F240, "arm 6 tokens"), (0x3C97BE0, "arm 7 tokens"),
           (ENCODE_PAIR, "address and hash pair"), (0x365E370, "role name"), (0x1650530, "chain name"), (DIGEST, "digest wrapper"), (TYPED_HASH, "typed hash"), (0x13F13D0, "Agent struct hash"),
           (0x38139C0, "byte concat"), (BOOK, "contract book builder"), (0x14CA560, "name and address parse"), (0x14CBD80, "namespace insert"), (0x14BF3A0, "namespace map from pairs"))
EXTRA_FUNCTIONS = ((0x1594080, "domain separator, run with no mutants: its other arms need other domain shapes"), (0x1592160, "ABI writer, listed in #964 and #394, run with no mutants"), (0x1592460, "ABI head size, run with no mutants"),
                   (0x15924E0, "ABI tail size, run with no mutants"), (0x158FB50, "token sort, run with no mutants"), (0x158FC70, "token iterator, run with no mutants"), (0x1591F20, "token writer, run with no mutants"),
                   (ABSORB, "Keccak absorb, in #154, run with no mutants"), (0x4F59E40, "Keccak squeeze, in #154, run with no mutants"), (KECCAK_F, "Keccak permutation, run with no mutants"))

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF, 16: (1 << 128) - 1}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x10000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x100000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 4000000

OUT = HEAP_BASE + 0x400
OUT2 = HEAP_BASE + 0x480
PAYLOAD_AT = HEAP_BASE + 0x500
NODES_AT = HEAP_BASE + 0x1000
HEAP_FREE = HEAP_BASE + 0x8000


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

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/", "/base/", "/chrono-"):
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
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {0: "rol", 4: "shl", 5: "shr", 7: "sar"}


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
        elif byte not in (0x2E, 0x64):
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
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x90:
        return finish("nop")
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
            return finish("pushi", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x6C, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1)
            if value != 0:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd", ("x", reg), rm, 8)
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
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, width)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
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
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0x3F
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAF:
            reg, rm = modrm()
            return finish("imul2", ("r", reg), rm, width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("bt", rm, ("r", reg), width)
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
        self.tails = {}
        self.real = frozenset()
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.steps = 0
        self.keep_rdx = False
        self.keep_float = False
        self.step_limit = STEP_LIMIT
        self.watch = {}

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
        self.keep_rdx = self.keep_float = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        kept = self.xmm[0]
        self.xmm = [POISON | POISON << 64] * 16
        if self.keep_float:
            self.xmm[0] = kept

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
                if self.read_code(pc, 1)[0] == 0x64:
                    raise Halt("thread local read at %#x" % pc)
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
        elif op == "pushi":
            self.push(self.get(row.a, 8))
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
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            right = self.get(row.a, 8)
            right = right - (1 << 64) if right & SIGN[8] else right
            product = (left * right) & ((1 << 128) - 1)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
        elif op == "jmp":
            hook = self.tails.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
            return row.target
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                if target in self.watch:
                    self.watch[target](self)
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.call_site = row.va
            self.call_target = target
            self.stub(hook)
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            if target not in self.real:
                raise Halt("indirect jump out of the text at %#x" % row.va)
            return target
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (self.regs[row.b[1]] & (8 * width - 1)) & 1)
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
        elif op in ("shl", "shr", "sar", "rol"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "rol":
                result = (value << count | value >> (8 * width - count)) & MASK[width]
            elif op == "shl":
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
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            left, right = self.get(row.a, width), self.get(row.b, width)
            left = left - (1 << (8 * width)) if left & SIGN[width] else left
            right = right - (1 << (8 * width)) if right & SIGN[width] else right
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op == "nop":
            pass
        elif op == "shld":
            count = row.target
            if count:
                self.put(row.a, width, self.get(row.a, width) << count | self.get(row.b, width) >> (8 * width - count))
        elif op == "bswap":
            self.regs[row.a[1]] = int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big")
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
                self.xmm[row.a[1]] = self.low(row.b) if row.b[0] != "r" else self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "cmpeqsd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left == right else 0)
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "divsd":
                result = left / right if right else math.copysign(math.inf, left) * math.copysign(1.0, right) if left == left and left else math.nan
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
            value = self.get(row.b, row.width)
            self.set_low(row.a[1], to_bits(float(value - (1 << (8 * row.width)) if value & SIGN[row.width] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "andnpd":
            self.xmm[row.a[1]] = (~self.xmm[row.a[1]] & ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpcklpd":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((((left >> (8 * at)) & 0xFF) | ((right >> (8 * at)) & 0xFF) << 8) << (16 * at) for at in range(8))
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = sum(((source >> (16 * ((row.target >> (2 * at)) & 3))) & 0xFFFF) << (16 * at) for at in range(4))
            self.xmm[row.a[1]] = (source >> 64) << 64 | words
        elif op == "pshufd":
            source = self.vector(row.b)
            self.xmm[row.a[1]] = sum(((source >> (32 * ((row.target >> (2 * at)) & 3))) & MASK[4]) << (32 * at) for at in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            bits = 8 * size
            self.xmm[row.a[1]] = sum((MASK[size] if (left >> at) & MASK[size] == (right >> at) & MASK[size] else 0) << at for at in range(0, 128, bits))
        elif op == "pmovmskb":
            source = self.xmm[row.b[1]]
            self.put(row.a, 4, sum(((source >> (8 * at + 7)) & 1) << at for at in range(16)))
        elif op == "tzcnt":
            value = self.get(row.b, row.width)
            result = 8 * row.width if value == 0 else (value & -value).bit_length() - 1
            self.cf = value == 0
            self.zf = result == 0
            self.put(row.a, row.width, result)
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


# ---- specification: written from the reading notes, it never looks at the evaluator ----

ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)
ROTATIONS = (1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44)
LANES = (10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1)
MASK64 = (1 << 64) - 1


def keccak_f(state):
    for constant in ROUND_CONSTANTS:
        columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        for x in range(5):
            right = columns[(x + 1) % 5]
            mixed = columns[(x + 4) % 5] ^ ((right << 1 | right >> 63) & MASK64)
            for y in range(0, 25, 5):
                state[y + x] ^= mixed
        last = state[1]
        for lane, turn in zip(LANES, ROTATIONS):
            state[lane], last = (last << turn | last >> (64 - turn)) & MASK64, state[lane]
        for y in range(0, 25, 5):
            row = state[y:y + 5]
            for x in range(5):
                state[y + x] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5] & MASK64)
        state[0] ^= constant


def keccak(data):
    rate = 136
    padded = bytearray(data) + b"\x01" + bytes((-len(data) - 1) % rate)
    padded[-1] |= 0x80
    state = [0] * 25
    for start in range(0, len(padded), rate):
        for at in range(rate // 8):
            state[at] ^= int.from_bytes(padded[start + 8 * at:start + 8 * at + 8], "little")
        keccak_f(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


def word(value):
    return value.to_bytes(32, "big")


def pad_right(data):
    return data + bytes(-len(data) % 32)


def is_dynamic(token):
    return token[0] in ("string", "array")


def abi_head_size(token):
    return 32


def abi_body(token):
    kind = token[0]
    if kind == "string":
        return word(len(token[1])) + pad_right(token[1])
    if kind == "array":
        return word(len(token[1])) + abi_encode(token[1])
    raise EvidenceError("not a dynamic token")


def abi_static(token):
    kind = token[0]
    if kind == "address":
        return bytes(12) + token[1]
    if kind == "uint":
        return word(token[1])
    if kind == "bool":
        return word(1 if token[1] else 0)
    if kind == "bytes32":
        return token[1]
    raise EvidenceError("not a static token")


def abi_encode(tokens):
    offset = 32 * len(tokens)
    heads, tails = [], []
    for token in tokens:
        if is_dynamic(token):
            heads.append(word(offset))
            body = abi_body(token)
            tails.append(body)
            offset += len(body)
        else:
            heads.append(abi_static(token))
    return b"".join(heads) + b"".join(tails)


def rows_tokens(rows):
    rows = rows[::-1]
    return [("array", [("address", row["hot"]) for row in rows]), ("array", [("address", row["cold"]) for row in rows]),
            ("array", [("uint", row["power"]) for row in rows])]


def payload_tokens(payload):
    kind = payload["arm"]
    if kind == 0:
        name = b"modify" + ROLE_NAMES[payload["role"]]
        return [("string", name), ("address", payload["validator"]), ("bool", payload["active"]), ("uint", payload["nonce"])]
    if kind in SIMPLE_ARMS:
        return [("string", SIMPLE_ARMS[kind]), ("uint", payload["value"]), ("uint", payload["nonce"])]
    if kind == 4:
        return [("string", b"updateValidatorSet"), ("uint", payload["epoch"])] + rows_tokens(payload["rows"])
    if kind == 5:
        return [("string", b"requestWithdrawal"), ("address", payload["account"]), ("address", payload["destination"]),
                ("uint", payload["amount"]), ("uint", payload["nonce"])]
    if kind == 6:
        return [("string", b"unlock"), ("uint", payload["epoch"])] + rows_tokens(payload["rows"]) + [("uint", payload["nonce"])]
    if kind == 7:
        return [("string", b"invalidateWithdrawals"), ("array", [("bytes32", item) for item in payload["ids"]]), ("uint", payload["nonce"])]
    raise EvidenceError("arm")


ROLE_NAMES = {0: b"Locker", 1: b"Finalizer"}
SIMPLE_ARMS = {1: b"changeDisputePeriodSeconds", 2: b"changeBlockDurationMillis", 3: b"changeLockerThreshold"}
CHAIN_NAMES = ("Local", "Sandbox", "Testnet", "Mainnet")
AGENT_TYPE = b"Agent(string source,bytes32 connectionId)"
DOMAIN_TYPE = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"


def expected_digest(source, connection, chain_id):
    domain_input = abi_encode([("bytes32", keccak(DOMAIN_TYPE)), ("bytes32", keccak(b"Exchange")), ("bytes32", keccak(b"1")), ("uint", chain_id), ("address", bytes(20))])
    domain = keccak(domain_input)
    struct_input = abi_encode([("bytes32", keccak(AGENT_TYPE)), ("bytes32", keccak(source)), ("bytes32", connection)])
    agent = keccak(struct_input)
    final = b"\x19\x01" + domain + agent
    return {"source": source, "domain_input": domain_input, "domain": domain, "struct_input": struct_input, "agent": agent, "final_input": final, "digest": keccak(final)}


def expected_messages(payload, chain, book):
    """The ordered hash inputs of one request and its digest, and the final results."""
    chain_id = 42161 if chain == 3 else 421614
    namespace = 2 if chain == 3 else 3
    contract = book[(namespace, (b"Bridge2" + CHAIN_NAMES[chain].encode()).ljust(16, b"\0"))]
    first = abi_encode(payload_tokens(payload))
    payload_hash = keccak(first)
    second = abi_encode([("address", contract), ("bytes32", payload_hash)])
    connection = keccak(second)
    result = expected_digest(b"a", connection, chain_id)
    result.update(payload_input=first, payload_hash=payload_hash, pair_input=second, connection=connection, chain_id=chain_id, contract=contract)
    return result


NAMESPACE_FILES = ("Localhost", "Mainnet", "Arbitrum", "ArbitrumTestnet", "Optimism", "Base", "HlUnitTest", "HlLocal", "HlSandbox", "HlTestnet", "HlMainnet")
SPEC_BOOK = {2: (("Usdc2Mainnet", "af88d065e77c8cc2239327c5edb3a432268e5831"), ("Bridge2Mainnet", "2df1c51e09aecf9cacb7bc98cb1742757f163df7")),
             3: (("Bridge2Testnet", "08cfc1b6b2dcf36a1480b99353a354aa8ac56f89"), ("Usdc2Testnet", "1baabb04529d43a73232b713c0fe471f7c7334d5"))}


def expected_book(files=None):
    """A contract file replaces the whole table of its namespace; a namespace with no built in table gains one."""
    tables = {namespace: [(name, value) for name, value in rows] for namespace, rows in SPEC_BOOK.items()}
    for number, name in enumerate(NAMESPACE_FILES):
        if files and name in files:
            tables[number] = [(key, value.hex()) for key, value in files[name]]
    rows = []
    for namespace, table in tables.items():
        rows += [(namespace, key, value) for key, value in table] if table else [(namespace, "", "")]
    return {"files": ["home/contract_addresses/%s.json" % name for name in NAMESPACE_FILES], "rows": sorted(rows)}


# ---- harness: real bytes through the text section; allocator, memory calls and the address lookup are stubbed ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_BCMP: self.on_bcmp, SLOT_MEMCMP: self.on_bcmp, SLOT_REALLOC: self.on_realloc, SLOT_MEMMOVE: self.on_copy}
        for slot in SLOT_PANIC:
            table[slot] = lambda m, which=slot: self.on_panic(m, which)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        calls = {ADDRESS_LOOKUP: self.on_lookup, FILE_PARSE: self.on_parse}
        machine.calls = calls
        machine.tails = calls
        machine.slots[ADDRESS_LOOKUP] = self.on_lookup
        machine.slots[FILE_CHECK] = self.on_file
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)
        self.book = {}
        self.book_base = {}
        self.files = []
        self.file_rows = {}
        machine.watch = {ABSORB: self.on_absorb}
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.absorbed = []

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def on_malloc(self, m):
        size = m.regs[RDI]
        if size > 0x40000:
            raise Halt("allocation size %#x at %#x" % (size, m.memory.read(m.regs[RSP], 8)))
        m.regs[RAX] = self.allocate(size)

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_realloc(self, m):
        regs = m.regs
        old, new = regs[RDI], regs[RSI]
        if old not in self.live:
            raise Halt("realloc %#x" % old)
        size = self.live.pop(old)
        at = self.allocate(new)
        m.memory.copy(at, old, min(size, new))
        regs[RAX] = at

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x8000:
            raise Halt("copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_bcmp(self, m):
        regs = m.regs
        left, right = m.memory.bytes_at(regs[RDI], regs[RDX]), m.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[8])

    def on_panic(self, m, slot):
        raise Panicked("slot %#x location %#x" % (slot, m.regs[RDI]))

    def on_file(self, m):
        name = m.memory.bytes_at(m.regs[RDI], m.regs[RSI])
        self.files.append(name)
        m.regs[RAX] = 1 if name.decode("ascii").rsplit("/", 1)[1][:-5] in self.file_rows else 0

    def on_parse(self, m):
        regs = m.regs
        out = regs[RDI]
        rows = self.file_rows[m.memory.bytes_at(regs[RSI], regs[RDX]).decode("ascii").rsplit("/", 1)[1][:-5]]
        if rows is None:
            m.memory.write(out, 4, 1)
            return
        m.memory.write(out, 4, 0)
        root = 0
        if rows:
            root = self.allocate(0x1A0)
            m.memory.put_bytes(root, bytes(0x1A0))
            m.memory.write(root + 0x196, 2, len(rows))
            for index, (name, value) in enumerate(rows):
                m.memory.put_bytes(root + 0x10 * index, name.encode("ascii").ljust(16, b"\0"))
                m.memory.put_bytes(root + 0xB8 + 0x14 * index, value)
        m.memory.write(out + 8, 8, root)
        m.memory.write(out + 0x10, 8, 0)
        m.memory.write(out + 0x18, 8, len(rows))

    def on_keccak_f(self, m):
        at = m.regs[RDI]
        state = [m.memory.read(at + 8 * index, 8) for index in range(25)]
        keccak_f(state)
        m.memory.put_bytes(at, b"".join(lane.to_bytes(8, "little") for lane in state))

    def fast(self, on):
        """Use the specification permutation; the sponge step alone costs 90 percent of the steps."""
        machine = self.machine
        if on:
            machine.slots[KECCAK_F] = self.on_keccak_f
        else:
            machine.slots.pop(KECCAK_F, None)
        self.real.stubs = frozenset(machine.slots) | frozenset(machine.calls)

    def on_lookup(self, m):
        regs = m.regs
        out, low, high, key = regs[RDI], regs[RSI], regs[RDX], regs[RCX] & 0xFF
        name = (low | high << 64).to_bytes(16, "little")
        self.log.append(["lookup", key, name.hex()])
        hit = self.book.get((key, name))
        if hit is None:
            m.memory.write(out, 1, 0)
            return
        m.memory.write(out, 1, 1)
        m.memory.put_bytes(out + 1, hit)

    def on_absorb(self, m):
        self.absorbed.append(m.memory.bytes_at(m.regs[RSI], m.regs[RDX]) if m.regs[RDX] else b"")

    def reset(self):
        self.machine.memory.reset()
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.absorbed = []
# ---- driving one case ----

NODE_SIZE = 0x220
NODE_EDGES = 0x220
NODE_PARENT = 0x210
NODE_SLOT = 0x218
NODE_LENGTH = 0x21A
ROW_STRIDE = 0x30


def pack_row(row):
    return row["power"].to_bytes(8, "little") + row["hot"] + row["cold"]


def put_tree(harness, rows):
    """Lay rows out as the height 0 or height 1 set; returns (root, height). Over 11 rows use one parent with one key between two leaves."""
    memory = harness.machine.memory
    memory.put_bytes(NODES_AT, bytes(0x1800))

    def node(index):
        return NODES_AT + index * (NODE_SIZE + 0x60)

    def fill(at, items):
        memory.put_bytes(at + NODE_LENGTH, len(items).to_bytes(2, "little"))
        for index, row in enumerate(items):
            memory.put_bytes(at + index * ROW_STRIDE, pack_row(row))

    if not rows:
        return 0, 0
    if len(rows) <= 11:
        fill(node(0), rows)
        return node(0), 0
    left, middle, right = rows[:6], rows[6], rows[7:]
    fill(node(0), [middle])
    fill(node(1), left)
    fill(node(2), right)
    for index in (1, 2):
        memory.write(node(index) + NODE_PARENT, 8, node(0))
        memory.write(node(index) + NODE_SLOT, 2, index - 1)
        memory.write(node(0) + NODE_EDGES + 8 * (index - 1), 8, node(index))
    return node(0), 1


def put_set(harness, at, rows, epoch):
    root, height = put_tree(harness, rows)
    memory = harness.machine.memory
    memory.write(at, 8, root)
    memory.write(at + 8, 8, height)
    memory.write(at + 0x10, 8, len(rows))
    memory.write(at + 0x18, 8, epoch)


def put_payload(harness, payload):
    memory = harness.machine.memory
    kind = payload["arm"]
    memory.put_bytes(PAYLOAD_AT, b"\xee" * 0x60)
    memory.write(PAYLOAD_AT, 1, kind)
    if kind == 0:
        memory.write(PAYLOAD_AT + 1, 1, payload["role"])
        memory.write(PAYLOAD_AT + 2, 1, 1 if payload["active"] else 0)
        memory.put_bytes(PAYLOAD_AT + 3, payload["validator"])
        memory.write(PAYLOAD_AT + 0x18, 8, payload["nonce"])
    elif kind in (1, 2, 3):
        memory.write(PAYLOAD_AT + 8, 8, payload["value"])
        memory.write(PAYLOAD_AT + 0x10, 8, payload["nonce"])
    elif kind == 4:
        put_set(harness, PAYLOAD_AT + 8, payload["rows"], payload["epoch"])
    elif kind == 5:
        memory.put_bytes(PAYLOAD_AT + 1, payload["account"])
        memory.put_bytes(PAYLOAD_AT + 0x15, payload["destination"])
        memory.write(PAYLOAD_AT + 0x30, 8, payload["amount"])
        memory.write(PAYLOAD_AT + 0x38, 8, payload["nonce"])
    elif kind == 6:
        memory.write(PAYLOAD_AT + 8, 8, payload["nonce"])
        put_set(harness, PAYLOAD_AT + 0x10, payload["rows"], payload["epoch"])
    elif kind == 7:
        ids = payload["ids"]
        at = HEAP_FREE - 0x2000
        memory.put_bytes(at, b"".join(ids))
        memory.write(PAYLOAD_AT + 8, 8, payload["nonce"])
        memory.write(PAYLOAD_AT + 0x10, 8, len(ids))
        memory.write(PAYLOAD_AT + 0x18, 8, at)
        memory.write(PAYLOAD_AT + 0x20, 8, len(ids))


def run_case(harness, payload, chain):
    harness.reset()
    machine = harness.machine
    put_payload(harness, payload)
    machine.run(BUILD, {RDI: OUT, RSI: PAYLOAD_AT, RDX: chain})
    memory = machine.memory
    request = memory.bytes_at(OUT, 0x58)
    tag_at = int.from_bytes(request[8:16], "little")
    result = {"cap": request[0], "tag": memory.bytes_at(tag_at, 1), "tag_len": int.from_bytes(request[16:24], "little"), "connection": request[0x18:0x38],
              "chain_id": int.from_bytes(request[0x38:0x40], "little"), "high": request[0x40:0x58]}
    machine.run(DIGEST, {RDI: OUT2, RSI: OUT})
    answer = memory.bytes_at(OUT2, 0x21)
    result["digest_flag"] = answer[0]
    result["digest"] = answer[1:]
    result["absorbed"] = list(harness.absorbed)
    result["lookups"] = list(harness.log)
    return result


def run_digest(harness, source, connection, chain, high):
    harness.reset()
    machine = harness.machine
    memory = machine.memory
    at = HEAP_FREE - 0x1000
    memory.put_bytes(at, source)
    memory.write(OUT, 8, len(source) or 1)
    memory.write(OUT + 8, 8, at)
    memory.write(OUT + 0x10, 8, len(source))
    memory.put_bytes(OUT + 0x18, connection)
    memory.write(OUT + 0x38, 8, chain)
    memory.write(OUT + 0x40, 8, 0)
    memory.write(OUT + 0x48, 8, 0)
    memory.write(OUT + 0x50, 8, high)
    machine.run(DIGEST, {RDI: OUT2, RSI: OUT})
    answer = memory.bytes_at(OUT2, 0x21)
    return {"flag": answer[0], "digest": answer[1:], "absorbed": list(harness.absorbed)}


def walk_book(machine):
    """Read the two level map through the node layout: outer u8 keys, inner 16 byte keys, 20 byte values."""
    memory = machine.memory
    if memory.read(OUT, 1) != 0 or memory.read(OUT + 0x10, 8) != 0:
        raise EvidenceError("book result shape")
    root = memory.read(OUT + 8, 8)
    rows = []
    for index in range(memory.read(root + 0x112, 2)):
        namespace = memory.read(root + 0x114 + index, 1)
        inner = memory.read(root + 8 + 0x18 * index, 8)
        if inner == 0:
            rows.append((namespace, "", ""))
            continue
        if memory.read(root + 0x10 + 0x18 * index, 8) != 0:
            raise EvidenceError("inner height")
        for item in range(memory.read(inner + 0x196, 2)):
            name = memory.bytes_at(inner + 0x10 * item, 16).rstrip(b"\0").decode("ascii")
            rows.append((namespace, name, memory.bytes_at(inner + 0xB8 + 0x14 * item, 20).hex()))
    return sorted(rows)


def run_book(harness, files=None):
    harness.reset()
    harness.file_rows = files or {}
    machine = harness.machine
    memory = machine.memory
    at = HEAP_FREE - 0x1000
    memory.put_bytes(at, b"home")
    for offset, value in ((0x30, 4), (0x38, at), (0x40, 4), (0x50, 0)):
        memory.statics[CONFIG + offset] = value
    memory.statics[OVERLAY_ONCE] = 0
    harness.files = []
    machine.run(BOOK, {RDI: OUT})
    return {"files": [name.decode("ascii") for name in harness.files], "rows": walk_book(machine)}


# ---- cases ----

class Case:
    def __init__(self, label, kind, **fields):
        self.label = label
        self.kind = kind
        self.fields = fields


def address(base):
    return bytes((base * 37 + 11 * index + 1) & 0xFF for index in range(20))


def rows_of(count, step=1):
    return [{"power": 1000 + step * index * index, "hot": address(40 + index), "cold": address(90 + index)} for index in range(count)]


def all_cases():
    cases = []

    def request(label, payload, chain=3, overlay=None, panic=None):
        cases.append(Case(label, "request", payload=payload, chain=chain, overlay=overlay, panic=panic))

    max64 = (1 << 64) - 1
    for chain in (3, 2):
        tag = "chain %d " % chain
        for role in (0, 1):
            for active in (True, False):
                request(tag + "modify role %d active %d" % (role, active), {"arm": 0, "role": role, "active": active, "validator": address(1 + role), "nonce": 9 + role})
        for arm in (1, 2, 3):
            request(tag + "uint arm %d" % arm, {"arm": arm, "value": 86400 + arm, "nonce": 1700000000000 + arm})
            request(tag + "uint arm %d limits" % arm, {"arm": arm, "value": max64, "nonce": 0})
        for count in (0, 1, 3, 11, 12, 13, 18):
            request(tag + "set of %d rows" % count, {"arm": 4, "epoch": 7 + count, "rows": rows_of(count)})
            request(tag + "unlock with %d rows" % count, {"arm": 6, "epoch": 3 + count, "rows": rows_of(count, 3), "nonce": 40 + count})
        request(tag + "withdrawal", {"arm": 5, "account": address(5), "destination": address(6), "amount": 123456789, "nonce": 1700000000123})
        request(tag + "withdrawal limits", {"arm": 5, "account": bytes(20), "destination": b"\xff" * 20, "amount": max64, "nonce": max64})
        request(tag + "withdrawal zero amount", {"arm": 5, "account": address(7), "destination": address(7), "amount": 0, "nonce": 0})
        for count in (0, 1, 2, 5):
            request(tag + "invalidate %d ids" % count, {"arm": 7, "ids": [bytes([0x31 + at]) * 32 for at in range(count)], "nonce": 11 + count})
    request("set epoch limit", {"arm": 4, "epoch": max64, "rows": [{"power": max64, "hot": bytes(20), "cold": b"\xff" * 20}]})
    request("unlock limits", {"arm": 6, "epoch": max64, "rows": [{"power": 0, "hot": b"\xff" * 20, "cold": bytes(20)}], "nonce": max64})
    withdrawal = {"arm": 5, "account": address(8), "destination": address(9), "amount": 5, "nonce": 6}
    for chain in (0, 1):
        request("chain %d name has no row" % chain, withdrawal, chain, panic="none")
        request("chain %d row from a contract file" % chain, withdrawal, chain, overlay=address(10 + chain))
    for source, chain, high in ((b"a", 42161, 0), (b"b", 42161, 0), (b"a", 1337, 0), (b"b", 1337, 0), (b"", 1, 0), (b"Mainnet", 999, 0), (b"a", (1 << 64) - 1, 0), (b"a", 0, 1), (b"a" * 40, 421614, 5), (b"a" * 136, 7, 0)):
        cases.append(Case("digest source %d bytes chain %d high %d" % (len(source), chain, high), "digest", source=source, connection=keccak(source + bytes([chain & 0xFF])), chain=chain, high=high))
    cases.append(Case("contract book", "book", files=None))
    one = [("Bridge2Mainnet", address(21))]
    three = [("Aa", address(22)), ("Bridge2Local", address(23)), ("Usdc2Testnet", address(24))]
    book_files = (("Arbitrum file replaces the table", {"Arbitrum": one}), ("ArbitrumTestnet file with three rows", {"ArbitrumTestnet": three}), ("HlMainnet file adds a namespace", {"HlMainnet": one}),
                  ("two files, first and sixth name", {"Localhost": three, "Base": one}), ("Arbitrum file with no rows", {"Arbitrum": []}))
    for label, files in book_files:
        cases.append(Case(label, "book", files=files))
    cases.append(Case("Mainnet file parse error", "book", files={"Mainnet": None}))
    return cases


def message_list(expected):
    return [expected["payload_input"], expected["pair_input"]] + digest_list(expected)


def digest_list(expected):
    return [b"Exchange", b"1", DOMAIN_TYPE, expected["domain_input"], AGENT_TYPE, expected["source"], expected["struct_input"], expected["final_input"]]


def compare_run(harness, case):
    """None when the real bytes agree with the specification, else a short reason."""
    try:
        if case.kind == "book":
            files = case.fields["files"]
            if files and None in files.values():
                try:
                    run_book(harness, files)
                except Panicked:
                    return None
                return "book: no panic"
            if run_book(harness, files) != expected_book(files):
                return "book: rows differ"
            return None
        if case.kind == "digest":
            fields = case.fields
            got = run_digest(harness, fields["source"], fields["connection"], fields["chain"], fields["high"])
            expected = expected_digest(fields["source"], fields["connection"], fields["chain"] | fields["high"] << 192)
            if got["flag"] != 0:
                return "digest: flag"
            if got["absorbed"] != digest_list(expected):
                return "digest: hash inputs"
            if got["digest"] != expected["digest"]:
                return "digest: result"
            return None
        fields = case.fields
        book = dict(harness.book_base)
        if fields["overlay"]:
            book[(3, (b"Bridge2" + CHAIN_NAMES[fields["chain"]].encode()).ljust(16, b"\0"))] = fields["overlay"]
        harness.book = book
        if fields["panic"]:
            try:
                run_case(harness, fields["payload"], fields["chain"])
            except Panicked as stop:
                if stop.args[0] != "slot %#x location %#x" % (0x576E470, NONE_LOCATION):
                    return "request: panic %s" % stop
                return None
            return "request: no panic"
        got = run_case(harness, fields["payload"], fields["chain"])
        expected = expected_messages(fields["payload"], fields["chain"], book)
        if got["tag"] != b"a" or got["tag_len"] != 1 or got["cap"] != 1 or got["high"] != bytes(24):
            return "request: shape"
        if got["chain_id"] != expected["chain_id"]:
            return "request: chain id"
        if got["absorbed"] != message_list(expected):
            return "request: hash inputs"
        if got["connection"] != expected["connection"] or got["digest"] != expected["digest"] or got["digest_flag"] != 0:
            return "request: result"
        namespace = 2 if fields["chain"] == 3 else 3
        if [row[1] for row in got["lookups"]] != [namespace]:
            return "request: namespace"
        if len(harness.live) != 1:
            return "request: live blocks"
        return None
    except (Halt, Panicked, EvidenceError, IndexError, KeyError, ValueError, OverflowError, TypeError, MemoryError) as stop:
        return "%s: stopped: %s" % (case.kind, str(stop)[:60])


SURVIVED_DEFAULT = "class label, not proven row by row: a Vec capacity, a token list capacity, a one byte longer squeeze or a word this path does not read again"
SURVIVED_REASONS = {0x14CA560: "class label: the hex text is fixed here, always with its 0x prefix and 42 bytes, so the other forms of the parse are not tried",
                    0x14CBD80: "class label: pair list bookkeeping that only a longer or unsorted list would show",
                    0x14BF3A0: "class label: map build bookkeeping that only a longer list would show",
                    0x1405720: "class label: a once state word, a scratch word or a drop that leaves the same rows",
                    0x38139C0: "class label: a capacity branch of the concat; the buffer is sized right the first time on this path"}


# ---- static reads ----

def slot_sites(image, slot):
    """Every FF 15 call in .text through one data slot."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            rows.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return rows


def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def require(image, va, data, what):
    if code(image, va, len(data)) != data:
        raise EvidenceError("%s: bytes at %#x differ" % (what, va))


def arm_rows(image):
    """The eight rows of the payload table, each landing inside the function."""
    begin, end = image.exact_fde(PAYLOAD_HASH)
    rows = []
    for index, (name, shape) in enumerate(ARM_TEXT):
        arm = ARMS + struct.unpack_from("<i", image.blob, image.offset(ARMS) + index * 4)[0]
        if not begin <= arm < end:
            raise EvidenceError("arm %d out of the function" % index)
        rows.append({"tag": index, "entry": "%#x" % arm, "action": name, "tokens": shape})
    return rows


def caller_rows(image):
    """The two calls of the request builder and the immediate tag each one stores just before it."""
    rows = []
    sites = slot_sites(image, SLOT_BUILD)
    if image_targets(image, SLOT_BUILD) != BUILD or sites != [site for site, _, _ in BUILD_CALLERS]:
        raise EvidenceError("request builder sites")
    for site, tag_store, pattern in BUILD_CALLERS:
        data = bytes.fromhex(pattern)
        require(image, tag_store, data, "tag store")
        rows.append({"site": "%#x" % site, "host": "%#x" % image.fde(site)[0], "tag_store": "%#x" % tag_store, "tag": data[-1]})
    return rows


def image_targets(image, slot):
    for address_, kind, addend, _ in image.relocations():
        if address_ == slot and kind == 8:
            return addend
    raise EvidenceError("slot %#x has no relative relocation" % slot)


def text_rows(image):
    rows = []
    for va, what in ((TEMPLATE, "contract name template, chain name appended"), (MODIFY_TEMPLATE, "arm 0 action name template, role name appended")):
        size = image.blob[image.offset(va)]
        rows.append({"va": "%#x" % va, "text": code(image, va + 1, size).decode("ascii"), "marker": code(image, va + 1 + size, 2).hex(), "what": what})
    return rows


def book_text_rows(image):
    """The four name and address texts, each from the lea pair and lengths in the first part of the builder."""
    rows = []
    for name_lea, value_lea, namespace, length in BOOK_SITES:
        name_at = lea_target(image, name_lea)
        value_at = lea_target(image, value_lea)
        require(image, value_lea + 7, b"\x48\x8d\x7c\x24", "pair call shape")
        rows.append({"namespace": namespace, "name_va": "%#x" % name_at, "name": code(image, name_at, length).decode("ascii"), "value_va": "%#x" % value_at, "value": code(image, value_at, 0x2A).decode("ascii")})
    return rows


def lea_target(image, site):
    data = code(image, site, 7)
    if data[1] != 0x8D or data[2] & 0xC7 != 5:
        raise EvidenceError("no rip lea at %#x" % site)
    return site + 7 + struct.unpack_from("<i", data, 3)[0]


def chain_rule_bytes(image):
    """`sete cl; xor ecx,3` after `cmp bpl,3`: chain 3 reads namespace 2, every other value namespace 3."""
    require(image, 0x358EAFA, bytes.fromhex("40 80 fd 03 0f 94 c1 83 f1 03".replace(" ", "")), "namespace rule")
    return {"site": "0x358eafa", "rule": "chain byte 3 gives namespace 2, any other value namespace 3"}


# ---- mutation ----

def displacement_at(image, row):
    """Offset inside the instruction of a non-stack field displacement, or None."""
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
            disp = operand[4]
            end = row.size - (row.imm_size or 0)
            data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    """Yield (va, offset in instruction, kind) for every conditional, immediate and field offset."""
    for row in rows:
        at = displacement_at(image, row)
        if at is not None:
            yield row.va, at, "offset"
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), "branch"
        elif row.op in ("set", "cmov"):
            yield row.va, None, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, "immediate"


def mutate_patch(image, row_va, at, kind="branch"):
    base = image.offset(row_va)
    window = bytes(image.blob[base:base + 16])
    if at is None:
        at = window.index(b"\x0f") + 1
    return {row_va + at: window[at] ^ (8 if kind == "offset" else 1)}


def tolerant_rows(image, begin, end):
    """Linear rows of a body; unwind pads past an unknown opcode are skipped to the next FDE end."""
    base = image.offset(begin)
    code_bytes = image.blob[base:base + (end - begin) + 16]

    def read(va, count):
        return code_bytes[va - begin:va - begin + count]

    rows = []
    va = begin
    while va < end:
        try:
            row = decode(read, va)
        except EvidenceError:
            break
        rows.append(row)
        va = row.next
    return rows


def run_mutants(image, reached):
    """A mutant only changes a run that reaches its instruction, so only those cases run, cheapest first and at most MUTANT_CASES of them."""
    results = []
    harness = make_harness(image)
    harness.fast(True)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    cases = all_cases()
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    for start, role in MUTATED:
        begin, end = image.exact_fde(start)
        for va, at, kind in mutation_targets(image, tolerant_rows(image, begin, end)):
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            for index in indices[:MUTANT_CASES]:
                failed = compare_run(harness, cases[index])
                if failed:
                    failed = cases[index].label + ": " + failed.split(":")[1].strip()
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed[:70] if failed else ""})
    return results


# ---- evidence ----

def make_harness(image):
    harness = Harness(image)
    rows = run_book(harness)["rows"]
    harness.book_base = {(namespace, name.encode("ascii").ljust(16, b"\0")): bytes.fromhex(value) for namespace, name, value in rows}
    return harness


def vector_line(case, expected):
    payload = case.fields["payload"]
    return "\t".join((case.label, str(payload["arm"]), str(case.fields["chain"]), expected["contract"].hex(), expected["payload_hash"].hex(), expected["connection"].hex(), expected["digest"].hex()))


def worked_lines():
    """One message per arm, in 32 byte words."""
    lines = ["label\tword\tvalue"]
    seen = set()
    book = {(2, b"Bridge2Mainnet\0\0"): bytes.fromhex(SPEC_BOOK[2][1][1]), (3, b"Bridge2Testnet\0\0"): bytes.fromhex(SPEC_BOOK[3][0][1])}
    for case in all_cases():
        if case.kind != "request" or case.fields["chain"] != 3 or case.fields["panic"] or case.fields["overlay"]:
            continue
        payload = case.fields["payload"]
        if payload["arm"] in seen or payload.get("rows") == [] or payload.get("ids") == []:
            continue
        seen.add(payload["arm"])
        data = abi_encode(payload_tokens(payload))
        lines += ["%s\t%d\t%s" % (case.label, at // 32, data[at:at + 32].hex()) for at in range(0, min(len(data), 32 * 24), 32)]
    return lines


def analyse(image, full=True):
    harness = make_harness(image)
    cases = all_cases()
    mismatches = []
    outcomes = collections.Counter()
    reached = []
    seen = set()
    lines = []
    vectors = ["label\tarm\tchain\tcontract\tpayload_hash\tconnection\tdigest"]
    machine = harness.machine
    for case in cases:
        machine.seen = set()
        trouble = compare_run(harness, case)
        if trouble:
            mismatches.append("%s: %s" % (case.label, trouble))
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        outcome = case.kind
        if case.kind == "request":
            payload = case.fields["payload"]
            outcome = "request arm %d" % payload["arm"]
            if case.fields["panic"]:
                outcome = "request panic, no address row"
            else:
                expected = expected_messages(payload, case.fields["chain"], harness.book)
                vectors.append(vector_line(case, expected))
        if case.kind == "book":
            outcome = "book, panic on a parse error" if case.fields["files"] and None in case.fields["files"].values() else "book"
        outcomes[outcome] += 1
        lines.append("\t".join((case.kind, case.label, outcome, "%d" % len(harness.absorbed))))
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    for start, role in MUTATED + EXTRA_FUNCTIONS:
        begin, end = image.exact_fde(start)
        rows = tolerant_rows(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    results_rows = run_mutants(image, reached) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    book = run_book(harness)
    doc = {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "arms": arm_rows(image),
        "callers": caller_rows(image),
        "templates": text_rows(image),
        "book_texts": book_text_rows(image),
        "book_rows": [{"namespace": namespace, "name": name, "value": value} for namespace, name, value in book["rows"]],
        "contract_files": book["files"],
        "namespace_rule": chain_rule_bytes(image),
        "lookup_panic_location": dict(zip(("path", "line", "column"), image.location(NONE_LOCATION, harness.relative))),
        "signed_types": {"domain": DOMAIN_TYPE.decode("ascii"), "agent": AGENT_TYPE.decode("ascii"), "prefix": code(image, PREFIX_1901, 2).hex()},
        "_results": results_rows, "_lines": lines, "_vectors": vectors,
    }
    return doc


UNREACHED_REASON = "no case reaches it: an allocator failure arm, a panic arm, an unwind pad, a domain field this path never leaves empty, or a contract file arm"


def reason_for(row):
    if row["result"] == "killed":
        return ""
    if row["result"] == "unreached":
        return UNREACHED_REASON
    return SURVIVED_REASONS.get(row["function"], SURVIVED_DEFAULT)


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    vectors = evidence.pop("_vectors")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    files["cases.tsv"] = "\n".join(["kind\tlabel\toutcome\thash_inputs"] + case_lines) + "\n"
    files["vectors.tsv"] = "\n".join(vectors) + "\n"
    files["worked_words.tsv"] = "\n".join(worked_lines()) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += [("%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_))) for row_ in results]
    files["mutations.tsv"] = "\n".join(lines) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (folder / name).write_text(text, encoding="ascii", newline="\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="output folder")
    options = parser.parse_args(argv)
    files = render(analyse(load_image()))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
