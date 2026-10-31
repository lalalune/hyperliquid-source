#!/usr/bin/env python3
"""Pin the node #94 setMarginTableIds path from ELF bytes: gate, apply loop and per-user rewrite.

The gate `0x273c140` (and copies), the apply loop `0x273bf80` (and copy) and the rewrite `0x3704680` run in a Python evaluator with
the table compare `0x3333920`, its memo helpers and the table getter `0x3759880`. Edge callees are stubbed. A separately written
specification predicts every result, stub argument and state word, and every condition, immediate and field offset is flipped to
show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
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

REWRITE = 0x3704680
RELATION = 0x3333920
MEMO_FIRST = 0x33980D0
MEMO_MISS = 0x33BD620
GETTER = 0x3759880
ENTRY = 0x33BD420
LOOPS = (0x273BF80, 0x4D4C3E0)
GATES = (0x273C140, 0x4D4C5A0, 0x4D4CA90)
BUILTIN = 0x3398F50
DROP_TIERS = 0x33AE9E0
DROP_MEMO = 0x33F7810
USERS = 0x3BB2290
NEXT_USER = 0x33B1E80
USER_ROW = 0x3596940
SET_INSERT = 0x339B590
SET_REMOVE = 0x33ACFE0
OI = 0x36F7350
LEV_INDEX = 0x370E6A0
LEAF_INSERT = 0x2F85640
DROP_ERROR = 0x3379490
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576E048
SLOT_LOOKUP = 0x5775988
SLOT_GETTER = 0x57746E0
SLOT_REWRITE = 0x5774B88
SLOT_DEX = 0x5773EC8
SLOT_ASSET = 0x5773318
SLOT_GROW = 0x5773DC0
LOC_ASSET = 0x56F21C0
LOC_TABLE = 0x56F21D8
LOC_EMPTY = 0x56E9B40
OK = 0x186
TOO_LONG = 0x143
NO_TABLE = 0x154
ERR_TAG = 0x99

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x4000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x30000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 30000

OUT = HEAP_BASE + 0x100
EXCHANGE = HEAP_BASE + 0x400
CONTROL = HEAP_BASE + 0xA00
KEYS_NODE = HEAP_BASE + 0xD00
VEC_IN = HEAP_BASE + 0xFC0
CH_BASE = HEAP_BASE + 0x3000
CH_STRIDE = 0x2F0
BUMP = HEAP_BASE + 0x6000

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
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd",
                  (0xEB, True): "orpd", (0x6C, True): "unpcklpd", (0x58, True): "addpd", (0x59, True): "mulpd", (0x5E, True): "divpd", (0x5F, True): "maxpd"}
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
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1)
            if value != 2:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmplepd", ("x", reg), rm, 16)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            return finish("psrlq", rm, ("i", value), 16)
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
        self.jump_low = self.jump_high = 0

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
            return row.target
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
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
            if not self.jump_low <= target < self.jump_high:
                raise Halt("indirect jump out of the function at %#x" % row.va)
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
        elif op in ("addpd", "mulpd", "divpd", "maxpd"):
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            parts = []
            for at in (0, 64):
                x, y = to_float(left >> at & MASK[8]), to_float(right >> at & MASK[8])
                parts.append(x + y if op == "addpd" else x * y if op == "mulpd" else x / y if op == "divpd" else (x if x > y else y))
            self.xmm[row.a[1]] = to_bits(parts[0]) | to_bits(parts[1]) << 64
        elif op == "cmplepd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = sum((MASK[8] if to_float(left >> at & MASK[8]) <= to_float(right >> at & MASK[8]) else 0) << at for at in (0, 64))
        elif op == "movmskpd":
            source = self.xmm[row.b[1]]
            self.put(row.a, 4, (source >> 63 & 1) | (source >> 127 & 1) << 1)
        elif op == "psrlq":
            source = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = sum(((source >> at & MASK[8]) >> row.b[1]) << at for at in (0, 64))
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




# ---- specification ----

def tiers_of(book, ident):
    """Tier rows (lower bound, leverage) of one table id, or None when a custom id is missing."""
    if ident < 50:
        return ((0, ident),)
    return dict(book["tables"]).get(ident)


def leverage_at(tiers, bound):
    picked = None
    for lower, leverage in tiers:
        if lower <= bound:
            picked = leverage
    return picked


def relation(new, old):
    """0 never above, 1 above somewhere and never below, 2 both."""
    pairs = [(lev, leverage_at(old, low)) for low, lev in new] + [(leverage_at(new, low), lev) for low, lev in old]
    above = any(left > right for left, right in pairs)
    below = any(left < right for left, right in pairs)
    return 2 if above and below else 1 if above else 0


def rewrite_spec(state, dex, asset, new_id):
    """State change of 0x3704680 on one dex. Returns (panic location or None, calls)."""
    book = state["dexes"][dex]
    calls = []
    if asset // 10000 != book["id"] or asset % 10000 >= len(book["rows"]):
        return LOC_ASSET, calls
    old_id = book["rows"][asset % 10000]
    book["rows"][asset % 10000] = new_id
    old = tiers_of(book, old_id)
    new = tiers_of(book, new_id)
    if old is None or new is None:
        return LOC_TABLE, calls
    if bool(new) != bool(old):
        return LOC_EMPTY, calls
    memo = {old_id: relation(new, old)}
    first = new[0][1] if new else 3
    for user in sorted(book["users"]):
        calls.append(("user", dex, user))
        position = book["users"][user].get(asset)
        if position is None:
            continue
        calls.append(("set", dex, 0x188, user))
        before = position["lev"]
        position["lev"] = min(before, first)
        table = position["table"]
        if table not in memo:
            tiers = tiers_of(book, table)
            if tiers is None:
                return LOC_TABLE, calls
            memo[table] = relation(new, tiers)
            calls.append(("memo", table, memo[table]))
        if memo[table] == 1:
            position["table"] = new_id
        calls.append(("oi", dex, asset, position["szi"], position["szi"], user))
        if position["lev"] != before:
            calls.append(("lev", dex, user, asset, position["lev"]))
    return None, calls


def loop_spec(state, rows):
    calls = []
    for asset, ident in rows:
        dex = asset // 10000
        if dex >= len(state["dexes"]):
            return "bounds", calls
        panic, more = rewrite_spec(state, dex, asset, ident)
        calls += more
        if panic:
            return panic, calls
    return None, calls


def gate_spec(state, entries, coins):
    """Returns (out tag, extra, panic, calls): validation first, then every rewrite in key order."""
    accepted = []
    stale = None
    for coin, ident in sorted(entries):
        if len(coin) > 100:
            return TOO_LONG, None, None, []
        found = coins.get(coin)
        if found is None:
            return ERR_TAG, "dex", None, []
        dex, asset = found
        if asset is None:
            return ERR_TAG, "asset", None, []
        if ident >= 50 and ident not in dict(state["dexes"][dex]["tables"]):
            return NO_TABLE, stale, None, []
        accepted.append((asset, ident))
        stale = ident
    panic, calls = loop_spec(state, accepted)
    return OK, None, panic, calls


def fresh_state(case):
    state = {"dexes": []}
    for book in case["dexes"]:
        state["dexes"].append({"id": book["id"], "tables": book["tables"], "rows": list(book["rows"]),
                               "users": {user: {asset: dict(row) for asset, row in held.items()} for user, held in book["users"].items()}})
    return state


# ---- harness ----

def to_signed(value):
    return value - (1 << 64) if value & SIGN[8] else value


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        machine.real = frozenset((REWRITE, RELATION, MEMO_FIRST, MEMO_MISS, GETTER, ENTRY) + LOOPS + GATES)
        machine.calls = {BUILTIN: self.on_builtin, DROP_TIERS: self.on_drop, DROP_MEMO: self.on_nothing, USERS: self.on_users, NEXT_USER: self.on_next,
                         USER_ROW: self.on_row, SET_INSERT: self.on_set, SET_REMOVE: self.on_remove, OI: self.on_oi, LEV_INDEX: self.on_lev,
                         LEAF_INSERT: self.on_leaf, DROP_ERROR: self.on_nothing, 0x2869350: self.on_key, 0x494A910: self.on_key, 0x277EBA0: self.on_recorder,
                         0x4DAF4A0: self.on_recorder, 0x28BA080: self.on_nothing, 0x49B9E60: self.on_nothing}
        tokens = {SLOT_FREE: self.on_nothing, SLOT_ALLOC: self.on_alloc, SLOT_PANIC: self.on_panic, SLOT_BOUNDS: self.on_bounds, SLOT_LOOKUP: self.on_lookup,
                  SLOT_DEX: self.on_dex, SLOT_ASSET: self.on_asset, SLOT_GROW: self.on_grow}
        for at, (slot, hook) in enumerate(tokens.items()):
            token = 0x7000000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        machine.memory.statics[SLOT_GETTER] = GETTER
        machine.memory.statics[SLOT_REWRITE] = REWRITE
        self.case = None
        self.calls = []
        self.at = BUMP
        self.keys = []
        self.walk = []
        self.names = {}
        self.key_at = 0

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        return here

    def dex_of(self, pointer):
        return (pointer - CH_BASE) // CH_STRIDE

    def on_nothing(self, machine):
        pass

    def on_drop(self, machine):
        machine.memory.write(machine.regs[RDI], 8, 0)

    def on_alloc(self, machine):
        machine.regs[RAX] = self.bump(machine.regs[RDI])

    def on_panic(self, machine):
        raise Panicked(machine.regs[RDI])

    def on_bounds(self, machine):
        raise Panicked("bounds")

    def on_recorder(self, machine):
        self.calls.append(("recorder",))

    def tier_node(self, tiers):
        memory = self.machine.memory
        node = self.bump(0x1C8)
        memory.write(node + 0x1C2, 2, len(tiers))
        for index, (lower, leverage) in enumerate(tiers):
            memory.write(node + 0x168 + 8 * index, 8, lower)
            memory.write(node + 0x20 * index + 0x18, 1, leverage)
        return node

    def on_builtin(self, machine):
        memory = machine.memory
        if machine.regs[RDX] != 0:
            raise Halt("builtin key")
        node = self.tier_node(((0, memory.read(machine.regs[RCX] + 0x18, 1)),))
        out = machine.regs[RSI]
        memory.write(out, 8, node)
        memory.write(out + 8, 8, 0)
        memory.write(out + 16, 8, 1)

    def on_lookup(self, machine):
        memory = machine.memory
        table, bound = machine.regs[RDI], machine.regs[RSI]
        node = memory.read(table + 0x18, 8)
        picked = None
        if node:
            for index in range(memory.read(node + 0x1C2, 2)):
                if memory.read(node + 0x168 + 8 * index, 8) <= bound:
                    picked = index
        if picked is None:
            raise Panicked(LOC_EMPTY)
        machine.regs[RAX] = node + 0x20 * picked

    def on_users(self, machine):
        memory = machine.memory
        dex = (memory.read(machine.regs[RSI], 8) - CONTROL) // 0x20
        self.walk = sorted(self.case["dexes"][dex]["users"])
        node = self.bump(8 + 20 * max(len(self.walk), 1))
        for index, user in enumerate(self.walk):
            memory.put_bytes(node + 8 + 20 * index, bytes([user] * 20))
        out = machine.regs[RDI]
        memory.write(out, 8, node if self.walk else 0)
        memory.write(out + 8, 8, 0)
        memory.write(out + 16, 8, len(self.walk))
        self.node = node
        self.index = 0

    def on_next(self, machine):
        out = machine.regs[RDI]
        if self.index >= len(self.walk):
            machine.memory.write(out, 8, 0)
            return
        machine.memory.write(out, 8, self.node)
        machine.memory.write(out + 16, 8, self.index)
        self.index += 1

    def on_row(self, machine):
        user = machine.memory.bytes_at(machine.regs[RSI], 20)[0]
        dex = self.dex_of(machine.regs[RDI] - 0xF8)
        self.calls.append(("user", dex, user))
        machine.regs[RAX] = self.rows[dex, user]

    def on_set(self, machine):
        dex = self.dex_of(machine.regs[RDI])
        field = machine.regs[RDI] - CH_BASE - dex * CH_STRIDE
        self.calls.append(("set", dex, field, machine.memory.bytes_at(machine.regs[RSI], 20)[0]))

    def on_remove(self, machine):
        self.calls.append(("remove",))

    def on_oi(self, machine):
        regs = machine.regs
        dex = self.dex_of(regs[R8])
        if regs[R8] != CH_BASE + dex * CH_STRIDE + 0x170:
            raise Halt("oi map")
        owner = [key[1] for key, row in self.rows.items() if key[0] == dex and row + 0x20 == regs[RCX]]
        self.calls.append(("oi", dex, regs[RDI], to_signed(regs[RSI]), to_signed(regs[RDX]), owner[0] if owner else None))

    def on_lev(self, machine):
        regs = machine.regs
        dex = self.dex_of(regs[RDI])
        if regs[RDI] != CH_BASE + dex * CH_STRIDE + 0x128:
            raise Halt("leverage index")
        self.calls.append(("lev", dex, machine.memory.bytes_at(regs[RSI], 20)[0], regs[RDX], regs[RCX] & MASK[4]))

    def on_leaf(self, machine):
        """Insert one memo key into the root leaf (a memo stays below 12 keys in every case)."""
        memory, regs = machine.memory, machine.regs
        handle = regs[RSI]
        node, height, index = memory.read(handle, 8), memory.read(handle + 8, 8), memory.read(handle + 16, 8)
        used = memory.read(node + 0x36, 2)
        if height or used >= 11:
            raise Halt("memo leaf full")
        for at in range(used, index, -1):
            memory.write(node + 8 + 4 * at, 4, memory.read(node + 4 + 4 * at, 4))
            memory.write(node + 0x38 + at, 1, memory.read(node + 0x37 + at, 1))
        memory.write(node + 8 + 4 * index, 4, regs[RDX] & MASK[4])
        memory.write(node + 0x38 + index, 1, regs[RCX] & 0xFF)
        memory.write(node + 0x36, 2, used + 1)
        self.calls.append(("memo", regs[RDX] & MASK[4], regs[RCX] & 0xFF))
        out = regs[RDI]
        memory.write(out, 8, node)
        memory.write(out + 8, 8, 0)
        memory.write(out + 16, 8, index)

    def on_key(self, machine):
        out = machine.regs[RDI]
        if self.key_at >= len(self.keys):
            machine.memory.write(out, 8, 0)
            return
        machine.memory.write(out, 8, KEYS_NODE)
        machine.memory.write(out + 16, 8, self.key_at)
        self.key_at += 1

    def error(self, machine, out, start_byte):
        machine.memory.write(out, 2, ERR_TAG)
        machine.memory.put_bytes(out + 2, bytes((start_byte + at) & 0xFF for at in range(0x5E)))

    def on_dex(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] not in (EXCHANGE + 0x5B8, EXCHANGE + 0x1038):
            raise Halt("dex list")
        found = self.case["coins"].get(self.names[regs[RDX]])
        if found is None:
            self.error(machine, regs[RDI], 0x10)
            return
        memory.write(regs[RDI], 2, OK)
        memory.write(regs[RDI] + 8, 8, CH_BASE + found[0] * CH_STRIDE)

    def on_asset(self, machine):
        regs, memory = machine.regs, machine.memory
        name = self.names[regs[RSI]]
        found = self.case["coins"][name]
        if regs[RCX] != CH_BASE + found[0] * CH_STRIDE or regs[RDX] != len(name):
            raise Halt("asset arguments")
        if found[1] is None:
            self.error(machine, regs[RDI], 0x40)
            return
        memory.write(regs[RDI], 2, OK)
        memory.write(regs[RDI] + 8, 8, found[1])

    def on_grow(self, machine):
        memory = machine.memory
        vec = machine.regs[RDI]
        cap, pointer, used = memory.read(vec, 8), memory.read(vec + 8, 8), memory.read(vec + 16, 8)
        grown = max(4, cap * 2)
        fresh = self.bump(grown * 16)
        if used:
            memory.copy(fresh, pointer, used * 16)
        memory.write(vec, 8, grown)
        memory.write(vec + 8, 8, fresh)

    def tree(self, keys, size, put, stale=None):
        """Lay out a B-tree of height 0 or 1. put(node, index, key) writes one key and value."""
        memory = self.machine.memory
        total, len_at, edge_at = size

        def node_of(chunk):
            node = self.bump(total + 0x60)
            memory.write(node + len_at, 2, len(chunk))
            for index, key in enumerate(chunk):
                put(node, index, key)
            if stale:
                stale(node, len(chunk))
            return node

        if len(keys) <= 11:
            return node_of(keys), 0
        seps = keys[5::6][:11]
        root = node_of(seps)
        start = 0
        for index, sep in enumerate(seps):
            stop = keys.index(sep)
            memory.write(root + edge_at + 8 * index, 8, node_of(keys[start:stop]))
            start = stop + 1
        memory.write(root + edge_at + 8 * len(seps), 8, node_of(keys[start:]))
        return root, 1

    def lay_tables(self, ch, book):
        memory = self.machine.memory
        tables = dict(book["tables"])

        def put(node, index, key):
            memory.write(node + 0x270 + 4 * index, 4, key)
            tiers = tables[key]
            memory.write(node + 8 + 0x38 * index + 0x18, 8, self.tier_node(tiers) if tiers else 0)
            memory.write(node + 8 + 0x38 * index + 0x20, 8, 0)
            memory.write(node + 8 + 0x38 * index + 0x28, 8, len(tiers))

        def stale(node, used):
            for index in range(used, 11):
                memory.write(node + 0x270 + 4 * index, 4, book.get("stale", 0xFFFFFFFF))

        root, height = self.tree(sorted(tables), (0x2A0, 0x29E, 0x2A0), put, stale) if tables else (0, 0)
        memory.write(ch + 0x38, 8, root)
        memory.write(ch + 0x40, 8, height)

    def lay_user(self, dex, user, held):
        memory = self.machine.memory
        row = self.bump(0x30)
        self.rows[dex, user] = row
        memory.write(row + 0x20, 8, sum(1 for pos in held.values() if pos["szi"]))

        def put(node, index, key):
            pos = held[key]
            spot = node + 0x40 * index
            memory.write(node + 0x2C8 + 8 * index, 8, key)
            for at in range(0, 0x40, 8):
                memory.write(spot + at, 8, 0x1111111111111111 * (at // 8 + 1))
            memory.write(spot + 4, 4, pos["lev"])
            memory.write(spot + 0x10, 8, pos["szi"])
            memory.write(spot + 0x38, 4, pos["table"])
            self.spots[dex, user, key] = spot

        def stale(node, used):
            for index in range(used, 11):
                memory.write(node + 0x2C8 + 8 * index, 8, self.case["dexes"][dex].get("stale", MASK[8]))

        root, height = self.tree(sorted(held), (0x328, 0x322, 0x328), put, stale) if held else (0, 0)
        memory.write(row + 8, 8, root)
        memory.write(row + 0x10, 8, height)
        memory.write(row + 0x18, 8, len(held))

    def layout(self, case):
        memory = self.machine.memory
        memory.reset()
        self.case = case
        self.calls = []
        self.at = BUMP
        self.rows = {}
        self.spots = {}
        for base in (0x5B8, 0x1038):
            memory.write(EXCHANGE + base, 8, len(case["dexes"]))
            memory.write(EXCHANGE + base + 8, 8, CH_BASE)
            memory.write(EXCHANGE + base + 16, 8, len(case["dexes"]))
        for dex, book in enumerate(case["dexes"]):
            ch = CH_BASE + dex * CH_STRIDE
            rows = self.bump(0x30 * max(1, len(book["rows"])))
            memory.write(ch + 8, 8, rows)
            memory.write(ch + 0x10, 8, len(book["rows"]))
            memory.write(ch + 0x30, 8, book["id"])
            for index, ident in enumerate(book["rows"]):
                memory.write(rows + 0x30 * index + 0x18, 4, ident)
            self.lay_tables(ch, book)
            memory.write(ch + 0x50, 8, 0x77)
            memory.write(ch + 0xF8, 8, CONTROL + dex * 0x20)
            memory.write(ch + 0x100, 8, 15)
            memory.write(ch + 0x110, 8, len(book["users"]))
            for user, held in book["users"].items():
                self.lay_user(dex, user, held)

    def state_errors(self, want):
        """Compare rows and every position word with the specification state."""
        memory = self.machine.memory
        for dex, book in enumerate(want["dexes"]):
            rows = memory.read(CH_BASE + dex * CH_STRIDE + 8, 8)
            for index, ident in enumerate(book["rows"]):
                if memory.read(rows + 0x30 * index + 0x18, 4) != ident:
                    return "row %d" % index
            for user, held in book["users"].items():
                for asset, pos in held.items():
                    spot = self.spots[dex, user, asset]
                    words = {at: 0x11111111 * (at // 8 + 1) for at in range(0, 0x40, 4)}
                    words.update({4: pos["lev"], 0x10: pos["szi"] & MASK[4], 0x14: (pos["szi"] & MASK[8]) >> 32, 0x38: pos["table"]})
                    for at, value in words.items():
                        if memory.read(spot + at, 4) != value:
                            return "position word %#x" % at
        return None

    def run_rewrite(self, case):
        self.layout(case)
        ch = CH_BASE + case["dex"] * CH_STRIDE
        value = self.machine.run(REWRITE, {RDI: OUT, RSI: ch, RDX: case["asset"], RCX: case["new"]})
        if value != OUT or self.machine.memory.read(OUT, 2) != OK:
            raise Halt("rewrite result")

    def run_loop(self, case):
        self.layout(case)
        memory = self.machine.memory
        rows = case["vector"]
        data = self.bump(16 * max(1, len(rows)))
        for index, (asset, ident) in enumerate(rows):
            memory.write(data + 16 * index, 8, asset)
            memory.write(data + 16 * index + 8, 4, ident)
        memory.write(VEC_IN, 8, len(rows))
        memory.write(VEC_IN + 8, 8, data)
        memory.write(VEC_IN + 16, 8, len(rows))
        if case["start"] == LOOPS[0]:
            self.machine.run(case["start"], {RDI: EXCHANGE, RSI: VEC_IN})
        else:
            self.machine.run(case["start"], {RDI: CH_BASE, RSI: len(case["dexes"]), RDX: VEC_IN})

    def run_gate(self, case):
        self.layout(case)
        memory = self.machine.memory
        self.keys = sorted(case["entries"])
        self.key_at = 0
        self.names = {}
        for index, (coin, ident) in enumerate(self.keys):
            pointer = self.bump(max(1, len(coin)))
            self.names[pointer] = coin
            memory.write(KEYS_NODE + 8 + 24 * index, 8, len(coin) + 1)
            memory.write(KEYS_NODE + 0x10 + 24 * index, 8, pointer)
            memory.write(KEYS_NODE + 0x18 + 24 * index, 8, len(coin))
            memory.write(KEYS_NODE + 0x110 + 4 * index, 4, ident)
        memory.write(VEC_IN, 8, KEYS_NODE if self.keys else 0)
        memory.write(VEC_IN + 8, 8, 0)
        memory.write(VEC_IN + 16, 8, len(self.keys))
        self.machine.run(case["start"], {RDI: OUT, RSI: EXCHANGE, RDX: VEC_IN})


def expected(case):
    """Specification result: (state, panic, calls, tag, extra)."""
    state = fresh_state(case)
    if case["kind"] == "rewrite":
        panic, calls = rewrite_spec(state, case["dex"], case["asset"], case["new"])
        return state, panic, calls, None, None
    if case["kind"] == "loop":
        panic, calls = loop_spec(state, case["vector"])
        return state, panic, calls, None, None
    tag, extra, panic, calls = gate_spec(state, case["entries"], case["coins"])
    return state, panic, calls, tag, extra


def compare_run(harness, case):
    """Return None when the real bytes match the specification, else a short description."""
    label = case["label"]
    panic = None
    try:
        try:
            {"rewrite": harness.run_rewrite, "loop": harness.run_loop, "gate": harness.run_gate}[case["kind"]](case)
        except Panicked as error:
            panic = error.args[0]
        state, want_panic, calls, tag, extra = expected(case)
        if panic != want_panic:
            return "%s: panic %r, spec %r" % (label, panic, want_panic)
        if harness.calls != calls:
            return "%s: calls %r, spec %r" % (label, harness.calls[:6], calls[:6])
        memory = harness.machine.memory
        if tag is not None and not panic:
            got = memory.read(OUT, 2)
            if got != tag:
                return "%s: tag %#x, spec %#x" % (label, got, tag)
            if tag == NO_TABLE:
                value = memory.read(OUT + 4, 4)
                wanted = 0xA5A5A5A5 if extra is None else extra
                if value != wanted:
                    return "%s: payload %#x, spec %#x" % (label, value, wanted)
            if tag == ERR_TAG:
                start_byte = 0x10 if extra == "dex" else 0x40
                if memory.bytes_at(OUT + 2, 0x5E) != bytes((start_byte + at) & 0xFF for at in range(0x5E)):
                    return "%s: error payload" % label
        problem = harness.state_errors(state)
        if problem:
            return "%s: state %s" % (label, problem)
    except (Halt, Panicked, EvidenceError, ZeroDivisionError, OverflowError, KeyError, IndexError, ValueError, TypeError) as error:
        return "%s: stopped: %s" % (label, error)
    return None


# ---- cases ----

STEP = ((0, 40), (100000000, 20), (500000000, 10))
STEP_LOW = ((0, 20), (100000000, 10), (500000000, 5))
STEP_HIGH = ((0, 50), (100000000, 25))
CROSS = ((0, 30), (100000000, 5))
MID = ((0, 40), (50000000, 20), (500000000, 10))
TABLES = ((50, STEP), (51, STEP_LOW), (52, STEP_HIGH), (53, CROSS), (54, MID), (55, STEP))


def position(lev=10, szi=1000, table=50):
    return {"lev": lev, "szi": szi, "table": table}


def book(rows=(50, 50, 7), users=None, tables=TABLES, dex=0, stale=None):
    row = {"id": dex, "rows": rows, "tables": tables, "users": users if users is not None else {}}
    if stale is not None:
        row["stale"] = stale
    return row


def rewrite_case(label, new, asset=1, **fields):
    case = dict(kind="rewrite", label=label, dex=0, asset=asset, new=new, dexes=(book(**fields),))
    return case


def rewrite_cases():
    rows = []
    add = rows.append
    add(rewrite_case("no users", 51))
    add(rewrite_case("asset id outside the dex", 51, asset=10001))
    add(rewrite_case("index at row count", 51, asset=3))
    add(rewrite_case("empty rows", 51, asset=0, rows=()))
    add(rewrite_case("old custom id missing", 51, rows=(50, 99, 7)))
    add(rewrite_case("new custom id missing", 99))
    add(rewrite_case("new custom id missing with no tables", 99, tables=(), rows=(1, 2, 3)))
    add(rewrite_case("id 49 is builtin", 49, users={1: {1: position()}}))
    add(rewrite_case("id 50 is custom", 50, rows=(7, 7, 7), users={1: {1: position(table=7)}}))
    add(rewrite_case("old id 49", 50, rows=(49, 49, 49), users={1: {1: position(table=49)}}))
    add(rewrite_case("old id 50", 7, users={1: {1: position()}}))
    add(rewrite_case("same id", 50, users={1: {1: position()}}))
    add(rewrite_case("equal tables under two ids", 55, users={1: {1: position()}}))
    for new in (50, 51, 52, 53, 54, 55, 1, 5, 10, 25, 40, 49):
        for old in (50, 51, 52, 53, 54, 3, 40, 49):
            add(rewrite_case("old %d new %d" % (old, new), new, rows=(old, old, old), users={1: {1: position(lev=33, table=old)}}))
    for lev in (0, 1, 5, 10, 19, 20, 21, 40, 41, 50, 255, 0x100, 0x10000, 0xFFFFFFFF):
        add(rewrite_case("leverage %d" % lev, 51, users={1: {1: position(lev=lev)}}))
    add(rewrite_case("position on another table", 54, users={1: {1: position(table=51)}}))
    add(rewrite_case("position on missing table", 54, users={1: {1: position(table=98)}}))
    add(rewrite_case("second user on missing table", 54, users={1: {1: position()}, 2: {1: position(table=98)}}))
    add(rewrite_case("positions on five tables", 52, users={at: {1: position(table=50 + at)} for at in range(6)}))
    add(rewrite_case("memo repeat", 52, users={at: {1: position(table=51)} for at in range(1, 6)}))
    add(rewrite_case("memo ordered insert", 52, users={1: {1: position(table=53)}, 2: {1: position(table=51)}, 3: {1: position(table=52)}, 4: {1: position(table=2)}}))
    add(rewrite_case("user without the asset", 51, users={1: {0: position()}}))
    add(rewrite_case("user with no positions", 51, users={1: {}}))
    add(rewrite_case("key above", 51, users={1: {2: position()}}))
    add(rewrite_case("zero size position", 51, users={1: {1: position(szi=0)}}))
    add(rewrite_case("short position", 51, users={1: {1: position(szi=-77)}}))
    add(rewrite_case("largest short", 51, users={1: {1: position(szi=-(1 << 63))}}))
    add(rewrite_case("users out of order", 51, users={9: {1: position()}, 3: {1: position()}, 200: {1: position()}}))
    held = {key: position(lev=30 + key % 5) for key in range(0, 60, 2)}
    rows_long = tuple(50 for _ in range(61))
    for asset in (0, 1, 10, 12, 22, 24, 34, 58, 59):
        add(rewrite_case("deep positions %d" % asset, 51, asset=asset, rows=rows_long, users={1: held, 2: {asset: position()}}))
    many = tuple((50 + at * 2, STEP if at % 2 else STEP_LOW) for at in range(30))
    for new in (50, 52, 72, 74, 76, 96, 98, 106, 108, 53):
        add(rewrite_case("deep tables %d" % new, new, tables=many, users={1: {1: position()}}))
    add(rewrite_case("deep old table", 50, rows=(74, 108, 7), tables=many, users={1: {1: position(table=108)}}))
    add(rewrite_case("empty tier list", 56, tables=TABLES + ((56, ()),), users={1: {1: position()}}))
    add(rewrite_case("both tier lists empty, leverage above 3", 56, rows=(56, 56, 56), tables=TABLES + ((56, ()),), users={1: {1: position(lev=9, table=56)}}))
    add(rewrite_case("both tier lists empty, leverage 2", 57, rows=(56, 56, 56), tables=TABLES + ((56, ()), (57, ())), users={1: {1: position(lev=2, table=56)}}))
    add(rewrite_case("stale asset key past the length", 51, stale=1, users={1: {0: position()}}))
    add(rewrite_case("stale asset key, deep", 51, asset=59, rows=rows_long, stale=59, users={1: held}))
    add(rewrite_case("stale old table id past the length", 51, rows=(70, 70, 70), stale=70, tables=TABLES))
    add(rewrite_case("stale new table id past the length", 70, stale=70))
    add(rewrite_case("stale position table past the length", 51, stale=70, users={1: {1: position(table=70)}}))
    add(rewrite_case("memo keys in reverse order", 52, users={at: {1: position(table=54 - at)} for at in range(1, 5)}))
    add(rewrite_case("memo keys around the start_byte", 52, rows=(51, 51, 51), users={1: {1: position(table=50)}, 2: {1: position(table=53)}, 3: {1: position(table=51)}, 4: {1: position(table=50)}, 5: {1: position(table=53)}}))
    add(rewrite_case("memo hit at each index", 52, users={at: {1: position(table=(50, 51, 53, 54)[at % 4])} for at in range(12)}))
    dexes = rewrite_case("second dex", 51, asset=10001)
    dexes["dex"], dexes["dexes"] = 0, (book(dex=1, users={1: {10001: position()}}),)
    add(dexes)
    return rows


def coins():
    return {"AAA": (0, 0), "BBB": (0, 1), "CCC": (1, 10000), "CCD": (1, 10001), "NOASSET": (0, None)}


def dex_pair():
    return (book(users={1: {0: position(), 1: position(lev=33)}, 2: {1: position(table=51)}}),
            book(dex=1, users={3: {10000: position(lev=45), 10001: position(table=7)}}))


def gate_cases():
    rows = []
    for start in GATES:
        def add(label, entries, names=None, dexes=None):
            rows.append(dict(kind="gate", label="%x %s" % (start, label), start=start, entries=entries, coins=names if names is not None else coins(), dexes=dexes if dexes is not None else dex_pair()))
        add("empty map", ())
        add("one builtin", (("AAA", 7),))
        add("one custom", (("BBB", 51),))
        add("two dexes", (("AAA", 51), ("CCC", 52)))
        add("five entries grow the vector", (("AAA", 51), ("BBB", 52), ("CCC", 53), ("CCD", 54), ("DDD", 5)), dict(coins(), DDD=(1, 10002)), (dex_pair()[0], book(rows=(50, 50, 50), dex=1)))
        add("id 49 not checked", (("AAA", 49),))
        add("id 50 checked", (("AAA", 50),), dexes=(book(tables=()), book(dex=1)))
        add("missing id first", (("AAA", 99),))
        add("missing id second keeps the previous id", (("AAA", 51), ("BBB", 99)))
        add("missing id third", (("AAA", 7), ("BBB", 51), ("CCC", 99)))
        add("first entries are not applied", (("AAA", 51), ("BBB", 99)))
        add("table on the other dex only", (("CCC", 60),), dexes=(book(tables=((60, STEP),)), book(dex=1)))
        add("coin of 100 bytes", (("A" * 100, 5),), {"A" * 100: (0, 0)})
        add("coin of 101 bytes", (("A" * 101, 5),), {"A" * 101: (0, 0)})
        add("long coin after a good one", (("AAA", 5), ("Z" * 101, 5)))
        add("unknown dex", (("NODEX", 5),))
        add("unknown coin", (("NOASSET", 5),))
        add("bad coin after a good one", (("AAA", 5), ("NOASSET", 5)))
        deep = tuple((50 + at * 2, STEP) for at in range(30))
        add("deep custom tables hit", (("AAA", 74),), dexes=(book(tables=deep), book(dex=1)))
        add("deep custom tables first separator", (("AAA", 60),), dexes=(book(tables=deep), book(dex=1)))
        add("deep custom tables miss", (("AAA", 75),), dexes=(book(tables=deep), book(dex=1)))
        add("deep custom tables above all", (("AAA", 200),), dexes=(book(tables=deep), book(dex=1)))
        add("no custom tables", (("AAA", 60),), dexes=(book(tables=()), book(dex=1)))
    return rows


def loop_cases():
    rows = []
    for start in LOOPS:
        def add(label, vector, dexes=None):
            rows.append(dict(kind="loop", label="%x %s" % (start, label), start=start, vector=vector, dexes=dexes if dexes is not None else dex_pair()))
        add("empty vector", ())
        add("one row", ((1, 51),))
        add("two dexes", ((0, 51), (10000, 7)))
        add("same asset twice", ((1, 51), (1, 52)))
        add("dex at the list length", ((20000, 7),))
        add("dex past the list after a good row", ((0, 7), (30000, 7)))
        add("row past the rows panics", ((5, 7),))
        add("missing table panics after a good row", ((0, 7), (1, 99)))
    return rows


def all_cases():
    return rewrite_cases() + gate_cases() + loop_cases()


# ---- static reads ----

GROUPS = (
    (GATES[0], "gate, copy 1"), (GATES[1], "gate, copy 2"), (GATES[2], "gate, copy 3"), (LOOPS[0], "apply loop, copy 1"), (LOOPS[1], "apply loop, copy 2"),
    (REWRITE, "per-user rewrite"), (RELATION, "table compare"), (MEMO_FIRST, "memo first insert"), (MEMO_MISS, "memo miss closure"), (GETTER, "table getter"), (ENTRY, "position entry"),
)
SLOTS = ((SLOT_REWRITE, REWRITE), (SLOT_GETTER, GETTER), (SLOT_LOOKUP, 0x33331A0), (SLOT_DEX, 0x3332080), (SLOT_ASSET, 0x374A1A0))
NAMES = (0x5A687C, 0x5B50BD)
NAME_TEXT = b"setMarginTableIds"
LOCATION_ROWS = ((LOC_ASSET, "asset id not in this dex, or index at or above the row count"), (LOC_TABLE, "custom table id missing from the map at +0x38"))
FIELDS = (
    ("clearinghouse +0x08, +0x10", "asset row pointer and row count; row stride 0x30, table id at row +0x18"),
    ("clearinghouse +0x30", "dex number compared with asset / 10000"),
    ("clearinghouse +0x38, +0x40", "custom tables: B-tree root and height; key u32 at +0x270, table value at +0x08 stride 0x38, length +0x29e, edges +0x2a0"),
    ("clearinghouse +0x50", "word copied to +0x30 of a built-in table"),
    ("clearinghouse +0xf8", "user hash table walked into a sorted address tree; row stride 0x78"),
    ("clearinghouse +0x128", "leverage index, argument of 0x370e6a0"),
    ("clearinghouse +0x170", "per-asset map, argument of 0x36f7350"),
    ("clearinghouse +0x188", "address set, gets every user that holds the asset"),
    ("user row +0x08, +0x10, +0x20", "position B-tree root and height, then a count word; key u64 at +0x2c8, value at +0x00 stride 0x40, length +0x322, edges +0x328"),
    ("position +0x04, +0x10, +0x38", "leverage u32, signed size, table id u32"),
    ("table +0x18, +0x20, +0x28", "tier B-tree root, height, length; key u64 at +0x168, value stride 0x20, leverage byte at value +0x18, length +0x1c2, first edge +0x1c8"),
)
REFERENCE_CLAIMS = (
    {"reference": "l1/action/vote_global.rs:75", "claim": "names SetMarginTableIds and a change row with margin_table_id", "observed": "the name is right; the action has no apply code in the reference tree", "verdict": "apply path missing"},
    {"reference": "l1/perp_meta.rs:298", "claim": "a table id change is one field write on the asset", "observed": "0x3704680 also walks every user: leverage clamp to the first tier, and a position table change only for compare result 1", "verdict": "per-user step missing"},
    {"reference": "l1/clearinghouse/margin_table.rs:198 relation_to", "claim": "0 no more permissive, 1 strictly more permissive, 2 incomparable", "observed": "0x3333920 gives the same three results over both tier lists", "verdict": "agrees; address and consumer were not named"},
)
REWRITE_REASONS = (
    (0x37046D3, 0x37048C3, "built-in table setup: read only by the stubbed builder or the stubbed drop"),
    (0x37048C3, 0x3704990, "table search depth, or setup read only by the stubbed builder or drop"),
    (0x3704990, 0x37049C0, "memo root setup, overwritten by the first insert"),
    (0x37049C0, 0x3704AA0, "descent to the first tier: every case has one tier leaf, or the bytes past it were zero"),
    (0x3704AA0, 0x3704BE0, "user iterator setup: read only by the stubbed walkers"),
    (0x3704BE0, 0x3704DB0, "position search internals: repeats the first search, or needs a depth the cases do not build"),
    (0x3704DB0, 0x3704EB0, "memo search internals: the memo stays one leaf"),
    (0x3704EB0, 0x3704FEC, "count bookkeeping: the size passed to 0x36f7350 is unchanged, so the count never moves"),
    (0x3704FEC, 0x37052A1, "iterator drain and drop path: frees are stubbed, or a panic tail"),
)
FUNCTION_REASONS = {
    GATES[0]: "iterator setup, string capacity or free path read only by a stub, or a table search limit no stale-key gate case reaches",
    GATES[1]: "iterator setup, string capacity or free path read only by a stub, or a table search limit no stale-key gate case reaches",
    GATES[2]: "iterator setup, string capacity or free path read only by a stub, or a table search limit no stale-key gate case reaches",
    LOOPS[0]: "tag passed to the stubbed drop, vector free path, or panic and recorder tail; the rewrite never returns an error",
    LOOPS[1]: "tag passed to the stubbed drop, vector free path, or panic and recorder tail; the rewrite never returns an error",
    RELATION: "tier tree walk above depth 0 or next-leaf step: every case has one leaf of at most 3 tiers, or a panic tail",
    MEMO_FIRST: "allocation size, node setup or return tag not read by this path, or a tree path the first insert never takes",
    MEMO_MISS: "drop path or empty-map path: the memo always holds the start_byte key, and frees are stubbed",
    GETTER: "built-in table fields read only by the stubbed builder or lookup, or a search limit over zero bytes",
    ENTRY: "vacant path: the position was found by the search just before this call",
}


def call_sites(image):
    """Every direct rel32 call to a gate or loop, and every FF 15 call through the rewrite slot."""
    relative = {}
    for slot, kind, addend, _ in image.relocations():
        if kind == 8:
            relative[slot] = addend
    for slot, target in SLOTS:
        if relative.get(slot) != target:
            raise EvidenceError("slot table changed")
    base, text = image.text_bytes()
    wanted = set(GATES + LOOPS)
    direct = {}
    at = text.find(b"\xe8")
    while 0 <= at <= len(text) - 5:
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in wanted:
            direct.setdefault(target, []).append(base + at)
        at = text.find(b"\xe8", at + 1)
    through = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == SLOT_REWRITE:
            through.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    rows = [{"function": "%#x" % key, "direct_calls": ["%#x" % va for va in sorted(direct.get(key, ()))]} for key in sorted(wanted)]
    return {"direct": rows, "rewrite_slot": "%#x" % SLOT_REWRITE, "rewrite_slot_calls": ["%#x" % va for va in through]}


def dex_list_reads(image):
    """The lea that passes the dex list to the coin resolver in each gate copy."""
    rows = []
    for start in GATES:
        begin, end = image.exact_fde(start)
        offset = image.offset(begin)
        data = bytes(image.blob[offset:offset + end - begin])
        at = data.find(b"\x48\x8d\x86")
        rows.append({"gate": "%#x" % start, "site": "%#x" % (begin + at), "offset": "%#x" % struct.unpack_from("<i", data, at + 3)[0]})
    return rows


def locations(image):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    rows = []
    for slot, role in LOCATION_ROWS:
        path, line, column = image.location(slot, relative)
        rows.append({"slot": "%#x" % slot, "path": path[path.find("l1/"):] if "l1/" in path else path, "line": line, "column": column, "role": role})
    return rows


def name_strings(image):
    rows = []
    for at in NAMES:
        base = image.offset(at)
        if bytes(image.blob[base:base + len(NAME_TEXT)]) != NAME_TEXT:
            raise EvidenceError("variant name moved")
        rows.append("%#x" % at)
    return rows


# ---- mutation ----

def displacement_at(image, row):
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
            disp = operand[4]
            end = row.size - (row.imm_size or 0)
            base = image.offset(row.va)
            data = bytes(image.blob[base:base + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    """Yield (va, byte offset in the instruction, xor mask, kind)."""
    for row in rows:
        at = displacement_at(image, row)
        if at is not None:
            yield row.va, at, 8, "offset"
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), 1, "branch"
        elif row.op in ("set", "cmov"):
            base = image.offset(row.va)
            yield row.va, bytes(image.blob[base:base + 16]).index(b"\x0f") + 1, 1, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, 1, "immediate"


def run_mutants(image, reached, cases):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for start, _ in GROUPS:
        begin, end = image.exact_fde(start)
        for va, at, xor, kind in mutation_targets(image, decode_range(image, begin, end)):
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            base = image.offset(va)
            machine.patches = {va + at: image.blob[base + at] ^ xor}
            machine.cache.pop(va, None)
            failed = None
            wanted = set(indices)
            for index in [item for item in first_kill if item in wanted] + indices:
                failed = compare_run(harness, cases[index])
                if failed:
                    if index in first_kill:
                        first_kill.remove(index)
                    first_kill.insert(0, index)
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
    return results


# ---- evidence ----

def outcome_of(case):
    _, panic, _, tag, _ = expected(case)
    if panic is not None:
        return "panic"
    return "ok" if tag in (None, OK) else "error %#x" % tag


def worked(image):
    """What one rewrite does to one position, read back from the real bytes."""
    harness = Harness(image)
    memory = harness.machine.memory
    rows = []
    for label, old, new, lev in (
        ("new table lower everywhere", 50, 51, 33), ("new table higher everywhere", 51, 50, 33), ("tier curves cross", 50, 53, 33),
        ("equal tiers under another id", 50, 55, 33), ("builtin 10x to custom", 10, 50, 7), ("custom to builtin 5x", 50, 5, 33),
    ):
        case = rewrite_case("w", new, rows=(old, old, old), users={1: {1: position(lev=lev, table=old)}})
        harness.run_rewrite(case)
        spot = harness.spots[0, 1, 1]
        rows.append({"label": label, "old_table": old, "new_table": new, "leverage_before": lev, "leverage_after": memory.read(spot + 4, 4), "position_table_after": memory.read(spot + 0x38, 4)})
    return rows


def stale_payload(image):
    """The word at out+4 of tag 0x154, read back from the real bytes."""
    harness = Harness(image)
    rows = []
    for label, entries in (("missing id first, nothing accepted", (("AAA", 99),)), ("missing id 99 after accepted id 51", (("AAA", 51), ("BBB", 99))), ("missing id 99 after 7 then 51", (("AAA", 7), ("BBB", 51), ("CCC", 99)))):
        case = dict(kind="gate", label="w", start=GATES[0], entries=entries, coins=coins(), dexes=dex_pair())
        harness.run_gate(case)
        rows.append({"label": label, "tag": "%#x" % harness.machine.memory.read(OUT, 2), "word_at_out_plus_4": "%#x" % harness.machine.memory.read(OUT + 4, 4)})
    return rows


def analyse(image, full=True):
    cases = all_cases()
    harness = Harness(image)
    machine = harness.machine
    mismatches, first = 0, ""
    reached = []
    outcomes = {}
    for case in cases:
        machine.seen = set()
        failed = compare_run(harness, case)
        reached.append(frozenset(machine.seen))
        if failed:
            mismatches += 1
            first = first or failed
        key = case["kind"] + " " + outcome_of(case)
        outcomes[key] = outcomes.get(key, 0) + 1
    functions = []
    touched = set().union(*reached)
    for start, role in GROUPS:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        base = image.offset(begin)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(bytes(image.blob[base:base + end - begin])).hexdigest(),
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched)})
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
        "fields": [{"where": where, "shape": shape} for where, shape in FIELDS],
        "variant_name_strings": name_strings(image),
        "callers": call_sites(image),
        "dex_list_reads": dex_list_reads(image),
        "locations": locations(image),
        "cases": {"total": len(cases), "outcomes": dict(sorted(outcomes.items()))},
        "mismatches": mismatches,
        "first_mismatch": first,
        "instructions_stepped": machine.steps,
        "worked": worked(image),
        "missing_table_payload": stale_payload(image),
        "reference_claims": list(REFERENCE_CLAIMS),
    }
    results = None
    if full:
        results = run_mutants(image, reached, cases)
        summary = {}
        for row in results:
            summary[row["result"]] = summary.get(row["result"], 0) + 1
        evidence["mutations"] = {name: summary.get(name, 0) for name in ("killed", "survived", "unreached")}
    return evidence, results


def reason_for(row):
    if row["function"] == REWRITE:
        for low, high, text in REWRITE_REASONS:
            if low <= row["va"] < high:
                return text
        return ""
    return FUNCTION_REASONS.get(row["function"], "")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    image = load_image()
    evidence, results = analyse(image)
    if evidence["mismatches"]:
        raise EvidenceError("specification mismatch: %s" % evidence["first_mismatch"])
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.json").write_text(json.dumps(evidence, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    for row in results:
        reason = "" if row["result"] == "killed" else reason_for(row)
        lines.append("%#x\t%#x\t%s\t%s\t%s\t%s" % (row["function"], row["va"], row["kind"], row["result"], row["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
