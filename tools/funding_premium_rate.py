#!/usr/bin/env python3
"""Pin the node #94 funding premium `0x3750ce0` and funding rate `0x3750610` from ELF bytes.

Both functions read one FundingTracker. The field offsets come from its serializer `0x3751850`. The real bytes run in a Python
evaluator with the edge callees stubbed (the map hash and the impact price walk). A separately written specification predicts
every result and every stub argument, and every condition, immediate, field offset, constant load and float opcode is flipped
to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
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

PREMIUM = 0x3750CE0
RATE = 0x3750610
SERIALIZER = 0x3751850
HASHER = 0x399C4A0
IMPACT = 0x3C027D0
SLOT_PREMIUM = 0x57745A8
SLOT_RATE = 0x5774D48
SLOT_PANIC = 0x576E470
SLOT_SUB = 0x576E150
SLOT_ONCE = 0x576E8B8
SLOT_CLAMP_PANIC = 0x576E098
LOC_ASSET = 0x56F21C0
LOC_DECIMALS = 0x56F3350
ONCE_WORD = 0x577AB98
STRUCT_NAME = 0x3AFC25
STRUCT_NAME_TEXT = b"struct FundingTracker with 8 elements"

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
HEAP_SIZE = 0x8000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 40000
MUTANT_STEP_LIMIT = 8000

OUT = HEAP_BASE + 0x100
BOOK = HEAP_BASE + 0x200
TRACKER = HEAP_BASE + 0x400
META = HEAP_BASE + 0x600
ROWS = HEAP_BASE + 0x700
MAP_BASES = {"override": HEAP_BASE + 0x1000, "multiplier": HEAP_BASE + 0x1600, "interest": HEAP_BASE + 0x1C00}
NODES = HEAP_BASE + 0x2400
SAMPLES = HEAP_BASE + 0x6000
ROW_STRIDE = 0x30
BUCKETS = 64

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

def to_float_u64(value):
    return float(value)


def premium_spec(case):
    """Independent statement of 0x3750ce0. Returns (panic, result, calls)."""
    asset, dex, rows = case["asset"], case["dex"], case["sz_decimals"]
    calls = []
    if asset // 10000 != dex or asset % 10000 >= len(rows):
        return ("panic", 194), None, calls
    sz = rows[asset % 10000]
    if sz > 6:
        return ("sub_overflow", 319), None, calls
    scale = 10.0 ** (6 - sz)
    oracle = float(case["oracle"]) / scale
    if oracle == 0.0:
        if case.get("once"):
            calls.append(("once",))
        return None, None, calls
    notional = case["default_impact"]
    if case["override"]:
        calls.append(("hash", 0x00, asset))
        notional = dict((k, v) for k, v in case["override"]).get(asset, notional)
    calls.append(("impact", 0x80, notional))
    calls.append(("impact", 0x98, notional))
    bid, ask = case["bid"], case["ask"]
    if bid == 0 or ask == 0:
        return None, None, calls
    high, low = float(bid) / scale, float(ask) / scale
    if case["binance"]:
        above = high - oracle
        below = -(low - oracle)
        premium = ((above if above > 0.0 else 0.0) - (below if below > 0.0 else 0.0)) / oracle
    else:
        premium = (high + low) * 0.5 / oracle + -1.0
    if asset in case["hl_only"]:
        premium /= 100.0
    if math.isfinite(premium):
        lower = -0.5 if -0.5 > premium else premium
        premium = 0.5 if 0.5 < lower else lower
    return None, (premium, bid, ask), calls


def rate_spec(case):
    """Independent statement of 0x3750610. Returns (result, calls)."""
    asset = case["asset"]
    calls = []
    samples = dict(case["premiums"]).get(asset)
    if not samples:
        return None, calls
    total = -0.0
    for value in samples:
        total += value
    mean = total / float(len(samples))
    interest = 0.0001
    if case["interest"]:
        calls.append(("hash", 0x60, asset))
        interest = dict(case["interest"]).get(asset, interest)
    gap = interest - mean
    bound = case["clamp"]
    if math.isfinite(gap) and math.isfinite(bound):
        low, high = sorted((bound, -bound)) if bound else (-0.0, 0.0)
        floor = low if low > gap else gap
        gap = high if high < floor else floor
    value = gap + mean
    multiplier = 1.0
    if case["multiplier"]:
        calls.append(("hash", 0x30, asset))
        multiplier = dict(case["multiplier"]).get(asset, multiplier)
    value *= multiplier
    if math.isfinite(value):
        floor = -0.32 if -0.32 > value else value
        value = 0.32 if 0.32 < floor else floor
    return value * 0.125, calls


# ---- harness ----

def mix(value):
    return (value * 0x9E3779B97F4A7C15 + 0x1234567) & MASK[8]


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        machine.calls = {HASHER: self.on_hash, IMPACT: self.on_impact}
        tokens = {SLOT_PANIC: self.on_panic, SLOT_SUB: self.on_sub, SLOT_ONCE: self.on_once, SLOT_CLAMP_PANIC: self.on_clamp}
        for at, (slot, hook) in enumerate(tokens.items()):
            token = 0x7000000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        self.case = None
        self.calls = []
        self.hashes = {}

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_sub(self, machine):
        raise Panicked(("sub_overflow", machine.regs[RDI]))

    def on_clamp(self, machine):
        raise Panicked(("clamp", machine.regs[RDI]))

    def on_once(self, machine):
        if machine.regs[RDI] != ONCE_WORD or machine.regs[RSI] & 0xFF != 1:
            raise Halt("bad once arguments")
        self.calls.append(("once",))

    def on_hash(self, machine):
        field = machine.regs[RDI] - 0x20 - TRACKER
        key = machine.memory.read(machine.regs[RSI], 8)
        self.calls.append(("hash", field, key))
        machine.regs[RAX] = self.hashes.get(key, mix(key))

    def on_impact(self, machine):
        if machine.regs[RDI] != BOOK:
            raise Halt("impact on another book")
        field = machine.regs[RDX] - BOOK
        self.calls.append(("impact", field, machine.memory.read(machine.regs[RSI], 8)))
        machine.regs[RAX] = self.case["bid"] if field == 0x80 else self.case["ask"]

    def table(self, name, entries):
        """Lay out one hash table the way the probe loop in the target reads it."""
        memory = self.machine.memory
        base = MAP_BASES[name]
        field = {"override": 0x00, "multiplier": 0x30, "interest": 0x60}[name]
        ctrl = base + BUCKETS * 16
        control = bytearray(b"\xff" * (BUCKETS + 16))
        for key, bits in entries:
            hashed = self.hashes.get(key, mix(key))
            top = hashed >> 57
            pos, stride = hashed & (BUCKETS - 1), 0
            while True:
                free = [at for at in range(16) if control[(pos + at) & (BUCKETS - 1)] == 0xFF]
                if free:
                    break
                stride += 16
                pos = (pos + stride) & (BUCKETS - 1)
            index = (pos + free[0]) & (BUCKETS - 1)
            control[index] = top
            if index < 16:
                control[BUCKETS + index] = top
            memory.write(ctrl - 16 * (index + 1), 8, key)
            memory.write(ctrl - 16 * (index + 1) + 8, 8, bits)
        memory.put_bytes(ctrl, bytes(control))
        for offset, value in ((0, ctrl), (8, BUCKETS - 1), (0x10, 0), (0x18, len(entries))):
            memory.write(TRACKER + field + offset, 8, value)

    def nodes(self, keys, write_value, shape, at):
        """Lay out a B-tree of height 0 or 1; returns (root, height, next free address)."""
        key_at, len_at, edge_at, size = shape
        memory = self.machine.memory

        def stale(address, used):
            if "stale" in self.case:
                for index in range(used, 11):
                    memory.write(address + key_at + 8 * index, 8, self.case["stale"])

        def leaf(chunk, address):
            memory.write(address + len_at, 2, len(chunk))
            stale(address, len(chunk))
            for index, key in enumerate(chunk):
                memory.write(address + key_at + 8 * index, 8, key)
                write_value(address, index, key)
            return address + size

        if len(keys) <= 11:
            return at, 0, leaf(keys, at)
        separators = keys[5::6][:11]
        root = at
        at += size
        memory.write(root + len_at, 2, len(separators))
        stale(root, len(separators))
        start = 0
        for index, separator in enumerate(separators):
            memory.write(root + key_at + 8 * index, 8, separator)
            write_value(root, index, separator)
            stop = keys.index(separator)
            memory.write(root + edge_at + 8 * index, 8, at)
            at = leaf(keys[start:stop], at)
            start = stop + 1
        memory.write(root + edge_at + 8 * len(separators), 8, at)
        at = leaf(keys[start:], at)
        return root, 1, at

    def layout(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset()
        self.case = case
        self.calls = []
        self.hashes = dict(case.get("hashes", ()))
        memory.statics[ONCE_WORD] = 1 if case.get("once") else 0
        for name in MAP_BASES:
            entries = case.get(name, ())
            bits = [(key, value if name == "override" else to_bits(value)) for key, value in entries]
            self.table(name, bits)
        memory.write(TRACKER + 0xA8, 8, to_bits(case.get("clamp", 0.0)))
        memory.write(TRACKER + 0xB0, 8, case.get("default_impact", 0))
        memory.write(TRACKER + 0xD0, 1, 1 if case.get("binance") else 0)
        at = NODES
        premiums = dict(case.get("premiums", ()))
        keys = sorted(premiums)
        cursor = [SAMPLES]

        def write_vector(node, index, key):
            samples = premiums[key]
            address = cursor[0]
            cursor[0] += 8 * len(samples)
            for position, value in enumerate(samples):
                memory.write(address + 8 * position, 8, to_bits(value))
            memory.write(node + 0x60 + 24 * index, 8, len(samples))
            memory.write(node + 0x68 + 24 * index, 8, address)
            memory.write(node + 0x70 + 24 * index, 8, len(samples))

        root, height = 0, 0
        if keys:
            root, height, at = self.nodes(keys, write_vector, (8, 0x16A, 0x170, 0x1D0), at)
        memory.write(TRACKER + 0x90, 8, root)
        memory.write(TRACKER + 0x98, 8, height)
        keys = sorted(case.get("hl_only", ()))
        root, height = 0, 0
        if keys:
            root, height, at = self.nodes(keys, lambda *_: None, (8, 0x62, 0x68, 0xC8), at)
        memory.write(TRACKER + 0xB8, 8, root)
        memory.write(TRACKER + 0xC0, 8, height)
        rows = case.get("sz_decimals", ())
        memory.write(META + 0x30, 8, case.get("dex", 0))
        memory.write(META + 0x08, 8, ROWS)
        memory.write(META + 0x10, 8, len(rows))
        for index, value in enumerate(rows):
            memory.write(ROWS + ROW_STRIDE * index + 0x2A, 1, value)

    def premium(self, case):
        self.layout(case)
        machine = self.machine
        memory = machine.memory
        try:
            value = machine.run(PREMIUM, {RDI: OUT, RSI: TRACKER, RDX: case["asset"], RCX: case["oracle"], R8: BOOK, R9: META})
        except Panicked as error:
            return error.args[0], None, self.calls
        if value != OUT:
            raise Halt("output pointer not returned")
        bid = memory.read(OUT + 8, 8)
        if bid == 0:
            return None, None, self.calls
        return None, (to_float(memory.read(OUT, 8)), bid, memory.read(OUT + 16, 8)), self.calls

    def rate(self, case):
        self.layout(case)
        machine = self.machine
        value = machine.run(RATE, {RDI: TRACKER, RSI: case["asset"]})
        if value == 0:
            return None, self.calls
        if value != 1:
            raise Halt("bad option tag")
        return to_float(machine.xmm[0] & MASK[8]), self.calls


def same(left, right):
    return left == right and math.copysign(1.0, left) == math.copysign(1.0, right) or (left != left and right != right)


def compare_run(harness, case):
    """Return None when the real bytes match the specification, else a short description."""
    label = case["label"]
    try:
        if case["kind"] == "premium":
            panic, result, calls = harness.premium(case)
            want_panic, want_result, want_calls = premium_spec(case)
            if want_panic:
                loc = {194: LOC_ASSET, 319: LOC_DECIMALS}[want_panic[1]]
                want_panic = (want_panic[0], loc)
            if panic != want_panic:
                return "%s: panic %r, spec %r" % (label, panic, want_panic)
            if (result is None) != (want_result is None):
                return "%s: option %r, spec %r" % (label, result, want_result)
            if result and not (same(result[0], want_result[0]) and result[1:] == want_result[1:]):
                return "%s: result %r, spec %r" % (label, result, want_result)
        else:
            result, calls = harness.rate(case)
            want_result, want_calls = rate_spec(case)
            if (result is None) != (want_result is None):
                return "%s: option %r, spec %r" % (label, result, want_result)
            if result is not None and not same(result, want_result):
                return "%s: result %r, spec %r" % (label, result, want_result)
    except (Halt, Panicked, EvidenceError, ZeroDivisionError, OverflowError, KeyError, IndexError, ValueError) as error:
        return "%s: stopped: %s" % (label, error)
    if calls != want_calls:
        return "%s: calls %r, spec %r" % (label, calls, want_calls)
    return None


# ---- cases ----

def stream(start):
    state = start
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11


def premium_case(label, **fields):
    case = dict(kind="premium", label=label, asset=1, dex=0, sz_decimals=(3, 2, 5), oracle=1000000, bid=1010000, ask=1020000, binance=False,
                override=(), default_impact=20000000000, hl_only=(), clamp=0.0005)
    case.update(fields)
    return case


def rate_case(label, **fields):
    case = dict(kind="rate", label=label, asset=7, premiums=((7, (0.0001,)),), interest=(), multiplier=(), clamp=0.0005)
    case.update(fields)
    return case


def crowded(key, count):
    """Keys sharing one start bucket and one tag; the wanted key lands after them."""
    hashes = [(9000 + at, 0x0A00000000000005) for at in range(count)] + [(key, 0x0A00000000000005)]
    return tuple(hashes)


def split_tags(key):
    """Tag matches two slots apart from each other, with other tags between them."""
    near, far = 0x0A00000000000005, 0x0C00000000000005
    return ((9000, near), (9001, far), (9002, far), (key, near))


def premium_cases():
    rows = []
    add = rows.append
    add(premium_case("asset id outside the dex", asset=10001))
    add(premium_case("dex mismatch high", asset=20001, dex=1))
    add(premium_case("local index at the row count", asset=3))
    add(premium_case("second dex asset", asset=10002, dex=1))
    add(premium_case("empty rows", asset=0, sz_decimals=()))
    for sz in (0, 1, 2, 3, 4, 5, 6, 7, 8, 255):
        add(premium_case("decimals %d" % sz, sz_decimals=(0, sz)))
        add(premium_case("decimals %d binance" % sz, sz_decimals=(0, sz), binance=True))
    add(premium_case("oracle zero", oracle=0))
    add(premium_case("oracle zero, once word set", oracle=0, once=True))
    add(premium_case("oracle zero, binance", oracle=0, binance=True, override=((1, 5),)))
    add(premium_case("oracle one", oracle=1))
    add(premium_case("oracle at 2^63", oracle=1 << 63))
    add(premium_case("oracle at 2^64-1", oracle=MASK[8]))
    add(premium_case("oracle 2^53+1", oracle=(1 << 53) + 1, bid=(1 << 53) + 3, ask=(1 << 53) + 5))
    for formula in (False, True):
        tag = "binance" if formula else "mid"
        add(premium_case(tag + " bid none", bid=0, binance=formula))
        add(premium_case(tag + " ask none", ask=0, binance=formula))
        add(premium_case(tag + " both none", ask=0, bid=0, binance=formula))
        add(premium_case(tag + " both above", bid=1010000, ask=1020000, binance=formula))
        add(premium_case(tag + " both below", bid=980000, ask=990000, binance=formula))
        add(premium_case(tag + " oracle between", bid=990000, ask=1010000, binance=formula))
        add(premium_case(tag + " crossed around oracle", bid=1010000, ask=990000, binance=formula))
        add(premium_case(tag + " equal to oracle", bid=1000000, ask=1000000, binance=formula))
        add(premium_case(tag + " high bit prices", bid=1 << 63, ask=(1 << 63) + (1 << 20), oracle=1 << 62, binance=formula))
        add(premium_case(tag + " top prices", bid=MASK[8], ask=MASK[8] - 1024, oracle=1, binance=formula))
        add(premium_case(tag + " clamp high", bid=1700000, ask=1700000, binance=formula))
        add(premium_case(tag + " clamp low", bid=100000, ask=100000, binance=formula))
        add(premium_case(tag + " exactly plus half", bid=1500000, ask=1500000, binance=formula))
        add(premium_case(tag + " exactly minus half", bid=500000, ask=500000, binance=formula))
        add(premium_case(tag + " hl only below the clamp", bid=1200000, ask=1200000, hl_only=(1,), binance=formula))
        add(premium_case(tag + " hl only above the clamp", bid=1700000, ask=1700000, hl_only=(1,), binance=formula))
        add(premium_case(tag + " hl only far above", bid=90000000, ask=90000000, hl_only=(1,), binance=formula))
        add(premium_case(tag + " hl only low", bid=100000, ask=100000, hl_only=(1,), binance=formula))
        add(premium_case(tag + " hl only other asset", bid=1200000, ask=1200000, hl_only=(0, 2, 5), binance=formula))
        add(premium_case(tag + " hl only first key", asset=1, hl_only=(1, 2, 3), binance=formula))
        add(premium_case(tag + " hl only last key", asset=1, hl_only=(0, 1), binance=formula))
        add(premium_case(tag + " hl only deep leaf", asset=1, hl_only=(0,) + tuple(range(1, 30)), binance=formula))
    many = tuple(range(0, 60, 2))
    sizes = tuple(2 for _ in range(61))
    for asset in (0, 1, 10, 11, 12, 13, 24, 30, 58, 59, 60):
        add(premium_case("deep set, asset %d" % asset, asset=asset, sz_decimals=sizes, hl_only=many, bid=1200000, ask=1200000))
    add(premium_case("override used", override=((1, 5000000000),)))
    add(premium_case("override other asset", override=((2, 5000000000),)))
    add(premium_case("override zero value", override=((1, 0),)))
    add(premium_case("override, many keys", override=tuple((at, 100 + at) for at in range(10))))
    add(premium_case("override, default zero", default_impact=0))
    add(premium_case("override behind a tag clash", override=((9000, 3), (9001, 4), (1, 5)), hashes=crowded(1, 2)))
    add(premium_case("override in the next group", override=tuple((9000 + at, at) for at in range(16)) + ((1, 77),), hashes=crowded(1, 16)))
    add(premium_case("override miss after a full group", override=tuple((9000 + at, at) for at in range(16)), hashes=crowded(1, 16)))
    add(premium_case("override miss after two groups", override=tuple((9000 + at, at) for at in range(29)), hashes=crowded(1, 29)))
    add(premium_case("override in the third group", override=tuple((9000 + at, at) for at in range(32)) + ((1, 77),), hashes=crowded(1, 32)))
    add(premium_case("override behind split tags", override=((9000, 3), (9001, 4), (9002, 6), (1, 5)), hashes=split_tags(1)))
    add(premium_case("first asset of dex 1", asset=10000, dex=1, sz_decimals=(2,)))
    add(premium_case("last index of dex 0", asset=9999, sz_decimals=(2,)))
    add(premium_case("first asset of dex 65535", asset=655350000, dex=65535, sz_decimals=(2,)))
    add(premium_case("below dex 65535", asset=655349999, dex=65534, sz_decimals=(2,)))
    add(premium_case("stale set key past the length", asset=11, hl_only=(1, 2), stale=11, sz_decimals=tuple(2 for _ in range(12)), bid=1200000, ask=1200000))
    add(premium_case("stale set key, deep", asset=31, hl_only=tuple(range(0, 30, 2)), stale=31, sz_decimals=tuple(2 for _ in range(32)), bid=1200000, ask=1200000))
    values = stream(94)
    for index in range(180):
        oracle = next(values) % (1 << (10 + index % 42)) + 1
        spread = lambda: oracle + (next(values) % (oracle // 2 + 2)) - oracle // 4
        add(premium_case("sweep %d" % index, oracle=oracle, bid=spread() or 1, ask=spread() or 1, binance=bool(index & 1), sz_decimals=(1, index % 7, 4),
                         hl_only=(1,) if index % 5 == 0 else (), override=((1, next(values)),) if index % 3 == 0 else ()))
    return rows


def rate_cases():
    rows = []
    add = rows.append
    add(rate_case("empty map", premiums=()))
    add(rate_case("asset missing", premiums=((6, (0.1,)), (8, (0.1,)))))
    add(rate_case("asset behind keys", premiums=((1, (0.1,)), (2, (0.2,)), (7, (0.3,)))))
    add(rate_case("empty vector", premiums=((7, ()),)))
    add(rate_case("empty vector with a rate map", premiums=((7, ()),), interest=((7, 0.01),)))
    for size in (1, 2, 3, 6, 7, 8, 9, 15, 16, 17, 23, 24, 25):
        add(rate_case("%d samples" % size, premiums=((7, tuple(0.0001 * (at + 1) * (-1) ** at for at in range(size))),)))
        add(rate_case("%d samples clamp off" % size, clamp=math.inf, premiums=((7, tuple(0.001 + at / 7.0 for at in range(size))),)))
    add(rate_case("negative zero sample", premiums=((7, (-0.0,)),), interest=((7, 0.0),)))
    add(rate_case("positive zero sample", premiums=((7, (0.0,)),), interest=((7, 0.0),)))
    add(rate_case("zero samples, default rate", premiums=((7, (0.0, 0.0, 0.0)),)))
    for clamp in (0.0, -0.0, 0.0005, -0.0005, 1e-12, 1.0, math.inf, -math.inf, math.nan):
        for premium in (0.0, 0.0002, -0.0002, 0.002, -0.002):
            add(rate_case("clamp %r premium %r" % (clamp, premium), clamp=clamp, premiums=((7, (premium,)),)))
    add(rate_case("sample nan", premiums=((7, (math.nan, 0.1)),)))
    add(rate_case("sample infinity", premiums=((7, (math.inf, 0.1)),)))
    add(rate_case("sample minus infinity", premiums=((7, (-math.inf,)),)))
    add(rate_case("samples infinity both ways", premiums=((7, (math.inf, -math.inf)),)))
    add(rate_case("rate nan", interest=((7, math.nan),)))
    add(rate_case("rate infinity", interest=((7, math.inf),)))
    add(rate_case("rate map other asset", interest=((8, 0.01),)))
    add(rate_case("rate map value", interest=((7, 0.003),), clamp=1.0))
    add(rate_case("rate map zero", interest=((7, 0.0),)))
    add(rate_case("rate map negative", interest=((7, -0.01),), clamp=0.5))
    add(rate_case("rate map tag clash", interest=((9000, 0.1), (9001, 0.2), (7, 0.003)), hashes=crowded(7, 2), clamp=1.0))
    add(rate_case("rate map next group", interest=tuple((9000 + at, 0.1) for at in range(16)) + ((7, 0.003),), hashes=crowded(7, 16), clamp=1.0))
    add(rate_case("rate map miss after a group", interest=tuple((9000 + at, 0.1) for at in range(16)), hashes=crowded(7, 16), clamp=1.0))
    add(rate_case("rate map third group", interest=tuple((9000 + at, 0.1) for at in range(32)) + ((7, 0.003),), hashes=crowded(7, 32), clamp=1.0))
    add(rate_case("rate map split tags", interest=((9000, 0.1), (9001, 0.2), (9002, 0.3), (7, 0.003)), hashes=split_tags(7), clamp=1.0))
    add(rate_case("multiplier third group", multiplier=tuple((9000 + at, 2.0) for at in range(32)) + ((7, 0.5),), hashes=crowded(7, 32)))
    add(rate_case("multiplier split tags", multiplier=((9000, 2.0), (9001, 3.0), (9002, 4.0), (7, 0.5)), hashes=split_tags(7)))
    add(rate_case("stale premium key", premiums=((1, (0.1,)), (2, (0.2,))), stale=7))
    add(rate_case("stale premium key in a leaf", asset=9, premiums=tuple((key, (0.1,)) for key in range(0, 16, 2)), stale=9))
    add(rate_case("largest finite gap", interest=((7, sys.float_info.max),), clamp=0.5))
    add(rate_case("largest finite clamp", clamp=sys.float_info.max))
    add(rate_case("multiplier value", multiplier=((7, 2.5),)))
    add(rate_case("multiplier other asset", multiplier=((8, 2.5),)))
    add(rate_case("multiplier zero", multiplier=((7, 0.0),)))
    add(rate_case("multiplier negative", multiplier=((7, -3.0),)))
    add(rate_case("multiplier nan", multiplier=((7, math.nan),)))
    add(rate_case("multiplier infinity", multiplier=((7, math.inf),)))
    add(rate_case("multiplier tag clash", multiplier=((9000, 2.0), (9001, 3.0), (7, 0.5)), hashes=crowded(7, 2)))
    add(rate_case("multiplier next group", multiplier=tuple((9000 + at, 2.0) for at in range(16)) + ((7, 0.5),), hashes=crowded(7, 16)))
    add(rate_case("multiplier miss after a group", multiplier=tuple((9000 + at, 2.0) for at in range(16)), hashes=crowded(7, 16)))
    add(rate_case("both maps", interest=((7, 0.002),), multiplier=((7, 3.0),), clamp=0.1))
    add(rate_case("saturates high", premiums=((7, (0.5,)),), multiplier=((7, 1.0),)))
    add(rate_case("saturates low", premiums=((7, (-0.5,)),)))
    add(rate_case("exactly plus 0.32", premiums=((7, (0.32,)),), interest=((7, 0.32),)))
    add(rate_case("exactly minus 0.32", premiums=((7, (-0.32,)),), interest=((7, -0.32),)))
    add(rate_case("saturates by multiplier", premiums=((7, (0.1,)),), multiplier=((7, 10.0),)))
    keys = tuple(range(0, 80, 2))
    for asset in (0, 2, 10, 12, 22, 24, 40, 78, 79, 80, 11):
        add(rate_case("deep tree, asset %d" % asset, asset=asset, premiums=tuple((key, (0.0001 * key,)) for key in keys)))
    values = stream(412)
    for index in range(150):
        size = 1 + next(values) % 12
        scale = (1e-5, 1e-4, 1e-3, 1e-2, 0.1, 1.0)[index % 6]
        samples = tuple(scale * ((next(values) % 2001) - 1000.0) / 1000.0 for _ in range(size))
        add(rate_case("sweep %d" % index, premiums=((7, samples),), clamp=(0.0005, 0.001, 0.0)[index % 3],
                      interest=((7, ((next(values) % 201) - 100.0) / 10000.0),) if index % 4 == 0 else (),
                      multiplier=((7, (next(values) % 101) / 10.0),) if index % 5 == 0 else ()))
    return rows


def all_cases():
    return premium_cases() + rate_cases()


# ---- static reads ----

GROUPS = ((PREMIUM, "funding premium"), (RATE, "funding rate"))
FIELD_TOKENS = (
    ("name", "asset_to_premiums"), ("offset", 0x90), ("name", "override_impact_usd"), ("offset", 0x00), ("offset", 0xA8), ("name", "clamp"),
    ("name", "default_impact_usd"), ("offset", 0xB0), ("name", "hl_only_perps"), ("offset", 0xB8), ("offset", 0xD0), ("name", "use_binance_formula"),
    ("offset", 0x30), ("name", "perp_to_funding_multiplier"), ("offset", 0x60), ("name", "perp_to_funding_interest_rate"),
)
FIELDS = (
    (0x00, "override_impact_usd", "hash map asset to u64 impact notional: control, mask, items +0x18, hasher +0x20; slot 16 bytes"),
    (0x30, "perp_to_funding_multiplier", "hash map asset to f64; same shape"),
    (0x60, "perp_to_funding_interest_rate", "hash map asset to f64; same shape"),
    (0x90, "asset_to_premiums", "B-tree asset to Vec of f64: root, +0x98 height; node keys +0x08, vectors +0x60 stride 24, length +0x16a, edges +0x170"),
    (0xA8, "clamp", "f64, sign ignored"),
    (0xB0, "default_impact_usd", "u64"),
    (0xB8, "hl_only_perps", "B-tree set of asset: root, +0xc0 height; node keys +0x08, length +0x62, edges +0x68"),
    (0xD0, "use_binance_formula", "byte, nonzero selects the impact gap formula"),
)
REFERENCE_CLAIMS = (
    {"reference": "l1/perp_meta.rs:470 compute_premium_and_impact_pxs", "claim": "one formula ((bid + ask) * 0.5 - oracle) / oracle", "observed": "0x3750ce0 has two: (max(first - oracle, 0) - max(oracle - second, 0)) / oracle when +0xd0 is nonzero, else mid / oracle - 1.0", "verdict": "second formula missing, and the first rounds differently"},
    {"reference": "l1/perp_meta.rs:482", "claim": "clamp to [-0.5, 0.5], then divide by 100", "observed": "the division by 100.0 comes first and the clamp second, so a member of hl_only_perps reaches +-0.5", "verdict": "order reversed"},
    {"reference": "l1/perp_meta.rs:481", "claim": "oracle 0 gives premium 0.0", "observed": "oracle 0 returns None with out+8 = 0 and the impact walk is not called", "verdict": "differs"},
    {"reference": "l1/dex_registry/perp_dex.rs:183 and l1/dex_registry/dex_registry.rs:154", "claim": "FundingTracker holds one field", "observed": "the struct name string says 8 elements and serializer 0x3751850 writes all 8", "verdict": "fields missing"},
    {"reference": "l1/ (whole tree)", "claim": "no 0.32, 0.125 or default 0.0001 funding formula", "observed": "0x3750610 is that formula", "verdict": "missing in the reference"},
)
REASONS = (
    ((PREMIUM, 0x3750D91, 0x3750D93), "oracle is a u64 over a power of ten, so the compare with 0.0 is never unordered"),
    ((PREMIUM, 0x3750DF9, 0x3750DFE), "pshuflw already filled the low four words with the tag, so 0x44 and 0x45 give the same bytes"),
    ((PREMIUM, 0x3750F92, 0x3750F9A), "the eight bytes after the used lane also leave the low lane sign mask in place"),
    ((RATE, 0x37507A5, 0x37507AA), "pshuflw already filled the low four words with the tag, so 0x44 and 0x45 give the same bytes"),
    ((RATE, 0x37508EF, 0x37508F4), "pshuflw already filled the low four words with the tag, so 0x44 and 0x45 give the same bytes"),
    ((RATE, 0x3750848, 0x3750852), "bit 0 of the mask cannot change a compare against 0x7fefffffffffffff: only a non-finite value is above it, with or without bit 0"),
    ((RATE, 0x3750872, 0x375087A), "the eight bytes after the used lane also leave the low lane sign mask in place"),
    ((PREMIUM, 0x3750F1A, 0x3750F28), "repeats the size check at 0x3750d48 on the same byte"),
    ((PREMIUM, 0x3750FCF, 0x3750FE2), "repeats the size check at 0x3750d48 on the same byte"),
    ((PREMIUM, 0x3751036, 0x375107E), "u64 prices over a power of ten stay below the 8.98e307 limit, and halving first gives the same value in this range"),
    ((PREMIUM, 0x37510DF, 0x37510FA), "the key compare result has only the three values -1, 0, 1"),
    ((PREMIUM, 0x3751102, 0x3751143), "the premium is finite for every u64 input (at most about 1.8e25), so the non-finite skip never runs"),
    ((PREMIUM, 0x375115E, 0x37511C0), "panic and side-call tail: the arguments are not compared beyond the stub checks"),
    ((RATE, 0x375067D, 0x3750690), "the key compare result has only the three values -1, 0, 1"),
    ((RATE, 0x375088A, 0x3750894), "bounds are built from min and max of finite values, so min > max never happens and the assert stays dead"),
    ((RATE, 0x37509BD, 0x3750A07), "dead assert tail of f64::clamp"),
)


def serializer_tokens(image):
    """Field names and offsets in the order the serializer touches them."""
    start, end = image.exact_fde(SERIALIZER)
    rows = decode_range(image, start, end)
    tokens = []
    for index, row in enumerate(rows):
        if row.op == "lea" and row.b[0] == "m" and row.b[1] is None:
            lengths = [other.b[1] for other in rows[index + 1:index + 3] if other.op == "mov" and other.b and other.b[0] == "i" and other.a[0] == "r" and other.a[1] in (RDX, RCX)]
            if lengths:
                at = image.offset(row.b[4])
                tokens.append(("name", bytes(image.blob[at:at + lengths[0]]).decode("ascii")))
            continue
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] == R14:
                tokens.append(("offset", operand[4]))
        if row.op == "add" and row.a == ("r", R14):
            tokens.append(("offset", row.b[1]))
        if row.op == "mov" and row.b == ("r", R14) and row.a == ("r", RSI):
            tokens.append(("offset", 0))
    return tokens


def field_map(image):
    tokens = serializer_tokens(image)
    if tuple(tokens) != FIELD_TOKENS:
        raise EvidenceError("serializer field order changed: %r" % (tokens,))
    at = image.offset(STRUCT_NAME)
    if bytes(image.blob[at:at + len(STRUCT_NAME_TEXT)]) != STRUCT_NAME_TEXT:
        raise EvidenceError("struct name string changed")
    return [{"offset": "%#04x" % offset, "name": name, "shape": shape} for offset, name, shape in FIELDS]


def rodata_reads(image, rows):
    """Every non-lea read of .rodata through a rip-relative operand, with the eight bytes at the target."""
    section = image.named[".rodata"]
    out = []
    for row in rows:
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] is None and operand[2] is None and row.op != "lea" and section["address"] <= operand[4] < section["address"] + section["size"]:
                base = image.offset(operand[4])
                data = bytes(image.blob[base:base + (16 if row.width == 16 else 8)])
                entry = {"site": "%#x" % row.va, "op": row.op, "target": "%#x" % operand[4], "hex": data.hex()}
                if row.width == 8:
                    entry["f64"] = repr(struct.unpack("<d", data)[0])
                out.append(entry)
    return out


def scale_table(image):
    base = image.offset(0x584B08)
    values = struct.unpack_from("<7d", image.blob, base)
    if values != tuple(10.0 ** at for at in range(7)):
        raise EvidenceError("scale table changed")
    return {"address": "0x584b08", "values": [repr(v) for v in values], "index": "6 - sz_decimals"}


def call_sites(image):
    """Who reaches each function: its data slot, FF 15 calls through the slot, and direct rel32 bytes."""
    wanted = {SLOT_PREMIUM: PREMIUM, SLOT_RATE: RATE}
    slots = {}
    for slot, kind, addend, _ in image.relocations():
        if kind == 8 and addend in (PREMIUM, RATE):
            slots.setdefault(addend, []).append(slot)
    for slot, target in wanted.items():
        if slots.get(target) != [slot]:
            raise EvidenceError("slot table changed")
    base, text = image.text_bytes()
    found = {SLOT_PREMIUM: [], SLOT_RATE: []}
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        slot = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if slot in found:
            found[slot].append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    direct = {PREMIUM: 0, RATE: 0}
    for opcode in (b"\xe8", b"\xe9"):
        at = text.find(opcode)
        while 0 <= at <= len(text) - 5:
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in direct:
                direct[target] += 1
            at = text.find(opcode, at + 1)
    return [{"function": "%#x" % wanted[slot], "slot": "%#x" % slot, "indirect_calls": ["%#x" % va for va in found[slot]], "direct_rel32": direct[wanted[slot]]} for slot in wanted]


def side_call(image):
    """Section and stored bytes of the word gating the side call at 0x375116b."""
    at = image.offset(ONCE_WORD)
    section = [row["name"] for row in image.mapped if row["address"] <= ONCE_WORD < row["address"] + row["size"]]
    return {"word": "%#x" % ONCE_WORD, "section": section[0], "file_bytes": bytes(image.blob[at:at + 4]).hex(), "slot": "%#x" % SLOT_ONCE}


def locations(image):
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    rows = []
    for slot, role in ((LOC_ASSET, "asset id not in this dex, or index at or above the row count"), (LOC_DECIMALS, "6 - sz_decimals underflows")):
        path, line, column = image.location(slot, relative)
        rows.append({"slot": "%#x" % slot, "path": path, "line": line, "column": column, "role": role})
    return rows


# ---- mutation ----

SWAP = {"minsd": 2, "maxsd": 2, "addsd": 4, "subsd": 4, "mulsd": 7, "divsd": 7, "addpd": 4, "subpd": 4, "maxpd": 2}


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
        if row.rip_at is not None and row.op not in ("calli", "lea"):
            yield row.va, row.rip_at, 8, "constant"
        if row.op in SWAP:
            base = image.offset(row.va)
            yield row.va, bytes(image.blob[base:base + 16]).index(b"\x0f") + 1, SWAP[row.op], "opcode"


def reason_for(row):
    va = int(row["va"], 16) if isinstance(row["va"], str) else row["va"]
    function = int(row["function"], 16) if isinstance(row["function"], str) else row["function"]
    for (owner, low, high), text in REASONS:
        if owner == function and low <= va < high:
            return text
    return ""


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
            order = [index for index in first_kill if index in wanted] + indices
            for index in order:
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
    if case["kind"] == "premium":
        panic, result, _ = premium_spec(case)
        return "panic " + panic[0] if panic else "none" if result is None else "some"
    result, _ = rate_spec(case)
    return "none" if result is None else "some"


def reference_premium(case):
    """The reference text, kept apart from the specification, for the worked table only."""
    rows, asset = case["sz_decimals"], case["asset"]
    scale = 10.0 ** (6 - rows[asset % 10000])
    oracle, bid, ask = float(case["oracle"]) / scale, float(case["bid"]) / scale, float(case["ask"]) / scale
    premium = 0.0 if oracle == 0.0 else ((bid + ask) * 0.5 - oracle) / oracle
    premium = max(-0.5, min(0.5, premium))
    if asset in case["hl_only"]:
        premium /= 100.0
    return premium


def worked(image):
    harness = Harness(image)
    rows = []
    for label, case in (
        ("mid formula", premium_case("w", bid=1010000, ask=1020000)),
        ("impact gap formula, same book", premium_case("w", bid=1010000, ask=1020000, binance=True)),
        ("impact gap formula, oracle inside the spread", premium_case("w", bid=990000, ask=1010000, binance=True)),
        ("hl only, 70 percent mid gap", premium_case("w", bid=1700000, ask=1700000, hl_only=(1,))),
        ("hl only, 7000 percent mid gap", premium_case("w", bid=71000000, ask=71000000, hl_only=(1,))),
        ("mid / oracle - 1 rounding", premium_case("w", oracle=1000003, bid=1000007, ask=1000011)),
        ("oracle 0", premium_case("w", oracle=0)),
    ):
        _, result, _ = harness.premium(case)
        rows.append({"function": "premium", "label": label, "oracle": case["oracle"], "first": case["bid"], "second": case["ask"], "real_bytes": None if result is None else repr(result[0]), "reference_text": repr(reference_premium(case))})
    for label, case in (
        ("no premium, default rate, clamp 0.0005", rate_case("w", premiums=((7, (0.0, 0.0)),))),
        ("mean 0.0002, clamp 0.0005", rate_case("w", premiums=((7, (0.0001, 0.0003)),))),
        ("mean 0.002, clamp 0.0005", rate_case("w", premiums=((7, (0.002,)),))),
        ("mean 0.5, saturated", rate_case("w", premiums=((7, (0.5,)),))),
        ("mean -0.5, saturated", rate_case("w", premiums=((7, (-0.5,)),))),
        ("multiplier 2.5", rate_case("w", premiums=((7, (0.0001,)),), multiplier=((7, 2.5),))),
        ("nan sample skips both clamps", rate_case("w", premiums=((7, (math.nan,)),))),
    ):
        result, _ = harness.rate(case)
        rows.append({"function": "rate", "label": label, "samples": [repr(v) for v in case["premiums"][0][1]], "real_bytes": repr(result)})
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
    begin, end = image.exact_fde(PREMIUM)
    premium_rows = decode_range(image, begin, end)
    begin, end = image.exact_fde(RATE)
    rate_rows = decode_range(image, begin, end)
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
        "fields": field_map(image),
        "constants": {"premium": rodata_reads(image, premium_rows), "rate": rodata_reads(image, rate_rows)},
        "scale_table": scale_table(image),
        "callers": call_sites(image),
        "locations": locations(image),
        "side_call": side_call(image),
        "cases": {"total": len(cases), "outcomes": dict(sorted(outcomes.items()))},
        "mismatches": mismatches,
        "first_mismatch": first,
        "instructions_stepped": machine.steps,
        "worked": worked(image),
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
