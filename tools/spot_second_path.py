#!/usr/bin/env python3
"""Pin the node #94 second spot order path from ELF bytes: two health reads around the order, a reserve step and a set insert.

`0x4d2f4a0`, `0x4d2e9e0` and `0x2726ce0` take the order the spot preprocess rewrote. They read the user row, run a reserve
step, run the order, settle two tokens, read the row again and insert the user into a set when a shortfall grew. The real
bytes run in a Python evaluator with the callees at the edge stubbed. A separately written specification predicts every
result and stub argument, and every condition, immediate and field offset is flipped to show the run can tell. No objdump
or readelf output is parsed, and the binary is never executed. Standard library only.
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

SECOND_A = 0x4D2F4A0
SECOND_B = 0x4D2E9E0
SECOND_C = 0x2726CE0
SNAPSHOT_A = 0x46F2BE0
SNAPSHOT_B = 0x46F2960
RESERVE_A = 0x46F09E0
RESERVE_B = 0x46F08A0
POST_A = 0x46F26F0
POST_B = 0x46F2480
POST_C = 0x2739B00
RATIO_REPORT = 0x373D8E0
BALANCE_LOOKUP = 0x371B3A0
DEFAULT_ROW = 0x5786350
ONCE_WORD = 0x5786380

SLOT_MEMCPY = 0x576DFE0
SLOT_MEMCMP = 0x576E488
SLOT_FREE = 0x576E010
SLOT_ONCE = 0x576E8B8
SLOT_PANIC = 0x576E470
SLOT_UNWRAP = 0x576E048
SLOT_BALANCES = 0x5773170
FAKE_MEMCPY = 0xFACE0010
FAKE_MEMCMP = 0xFACE0020

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
HEAP_SIZE = 0x8000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 20000

STATE = HEAP_BASE + 0x100
OUT = HEAP_BASE + 0x1000
ORDER = HEAP_BASE + 0x1100
ROOT_NODE = HEAP_BASE + 0x2000
LEAF_NODES = HEAP_BASE + 0x3000
VECTOR = HEAP_BASE + 0x7000

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
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
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
        self.lazy = bytearray(0x30)

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
        if DEFAULT_ROW <= addr and addr + count <= DEFAULT_ROW + 0x30:
            return self.lazy, addr - DEFAULT_ROW
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
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
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


# ---- specification, written from the instruction read and kept apart from the evaluator ----

RAMPS = {}


def ramp(size, start):
    """Non-periodic filler, so that a wrong field offset reads a wrong value."""
    key = (size, start)
    if key not in RAMPS:
        RAMPS[key] = bytes((start + index * 37 + (index >> 4)) & 0xFF | 1 for index in range(size))
    return RAMPS[key]


def word(data, at, width=8):
    return int.from_bytes(data[at:at + width], "little")


def put_word(data, at, width, value):
    data[at:at + width] = (value & MASK[width]).to_bytes(width, "little")


U64 = MASK[8]
RESULT_BYTES = 0x60
WORD_FAILED = 0x187
WORD_CARRIED = 0x188
BYTE_GOOD = 0x11
BYTE_SHORT = 0xC
EXEMPT_USER = b"\xbb" * 20
RESERVE_MODE = 3
OFF_RATIO_META = 0x90
OFF_RATIO_BLOCK = 0x560
OFF_BALANCES = 0x80
OFF_ACCOUNT = 0x498
OFF_SHORTFALL_SET = 0x8B8
OFF_SHORTFALL_SET_B = 0x1338
OFF_SMALL_BLOCK = 0x60
LOC_SETTLE_FIRST = 0x57445F8
LOC_SETTLE_SECOND = 0x5744610
LOC_UNWRAP = 0x570D858
UNWRAP_LENGTH = 0x2B
UNWRAP_TEXT = 0x5A85C6
UNWRAP_TABLE = 0x570DB90
ONCE_TABLE = 0x56F22C8
ONCE_NOTE = 0x56F22B0
LOC_NONE_A = 0x57357B8
LOC_NONE_C = 0x56C6A38
DEFAULT_DATE = 0x0F6B2021
VALUE_STRIDE = 0x30
ROW_BYTES = 0x30

COPIES = {
    "a": {"entry": SECOND_A, "report": RATIO_REPORT, "clone": 0x4987250, "health": 0x48CFB90, "drop_map": 0x49A8520, "reserve": 0x48CE500, "apply": 0x46F1B90, "run": 0x445F870, "settle": 0x46EF720, "drop_result": 0x4DAE9C0, "insert": 0x4941FE0, "none_at": LOC_NONE_A, "located": True, "set_at": OFF_SHORTFALL_SET},
    "b": {"entry": SECOND_B, "report": RATIO_REPORT, "clone": 0x4987250, "health": 0x48CFB90, "drop_map": 0x49A8520, "reserve": 0x48CE500, "apply": 0x46F12A0, "run": 0x44612D0, "settle": 0x46EF4A0, "drop_result": 0x4DAE9C0, "insert": 0x4941FE0, "none_at": LOC_NONE_A, "located": True, "set_at": OFF_SHORTFALL_SET_B},
    "c": {"entry": SECOND_C, "report": RATIO_REPORT, "clone": 0x289A040, "health": 0x28DB540, "drop_map": 0x28ABF00, "reserve": 0x232B4F0, "apply": 0x2739210, "run": 0x26D2560, "settle": 0x272F880, "drop_result": 0x277CBC0, "insert": 0x284F810, "none_at": LOC_NONE_C, "located": False, "set_at": OFF_SHORTFALL_SET},
}


def find_row(tree, user):
    """Value address of the user in a B-tree of 20 byte keys, or None."""
    if tree is None:
        return None
    keys, leaves = tree
    node, rows = ROOT_NODE, keys
    index = 0
    while True:
        index = 0
        for key in rows:
            if key == user:
                return node + index * VALUE_STRIDE
            if user < key:
                break
            index += 1
        if not leaves or node != ROOT_NODE:
            return None
        node, rows = LEAF_NODES + index * NODE_SIZE, leaves[index]


STATE_BYTES = 0x900


def ratio(report):
    return float(report[3]) / float(report[1])


def order_bytes(w):
    data = bytearray(ramp(0xC4, 0x21))
    put_word(data, 0x48, 8, w["tag"])
    put_word(data, 0x70, 8, w["capacity"])
    put_word(data, 0x78, 8, VECTOR)
    put_word(data, 0x98, 8, w["base"])
    put_word(data, 0xA0, 8, w["quote"])
    put_word(data, 0xA8, 8, w["last"])
    data[0xB0:0xC4] = w["user"]
    return bytes(data)


def run_bytes(w):
    data = bytearray(ramp(RESULT_BYTES, 0x47))
    put_word(data, 0, 2, w["run_word"])
    return bytes(data)


class Trace:
    def __init__(self, w):
        self.w = w
        self.events = []
        self.once = w["once"]
        self.tree = w["tree"]

    def row(self):
        """The Once gate sits after the walk, on found and missing rows alike."""
        if self.once > 0:
            self.events.append(("once", ONCE_WORD, DEFAULT_ROW, 1, ONCE_TABLE, ONCE_NOTE))
            self.once -= 1
        found = find_row(self.tree, self.w["user"])
        return DEFAULT_ROW if found is None else found

    def free_vector(self):
        w = self.w
        if w["tag"] < 2 and w["capacity"] != 0:
            self.events.append(("free", VECTOR, (w["capacity"] * 0x48) & U64, 0))


def failed(code):
    return {"word": WORD_FAILED, "byte": code, "rest": None}


def row_image(w, at):
    if at == DEFAULT_ROW:
        return bytes(8) + DEFAULT_DATE.to_bytes(4, "little") + bytes(0x24)
    data = bytearray(ramp(VALUE_STRIDE, (0x3D + (at >> 4)) & 0xFF))
    data[0] = w["row_byte"]
    put_word(data, 8, 4, w["row_word"])
    put_word(data, 0x18, 8, w["row_map"][1])
    put_word(data, 0x20, 8, w["row_map"][2])
    put_word(data, 0x28, 8, w["row_map"][0])
    return bytes(data)


CLONE_WORDS = (0x7A7A0011, 0x7A7A0022, 0x7A7A0033)


def map_event(head, cloned):
    return ("drop map", head) + (CLONE_WORDS if cloned else (0, 0, 0))


def reserve_bytes(w):
    data = bytearray(ramp(0x110, 0x53))
    reserve = w["reserve"]
    put_word(data, 0, 8, reserve[0])
    data[8] = reserve[1]
    put_word(data, 0x100, 8, reserve[2])
    data[0x108] = reserve[3]
    return bytes(data)


def finish(result):
    if result["word"] == WORD_FAILED:
        return failed(result["byte"])
    return result


def spec_second(w, copy):
    """The whole path. The result's bytes past the third only count when the order's own result goes out."""
    t = Trace(w)
    names = COPIES[copy]
    answer = {"events": t.events, "stop": None, "out": None}
    block = STATE + OFF_RATIO_BLOCK
    meta = STATE + OFF_RATIO_META
    at = t.row()
    t.events.append(("report", at, block, meta))
    before = w["before"]
    if before[0] == 1:
        answer["out"] = failed(before[1])
        t.free_vector()
        return answer
    at = t.row()
    row = row_image(w, at)
    head = row[:0x18]
    length, pointer, count = word(row, 0x28), word(row, 0x18), word(row, 0x20)
    if length:
        if pointer == 0:
            answer["stop"] = ("none", names["none_at"])
            return answer
        t.events.append(("clone", pointer, count))
    t.events.append(("health", head, block, meta, 0))
    first = w["health"]
    if first[0] == 1:
        t.events.append(map_event(head, length != 0))
        t.free_vector()
        answer["out"] = failed(first[1])
        return answer
    if first[1] >= 1 << 63 or first[2] >= 1 << 63:
        answer["stop"] = ("unwrap", LOC_UNWRAP, UNWRAP_LENGTH, UNWRAP_TEXT, UNWRAP_TABLE)
        return answer
    margin = first[1] - first[2]
    if word(row, 8, 4) == 0:
        t.free_vector()
        answer["out"] = failed(row[0])
        return answer
    code = BYTE_GOOD
    if w["last"]:
        small = STATE_IMAGE[OFF_SMALL_BLOCK:OFF_SMALL_BLOCK + 12]
        t.events.append(("reserve", STATE + OFF_ACCOUNT, w["user"], w["base"], RESERVE_MODE, 1, w["last"], small, STATE + OFF_BALANCES))
        reserve = w["reserve"]
        data = reserve_bytes(w)
        if reserve[0] == 3:
            code = reserve[1]
        elif reserve[0] != 2:
            if reserve[3] != 0 or reserve[2] != w["last"]:
                t.events.append(("drop map", data[0xB0:0xC8], word(data, 0xC8), word(data, 0xD0), word(data, 0xD8)))
                code = BYTE_SHORT
            else:
                t.events.append(("apply", w["user"], w["base"], RESERVE_MODE, 0, data))
    if code != BYTE_GOOD:
        t.free_vector()
        result = failed(code)
    else:
        data = order_bytes(w)
        t.events.append(("run", data[:0x48], w["user"], data[0x48:0x98], STATE, 0))
        if "tree_after" in w:
            t.tree = w["tree_after"]
        t.events.append(("settle", w["user"], w["quote"], 0, LOC_SETTLE_FIRST if names["located"] else None))
        t.events.append(("settle", w["user"], w["base"], 0, LOC_SETTLE_SECOND if names["located"] else None))
        at = t.row()
        t.events.append(("report", at, block, meta))
        after = w["after"]
        ran = run_bytes(w)
        if after[0] == 1:
            t.events.append(("drop result", ran))
            result = failed(after[1])
        else:
            if before[1] != 0 and after[1] != 0 and ratio(before) > ratio(after):
                t.events.append(("balance lookup", STATE + OFF_BALANCES, w["user"]))
            result = {"word": w["run_word"], "byte": ran[2], "rest": ran}
    at = t.row()
    t.events.append(("health", row_image(w, at)[:0x18], block, meta, 0))
    second = w["post"]
    post = BYTE_GOOD
    if second[0] == 1:
        post = second[1]
    else:
        if second[1] >= 1 << 63 or second[2] >= 1 << 63:
            answer["stop"] = ("unwrap", LOC_UNWRAP, UNWRAP_LENGTH, UNWRAP_TEXT, UNWRAP_TABLE)
            return answer
        now = second[1] - second[2]
        if now < 0 and now < margin and w["user"] != EXEMPT_USER:
            t.events.append(("insert", STATE + names["set_at"], w["user"]))
    t.events.append(map_event(head, length != 0))
    if post != BYTE_GOOD:
        if result["word"] != WORD_FAILED:
            t.events.append(("drop result", result["rest"]))
        answer["out"] = failed(post)
    elif result["word"] == WORD_CARRIED:
        answer["out"] = failed(result["byte"])
    else:
        answer["out"] = finish(result)
    return answer


# ---- harness: real bytes; the callees at the edge are stubbed and their arguments compared ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Case:
    def __init__(self, label, kind, copy, world):
        self.label = label
        self.kind = kind
        self.copy = copy
        self.world = world


NODE_KEYS = 0x218
NODE_LENGTH = 0x2F6
NODE_EDGES = 0x2F8
NODE_SIZE = 0x358
NODE_CAPACITY = 11
UNMAPPED = 0x10
STATE_IMAGE = ramp(STATE_BYTES, 0x2B)
TEMPTING = b"\x7f" * 20


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        machine.memory.statics.update(relative)
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCPY
        machine.memory.statics[SLOT_MEMCMP] = FAKE_MEMCMP
        self.base_slots = {relative[SLOT_PANIC]: self.on_panic, relative[SLOT_UNWRAP]: self.on_unwrap, FAKE_MEMCPY: self.on_memcpy, FAKE_MEMCMP: self.on_memcmp}
        machine.slots = dict(self.base_slots)
        self.real = RealExcept()
        machine.real = self.real
        self.events = []

    def on_panic(self, m):
        raise Panicked(("none", m.regs[RDI]))

    def on_unwrap(self, m):
        raise Panicked(("unwrap", m.regs[R8], m.regs[RSI], m.regs[RDI], m.regs[RCX]))

    def on_memcpy(self, m):
        count = m.regs[RDX]
        if count > 0x400:
            raise Halt("memcpy length")
        m.memory.copy(m.regs[RDI], m.regs[RSI], count)
        m.regs[RAX] = m.regs[RDI]

    def on_memcmp(self, m):
        count = m.regs[RDX]
        if count > 0x40:
            raise Halt("memcmp length")
        left = m.memory.bytes_at(m.regs[RDI], count)
        right = m.memory.bytes_at(m.regs[RSI], count)
        m.regs[RAX] = 0
        for one, two in zip(left, right):
            if one != two:
                m.regs[RAX] = (one - two) & MASK[4]
                break

    def write_tree(self, tree, w):
        memory = self.machine.memory

        def node(at, keys, edges):
            memory.put_bytes(at, ramp(NODE_SIZE, 0x19))
            for index in range(NODE_CAPACITY):
                memory.put_bytes(at + NODE_KEYS + index * 20, keys[index] if index < len(keys) else TEMPTING)
                if index < len(keys):
                    memory.put_bytes(at + index * VALUE_STRIDE, row_image(w, at + index * VALUE_STRIDE))
            memory.write(at + NODE_LENGTH, 2, len(keys))
            for index in range(NODE_CAPACITY + 1):
                memory.write(at + NODE_EDGES + index * 8, 8, edges[index] if index < len(edges) else UNMAPPED + index * 8)
        if tree is None:
            memory.write(STATE + 0x598, 8, 0)
            memory.write(STATE + 0x5A0, 8, 3)
            return
        keys, leaves = tree
        edges = [LEAF_NODES + index * NODE_SIZE for index in range(len(leaves))]
        node(ROOT_NODE, keys, edges)
        for at, leaf in zip(edges, leaves):
            node(at, leaf, [])
        memory.write(STATE + 0x598, 8, ROOT_NODE)
        memory.write(STATE + 0x5A0, 8, 1 if leaves else 0)

    def run_second(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        names = COPIES[case.copy]
        self.events = []
        events = self.events
        once = [w["once"]]

        def on_once(m):
            events.append(("once", m.regs[RDI], memory.read(memory.read(m.regs[RDX], 8), 8), m.regs[RSI] & 0xFF, m.regs[RCX], m.regs[R8]))
            once[0] -= 1
            memory.statics[ONCE_WORD] = 1 if once[0] > 0 else 0

        def report_out(out, row):
            if row[0] == 1:
                memory.write(out, 1, 1)
                memory.write(out + 1, 1, row[1])
            else:
                memory.write(out, 1, 0)
                memory.put_bytes(out + 1, ramp(0x2F, 0x63))
                memory.write(out + 8, 8, row[1])
                memory.write(out + 0x18, 8, row[3])
                memory.write(out + 0x10, 8, row[2])

        reports = [w["before"], w["after"]]
        healths = [w["health"], w["post"]]

        def on_report(m):
            events.append(("report", m.regs[RSI], m.regs[RDX], m.regs[RCX]))
            report_out(m.regs[RDI], reports.pop(0))
            m.regs[RAX] = m.regs[RDI]

        def on_clone(m):
            events.append(("clone", m.regs[RSI], m.regs[RDX]))
            for index, value in enumerate(CLONE_WORDS):
                memory.write(m.regs[RDI] + index * 8, 8, value)
            m.regs[RAX] = m.regs[RDI]

        def on_health(m):
            events.append(("health", memory.bytes_at(m.regs[RSI], 0x18), m.regs[RDX], m.regs[RCX], m.regs[R8]))
            row = healths.pop(0)
            out = m.regs[RDI]
            memory.put_bytes(out, ramp(0x30, 0x6B))
            if row[0] == 1:
                memory.write(out, 1, 1)
                memory.write(out + 1, 1, row[1])
            else:
                memory.write(out, 1, 0)
                memory.write(out + 8, 8, row[2])
                memory.write(out + 0x10, 8, row[1])
            m.regs[RAX] = out

        def on_drop_map(m):
            at = m.regs[RDI]
            first = memory.read(at, 8)
            events.append(("drop map", memory.bytes_at(at - 0x18, 0x18), first, memory.read(at + 8, 8) if first else 0, memory.read(at + 0x10, 8)))

        def on_reserve(m):
            at = m.regs[RSP]
            block = memory.read(at + 0x18, 8)
            events.append(("reserve", m.regs[RSI], memory.bytes_at(m.regs[RDX], 20), m.regs[RCX], m.regs[R8] & MASK[4], memory.read(at + 8, 8) & 0xFF, memory.read(at + 0x10, 8), memory.bytes_at(block, 12), memory.read(at + 0x20, 8)))
            memory.put_bytes(m.regs[RDI], reserve_bytes(w))
            m.regs[RAX] = m.regs[RDI]

        def on_apply(m):
            if m.regs[RDI] != STATE:
                raise Halt("apply state")
            events.append(("apply", memory.bytes_at(m.regs[RSI], 20), m.regs[RDX], m.regs[RCX] & MASK[4], m.regs[R9] & MASK[4], memory.bytes_at(m.regs[R8], 0x110)))

        def on_run(m):
            events.append(("run", memory.bytes_at(m.regs[RSI], 0x48), memory.bytes_at(m.regs[RDX], 20), memory.bytes_at(m.regs[RCX], 0x50), m.regs[R8], m.regs[R9] & MASK[4]))
            memory.put_bytes(m.regs[RDI], run_bytes(w))
            if "tree_after" in w:
                self.write_tree(w["tree_after"], w)
            m.regs[RAX] = m.regs[RDI]

        def on_settle(m):
            if m.regs[RDI] != STATE:
                raise Halt("settle state")
            events.append(("settle", memory.bytes_at(m.regs[RSI], 20), m.regs[RDX], m.regs[RCX] & MASK[4], m.regs[R9] if names["located"] else None))

        def on_drop_result(m):
            events.append(("drop result", memory.bytes_at(m.regs[RDI], RESULT_BYTES)))

        def on_insert(m):
            events.append(("insert", m.regs[RDI], memory.bytes_at(m.regs[RSI], 20)))
            m.regs[RAX] = 0x5151

        def on_free(m):
            events.append(("free", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

        def on_balances(m):
            events.append(("balance lookup", m.regs[RDI], memory.bytes_at(m.regs[RSI], 20)))
            m.regs[RAX] = 0x5252

        calls = {names["report"]: on_report, names["clone"]: on_clone, names["health"]: on_health, names["drop_map"]: on_drop_map, names["reserve"]: on_reserve, names["apply"]: on_apply, names["run"]: on_run, names["settle"]: on_settle, names["drop_result"]: on_drop_result, names["insert"]: on_insert}
        relative = self.relative
        machine.slots = dict(self.base_slots)
        machine.slots.update({relative[SLOT_FREE]: on_free, relative[SLOT_ONCE]: on_once, relative[SLOT_BALANCES]: on_balances})
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)
        memory.reset()
        memory.statics[ONCE_WORD] = 1 if once[0] > 0 else 0
        memory.lazy[:] = row_image(w, DEFAULT_ROW)
        memory.put_bytes(STATE, STATE_IMAGE)
        self.write_tree(w["tree"], w)
        memory.put_bytes(ORDER, order_bytes(w))
        answer = {"events": events, "stop": None, "out": None}
        try:
            rax = machine.run(names["entry"], {RDI: OUT, RSI: STATE, RDX: ORDER})
        except Panicked as stop:
            answer["stop"] = stop.args[0]
            return answer
        if rax != OUT and case.copy != "c":
            raise Halt("result pointer")
        out = memory.bytes_at(OUT, RESULT_BYTES)
        value = word(out, 0, 2)
        answer["out"] = {"word": value, "byte": out[2], "rest": None if value == WORD_FAILED else out}
        return answer

    def run(self, case):
        return self.run_second(case)


def spec_run(case):
    return spec_second(case.world, case.copy)


CRASHES = (Halt, IndexError, KeyError, OverflowError, ValueError, TypeError, ZeroDivisionError, EvidenceError)


def compare_run(harness, case):
    """Empty when the bytes and the specification agree, else one line."""
    wanted = spec_run(case)
    try:
        found = harness.run(case)
    except CRASHES as error:
        return "%s: crash %s %s" % (case.label, type(error).__name__, error)
    if found != wanted:
        keys = sorted(key for key in wanted if found.get(key) != wanted[key])
        detail = ""
        if keys:
            left, right = found.get(keys[0]), wanted[keys[0]]
            if isinstance(left, list) and isinstance(right, list):
                pairs = [(one, two) for one, two in zip(left, right) if one != two]
                left, right = pairs[0] if pairs else (len(left), len(right))
            detail = "%s found %s wanted %s" % (keys[0], str(left)[:400], str(right)[:400])
        return "%s: differs: %s" % (case.label, detail)
    return ""


# ---- cases ----

USER = bytes(range(0x31, 0x45))
BASE = 0x1234567
QUOTE = 0x7654321
BIG = 0x7FFFFFFFFFFFFFFF
TOP = 1 << 63


def user_at(step):
    return bytes([0x31 + step]) + bytes(range(0x32, 0x45))


def world(**change):
    w = {
        "user": USER, "tag": 0, "capacity": 3, "base": BASE, "quote": QUOTE, "last": 900,
        "tree": ([USER], []), "row_byte": 0x2E, "row_word": 7, "row_map": (0, 0, 0), "once": 0,
        "before": (0, 1000, 11, 500, 13, 17), "health": (0, 5000, 1000), "reserve": (0, 0x5C, 900, 0),
        "run_word": 0x186, "after": (0, 1000, 21, 600, 23, 27), "post": (0, 6000, 1000),
    }
    w.update(change)
    return w


def scenario_list():
    rows = []

    def add(label, **change):
        rows.append((label, world(**change)))

    add("accepted, ratio up")
    add("user missing from an empty map", tree=None)
    add("user missing from a one node map", tree=([user_at(1)], []))
    add("user before every key", tree=([user_at(1), user_at(2)], []))
    add("user after every key", user=user_at(9), tree=([USER, user_at(1)], []))
    add("user second key", user=user_at(1), tree=([USER, user_at(1), user_at(2)], []))
    add("user last of full node", user=user_at(10), tree=([user_at(index) for index in range(11)], []))
    add("user in first leaf", tree=([user_at(3)], [[user_at(-2), USER], [user_at(5)]]))
    add("user in second leaf", user=user_at(5), tree=([user_at(3)], [[USER], [user_at(4), user_at(5)]]))
    add("user in the root of a two level map", user=user_at(3), tree=([user_at(3)], [[USER], [user_at(5)]]))
    add("user absent from two levels", user=user_at(4), tree=([user_at(3)], [[USER], [user_at(5)]]))
    add("user past two levels", user=user_at(8), tree=([user_at(3)], [[USER], [user_at(5)]]))
    add("user above the unused key slots", user=b"\xf0" * 20, tree=([USER, user_at(1)], []))
    add("user above the unused key slots of a leaf", user=b"\xf0" * 20, tree=([user_at(3)], [[USER], [user_at(5)]]))
    add("user above a full node", user=b"\xf0" * 20, tree=([user_at(index) for index in range(11)], []))
    add("row added by the order", tree=None, tree_after=([USER], []))
    add("row gone after the order", tree_after=None)
    add("row moved by the order", tree_after=([user_at(-3), USER], []))
    for count in (1, 2, 3, 4, 9):
        add("once gate pending for %d reads" % count, once=count)
        add("once gate pending for %d reads, user missing" % count, once=count, tree=None)
    add("once gate pending past a stop", once=9, last=0, tree=([user_at(1)], []))
    add("once gate on the empty map", once=2, tree=None, last=0, run_word=0x188)
    add("first report stops", before=(1, 0x37))
    add("first report stops, tag 2 keeps the vector", before=(1, 0x37), tag=2)
    add("first report stops, tag 1 frees", before=(1, 0x38), tag=1)
    add("first report stops, no capacity", before=(1, 0x37), capacity=0)
    add("first report stops, wide capacity", before=(1, 0x37), capacity=(1 << 61) + 5)
    add("row has a map", row_map=(4, 0x8877, 2))
    add("row has a map, one entry", row_map=(1, 0x8878, 1))
    add("row map with empty root panics", row_map=(4, 0, 2))
    add("row map with no length and a root", row_map=(0, 0x8877, 2))
    add("row map with a length and no height", row_map=(1, 0x8878, 0))
    add("snapshot stops", health=(1, 0x41))
    add("snapshot stops with a map", health=(1, 0x42), row_map=(2, 0x8877, 2))
    add("snapshot stops, tag 2", health=(1, 0x41), tag=2)
    add("snapshot stops, no capacity", health=(1, 0x41), capacity=0)
    add("snapshot first word negative", health=(0, TOP, 5))
    add("snapshot second word negative", health=(0, 5, TOP))
    add("snapshot words at the sign edge", health=(0, BIG, BIG))
    add("row word zero", row_word=0)
    add("row word zero, tag 3", row_word=0, tag=3)
    add("row word zero, no capacity", row_word=0, capacity=0)
    add("row word high bits only", row_word=0x80000000)
    add("no last skips the reserve", last=0)
    add("no last with a map", last=0, row_map=(2, 0x8877, 2))
    add("reserve tag 3 good byte", reserve=(3, 0x11, 900, 0))
    add("reserve tag 3 stops", reserve=(3, 0x33, 900, 0))
    add("reserve tag 3 stops, tag 2", reserve=(3, 0x33, 900, 0), tag=2)
    add("reserve tag 3 stops, no capacity", reserve=(3, 0x33, 900, 0), capacity=0)
    add("reserve tag 2 skips the apply", reserve=(2, 0x33, 1, 1))
    add("reserve tag 1 applies", reserve=(1, 0x2D, 900, 0))
    add("reserve amount short", reserve=(0, 0x5C, 899, 0))
    add("reserve amount long", reserve=(0, 0x5C, 901, 0))
    add("reserve amount low word only", reserve=(0, 0x5C, (1 << 32) + 900, 0))
    add("reserve flag set", reserve=(0, 0x5C, 900, 1))
    add("reserve flag high value", reserve=(1, 0x5C, 900, 0x80))
    add("reserve short, tag 2", reserve=(0, 0x5C, 899, 0), tag=2)
    add("reserve short, no capacity", reserve=(0, 0x5C, 899, 0), capacity=0)
    add("reserve stop then report path stops", reserve=(3, 0x33, 900, 0), post=(1, 0x22))
    add("second report stops", after=(1, 0x39))
    add("second report stops, post stops", after=(1, 0x39), post=(1, 0x22))
    add("ratio equal", after=(0, 1000, 21, 500, 23, 27))
    add("ratio down", after=(0, 1000, 21, 499, 23, 27))
    add("ratio down by a scale", after=(0, 2000, 21, 500, 23, 27))
    add("ratio up by a scale", after=(0, 500, 21, 500, 23, 27))
    add("ratio before zero denominator", before=(0, 0, 11, 500, 13, 17), after=(0, 1000, 21, 1, 23, 27))
    add("ratio after zero denominator", after=(0, 0, 21, 1, 23, 27))
    add("ratio both zero denominators", before=(0, 0, 11, 5, 13, 17), after=(0, 0, 21, 1, 23, 27))
    add("ratio numerator top bit", before=(0, 1, 11, TOP + 2048, 13, 17), after=(0, 1, 21, TOP, 23, 27))
    add("ratio denominator top bit", before=(0, TOP, 11, 1, 13, 17), after=(0, TOP + 4096, 21, 1, 23, 27))
    add("ratio numerator low word lost", before=(0, 1, 11, 1 << 32, 13, 17), after=(0, 1, 21, (1 << 32) - 1, 23, 27))
    add("ratio denominator low word lost", before=(0, (1 << 32) - 1, 11, 1 << 40, 13, 17), after=(0, 1 << 32, 21, 1 << 40, 23, 27))
    add("ratio hides a first word move", before=(0, 1 << 33, 11, 1 << 33, 13, 17), after=(0, (1 << 33) + 1, 21, 1 << 33, 23, 27))
    add("ratio unsigned words", before=(0, U64, 11, U64, 13, 17), after=(0, U64, 21, U64 - 4096, 23, 27))
    add("run word carried", run_word=0x188)
    add("run word carried with post stop", run_word=0x188, post=(1, 0x22))
    add("run word failed", run_word=0x187)
    add("run word failed with post stop", run_word=0x187, post=(1, 0x22))
    add("run word 0x189", run_word=0x189)
    add("run word 0x88 high byte", run_word=0x88)
    add("run word 0x18 7 high byte", run_word=0x287)
    add("post stops", post=(1, 0x22))
    add("post stops with a map", post=(1, 0x22), row_map=(2, 0x8877, 2))
    add("post first word negative", post=(0, TOP, 5))
    add("post second word negative", post=(0, 5, TOP))
    add("post no shortfall", post=(0, 1000, 1000))
    add("shortfall new from a surplus", post=(0, 999, 1000))
    add("shortfall same as before", health=(0, 1000, 1100), post=(0, 1000, 1100))
    add("shortfall one smaller", health=(0, 1000, 1100), post=(0, 1001, 1100))
    add("shortfall one larger", health=(0, 1000, 1100), post=(0, 999, 1100))
    add("shortfall larger, map kept", health=(0, 1000, 1100), post=(0, 999, 1100), row_map=(2, 0x8877, 2))
    add("shortfall larger on a missing row", tree=None, health=(0, 1000, 1100), post=(0, 999, 1100))
    add("shortfall huge", health=(0, 1, 1), post=(0, 0, BIG))
    add("shortfall from the far edge", health=(0, 0, BIG), post=(0, 0, BIG))
    add("surplus huge before", health=(0, BIG, 0), post=(0, 0, 1))
    add("shortfall larger, exempt address", user=EXEMPT_USER, tree=([EXEMPT_USER], []), health=(0, 1000, 1100), post=(0, 999, 1100))
    for at in (0, 7, 15, 16, 19):
        near = bytearray(EXEMPT_USER)
        near[at] ^= 1
        near = bytes(near)
        add("shortfall larger, near exempt byte %d" % at, user=near, tree=([near], []), health=(0, 1000, 1100), post=(0, 999, 1100))
    add("shortfall after a failed reserve", reserve=(3, 0x33, 900, 0), health=(0, 1000, 1100), post=(0, 999, 1100))
    add("shortfall after a stopped second report", after=(1, 0x39), health=(0, 1000, 1100), post=(0, 999, 1100))
    add("shortfall with the run word failed", run_word=0x187, health=(0, 1000, 1100), post=(0, 999, 1100))
    return rows


def all_cases():
    return [Case("%s: %s" % (copy, label), "second", copy, w) for copy in ("a", "b", "c") for label, w in scenario_list()]


# ---- static reads ----

def direct_sites(image, targets):
    """Every E8/E9 rel32 byte pattern in .text that lands on a target."""
    base, text = image.text_bytes()
    found = {target: [] for target in targets}
    for opcode in (b"\xe8", b"\xe9"):
        at = text.find(opcode)
        while 0 <= at <= len(text) - 5:
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in found:
                found[target].append((base + at, opcode[0]))
            at = text.find(opcode, at + 1)
    return found


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


def twin_rows(image, left, right):
    """Two functions of one source: same length, and every instruction equal once call targets and rip words are compared as absolute targets."""
    first = decode_range(image, *image.exact_fde(left))
    second = decode_range(image, *image.exact_fde(right))
    if len(first) != len(second):
        raise EvidenceError("twin length differs: %#x" % left)
    targets = {}
    offsets = {}
    rip_targets = {}
    shifted = 0
    span = image.exact_fde(left)[1] - left
    for one, two in zip(first, second):
        if one.va - left != two.va - right:
            raise EvidenceError("twin layout differs at %#x" % one.va)
        if one.op != two.op:
            raise EvidenceError("twin instruction differs at %#x" % one.va)
        one_bytes = bytes(image.blob[image.offset(one.va):image.offset(one.va) + one.size])
        two_bytes = bytes(image.blob[image.offset(two.va):image.offset(two.va) + two.size])
        if one.cc != two.cc:
            raise EvidenceError("twin condition differs at %#x" % one.va)
        if one.op in ("call", "jmp", "jcc") and one.target is not None:
            local = 0 <= one.target - left < span
            if local and one.target - left != two.target - right:
                raise EvidenceError("twin jump differs at %#x" % one.va)
            if not local and one.target != two.target:
                targets[one.target] = two.target
            continue
        if one.rip_at is not None:
            left_word = [operand[4] for operand in (one.a, one.b) if operand and operand[0] == "m" and operand[1] is None]
            right_word = [operand[4] for operand in (two.a, two.b) if operand and operand[0] == "m" and operand[1] is None]
            if left_word != right_word:
                rip_targets["%#x" % left_word[0]] = "%#x" % right_word[0]
            shifted += 1
            continue
        if one_bytes == two_bytes:
            continue
        changed = [index for index in range(one.size) if one_bytes[index] != two_bytes[index]]
        if one.size == two.size and changed[-1] - changed[0] < 4:
            offsets["%#x" % one.va] = "%s to %s" % (one_bytes.hex(), two_bytes.hex())
            continue
        raise EvidenceError("twin instruction differs at %#x" % one.va)
    return {"left": "%#x" % left, "right": "%#x" % right, "instructions": len(first), "call_targets_that_differ": {"%#x" % key: "%#x" % value for key, value in sorted(targets.items())},
            "rip_words_compared_as_targets": shifted, "rip_targets_that_differ": rip_targets, "field_words_that_differ": offsets}


HOST_BYTES = (
    (0x2765701, "498d8fb8080000", "lea rcx, [r15+0x8b8]: the sweep 0x2765600 takes the set field the third copy's post check inserts into"),
    (0x2765933, "80783c04", "cmp byte [rax+0x3c], 4: the same sweep's user mode gate"),
    (0x2765B12, "488b8424c8000000", "mov rax, [rsp+0xc8]: the sweep reads report word +8 of 0x373d8e0"),
    (0x2765B1A, "483b8424e8000000", "cmp rax, [rsp+0xe8]: against report word +0x28"),
    (0x2765B42, "483b8424e0000000", "cmp rax, [rsp+0xe0]: against report word +0x20"),
    (0x2765B51, "483b8424d8000000", "cmp rax, [rsp+0xd8]: against report word +0x18"),
    (0x3790914, "bf3bf90a00", "mov edi, 0xaf93b: the default row builder's date argument, days from year 1 to 1970-01-01"),
    (0x3790923, "894308", "mov [rbx+8], eax: the date goes to row +8"),
    (0x379092E, "48c70300000000", "mov qword [rbx], 0: default row word 0"),
    (0x3790935, "48c7431800000000", "mov qword [rbx+0x18], 0: default row map root"),
    (0x379093D, "48c7432800000000", "mov qword [rbx+0x28], 0: default row map length"),
)


def read_host_bytes(image):
    rows = []
    for va, wanted, meaning in HOST_BYTES:
        data = bytes(image.blob[image.offset(va):image.offset(va) + len(wanted) // 2]).hex()
        if data != wanted:
            raise EvidenceError("host bytes at %#x: %s" % (va, data))
        rows.append({"va": "%#x" % va, "bytes": data, "meaning": meaning})
    return rows


EXEMPT_PARTS = ((0x204560, 16), (0x208160, 4))
SWEEP_EXEMPT_PARTS = ((0x5994D8, 16), (0x5994E8, 4))


def exempt_address(image, parts):
    """The 20 byte address two constants spell, read from .rodata."""
    return b"".join(bytes(image.blob[image.offset(va):image.offset(va) + size]) for va, size in parts)


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



GROUPS = (
    (SECOND_A, "second path, first copy"), (SECOND_B, "second path, second copy"), (SECOND_C, "second path, third copy"),
    (SNAPSHOT_A, "snapshot, first copy"), (SNAPSHOT_B, "snapshot, second copy"),
    (RESERVE_A, "reserve step, first copy"), (RESERVE_B, "reserve step, second copy"),
    (POST_A, "post check, first copy"), (POST_B, "post check, second copy"), (POST_C, "post check, third copy"),
)


def mutated_groups(image):
    """(function start, role, decoded rows)."""
    return [(start, role, decode_range(image, *image.exact_fde(start))) for start, role in GROUPS]


def run_mutants(image, reached, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run."""
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    cases = all_cases()
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for start, _, rows in mutated_groups(image):
        for va, at, kind in mutation_targets(image, rows):
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
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
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

REFERENCE_CLAIMS = (
    {"reference": "l1/spot_clearinghouse/cl_trait.rs:338", "claim": "replace_order_after_existing_lookup_main_book and _alt_book are trait methods with no body in the tree", "observed": "three bodies, 0x4d2f4a0, 0x4d2e9e0 and 0x2726ce0; the first two differ in helper targets and one set offset", "verdict": "bodies are new here; the name replace does not fit: no book lookup, cancel or insert sits in these bodies"},
    {"reference": "l1/spot_clearinghouse/cl_trait.rs:386", "claim": "use_main_book_for_replace picks the body", "observed": "the body fixes which order runner and set offset are used: 0x445f870 with +0x8b8, 0x44612d0 with +0x1338", "verdict": "pairing agrees, which is main is not settled"},
    {"reference": "l1/spot_clearinghouse/cl_trait.rs:392", "claim": "SPOT_OUTCOME_INTERNAL_DIRECT_FAILED clears the guard", "observed": "every stop here returns word 0x187 and a byte; the run word 0x188 is rewritten to 0x187", "verdict": "agrees; word 0x188 is not in the reference adapter"},
)
FIELDS = {
    "state": {"+0x60": "12 bytes passed by pointer to the reserve step", "+0x80": "first argument of the balance lookup 0x371b3a0 and last stack argument of the reserve step", "+0x90": "meta block of both reports", "+0x498": "account block of the reserve step", "+0x560": "block of both reports", "+0x598/+0x5a0": "user row map: root, height", "+0x8b8": "set the first and third copies insert into", "+0x1338": "set the second copy inserts into"},
    "order_block": {"+0x00": "0x48 bytes passed to the order runner", "+0x48": "0x50 bytes passed to the order runner: tag, 0x20 bytes, vector capacity, vector pointer, 0x18 bytes", "+0x48 word": "tag: below 2 means this block owns the vector", "+0x70/+0x78": "vector capacity and pointer, rows of 0x48 bytes", "+0x98": "base token", "+0xa0": "quote token", "+0xa8": "last, amount of the reserve step", "+0xb0": "user, 20 bytes"},
    "user_map_node": {"+0x00": "values, 0x30 bytes each", "+0x218": "keys, 20 bytes each", "+0x2f6": "length, u16", "+0x2f8": "edges"},
    "user_row": {"+0x00": "24 bytes copied into the snapshot", "+0x08": "u32, a date in the default row and the niche of the snapshot result", "+0x18/+0x20/+0x28": "map: root, height word, length"},
    "ratio_report": {"+0": "byte: 1 stops", "+1": "code", "+8": "denominator; the value the sweep 0x2765600 compares", "+0x18": "numerator; the lowest of the sweep's three thresholds"},
    "health_report": {"+0": "byte: nonzero stops", "+1": "code", "+8": "second word", "+0x10": "first word, margin is first minus second"},
    "reserve_result": {"+0": "tag: 3 stops with the byte, 2 goes on with no apply", "+8": "byte", "+0x100": "amount, must equal last", "+0x108": "byte, must be zero", "+0xc8": "map dropped on a short reserve"},
}
UNWIND = "unwind landing pad: no case unwinds"
PANIC_TEXT = "the two immediates of the unwrap panic call: the message pointer and length only reach the panic stub, which compares the location"
TEMPLATE_WORD = "the niche byte of a stopped snapshot, the caller reads the u32 at +8 and a stop leaves it 0 either way"


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "no case in the list separates this mutant; no claim rests on this row")


COPY_BACK = "this second memcpy writes bytes back over the place the result already holds, so its length cannot show; the third copy, which has a separate target, kills the same immediate"
REASONS = {0x46F0AAB: COPY_BACK, 0x46F096B: COPY_BACK}
REASON_RANGES = ((0x4D2FE92, 0x4D2FF52, UNWIND), (0x4D2F3D2, 0x4D2F492, UNWIND), (0x2727AEE, 0x2727BB1, UNWIND), (0x46F2937, 0x46F2954, UNWIND), (0x46F26C7, 0x46F26E4, UNWIND), (0x2739D47, 0x2739D64, UNWIND))


def outcome_name(case, spec):
    if spec["stop"]:
        return "panic: " + spec["stop"][0]
    names = [event[0] for event in spec["events"]]
    out = spec["out"]
    ran = "run" in names
    text = "ran" if ran else "not run"
    text += ", inserted" if "insert" in names else ""
    text += ", lookup" if "balance lookup" in names else ""
    return "%s, word %#x" % (text, out["word"])


def case_line(case, spec):
    return "%s\t%s\t%s" % (case.copy, case.label.split(": ", 1)[1], outcome_name(case, spec))


def worked_runs(harness):
    """One order that grew a shortfall, as its events."""
    w = world(health=(0, 1000, 1100), post=(0, 999, 1100))
    found = harness.run(Case("worked", "second", "a", w))
    return {"margin_before": 1000 - 1100, "margin_after": 999 - 1100, "events": [event[0] for event in found["events"]], "word": "%#x" % found["out"]["word"]}


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    lines = []
    machine = harness.machine
    for case in cases:
        machine.seen = set()
        trouble = compare_run(harness, case)
        if trouble:
            mismatches.append(trouble)
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        spec = spec_run(case)
        name = outcome_name(case, spec)
        outcomes[name] = outcomes.get(name, 0) + 1
        lines.append(case_line(case, spec))
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    for start, role in GROUPS:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = harness.relative
    tables = {SLOT_BALANCES: BALANCE_LOOKUP, DEFAULT_ROW: 0x3790910, 0x56F22E0: 0x37617F0}
    for slot, value in tables.items():
        if relative.get(slot) != value:
            raise EvidenceError("slot %#x" % slot)
    site_rows = []
    direct = direct_sites(image, tuple(start for start, _ in GROUPS) + (RATIO_REPORT,))
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    locations = []
    for slot, name in ((LOC_SETTLE_FIRST, "first settle, quote token"), (LOC_SETTLE_SECOND, "second settle, base token"), (LOC_UNWRAP, "report words negative"), (LOC_NONE_A, "row map with a length and no root, first copies"), (LOC_NONE_C, "row map with a length and no root, third copy")):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    exempt = exempt_address(image, EXEMPT_PARTS)
    sweep_exempt = exempt_address(image, SWEEP_EXEMPT_PARTS)
    if exempt != EXEMPT_USER:
        raise EvidenceError("exempt address")
    twins = [twin_rows(image, SECOND_A, SECOND_B), twin_rows(image, SNAPSHOT_A, SNAPSHOT_B), twin_rows(image, RESERVE_A, RESERVE_B), twin_rows(image, POST_A, POST_B), twin_rows(image, POST_A, POST_C)]
    host_bytes = read_host_bytes(image)
    worked = worked_runs(harness)
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "data_words": {"%#x" % slot: "%#x" % value for slot, value in sorted(tables.items())},
        "copies": {key: {name: ("%#x" % value if not isinstance(value, bool) else value) for name, value in sorted(COPIES[key].items())} for key in sorted(COPIES)},
        "twins": twins,
        "host_bytes": host_bytes,
        "exempt_address": {"post_check": exempt.hex(), "sweep": sweep_exempt.hex(), "same": exempt == sweep_exempt},
        "locations": locations,
        "fields": FIELDS,
        "worked_example": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows, "_lines": lines,
    }


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    files["cases.tsv"] = "\n".join(["copy\tlabel\toutcome"] + case_lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += ["%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_)) for row_ in results]
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
