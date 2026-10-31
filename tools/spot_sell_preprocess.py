#!/usr/bin/env python3
"""Pin the node #94 spot sell preprocess for portfolio margin users, from ELF bytes: gates, health class, rewritten order.

`0x4c21720`, `0x4c21230` and `0x26d2070` decide, before an order reaches the book, whether a spot order is handed to a
second path or runs directly, and `0x48cfb30` and `0x28db4e0` turn a health report into a class. The real bytes run in a
Python evaluator with the callees at the edge stubbed. A separately written specification predicts every result and
stub argument, and every condition, immediate and field offset is flipped to show the run can tell. Four callers run as
context, with no mutants. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

PRE_A = 0x4C21720
PRE_B = 0x4C21230
PRE_C = 0x26D2070
ADAPTER_A = 0x445E270
ADAPTER_B = 0x445E630
ADAPTER_C = 0x445E9F0
ADAPTER_D = 0x445EDB0
HEALTH_CLASS = 0x48CFB30
HEALTH_REPORT = 0x48CFB90
HEALTH_CLASS_C = 0x28DB4E0
HEALTH_REPORT_C = 0x28DB540
USER_ROW = 0x46F2FE0
USER_ROW_B = 0x46F2E60
USER_ROW_C = 0x2755400
ROOM = 0x48CAC10
ROOM_C = 0x28D8B10

SLOT_MEMCPY = 0x576DFE0
SLOT_BOUNDS = 0x576DFC8
SLOT_PANIC = 0x576E470
SLOT_NOUNWIND = 0x576E128
SLOT_RECORDER = 0x5773190
SLOT_ACCOUNT = 0x5773E58
SLOT_BALANCES = 0x5773170
SLOT_BALANCE = 0x5774770
SLOT_AMOUNT = 0x5774768
SLOT_QUOTE = 0x5774778
SLOT_NOTIONAL = 0x5774780
FAKE_MEMCPY = 0xFACE0010

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
HEAP_SIZE = 0x10000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 30000

STATE = HEAP_BASE + 0x100
OUT = HEAP_BASE + 0x8000
ORDER = HEAP_BASE + 0x8200
CONTEXT = HEAP_BASE + 0x8400
USER = HEAP_BASE + 0x8500
SPOTS = HEAP_BASE + 0x8600
ROOT_NODE = HEAP_BASE + 0x9000
LEAF_NODES = HEAP_BASE + 0xA000
RESULT = HEAP_BASE + 0xE000
USER_ROW_AT = HEAP_BASE + 0xE800
ACCOUNT = HEAP_BASE + 0xE900
BALANCES = HEAP_BASE + 0xEA00
BLOCK_END = HEAP_BASE + 0xF000

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
TIF_MASK = 0x15
NOTIONAL_FLOOR = 1000000000
PRODUCT_CAP = 0x7FFFFFFFFFFFFFFE
LOC_RECORD = 0x56DFD90
LOC_SPOT = 0x5742350
RESULT_BYTES = 0x60
ACCOUNT_OFFSET = 0x498
RISK_OFFSET = 0x560
META_OFFSET = 0x90
BALANCE_OFFSET = 0x80
TAG_REPLACE, TAG_DIRECT, TAG_ERROR = 1, 2, 3
WORD_FAILED = 0x187
WORD_REJECT = 0xE1
BYTE_REJECT = 0xA
SEQUENCE_WARNING = None


def blank_result():
    return bytearray([STACK_MARK]) * RESULT_BYTES


def direct_result(flag):
    out = blank_result()
    put_word(out, 0, 8, TAG_DIRECT)
    out[8] = flag
    return out


def error_result(code):
    out = blank_result()
    put_word(out, 0, 8, TAG_ERROR)
    out[8] = code
    return out


def spec_class(value, low, middle, high):
    """Health class of `0x48cfb30`: 0 above high, 1 above middle, 2 above low, else 3."""
    if value > high:
        return 0
    if value > middle:
        return 1
    return 2 if value > low else 3


def spec_health(w):
    """Flag and class word of `0x48cfb30` run alone."""
    report = w["report"]
    events = [("report", ACCOUNT, STATE + RISK_OFFSET, STATE + META_OFFSET, 0)]
    if report[0] == 1:
        return {"events": events, "stop": None, "flag": 1, "class": report[1]}
    return {"events": events, "stop": None, "flag": 0, "class": spec_class(*report[1:])}


def spec_pre(w, location=None):
    """Result bytes, stub calls and stop of one preprocess run."""
    order = w["order"]
    events = []
    answer = {"events": events, "stop": None, "out": None}
    if w["enabled"] != 1 or w["paused"] & 1:
        answer["out"] = direct_result(0)
        return answer
    spot = word(order, 0x28)
    if spot >= len(w["spots"]):
        answer["stop"] = ("bounds", spot, len(w["spots"]), location or LOC_SPOT)
        return answer
    size_tag, size = word(order, 0), word(order, 8)
    if size_tag == 0 or order[0x30] == 0 or order[0x31] != 0 or order[0x19] != 2 or w["tree"] is None:
        answer["out"] = direct_result(0)
        return answer
    base, quote = w["spots"][spot]
    keys = tree_keys(w["tree"])
    if base not in keys or quote not in keys:
        answer["out"] = direct_result(0)
        return answer
    events.append(("user row", STATE, w["user"]))
    if w["mode"] < 4 or w["halted"] & 1:
        answer["out"] = direct_result(0)
        return answer
    events.append(("account", STATE + ACCOUNT_OFFSET, w["user"]))
    events.append(("report", ACCOUNT, STATE + RISK_OFFSET, STATE + META_OFFSET, 0))
    report = w["report"]
    if report[0] == 1:
        answer["out"] = error_result(report[1])
        return answer
    if spec_class(*report[1:]) < 2:
        answer["out"] = direct_result(0)
        return answer
    events.append(("room", ACCOUNT, base, 3, 3, STATE + META_OFFSET, STATE + RISK_OFFSET, 0))
    room = w["room"]
    if room[0]:
        answer["out"] = error_result(room[1])
        return answer
    events.append(("balances", STATE + BALANCE_OFFSET, USER))
    events.append(("balance", BALANCES, base))
    total, held, _ = w["balance"]
    free = total - held
    if free < 0:
        free = 0
        events.append(("recorded", LOC_RECORD))
    left = free + room[1]
    if left > U64:
        left = U64
        events.append(("recorded", LOC_RECORD))
    events.append(("amount", STATE + META_OFFSET, base, size))
    ok, amount = w["amount"]
    if not ok & 1 or left >= amount >> 1:
        answer["out"] = direct_result(0)
        return answer
    events.append(("quote", ACCOUNT, spot, base, quote, STATE + RISK_OFFSET, STATE + META_OFFSET))
    tag, x, low, high, last = w["quote"]
    if tag == 3:
        answer["out"] = error_result(x & 0xFF)
        return answer
    if (tag & 0xFFFFFFFF) == 2 or room[1] >= last:
        answer["out"] = direct_result(0)
        return answer
    price = word(order, 0x20)
    product = price * size
    if product > U64 or product > PRODUCT_CAP:
        answer["out"] = direct_result(0)
        return answer
    events.append(("notional", STATE + META_OFFSET, quote, product))
    if w["notional"] < NOTIONAL_FLOOR:
        answer["out"] = direct_result(0)
        return answer
    tif = order[0x10]
    if TIF_MASK >> (tif & 31) & 1:
        answer["out"] = direct_result(1)
        return answer
    price = max(low, price)
    if price > high:
        answer["out"] = direct_result(1)
        return answer
    new = min(x, size) if tag & 1 else size
    if new < size:
        new += 1
    out = blank_result()
    put_word(out, 0, 8, TAG_REPLACE)
    put_word(out, 8, 8, new)
    out[0x10] = order[0x10]
    out[0x11:0x19] = order[0x11:0x19]
    out[0x19] = 2
    out[0x1A:0x20] = order[0x1A:0x20]
    put_word(out, 0x20, 8, price)
    put_word(out, 0x28, 8, spot)
    put_word(out, 0x30, 2, 1)
    out[0x32:0x43] = order[0x32:0x43]
    put_word(out, 0x48, 8, base)
    put_word(out, 0x50, 8, quote)
    put_word(out, 0x58, 8, last)
    answer["out"] = out
    return answer


def tree_keys(tree):
    return set(tree[0]) | {key for leaf in tree[1] for key in leaf}


def spec_adapter(w, copy):
    """Stub calls and result bytes of one adapter run."""
    events = []
    order, context, pre = w["order"], w["context"], w["pre"]
    answer = {"events": events, "stop": None, "out": None, "enabled": w["enabled"]}
    direct = True
    flag = 0
    if word(context, 0, 4) <= 1:
        events.append(("pre", COPIES[copy]["pre"], w["user"]))
        tag = word(pre, 0)
        if tag == 3:
            direct = True
        elif word(pre, 0, 4) == 2:
            flag = pre[8]
        else:
            direct = False
    if direct:
        spot = word(order, 0x28)
        if spot >= len(w["spots"]):
            answer["stop"] = ("bounds", spot, len(w["spots"]), COPIES[copy]["location"])
            return answer
        book = w["spots"][spot][order[0x30] ^ 1]
        events.append(("direct", COPIES[copy]["direct"], w["user"], book, 2, bytes(order[:0x48]), bytes(context), flag))
        skip = COPIES[copy]["skip"]
        answer["out"] = bytes(ramp(RESULT_BYTES + skip, 0x35)[skip:RESULT_BYTES + skip])
        return answer
    block = (bytes(pre[:0x1A]), bytes(pre[0x1A:0x20]) if pre[0x19] == 2 else None, bytes(pre[0x20:0x32]) + bytes([pre[0x32] & 1]), bytes(pre[0x33:0x43]) if pre[0x32] & 1 else None,
             bytes(context), bytes(pre[0x48:0x60]), w["user"])
    events.append(("second", COPIES[copy]["second"], block))
    second = w["second"]
    if second == WORD_FAILED:
        answer["enabled"] = 0
        out = bytearray(blank_result())
        put_word(out, 0, 2, WORD_REJECT)
        out[2] = BYTE_REJECT
        answer["out"] = bytes(out)
    else:
        data = bytearray(ramp(RESULT_BYTES, 0x47))
        put_word(data, 0, 2, second)
        answer["out"] = bytes(data)
    return answer


COPIES = {
    "a": {"skip": 8, "entry": ADAPTER_A, "pre": PRE_A, "direct": 0x4D3DDB0, "second": 0x4D2F4A0, "location": 0x571FD18, "panic_note": 0x571FD60},
    "b": {"skip": 0, "entry": ADAPTER_B, "pre": PRE_B, "direct": 0x4D3BE40, "second": 0x4D2E9E0, "location": 0x571FD18, "panic_note": 0x571FD60},
    "c": {"skip": 8, "entry": ADAPTER_C, "pre": PRE_B, "direct": 0x4D3C640, "second": 0x4D2E9E0, "location": 0x571FD18, "panic_note": 0x571FD60},
    "d": {"skip": 0, "entry": ADAPTER_D, "pre": PRE_A, "direct": 0x4D3E860, "second": 0x4D2F4A0, "location": 0x571FD18, "panic_note": 0x571FD60},
}
PRES = {
    "a": {"entry": PRE_A, "user_row": USER_ROW, "report": HEALTH_REPORT, "room": ROOM, "location": LOC_SPOT},
    "b": {"entry": PRE_B, "user_row": USER_ROW_B, "report": HEALTH_REPORT, "room": ROOM, "location": LOC_SPOT},
    "c": {"entry": PRE_C, "user_row": USER_ROW_C, "report": HEALTH_REPORT_C, "room": ROOM_C, "location": 0x56BD208},
}


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


NODE_KEYS = 0x798
NODE_LENGTH = 0x7F2
NODE_EDGES = 0x7F8
NODE_SIZE = 0x858
NODE_CAPACITY = 11
ROOT_NODE_PAD = 0x5A5A5A0000000000
UNMAPPED = 0x10


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        machine.memory.statics.update(self.relative)
        relative = self.relative
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCPY
        self.base_slots = {relative[SLOT_PANIC]: self.on_panic, relative[SLOT_BOUNDS]: self.on_bounds, relative[SLOT_RECORDER]: self.on_recorder}
        machine.slots = dict(self.base_slots)
        self.real = RealExcept()
        machine.real = self.real
        self.events = []
        self.case = None

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_recorder(self, m):
        if m.regs[RDI] != 0:
            raise Halt("recorder argument")
        self.events.append(("recorded", m.regs[RSI]))

    def stubs(self, slots, calls):
        machine = self.machine
        machine.slots = dict(self.base_slots)
        machine.slots.update(slots)
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)

    def write_tree(self, tree, fill):
        """A node height of 0 or 1, with every unused key slot holding a tempting key and every leaf edge unmapped."""
        memory = self.machine.memory

        def node(at, keys, edges):
            memory.put_bytes(at, ramp(NODE_SIZE, 0x19))
            for index in range(NODE_CAPACITY):
                memory.write(at + NODE_KEYS + index * 8, 8, keys[index] if index < len(keys) else fill)
            memory.write(at + NODE_LENGTH, 2, len(keys))
            for index in range(NODE_CAPACITY + 1):
                memory.write(at + NODE_EDGES + index * 8, 8, edges[index] if index < len(edges) else UNMAPPED + index * 8)
        keys, leaves = tree
        edges = [LEAF_NODES + index * NODE_SIZE for index in range(len(leaves))]
        node(ROOT_NODE, keys, edges)
        for at, leaf in zip(edges, leaves):
            node(at, leaf, [])
        return 1 if leaves else 0

    def write_state(self, w):
        memory = self.machine.memory
        memory.put_bytes(STATE, ramp(0x700, 0x2B))
        memory.write(STATE + 0x5B3, 1, w["enabled"])
        memory.write(STATE + 0x5B4, 1, w["paused"])
        memory.write(STATE + 0x5B0, 1, w["halted"])
        memory.write(STATE + 0x1F8, 8, SPOTS)
        memory.write(STATE + 0x200, 8, len(w["spots"]))
        for index, row in enumerate(w["spots"]):
            memory.put_bytes(SPOTS + index * 0x20, ramp(0x20, 0x71 + index))
            memory.write(SPOTS + index * 0x20, 8, row[0])
            memory.write(SPOTS + index * 0x20 + 8, 8, row[1])

    def run_pre(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        relative = self.relative
        self.events = []
        events = self.events

        def on_user_row(m):
            events.append(("user row", m.regs[RDI], memory.bytes_at(m.regs[RSI], 20)))
            memory.put_bytes(USER_ROW_AT, ramp(0x60, 0x3D))
            memory.write(USER_ROW_AT + 0x3C, 1, w["mode"])
            m.regs[RAX] = USER_ROW_AT

        def on_account(m):
            events.append(("account", m.regs[RDI], memory.bytes_at(m.regs[RSI], 20)))
            m.regs[RAX] = ACCOUNT

        def on_report(m):
            events.append(("report", m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8]))
            out = m.regs[RDI]
            report = w["report"]
            if report[0] == 1:
                memory.write(out, 1, 1)
                memory.write(out + 1, 1, report[1])
            else:
                memory.write(out, 1, 0)
                memory.write(out + 8, 8, report[1])
                memory.write(out + 0x18, 8, report[2])
                memory.write(out + 0x20, 8, report[3])
                memory.write(out + 0x28, 8, report[4])
                memory.write(out + 0x10, 8, report[1] ^ 0x5A)
            m.regs[RAX] = out

        def on_room(m):
            at = m.regs[RSP]
            events.append(("room", m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R9] & 0xFFFFFFFF, memory.read(at + 8, 8), memory.read(at + 0x10, 8), memory.read(at + 0x18, 8)))
            out = m.regs[RDI]
            room = w["room"]
            memory.write(out, 1, room[0])
            if room[0]:
                memory.write(out + 1, 1, room[1])
            else:
                memory.write(out + 1, 1, 0x63)
                memory.write(out + 8, 8, room[1])
                memory.write(out + 0x10, 8, room[1] ^ 0xA5)
            m.regs[RAX] = out

        def on_balances(m):
            events.append(("balances", m.regs[RDI], m.regs[RSI]))
            m.regs[RAX] = BALANCES

        def on_balance(m):
            events.append(("balance", m.regs[RSI], m.regs[RDX]))
            out = m.regs[RDI]
            for index, value in enumerate(w["balance"]):
                memory.write(out + index * 8, 8, value)
            m.regs[RAX] = out

        def on_amount(m):
            events.append(("amount", m.regs[RDI], m.regs[RSI], m.regs[RDX]))
            m.regs[RAX] = w["amount"][0]
            m.regs[RDX] = w["amount"][1]
            m.keep_rdx = True

        def on_quote(m):
            events.append(("quote", m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8], m.regs[R9], memory.read(m.regs[RSP], 8)))
            out = m.regs[RDI]
            tag, x, low, high, last = w["quote"]
            memory.write(out, 8, tag)
            memory.write(out + 8, 8, x)
            memory.write(out + 0x10, 8, low)
            memory.write(out + 0x18, 8, high)
            memory.write(out + 0x20, 8, last)
            m.regs[RAX] = out

        def on_notional(m):
            events.append(("notional", m.regs[RDI], m.regs[RSI], m.regs[RDX]))
            m.regs[RAX] = w["notional"]

        slots = {relative[SLOT_ACCOUNT]: on_account, relative[SLOT_BALANCES]: on_balances, relative[SLOT_BALANCE]: on_balance, relative[SLOT_AMOUNT]: on_amount, relative[SLOT_QUOTE]: on_quote, relative[SLOT_NOTIONAL]: on_notional}
        pre = PRES[case.copy]
        calls = {pre["user_row"]: on_user_row, pre["report"]: on_report, pre["room"]: on_room}
        self.stubs(slots, calls)
        memory.reset()
        self.write_state(w)
        if w["tree"] is None:
            memory.write(STATE + 0x568, 8, 0)
            memory.write(STATE + 0x570, 8, 3)
        else:
            memory.write(STATE + 0x570, 8, self.write_tree(w["tree"], w["fill"]))
            memory.write(STATE + 0x568, 8, ROOT_NODE)
        memory.put_bytes(ORDER, w["order"])
        memory.put_bytes(USER, w["user"])
        entry = pre["entry"]
        answer = {"events": events, "stop": None, "out": None}
        try:
            rax = machine.run(entry, {RDI: OUT, RSI: ORDER, RDX: USER, RCX: STATE})
        except Panicked as stop:
            answer["stop"] = stop.args[0]
            return answer
        if rax != OUT and case.copy != "c":
            raise Halt("result pointer")
        answer["out"] = bytearray(memory.bytes_at(OUT, RESULT_BYTES))
        return answer

    def run_health(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.events = []
        events = self.events

        def on_report(m):
            events.append(("report", m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8]))
            out = m.regs[RDI]
            report = w["report"]
            memory.write(out, 1, report[0])
            if report[0] == 1:
                memory.write(out + 1, 1, report[1])
            else:
                for at, value in zip((8, 0x18, 0x20, 0x28), report[1:]):
                    memory.write(out + at, 8, value)
                memory.write(out + 0x10, 8, report[1] ^ 0x5A)
            m.regs[RAX] = out

        pre = PRES[case.copy]
        self.stubs({}, {pre["report"]: on_report})
        memory.reset()
        entry = HEALTH_CLASS_C if case.copy == "c" else HEALTH_CLASS
        rax = machine.run(entry, {RDI: ACCOUNT, RSI: STATE + RISK_OFFSET, RDX: STATE + META_OFFSET})
        return {"events": events, "stop": None, "flag": rax & 0xFF, "class": machine.regs[RDX] & 0xFF}

    def run_adapter(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        copy = COPIES[case.copy]
        self.events = []
        events = self.events

        def on_pre(m):
            if m.regs[RSI] != ORDER or m.regs[RCX] != STATE:
                raise Halt("preprocess arguments")
            events.append(("pre", copy["pre"], memory.bytes_at(m.regs[RDX], 20)))
            memory.put_bytes(m.regs[RDI], w["pre"])
            m.regs[RAX] = m.regs[RDI]

        def on_direct(m):
            at = m.regs[RSP]
            block = memory.read(at + 8, 8)
            if m.regs[RSI] != STATE or m.regs[RCX] != 1 or memory.read(at + 0x10, 8) != copy["panic_note"]:
                raise Halt("direct arguments")
            if memory.read(block + 0x98, 8) != USER:
                raise Halt("direct user pointer")
            events.append(("direct", copy["direct"], memory.bytes_at(m.regs[RDX], 20), m.regs[R8], memory.read(m.regs[R9], 8), memory.bytes_at(block, 0x48), memory.bytes_at(block + 0x48, 0x50), memory.read(memory.read(block + 0xA0, 8), 1)))
            memory.put_bytes(m.regs[RDI], ramp(RESULT_BYTES + copy["skip"], 0x35))
            m.regs[RAX] = m.regs[RDI]

        def on_second(m):
            if m.regs[RSI] != STATE:
                raise Halt("second arguments")
            block = m.regs[RDX]
            data = memory.bytes_at(block, 0xC4)
            pre = w["pre"]
            events.append(("second", copy["second"], (data[:0x1A], data[0x1A:0x20] if pre[0x19] == 2 else None, data[0x20:0x33], data[0x33:0x43] if pre[0x32] & 1 else None,
                                                     data[0x48:0x98], data[0x98:0xB0], data[0xB0:0xC4])))
            result = bytearray(ramp(RESULT_BYTES, 0x47))
            put_word(result, 0, 2, w["second"])
            memory.put_bytes(m.regs[RDI], bytes(result))
            m.regs[RAX] = m.regs[RDI]

        self.stubs({}, {copy["pre"]: on_pre, copy["direct"]: on_direct, copy["second"]: on_second})
        memory.reset()
        self.write_state(w)
        memory.put_bytes(ORDER, w["order"])
        memory.put_bytes(USER, w["user"])
        memory.put_bytes(CONTEXT, w["context"])
        answer = {"events": events, "stop": None, "out": None, "enabled": w["enabled"]}
        try:
            rax = machine.run(copy["entry"], {RDI: OUT, RSI: ORDER, RDX: USER, RCX: CONTEXT, R8: STATE})
        except Panicked as stop:
            answer["stop"] = stop.args[0]
            return answer
        if rax != OUT:
            raise Halt("result pointer")
        answer["out"] = memory.bytes_at(OUT, RESULT_BYTES)
        answer["enabled"] = memory.read(STATE + 0x5B3, 1)
        return answer

    def run(self, case):
        if case.kind == "health":
            return self.run_health(case)
        return self.run_pre(case) if case.kind == "pre" else self.run_adapter(case)


def spec_run(case):
    if case.kind == "health":
        return spec_health(case.world)
    return spec_pre(case.world, PRES[case.copy]["location"]) if case.kind == "pre" else spec_adapter(case.world, case.copy)


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
            detail = "%s found %s wanted %s" % (keys[0], str(left)[:500], str(right)[:500])
        return "%s: differs: %s" % (case.label, detail)
    return ""


# ---- cases ----

BASE = 0x11
QUOTE = 0x22
TREE_FLAT = ((0x05, BASE, QUOTE, 0x90), ())
TREE_DEEP = ((QUOTE,), ((0x05, BASE), (0x90, 0xA0)))
LONG_USER = bytes(ramp(20, 0x83))
FILL_KEY = 0x7777


def make_order(**change):
    order = bytearray(ramp(0x48, 0x57))
    fields = {"tag": 1, "size": 1000, "tif": 1, "k": 2, "price": 2000000, "spot": 1, "side": 1, "reduce": 0}
    fields.update(change)
    put_word(order, 0, 8, fields["tag"])
    put_word(order, 8, 8, fields["size"])
    order[0x10] = fields["tif"]
    order[0x19] = fields["k"]
    put_word(order, 0x20, 8, fields["price"])
    put_word(order, 0x28, 8, fields["spot"])
    order[0x30] = fields["side"]
    order[0x31] = fields["reduce"]
    return bytes(order)


def pre_world(order=None, **change):
    w = {"enabled": 1, "paused": 0, "halted": 0, "spots": [(0x70, 0x71), (BASE, QUOTE), (0x72, 0x73)], "tree": TREE_FLAT, "fill": FILL_KEY,
         "mode": 4, "report": (0, 50, 10, 100, 200), "room": (0, 30), "balance": (500, 200, 7), "amount": (1, 1000000), "quote": (1, 700, 1900000, 2100000, 900),
         "notional": 2000000000, "order": make_order(**(order or {})), "user": LONG_USER}
    w.update(change)
    return w


def pre_cases():
    rows = []

    def add(label, **change):
        rows.append((label, pre_world(**change)))

    add("accepted")
    add("deep tree", tree=TREE_DEEP)
    add("deep tree, base in the root", tree=((BASE,), ((0x05,), (QUOTE, 0x90))))
    add("deep tree, quote left of base", tree=((0x20,), ((0x05, BASE), (QUOTE, 0x90))), spots=[(0x70, 0x71), (0x22, 0x11), (0x72, 0x73)])
    for value in (0, 2, 3, 0xFF):
        add("enabled byte %d" % value, enabled=value)
    for value in (1, 3, 0xFF, 2, 0xFE):
        add("paused byte %d" % value, paused=value)
    for value in (1, 3, 2, 0xFE):
        add("halted byte %d" % value, halted=value)
    for spot in (3, 4, 1 << 40):
        add("spot %d past the list" % spot, order={"spot": spot})
    add("spot past the list, not enabled", order={"spot": 9}, enabled=0)
    add("spot past the list, paused", order={"spot": 9}, paused=1)
    add("no size", order={"tag": 0})
    add("size tag 2", order={"tag": 2})
    add("side 0", order={"side": 0})
    add("side 2", order={"side": 2})
    add("reduce only", order={"reduce": 1})
    add("reduce byte 2", order={"reduce": 2})
    for k in (0, 1, 3):
        add("k %d" % k, order={"k": k})
    add("no tree", tree=None)
    add("base missing", tree=((0x05, QUOTE, 0x90), ()))
    add("quote missing", tree=((0x05, BASE, 0x90), ()))
    add("both missing", tree=((0x05, 0x90), ()))
    add("empty root", tree=((), ()), fill=BASE)
    add("empty root, other filler", tree=((), ()))
    add("short root, base in a spare slot", tree=((0x05,), ()), fill=BASE)
    add("deep, base missing", tree=((QUOTE,), ((0x05,), (0x90,))))
    add("deep, quote missing", tree=((BASE,), ((0x05,), (0x90,))))
    add("deep, base missing past the end", tree=((QUOTE,), ((0x05,), (0x90,))), spots=[(0x70, 0x71), (0xF0, QUOTE), (0x72, 0x73)])
    add("deep, quote missing past the end", tree=((BASE,), ((0x05,), (0x90,))), spots=[(0x70, 0x71), (BASE, 0xF0), (0x72, 0x73)])
    add("deep, base missing below", tree=((0x40,), ((0x05,), (QUOTE, 0x90))), spots=[(0x70, 0x71), (0x06, QUOTE), (0x72, 0x73)])
    add("deep, quote missing below", tree=((0x40,), ((0x05, BASE), (0x90,))), spots=[(0x70, 0x71), (BASE, 0x22), (0x72, 0x73)])
    for mode in (0, 1, 2, 3):
        add("mode %d" % mode, mode=mode)
    add("mode 5", mode=5)
    add("mode 0xff", mode=0xFF)
    add("report error", report=(1, 0x2B))
    add("report error code 0", report=(1, 0))
    for value, name in ((201, "above high"), (200, "at high"), (101, "above middle"), (100, "at middle"), (11, "above low"), (10, "at low"), (9, "below low")):
        add("health %s" % name, report=(0, value, 10, 100, 200))
    add("health, thresholds all equal", report=(0, 7, 7, 7, 7))
    add("health, high bits", report=(0, (1 << 63) + 2, (1 << 63) + 1, (1 << 63) + 2, 1 << 63))
    add("room error", room=(1, 0x37))
    add("room error code 0", room=(9, 0))
    add("no room", room=(0, 0))
    add("held above total", balance=(100, 200, 7))
    add("held equal total", balance=(200, 200, 7))
    add("room saturates", room=(0, U64), balance=(500, 200, 7))
    add("room just fits", room=(0, U64 - 300), balance=(500, 200, 7), amount=(1, U64))
    add("room and borrow, both record", room=(0, U64), balance=(0, 1, 7), amount=(1, U64))
    add("amount refused", amount=(0, 1000000))
    add("amount flag 2", amount=(2, 1000000))
    add("amount flag 3", amount=(3, 1000000))
    add("left below half by one", balance=(329, 0, 7), room=(0, 170), amount=(1, 1000))
    add("left at half", balance=(330, 0, 7), room=(0, 170), amount=(1, 1000))
    add("left at half of an odd amount", balance=(330, 0, 7), room=(0, 170), amount=(1, 1001))
    add("left below half of an odd amount", balance=(329, 0, 7), room=(0, 170), amount=(1, 1001))
    add("left at the top half", balance=(1 << 62, 0, 7), room=(0, 1 << 62), amount=(1, U64))
    add("quote stops", quote=(3, 0x41, 1900000, 2100000, 900))
    add("quote stops, high word", quote=(3, (9 << 56) + 0x42, 1900000, 2100000, 900))
    add("quote gives nothing", quote=(2, 700, 1900000, 2100000, 900))
    add("room at last", room=(0, 900), balance=(0, 0, 7))
    add("room above last", room=(0, 901), balance=(0, 0, 7))
    add("room one below last", room=(0, 899), balance=(0, 0, 7))
    add("tag 0, room at last", room=(0, 900), balance=(0, 0, 7), quote=(0, 700, 1900000, 2100000, 900))
    add("x far above last", quote=(1, 9000, 1900000, 2100000, 900))
    add("tag 0", quote=(0, 700, 1900000, 2100000, 900))
    add("tag 0, x below size", quote=(0, 3, 1900000, 2100000, 900))
    add("x above size", quote=(1, 5000, 1900000, 2100000, 9000))
    add("x equals size", quote=(1, 1000, 1900000, 2100000, 9000))
    add("x just below size", quote=(1, 999, 1900000, 2100000, 9000))
    add("x zero", quote=(1, 0, 1900000, 2100000, 9000))
    add("product at the cap", order={"size": 1, "price": PRODUCT_CAP}, quote=(0, 0, 1, U64, 900))
    add("product above the cap", order={"size": 1, "price": PRODUCT_CAP + 1}, quote=(0, 0, 1, U64, 900))
    add("product wraps to a small word", order={"size": 1 << 33, "price": (1 << 31) + 1}, quote=(0, 0, 1, U64, 900))
    add("product wraps", order={"size": 1 << 40, "price": 1 << 40}, quote=(0, 0, 1, U64, 900))
    add("product wraps high", order={"size": U64, "price": U64}, quote=(0, 0, 1, U64, 900))
    add("notional at the floor", notional=NOTIONAL_FLOOR)
    add("notional below the floor", notional=NOTIONAL_FLOOR - 1)
    add("notional far above", notional=U64)
    add("notional zero", notional=0)
    for tif in list(range(0, 8)) + [0x20, 0x21, 0x22, 0x24, 0x40, 0x41, 0x80, 0xFF]:
        add("tif %#x" % tif, order={"tif": tif})
    add("price below low", order={"price": 1000000})
    add("price at low", order={"price": 1900000})
    add("price at high", order={"price": 2100000})
    add("price above high", order={"price": 2100001})
    add("low above high", quote=(1, 700, 2200000, 2100000, 900))
    add("low at high, price below", quote=(1, 700, 2100000, 2100000, 900), order={"price": 1000000})
    add("low above high by one", quote=(1, 700, 2100001, 2100000, 900), order={"price": 1000000})
    add("low filler, keys in the last leaf", tree=((0x08,), ((0x05,), (BASE, QUOTE))), fill=1)
    add("low filler, flat", tree=((0x05, BASE, QUOTE), ()), fill=1)
    add("low filler, base past the end", tree=((0x05, QUOTE), ()), fill=1, spots=[(0x70, 0x71), (0xF0, QUOTE), (0x72, 0x73)])
    add("low filler, quote past the end", tree=((0x05, BASE), ()), fill=1, spots=[(0x70, 0x71), (BASE, 0xF0), (0x72, 0x73)])
    add("low filler, quote in the last leaf", tree=((0x08,), ((BASE, ), (0x20, QUOTE))), fill=1, spots=[(0x70, 0x71), (0x05, QUOTE), (0x72, 0x73)])
    add("spot 0", spots=[(BASE, QUOTE), (0x70, 0x71)], order={"spot": 0})
    add("spot 2", spots=[(0x70, 0x71), (0x72, 0x73), (BASE, QUOTE)], order={"spot": 2})
    add("spot 1 of 2", spots=[(0x70, 0x71), (BASE, QUOTE)])
    add("other pair", spots=[(0x70, 0x71), (0x90, 0x05), (0x72, 0x73)])
    return rows


def adapter_world(pre=None, **change):
    order = make_order()
    w = {"enabled": 1, "paused": 0, "halted": 0, "spots": [(0x70, 0x71), (BASE, QUOTE), (0x72, 0x73)], "order": order, "user": LONG_USER,
         "context": ramp(0x50, 0x67), "second": 0x186}
    w["context"] = bytes(bytearray(b"\x00\x00\x00\x00") + w["context"][4:])
    w.update(change)
    w["pre"] = pre if pre is not None else replace_result()
    return w


def replace_result(k=2, cloid=1, tag=1):
    out = bytearray(ramp(RESULT_BYTES, 0x15))
    put_word(out, 0, 8, tag)
    out[0x19] = k
    out[0x32] = cloid
    return bytes(out)


def plain(tag, byte, rest=0x15):
    out = bytearray(ramp(RESULT_BYTES, rest))
    put_word(out, 0, 8, tag)
    out[8] = byte
    return bytes(out)


def context_with(value):
    data = bytearray(ramp(0x50, 0x67))
    put_word(data, 0, 4, value)
    return bytes(data)


def adapter_cases():
    rows = []

    def add(label, pre=None, **change):
        rows.append((label, adapter_world(pre, **change)))

    add("second path")
    add("second path, tag 0", replace_result(tag=0))
    add("second path, record k 1", replace_result(k=1))
    add("second path, record k 3", replace_result(k=3))
    add("second path, no cloid", replace_result(cloid=0))
    add("second path, cloid byte 3", replace_result(cloid=3))
    add("second path, cloid byte 2", replace_result(cloid=2))
    add("second path fails", second=WORD_FAILED)
    add("second path word 0x188", second=0x188)
    add("second path word 0x87", second=0x87)
    add("second path word 0x10187", second=0x187 ^ 0x100)
    add("direct, flag 0", plain(2, 0))
    add("direct, flag 1", plain(2, 1))
    add("direct, flag byte 0xfe", plain(2, 0xFE))
    add("error turns direct", plain(3, 0x41))
    add("error, flag byte is dropped", plain(3, 1))
    add("buy side book", plain(2, 0), order=make_order(side=0))
    add("sell side book", plain(2, 0), order=make_order(side=1))
    add("spot 0", plain(2, 0), order=make_order(spot=0))
    add("spot 2", plain(2, 0), order=make_order(spot=2))
    add("spot past the list", plain(2, 0), order=make_order(spot=3))
    add("spot far past the list", plain(2, 0), order=make_order(spot=1 << 40))
    add("error, spot past the list", plain(3, 7), order=make_order(spot=3))
    for value in (2, 3, 0x100, 0x80000000, 0xFFFFFFFF):
        add("context %#x skips the preprocess" % value, plain(1, 9), context=context_with(value))
    add("context 1 calls it", plain(2, 0), context=context_with(1))
    add("context 0 calls it", plain(2, 1), context=context_with(0))
    add("context 1 with a high word", plain(2, 0), context=bytes(context_with(1)[:4]) + b"\x09\x00\x00\x00" + bytes(context_with(1)[8:]))
    return rows


HEALTH_ROWS = ((0, 201, 10, 100, 200), (0, 200, 10, 100, 200), (0, 101, 10, 100, 200), (0, 100, 10, 100, 200), (0, 11, 10, 100, 200), (0, 10, 10, 100, 200), (0, 9, 10, 100, 200),
               (0, 7, 7, 7, 7), (0, 8, 7, 7, 7), (0, 0, 0, 0, 0), (0, U64, U64, U64, U64), (0, U64, 1, 2, U64 - 1), (1, 0x2B), (1, 0))


def all_cases():
    cases = []
    for copy in ("a", "c"):
        for index, row in enumerate(HEALTH_ROWS):
            cases.append(Case("health %s: row %d" % (copy, index), "health", copy, {"report": row}))
    for copy in sorted(PRES):
        for label, w in pre_cases():
            cases.append(Case("pre %s: %s" % (copy, label), "pre", copy, w))
    for copy in sorted(COPIES):
        for label, w in adapter_cases():
            cases.append(Case("adapter %s: %s" % (copy, label), "adapter", copy, w))
    return cases


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
    (0x46F3011, "498b8e40070000", "mov rcx, [r14+0x740]: the row table of the user row lookup the first preprocess calls"),
    (0x46F2E91, "498b8ec0110000", "mov rcx, [r14+0x11c0]: the row table of the lookup the second preprocess calls"),
    (0x4C2190E, "80783c04", "cmp byte [rax+0x3c], 4: the mode gate of the first preprocess"),
    (0x4C2141E, "80783c04", "cmp byte [rax+0x3c], 4: the mode gate of the second preprocess"),
    (0x4C21B07, "483dff c99a3b".replace(" ", ""), "cmp rax, 0x3b9ac9ff: last refused notional"),
    (0x4C21AC5, "48bafeffffffffffff7f", "mov rdx, 0x7ffffffffffffffe: last admitted product"),
    (0x235942D, "4180e6014588b5b3050000", "and r14b, 1; mov [r13+0x5b3], r14b: sub table 0x3dd340 entry 0, reached with inner word 2 in the action arm the main table sends words below 0x12 to"),
    (0x26D1C0F, "6681bc24100100008701", "cmp word [rsp+0x110], 0x187, after the second path of 0x26d16b0"),
    (0x26D1C1B, "41c686b305000000", "mov byte [r14+0x5b3], 0, in 0x26d16b0"),
    (0x26D15D7, "41c686b305000000", "mov byte [r14+0x5b3], 0, in 0x26d0e50"),
)


def read_host_bytes(image):
    rows = []
    for va, wanted, meaning in HOST_BYTES:
        data = bytes(image.blob[image.offset(va):image.offset(va) + len(wanted) // 2]).hex()
        if data != wanted:
            raise EvidenceError("host bytes at %#x: %s" % (va, data))
        rows.append({"va": "%#x" % va, "bytes": data, "meaning": meaning})
    return rows


NAME_TABLE = 0x570D358
NAME_ROWS = 10


def name_rows(image, relative):
    """Rows of (pointer, length) in .data.rel.ro, read through relocations and raw length words."""
    rows = []
    for index in range(NAME_ROWS):
        at = NAME_TABLE + index * 0x10
        length = struct.unpack_from("<Q", image.blob, image.offset(at + 8))[0]
        start = image.offset(relative[at])
        rows.append(bytes(image.blob[start:start + length]).decode())
    return rows


GUARD_DISPLACEMENT = b"\xb3\x05\x00\x00"


def guard_writers(image):
    """Every `mov byte [reg+0x5b3], imm8` or `mov byte [reg+0x5b3], r8` in .text, from a byte pattern."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(GUARD_DISPLACEMENT)
    while at >= 0:
        modrm = text[at - 1]
        opcode = text[at - 2]
        if modrm >> 6 == 2 and modrm & 7 != 4:
            if opcode == 0xC6 and modrm >> 3 & 7 == 0:
                rex = text[at - 3]
                rows.append((base + at - (3 if 0x40 <= rex <= 0x4F else 2), "imm8 %#x" % text[at + 4]))
            elif opcode == 0x88:
                rex = text[at - 3]
                rows.append((base + at - (3 if 0x40 <= rex <= 0x4F else 2), "register"))
        at = text.find(GUARD_DISPLACEMENT, at + 1)
    return [(va, what, image.fde(va)[0]) for va, what in rows if fde_holds(image, va)]


def fde_holds(image, va):
    try:
        image.fde(va)
    except EvidenceError:
        return False
    return True


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



GROUPS = ((PRE_A, "preprocess, first copy"), (PRE_B, "preprocess, second copy"), (PRE_C, "preprocess, third copy"), (HEALTH_CLASS, "health class"), (HEALTH_CLASS_C, "health class, third copy"))
CONTEXT_GROUPS = ((ADAPTER_A, "caller A, run with no mutants"), (ADAPTER_B, "caller B, run with no mutants"), (ADAPTER_C, "caller C, run with no mutants"), (ADAPTER_D, "caller D, run with no mutants"))


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
    {"reference": "l1/spot_clearinghouse/cl_trait.rs:328", "claim": "preprocess_main_spot_order and preprocess_perp_dex_order are trait methods with no body in the tree", "observed": "two bodies, 0x4c21720 and 0x4c21230, equal but for the user row lookup", "verdict": "bodies are new here; which name goes with which body is not settled"},
    {"reference": "l1/spot_clearinghouse/cl_trait.rs:359", "claim": "ctx.tag > 1 skips the preprocess", "observed": "cmp dword [rcx], 1; ja", "verdict": "agrees, as a u32 compare"},
    {"reference": "l1/spot_clearinghouse/cl_trait.rs:367", "claim": "fallback or status 3 runs the direct path", "observed": "tag 3 takes it with flag 0, tag 2 with the byte of the result", "verdict": "agrees; the code of a tag 3 result is dropped"},
    {"reference": "l1/spot_clearinghouse/cl_trait.rs:373", "claim": "the direct path gets the opposite side book", "observed": "word (side ^ 1) of the spot row", "verdict": "agrees"},
    {"reference": "l1/spot_clearinghouse/cl_trait.rs:12", "claim": "391, 225 and 10 are the failure word, the rejected word and its code", "observed": "0x187, 0xe1 and 0xa, and a write of 0 to state +0x5b3", "verdict": "agrees"},
    {"reference": "l1/spot_clearinghouse/cl_trait.rs:386", "claim": "use_main_book_for_replace picks one of two replace bodies and goes with the preprocess choice", "observed": "0x4c21720 always pairs with 0x4d2f4a0, 0x4c21230 with 0x4d2e9e0", "verdict": "pairing agrees; the replace bodies are not read here"},
)
FIELDS = {
    "state": {"+0x80": "first argument of the balance row lookup 0x371b3a0", "+0x90": "meta block given to every amount helper", "+0x1f8/+0x200": "spot rows: pointer, count, stride 0x20; words 0 and 1 are read", "+0x498": "first argument of the account lookup 0x373acd0", "+0x560": "block given to the health report; +0x568 root and +0x570 height of a map with u64 keys and 0xb0 byte values", "+0x5b0": "bit 0 set sends the order direct", "+0x5b3": "must be exactly 1; written 0 by the adapters after word 0x187", "+0x5b4": "bit 0 set sends the order direct"},
    "order": {"+0x00/+0x08": "size option: tag, value", "+0x10": "tif byte", "+0x11": "8 bytes copied", "+0x19": "byte k; 2 is the slab shape", "+0x1a": "6 bytes copied", "+0x20": "price", "+0x28": "spot index", "+0x30": "side", "+0x31": "reduce only", "+0x32": "cloid, 17 bytes"},
    "map_node": {"+0x798": "keys, 11 slots of 8 bytes", "+0x7f2": "length, u16", "+0x7f8": "edges"},
    "report": {"+0": "byte: 1 stops", "+1": "code", "+8": "value compared", "+0x18": "low threshold", "+0x20": "middle threshold", "+0x28": "high threshold"},
    "quote_result": {"+0": "tag: 0 or 1 go on, 2 direct, 3 stop", "+8": "x, or the stop code", "+0x10": "low price", "+0x18": "high price", "+0x20": "last"},
    "replace_result": {"+0": "1", "+8": "new size", "+0x10..+0x1f": "tif and bytes of the order, k forced to 2", "+0x20": "price", "+0x28": "spot", "+0x30": "side 1, reduce only 0", "+0x32": "cloid", "+0x48/+0x50": "base, quote", "+0x58": "last"},
    "second_block": {"+0x00": "first 0x48 bytes of the preprocess result", "+0x48": "context, 0x50 bytes", "+0x98/+0xa0/+0xa8": "base, quote, last", "+0xb0": "user, 20 bytes"},
    "direct_block": {"+0x00": "order, 0x48 bytes", "+0x48": "context, 0x50 bytes", "+0x98": "user pointer", "+0xa0": "pointer to the flag byte"},
}
UNWIND = "unwind landing pad: no case unwinds"
SIDE_EFFECT_FREE = "the adapter copies a word that only moves around uncompared stack bytes"


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "no case in the list separates this mutant; no claim rests on this row")


SATURATED = "the saturated word is only compared with half of a u64, so any word from 2^63 up acts the same"
REASONS = {0x4C21BE9: SATURATED, 0x4C216F9: SATURATED, 0x26D2533: SATURATED}
REASON_RANGES = ()


def outcome_name(case, spec):
    if spec["stop"]:
        return "%s: index panic" % case.kind
    if case.kind == "health":
        return "health: flag %d" % spec["flag"] if spec["flag"] else "health: class %d" % spec["class"]
    if case.kind == "pre":
        out = spec["out"]
        tag = word(out, 0)
        return "pre: " + {1: "second path", 2: "direct, flag %d" % out[8], 3: "stop code"}[tag]
    names = [event[0] for event in spec["events"]]
    return "adapter: " + ("direct" if "direct" in names else "second path, rejected" if spec["enabled"] == 0 else "second path")


def case_line(case, spec):
    return "%s\t%s\t%s\t%s" % (case.kind, case.copy, case.label.split(": ", 1)[1], outcome_name(case, spec))


def worked_runs(harness):
    """One accepted order, shown as its input and result words."""
    w = pre_world()
    found = harness.run(Case("worked", "pre", "a", w))
    data = found["out"]
    return {"input": {"size": word(w["order"], 8), "price": word(w["order"], 0x20), "x": w["quote"][1], "low": w["quote"][2], "high": w["quote"][3], "last": w["quote"][4]},
            "output": {"tag": word(data, 0), "size": word(data, 8), "price": word(data, 0x20), "k": data[0x19], "side": data[0x30], "reduce_only": data[0x31], "base": word(data, 0x48), "quote": word(data, 0x50), "last": word(data, 0x58)}}


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
    for start, role in GROUPS + CONTEXT_GROUPS:
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = harness.relative
    slots = {SLOT_ACCOUNT: 0x373ACD0, SLOT_BALANCES: 0x371B3A0, SLOT_BALANCE: 0x3724E80, SLOT_AMOUNT: 0x37606B0, SLOT_QUOTE: 0x37344A0, SLOT_NOTIONAL: 0x375FA80}
    for slot, value in slots.items():
        if relative.get(slot) != value:
            raise EvidenceError("slot %#x" % slot)
    site_rows = []
    direct = direct_sites(image, (PRE_A, PRE_B, PRE_C, ADAPTER_A, ADAPTER_B, ADAPTER_C, ADAPTER_D, HEALTH_CLASS, HEALTH_CLASS_C, ROOM, ROOM_C))
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    for slot, value in ((SLOT_QUOTE, 0x37344A0), ):
        for va in slot_sites(image, slot):
            site_rows.append((value, va, "slot %#x" % slot, image.fde(va)[0], image.fde(va)[1]))
    locations = []
    for slot, name in ((LOC_SPOT, "spot past the list, in the preprocess"), (COPIES["a"]["location"], "spot past the list, in the adapters"), (COPIES["a"]["panic_note"], "location given to the direct path"), (PRES["c"]["location"], "spot past the list, in the third preprocess"), (LOC_RECORD, "recorder: saturating balance arithmetic")):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    twins = [twin_rows(image, PRE_A, PRE_B), twin_rows(image, ADAPTER_A, ADAPTER_B), twin_rows(image, ADAPTER_A, ADAPTER_C), twin_rows(image, ADAPTER_A, ADAPTER_D)]
    host_bytes = read_host_bytes(image)
    names = name_rows(image, relative)
    writers = guard_writers(image)
    worked = worked_runs(harness)
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "slots": {"%#x" % slot: "%#x" % value for slot, value in sorted(slots.items())},
        "copies": {key: {name: "%#x" % value for name, value in COPIES[key].items() if name != "skip"} for key in sorted(COPIES)},
        "direct_result_offset": {key: COPIES[key]["skip"] for key in sorted(COPIES)},
        "preprocess_copies": {key: {name: "%#x" % value for name, value in sorted(PRES[key].items())} for key in sorted(PRES)},
        "twins": twins,
        "host_bytes": host_bytes,
        "variant_name_rows": {"table": "%#x" % NAME_TABLE, "rows": names},
        "guard_writers": [{"va": "%#x" % va, "write": what, "fde": "%#x" % fde} for va, what, fde in writers],
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
    files["cases.tsv"] = "\n".join(["kind\tcopy\tlabel\toutcome"] + case_lines) + "\n"
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
