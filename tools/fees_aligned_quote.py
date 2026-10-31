#!/usr/bin/env python3
"""Pin the node #94 aligned quote token fee path from ELF bytes: the enable writer, the spot fee class bytes and their fill hosts.

The writer 0x274db00 and its copies, the same-deployer collector 0x27e61a0, the spot wrapper 0x372f020, the outcome hosts 0x3726360
and 0x3726980 and the two fill sites run in a Python evaluator. The fee body 0x3742460 runs as real bytes behind them. A separately
written specification predicts every result, stub argument, record byte and final state word, and every condition, immediate and
field offset of the mapped code is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is
never executed. Standard library only.
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

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 = range(16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x4000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x40000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 300000


class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class Finished(Exception):
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
        elif byte not in (0x2E, 0xF0):
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
            if value not in (0, 5):
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd" if value == 0 else "cmpnltsd", ("x", reg), rm, 8)
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
        if two == 0xB0:
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), 1)
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
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
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
        self.watch = {}
        self.steps = 0
        self.keep_rdx = False
        self.keep_float = False
        self.step_limit = STEP_LIMIT
        self.jump_ranges = ()
        self.call_site = 0
        self.frame = 0

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
        self.regs[RSP] = STACK_TOP - 0x100 - self.frame
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
            if pc in self.watch:
                self.watch[pc](self)
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
                self.call_site = row.va
                self.stub(hook)
                return self.pop()
            if not any(low <= target < high for low, high in self.jump_ranges):
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
        elif op == "cmpnltsd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], 0 if left < right else MASK[8])
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


def relative_slots(image):
    return {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}


WRITERS = (
    dict(name="first", entry=0x274DB00, dex_list=0x5C0, dex_len=0x5C8),
    dict(name="second", entry=0x4D6E380, dex_list=0x5C0, dex_len=0x5C8),
    dict(name="third", entry=0x4D6EA40, dex_list=0x1040, dex_len=0x1048),
)
WRITER_SIZE = 1714
# call offsets inside a writer; the targets are read from each copy
WRITER_CALLS = {0x8F: "drop", 0x2FE: "collect", 0x30E: "remove", 0x447: "gate", 0x546: "iter", 0x5CF: "insert", 0x5FB: "dropval", 0x631: "dropset"}
COLLECT = 0x27E61A0
FILTER = 0x257D2F0
TREE_NEXT = 0x27E09E0
SET_BUILD = 0x1B0EDC0
SET_PUSH = 0x1AF7FD0
VEC_GROW = 0x251B070
VEC_GROW_INNER = 0x251AEC0
WRAPPER = 0x372F020
MINT = 0x3726360
BURN = 0x3726980
STATS = 0x372E0A0
STATS_SITE = 0x372E2F0
LOOP = 0x372B9D0
LOOP_START = 0x372BEC0
LOOP_SITE = 0x372C114
FEE = 0x3742460
RATES = 0x3743DF0
DISCOUNT = 0x3743020
HASH = 0x399C4A0
OUTCOME_UNIT = 0x385C150
OUTCOME_LEGS = 0x3C18FB0
PREDICATE = 0x3728670
PANIC_BOUND = 0x157B64F
PANIC_NONE = 0x157A9F0
PANIC_INDEX = 0x157B520
UNWRAP = 0x157AA10
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_PANIC_INDEX = 0x576E470
SLOT_FAIL = 0x576E020
SLOT_LAYOUT = 0x576DFB8
SLOT_REALLOC = 0x576E030
STATUS_TABLE = 0x59A8D0
OK = 0x186
BAD_QUOTE = 0xEF
DUPLICATE = 0xF0
TEXT_STATUS = 0xDF
TEXT_DISABLE = 0x3EFF10
TEXT_DISABLE_LEN = 0x3F
TEXT_ENABLE = 0x599997
TEXT_ENABLE_LEN = 0x2A
TOKEN_ROW = 0xE8
DEX_ROW = 0x2F0
STATE = HEAP_BASE + 0x1000
TRACKER = HEAP_BASE + 0x3000
OUT = HEAP_BASE + 0x100
INPUT = HEAP_BASE + 0x400
USER = HEAP_BASE + 0x900
BUMP = HEAP_BASE + 0x3800
CAPACITY = 11
ALIGNED = dict(leaf=0x278, inner=0x2D8, keys=0x218, length=0x272, slot=0x270, parent=0x210, values=0, stride=0x30, edges=0x278)
STATUS = dict(leaf=0x70, inner=0xD0, keys=8, length=0x62, slot=0x60, parent=0, values=0x64, stride=1, edges=0x70)
SET = dict(leaf=0x68, inner=0xC8, keys=8, length=0x62, slot=0x60, parent=0, values=0x60, stride=0, edges=0x68)
WRITER_FRAME = 0x30 + 0xF8


def word(data, at):
    return struct.unpack_from("<Q", data, at)[0]


def address(index):
    return bytes((index * 7 + at * 11 + 1) & 0xFF for at in range(20))


# ---- specification ----

def group_of(case, target):
    """Aligned tokens with the same deployer as `target`, in key order."""
    deployer = case["tokens"][target]
    return [token for token in sorted(case["aligned"]) if case["tokens"][token] is not None and case["tokens"][token] == deployer]


def writer_spec(case):
    """Status tag, text or gate payload, stub calls in order, aligned map after, dex byte per row after."""
    token, enable, force = case["token"], case["enable"], case["force"]
    aligned = dict(case["aligned"])
    dex = [(row[0], row[1]) for row in case["dex"]]
    if token >= len(case["tokens"]):
        return dict(panic="index")
    if case["tokens"][token] is None:
        return dict(tag=BAD_QUOTE, calls=[], aligned=aligned, dex=dex, text=None)
    calls = ["drop"]
    done = lambda tag, text=None: dict(tag=tag, calls=calls, aligned=aligned, dex=dex, text=text)
    status = case["status"].get(token)
    if enable:
        if status != 0:
            return done(BAD_QUOTE)
        group = group_of(case, token)
        known = token in group
        rest = [item for item in group if item != token]
        calls += ["collect", "remove"]
        if rest:
            calls.append("iter")
            return done(DUPLICATE)
        calls.append("gate:%d" % (4 if known else 2))
        if case["gate"] != OK:
            calls.append("iter")
            return done(case["gate"], "gate")
        if known:
            calls.append("dropval")
            if not force and not aligned[token]:
                calls.append("iter")
                return done(TEXT_STATUS, (TEXT_ENABLE, TEXT_ENABLE_LEN))
        else:
            calls.append("insert")
        aligned[token] = 1
        calls.append("dropset")
    else:
        if not force and status is not None and status != 1:
            return done(TEXT_STATUS, (TEXT_DISABLE, TEXT_DISABLE_LEN))
        if token in aligned:
            aligned[token] = 0
    dex = [(row, bytes([enable]) + byte[1:] if row == token else byte) for row, byte in dex]
    return done(OK)


def to_i64(value):
    if value != value or value in (float("inf"), float("-inf")):
        return 0
    if value >= 9.223372036854775807e18:
        return (1 << 63) - 1
    if value <= -9.223372036854775808e18:
        return -(1 << 63)
    return int(value)


def class_rate(rate, second, klass, weight, cross, aligned, scales, discount):
    if klass == 0:
        value = rate
    elif (klass == 1) if second else (klass != 2):
        value = rate / 5.0
    else:
        value = max(rate, 0.0) * weight
    plain = scales[0] if aligned & int(cross) else 1.0
    negative = scales[1] if aligned and not cross else plain
    value *= negative if value < 0.0 else plain
    if value > 0.0:
        value *= 1.0 - discount
    return value


def fee_spec(fee, klass, weight, cross, aligned, leg, notional, scales):
    """The words of 0x3742460 this packet depends on: gross, rebate, extra. Referrer and builder arms stay out of the fixture."""
    pick = 0 if cross else 1
    first = fee["first"][pick]
    second = fee["second"][pick] if fee["two"] else None
    high = None
    if fee["two"]:
        high = class_rate(second, True, klass, weight, cross, aligned, scales, fee["discount"])
    if fee["two"] and not leg:
        used = high
    else:
        used = class_rate(first, False, klass, weight, cross, aligned, scales, fee["discount"])
    if notional >> 63:
        return dict(panic="unwrap")
    amount = float(notional)
    paid = to_i64(used * amount)
    gross = max(paid, 0)
    rebate = -paid if paid <= 0 else 0
    if not leg:
        return dict(gross=gross, rebate=rebate, extra=0, leg=0)
    extra = max(to_i64(max(high - used, 0.0) * amount), 0) if fee["two"] else 0
    return dict(gross=gross + extra, rebate=rebate, extra=extra, leg=1)


def class_of(case, base):
    if base in case["quotes"]:
        return 1
    return 2 if case["outcome"] else 0


def wrapper_spec(case):
    if case["spot"] >= len(case["pairs"]):
        return dict(panic="bound")
    base, quote = case["pairs"][case["spot"]]
    klass = class_of(case, base)
    byte = case["aligned"].get(quote, 0)
    return dict(klass=klass, leg=case["leg"], byte=byte, predicate=None if base in case["quotes"] else base,
                fee=fee_spec(case["fee"], klass, case["weight"], case["cross"], byte, case["leg"], case["notional"], case["scales"]))


def mint_spec(case):
    if case["unit"] == 0:
        return dict(error=case["unit_error"])
    row = case["outcomes"].get(case["token"]) if case["outcomes"] else None
    if row is None or case.get("count") == 0:
        return dict(error=4)
    size = case["limit"]
    if case["clip"] & 1:
        size = min(size, case["amount"] // case["unit"])
    if size == 0:
        return dict(empty=True)
    notional = size * case["unit"]
    if notional >> 64:
        return dict(error=0xE)
    byte = case["aligned"].get(case["quote"], 0)
    return dict(size=size, notional=notional, byte=byte, words=row,
                fee=fee_spec(case["fee"], 2, case["weight"], True, byte, 0, notional, case["scales"]))


def burn_spec(case):
    if case["amount"] == 0:
        return dict(empty=True, free=case["cap"])
    row = case["outcomes"].get(case["token"]) if case["outcomes"] else None
    if row is None or case.get("count") == 0:
        return dict(error=4, free=case["cap"])
    if case["left"] is not None:
        return dict(error=case["left"], free=case["cap"])
    if case["right"] is not None:
        return dict(error=case["right"], free=case["cap"])
    if case["quote_left"] != case["quote_right"]:
        return dict(error=0xF, free=case["cap"])
    notional = case["amount"] * row
    if notional >> 64:
        return dict(error=0xE, free=case["cap"], rows=len(case["items"]))
    byte = case["aligned"].get(case["quote_left"], 0)
    return dict(notional=notional, byte=byte, free=case["cap"], fee=fee_spec(case["fee"], 2, case["weight"], True, byte, 0, notional, case["scales"]))


def site_spec(case):
    base, quote = case["pairs"][case["spot"]]
    return dict(klass=class_of(case, base), byte=case["aligned"].get(quote, 0), predicate=None if base in case["quotes"] else base)


# ---- trees ----

def tree_height(count):
    level, room = 0, CAPACITY
    while room < count:
        level += 1
        room = room * (CAPACITY + 1) + CAPACITY
    return level


def build_tree(memory, bump, shape, items, put, stale=()):
    """B-tree over sorted (key, value) items; returns the root and its height."""
    if not items:
        return 0, 0

    def make(rows, level, parent, slot):
        node = bump(shape["inner"] if level else shape["leaf"])
        memory.write(node + shape["parent"], 8, parent)
        memory.write(node + shape["slot"], 2, slot)
        room = CAPACITY
        for _ in range(level - 1):
            room = room * (CAPACITY + 1) + CAPACITY
        if level == 0:
            entries, children = rows, []
        else:
            parts = 2
            while (len(rows) - (parts - 1)) > parts * room:
                parts += 1
            size = (len(rows) - (parts - 1)) // parts
            extra = (len(rows) - (parts - 1)) - size * parts
            at, entries, children = 0, [], []
            for index in range(parts):
                take = size + (1 if index < extra else 0)
                children.append(rows[at:at + take])
                at += take
                if index + 1 < parts:
                    entries.append(rows[at])
                    at += 1
        memory.write(node + shape["length"], 2, len(entries))
        for index, (key, value) in enumerate(entries):
            memory.write(node + shape["keys"] + 8 * index, 8, key)
            put(node + shape["values"] + shape["stride"] * index, value)
        for index in range(len(entries), CAPACITY):
            if stale:
                memory.write(node + shape["keys"] + 8 * index, 8, stale[index % len(stale)])
        for index, part in enumerate(children):
            memory.write(node + shape["edges"] + 8 * index, 8, make(part, level - 1, node, index))
        return node

    height = tree_height(len(items))
    return make(items, height, 0, 0), height


def tree_items(memory, shape, node, height):
    if not node:
        return []
    found = []
    count = memory.read(node + shape["length"], 2)
    for index in range(count + 1):
        if height:
            found += tree_items(memory, shape, memory.read(node + shape["edges"] + 8 * index, 8), height - 1)
        if index < count:
            found.append((memory.read(node + shape["keys"] + 8 * index, 8), node + shape["values"] + shape["stride"] * index))
    return found


def insertion_point(memory, shape, node, height, key):
    """Leaf and index where a missing key goes."""
    while True:
        count = memory.read(node + shape["length"], 2)
        index = 0
        while index < count and memory.read(node + shape["keys"] + 8 * index, 8) < key:
            index += 1
        if height == 0:
            return node, index
        node = memory.read(node + shape["edges"] + 8 * index, 8)
        height -= 1


# ---- evaluator harness ----

class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        machine.memory.reset()
        self.fee_real = frozenset({FEE})
        self.chain = frozenset({FILTER, TREE_NEXT, SET_BUILD, SET_PUSH, VEC_GROW, VEC_GROW_INNER})
        machine.real = self.chain | self.fee_real
        for layout in WRITERS:
            machine.real |= {layout["entry"]}
        machine.real |= {WRAPPER, MINT, BURN, STATS, LOOP}
        machine.jump_ranges = [image.exact_fde(start) for start in machine.real | {COLLECT}]
        self.writer_stubs = {}
        for layout in WRITERS:
            base = image.offset(layout["entry"])
            for at, name in WRITER_CALLS.items():
                if image.blob[base + at] != 0xE8:
                    raise EvidenceError("not a call at %#x" % (layout["entry"] + at))
                target = layout["entry"] + at + 5 + struct.unpack_from("<i", image.blob, base + at + 1)[0]
                self.writer_stubs[(layout["name"], name)] = target
        machine.calls = {HASH: self.on_hash, OUTCOME_UNIT: self.on_unit, OUTCOME_LEGS: self.on_legs}
        hooks = {PREDICATE: self.on_predicate, RATES: self.on_rates, DISCOUNT: self.on_discount, PANIC_BOUND: self.on_panic("bound"), PANIC_NONE: self.on_panic("none"),
                 PANIC_INDEX: self.on_panic("index"), UNWRAP: self.on_panic("unwrap")}
        tokens = {}
        for at, (target, hook) in enumerate(hooks.items()):
            token = 0x7000000 + at * 16
            tokens[target] = token
            machine.slots[token] = hook
        for slot, target in relative_slots(image).items():
            if target in tokens:
                machine.memory.statics[slot] = tokens[target]
            elif target in machine.real:
                machine.memory.statics[slot] = target
        table = ((SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_MEMCPY, self.on_memcpy), (SLOT_MEMMOVE, self.on_memcpy), (SLOT_PANIC_INDEX, self.on_panic("index")),
                 (SLOT_FAIL, self.on_panic("alloc")), (SLOT_LAYOUT, self.on_panic("layout")), (SLOT_REALLOC, self.on_realloc))
        for at, (slot, hook) in enumerate(table):
            token = 0x7100000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        self.case = None
        self.at = BUMP
        self.calls, self.frees = [], []
        self.set = []
        self.inserted = {}
        self.seen_record = None
        self.predicates = []
        self.sizes = {}
        self.allocs = []
        machine.watch[FEE] = self.on_fee_entry

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

    def check(self, condition, text):
        if not condition:
            raise Halt(text)

    def on_alloc(self, machine):
        self.check(machine.regs[RDI] < 0x10000, "alloc size")
        machine.regs[RAX] = self.bump(machine.regs[RDI])
        self.sizes[machine.regs[RAX]] = machine.regs[RDI]
        self.allocs.append(machine.regs[RDI])

    def on_realloc(self, machine):
        regs = machine.regs
        self.check(regs[RSI] < 0x10000 and regs[RDI] in self.sizes, "realloc args")
        block = self.bump(regs[RSI])
        machine.memory.copy(block, regs[RDI], min(self.sizes[regs[RDI]], regs[RSI]))
        self.sizes[block] = regs[RSI]
        regs[RAX] = block

    def on_free(self, machine):
        self.frees.append(machine.regs[RSI])

    def on_memcpy(self, machine):
        regs = machine.regs
        if regs[RDX]:
            self.check(regs[RDX] < 0x10000, "copy size")
            machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_panic(self, name):
        def panic(machine):
            raise Panicked(name)
        return panic

    def on_hash(self, machine):
        regs = machine.regs
        self.check(regs[RDI] == STATE + 0x10 + 0xF0, "hash hasher")
        regs[RAX] = table_hash(machine.memory.read(regs[RSI], 8))

    def on_unit(self, machine):
        regs, case, memory = machine.regs, self.case, machine.memory
        self.check(regs[RCX] == STATE + 0x10 and regs[R8] == STATE and regs[RDX] == case["token"], "unit args")
        self.check(memory.bytes_at(regs[RSI], 20) == address(9), "unit user")
        memory.write(regs[RDI], 8, case["unit"])
        if case["unit"]:
            memory.write(regs[RDI] + 8, 8, case["quote"])
            memory.write(regs[RDI] + 0x10, 8, case["limit"])
        else:
            memory.write(regs[RDI] + 8, 1, case["unit_error"])

    def on_legs(self, machine):
        regs, case, memory = machine.regs, self.case, machine.memory
        self.check(regs[RDX] == STATE + 0x10 and regs[RSI] == self.row_address, "legs args")
        out = regs[RDI]
        for at, error, quote in ((0, case["left"], case["quote_left"]), (0x10, case["right"], case["quote_right"])):
            memory.write(out + at, 1, 0 if error is None else 1)
            memory.write(out + at + 1, 1, 0 if error is None else error)
            memory.write(out + at + 8, 8, quote)

    def on_predicate(self, machine):
        regs = machine.regs
        self.check(regs[RDI] == STATE + 0x10, "predicate meta")
        self.predicates.append(regs[RSI])
        regs[RAX] = 1 if self.case["outcome"] else 0

    def on_rates(self, machine):
        regs, memory, fee = machine.regs, machine.memory, self.case["fee"]
        self.check(regs[RSI] == TRACKER and memory.bytes_at(regs[RDX], 20) == address(9), "rates args")
        out = regs[RDI]
        for at in range(0, 0x78, 8):
            memory.write(out + at, 8, 0)
        memory.write(out + 0x10, 8, to_bits(fee["first"][0]))
        memory.write(out + 0x18, 8, to_bits(fee["first"][1]))
        memory.write(out + 0x58, 8, to_bits(fee["second"][0]))
        memory.write(out + 0x60, 8, to_bits(fee["second"][1]))
        memory.write(out + 0x68, 4, fee["two"])

    def on_discount(self, machine):
        regs = machine.regs
        self.check(regs[RDI] == TRACKER and machine.memory.bytes_at(regs[RSI], 20) == address(9), "discount args")
        machine.xmm[0] = to_bits(self.case["fee"]["discount"])
        machine.keep_float = True

    # writer stubs

    def frame(self):
        return STACK_TOP - 0x108 - WRITER_FRAME

    def on_drop(self, machine):
        self.check(machine.regs[RDI] == self.frame() and machine.memory.read(machine.regs[RDI], 2) == BAD_QUOTE, "drop args")
        self.calls.append("drop")

    def on_collect(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        base = self.frame()
        self.check(regs[RDI] == base + 0x98 and regs[RSI] == base, "collect frame")
        has = 1 if self.aligned_root else 0
        wanted = (has, 0, self.aligned_root, self.aligned_height, has, 0, self.aligned_root, self.aligned_height, len(case["aligned"]), STATE + 0x90)
        got = tuple(memory.read(base + 8 * index, 8) for index in range(10))
        self.check(got == wanted, "collect iterator")
        self.check(memory.bytes_at(base + 0x50, 20) == case["tokens"][case["token"]], "collect deployer")
        self.set = group_of(case, case["token"])
        memory.write(regs[RDI], 8, base - 0x1000 if self.set else 0)
        memory.write(regs[RDI] + 8, 8, 7)
        memory.write(regs[RDI] + 0x10, 8, len(self.set))
        self.calls.append("collect")

    def on_remove(self, machine):
        regs, memory = machine.regs, machine.memory
        base = self.frame()
        self.check(regs[RDI] == base + 0x98 and regs[RSI] == base + 0xD0 and memory.read(regs[RSI], 8) == self.case["token"], "remove args")
        found = self.case["token"] in self.set
        if found:
            self.set.remove(self.case["token"])
        memory.write(regs[RDI] + 0x10, 8, len(self.set))
        regs[RAX] = int(found) | 0xABCD00
        self.calls.append("remove")

    def on_gate(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        base = self.frame()
        self.check(regs[RDI] == base and regs[RSI] == STATE and regs[RDX] == base + 0xB0, "gate args")
        self.check(memory.bytes_at(regs[RDX], 20) == case["tokens"][case["token"]], "gate deployer")
        memory.put_bytes(regs[RDI], bytes((at * 5 + 3) & 0xFF for at in range(0x60)))
        memory.write(regs[RDI], 2, case["gate"])
        self.calls.append("gate:%d" % (regs[RCX] & 0xFF))

    def on_iter(self, machine):
        regs, memory = machine.regs, machine.memory
        base = self.frame()
        self.check(regs[RDI] == base + 0x70 and regs[RSI] == base, "iter args")
        root = memory.read(base + 0x98, 8)
        got = tuple(memory.read(base + 8 * index, 8) for index in range(9))
        if root:
            self.check(got == (1, 0, root, 7, 1, 0, root, 7, len(self.set)), "iter frame")
        else:
            self.check((got[0], got[4], got[8]) == (0, 0, 0), "iter empty frame")
        memory.write(regs[RDI], 8, 0)
        self.calls.append("iter")

    def on_insert(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        base = self.frame()
        self.check(regs[RDI] == base + 0xD8 and regs[RSI] == base + 0x70 and regs[RDX] == base, "insert args")
        entry = tuple(memory.read(regs[RSI] + 8 * index, 8) for index in range(5))
        if self.aligned_root:
            node, index = insertion_point(memory, ALIGNED, self.aligned_root, self.aligned_height, case["token"])
            wanted = (STATE + 0x2B0, case["token"], node, 0, index)
        else:
            wanted = (STATE + 0x2B0, case["token"], 0)
            entry = entry[:3]
        self.check(entry == wanted, "insert entry")
        value = memory.bytes_at(base, 0x30)
        expected = struct.pack("<QI", case["time"][0], case["time"][1]) + b"\x01"
        self.check(value[:0x10] == bytes(0x10) and value[0x18:0x20] == bytes(8) and value[0x20:0x2D] == expected, "insert value")
        block = self.bump(0x2D0)
        memory.put_bytes(block + 0x30, value)
        memory.write(regs[RDI], 8, block)
        memory.write(regs[RDI] + 8, 8, 0)
        memory.write(regs[RDI] + 0x10, 8, 1)
        self.inserted[case["token"]] = block + 0x30
        self.calls.append("insert")

    def on_dropval(self, machine):
        self.check(machine.regs[RDI] == self.frame() + 8, "dropval args")
        self.calls.append("dropval")

    def on_dropset(self, machine):
        self.check(machine.regs[RDI] == self.frame() + 0x98, "dropset args")
        self.calls.append("dropset")

    def on_fee_entry(self, machine):
        self.seen_record = (machine.regs[RSI], machine.memory.bytes_at(machine.regs[RDX], 0x57))

    def on_fee_stop(self, machine):
        self.on_fee_entry(machine)
        raise Finished()

    # layout

    def start(self, case):
        memory = self.machine.memory
        memory.reset(self.at - HEAP_BASE if self.at > BUMP else 0x4000)
        self.at = BUMP
        self.case = case
        self.calls, self.frees, self.predicates, self.allocs = [], [], [], []
        self.inserted, self.set = {}, []
        self.seen_record = None
        self.machine.frame = 0

    def lay_tracker(self, case):
        memory = self.machine.memory
        for at, value in ((0x90, case["scales"][0]), (0x98, case["scales"][1])):
            memory.write(TRACKER + at, 8, to_bits(value))
        memory.write(TRACKER + 0x40, 8, 0)
        memory.write(TRACKER + 0xD8, 8, 0)

    def stale_keys(self, case):
        if "pairs" in case:
            return tuple(key for pair in case["pairs"] for key in pair)
        if "quote" in case:
            return (case["quote"],)
        if "quote_left" in case:
            return (case["quote_left"],)
        return (case["token"],) if "token" in case else ()

    def lay_trees(self, case, offset_aligned, offset_quotes=None):
        memory = self.machine.memory
        items = sorted(case["aligned"].items())
        self.aligned_items = items

        def put_value(where, byte):
            memory.put_bytes(where, bytes((at * 3 + 1) & 0xFF for at in range(0x2C)) + bytes([byte]))
        root, height = build_tree(memory, self.bump, ALIGNED, [(key, value) for key, value in items], put_value, self.stale_keys(case))
        memory.write(STATE + offset_aligned, 8, root)
        memory.write(STATE + offset_aligned + 8, 8, height)
        memory.write(STATE + offset_aligned + 0x10, 8, len(items))
        self.aligned_root, self.aligned_height = root, height
        if offset_quotes is not None:
            quotes = sorted((case["quotes"].items() if isinstance(case["quotes"], dict) else ((key, 0) for key in case["quotes"])))
            root, height = build_tree(memory, self.bump, STATUS, quotes, lambda where, byte: memory.write(where, 1, byte), self.stale_keys(case))
            memory.write(STATE + offset_quotes, 8, root)
            memory.write(STATE + offset_quotes + 8, 8, height)
            memory.write(STATE + offset_quotes + 0x10, 8, len(quotes))

    def lay_writer(self, case):
        memory = self.machine.memory
        layout = case["layout"]
        for name, target in ((key[1], value) for key, value in self.writer_stubs.items() if key[0] == layout["name"]):
            self.machine.calls[target] = getattr(self, "on_" + name)
        rows = self.bump(TOKEN_ROW * max(1, len(case["tokens"])))
        memory.write(STATE + 0x210, 8, rows)
        memory.write(STATE + 0x218, 8, len(case["tokens"]))
        for index, deployer in enumerate(case["tokens"]):
            base = rows + index * TOKEN_ROW
            memory.write(base + 0xD2, 1, 2 if deployer is None else 3)
            memory.put_bytes(base + 0xD3, deployer or bytes(20))
        self.lay_trees(case, 0x2B0)
        status = sorted(case["status"].items())
        root, height = build_tree(memory, self.bump, STATUS, status, lambda where, byte: memory.write(where, 1, byte), self.stale_keys(case))
        memory.write(STATE + 0x2E0, 8, root)
        memory.write(STATE + 0x2E8, 8, height)
        memory.write(STATE + 0x60, 8, case["time"][0])
        memory.write(STATE + 0x68, 4, case["time"][1])
        dex = self.bump(DEX_ROW * max(1, len(case["dex"])))
        memory.write(STATE + layout["dex_list"], 8, dex)
        memory.write(STATE + layout["dex_len"], 8, len(case["dex"]))
        self.dex = dex
        for index, (token, byte) in enumerate(case["dex"]):
            memory.write(dex + index * DEX_ROW + 0x50, 8, token)
            memory.put_bytes(dex + index * DEX_ROW + 0x58, byte)

    def run_writer(self, case):
        self.start(case)
        self.lay_writer(case)
        self.machine.run(case["layout"]["entry"], {RDI: OUT, RSI: STATE, RDX: case["token"], RCX: case["enable"] | 0xAB00, R8: case["force"] | 0xCD00})
        memory = self.machine.memory
        tag = memory.read(OUT, 2)
        aligned = {}
        for key, where in tree_items(memory, ALIGNED, self.aligned_root, self.aligned_height):
            aligned[key] = memory.read(where + 0x2C, 1)
            self.check(memory.bytes_at(where, 0x2C) == bytes((at * 3 + 1) & 0xFF for at in range(0x2C)), "value bytes moved")
        for key, where in self.inserted.items():
            aligned[key] = memory.read(where + 0x2C, 1)
        dex = [(memory.read(self.dex + index * DEX_ROW + 0x50, 8), memory.bytes_at(self.dex + index * DEX_ROW + 0x58, len(case["dex"][index][1]))) for index in range(len(case["dex"]))]
        for where in self.inserted.values():
            self.check(memory.read(where + 0x30 + 0x2C, 1) == STACK_MARK, "write past the new value")
        text = b""
        if tag == TEXT_STATUS:
            text = memory.bytes_at(memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8))
        return dict(tag=tag, out=memory.bytes_at(OUT, 0x60), calls=self.calls, aligned=aligned, dex=dex, text=text)

    def run_collect(self, case):
        self.start(case)
        memory = self.machine.memory
        rows = self.bump(TOKEN_ROW * max(1, len(case["tokens"])))
        memory.write(STATE + 0x180 + 0x90, 8, rows)
        memory.write(STATE + 0x188 + 0x90, 8, len(case["tokens"]))
        for index, deployer in enumerate(case["tokens"]):
            base = rows + index * TOKEN_ROW
            memory.write(base + 0xD2, 1, 2 if deployer is None else 3)
            memory.put_bytes(base + 0xD3, deployer or bytes(20))
            memory.write(base + 0xE7, 1, 0)
        self.lay_trees(case, 0x2B0)
        has = 1 if self.aligned_root else 0
        words = (has, 0, self.aligned_root, self.aligned_height, has, 0, self.aligned_root, self.aligned_height, len(case["aligned"]), STATE + 0x90)
        for index, value in enumerate(words):
            memory.write(INPUT + 8 * index, 8, value)
        memory.put_bytes(INPUT + 0x50, case["deployer"])
        self.machine.run(COLLECT, {RDI: OUT, RSI: INPUT})
        root, height, count = memory.read(OUT, 8), memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8)
        return dict(items=[key for key, _ in tree_items(memory, SET, root, height)], count=count, parent=memory.read(root, 8) if root else 0, frees=list(self.frees))

    def lay_meta(self, case):
        memory = self.machine.memory
        pairs = self.bump(0x20 * max(1, len(case["pairs"])))
        memory.write(STATE + 0x178, 8, pairs)
        memory.write(STATE + 0x180, 8, len(case["pairs"]))
        for index, (base, quote) in enumerate(case["pairs"]):
            memory.write(pairs + index * 0x20, 8, base)
            memory.write(pairs + index * 0x20 + 8, 8, quote)
        memory.write(STATE + 0x150, 8, to_bits(case["weight"]))
        self.lay_trees(case, 0x230, 0x260)
        self.lay_tracker(case)

    def fee_input(self, base):
        """The first 0x28 bytes of the fee record: no builder, a position-dependent word and address."""
        memory = self.machine.memory
        memory.write(base, 8, 0)
        memory.write(base + 8, 8, 0x1122334455667788)
        memory.put_bytes(base + 0x10, address(5))
        memory.write(base + 0x24, 4, 0x99AABBCC)

    def run_wrapper(self, case):
        self.start(case)
        self.lay_meta(case)
        memory = self.machine.memory
        self.fee_input(INPUT)
        memory.write(INPUT + 0x28, 8, TRACKER)
        memory.write(INPUT + 0x30, 8, case["spot"])
        memory.put_bytes(USER, address(9))
        memory.put_bytes(INPUT + 0x38, address(9))
        memory.write(INPUT + 0x4C, 1, int(case["cross"]))
        memory.write(INPUT + 0x4D, 1, case["leg"])
        memory.write(INPUT + 0x4E, 1, case["flag"])
        self.machine.run(WRAPPER, {RDI: OUT, RSI: STATE, RDX: INPUT, RCX: case["notional"]})
        return fee_words(memory, OUT)

    def lay_outcomes(self, case, shape):
        """Hash table at meta +0xd0: 16 buckets of 0x90 bytes before the control bytes, one decoy, the key at its probe slot."""
        memory = self.machine.memory
        mask = 15
        size = 16 * 0x90
        block = self.bump(size + 32)
        ctrl = block + size
        memory.put_bytes(ctrl, b"\xff" * 32)
        meta = STATE + 0x10
        memory.write(meta + 0xD0, 8, ctrl)
        memory.write(meta + 0xD8, 8, mask)
        keys = dict(case["outcomes"] or {})
        memory.write(meta + 0xE8, 8, case.get("count", 0 if case["outcomes"] is None else case.get("crowd", 1) + len(keys)))
        memory.write(meta + 0x140, 8, to_bits(case["weight"]))
        self.row_address = 0

        def place(key, words):
            value = table_hash(key)
            index = value & mask
            while memory.read(ctrl + index, 1) != 0xFF:
                index = (index + 1) & mask
            for spot in (index, 16 + index) if index < 16 else (index,):
                memory.write(ctrl + spot, 1, value >> 57)
            end = ctrl - index * 0x90
            memory.write(end - 0x90, 8, key)
            memory.write(end - 0x68, 8, words[0])
            memory.write(end - 0x40, 8, words[1])
            memory.write(end - 8, 8, words[2])
            return end
        for at in range(case.get("crowd", 1)):
            place(case["token"] ^ (0x40 + at * 0x80), (1, 2, 3))
        for key, words in keys.items():
            self.row_address = place(key, shape(words)) - 0x88

    def run_mint(self, case):
        self.start(case)
        memory = self.machine.memory
        self.lay_trees(case, 0x230)
        self.lay_tracker(case)
        self.lay_outcomes(case, lambda value: (value[0], value[1], 0))
        memory.put_bytes(USER, address(9))
        top = STACK_TOP - 0x108
        memory.write(top + 8, 8, case["amount"])
        memory.write(top + 0x10, 8, STATE)
        memory.write(top + 0x18, 8, TRACKER)
        self.machine.run(MINT, {RDI: OUT, RSI: STATE + 0x10, RDX: case["side"] | 0x5500, RCX: USER, R8: case["token"], R9: case["clip"]})
        return out_view(memory, self)

    def run_burn(self, case):
        self.start(case)
        memory = self.machine.memory
        self.lay_trees(case, 0x230)
        self.lay_tracker(case)
        self.lay_outcomes(case, lambda value: (0, 0, value))
        memory.put_bytes(USER, address(9))
        items = self.bump(max(1, len(case["items"])) * 0x10)
        for index, pair in enumerate(case["items"]):
            memory.write(items + index * 0x10, 8, pair[0])
            memory.write(items + index * 0x10 + 8, 8, pair[1])
        for at, value in ((0, case["cap"]), (8, items), (0x10, len(case["items"])), (0x18, case["token"]), (0x20, case["amount"])):
            memory.write(INPUT + at, 8, value)
        memory.write(STACK_TOP - 0x108 + 8, 8, TRACKER)
        self.machine.run(BURN, {RDI: OUT, RSI: STATE + 0x10, RDX: case["side"] | 0x5500, RCX: USER, R8: INPUT, R9: STATE})
        return out_view(memory, self)

    def run_stats(self, case):
        self.start(case)
        self.lay_meta(case)
        memory = self.machine.memory
        self.fee_input(INPUT + 0x120)
        memory.put_bytes(INPUT + 0x1C8, address(9))
        memory.write(INPUT + 0x1F0, 8, case["spot"])
        memory.write(INPUT + 0x1F8, 8, 5)
        memory.write(INPUT + 0x208, 8, case["notional"])
        memory.write(INPUT + 0x224, 1, case["taker"])
        self.machine.real -= self.fee_real
        self.machine.calls[FEE] = self.on_fee_stop
        try:
            self.machine.run(STATS, {RDI: STATE, RSI: case["flag"] | 0x7700, RDX: 1, RCX: INPUT, R8: TRACKER})
        except Finished:
            pass
        finally:
            self.machine.real |= self.fee_real
            del self.machine.calls[FEE]
        return self.seen_record

    def run_loop(self, case):
        self.start(case)
        self.lay_meta(case)
        memory = self.machine.memory
        machine = self.machine
        machine.frame = 0x6A8
        base = STACK_TOP - 0x108 - 0x6A8
        self.fee_input(INPUT + 0x28)
        pairs = memory.read(STATE + 0x178, 8)
        machine_args = {R15: STATE, RBX: memory.read(STATE + 0x260, 8), R14: case["pairs"][case["spot"]][0], R12: INPUT, R9: pairs, RBP: case["leg"]}
        memory.write(base + 0xF, 1, case["taker"])
        memory.write(base + 0x80, 8, case["spot"] * 0x20)
        memory.write(base + 0x88, 8, STATE + 0x10)
        memory.put_bytes(base + 0x60, address(9))
        memory.write(base + 0x220, 8, case["notional"])
        memory.write(base + 0x1DC, 4, case["flag"] | 0x7700)
        memory.write(base + 0x228, 8, TRACKER)
        self.machine.real -= self.fee_real
        self.machine.calls[FEE] = self.on_fee_stop
        try:
            self.machine.run(LOOP_START, machine_args)
        except Finished:
            pass
        finally:
            self.machine.real |= self.fee_real
            del self.machine.calls[FEE]
        return self.seen_record


def table_hash(key):
    value = (key * 0x9E3779B97F4A7C15 + 0x123456789) & MASK[8]
    return value ^ (value >> 29)


def fee_words(memory, base):
    return dict(gross=memory.read(base + 0x50, 8), rebate=memory.read(base + 0x58, 8), extra=memory.read(base + 0x60, 8), tag=memory.read(base, 1), builder=memory.read(base + 0x28, 1))


def out_view(memory, harness):
    return dict(first=memory.read(OUT, 1), word=memory.read(OUT, 8), tag=memory.read(OUT + 8, 8), memory=memory, frees=list(harness.frees), allocs=list(harness.allocs))


# ---- cases ----

SCALES = (0.8, 1.5)
TIME = (0x1122334455667788, 0x33445566)
OWNER_A, OWNER_B = address(1), address(2)
TOKENS = (None, OWNER_A, OWNER_A, OWNER_B, OWNER_B, None) + (None,) * 200


def join(left, right):
    return {**left, **right}


def wide(count, step=1, first=6):
    return {first + at * step: at & 1 for at in range(count)}


def writer_cases():
    rows = []
    aligned_shapes = (
        ("none", {}), ("self on", {1: 1}), ("self off", {1: 0}), ("peer on", {2: 1}), ("peer off", {2: 0}), ("self and peer", {1: 1, 2: 1}), ("other owner", {3: 1}), ("self on other", {1: 1, 3: 0}),
        ("wide", join(wide(30), {1: 1})), ("wide off", join(wide(30), {1: 0})), ("wide miss", wide(30)), ("deep", join(wide(160), {1: 0})), ("deep miss", wide(160)), ("high key", join(wide(9), {190: 1})),
    )
    status_shapes = (("none", {}), ("active", {1: 0}), ("disabled", {1: 1}), ("third", {1: 2}), ("wide active", join({key: 1 for key in range(3, 40)}, {1: 0})), ("wide disabled", join({key: 0 for key in range(3, 40)}, {1: 1})),
                     ("wide miss", {key: 0 for key in range(3, 40)}), ("deep", join({key: 1 for key in range(3, 200)}, {1: 0})), ("deep miss", {key: 0 for key in range(3, 200)}), ("deep off", join({key: 0 for key in range(3, 200)}, {1: 1})))
    for layout in WRITERS:
        for name_a, aligned in aligned_shapes:
            for name_s, status in status_shapes:
                for enable in (0, 1):
                    for force in (0, 1):
                        for count in ((0, 1, 2, 3, 4, 5, 9) if name_s == "active" and name_a == "none" or name_s == "disabled" and name_a == "self on" else (6,)):
                            dex = [((1 if at % 2 == 0 else 2 + at), bytes([0x70 + at])) for at in range(count)]
                            rows.append(dict(kind="writer", layout=layout, token=1, enable=enable, force=force, tokens=TOKENS, status=status, aligned=aligned, dex=dex, gate=OK, time=TIME,
                                             label="%s/%s/%s/e%d/f%d/d%d" % (layout["name"], name_a, name_s, enable, force, count)))
        for gate in (0x55, 0x12E):
            for aligned in ({}, {1: 1}, {3: 1}):
                rows.append(dict(kind="writer", layout=layout, token=1, enable=1, force=0, tokens=TOKENS, status={1: 0}, aligned=aligned, dex=[(1, b"\x07")], gate=gate, time=TIME, label="%s/gate %#x" % (layout["name"], gate)))
        for token in (0, 5, 206, 300):
            rows.append(dict(kind="writer", layout=layout, token=token, enable=1, force=1, tokens=TOKENS, status={0: 0, 5: 0}, aligned={}, dex=[], gate=OK, time=TIME, label="%s/token %d" % (layout["name"], token)))
        for token in (24, 34, 38, 42):
            middle = {key: 1 for key in range(33, 44)}
            pairs = ({key: 0 for key in range(33, 44)}, {key: 1 for key in range(20, 31)}, {key: 0 for key in range(20, 31)})
            status = {key: 0 for key in range(20, 44)}
            off = {key: 1 for key in range(20, 44)}
            word_rows = [(9, struct.pack("<Q", 7)), (8, struct.pack("<Q", token)), (9, struct.pack("<Q", token)), (6, struct.pack("<Q", token)), (token, struct.pack("<Q", 0x70)), (9, struct.pack("<Q", token)), (9, struct.pack("<Q", token)), (9, struct.pack("<Q", token))]
            filled = struct.pack("<Q", token)
            other_rows = [(9, filled), (token, filled), (token, filled), (8, filled), (9, filled), (token, filled), (7, filled), (8, filled)]
            shapes = (middle,) + pairs + ({key: key & 1 for key in range(33, 44)}, {key: 1 for key in range(33, 43)}, {key: 0 for key in range(33, 43)}, {20: 1, 21: 1, 22: 1})
            for number, aligned in enumerate(shapes):
                for enable in (0, 1):
                    for force in (0, 1):
                        for table in (status, off):
                            rows.append(dict(kind="writer", layout=layout, token=token, enable=enable, force=force, tokens=(None,) * 20 + tuple(address(at + 3) for at in range(30)), status=table, aligned=aligned, dex=word_rows if number & 1 else other_rows, gate=OK, time=TIME,
                                             label="%s/inner %d %d %d %d %d" % (layout["name"], token, number, enable, force, table is off)))
        rows.append(dict(kind="writer", layout=layout, token=2, enable=1, force=0, tokens=TOKENS, status={2: 0}, aligned={1: 1}, dex=[(2, b"\x00")], gate=OK, time=TIME, label="%s/peer holds" % layout["name"]))
        rows.append(dict(kind="writer", layout=layout, token=3, enable=1, force=1, tokens=TOKENS, status={3: 0}, aligned={1: 1, 4: 0}, dex=[(3, b"\x00")], gate=OK, time=TIME, label="%s/inactive peer counts" % layout["name"]))
    return rows


def collect_cases():
    rows = []
    many = tuple(address(1 + at % 3) if at % 7 else None for at in range(40))
    for count in (0, 1, 2, 3, 5, 8, 12, 16, 20):
        for owner in (1, 2):
            aligned = {at: at & 1 for at in range(0, count)}
            tokens = tuple(address(1 + at % 2) if at % 5 != 4 else None for at in range(max(count, 1)))
            rows.append(dict(kind="collect", tokens=tokens, aligned=aligned, deployer=address(owner), label="%d/%d" % (count, owner)))
    rows.append(dict(kind="collect", tokens=many, aligned={at: 1 for at in range(0, 40, 2)}, deployer=address(2), label="many"))
    rows.append(dict(kind="collect", tokens=many, aligned={at: 1 for at in range(1, 37, 3)}, deployer=address(1), label="many two"))
    near = tuple(address(1)[:at] + bytes([address(1)[at] ^ 1]) + address(1)[at + 1:] for at in range(20))
    rows.append(dict(kind="collect", tokens=near + (address(1),), aligned={at: 1 for at in range(21)}, deployer=address(1), label="one byte apart"))
    rows.append(dict(kind="collect", tokens=(address(1),), aligned={0: 1, 5: 1}, deployer=address(1), label="key past list"))
    rows.append(dict(kind="collect", tokens=(address(1),), aligned={5: 1}, deployer=address(1), label="only key past list"))
    rows.append(dict(kind="collect", tokens=(address(2), address(1)), aligned={0: 1, 1: 1, 7: 1}, deployer=address(1), label="key past list after a skip"))
    return rows


def fee_rows():
    return (dict(first=(7e-4, 2.5e-4), second=(9e-4, 4e-4), two=0, discount=0.0), dict(first=(7e-4, -3e-5), second=(9e-4, -2e-5), two=0, discount=0.1), dict(first=(7e-4, 2.5e-4), second=(9e-4, 4e-4), two=1, discount=0.2),
            dict(first=(5e-4, -1e-4), second=(3e-4, 2e-4), two=2, discount=0.0), dict(first=(-1e-4, -1e-4), second=(-2e-4, -3e-4), two=1, discount=0.05))


META = dict(pairs=((10, 0), (11, 0), (12, 20), (13, 30), (14, 40), (20, 0), (15, 77), (13, 20)), quotes={20: 0, 30: 1, 13: 2}, aligned={20: 1, 30: 0, 40: 2, 0: 0}, weight=0.25, scales=SCALES)
WIDE_META = dict(META, quotes=join({key: key & 1 for key in range(1000, 1040)}, {13: 0}), aligned=join({key: 1 for key in range(1000, 1040)}, {20: 1, 30: 0, 40: 2}))
FULL_META = dict(META, pairs=((2, 16), (6, 20), (10, 25), (11, 26), (12, 15), (0, 20), (1, 18)), quotes={key: key & 1 for key in range(1, 12)}, aligned={key: key & 1 for key in range(15, 26)})
EVEN_META = dict(META, pairs=((6, 20), (7, 21), (9, 23), (10, 24), (8, 22), (30, 19), (31, 15), (40, 30)), quotes={key: key & 1 for key in range(1, 11)}, aligned={key: key & 1 for key in range(15, 25)})
DEEP_META = dict(META, quotes=join({key: 0 for key in range(1000, 1180)}, {13: 0}), aligned=join({key: 1 for key in range(1000, 1180)}, {20: 1}))


def wrapper_cases():
    rows = []
    for meta_name, meta in (("plain", META), ("wide", WIDE_META), ("deep", DEEP_META), ("full", FULL_META), ("even", EVEN_META)):
        for spot in range(len(meta["pairs"])):
            for outcome in (False, True):
                for cross in (False, True):
                    for leg in (0, 1):
                        for index, fee in enumerate(fee_rows()):
                            rows.append(dict(meta, kind="wrapper", spot=spot, outcome=outcome, cross=cross, leg=leg, flag=index & 1, fee=fee, notional=10 ** 12 + spot, label="%s/%d/%d/%d/%d/%d" % (meta_name, spot, outcome, cross, leg, index)))
    rows.append(dict(META, kind="wrapper", spot=8, outcome=False, cross=True, leg=0, flag=0, fee=fee_rows()[0], notional=5, label="spot past list"))
    rows.append(dict(META, kind="wrapper", spot=2 ** 60, outcome=False, cross=True, leg=0, flag=0, fee=fee_rows()[0], notional=5, label="spot far past list"))
    rows.append(dict(META, kind="wrapper", spot=0, outcome=False, cross=True, leg=0, flag=0, fee=fee_rows()[0], notional=1 << 63, label="negative notional"))
    rows.append(dict(META, kind="wrapper", spot=2, outcome=False, cross=False, leg=0, flag=1, fee=fee_rows()[1], notional=(1 << 63) - 1, label="largest notional"))
    return rows


def mint_cases():
    rows = []
    base = dict(aligned=META["aligned"], weight=0.25, scales=SCALES, token=70, side=1, unit=5000, unit_error=0, quote=20, limit=1000, amount=7000000, clip=0, outcomes={70: (0x51, 0x52)}, fee=fee_rows()[0])
    rows.append(dict(base, label="plain"))
    for quote in (0, 20, 30, 40, 99):
        for side in (0, 1):
            for fee in fee_rows():
                rows.append(dict(base, quote=quote, side=side, fee=fee, label="q%d/s%d/%s" % (quote, side, fee["two"])))
    for quote in range(15, 26):
        rows.append(dict(base, quote=quote, aligned={key: key & 1 for key in range(15, 26)}, label="full q%d" % quote))
    for clip in (0, 1, 2, 3):
        for amount, unit, limit in (((1 << 32) + 7, 5, 1 << 40), ((1 << 33) + 7, (1 << 32) + 1, 1 << 40), (7000000, 5000, 1000), (7000000, 5000, 100), (4999, 5000, 9), (1 << 40, 5000, 1 << 34), (1 << 40, 1 << 35, 9), (5000, 5000, 1), (1 << 33, 3, 1 << 33)):
            rows.append(dict(base, clip=clip, amount=amount, unit=unit, limit=limit, label="clip %d/%d/%d/%d" % (clip, amount, unit, limit)))
    for limit, unit in ((0, 5), (1 << 63, 2), (1 << 32, 1 << 32), ((1 << 32) - 1, 1 << 32), (1 << 60, 1 << 4)):
        rows.append(dict(base, limit=limit, unit=unit, label="limit %d %d" % (limit, unit)))
    for error in (1, 7, 0xFE):
        rows.append(dict(base, unit=0, unit_error=error, label="unit error %d" % error))
    rows.append(dict(base, outcomes=None, label="no outcomes"))
    rows.append(dict(base, outcomes={}, label="miss"))
    rows.append(dict(base, crowd=9, label="crowd"))
    rows.append(dict(base, crowd=15, label="crowd full"))
    rows.append(dict(base, crowd=0, label="alone"))
    rows.append(dict(base, count=0, label="count word zero"))
    rows.append(dict(base, outcomes={}, crowd=14, label="crowd miss"))
    return rows


def burn_cases():
    rows = []
    base = dict(aligned=META["aligned"], weight=0.25, scales=SCALES, token=70, side=1, cap=4, items=((1, 2), (3, 4), (5, 6)), amount=1000, outcomes={70: 6000}, left=None, right=None, quote_left=20, quote_right=20, fee=fee_rows()[0])
    rows.append(dict(base, label="plain"))
    for quote in (0, 20, 30, 40, 99):
        for side in (0, 1):
            for fee in fee_rows():
                rows.append(dict(base, quote_left=quote, quote_right=quote, side=side, fee=fee, label="q%d/s%d/%s" % (quote, side, fee["two"])))
    for count in (0, 1, 2, 3, 4, 5):
        rows.append(dict(base, items=tuple((at * 2 + 1, at * 2 + 2) for at in range(count)), cap=count + 1, label="items %d" % count))
    rows.append(dict(base, cap=0, items=(), label="no capacity"))
    rows.append(dict(base, amount=0, label="zero amount"))
    rows.append(dict(base, amount=0, cap=0, items=(), label="zero amount no capacity"))
    rows.append(dict(base, outcomes=None, label="no outcomes"))
    rows.append(dict(base, outcomes={}, label="miss"))
    rows.append(dict(base, crowd=9, label="crowd"))
    rows.append(dict(base, crowd=15, label="crowd full"))
    rows.append(dict(base, outcomes={}, crowd=14, label="crowd miss"))
    rows.append(dict(base, left=9, label="left error"))
    rows.append(dict(base, right=8, label="right error"))
    rows.append(dict(base, left=9, right=8, label="both errors"))
    rows.append(dict(base, quote_right=30, label="quotes differ"))
    rows.append(dict(base, amount=1 << 60, outcomes={70: 1 << 8}, label="overflow"))
    rows.append(dict(base, amount=1 << 60, outcomes={70: 1 << 8}, items=((1, 2),), cap=1, label="overflow one row"))
    rows.append(dict(base, amount=1 << 60, outcomes={70: 1 << 8}, items=(), cap=1, label="overflow no rows"))
    rows.append(dict(base, crowd=0, label="alone"))
    rows.append(dict(base, count=0, label="count word zero"))
    for quote in range(15, 26):
        rows.append(dict(base, quote_left=quote, quote_right=quote, aligned={key: key & 1 for key in range(15, 26)}, label="full q%d" % quote))
    rows.append(dict(base, amount=1 << 60, outcomes={70: 15}, label="fits"))
    return rows


def site_cases(kind):
    rows = []
    for meta_name, meta in (("plain", META), ("wide", WIDE_META), ("deep", DEEP_META), ("full", FULL_META), ("even", EVEN_META)):
        for spot in range(len(meta["pairs"])):
            for outcome in (False, True):
                for taker in (0, 1):
                    for leg in (0, 1):
                        rows.append(dict(meta, kind=kind, spot=spot, outcome=outcome, taker=taker, leg=leg, flag=leg ^ taker, fee=fee_rows()[0], notional=(0x77 << 32) + spot,
                                         label="%s/%d/%d/%d/%d" % (meta_name, spot, outcome, taker, leg)))
    return rows


def all_cases():
    rows = writer_cases() + collect_cases() + wrapper_cases() + [dict(case, kind="mint") for case in mint_cases()] + [dict(case, kind="burn") for case in burn_cases()] + site_cases("stats") + site_cases("loop")
    rows.append(dict(META, kind="stats", spot=8, outcome=False, taker=1, leg=0, flag=0, fee=fee_rows()[0], notional=9, label="spot past list"))
    return rows


# ---- comparison ----

def record_bytes(first, weight, klass, leg, notional, cross, byte, flag):
    """Defined bytes of the 0x3742460 record: (offset, bytes) pairs."""
    return ((0, first), (0x28, struct.pack("<dBB", weight, klass, leg)), (0x38, struct.pack("<Q", notional)), (0x40, address(9)), (0x54, bytes([cross, byte, flag])))


def check_record(seen, parts):
    if seen is None:
        return "fee not reached"
    if seen[0] != TRACKER:
        return "fee context"
    for at, data in parts:
        if seen[1][at:at + len(data)] != data:
            return "record +%#x" % at
    return ""


def input_head():
    return struct.pack("<QQ", 0, 0x1122334455667788) + address(5) + struct.pack("<I", 0x99AABBCC)


def check_fee(words, want):
    for name in ("gross", "rebate", "extra"):
        if words[name] != (want[name] & MASK[8]):
            return "fee %s %d wanted %d" % (name, words[name], want[name] & MASK[8])
    if words["tag"] or words["builder"]:
        return "fee tags"
    return ""


def compare_writer(harness, case):
    want = writer_spec(case)
    try:
        got = harness.run_writer(case)
    except Panicked as panic:
        return "" if want.get("panic") == str(panic) else "panic %s" % panic
    if "panic" in want:
        return "panic missing"
    if got["tag"] != want["tag"]:
        return "tag %#x wanted %#x" % (got["tag"], want["tag"])
    if want["text"] == "gate":
        pattern = bytearray((at * 5 + 3) & 0xFF for at in range(0x60))
        pattern[:2] = struct.pack("<H", case["gate"])
        if got["out"] != bytes(pattern):
            return "gate payload"
    elif want["text"]:
        base = harness.image.offset(want["text"][0])
        if got["text"] != bytes(harness.image.blob[base:base + want["text"][1]]):
            return "text payload"
    if got["calls"] != want["calls"]:
        return "calls %r wanted %r" % (got["calls"], want["calls"])
    if got["aligned"] != want["aligned"]:
        return "aligned %r" % sorted(got["aligned"].items())[:4]
    if got["dex"] != want["dex"]:
        return "dex"
    return ""


def compare_collect(harness, case):
    deployer = case["deployer"]
    want = []
    for key in sorted(case["aligned"]):
        if key >= len(case["tokens"]):
            want = "bound"
            break
        if case["tokens"][key] == deployer:
            want.append(key)
    try:
        got = harness.run_collect(case)
    except Panicked as panic:
        return "" if want == "bound" else "panic %s" % panic
    if want == "bound":
        return "panic missing"
    if got["items"] != want or got["count"] != len(want):
        return "set %r wanted %r" % (got["items"], want)
    if got["parent"] or (not want and got["frees"]):
        return "set root"
    return ""


def compare_wrapper(harness, case):
    want = wrapper_spec(case)
    try:
        words = harness.run_wrapper(case)
    except Panicked as panic:
        return "" if want.get("panic") == str(panic) or want.get("fee", {}).get("panic") == str(panic) else "panic %s" % panic
    if "panic" in want or "panic" in want["fee"]:
        return "panic missing"
    failed = check_record(harness.seen_record, record_bytes(input_head(), case["weight"], want["klass"], want["leg"], case["notional"], int(case["cross"]), want["byte"], case["flag"]))
    if failed:
        return failed
    if harness.predicates != ([] if want["predicate"] is None else [want["predicate"]]):
        return "predicate"
    return check_fee(words, want["fee"])


def vec_rows(memory, at, count, words=3):
    return [tuple(memory.read(at + index * words * 8 + part * 8, 8) for part in range(words)) for index in range(count)]


def compare_mint(harness, case):
    want = mint_spec(case)
    try:
        got = harness.run_mint(case)
    except Panicked as panic:
        return "" if want.get("fee", {}).get("panic") == str(panic) else "panic %s" % panic
    if "panic" in want.get("fee", {}):
        return "panic missing"
    memory = got["memory"]
    if "error" in want:
        return "" if got["first"] == want["error"] and got["tag"] == 4 else "error %d" % got["first"]
    if want.get("empty"):
        return "" if got["tag"] == 3 else "empty"
    failed = check_record(harness.seen_record, ((0, bytes(8)),) + record_bytes(b"", case["weight"], 2, 0, want["notional"], 1, want["byte"], case["side"])[1:])
    if failed:
        return failed
    fee = dict(gross=memory.read(OUT + 8 + 0x50, 8), rebate=memory.read(OUT + 8 + 0x58, 8), extra=memory.read(OUT + 8 + 0x60, 8), tag=memory.read(OUT + 8, 1), builder=memory.read(OUT + 8 + 0x28, 1))
    failed = check_fee(fee, want["fee"])
    if failed:
        return failed
    if got["word"] != case["quote"]:
        return "out word"
    token, size, words = case["token"], want["size"], want["words"]
    if (memory.read(OUT + 0x70, 8), memory.read(OUT + 0x80, 8), memory.read(OUT + 0x88, 8), memory.read(OUT + 0x98, 8), memory.read(OUT + 0xA0, 1)) != (2, 2, 1, 1, 1):
        return "out shape"
    if vec_rows(memory, memory.read(OUT + 0x78, 8), 2) != [(token, words[0], size), (token, words[1], size)]:
        return "leg rows"
    if vec_rows(memory, memory.read(OUT + 0x90, 8), 1) != [(token, case["quote"], want["notional"])]:
        return "quote row"
    return "" if got["allocs"] == [0x30, 0x18] else "allocs"


def compare_burn(harness, case):
    want = burn_spec(case)
    try:
        got = harness.run_burn(case)
    except Panicked as panic:
        return "" if want.get("fee", {}).get("panic") == str(panic) else "panic %s" % panic
    if "panic" in want.get("fee", {}):
        return "panic missing"
    memory = got["memory"]
    frees = [size for size in got["frees"]]
    freed = [case["cap"] << 4] if case["cap"] else []
    if "error" in want or want.get("empty"):
        if want.get("empty"):
            if got["tag"] != 3:
                return "empty"
        elif got["first"] != want["error"] or got["tag"] != 4:
            return "error %d" % got["first"]
        extra = [want["rows"] * 0x18] if want.get("rows") else []
        return "" if frees == extra + freed else "frees %r" % frees
    failed = check_record(harness.seen_record, ((0, bytes(8)),) + record_bytes(b"", case["weight"], 2, 0, want["notional"], 1, want["byte"], case["side"])[1:])
    if failed:
        return failed
    fee = dict(gross=memory.read(OUT + 8 + 0x50, 8), rebate=memory.read(OUT + 8 + 0x58, 8), extra=memory.read(OUT + 8 + 0x60, 8), tag=memory.read(OUT + 8, 1), builder=memory.read(OUT + 8 + 0x28, 1))
    failed = check_fee(fee, want["fee"])
    if failed:
        return failed
    quote = case["quote_left"]
    count = len(case["items"])
    if (got["word"], memory.read(OUT + 0x70, 8), memory.read(OUT + 0x80, 8), memory.read(OUT + 0x88, 8), memory.read(OUT + 0x98, 8), memory.read(OUT + 0xA0, 1)) != (quote, count, count, 1, 1, 3):
        return "out shape"
    if count and vec_rows(memory, memory.read(OUT + 0x78, 8), count) != [item + (case["amount"],) for item in case["items"]]:
        return "item rows"
    if not count and memory.read(OUT + 0x78, 8) != 8:
        return "empty pointer"
    if got["allocs"] != ([count * 0x18] if count else []) + [0x18]:
        return "allocs"
    if vec_rows(memory, memory.read(OUT + 0x90, 8), 1) != [(case["token"], quote, want["notional"])]:
        return "quote row"
    return "" if frees == freed else "frees %r" % frees


def compare_site(harness, case):
    if case["spot"] >= len(case["pairs"]):
        try:
            harness.run_stats(case)
        except Panicked as panic:
            return "" if str(panic) == "bound" else "panic %s" % panic
        return "panic missing"
    want = site_spec(case)
    if case["kind"] == "stats":
        seen = harness.run_stats(case)
        parts = record_bytes(input_head(), case["weight"], want["klass"], 1, case["notional"], case["taker"], want["byte"], case["flag"])
    else:
        seen = harness.run_loop(case)
        parts = record_bytes(input_head(), case["weight"], want["klass"], case["leg"], case["notional"], int(case["leg"] == case["taker"]), want["byte"], case["flag"])
    failed = check_record(seen, parts)
    if failed:
        return failed
    return "" if harness.predicates == ([] if want["predicate"] is None else [want["predicate"]]) else "predicate"


COMPARE = dict(writer=compare_writer, collect=compare_collect, wrapper=compare_wrapper, mint=compare_mint, burn=compare_burn, stats=compare_site, loop=compare_site)


def compare_run(harness, case):
    try:
        return COMPARE[case["kind"]](harness, case)
    except (Halt, Panicked, Finished, EvidenceError, struct.error, ZeroDivisionError, KeyError, MemoryError, IndexError, ValueError, OverflowError) as error:
        return "%s: %s: %s" % (case["kind"], case["label"], error)


# ---- mutation survey ----

def groups(image):
    return (("writer", 0x274DB00, 0x274DB00 + WRITER_SIZE), ("collect", COLLECT, image.exact_fde(COLLECT)[1]), ("filter", FILTER, 0x257D3D3), ("wrapper", WRAPPER, image.exact_fde(WRAPPER)[1]),
            ("mint", MINT, image.exact_fde(MINT)[1]), ("burn", BURN, image.exact_fde(BURN)[1]), ("stats site", STATS, STATS_SITE + 5), ("loop site", LOOP_START, LOOP_SITE + 5))


def stepped_groups(image):
    rows = [("writer " + layout["name"], layout["entry"], layout["entry"] + WRITER_SIZE) for layout in WRITERS[1:]]
    return list(groups(image)) + rows + [("fee body, real, not mutated", FEE, image.exact_fde(FEE)[1])]


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
    by_va = {}
    for index, touched in enumerate(reached):
        if cases[index]["kind"] == "writer" and cases[index]["layout"]["name"] != "first":
            continue
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for role, begin, end in groups(image):
        for va, at, xor, kind in mutation_targets(image, decode_range(image, begin, end)):
            indices = by_va.get(va)
            if not indices:
                results.append({"group": role, "va": va, "kind": kind, "result": "unreached", "by": ""})
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
                    del first_kill[60:]
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"group": role, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0][:40] if failed else ""})
    return results


# ---- facts read from bytes ----

def text_range(image):
    return image.text_bytes()


def direct_callers(image, targets):
    """Call sites by e8 byte pattern, kept only when the site lies in an FDE and the target is an FDE start."""
    base, code = text_range(image)
    out = []
    at = code.find(b"\xe8")
    wanted = set(targets)
    while at >= 0:
        if at + 5 <= len(code):
            target = base + at + 5 + struct.unpack_from("<i", code, at + 1)[0]
            if target in wanted:
                out.append((base + at, target))
        at = code.find(b"\xe8", at + 1)
    return sorted(out)


def argument_form(image, site):
    """Bytes before a writer call give the enable and force arguments."""
    start = image.offset(site)
    head = bytes(image.blob[start - 16:start])
    if b"\x41\xb8\x01\x00\x00\x00" in head:
        force = 1
    elif b"\x45\x31\xc0" in head:
        force = 0
    else:
        raise EvidenceError("force form at %#x" % site)
    if b"\xb9\x01\x00\x00\x00" in head:
        enable = "1"
    elif b"\x31\xc9" in head:
        enable = "0"
    elif b"\x0f\xb6\x4e\x10" in head:
        enable = "action +0x10"
    else:
        raise EvidenceError("enable form at %#x" % site)
    return enable, force


def scale_readers(image):
    """Scalar SSE loads and products of tracker +0x90, +0x98, +0xa0 in the state code range, by fixed byte shapes."""
    base, code = text_range(image)
    rows = []
    for disp in (0x90, 0x98, 0xA0):
        pattern = struct.pack("<I", disp)
        at = code.find(pattern)
        while at >= 0:
            site = base + at
            if at >= 5 and (0x2400000 <= site < 0x3C80000 or 0x4300000 <= site < 0x4E00000):
                opcode, modrm = code[at - 2], code[at - 1]
                if code[at - 3] == 0x0F and opcode in (0x10, 0x58, 0x59, 0x5C, 0x5E) and modrm >> 6 == 2 and (modrm & 7) != 4:
                    prefix = code[at - 4]
                    plain = prefix == 0xF2
                    rex = 0x40 <= prefix < 0x50 and code[at - 5] == 0xF2
                    if plain or rex:
                        rows.append((disp, site, image.fde(site)[0]))
            at = code.find(pattern, at + 1)
    return rows


def status_text(image, tag):
    arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, image.offset(STATUS_TABLE + 4 * tag))[0]
    data = bytes(image.blob[image.offset(arm):image.offset(arm) + 26])
    if data[:11] != bytes.fromhex("488b3e488b4608488b4018") or data[11:14] != b"\x48\x8d\x35" or data[18] != 0xBA:
        raise EvidenceError("status arm shape %#x" % tag)
    text = arm + 18 + struct.unpack("<i", data[14:18])[0]
    start = image.offset(text)
    return bytes(image.blob[start:start + struct.unpack("<I", data[19:23])[0]]).decode()


PINS = (
    ("0x3744a28", "488d8424300100004983c770498b4f1048894810410f10070f11", "patch word +0x68 bit 0 true: 3 words from update +0x70 go to frame +0x130, which is tracker +0x90 of the 0xc0-byte copy"),
    ("0x37581ac", "488d4b50", "serializer 0x37580a0: key collateralToken reads row +0x50"),
    ("0x37581cf", "488d4b58", "serializer 0x37580a0: key collateralIsAlignedQuoteToken reads row +0x58"),
    ("0x371314c", "440fb67658", "0x37130b0: perp fee loads the byte at clearinghouse +0x58, tested before tracker +0x90 and +0x98"),
    ("0x371548d", "41807e5800", "0x37153f0: perp volume tests the byte at clearinghouse +0x58"),
    ("0x37154a5", "f2410f108c24a0000000", "0x37153f0: scale from tracker +0xa0 (a SIB form the shape scan leaves out)"),
    ("0x274dea5", "40886858", "writer: row +0x58 = enable when row +0x50 == token"),
    ("0x3742519", "410fb6442455", "0x3742460: fee body loads record +0x55"),
    ("0x3742511", "f20f10be90000000", "0x3742460: scale from tracker +0x90"),
    ("0x374259e", "f2440f108698000000", "0x3742460: scale from tracker +0x98"),
    ("0x372fadd", "f20f1091a0000000", "0x372faa0: volume scale from tracker +0xa0"),
)


def pin_rows(image):
    rows = []
    for va, hexa, text in PINS:
        address_value = int(va, 16)
        start = image.offset(address_value)
        if hexa is None:
            data = bytes(image.blob[start:start + 8])
        else:
            want = bytes.fromhex(hexa.replace(" ", ""))
            data = bytes(image.blob[start:start + len(want)])
            if data != want:
                raise EvidenceError("pin %s: %s" % (va, data.hex()))
        rows.append((va, data.hex(), text))
    return rows


def key_rows(image):
    """Key literals at the serializer lea targets."""
    rows = []
    for va, size in ((0x598034, 0xF), (0x598043, 0x1D), (0x598060, 0x13)):
        start = image.offset(va)
        rows.append({"address": "%#x" % va, "text": bytes(image.blob[start:start + size]).decode()})
    return rows


def path_rows():
    return (
        (1, "vote", "0x1b2c4e0 family", "alignedQuoteTokenConfig gives cross_scale, add_rebate_scale, vlm_contribution_scale (fees-schedule-vote-94)"),
        (2, "schedule", "0x3744550", "patch bit at update +0x68 copies the 3 words to tracker +0x90, +0x98, +0xa0"),
        (3, "enable", "0x274db00 + 2 copies", "aligned map value +0x2c and byte +0x58 of every dex row whose collateral +0x50 is the token"),
        (4, "owner rule", "0x27e61a0 + 0x257d2f0", "aligned tokens with the same deployer, active or not; any other than the token refuses with 0xf0"),
        (5, "spot class", "0x372f020", "base in quote_token_to_status gives class 1, else outcome test gives class 2, else 0; quote's value +0x2c gives the aligned byte"),
        (6, "outcome fee", "0x3726360 + 0x3726980", "class always 2, weight meta +0x140, cross byte 1, leg 0, aligned byte of the outcome quote"),
        (7, "fill sites", "0x372e2f0 + 0x372c114", "same selection inline; cross byte is the record taker side"),
        (8, "fee body", "0x3742460", "class changes the rate, aligned byte changes the multiplier, real bytes run behind steps 5 and 6"),
        (9, "perp", "0x37130b0, 0x37153f0", "same 3 words, selected by clearinghouse +0x58 (fees-trade-fee-94, fees-unit-conversion-94; that packet's name trial is wrong)"),
    )


def writer_rows():
    return (
        ("all", "token past list", "panic", "bounds check on state +0x218"),
        ("all", "row +0xd2 bit 0 clear", "0xef", "no stub runs"),
        ("enable", "status missing or byte not 0", "0xef", "force does not help"),
        ("enable", "another aligned token has this deployer", "0xf0", "inactive entries count"),
        ("enable", "gate refuses", "gate payload", "0x60 bytes forwarded, mode 4 when the token is in the set, else 2"),
        ("enable", "entry exists, active 0, force 0", "0xdf", "cannot enable disabled aligned quote token"),
        ("enable", "entry exists otherwise", "0x186", "active = 1, other value words stay, dex bytes = 1"),
        ("enable", "no entry", "0x186", "insert: words 0, state +0x60 time, active 1, dex bytes = 1"),
        ("disable", "force 0, status present and not 1", "0xdf", "cannot disable aligned quote token before disabling quote token"),
        ("disable", "otherwise", "0x186", "active = 0 when an entry exists; a missing entry is no error; dex bytes = 0"),
    )


def sample_rows():
    """One row per class and aligned byte through the real wrapper and fee body."""
    fee = fee_rows()[1]
    rows = []
    for spot, label in ((0, "plain base, quote 0"), (2, "plain base, aligned quote"), (3, "base is a quote token, quote not aligned"), (7, "base is a quote token, aligned quote"), (6, "outcome base, plain quote")):
        for cross in (True, False):
            rows.append((spot, label, int(cross), dict(META, kind="wrapper", spot=spot, outcome=spot == 6, cross=cross, leg=0, flag=0, fee=fee, notional=10 ** 12, label="sample")))
    return rows


def reference_rows():
    return (
        ("l1/spot_meta.rs", "re-enable sets active with no refusal", "0xdf without force when the entry is inactive"),
        ("l1/spot_meta.rs", "disable needs status Disabled", "a missing status passes, and force skips the test"),
        ("l1/spot_meta.rs", "first_aligned_time rewritten when 0", "an existing entry keeps every word but active"),
        ("l1/spot_meta.rs", "no deployer rule, no gate", "0xf0 and the 0x2751b30 gate come first"),
        ("l1/spot_meta.rs", "no dex row write", "every row with this collateral gets the enable byte"),
        ("l1/spot_clearinghouse/cl_trait.rs", "aligned_quote_wei added to an accumulator", "the fee body only scales rates by the aligned byte"),
        ("l1/spot_meta.rs", "cross_scale u64, add_rebate_scale u64, vlm_contribution_scale u64", "f64 words: read by movsd and multiplied"),
    )


SORT = "insertion sort over keys that arrive in order from the tree, it never moves one"
COPY = "copies option payload bytes the fee body leaves unset when both tags are 0"
SPLAT = "pshufd pattern over equal words of one repeated tag byte"
REASONS = {
    0x274DCAC: "a stale key found past the length writes an unused value slot on disable, no live byte changes",
    0x274DCB5: "a stale key found past the length writes an unused value slot on disable, no live byte changes",
    0x274DD2E: "the row count division floors the same with 8 more bytes",
    0x27E61D9: "back handle of the iterator, not read on a forward walk",
    0x27E61DD: "back handle of the iterator, not read on a forward walk",
    0x27E6229: "leaf allocation 0x69 instead of 0x68, the arena rounds up",
    0x27E62E4: "one key takes the sort arm, same result",
    0x27E62FB: SORT, 0x27E6363: SORT, 0x27E636F: SORT, 0x27E6377: SORT, 0x27E637E: SORT, 0x27E63B8: SORT,
    0x257D3C8: "vector allocation 0x21 instead of 0x20, the capacity word stays 4",
    0x372641D: SPLAT, 0x3726A16: SPLAT,
    0x3726675: COPY, 0x3726699: COPY, 0x37266A1: COPY, 0x3726DAA: COPY, 0x3726DCF: COPY, 0x3726DD9: COPY,
    0x3726B0A: "the row limit needs 2^58 rows",
    0x372E0AA: "frame size, the range stops at the fee call and never returns",
    0x372E0FC: "copy of the user to a frame slot read after the fee call, outside the range",
    0x372E10A: "copy of the user to a frame slot read after the fee call, outside the range",
}
UNREACHED = "not stepped: unwind pad, allocation failure arm, sort swap arm, outcome table false tag or second probe group, or aligned tree descent in an outcome host"
GROUP_REASONS = "not classified"


def analyse(image, full=True):
    cases = all_cases()
    harness = Harness(image)
    machine = harness.machine
    mismatches, first = 0, ""
    reached = []
    kinds = {}
    for case in cases:
        machine.seen = set()
        failed = compare_run(harness, case)
        reached.append(frozenset(machine.seen))
        if failed:
            mismatches += 1
            first = first or "%s: %s" % (case["label"], failed)
        kinds[case["kind"]] = kinds.get(case["kind"], 0) + 1
    touched = set().union(*reached)
    functions = []
    for role, begin, end in stepped_groups(image):
        rows = decode_range(image, begin, end)
        base = image.offset(begin)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(bytes(image.blob[base:base + end - begin])).hexdigest(),
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched)})
    callers = direct_callers(image, [layout["entry"] for layout in WRITERS])
    sites = []
    for site, target in callers:
        enable, force = argument_form(image, site)
        sites.append({"site": "%#x" % site, "writer": "%#x" % target, "host": "%#x" % image.fde(site)[0], "enable": enable, "force": force})
    readers = {}
    for disp, site, host in scale_readers(image):
        readers.setdefault("%#x" % disp, []).append({"site": "%#x" % site, "function": "%#x" % host})
    stubs = {}
    for (name, role), target in sorted(harness.writer_stubs.items()):
        stubs.setdefault(name, {})[role] = "%#x" % target
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
        "writer_callers": sites,
        "writer_stubs": stubs,
        "scale_readers": readers,
        "keys": key_rows(image),
        "status": {"%#x" % tag: status_text(image, tag) for tag in (BAD_QUOTE, DUPLICATE)},
        "texts": [text for text in (bytes(image.blob[image.offset(TEXT_DISABLE):image.offset(TEXT_DISABLE) + TEXT_DISABLE_LEN]).decode(), bytes(image.blob[image.offset(TEXT_ENABLE):image.offset(TEXT_ENABLE) + TEXT_ENABLE_LEN]).decode())],
        "cases": {"total": len(cases), "by_kind": dict(sorted(kinds.items()))},
        "mismatches": mismatches,
        "first_mismatch": first,
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
    if row["result"] == "unreached":
        return UNREACHED
    return REASONS.get(row["va"], GROUP_REASONS)


def write_tsv(path, header, rows):
    lines = ["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def class_samples(image):
    harness = Harness(image)
    rows = []
    for spot, label, cross, case in sample_rows():
        want = wrapper_spec(case)
        failed = compare_run(harness, case)
        if failed:
            raise EvidenceError("sample: %s" % failed)
        rows.append((label, cross, want["klass"], want["byte"], want["fee"]["gross"], want["fee"]["rebate"]))
    return rows


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
    write_tsv(out / "path-map.tsv", ("order", "stage", "address", "behaviour"), path_rows())
    write_tsv(out / "writer-rules.tsv", ("mode", "condition", "result", "note"), writer_rows())
    write_tsv(out / "pins.tsv", ("address", "bytes", "meaning"), pin_rows(image))
    write_tsv(out / "class-samples.tsv", ("case", "cross", "class", "aligned_byte", "gross", "rebate"), class_samples(image))
    write_tsv(out / "reference-diff.tsv", ("reference_file", "reference_says", "bytes_say"), reference_rows())
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row in results:
        reason = "" if row["result"] == "killed" else reason_for(row)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row["group"], row["va"], row["kind"], row["result"], row["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
