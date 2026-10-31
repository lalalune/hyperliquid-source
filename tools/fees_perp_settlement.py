#!/usr/bin/env python3
"""Pin the node #94 perp fill fee settlement from ELF bytes: the whole body of 0x3710a70 and the exempt address test 0x37e4fb0.

Both functions run in a Python evaluator. A separately written specification predicts every stub call in order, every balance and
pool word, every recorder call, panic Location and party block byte, and every condition, immediate and field offset of 0x3710a70
is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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
HEAP_SIZE = 0x80000
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


FILL_FN = 0x3710A70
PREDICATE = 0x37E4FB0
FEE = 0x37130B0
CREDIT = 0x37067B0
ROW = 0x3596940
READ_ROW = 0x36F57F0
SET_INSERT = 0x339B590
SET_REMOVE = 0x33ACFE0
ENTRY = 0x33BD420
SIZE_HOOK = 0x36F7350
LEVERAGE_HOOK = 0x370E6A0
APPLY = 0x36FE830
HASH_USER = 0x399C7A0
HASH_ASSET = 0x399C4A0
SLOT_PREDICATE = 0x5773228
SLOT_FEE = 0x5774890
SLOT_CREDIT = 0x5774918
SLOT_RECORDER = 0x5773190
SLOT_ONCE = 0x576E8B8
SLOT_UNWRAP = 0x576E048
ONCE_CELL = 0x577AB98
OK_TAG = 0x186
LOC_NET = 0x5714C10
LOC_SZ = 0x56EE580
LOC_APPLY = 0x56F1F90
LOC_BALANCE = 0x56F1CF8
LOC_POOL = 0x5714C28
LOC_DEPLOYER = 0x570B4E0
LOC_TOTAL = 0x570B4F8
LOC_FREE = 0x5714D30
LOC_DOUBLE = 0x56F1F00
LOC_OI_DOWN = 0x56F1C98
LOC_OI_UP = 0x56F1C68
LOC_OI_MIN = 0x56F1C80
OI_ENTRY = 0x33BC4D0
LOC_SUM = 0x56F1F30
PARTY_SIZE = 0x100
FILL_SIZE = 0x240
CH = HEAP_BASE + 0x1000
OUT_SIZE = 0x78
FILL = HEAP_BASE + 0x400
EMPTY_ROW = HEAP_BASE + 0xA00
BUMP = HEAP_BASE + 0x2000
CTX = 0x7654321012340
CAPACITY = 11
MAX = (1 << 64) - 1
HALF = 1 << 63
LIMIT = HALF - 2
DEFAULT_LEVERAGE = 20
TOTALS = dict(leaf=0xC0, inner=0x120, keys=8, length=0xBA, slot=0xB8, parent=0, values=0x60, stride=8, edges=0xC0, width=8)
POSITIONS = dict(leaf=0x328, inner=0x388, keys=0x2C8, length=0x322, slot=0x320, parent=0x2C0, values=0, stride=0x40, edges=0x328, width=8)
PRIVILEGED_BYTES = ((0x206D40, 0x203680), (0x206D50, 0x205350), (0x209500, 0x209110), (0x2039B0, 0x2074D0),
                    (0x204070, 0x209120), (0x206680, 0x2069A0), (0x2084D0, 0x207EE0), (0x2069B0, 0x2039C0))


def address(index):
    return bytes((index * 7 + at * 11 + 1) & 0xFF for at in range(20))


def privileged_addresses(image):
    rows = []
    for head, tail in PRIVILEGED_BYTES:
        rows.append(bytes(image.blob[image.offset(head):image.offset(head) + 16]) + bytes(image.blob[image.offset(tail):image.offset(tail) + 4]))
    return rows


def signed(value):
    return value - (1 << 64) if value & SIGN[8] else value


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


def tree_items(memory, node, height):
    shape = POSITIONS
    if not node:
        return []
    found = []
    count = memory.read(node + shape["length"], 2)
    if count > CAPACITY:
        raise Halt("node length")
    for index in range(count + 1):
        if height:
            found += tree_items(memory, memory.read(node + shape["edges"] + 8 * index, 8), height - 1)
        if index < count:
            found.append((memory.read(node + shape["keys"] + 8 * index, 8), node + shape["values"] + shape["stride"] * index))
    return found


def lay_table(memory, bump, entries, stride, put, walls=(0, 0)):
    """hashbrown table of 64 buckets; entries are (hash, payload). Returns the control pointer and mask."""
    buckets = 64
    area = bump(stride * buckets + buckets + 16)
    ctrl = area + stride * buckets
    used = {}
    for slot in range(*walls):
        used[slot] = 0x80
    for hashed, payload in entries:
        pos, step = hashed & (buckets - 1), 0
        while True:
            free = [offset for offset in range(16) if (pos + offset) & (buckets - 1) not in used]
            if free:
                slot = (pos + free[0]) & (buckets - 1)
                break
            step += 16
            pos = (pos + step) & (buckets - 1)
        used[slot] = hashed >> 57
        put(ctrl - (slot + 1) * stride, payload)
    data = bytearray(b"\xff" * (buckets + 16))
    for slot, value in used.items():
        data[slot] = value
        if slot < 16:
            data[buckets + slot] = value
    memory.put_bytes(ctrl, bytes(data))
    return ctrl, buckets - 1


# ---- specification ----

class Refused(Exception):
    """The specification's panic: the Location record the path names."""


def saturating_sub(left, right, record, location):
    value = signed(left) - signed(right)
    if value >= HALF or value < -HALF:
        record.append((0, location))
        value = HALF - 1 if value >= HALF else -HALF
    return value & MAX


def saturating_add(left, right, record, location):
    value = signed(left) + signed(right)
    if value >= HALF or value < -HALF:
        record.append((0, location))
        value = HALF - 1 if value >= HALF else -HALF
    return value & MAX


def margin_part(size, row, record):
    """Bytes 0x37116a1..0x371177e: the amount of one signed size, words as in the inner row."""
    low, high, bid_count, ask_count, unit, divisor = row["a"], row["b"], row["c"], row["d"], row["k"], row["lev"]
    size = signed(size)
    big, small, count = (high, low, ask_count) if size > 0 else (low, high, bid_count)
    magnitude = abs(size)
    product, bad = 0, False
    if unit:
        product = unit * magnitude
        bad = product > MAX or product & MAX > LIMIT
        product &= MAX
    value = 0
    if count != 0 and count <= big and not bad:
        ratio = big // count
        if magnitude >= HALF:
            record.append((0, LOC_DOUBLE))
            twice = MAX
        else:
            twice = 2 * magnitude
        scaled = 2 * product
        if big >= scaled and count >= twice:
            total = ratio * (count - twice)
            if total <= LIMIT:
                value = min(total, big - scaled)
    return max(small, value) // divisor


def spec(case, privileged):
    """Log of every stub call plus the final words; a panic ends the log with its Location."""
    log, record = [], []
    rows = {user: dict(balance=row["balance"], count=row["count"], positions={asset: list(value) for asset, value in row["positions"].items()}) for user, row in case["rows"].items()}
    pool, free = case["pool"], case["free"]
    blocks = {}
    deployer = protocol = 0
    asset, size = case["asset"], case["sz"]
    exempt = False
    panic = None
    active = None

    def word(value, location):
        nonlocal pool
        if signed(value) < 0:
            raise Refused(LOC_NET)
        pool = saturating_sub(pool, value, record, LOC_POOL)

    try:
        for party in (0, 1):
            user = case["party"][party]
            if who(user) in privileged:
                if signed(size) < 0:
                    raise Refused(LOC_SZ)
                exempt = True
                net = 0
            else:
                row = case["records"][party]
                log.append(("fee", party, int(party == case["maker"])))
                if signed(row["gross"]) < 0 or signed(row["rebate"]) < 0:
                    raise Refused(LOC_NET)
                net = row["gross"] - row["rebate"]
                if user not in rows:
                    rows[user] = dict(balance=0, count=0, positions={})
                    log.append(("row new", user))
                held = rows[user]
                log.append(("set", "touched", user))
                old_count = held["count"]
                if asset not in held["positions"]:
                    held["positions"][asset] = [0, DEFAULT_LEVERAGE, 0, 0]
                    log.append(("entry new", user))
                position = held["positions"][asset]
                if position[0]:
                    position[2] = saturating_sub(position[2], net & MAX, record, LOC_BALANCE)
                else:
                    held["balance"] = saturating_sub(held["balance"], net & MAX, record, LOC_BALANCE)
                log.append(("size hook", user, position[3]))
                held["count"] = case["next_count"][party]
                if old_count:
                    if held["count"] == 0:
                        log.append(("remove", "active", user))
                elif held["count"]:
                    log.append(("set", "active", user))
                if row["extra"]:
                    word(row["extra"], LOC_POOL)
                if row["builder_tag"] & 1:
                    word(row["builder"], LOC_POOL)
                if row["referrer_tag"] == 1:
                    word(row["referrer"], LOC_POOL)
                deployer = saturating_add(deployer, row["deployer"], record, LOC_DEPLOYER)
                protocol = saturating_add(protocol, row["protocol"], record, LOC_DEPLOYER)
                blocks[party] = True
                if signed(size) < 0:
                    raise Refused(LOC_SZ)
            amount = size if party == 0 else -signed(size) & MAX
            log.append(("apply", party, amount, net & MAX, user))
            if case["apply_fail"] == party:
                raise Refused(LOC_APPLY)
            if user in rows and asset in rows[user]["positions"]:
                position = rows[user]["positions"][asset]
                position[3] = (position[3] + amount) & MAX
        if not exempt:
            if saturating_add(deployer, protocol, record, LOC_TOTAL) == 0:
                if case["once"]:
                    log.append(("once",))
                if free + case["ntl"] > MAX:
                    record.append((0, LOC_FREE))
                    free = MAX
                else:
                    free += case["ntl"]
        log.append(("credit", deployer, protocol))
        maker = case["party"][case["maker"]]
        log.append(("read row", maker))
        held = rows.get(maker)
        position = held["positions"].get(asset) if held else None
        new_size = position[3] if position else 0
        table = case["table"].get(maker)
        if case["outer_items"] and table and table["inner_items"] and asset in table["rows"]:
            row = table["rows"][asset]
            old = margin_part(row["size"], row, record)
            active = (maker, asset)
            new = margin_part(new_size, row, record)
            total = table["sum"] + new
            if total > MAX:
                record.append((0, LOC_SUM))
                total = MAX
            if total < old:
                record.append((0, LOC_SUM))
                total = 0
            else:
                total -= old
            active = (maker, asset, new_size, total)
    except Refused as stop:
        panic = stop.args[0]
    return dict(log=log, record=record, rows=rows, pool=pool, free=free, panic=panic, blocks=blocks, active=active)


def hook_spec(case):
    """0x36f7350 from bytes: count of open positions, then |old| out of and |new| into the asset total."""
    old, new, count, total = signed(case["old"]), signed(case["new"]), case["count"], signed(case["total"]) if case["asset"] in case["assets"] else 0
    record = []
    if old == 0 and new != 0:
        count = min(count + 1, MAX)
    elif old != 0 and new == 0 and count:
        count -= 1
    panic = None
    if case["old"] == HALF:
        return dict(count=count, total=None, record=record, panic=LOC_OI_MIN)
    value = total - abs(old)
    if value < -HALF:
        record.append((0, LOC_OI_DOWN))
        value = -HALF
    if case["new"] == HALF:
        return dict(count=count, total=value, record=record, panic=LOC_OI_MIN)
    value += abs(new)
    if value >= HALF:
        record.append((0, LOC_OI_UP))
        value = HALF - 1
    return dict(count=count, total=value, record=record, panic=panic)


def who(index):
    return address(index) if index >= 0 else PRIVILEGED[-index - 1]


PRIVILEGED = []


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        machine.memory.reset()
        machine.real = FILL_REAL
        machine.jump_ranges = [image.exact_fde(start) for start in REAL]
        machine.step_limit = 12000
        machine.calls = {OI_ENTRY: self.on_total, ROW: self.on_row, READ_ROW: self.on_read_row, SET_INSERT: self.on_insert, SET_REMOVE: self.on_remove, ENTRY: self.on_entry,
                         SIZE_HOOK: self.on_size, LEVERAGE_HOOK: self.on_leverage, APPLY: self.on_apply, HASH_USER: self.on_hash_user, HASH_ASSET: self.on_hash_asset}
        table = ((SLOT_FEE, self.on_fee), (SLOT_CREDIT, self.on_credit), (SLOT_RECORDER, self.on_recorder), (SLOT_ONCE, self.on_once), (SLOT_UNWRAP, self.on_unwrap))
        for at, (slot, hook) in enumerate(table):
            token = 0x7100000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        machine.memory.statics[SLOT_PREDICATE] = PREDICATE
        machine.memory.statics[ONCE_CELL] = 0
        self.at = BUMP
        self.case = None
        if not PRIVILEGED:
            PRIVILEGED.extend(privileged_addresses(image))
        self.privileged = frozenset(PRIVILEGED)

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

    def check(self, condition, text):
        if not condition:
            raise Halt(text)

    def user_at(self, at):
        key = self.machine.memory.bytes_at(at, 20)
        for user in self.case["party"] + (self.case.get("alien"),):
            if user is not None and who(user) == key:
                return user
        raise Halt("unknown user")

    def on_recorder(self, machine):
        self.record.append((machine.regs[RDI] & MASK[4], machine.regs[RSI]))

    def on_once(self, machine):
        regs = machine.regs
        self.check(regs[RDI] == ONCE_CELL and regs[RSI] & 0xFF == 1, "once args")
        self.log.append(("once",))

    def on_unwrap(self, machine):
        regs = machine.regs
        self.check(regs[RSI] == 0x2B, "unwrap size")
        if regs[R8] in (LOC_OI_MIN,):
            raise Panicked(regs[R8])
        if regs[R8] == LOC_APPLY:
            self.check(machine.memory.read(regs[RDX], 2) == self.fail_tag and machine.memory.read(regs[RDX] + 8, 8) == 0x5A5A5A5A0000 and machine.memory.read(regs[RDX] + 0x58, 8) == 0x1234FEDC, "error payload")
        raise Panicked(regs[R8])

    def on_fee(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        self.check(regs[RSI] == CH and regs[RCX] == case["ntl"], "fee args")
        frame = regs[RDX]
        party = memory.read(frame + 0x4D, 1)
        self.check(party in (0, 1) and not (party in self.fee_seen), "fee party")
        self.fee_seen.add(party)
        self.current = party
        base = FILL + party * PARTY_SIZE
        self.check(memory.bytes_at(frame, 0x28) == memory.bytes_at(base + 0x20, 0x28), "fee head")
        self.check(memory.read(frame + 0x28, 8) == CTX and memory.read(frame + 0x30, 8) == case["asset"], "fee ctx")
        self.check(memory.bytes_at(frame + 0x38, 20) == who(case["party"][party]), "fee user")
        self.check(memory.read(frame + 0x4E, 1) == case["flag"], "fee flag")
        self.log.append(("fee", party, memory.read(frame + 0x4C, 1)))
        memory.put_bytes(regs[RDI], record_image(case["records"][party], party))

    def on_credit(self, machine):
        regs = machine.regs
        self.check(regs[RDI] == CH and regs[RCX] == CTX, "credit args")
        self.log.append(("credit", regs[RSI], regs[RDX]))

    def row_for(self, machine):
        self.check(machine.regs[RDI] == CH + 0xF8, "row map")
        return self.user_at(machine.regs[RSI])

    def on_row(self, machine):
        user = self.row_for(machine)
        if user not in self.rows:
            self.lay_row(user, dict(balance=0, count=0, positions={}))
            self.log.append(("row new", user))
        machine.regs[RAX] = self.rows[user]

    def on_read_row(self, machine):
        user = self.row_for(machine)
        self.log.append(("read row", user))
        machine.regs[RAX] = self.rows.get(user, EMPTY_ROW)

    def set_name(self, base):
        names = {CH + 0x188: "touched", CH + 0x158: "active"}
        self.check(base in names, "set base")
        return names[base]

    def on_insert(self, machine):
        self.log.append(("set", self.set_name(machine.regs[RDI]), self.user_at(machine.regs[RSI])))

    def on_remove(self, machine):
        self.log.append(("remove", self.set_name(machine.regs[RDI]), self.user_at(machine.regs[RSI])))

    def find(self, row, asset):
        memory = self.machine.memory
        for key, where in tree_items(memory, memory.read(row + 8, 8), memory.read(row + 0x10, 8)):
            if key == asset:
                return where
        return None

    def on_entry(self, machine):
        """Check the handle of the inline search byte by byte, then give the value."""
        regs, memory, case = machine.regs, machine.memory, self.case
        handle, asset = regs[RDI], case["asset"]
        self.check(memory.read(regs[RSI], 8) == asset and regs[RDX] == CH, "entry args")
        user = case["party"][self.current]
        row = self.rows[user]
        root, height = memory.read(row + 8, 8), memory.read(row + 0x10, 8)
        where = self.find(row, asset)
        if where is None:
            self.check(memory.read(handle, 8) == row + 8 and memory.read(handle + 8, 8) == asset, "vacant handle")
            if root:
                self.check(memory.read(handle + 0x10, 8) == self.leaf_of(root, height, asset) and memory.read(handle + 0x18, 8) == 0, "vacant node")
                self.check(memory.read(handle + 0x20, 8) == self.index_in(self.leaf_of(root, height, asset), asset), "vacant index")
            else:
                self.check(memory.read(handle + 0x10, 8) == 0, "vacant empty")
            self.log.append(("entry new", user))
            items = [(key, tuple(memory.read(place + at, 8) for at in range(0, 0x40, 8))) for key, place in tree_items(memory, root, height)]
            fresh = bytearray(0x40)
            fresh[4] = DEFAULT_LEVERAGE
            items.append((asset, struct.unpack("<8Q", bytes(fresh))))

            def put(place, words):
                for at, value in enumerate(words):
                    memory.write(place + at * 8, 8, value)
            root, height = build_tree(memory, self.bump, POSITIONS, sorted(items), put)
            memory.write(row + 8, 8, root)
            memory.write(row + 0x10, 8, height)
            memory.write(row + 0x18, 8, len(items))
            where = self.find(row, asset)
        else:
            node = self.node_holding(root, height, where)
            self.check(memory.read(handle, 8) == 0 and memory.read(handle + 8, 8) == node, "found handle")
            self.check(memory.read(handle + 0x20, 8) == row + 8, "found tree")
            self.check(memory.read(handle + 0x18, 8) == (where - node) // 0x40, "found index")
        regs[RAX] = where
        self.entry = where

    def node_holding(self, root, height, where):
        memory = self.machine.memory
        node, level = root, height
        while True:
            if node <= where < node + 0x2C0:
                return node
            count = memory.read(node + 0x322, 2)
            asset = None
            target = next(key for key, place in tree_items(memory, root, height) if place == where)
            index = 0
            while index < count and memory.read(node + 0x2C8 + index * 8, 8) < target:
                index += 1
            node = memory.read(node + 0x328 + index * 8, 8)
            level -= 1

    def leaf_of(self, root, height, asset):
        memory = self.machine.memory
        if not root:
            return 0
        node = root
        for _ in range(height):
            count = memory.read(node + 0x322, 2)
            index = 0
            while index < count and memory.read(node + 0x2C8 + index * 8, 8) < asset:
                index += 1
            node = memory.read(node + 0x328 + index * 8, 8)
        return node

    def index_in(self, node, asset):
        memory = self.machine.memory
        count = memory.read(node + 0x322, 2)
        index = 0
        while index < count and memory.read(node + 0x2C8 + index * 8, 8) < asset:
            index += 1
        return index

    def on_size(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        party = self.current
        user = case["party"][party]
        self.check(regs[RDI] == case["asset"] and regs[RSI] == memory.read(self.entry + 0x10, 8) and regs[RDX] == regs[RSI], "size args")
        self.check(regs[RCX] == self.rows[user] + 0x20 and regs[R8] == CH + 0x170, "size places")
        self.log.append(("size hook", user, regs[RSI]))
        memory.write(regs[RCX], 8, case["next_count"][party])

    def on_leverage(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        party = self.current
        self.check(regs[RDI] == CH + 0x128 and regs[RDX] == case["asset"], "leverage args")
        self.check(memory.bytes_at(regs[RSI], 20) == who(case["party"][party]), "leverage user")
        self.log.append(("leverage hook", case["party"][party], regs[RCX] & MASK[4]))

    def on_apply(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        self.check(regs[RSI] == CH and regs[RDX] == case["asset"] and regs[RCX] == case["px"], "apply args")
        user_at = regs[R9]
        user = self.user_at(user_at)
        party = self.applied
        self.applied += 1
        net = memory.read(regs[RSP] + 8, 8)
        self.log.append(("apply", party, regs[R8], net, user))
        out = regs[RDI]
        if case["apply_fail"] == party:
            self.fail_tag = 0x63
            memory.write(out, 2, 0x63)
            memory.write(out + 8, 8, 0x5A5A5A5A0000)
            memory.write(out + 0x58, 8, 0x1234FEDC)
            return
        memory.write(out, 2, OK_TAG)
        row = self.rows.get(user)
        if row is not None:
            where = self.find(row, case["asset"])
            if where is not None:
                memory.write(where + 0x10, 8, memory.read(where + 0x10, 8) + regs[R8])

    def on_hash_user(self, machine):
        regs = machine.regs
        self.check(regs[RDI] == CH + 0x148, "user hash state")
        regs[RAX] = user_hash(self.machine.memory.bytes_at(regs[RSI], 20), self.case)

    def on_hash_asset(self, machine):
        regs, memory = machine.regs, machine.memory
        self.check(regs[RDI] == self.inner_hasher, "asset hash state")
        regs[RAX] = asset_hash(memory.read(regs[RSI], 8), self.case)

    def on_total(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        handle = regs[RDI]
        root, height = memory.read(CH + 0x170, 8), memory.read(CH + 0x178, 8)
        if case["asset"] in case["assets"]:
            place, node, index = self.total_at
            self.check(memory.read(handle, 8) == 0 and memory.read(handle + 8, 8) == node and memory.read(handle + 0x10, 8) == case["node_height"] and memory.read(handle + 0x18, 8) == index and memory.read(handle + 0x20, 8) == CH + 0x170, "total handle")
        else:
            self.check(memory.read(handle, 8) == CH + 0x170 and memory.read(handle + 8, 8) == case["asset"], "total vacant")
            if root:
                node, level = root, height
                while True:
                    length = memory.read(node + 0xBA, 2)
                    index = 0
                    while index < length and memory.read(node + 8 + index * 8, 8) < case["asset"]:
                        index += 1
                    if not level:
                        break
                    node = memory.read(node + 0xC0 + index * 8, 8)
                    level -= 1
                self.check(memory.read(handle + 0x10, 8) == node and memory.read(handle + 0x18, 8) == 0 and memory.read(handle + 0x20, 8) == index, "total vacant place")
            else:
                self.check(memory.read(handle + 0x10, 8) == 0, "total vacant empty")
            place = self.bump(8)
            memory.write(place, 8, 0)
            self.total_at = (place, 0, 0)
        regs[RAX] = place

    def lay_row(self, user, row):
        memory = self.machine.memory
        base = self.bump(0x30)
        items = []
        for asset, (isolated, leverage, margin, size) in row["positions"].items():
            items.append((asset, (isolated, leverage, margin, size)))
        memory.write(base, 8, row["balance"])
        memory.write(base + 0x20, 8, row["count"])
        memory.write(base + 0x28, 8, 0x3131313131313131)

        def put(where, value):
            memory.put_bytes(where, bytes((at * 3 + 0x41) & 0xFF for at in range(0x40)))
            memory.write(where, 1, value[0])
            memory.write(where + 4, 4, value[1])
            memory.write(where + 8, 8, value[2])
            memory.write(where + 0x10, 8, value[3])
        root, height = build_tree(memory, self.bump, POSITIONS, sorted(items), put, self.case["stale"])
        memory.write(base + 8, 8, root)
        memory.write(base + 0x10, 8, height)
        memory.write(base + 0x18, 8, len(items))
        self.rows[user] = base

    def lay_tables(self):
        memory, case = self.machine.memory, self.case
        entries = []
        for user, table in case["table"].items():
            entries.append((user_hash(who(user), case), user))
        for index in range(case["decoys"]):
            twin = bytearray(who(case["party"][case["maker"]]))
            twin[(index * 7 + 16) % 20] ^= 0x40
            entries.insert(0, (user_hash(who(case["party"][case["maker"]]), case), bytes(twin)))
        outer_ctrl = {}

        def put_outer(at, payload):
            end = at + 0x50
            if isinstance(payload, bytes):
                memory.put_bytes(at, payload)
                return
            memory.put_bytes(at, who(payload))
            table = case["table"][payload]
            inner = []
            for asset in sorted(table["rows"]):
                inner.append((asset_hash(asset, case), (asset, table["rows"][asset])))
            for index in range(table["decoys"]):
                key = case["asset"] ^ (1 << (index * 13 % 64))
                inner.insert(0, (asset_hash(case["asset"], case), (key, None)))

            def put_inner(place, item):
                key, row = item
                memory.write(place, 8, key)
                if row is None:
                    return
                outer_ctrl[key] = place
                for at_word, name in ((8, "a"), (0x10, "b"), (0x18, "c"), (0x20, "d"), (0x28, "size"), (0x30, "k")):
                    memory.write(place + at_word, 8, row[name])
                memory.write(place + 0x38, 4, row["lev"])
            ctrl, mask = lay_table(memory, self.bump, inner, 0x40, put_inner, table["walls"])
            memory.write(end - 0x38, 8, ctrl)
            memory.write(end - 0x30, 8, mask)
            memory.write(end - 0x20, 8, table["inner_items"])
            memory.write(end - 8, 8, table["sum"])
            if payload == case["party"][case["maker"]]:
                self.inner_hasher = end - 0x18
                self.sum_at = end - 8
                self.rows_at = outer_ctrl
        ctrl, mask = lay_table(memory, self.bump, entries, 0x50, put_outer, case["walls"])
        memory.write(CH + 0x128, 8, ctrl)
        memory.write(CH + 0x130, 8, mask)
        memory.write(CH + 0x140, 8, case["outer_items"])

    def start(self, case):
        memory = self.machine.memory
        memory.reset(self.at - HEAP_BASE if self.at > BUMP else 0x4000)
        self.at = BUMP
        self.case = case
        self.rows, self.log, self.record = {}, [], []
        self.fee_seen = set()
        self.current = 0
        self.applied = 0
        self.fail_tag = 0
        self.entry = 0
        self.inner_hasher = 0
        self.sum_at = 0
        self.rows_at = {}
        memory.statics[ONCE_CELL] = case["once"]
        memory.write(CH + 0x238, 8, case["pool"])
        memory.write(CH + 0x2D8, 8, case["free"])
        memory.write(EMPTY_ROW + 8, 8, 0)
        memory.write(EMPTY_ROW + 0x10, 8, 0)
        for user, row in case["rows"].items():
            self.lay_row(user, row)
        self.lay_tables()
        memory.put_bytes(FILL, bytes((at * 5 + 3) & 0xFF for at in range(FILL_SIZE)))
        memory.put_bytes(FILL + 0xD8, who(case["party"][0]))
        memory.put_bytes(FILL + 0x1D8, who(case["party"][1]))
        memory.write(FILL + 0x200, 8, case["px"])
        memory.write(FILL + 0x208, 8, case["asset"])
        memory.write(FILL + 0x210, 8, case["sz"])
        memory.write(FILL + 0x218, 8, case["ntl"])
        memory.write(FILL + 0x234, 1, case["maker"])

    def run_hook(self, case):
        memory = self.machine.memory
        memory.reset(self.at - HEAP_BASE if self.at > BUMP else 0x4000)
        self.at = BUMP
        self.case = case
        self.record = []
        self.machine.real = HOOK_REAL
        items = sorted((asset, (case["total"] if asset == case["asset"] else 0x1111 + asset)) for asset in case["assets"])
        root, height = build_tree(memory, self.bump, TOTALS, items, lambda where, value: memory.write(where, 8, value), case["stale"])
        memory.write(CH + 0x170, 8, root)
        memory.write(CH + 0x178, 8, height)
        memory.write(CH + 0x20, 8, case["count"])
        self.total_at = None
        if case["asset"] in case["assets"]:

            def walk(node, level):
                length = memory.read(node + 0xBA, 2)
                for index in range(length):
                    if memory.read(node + 8 + index * 8, 8) == case["asset"]:
                        self.total_at = (node + 0x60 + index * 8, node, index)
                        case["node_height"] = level
                if level:
                    for index in range(length + 1):
                        walk(memory.read(node + 0xC0 + index * 8, 8), level - 1)
            walk(root, height)
        panic = None
        try:
            self.machine.run(SIZE_HOOK, {RDI: case["asset"], RSI: case["old"], RDX: case["new"], RCX: CH + 0x20, R8: CH + 0x170})
        except Panicked as stop:
            panic = stop.args[0]
        finally:
            self.machine.real = FILL_REAL
        total = memory.read(self.total_at[0], 8) if self.total_at else None
        return dict(count=memory.read(CH + 0x20, 8), total=total, record=self.record, panic=panic)

    def run(self, case):
        self.start(case)
        memory = self.machine.memory
        before = memory.bytes_at(FILL, FILL_SIZE)
        panic = None
        try:
            self.machine.run(FILL_FN, {RDI: CH, RSI: case["flag"] | 0x7700, RDX: FILL, RCX: CTX})
        except Panicked as stop:
            panic = stop.args[0]
        rows = {}
        for user, base in self.rows.items():
            root, height, count = (memory.read(base + at, 8) for at in (8, 0x10, 0x18))
            items = tree_items(memory, root, height)
            self.check(len(items) == count, "position count")
            rows[user] = dict(balance=memory.read(base, 8), count=memory.read(base + 0x20, 8),
                              positions={key: [memory.read(where, 1), memory.read(where + 4, 4), memory.read(where + 8, 8), memory.read(where + 0x10, 8)] for key, where in items})
        active = None
        if self.sum_at:
            active = dict(total=memory.read(self.sum_at, 8), sizes={asset: memory.read(place + 0x28, 8) for asset, place in self.rows_at.items()})
        return dict(log=self.log, record=self.record, rows=rows, pool=memory.read(CH + 0x238, 8), free=memory.read(CH + 0x2D8, 8), panic=panic,
                    block=memory.bytes_at(FILL, FILL_SIZE), before=before, active=active)


def user_hash(key, case):
    if case["collide"]:
        return 0x2A00000000000000 | 5
    return int.from_bytes(key[:8], "little") * 0x9E3779B97F4A7C15 & MAX


def asset_hash(key, case):
    if case["collide"]:
        return 0x1500000000000000 | 9
    return (key * 0x9E3779B97F4A7C15 + 0x1234) & MAX


def record_image(row, party):
    """0x78 output bytes; filler differs by party so a crossed copy shows."""
    data = bytearray((at * 7 + 0x21 + party * 13) & 0xFF for at in range(OUT_SIZE))
    struct.pack_into("<Q", data, 0, 0xA5B4C300 | row["builder_tag"])
    struct.pack_into("<Q", data, 8, row["builder"])
    struct.pack_into("<I", data, 0x28, row["referrer_tag"])
    struct.pack_into("<Q", data, 0x30, row["referrer"])
    struct.pack_into("<Q", data, 0x50, row["gross"])
    struct.pack_into("<Q", data, 0x58, row["rebate"])
    struct.pack_into("<Q", data, 0x60, row["extra"])
    struct.pack_into("<Q", data, 0x68, row["deployer"])
    struct.pack_into("<Q", data, 0x70, row["protocol"])
    return bytes(data)


def compare_hook(harness, case):
    want = hook_spec(case)
    try:
        got = harness.run_hook(case)
    except (Halt, EvidenceError, KeyError, IndexError, TypeError) as error:
        return "fault: %s" % str(error)[:60]
    if got["count"] != want["count"] or got["record"] != want["record"] or got["panic"] != want["panic"]:
        return "hook words differ"
    if want["total"] is not None and signed(got["total"]) != want["total"]:
        return "hook total differs"
    return ""


def compare_run(harness, case):
    if case["kind"] == "size hook":
        return compare_hook(harness, case)
    want = spec(case, harness.privileged)
    try:
        got = harness.run(case)
    except (Halt, EvidenceError, KeyError, IndexError, ZeroDivisionError, OverflowError, StopIteration, TypeError) as error:
        return "fault: %s" % str(error)[:60]
    for name in ("log", "record", "panic"):
        if got[name] != want[name]:
            return "%s differ" % name
    if got["pool"] != want["pool"] or got["free"] != want["free"]:
        return "words differ"
    if got["rows"] != want["rows"]:
        return "rows differ"
    expected = bytearray(got["before"])
    for party in want["blocks"]:
        base = party * PARTY_SIZE
        expected[base + 0x58:base + 0xD0] = record_image(case["records"][party], party)
    if bytes(expected) != got["block"]:
        return "party block differs"
    if got["active"] is not None:
        sizes = {asset: row["size"] for asset, row in case["table"][case["party"][case["maker"]]]["rows"].items()} if case["party"][case["maker"]] in case["table"] else {}
        total = case["table"][case["party"][case["maker"]]]["sum"] if case["party"][case["maker"]] in case["table"] else 0
        if want["active"]:
            _, asset, new_size, total = want["active"]
            sizes[asset] = new_size
        if got["active"]["total"] != total or got["active"]["sizes"] != sizes:
            return "margin row differs"
    return ""


# ---- vectors ----

BUYER, SELLER, OTHER = 3, 4, 9
ASSET = 0x2A
SIDE = 0x7B


def fee_row(gross=0, rebate=0, builder_tag=0, builder=0, referrer_tag=0, referrer=0, extra=0, deployer=0, protocol=0):
    return dict(gross=gross, rebate=rebate, builder_tag=builder_tag, builder=builder, referrer_tag=referrer_tag, referrer=referrer, extra=extra, deployer=deployer, protocol=protocol)


NONE = fee_row()
PLAIN = fee_row(gross=9000, deployer=2500, protocol=6500)
MAKER = fee_row(rebate=1500)
PAID = fee_row(gross=9000, builder_tag=1, builder=100, referrer_tag=1, referrer=70, extra=40, deployer=2500, protocol=6290)


def account(balance=10 ** 9, count=1, positions=None):
    return dict(balance=balance, count=count, positions={ASSET: (0, 7, 0, 500)} if positions is None else positions)


def margin_row(a=4000000, b=2000000, c=4000, d=2000, size=0, k=0, lev=5):
    return dict(a=a, b=b, c=c, d=d, size=size, k=k, lev=lev)


def margin(total=5000, rows=None, inner_items=1, decoys=0, walls=(0, 0)):
    return dict(sum=total, rows={ASSET: margin_row()} if rows is None else rows, inner_items=inner_items, decoys=decoys, walls=walls)


def world(label, **over):
    case = dict(label=label, kind="fill", party=(BUYER, SELLER), maker=0, asset=ASSET, px=0x1234567, sz=300, ntl=777000, flag=1,
                records=(PLAIN, PLAIN), rows={BUYER: account(), SELLER: account()}, pool=10 ** 12, free=55, once=0,
                next_count=(1, 1), apply_fail=None, table={}, outer_items=0, walls=(0, 0), decoys=0, collide=False, stale=(), alien=None)
    case.update(over)
    return case


def with_margin(label, table=None, maker=0, **over):
    table = margin() if table is None else table
    party = over.get("party", (BUYER, SELLER))
    return world(label, table={party[maker]: table}, outer_items=1, maker=maker, **over)


def fee_cases():
    rows = [world("plain fill"), world("no fee words", records=(NONE, NONE)), world("rebate maker", records=(PLAIN, MAKER)), world("rebate first", records=(MAKER, PLAIN)),
            world("paid words", records=(PAID, PAID)), world("flag zero", flag=0), world("maker 1", maker=1), world("zero size", sz=0),
            world("builder tag 2", records=(fee_row(gross=9, builder_tag=2, builder=500, deployer=3), NONE)), world("builder tag 3", records=(fee_row(gross=9, builder_tag=3, builder=500, deployer=3), NONE)),
            world("referrer tag 0x101", records=(fee_row(gross=9, referrer_tag=0x101, referrer=500, deployer=3), NONE)), world("referrer tag 0x10000", records=(fee_row(gross=9, referrer_tag=0x10001, referrer=500, deployer=3), NONE)),
            world("referrer tag 2", records=(fee_row(gross=9, referrer_tag=2, referrer=500, deployer=3), NONE)),
            world("isolated", rows={BUYER: account(positions={ASSET: (1, 3, 8000, 500)}), SELLER: account(positions={ASSET: (2, 3, 8000, -500 & MAX)})}),
            world("isolated rebate", records=(PLAIN, MAKER), rows={BUYER: account(positions={ASSET: (1, 3, 8000, 500)}), SELLER: account(positions={ASSET: (1, 3, 8000, 500)})}),
            world("no row", rows={}),
            world("no position", rows={BUYER: account(positions={}), SELLER: account(positions={7: (0, 3, 0, 1), 100: (0, 3, 0, 2)})}),
            world("full leaf vacant", rows={BUYER: account(positions={at * 2 + 1: (0, 2, 0, at) for at in range(10)}), SELLER: account(positions={at * 200: (0, 2, 0, at) for at in range(1, 11)})}),
            world("count to zero", next_count=(0, 0)), world("count from zero", rows={BUYER: account(count=0), SELLER: account(count=0)}), world("count stays zero", next_count=(0, 0), rows={BUYER: account(count=0), SELLER: account(count=0)}),
            world("count mix", next_count=(0, 5), rows={BUYER: account(count=4), SELLER: account(count=0)}),
            world("same user", party=(BUYER, BUYER), rows={BUYER: account()}),
            world("once busy", records=(NONE, NONE), once=1), world("once other value", records=(NONE, NONE), once=3), world("once ignored with fee", once=1),
            world("zero total sum", records=(fee_row(deployer=5), fee_row(protocol=-5 & MAX))),
            world("zero total deployer sum", records=(fee_row(deployer=5), fee_row(deployer=-5 & MAX))),
            world("free carry", records=(NONE, NONE), free=MAX - 5, ntl=6), world("free top exact", records=(NONE, NONE), free=MAX - 5, ntl=5), world("free carry far", records=(NONE, NONE), free=MAX, ntl=MAX),
            world("negative deployer", records=(fee_row(gross=4, deployer=-1 & MAX, protocol=5), NONE)),
            ]
    for party in (0, 1):
        for name, row in (("gross", fee_row(gross=HALF)), ("rebate", fee_row(rebate=HALF)), ("extra", fee_row(extra=HALF)), ("builder", fee_row(builder_tag=1, builder=MAX)), ("referrer", fee_row(referrer_tag=1, referrer=HALF + 5))):
            rows.append(world("negative %s %d" % (name, party), records=tuple(row if at == party else PLAIN for at in (0, 1))))
        rows.append(world("apply fails %d" % party, apply_fail=party))
        rows.append(world("exempt %d" % party, party=tuple(-1 if at == party else (BUYER, SELLER)[at] for at in (0, 1)), rows={BUYER: account(), SELLER: account()}))
        rows.append(world("exempt no fee words %d" % party, records=(NONE, NONE), party=tuple(-2 if at == party else (BUYER, SELLER)[at] for at in (0, 1))))
        rows.append(world("exempt negative size %d" % party, sz=-3 & MAX, party=tuple(-1 if at == party else (BUYER, SELLER)[at] for at in (0, 1))))
        rows.append(world("exempt zero size %d" % party, sz=0, party=tuple(-1 if at == party else (BUYER, SELLER)[at] for at in (0, 1))))
        rows.append(world("exempt fails %d" % party, apply_fail=party, party=tuple(-1 if at == party else (BUYER, SELLER)[at] for at in (0, 1))))
    rows.append(world("negative size", sz=-3 & MAX))
    rows.append(world("exempt pair", party=(-1, -2), rows={}))
    rows.append(world("exempt pair no fee", party=(-3, -4), rows={}, records=(NONE, NONE)))
    for index in range(8):
        rows.append(world("exempt %d" % index, party=(-index - 1, SELLER), rows={SELLER: account()}))
    # balance and pool saturation, both directions
    for name, value, fee in (("low", HALF, fee_row(gross=5)), ("low exact", HALF + 5, fee_row(gross=5)), ("high", HALF - 2, fee_row(rebate=5)), ("high exact", HALF - 6, fee_row(rebate=5))):
        rows.append(world("balance %s" % name, rows={BUYER: account(balance=value), SELLER: account()}, records=(fee, NONE)))
        rows.append(world("margin %s" % name, rows={BUYER: account(positions={ASSET: (1, 3, value, 500)}), SELLER: account()}, records=(fee, NONE)))
    for name, fee in (("extra", fee_row(extra=9)), ("builder", fee_row(builder_tag=1, builder=9)), ("referrer", fee_row(referrer_tag=1, referrer=9))):
        for pool in (HALF + 3, HALF, HALF + 9):
            rows.append(world("pool %s %#x" % (name, pool), pool=pool, records=(fee, NONE)))
    rows.append(world("pool all words", pool=HALF + 2, records=(fee_row(extra=9, builder_tag=1, builder=9, referrer_tag=1, referrer=9), NONE)))
    rows.append(world("pool small", pool=3, records=(PAID, PAID)))
    big = HALF - 3
    for name, one, two in (("deployer up", fee_row(deployer=big), fee_row(deployer=big)), ("deployer down", fee_row(deployer=HALF), fee_row(deployer=-1 & MAX)),
                           ("protocol up", fee_row(protocol=big), fee_row(protocol=big)), ("protocol down", fee_row(protocol=HALF), fee_row(protocol=-1 & MAX)),
                           ("both up", fee_row(deployer=big, protocol=big), fee_row(deployer=big, protocol=big)),
                           ("total up", fee_row(deployer=big), fee_row(protocol=big)), ("total down", fee_row(deployer=HALF), fee_row(protocol=HALF)), ("total down one", fee_row(deployer=HALF + 1), fee_row(protocol=-2 & MAX)),
                           ("total min only", fee_row(deployer=HALF), fee_row(protocol=HALF + 1))):
        rows.append(world(name, records=(one, two)))
    # position tree shapes: the asset sits at every place of 1, 2 and 3 level trees
    for count in (1, 2, 11, 12, 13, 30, 200):
        keys = [at * 16 + 5 for at in range(count)]
        for at in sorted({0, min(1, count - 1), count // 3, count // 2, count - 1}):
            positions = {key: (0, 4, 0, key) for key in keys}
            rows.append(world("tree %d at %d" % (count, at), asset=keys[at], rows={BUYER: account(positions=positions), SELLER: account(positions=dict(positions))}))
        for shift in (-2, 2):
            asset = keys[count // 2] + shift
            rows.append(world("tree %d near %d" % (count, shift), asset=asset, rows={BUYER: account(positions={key: (0, 4, 0, key) for key in keys}), SELLER: account()}))
        rows.append(world("tree %d past end" % count, asset=keys[-1] + 3, rows={BUYER: account(positions={key: (0, 4, 0, key) for key in keys}), SELLER: account(positions={key: (0, 4, 0, key) for key in keys})}, stale=(0, MAX, keys[0], 1 << 40)))
    rows.append(world("high asset key", asset=HALF + 44, rows={BUYER: account(positions={7: (0, 3, 0, 1), HALF + 44: (0, 3, 0, 2), MAX - 1: (0, 3, 0, 3)}), SELLER: account()}))
    return rows


def margin_cases():
    rows = [with_margin("margin plain"), with_margin("margin maker 1", maker=1), with_margin("margin held size", table=margin(rows={ASSET: margin_row(size=500)})),
            with_margin("margin empty outer"), world("margin no outer items", table={BUYER: margin()}, outer_items=0),
            world("margin other user", table={OTHER: margin()}, outer_items=1), with_margin("margin no inner items", table=margin(inner_items=0)),
            with_margin("margin other asset", table=margin(rows={ASSET + 1: margin_row()})), with_margin("margin inner other asset many", table=margin(rows={at * 3 + 1: margin_row(a=at + 1) for at in range(40)})),
            with_margin("margin decoy users", decoys=9, collide=True), with_margin("margin decoy assets", table=margin(decoys=9), collide=True),
            with_margin("margin decoys wide", table=margin(decoys=20), decoys=20, collide=True),
            with_margin("margin walls one", walls=(5, 21), table=margin(walls=(9, 25)), collide=True), with_margin("margin walls two", walls=(5, 37), table=margin(walls=(9, 41)), collide=True),
            with_margin("margin walls outer", walls=(5, 37), collide=True), with_margin("margin walls inner", table=margin(walls=(9, 41)), collide=True),
            with_margin("margin miss after decoys", table=margin(decoys=30, rows={}), decoys=0, collide=True),
            world("margin user miss after decoys", table={OTHER: margin()}, outer_items=1, decoys=30, collide=True),
            with_margin("margin position gone", rows={BUYER: account(positions={}), SELLER: account()}),
            with_margin("margin other assets", rows={BUYER: account(positions={1: (0, 2, 0, 4), ASSET: (0, 2, 0, 9), 99: (0, 2, 0, 5)}), SELLER: account()}),
            with_margin("margin no row maker exempt", party=(-1, SELLER), rows={SELLER: account()}, table=margin(rows={ASSET: margin_row(size=500)})),
            world("margin no row exempt no items", party=(-1, SELLER), rows={SELLER: account()}, table={-1: margin(rows={ASSET: margin_row(size=500)})}, outer_items=0),
            with_margin("margin exempt tree miss", party=(-1, SELLER), rows={-1: account(positions={at * 2 + 1: (0, 2, 0, at + 1) for at in range(40) if at * 2 + 1 != ASSET}), SELLER: account()}, table=margin(rows={ASSET: margin_row(size=500)})),
            with_margin("margin exempt leaf miss", party=(-1, SELLER), rows={-1: account(positions={at * 2 + 1: (0, 2, 0, at + 1) for at in range(8) if at * 2 + 1 != ASSET}), SELLER: account()}, table=margin(rows={ASSET: margin_row(size=500)})),
            with_margin("margin exempt stale", stale=(ASSET, ASSET + 1), party=(-1, SELLER), rows={-1: account(positions={1: (0, 2, 0, 1), 2: (0, 2, 0, 3)}), SELLER: account()}, table=margin(rows={ASSET: margin_row(size=500)})),
            with_margin("margin exempt leaf low", party=(-1, SELLER), rows={-1: account(positions={1: (0, 2, 0, 1), 2: (0, 2, 0, 3)}), SELLER: account()}, table=margin(rows={ASSET: margin_row(size=500)})),
            with_margin("margin exempt leaf high", party=(-1, SELLER), rows={-1: account(positions={1000: (0, 2, 0, 1), 2000: (0, 2, 0, 3)}), SELLER: account()}, table=margin(rows={ASSET: margin_row(size=500)})),
            with_margin("margin exempt has size", party=(-1, SELLER), rows={-1: account(positions={1: (0, 2, 0, 1), ASSET: (0, 2, 0, 700), 2000: (0, 2, 0, 3)}), SELLER: account()}, table=margin(rows={ASSET: margin_row(size=500)})),
            with_margin("margin position tree", rows={BUYER: account(positions={at * 2: (0, 2, 0, at + 1) for at in range(40)}), SELLER: account()}),
            with_margin("margin miss tree", asset=ASSET + 1, table=margin(rows={ASSET + 1: margin_row()}), rows={BUYER: account(positions={at * 2: (0, 2, 0, at + 1) for at in range(40)}), SELLER: account()}),
            ]
    shapes = []
    for name, row in (("k", margin_row(k=3, size=-200 & MAX)), ("k up", margin_row(k=3, size=200)), ("k big", margin_row(k=2000, size=100)), ("k over 2p", margin_row(k=20000, size=100)),
                      ("no count", margin_row(c=0, d=0, size=100)), ("no count neg", margin_row(c=0, d=0, size=-100 & MAX)), ("count above big", margin_row(c=4000001, d=2000001, size=7)),
                      ("count equal big", margin_row(a=500, b=500, c=500, d=500, size=2)), ("size wall", margin_row(c=100, d=100, size=50)), ("size past wall", margin_row(c=100, d=100, size=51)),
                      ("size min", margin_row(size=HALF)), ("k size min", margin_row(k=1, size=HALF)), ("product limit", margin_row(a=MAX, b=MAX, c=2, d=2, k=LIMIT, size=1)), ("product past limit", margin_row(a=MAX, b=MAX, c=8, d=8, k=LIMIT + 1, size=1)),
                      ("product carry", margin_row(a=MAX, b=MAX, c=1 << 40, d=1 << 40, k=1 << 33, size=1 << 31)), ("wide words", margin_row(a=1 << 40, b=1 << 41, c=1 << 34, d=1 << 35, size=3)), ("wide divisor", margin_row(a=(1 << 34) + 7, b=(1 << 33) + 5, lev=7)),
                      ("wide lev", margin_row(a=(1 << 34) + 7, b=(1 << 33) + 5, lev=0xFFFFFFF1)), ("high bit lev", margin_row(lev=0x80000001)), ("total over limit", margin_row(a=1 << 63, b=1 << 63, c=2, d=2, size=0)),
                      ("total at limit", margin_row(a=LIMIT, b=LIMIT, c=1, d=1, size=0)), ("total past limit", margin_row(a=LIMIT + 1, b=LIMIT + 1, c=1, d=1, size=0)), ("low above value", margin_row(a=10, b=9000, c=5, d=5, size=1)), ("low above value 2", margin_row(a=9000, b=10, c=5, d=5, size=1)),
                      ("min by value", margin_row(a=1000, b=1000, c=10, d=10, k=1, size=2)), ("min by big", margin_row(a=1000, b=1000, c=10, d=10, k=200, size=2)), ("zero size k", margin_row(k=9, size=0)), ("count high only", margin_row(c=0, d=9, size=1)), ("count low only", margin_row(c=9, d=0, size=1)),
                      ("count high only neg", margin_row(c=0, d=9, size=-1 & MAX)), ("count low only neg", margin_row(c=9, d=0, size=-1 & MAX)), ("doubled equals big", margin_row(a=1000, b=1000, c=10, d=10, k=50, size=10)), ("doubled equals count", margin_row(a=1000, b=1000, c=20, d=20, k=1, size=10))):
        shapes.append((name, row))
    for name, row in shapes:
        for fill_size, label in ((300, "up"), (0, "flat")):
            rows.append(with_margin("margin %s %s" % (name, label), table=margin(rows={ASSET: row}), sz=fill_size))
            rows.append(with_margin("margin %s %s maker 1" % (name, label), maker=1, table=margin(rows={ASSET: row}), sz=fill_size))
    new_sizes = (0, 1, 50, 51, 100, 2000, 4000, 4001, HALF - 1, HALF, HALF + 1, MAX, MAX - 49, MAX - 50, MAX - 1999, MAX - 3999)
    for at, held in enumerate(new_sizes):
        for name, row in (("plain", margin_row(k=1, c=100, d=100, size=at)), ("no k", margin_row(a=1 << 40, b=1 << 41, c=1 << 30, d=1 << 31, size=at)), ("wide", margin_row(a=1 << 40, b=(1 << 40) + 9, c=1 << 35, d=1 << 34, k=2, size=at * 3))):
            rows.append(with_margin("margin new %s %d" % (name, at), table=margin(rows={ASSET: row}), rows={BUYER: account(positions={ASSET: (0, 2, 0, held)}), SELLER: account()}, sz=0))
    for name, total, row in (("carry", MAX, margin_row(size=0, a=1 << 40, c=4)), ("carry floor", MAX, margin_row(size=-1000 & MAX, a=1 << 40, c=4)), ("floor", 0, margin_row(size=1000)), ("floor exact", 400000, margin_row(size=-1000 & MAX, b=1 << 20, d=1 << 3, c=0)), ("top exact", MAX - 400000, margin_row())):
        rows.append(with_margin("margin sum %s" % name, table=margin(total=total, rows={ASSET: row}), rows={BUYER: account(positions={ASSET: (0, 2, 0, 0)}), SELLER: account()}, sz=7))
    gap = (HALF - 1) // 7 + 2
    for name, row, held in (("limit product", margin_row(a=0, b=MAX, c=4, d=4, k=HALF - 1, size=1, lev=1), 0), ("limit after min", margin_row(a=1, b=7 * gap, c=1, d=gap, size=HALF, lev=1), 1),
                            ("min wall", margin_row(a=MAX, b=0, c=MAX, d=1, size=HALF, lev=1), 0), ("min wall new", margin_row(a=MAX, b=0, c=MAX, d=1, size=0, lev=1), HALF),
                            ("short count", margin_row(a=0, b=900, c=4, d=4, size=0, lev=1), 1), ("short count old", margin_row(a=0, b=900, c=4, d=4, size=1, lev=1), 0),
                            ("short count neg", margin_row(a=900, b=0, c=4, d=4, size=0, lev=1), MAX), ("short count neg old", margin_row(a=900, b=0, c=4, d=4, size=MAX, lev=1), 0)):
        rows.append(with_margin("margin edge %s" % name, table=margin(total=1 << 40, rows={ASSET: row}), rows={BUYER: account(positions={ASSET: (0, 2, 0, held)}), SELLER: account()}, sz=0))
    seed = 0x1B873593
    words = (0, 1, 7, 1000, 1 << 20, (1 << 32) - 1, 1 << 32, (1 << 33) + 3, 1 << 40, 1 << 62, HALF - 3, HALF, MAX)
    for index in range(260):
        picks = []
        for _ in range(9):
            seed = (seed * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MAX
            picks.append(seed >> 33)
        row = margin_row(a=words[picks[0] % 13], b=words[picks[1] % 13], c=words[picks[2] % 11], d=words[picks[3] % 11], k=(0, 1, 3, 1 << 20, 1 << 33)[picks[4] % 5],
                         size=(picks[5] % 5000 - 2500) & MAX, lev=1 + picks[6] % 40)
        rows.append(with_margin("margin random %d" % index, maker=picks[7] & 1, table=margin(total=picks[8] << 8, rows={ASSET: row}), sz=picks[6] % 3000))
    return rows


def hook_cases():
    rows = []
    sizes = (0, 1, 5, HALF - 1, MAX, MAX - 4, HALF + 1, HALF)
    for old in sizes:
        for new in sizes:
            for count, total in ((0, 0), (1, 100), (5, HALF - 3), (MAX, HALF + 2)):
                rows.append(dict(label="hook %#x %#x %d" % (old, new, count), kind="size hook", old=old, new=new, count=count, total=total, asset=33, assets=(5, 33, 90), stale=()))
    for count in (0, 1, 11, 12, 40, 200):
        keys = [at * 8 + 1 for at in range(count)]
        for asset in ([keys[count // 2], keys[-1], keys[0], keys[-1] + 4, keys[count // 2] + 2, keys[0] - 1] if count else [7]):
            rows.append(dict(label="hook tree %d %d" % (count, asset), kind="size hook", old=3, new=4, count=2, total=50, asset=asset, assets=tuple(keys), stale=(asset, 0, MAX)))
    return rows


def all_cases():
    return fee_cases() + margin_cases() + hook_cases()


FILL_REAL = frozenset((FILL_FN, PREDICATE))
HOOK_REAL = frozenset((SIZE_HOOK,))
REAL = (FILL_FN, PREDICATE, SIZE_HOOK)
FUNCTIONS = (("perp fill settlement", FILL_FN), ("open position count and asset total", SIZE_HOOK))
HELPERS = (("exempt address test", PREDICATE),)
STUBS = (
    ("0x37130b0", "fee of one party, slot 0x5774890", "fees-trade-fee-94; whole frame checked, output bytes come from the vector"),
    ("0x37067b0", "dex fee credit, slot 0x5774918", "fees-collection-94; arguments listed and compared"),
    ("0x3596940", "user row of clearinghouse +0xf8, inserts", "row created on a miss"),
    ("0x36f57f0", "user row, read only", "a shared empty row on a miss"),
    ("0x339b590", "address set insert", "called with clearinghouse +0x188 and +0x158; listed and compared"),
    ("0x33acfe0", "address set remove", "called with clearinghouse +0x158; listed and compared"),
    ("0x33bd420", "position entry by search handle", "handle words checked against an independent tree walk; a vacant handle inserts a default value"),
    ("0x36f7350", "size hook, stub in the fill vectors", "run real in its own size hook vectors; in fill vectors arguments checked and row +0x20 is forced from the vector"),
    ("0x33bc4d0", "asset total entry", "handle checked against an independent tree walk; runs under the real size hook only"),
    ("0x370e6a0", "leverage hook", "never called: its gate compares two reads of value +4 around one store that cannot touch +4"),
    ("0x36fe830", "position update of the fill", "arguments checked; adds the signed size or returns an error tag"),
    ("0x399c7a0", "address hash", "a test hash, hasher place checked"),
    ("0x399c4a0", "asset hash", "a test hash, hasher place checked"),
    ("0x358dcd0", "amount recorder, slot 0x5773190", "every call listed and compared"),
)


# ---- mutation survey ----

def stepped_groups(image):
    return [(role, begin, image.exact_fde(begin)[1]) for role, begin in FUNCTIONS]


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
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for role, begin, end in stepped_groups(image):
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

def direct_callers(image, targets):
    """Call sites by e8 byte pattern; the target must be an FDE start."""
    base, code = image.text_bytes()
    out = []
    wanted = set(targets)
    at = code.find(b"\xe8")
    while at >= 0:
        if at + 5 <= len(code):
            target = base + at + 5 + struct.unpack_from("<i", code, at + 1)[0]
            if target in wanted:
                out.append((base + at, target))
        at = code.find(b"\xe8", at + 1)
    return sorted(out)


def slot_callers(image, slots):
    """`call [rip + disp]` sites, ff 15 pattern, through named data slots."""
    base, code = image.text_bytes()
    out = []
    at = code.find(b"\xff\x15")
    while at >= 0:
        if at + 6 <= len(code):
            slot = base + at + 6 + struct.unpack_from("<i", code, at + 2)[0]
            if slot in slots:
                out.append((base + at, slot))
        at = code.find(b"\xff\x15", at + 1)
    return sorted(out)


def caller_rows(image):
    relative = relative_slots(image)
    rows = []
    for name, target in (("fill apply", FILL_FN), ("exempt test", PREDICATE)):
        slots = {slot for slot, value in relative.items() if value == target}
        for site, slot in slot_callers(image, slots):
            rows.append((name, "%#x" % site, "%#x" % image.fde(site)[0], "slot %#x" % slot))
    return rows


LOCATIONS = (
    (LOC_NET, "panic", "negative gross, rebate, extra, builder or referrer word"),
    (LOC_SZ, "panic", "negative fill size"),
    (LOC_APPLY, "panic", "position update returned another tag than 0x186"),
    (LOC_BALANCE, "recorder kind 0", "balance or isolated margin saturates"),
    (LOC_POOL, "recorder kind 0", "clearinghouse +0x238 saturates"),
    (LOC_DEPLOYER, "recorder kind 0", "deployer or protocol sum saturates"),
    (LOC_TOTAL, "recorder kind 0", "deployer plus protocol saturates in the zero test"),
    (LOC_FREE, "recorder kind 0", "clearinghouse +0x2d8 saturates"),
    (LOC_DOUBLE, "recorder kind 0", "2 x size saturates"),
    (LOC_SUM, "recorder kind 0", "maker sum saturates at the top or at 0"),
)


def location_rows(image):
    relative = relative_slots(image)
    rows = []
    for slot, kind, meaning in LOCATIONS:
        path, line, column = image.location(slot, relative)
        rows.append(("%#x" % slot, kind, path, line, column, meaning))
    return rows


def privileged_rows(image):
    return [(index, "%#x" % head, "%#x" % tail, value.hex()) for index, ((head, tail), value) in enumerate(zip(PRIVILEGED_BYTES, privileged_addresses(image)))]


PINS = (
    ("0x3710a93", "488b8218020000", "fill +0x218 is the notional given to the fee slot"),
    ("0x3710abf", "0fb68234020000", "fill +0x234 is the maker party index"),
    ("0x3710cf8", "0f9484249c000000", "fee frame +0x4c: sete on party == fill +0x234"),
    ("0x3710f1b", "488b6810", "position value +0x10, size, read before the balance store"),
    ("0x3710f23", "803800", "position value byte +0: 0 picks row +0, else value +8"),
    ("0x3710f2a", "8b4004", "position value +4 read before the balance store"),
    ("0x3710f5a", "498b542410", "the same size word read again after the store"),
    ("0x3710f5f", "458b642404", "the same +4 word read again after the store"),
    ("0x371107e", "498b9e38020000", "pool word at clearinghouse +0x238"),
    ("0x37113c3", "488b9bd8020000", "clearinghouse +0x2d8 read in the zero fee arm"),
    ("0x37113f1", "ff1521350602", "call through slot 0x5774918, the dex fee credit"),
    ("0x37116ba", "49f7e7", "unsigned product K * |size|"),
    ("0x371172f", "4d01ff", "2 * |size|, old value"),
    ("0x371173b", "4d01d2", "2 * product, old value"),
    ("0x3711892", "49895df8", "maker sum stored at outer entry end -8"),
    ("0x36f736d", "0f85b3000000", "size hook: old 0 and new not 0 goes to the count increment"),
    ("0x370c810", "498b9738020000", "serializer: clearinghouse +0x238 right after the key total_net_deposit"),
    ("0x370c855", "498b9740020000", "serializer: clearinghouse +0x240 right after the key total_non_bridge_deposit"),
    ("0x370ca1c", "4d8b87d8020000", "serializer: clearinghouse +0x2d8 right before the key znfn"),
)


def pin_rows(image):
    rows = []
    for va, hexa, text in PINS:
        start = image.offset(int(va, 16))
        want = bytes.fromhex(hexa.replace(" ", ""))
        data = bytes(image.blob[start:start + len(want)])
        if data != want:
            raise EvidenceError("pin %s: %s" % (va, data.hex()))
        rows.append((va, data.hex(), text))
    return rows


SERDE = ((0x370C7F2, 0x598C55, 0x11, 0x238), (0x370C837, 0x598C66, 0x18, 0x240), (0x370CA23, 0x209E9C, 4, 0x2D8))


def serde_rows(image):
    """Field names from the rip lea of each key inside serializer 0x370c340; lengths are the immediates beside it."""
    rows = []
    for site, key, length, field in SERDE:
        data = bytes(image.blob[image.offset(site):image.offset(site) + 7])
        if data[:2] != b"\x48\x8d" or site + 7 + struct.unpack_from("<i", data, 3)[0] != key:
            raise EvidenceError("key lea %#x" % site)
        text = bytes(image.blob[image.offset(key):image.offset(key) + length]).decode()
        rows.append(("%#x" % field, text, "%#x" % site, "%#x" % key))
    return rows


def path_rows():
    return (
        (1, "caller", "0x26ed0ec, 0x4312265, 0x4315ec5, 0x37087ed", "slot 0x5774868; rdi is a dex clearinghouse (row of stride 0x2f0 in the 3 match hosts), esi one byte, rdx the fill, rcx ctx"),
        (2, "exempt test", "0x37e4fb0", "slot 0x5773228 on each party address, party 0 first: 8 fixed addresses; a hit skips every fee step and sets a flag; the size must still be >= 0"),
        (3, "fee", "0x37130b0", "slot 0x5774890, frame: party +0x20..+0x48, ctx, asset, user, s = party == fill +0x234, party, flag; notional fill +0x218"),
        (4, "sign gate", "0x3710a70", "gross and rebate must be >= 0 as i64, else panic at 0x5714c10"),
        (5, "row and dirty mark", "0x3596940, 0x339b590", "row of clearinghouse +0xf8, created on a miss; user goes into set +0x188"),
        (6, "position entry", "0x33bd420", "inline B-tree search of row +8 by asset, then entry by handle; a vacant asset inserts a value"),
        (7, "fee debit", "0x3710a70", "net = gross - rebate; value byte +0 == 0: row +0 -= net; else value +8 -= net; signed saturating, recorder 0x56f1cf8"),
        (8, "position wrapper", "0x36f7350", "asset, size, the same size, row +0x20, clearinghouse +0x170: a size that does not move changes no count and no total; only the asset total entry appears"),
        (9, "dead arms", "0x370e6a0, 0x33acfe0, 0x339b590", "leverage hook and set +0x158 follow value +4 and row +0x20, which this site cannot move"),
        (10, "deposit total", "0x3710a70", "clearinghouse +0x238 total_net_deposit falls by extra (skipped at 0), builder (tag bit 0), referrer (tag dword == 1); sign gate on each; saturating, recorder 0x5714c28"),
        (11, "sums", "0x3710a70", "deployer and protocol words of both parties, signed saturating, recorder 0x570b4e0"),
        (12, "party block", "0x3710a70", "whole 0x78 byte fee output stored at party +0x58..+0xd0"),
        (13, "size gate", "0x3710a70", "fill +0x210 must be >= 0 as i64, else panic at 0x56ee580; party 0 gets +size, party 1 gets -size"),
        (14, "position update", "0x36fe830", "(out, clearinghouse, asset, fill +0x200, signed size, user, stack word net or 0); a tag other than 0x186 panics at 0x56f1f90"),
        (15, "znfn", "0x3710a70", "no exempt party and deployer + protocol == 0: clearinghouse +0x2d8 (key znfn) += notional, unsigned saturating, recorder 0x5714d30; lazy cell 0x577ab98 forced first"),
        (16, "credit", "0x37067b0", "slot 0x5774918 (clearinghouse, deployer sum, protocol sum, ctx) on every fill, also at 0"),
        (17, "maker margin", "0x36f57f0, 0x3710a70", "maker size read from its row; outer map +0x128 by user, inner by asset; row size replaced, outer entry end -8 += f(new) - f(old)"),
    )


def word_rows():
    return (
        ("+0x00", "bit 0 of low byte", "builder present"),
        ("+0x08", "i64 >= 0", "builder amount; leaves total_net_deposit"),
        ("+0x28", "dword == 1", "referrer present; 2 and 0x101 do not count"),
        ("+0x30", "i64 >= 0", "referrer amount; leaves total_net_deposit"),
        ("+0x50", "i64 >= 0", "gross; debited from the party"),
        ("+0x58", "i64 >= 0", "rebate; credited to the party through net"),
        ("+0x60", "i64 >= 0, skipped at 0", "extra; leaves total_net_deposit"),
        ("+0x68", "any i64", "deployer part; summed, no sign gate"),
        ("+0x70", "any i64", "protocol part; summed, no sign gate"),
    )


def margin_rows():
    return (
        ("s > 0", "big = end -0x30, small = end -0x38, count = end -0x20"),
        ("s <= 0", "big = end -0x38, small = end -0x30, count = end -0x28"),
        ("product", "p = K * |s|, K = end -0x10; p above 2^63 - 2 or a carry gives value 0"),
        ("gate", "count == 0, count > big gives value 0"),
        ("doubles", "2 * |s| saturates with a recorder call; big < 2p or count < 2|s| gives value 0"),
        ("value", "w = floor(big / count) * (count - 2|s|); w above 2^63 - 2 gives 0, else min(w, big - 2p)"),
        ("result", "f(s) = floor(max(small, value) / L), L = dword end -8"),
        ("sum", "sum = sat(sum + f(new)) then floor at 0 of sum - f(old); both limits call the recorder at 0x56f1f30"),
    )


def reference_rows():
    return (
        ("l1/exchange/impl_trading.rs apply_trade_outcome", "maker and taker deltas from taker_side", "party 0 always gets +size, party 1 always -size; fill +0x234 only names the maker for s and the margin tail"),
        ("l1/fees/compute.rs apply_perp_funding_and_volume_update", "paid fee units per user, no balance debit", "that name fits 0x37153f0; the debit, gross - rebate, happens in 0x3710a70, which the reference does not model"),
        ("l1/clearinghouse/clearinghouse.rs apply_trade_or_fill_update side_notional_hint", "a notional hint", "the stack word is the party's net fee, 0 for an exempt party"),
        ("l1/clearinghouse/impl_first_dex.rs remaining_notional_budget at +0x238", "a transfer budget", "serializer 0x370c340 prints +0x238 under total_net_deposit, and this path lowers it by builder, referrer and extra amounts"),
        ("l1/clearinghouse/clearinghouse.rs rescale_position_oi_unit", "runs when the unit changes", "the gate at 0x3710f82 compares two reads of value +4 around one balance store, so 0x370e6a0 cannot run from here"),
        ("l1/clearinghouse/clearinghouse.rs update_open_interest_by_slot", "subtract old, add new, saturating, entry removed at 0", "0x36f7350 also keeps row +0x20, panics on |i64::MIN|, and never removes an entry"),
        ("all of l1", "no znfn", "clearinghouse +0x2d8, key znfn, grows by notional only on a fill with zero deployer + protocol and no exempt party"),
        ("l1/exchange/impl_trading.rs is_vault_privileged", "a limit for the action cap", "the same 8 addresses in 0x37e4fb0 also skip the fee of a fill"),
    )


DEAD = "the limit test before this arm keeps the product at or below 2^63 - 2, so its sign check never fires"
BROADCAST = "pshufd of a value whose 16 bytes are already equal"
TOTAL = "the saturated total is only tested against 0 and is never 0"
LEA = "lea of +0x128 is read only by the dead leverage hook call"
REASONS = {0x3710B87: LEA, 0x3711513: BROADCAST, 0x37115F9: BROADCAST, 0x371197E: TOTAL, 0x3711982: TOTAL}
UNSTEPPED = (
    (0x3710F8C, 0x3710FA7, "leverage hook call: value +4 cannot differ between the two reads"),
    (0x3711AAD, 0x3711AFF, "recorder arm of the first doubled product: ruled out by the limit test"),
    (0x3711B42, 0x3711B84, "recorder arm of the second doubled product: ruled out by the limit test"),
    (0x3711964, 0x3711966, "ud2 after the unwrap call"),
    (0x37119B1, 0x37119B6, "jump for a saturated total of 0: a saturated total is never 0"),
    (0x3711B84, 0x3711B9F, "unwind pad"),
)
PADDING = (0x3710C4A, 0x3710CAA, 0x3710EA5, 0x3710EC7, 0x371149C, 0x36F73E9)


def unstepped_rows(evidence):
    rows = []
    for row in evidence["functions"]:
        for text in row["unstepped"]:
            va = int(text, 16)
            reason = "padding between blocks" if va in PADDING else next((why for low, high, why in UNSTEPPED if low <= va < high), None)
            if reason is None:
                raise EvidenceError("unclassified unstepped instruction %s" % text)
            rows.append((row["start"], text, reason))
    return rows


def analyse(image, full=True, reached_out=None):
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
    for role, begin in FUNCTIONS + HELPERS:
        end = image.exact_fde(begin)[1]
        rows = decode_range(image, begin, end)
        base = image.offset(begin)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(bytes(image.blob[base:base + end - begin])).hexdigest(),
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched), "unstepped": ["%#x" % row.va for row in rows if row.va not in touched]})
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
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
        return DEAD
    if row["va"] in REASONS:
        return REASONS[row["va"]]
    raise EvidenceError("survivor without a reason: %#x" % row["va"])


def write_tsv(path, header, rows):
    lines = ["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


FLOWS = (
    ("plain fee, both parties", dict()),
    ("taker pays, maker rebate", dict(records=(PLAIN, MAKER))),
    ("builder, referrer, extra on both", dict(records=(PAID, PAID))),
    ("no fee words: znfn grows", dict(records=(NONE, NONE))),
    ("party 0 exempt", dict(party=(-1, SELLER), rows={SELLER: account()})),
    ("isolated position pays from margin", dict(rows={BUYER: account(positions={ASSET: (1, 3, 8000, 500)}), SELLER: account()})),
)


def flow_rows(image):
    """One row per named case from the evaluated bytes: what moved."""
    harness = Harness(image)
    rows = []
    for label, over in FLOWS:
        case = world(label, **over)
        failed = compare_run(harness, case)
        if failed:
            raise EvidenceError("flow %s: %s" % (label, failed))
        got = harness.run(case)
        credit = next(item for item in got["log"] if item[0] == "credit")

        def moved(party):
            user = case["party"][party]
            old, new = case["rows"].get(user), got["rows"].get(user)
            if not new:
                return (0, 0)
            start = old["balance"] if old else 0
            first = old["positions"][ASSET][2] if old and ASSET in old["positions"] else 0
            return (signed(new["balance"]) - signed(start), signed(new["positions"][ASSET][2]) - first if ASSET in new["positions"] else 0)
        one, two = moved(0), moved(1)
        rows.append((label, one[0], one[1], two[0], two[1], got["pool"] - case["pool"], got["free"] - case["free"], credit[1], credit[2]))
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
    write_tsv(out / "fee-words.tsv", ("output_offset", "gate", "use"), word_rows())
    write_tsv(out / "margin-rule.tsv", ("part", "rule"), margin_rows())
    write_tsv(out / "exempt-addresses.tsv", ("index", "head_16_bytes_at", "tail_4_bytes_at", "address"), privileged_rows(image))
    write_tsv(out / "serde-names.tsv", ("clearinghouse_offset", "key", "lea_site", "key_address"), serde_rows(image))
    write_tsv(out / "call-sites.tsv", ("callee", "site", "function", "form"), caller_rows(image))
    write_tsv(out / "locations.tsv", ("record", "use", "file", "line", "column", "meaning"), location_rows(image))
    write_tsv(out / "pins.tsv", ("address", "bytes", "meaning"), pin_rows(image))
    write_tsv(out / "stubs.tsv", ("address", "role", "note"), STUBS)
    write_tsv(out / "flows.tsv", ("case", "party0_row", "party0_margin", "party1_row", "party1_margin", "deposit_total", "znfn", "credit_deployer", "credit_protocol"), flow_rows(image))
    write_tsv(out / "unstepped.tsv", ("function", "address", "reason"), unstepped_rows(evidence))
    write_tsv(out / "reference-diff.tsv", ("reference", "reference_says", "bytes_say"), reference_rows())
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row in results:
        reason = "" if row["result"] == "killed" else reason_for(row)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row["group"], row["va"], row["kind"], row["result"], row["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
