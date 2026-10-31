#!/usr/bin/env python3
"""Pin the node #94 spot fill fee settlement from ELF bytes: the matched fill 0x372b9d0, the order charge 0x372e0a0 and the split 0x3c018a0.

The three functions and the balance tree helpers behind them run in a Python evaluator. A separately written specification predicts
every balance word, fee pool word, deployer credit, token index row, recorder call, panic Location, fee record byte and party block
byte, and every condition, immediate and field offset of the three functions is flipped to show the run can tell. No objdump or
readelf output is parsed, and the binary is never executed. Standard library only.
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


FILL_FN = 0x372B9D0
CHARGE_FN = 0x372E0A0
SPLIT_FN = 0x3C018A0
PARTY_ITER = 0x3BB6760
BALANCE_ENTRY = 0x33BB560
POOL_ENTRY = 0x33BC720
USER_ENTRY = 0x33C0D60
SET_INSERT = 0x3398240
FEE = 0x3742460
CONVERT = 0x333E310
ROW = 0x35964F0
SLOT_UNIT = 0x57747A0
SLOT_PREDICATE = 0x5773198
SLOT_READ_ROW = 0x5773170
SLOT_RECORDER = 0x5773190
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_BCMP = 0x576E488
SLOT_NONE = 0x576E470
SLOT_UNWRAP = 0x576E048
SLOT_BOUND = 0x576DFC8
SLOT_STR = 0x576E108
SLOT_FAIL = 0x576E020
OVERFLOW_TAG = 0xBE
LOC_SPOT = 0x56F1FD8
LOC_SPOT_CHARGE = 0x5714C70
LOC_TOKEN = 0x56F21F0
LOC_RECEIVE = 0x56F2038
LOC_DEBIT = 0x56F1FF0
LOC_REBATE_ADD = 0x56F2050
LOC_RECEIVE_ADD = 0x56F2068
LOC_CONVERT = 0x5714D00
LOC_GROSS = 0x5714C88
LOC_REBATE = 0x5714CA0
LOC_BUILDER = 0x5714CB8
LOC_REFERRER = 0x5714CD0
LOC_EXTRA = 0x5714CE8
LOC_FLOOR = 0x56DFD90
LOC_CEILING = 0x56DFD78
LOC_SHORT_FILL = 0x56F2020
LOC_SHORT_CHARGE = 0x56F2080
TOKEN_ROW = 0xE8
PARTY_SIZE = 0xF8
STATE = HEAP_BASE + 0x1000
TRACKER = HEAP_BASE + 0x3000
OUT = HEAP_BASE + 0x100
TOKENS = HEAP_BASE + 0x180
ACC = HEAP_BASE + 0x1A0
RECORD = HEAP_BASE + 0x200
FILL = HEAP_BASE + 0x400
EMPTY_ROW = HEAP_BASE + 0x900
BUMP = HEAP_BASE + 0x3800
CAPACITY = 11
TOP = STACK_TOP - 0x108
MAX = (1 << 64) - 1
DENOMINATOR = 100000.0
CAP = 1.01
ALIGNED = dict(leaf=0x278, inner=0x2D8, keys=0x218, length=0x272, slot=0x270, parent=0x210, values=0, stride=0x30, edges=0x278, width=8)
STATUS = dict(leaf=0x70, inner=0xD0, keys=8, length=0x62, slot=0x60, parent=0, values=0x64, stride=1, edges=0x70, width=8)
BALANCES = dict(leaf=0x170, inner=0x1D0, keys=8, length=0x16A, slot=0x168, parent=0, values=0x60, stride=0x18, edges=0x170, width=8)
POOL = dict(leaf=0xC0, inner=0x120, keys=8, length=0xBA, slot=0xB8, parent=0, values=0x60, stride=8, edges=0xC0, width=8)
SET = dict(leaf=0x68, inner=0xC8, keys=8, length=0x62, slot=0x60, parent=0, values=0x60, stride=0, edges=0x68, width=8)
USERS = dict(leaf=0x1F0, inner=0x250, keys=0x110, length=0x1EE, slot=0x1EC, parent=0, values=8, stride=0x18, edges=0x1F0, width=20)


def address(index):
    return bytes((index * 7 + at * 11 + 1) & 0xFF for at in range(20))


# ---- trees ----

def tree_height(count):
    level, room = 0, CAPACITY
    while room < count:
        level += 1
        room = room * (CAPACITY + 1) + CAPACITY
    return level


def put_key(memory, shape, node, index, key):
    if shape["width"] == 8:
        memory.write(node + shape["keys"] + 8 * index, 8, key)
    else:
        memory.put_bytes(node + shape["keys"] + shape["width"] * index, key)


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
            put_key(memory, shape, node, index, key)
            put(node + shape["values"] + shape["stride"] * index, value)
        for index in range(len(entries), CAPACITY):
            if stale:
                put_key(memory, shape, node, index, stale[index % len(stale)])
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
    if count > CAPACITY:
        raise Halt("node length")
    for index in range(count + 1):
        if height:
            found += tree_items(memory, shape, memory.read(node + shape["edges"] + 8 * index, 8), height - 1)
        if index < count:
            if shape["width"] == 8:
                key = memory.read(node + shape["keys"] + 8 * index, 8)
            else:
                key = memory.bytes_at(node + shape["keys"] + shape["width"] * index, shape["width"])
            found.append((key, node + shape["values"] + shape["stride"] * index))
    return found


def checked_items(memory, shape, node, height):
    found = tree_items(memory, shape, node, height)
    keys = [key for key, _ in found]
    if keys != sorted(set(keys)):
        raise Halt("tree order")
    return found


# ---- specification ----

class Refused(Exception):
    """The specification's panic: the Location record the path names."""


def convert(case, amount):
    if amount in case["convert_fail"]:
        raise Refused("none:%#x" % LOC_CONVERT)
    return (amount * case["convert"][0] // case["convert"][1]) & MAX


def add(left, right, location):
    if left + right > MAX:
        raise Refused("unwrap:%#x" % location)
    return left + right


def split_spec(case, acc, record, leg):
    """0x3c018a0: gross and rebate go to the accumulators, the leg's slot also takes builder, referrer and extra."""
    gross, rebate = record["gross"], record["rebate"]
    if gross:
        if leg:
            slot = 1
        else:
            gross = convert(case, gross)
            slot = 0
        acc[slot] = add(acc[slot], gross, LOC_GROSS)
    if rebate:
        if leg:
            rebate = convert(case, rebate)
            slot = 2
        else:
            slot = 3
        acc[slot] = add(acc[slot], rebate, LOC_REBATE)
    slot = 2 + (leg & 0xFF != 0)
    if record["builder_tag"] & 1:
        acc[slot] = add(acc[slot], record["builder"], LOC_BUILDER)
    if record["referrer_tag"]:
        acc[slot] = add(acc[slot], record["referrer"], LOC_REFERRER)
    if record["extra"]:
        acc[slot] = add(acc[slot], record["extra"], LOC_EXTRA)
    return dict(gross_some=int(record["gross"] != 0), gross=gross, rebate_some=int(record["rebate"] != 0), rebate=rebate)


def deployer_amount(net, share, listed):
    """Listed tokens take 0 by both arms; else share / 1e5 when at most 1.01, saturating."""
    if listed:
        return 0
    factor = float(share) / DENOMINATOR
    if factor > CAP:
        return 0
    value = factor * float(net)
    if value >= 18446744073709551616.0:
        return MAX
    return int(value)


class Ledger:
    """A plain Python copy of the fixture state, moved by the rules in order."""

    def __init__(self, case):
        self.case = case
        self.balances = {key: list(value) for key, value in case["balances"].items()}
        self.pool = dict(case["pool"])
        self.sets = {user: set(tokens) for user, tokens in case["sets"].items()}
        self.rows = set(case["rows"])
        self.created = []
        self.recorder = []
        self.predicates = []
        self.fees = []
        self.blocks = {}
        self.reads = []

    def row(self, user):
        if user not in self.rows:
            self.rows.add(user)
            self.created.append(user)

    def entry(self, user, token):
        return self.balances.setdefault((user, token), [0, 0, 0])

    def index(self, user, token):
        self.sets.setdefault(user, set()).add(token)

    def floor(self, value, amount):
        if value < amount:
            self.recorder.append((0, LOC_FLOOR))
            return 0
        return value - amount

    def ceiling(self, value, amount):
        if value + amount > MAX:
            self.recorder.append((0, LOC_CEILING))
            return MAX
        return value + amount

    def settle_token(self, token, collected, paid, short):
        case = self.case
        if collected < paid:
            self.recorder.append((2, short))
            self.pool[token] = self.floor(self.pool.get(token, 0), paid - collected)
            return
        net = collected - paid
        if token >= len(case["tokens"]):
            raise Refused("none:%#x" % LOC_TOKEN)
        flag, deployer, share = case["tokens"][token]
        if flag & 1:
            amount = deployer_amount(net, share, token in case["quotes"])
            self.row(deployer)
            entry = self.entry(deployer, token)
            self.index(deployer, token)
            entry[0] = self.ceiling(entry[0], amount)
            net = self.floor(net, amount)
        self.pool[token] = self.ceiling(self.pool.get(token, 0), net)

    def view(self, result=None):
        return dict(result=result, balances={key: tuple(value) for key, value in self.balances.items()}, pool=self.pool, sets=self.sets, created=self.created,
                    recorder=self.recorder, predicates=self.predicates, fees=self.fees, blocks=self.blocks, reads=self.reads)


def fill_spec(case):
    ledger = Ledger(case)
    try:
        return fill_steps(case, ledger)
    except Refused as panic:
        return dict(panic=str(panic))


def fill_steps(case, ledger):
    if case["spot"] >= len(case["pairs"]):
        raise Refused("bound:%#x" % LOC_SPOT)
    px, size, unit = case["px"], case["sz"], case["unit"]
    quote_wei = px * size
    if quote_wei > MAX or not unit[0] & 1:
        return ledger.view("skip")
    base, quote = case["pairs"][case["spot"]]
    token, base_wei = unit[1], unit[2]
    users = case["party"]
    ledger.reads = [users[0]]
    have = case["balances"].get((users[0], quote), (0,))[0]
    if have < quote_wei:
        return ledger.view("short 0")
    ledger.reads.append(users[1])
    have = case["balances"].get((users[1], token), (0,))[0]
    if have < base_wei:
        return ledger.view("short 1")
    acc = [0, 0, 0, 0]
    legs = ((users[0], token, base_wei, quote, quote_wei), (users[1], quote, quote_wei, token, base_wei))
    for leg, (user, receive_token, receive, pay_token, pay) in enumerate(legs):
        listed = base in case["quotes"]
        if not listed:
            ledger.predicates.append(base)
        record = None
        if listed or not case["outcome"]:
            if not listed:
                ledger.predicates.append(base)
            record = case["records"][leg]
            ledger.fees.append((leg, 1 if listed else 0, int(leg == case["taker"])))
        ledger.row(user)
        if record is None:
            ledger.blocks[leg] = None
        else:
            out = split_spec(case, acc, record, leg)
            if out["gross_some"]:
                if receive < out["gross"]:
                    raise Refused("none:%#x" % LOC_RECEIVE)
                receive -= out["gross"]
            if out["rebate_some"]:
                entry = ledger.entry(user, pay_token)
                ledger.index(user, pay_token)
                entry[0] = add(out["rebate"], entry[0], LOC_REBATE_ADD)
            ledger.blocks[leg] = record
        entry = ledger.entry(user, receive_token)
        ledger.index(user, receive_token)
        entry[0] = add(receive, entry[0], LOC_RECEIVE_ADD)
        entry = ledger.entry(user, pay_token)
        if entry[0] < pay:
            raise Refused("none:%#x" % LOC_DEBIT)
        entry[0] -= pay
        entry[1] = ledger.floor(entry[1], pay)
    ledger.settle_token(token, acc[0], acc[2], LOC_SHORT_FILL)
    ledger.settle_token(quote, acc[1], acc[3], LOC_SHORT_FILL)
    return ledger.view("settled")


def charge_spec(case):
    ledger = Ledger(case)
    if not case["count"] or not case["px"]:
        return ledger.view("skip")
    if case["spot"] >= len(case["pairs"]):
        return dict(panic="bound:%#x" % LOC_SPOT_CHARGE)
    base, quote = case["pairs"][case["spot"]]
    listed = base in case["quotes"]
    if not listed:
        ledger.predicates.append(base)
    klass = 1 if listed else (2 if case["outcome"] else 0)
    record = dict(case["records"][1], rebate=0)
    ledger.fees.append((1, klass, case["taker"]))
    acc = [0, 0, 0, 0]
    user = case["party"][1]
    try:
        out = split_spec(case, acc, record, 1)
        ledger.row(user)
        entry = ledger.entry(user, quote)
        fee = acc[1]
        if entry[1] + fee > MAX or entry[1] + fee > entry[0]:
            fee = ledger.floor(entry[0], entry[1])
        entry[0] -= fee
        ledger.blocks[1] = record
        ledger.settle_token(base, acc[0], acc[2], LOC_SHORT_CHARGE)
        ledger.settle_token(quote, acc[1], acc[3], LOC_SHORT_CHARGE)
    except Refused as panic:
        return dict(panic=str(panic))
    return ledger.view("charged")


# ---- evaluator harness ----

class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        machine.memory.reset()
        machine.real = frozenset(REAL)
        machine.jump_ranges = [image.exact_fde(start) for start in REAL]
        machine.step_limit = 80000
        machine.calls = {FEE: self.on_fee, CONVERT: self.on_convert, ROW: self.on_row}
        table = ((SLOT_UNIT, self.on_unit), (SLOT_PREDICATE, self.on_predicate), (SLOT_READ_ROW, self.on_read_row), (SLOT_RECORDER, self.on_recorder),
                 (SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_MEMCPY, self.on_memcpy), (SLOT_MEMMOVE, self.on_memcpy), (SLOT_BCMP, self.on_bcmp),
                 (SLOT_NONE, self.on_none), (SLOT_UNWRAP, self.on_unwrap), (SLOT_BOUND, self.on_bound), (SLOT_STR, self.on_stop("str")), (SLOT_FAIL, self.on_stop("alloc")))
        for at, (slot, hook) in enumerate(table):
            token = 0x7100000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        self.at = BUMP
        self.case = None

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
        size = machine.regs[RDI]
        self.check(size in (0x68, 0xC8, 0x170, 0x1D0, 0xC0, 0x120, 0x1F0, 0x250), "alloc size %#x" % size)
        machine.regs[RAX] = self.bump(size)

    def on_free(self, machine):
        raise Halt("free")

    def on_memcpy(self, machine):
        regs = machine.regs
        if regs[RDX]:
            self.check(regs[RDX] < 0x10000, "copy size")
            machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_bcmp(self, machine):
        regs, memory = machine.regs, machine.memory
        self.check(regs[RDX] == 20, "compare size")
        left, right = memory.bytes_at(regs[RDI], 20), memory.bytes_at(regs[RSI], 20)
        regs[RAX] = (-1 if left < right else 1 if left > right else 0) & MASK[4]

    def on_stop(self, name):
        def stop(machine):
            raise Panicked(name)
        return stop

    def on_none(self, machine):
        raise Panicked("none:%#x" % machine.regs[RDI])

    def on_unwrap(self, machine):
        self.check(machine.memory.read(machine.regs[RDX], 2) == OVERFLOW_TAG and machine.regs[RSI] == 0x2B, "unwrap payload")
        raise Panicked("unwrap:%#x" % machine.regs[R8])

    def on_bound(self, machine):
        raise Panicked("bound:%#x" % machine.regs[RDX])

    def on_recorder(self, machine):
        self.recorder.append((machine.regs[RDI] & MASK[4], machine.regs[RSI]))

    def on_unit(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        self.check(regs[RSI] == STATE + 0x10 and regs[RDX] == case["spot"] and regs[RCX] & 0xFF == 0 and regs[R8] == case["px"] and regs[R9] == case["sz"], "unit args")
        flag, token, wei = case["unit"]
        memory.write(regs[RDI], 8, token)
        memory.write(regs[RDI] + 8, 8, 0xABCDEF00 | flag)
        memory.write(regs[RDI] + 0x10, 8, wei)

    def on_predicate(self, machine):
        regs = machine.regs
        self.check(regs[RDI] == STATE + 0x10, "predicate meta")
        self.predicates.append(regs[RSI])
        regs[RAX] = 0x5500 | int(self.case["outcome"])

    def user_of(self, machine, at):
        key = machine.memory.bytes_at(at, 20)
        for user in self.case["known"]:
            if address(user) == key:
                return user
        raise Halt("unknown user")

    def on_row(self, machine):
        regs = machine.regs
        self.check(regs[RDI] == STATE + 0x298, "row map")
        user = self.user_of(machine, regs[RSI])
        if user not in self.rows:
            self.lay_row(user, ())
            self.created.append(user)
        regs[RAX] = self.rows[user]

    def on_read_row(self, machine):
        regs = machine.regs
        self.check(regs[RDI] == STATE, "read row state")
        user = self.user_of(machine, regs[RSI])
        self.reads.append(user)
        regs[RAX] = self.rows.get(user, EMPTY_ROW)

    def on_convert(self, machine):
        regs, case = machine.regs, self.case
        self.check(regs[RSI] == self.convert_token and regs[RDX] == case["px"] and regs[RCX] & 0xFF == 0 and regs[R8] == STATE + 0x10, "convert args")
        failed = regs[RDI] in case["convert_fail"]
        regs[RAX] = 0xABC0 | int(not failed)
        regs[RDX] = POISON if failed else (regs[RDI] * case["convert"][0] // case["convert"][1]) & MAX
        machine.keep_rdx = True

    def on_fee(self, machine):
        regs, memory, case = machine.regs, machine.memory, self.case
        self.check(regs[RSI] == TRACKER, "fee tracker")
        record = regs[RDX]
        self.seen.append((bytes(memory.bytes_at(record, 0x58))))
        leg = memory.read(record + 0x31, 1)
        self.write_record(memory, regs[RDI], case["records"][leg], leg)

    def write_record(self, memory, at, row, leg):
        memory.put_bytes(at, record_image(row, leg))

    def lay_row(self, user, entries):
        memory = self.machine.memory
        row = self.bump(0x30)
        stale = self.case.get("stale", ())
        items = sorted(entries)
        root, height = build_tree(memory, self.bump, BALANCES, items, lambda where, value: [memory.write(where + at * 8, 8, word) for at, word in enumerate(value)], stale)
        memory.write(row + 0x10, 8, root)
        memory.write(row + 0x18, 8, height)
        memory.write(row + 0x20, 8, len(items))
        self.rows[user] = row

    def start(self, case):
        memory = self.machine.memory
        memory.reset(self.at - HEAP_BASE if self.at > BUMP else 0x4000)
        self.at = BUMP
        self.case = case
        self.rows, self.created, self.recorder, self.predicates, self.reads, self.seen = {}, [], [], [], [], []
        self.machine.frame = 0
        state = STATE
        for at in (0x10, 0x298, 0x2B0):
            memory.write(state + at, 8, 0x4141414141414141)
        memory.write(state + 0x188, 8, 0)
        pairs = self.bump(0x20 * max(1, len(case["pairs"])))
        memory.write(state + 0x178, 8, pairs)
        memory.write(state + 0x180, 8, len(case["pairs"]))
        for index, (base, quote) in enumerate(case["pairs"]):
            memory.write(pairs + index * 0x20, 8, base)
            memory.write(pairs + index * 0x20 + 8, 8, quote)
        rows = self.bump(TOKEN_ROW * max(1, len(case["tokens"])))
        memory.write(state + 0x190, 8, rows)
        memory.write(state + 0x198, 8, len(case["tokens"]))
        for index, (flag, deployer, share) in enumerate(case["tokens"]):
            base = rows + index * TOKEN_ROW
            memory.write(base + 0xA8, 8, share)
            memory.write(base + 0xD2, 1, flag)
            memory.put_bytes(base + 0xD3, address(deployer))
        memory.write(state + 0x150, 8, to_bits(case["weight"]))
        stale = case["stale"]
        memory.write(EMPTY_ROW + 0x10, 8, 0)
        memory.write(EMPTY_ROW + 0x18, 8, 0)
        root, height = build_tree(memory, self.bump, ALIGNED, sorted(case["aligned"].items()), lambda where, byte: memory.write(where + 0x2C, 1, byte), stale)
        memory.write(state + 0x230, 8, root)
        memory.write(state + 0x238, 8, height)
        root, height = build_tree(memory, self.bump, STATUS, sorted(case["quotes"].items()), lambda where, byte: memory.write(where, 1, byte), stale)
        memory.write(state + 0x260, 8, root)
        memory.write(state + 0x268, 8, height)
        pool = sorted(case["pool"].items())
        root, height = build_tree(memory, self.bump, POOL, pool, lambda where, value: memory.write(where, 8, value), stale)
        memory.write(state + 0x3A0, 8, root)
        memory.write(state + 0x3A8, 8, height)
        memory.write(state + 0x3B0, 8, len(pool))

        def put_set(where, tokens):
            items = [(token, 0) for token in sorted(tokens)]
            root, height = build_tree(memory, self.bump, SET, items, lambda at, value: None, stale)
            memory.write(where, 8, root)
            memory.write(where + 8, 8, height)
            memory.write(where + 0x10, 8, len(items))
        users = sorted((address(user), tokens) for user, tokens in case["sets"].items())
        root, height = build_tree(memory, self.bump, USERS, users, put_set)
        memory.write(state + 0x400, 8, root)
        memory.write(state + 0x408, 8, height)
        memory.write(state + 0x410, 8, len(users))
        held = {}
        for (user, token), value in case["balances"].items():
            held.setdefault(user, []).append((token, value))
        for user in case["rows"]:
            self.lay_row(user, held.get(user, ()))

    def lay_party(self, base, index):
        memory = self.machine.memory
        case = self.case
        memory.put_bytes(base, bytes((at * 5 + 3 + index) & 0xFF for at in range(PARTY_SIZE)))
        memory.write(base, 4, 1)
        memory.write(base + 0x60, 8, 1)
        memory.write(base + 0x88, 4, 0)
        memory.put_bytes(base + 0xD0, address(case["party"][index]))

    def state_view(self):
        memory, case = self.machine.memory, self.case
        balances = {}
        for user, row in self.rows.items():
            root, height, count = (memory.read(row + at, 8) for at in (0x10, 0x18, 0x20))
            items = checked_items(memory, BALANCES, root, height)
            self.check(len(items) == count, "balance count")
            for key, where in items:
                balances[(user, key)] = tuple(memory.read(where + at, 8) for at in (0, 8, 0x10))
        root, height, count = (memory.read(STATE + at, 8) for at in (0x3A0, 0x3A8, 0x3B0))
        items = checked_items(memory, POOL, root, height)
        self.check(len(items) == count, "pool count")
        pool = {key: memory.read(where, 8) for key, where in items}
        root, height, count = (memory.read(STATE + at, 8) for at in (0x400, 0x408, 0x410))
        items = checked_items(memory, USERS, root, height)
        self.check(len(items) == count, "user count")
        sets = {}
        names = {address(user): user for user in case["known"]}
        for key, where in items:
            root, height, count = (memory.read(where + at, 8) for at in (0, 8, 0x10))
            found = [token for token, _ in checked_items(memory, SET, root, height)]
            self.check(len(found) == count, "set count")
            sets[names[key]] = set(found)
        return dict(balances=balances, pool=pool, sets=sets, created=self.created, recorder=self.recorder, predicates=self.predicates, reads=self.reads)

    def run_split(self, case):
        self.start(case)
        memory = self.machine.memory
        self.convert_token = case["token"]
        memory.put_bytes(RECORD, record_image(case["record"], 0))
        for index, value in enumerate(case["acc"]):
            memory.write(ACC + index * 8, 8, value)
        memory.write(TOKENS, 8, case["token"])
        memory.write(TOP + 8, 8, STATE + 0x10)
        result = self.machine.run(SPLIT_FN, {RDI: OUT, RSI: ACC, RDX: TOKENS, RCX: case["leg"] | case["junk"], R8: case["px"], R9: RECORD})
        self.check(result == OUT, "split return")
        return dict(out=[memory.read(OUT + at, 8) for at in (0, 8, 0x10, 0x18)], acc=[memory.read(ACC + at, 8) for at in (0, 8, 0x10, 0x18)])

    def run_fill(self, case):
        self.start(case)
        memory = self.machine.memory
        self.lay_party(FILL, 0)
        self.lay_party(FILL + PARTY_SIZE, 1)
        memory.write(FILL + 0x1F0, 8, case["px"])
        memory.write(FILL + 0x1F8, 8, case["spot"])
        memory.write(FILL + 0x200, 8, case["sz"])
        memory.write(FILL + 0x208, 8, case["notional"])
        memory.write(FILL + 0x224, 1, case["taker"])
        self.convert_token = case["unit"][1]
        self.machine.run(FILL_FN, {RDI: STATE, RSI: case["flag"] | 0x7700, RDX: FILL, RCX: TRACKER})
        return self.state_view()

    def run_charge(self, case):
        self.start(case)
        memory = self.machine.memory
        memory.put_bytes(FILL, bytes((at * 5 + 3) & 0xFF for at in range(0x230)))
        memory.put_bytes(FILL + 0x1C8, address(case["party"][1]))
        memory.write(FILL + 0x1F0, 8, case["spot"])
        memory.write(FILL + 0x1F8, 8, case["px"])
        memory.write(FILL + 0x208, 8, case["notional"])
        memory.write(FILL + 0x224, 1, case["taker"])
        self.convert_token = case["pairs"][case["spot"]][0] if case["spot"] < len(case["pairs"]) else 0
        self.machine.run(CHARGE_FN, {RDI: STATE, RSI: case["flag"] | 0x7700, RDX: case["count"], RCX: FILL, R8: TRACKER})
        return self.state_view()


def record_image(row, leg):
    """0x68 record bytes; filler differs by leg so a crossed copy shows."""
    data = bytearray((at * 7 + 0x21 + leg * 13) & 0xFF for at in range(0x68))
    struct.pack_into("<Q", data, 0, 0xA5B4C300 | row["builder_tag"])
    struct.pack_into("<Q", data, 8, row["builder"])
    data[0x28] = row["referrer_tag"]
    struct.pack_into("<Q", data, 0x30, row["referrer"])
    struct.pack_into("<Q", data, 0x50, row["gross"])
    struct.pack_into("<Q", data, 0x58, row["rebate"])
    struct.pack_into("<Q", data, 0x60, row["extra"])
    return bytes(data)


# ---- comparison ----

def compare_state(harness, got, want):
    for name in ("balances", "pool", "sets", "created", "recorder", "predicates", "reads"):
        if got[name] != want[name]:
            return "%s differ" % name
    return ""


def check_seen(harness, case, want, leg_input):
    if len(harness.seen) != len(want["fees"]):
        return "fee count"
    for seen, (leg, klass, cross) in zip(harness.seen, want["fees"]):
        quote = case["pairs"][case["spot"]][1]
        parts = ((0x28, struct.pack("<dBB", case["weight"], klass, leg)), (0x38, struct.pack("<Q", case["notional"])), (0x54, bytes([cross, case["aligned"].get(quote, 0), case["flag"]])))
        head, user = leg_input(leg)
        parts += ((0, head), (0x40, user))
        for at, data in parts:
            if seen[at:at + len(data)] != data:
                return "record +%#x" % at
    return ""


def compare_split(harness, case):
    acc = list(case["acc"])
    try:
        out = split_spec(case, acc, case["record"], case["leg"])
    except Refused as panic:
        try:
            harness.run_split(case)
        except Panicked as seen:
            return "" if str(seen) == str(panic) else "panic %s wanted %s" % (seen, panic)
        return "panic missing"
    got = harness.run_split(case)
    if got["acc"] != acc:
        return "accumulators"
    if got["out"] != [out["gross_some"], out["gross"], out["rebate_some"], out["rebate"]]:
        return "out"
    return ""


def compare_fill(harness, case):
    want = fill_spec(case)
    if "panic" in want:
        try:
            harness.run_fill(case)
        except Panicked as seen:
            return "" if str(seen) == want["panic"] else "panic %s wanted %s" % (seen, want["panic"])
        return "panic missing"
    got = harness.run_fill(case)
    failed = compare_state(harness, got, want)
    if failed:
        return failed
    memory = harness.machine.memory

    def leg_input(leg):
        return bytes((at * 5 + 3 + leg) & 0xFF for at in range(0x28, 0x50)), address(case["party"][leg])
    failed = check_seen(harness, case, want, leg_input)
    if failed:
        return failed
    for leg, record in want["blocks"].items():
        base = FILL + PARTY_SIZE * leg + 0x60
        if record is None:
            if any(memory.read(base + at, 8) for at in (0, 0x28, 0x50, 0x58, 0x60)):
                return "no-fee block"
        elif memory.bytes_at(base, 0x68) != record_image(record, leg):
            return "block %d" % leg
    if want["result"] != "settled":
        for leg in (0, 1):
            if memory.read(FILL + PARTY_SIZE * leg + 0x60, 8) != 1:
                return "block touched"
    return ""


def compare_charge(harness, case):
    want = charge_spec(case)
    if "panic" in want:
        try:
            harness.run_charge(case)
        except Panicked as seen:
            return "" if str(seen) == want["panic"] else "panic %s wanted %s" % (seen, want["panic"])
        return "panic missing"
    got = harness.run_charge(case)
    failed = compare_state(harness, got, want)
    if failed:
        return failed
    memory = harness.machine.memory

    def leg_input(leg):
        return bytes((at * 5 + 3) & 0xFF for at in range(0x120, 0x148)), address(case["party"][1])
    failed = check_seen(harness, case, want, leg_input)
    if failed:
        return failed
    if want["result"] == "charged" and memory.bytes_at(FILL + 0x158, 0x68) != record_image(want["blocks"][1], 1):
        return "order block"
    return ""


COMPARE = dict(split=compare_split, fill=compare_fill, charge=compare_charge)


def compare_run(harness, case):
    try:
        return COMPARE[case["kind"]](harness, case)
    except (Halt, Panicked, Finished, EvidenceError, struct.error, ZeroDivisionError, KeyError, MemoryError, IndexError, ValueError, OverflowError) as error:
        return "%s: %s: %s" % (case["kind"], case["label"], error)


# ---- cases ----

def fee_row(gross=0, rebate=0, builder_tag=0, builder=0, referrer_tag=0, referrer=0, extra=0):
    return dict(gross=gross, rebate=rebate, builder_tag=builder_tag, builder=builder, referrer_tag=referrer_tag, referrer=referrer, extra=extra)


NONE = fee_row()
PAIRS = ((3, 2), (4, 2), (5, 1), (6, 7), (2, 1), (30, 31))
BUYER, SELLER, DEPLOY_A, DEPLOY_B = 1, 2, 3, 4
GROSS = fee_row(gross=9000)
BOTH = fee_row(gross=9000, rebate=1100)
REBATE = fee_row(rebate=1500)
PAID = fee_row(gross=9000, builder_tag=1, builder=100, referrer_tag=1, referrer=70, extra=40)


def world(**over):
    """Two parties with live rows and balances; token rows with a deployer; a quote list and an aligned map."""
    case = dict(pairs=PAIRS, spot=0, px=70000, sz=5000, unit=(1, 3, 500000), notional=(0x77 << 32) + 5, taker=1, flag=1, weight=0.25, outcome=False, aligned={2: 1, 7: 0}, quotes={1: 0, 9: 3},
                tokens=[(2, 0, 0), (2, 0, 0), (3, DEPLOY_A, 50000), (3, DEPLOY_B, 40000), (2, 0, 0), (3, DEPLOY_A, 25000), (2, 0, 0), (2, 0, 0), (2, 0, 0), (3, DEPLOY_B, 5000)],
                pool={1: 500, 2: 7000000, 3: 100000000}, convert=(3, 7), convert_fail=(), party=(BUYER, SELLER), rows=(BUYER, SELLER, DEPLOY_A),
                balances={(BUYER, 2): (10 ** 12, 10 ** 10, 0x31), (BUYER, 3): (77, 0, 0x32), (SELLER, 3): (10 ** 12, 10 ** 9, 0x33), (SELLER, 2): (55, 3, 0x34), (DEPLOY_A, 2): (66, 0, 0x35), (DEPLOY_A, 3): (44, 0, 0x36)},
                sets={BUYER: (2, 3), SELLER: (2, 3), DEPLOY_A: (2,)}, records=(NONE, NONE), known=(BUYER, SELLER, DEPLOY_A, DEPLOY_B), stale=(1, 2, 3, 4, 5, 6, 7, 9, 30, 31, 1000), acc=(0, 0, 0, 0), record=NONE, leg=0, token=3,
                junk=0, px_is_sz=False, count=1)
    case.update(over)
    return case


def adjust(base, **over):
    return dict(base, **over)


def balances_with(extra):
    table = dict(world()["balances"])
    table.update(extra)
    return {key: value for key, value in table.items() if value is not None}


def deep(count, keys=(BUYER, SELLER, DEPLOY_A)):
    table = balances_with({})
    for user in keys:
        for at in range(count):
            table[(user, 1000 + 2 * at)] = (at, 1, 2)
    return table


def fill_cases():
    rows = []

    def push(label, **over):
        rows.append(world(kind="fill", label=label, **over))
    fees = (("none", NONE), ("gross", GROSS), ("both", BOTH), ("rebate", REBATE), ("paid", PAID), ("all", fee_row(9000, 1100, 1, 100, 1, 70, 40)), ("high tag bits", fee_row(9000, 0, 2, 100, 0, 70, 0)), ("referrer byte", fee_row(9000, 0, 0, 100, 0x80, 70, 0)))
    for left_name, left in fees:
        for right_name, right in fees:
            push("fees %s/%s" % (left_name, right_name), records=(left, right))
    for spot in range(len(PAIRS)):
        for outcome in (False, True):
            for taker in (0, 1):
                for flag in (0, 1):
                    token, base_wei = PAIRS[spot][0], 500000
                    table = balances_with({(SELLER, token): (10 ** 12, 10 ** 9, 0x37), (BUYER, PAIRS[spot][1]): (10 ** 12, 10 ** 10, 0x38)})
                    push("spot %d/%d/%d/%d" % (spot, outcome, taker, flag), spot=spot, outcome=outcome, taker=taker, flag=flag, unit=(1, token, base_wei), balances=table, records=(BOTH, PAID),
                         tokens=world()["tokens"] + [(2, 0, 0)] * 22, sets={BUYER: (2, 3), SELLER: (2, 3), DEPLOY_A: (2,)})
    push("spot one past", spot=len(PAIRS))
    push("spot far past", spot=1 << 40)
    push("no pairs", pairs=(), spot=0)
    push("product overflow", px=1 << 40, sz=1 << 24)
    push("product edge", px=1 << 32, sz=(1 << 32) - 1, balances=balances_with({(BUYER, 2): (MAX, 0, 1)}))
    push("product zero", px=0, sz=9, unit=(1, 3, 0))
    push("size zero", sz=0, unit=(1, 3, 0))
    push("unit refused", unit=(0, 3, 500000))
    push("unit flag bit", unit=(2, 3, 500000))
    push("unit bit with high bits", unit=(0x81, 3, 500000))
    push("unit token differs", unit=(1, 5, 500000), balances=balances_with({(SELLER, 5): (10 ** 12, 0, 1)}))
    push("unit token differs fee", unit=(1, 5, 500000), balances=balances_with({(SELLER, 5): (10 ** 12, 0, 1)}), records=(BOTH, BOTH))
    quote_wei = 350000000
    for name, table in (("exact 0", {(BUYER, 2): (quote_wei, 0, 1)}), ("below 0", {(BUYER, 2): (quote_wei - 1, 0, 1)}), ("above 0", {(BUYER, 2): (quote_wei + 1, 0, 1)}), ("missing 0", {(BUYER, 2): None}),
                        ("exact 1", {(SELLER, 3): (500000, 0, 1)}), ("below 1", {(SELLER, 3): (499999, 0, 1)}), ("above 1", {(SELLER, 3): (500001, 0, 1)}), ("missing 1", {(SELLER, 3): None}),
                        ("hold above total 0", {(BUYER, 2): (quote_wei, quote_wei * 2, 1)}), ("hold above total 1", {(SELLER, 3): (500000, 900000, 1)}), ("hold exact", {(BUYER, 2): (quote_wei, quote_wei, 1)}),
                        ("hold below pay", {(BUYER, 2): (quote_wei * 2, quote_wei - 1, 1)}), ("hold above pay", {(BUYER, 2): (quote_wei * 2, quote_wei + 1, 1)}), ("sell hold below", {(SELLER, 3): (10 ** 9, 499999, 1)})):
        push("balance " + name, balances=balances_with(table), records=(GROSS, BOTH))
        push("balance plain " + name, balances=balances_with(table))
    push("no row 0", rows=(SELLER, DEPLOY_A), balances={key: value for key, value in balances_with({}).items() if key[0] != BUYER}, px=0, unit=(1, 3, 0))
    push("no row 1", rows=(BUYER, DEPLOY_A), balances={key: value for key, value in balances_with({}).items() if key[0] != SELLER}, unit=(1, 3, 0))
    push("no row at all", rows=(DEPLOY_A,), balances={key: value for key, value in balances_with({}).items() if key[0] == DEPLOY_A}, px=0, unit=(1, 3, 0), records=(REBATE, BOTH))
    push("no set row", sets={DEPLOY_A: (2,)}, records=(BOTH, BOTH))
    push("empty user tree", sets={}, records=(BOTH, GROSS))
    push("set row without tokens", sets={BUYER: (), SELLER: (), DEPLOY_A: ()}, records=(BOTH, GROSS))
    many = {user: (1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20) for user in (BUYER, SELLER, DEPLOY_A)}
    push("wide sets", sets=many, records=(BOTH, GROSS))
    crowd = {index: (2,) for index in range(5, 37)}
    crowd.update({BUYER: (2,), SELLER: (2,), DEPLOY_A: (3,)})
    push("many users", sets=crowd, records=(BOTH, BOTH), known=tuple(sorted(crowd)) + (DEPLOY_B,))
    crowd = {index: (2,) for index in (5, 6, 7, 8)}
    crowd.update({BUYER: (3,)})
    push("few users", sets=crowd, records=(BOTH, BOTH), known=tuple(sorted(crowd)) + (SELLER, DEPLOY_A, DEPLOY_B))
    push("deep balances", balances=deep(30), records=(BOTH, BOTH))
    push("deeper balances", balances=deep(170), records=(BOTH, GROSS))
    push("new tokens in deep", balances={key: value for key, value in deep(30).items() if key not in ((BUYER, 3), (SELLER, 2))}, records=(BOTH, BOTH))
    push("no entry received", balances=balances_with({(BUYER, 3): None, (SELLER, 2): None}), records=(BOTH, GROSS))
    push("full leaf", balances={**balances_with({}), **{(BUYER, 4 + at): (1, 0, 0) for at in range(9)}}, sets={BUYER: (2, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14), SELLER: (2, 3), DEPLOY_A: (2,)}, records=(REBATE, GROSS))
    push("receive overflow", balances=balances_with({(BUYER, 3): (MAX - 3, 0, 1)}))
    push("receive edge", balances=balances_with({(BUYER, 3): (MAX - 500000, 0, 1)}))
    push("receive overflow 1", balances=balances_with({(SELLER, 2): (MAX - 3, 0, 1)}))
    push("rebate overflow", balances=balances_with({(BUYER, 2): (MAX - 3, 0, 1)}), records=(REBATE, NONE))
    push("rebate edge", balances=balances_with({(BUYER, 2): (MAX - 642, 0, 1)}), records=(REBATE, NONE))
    push("gross above receive", records=(fee_row(gross=2000000), NONE), convert=(1, 1))
    push("gross equals receive", records=(fee_row(gross=500000), NONE), convert=(1, 1))
    push("gross just above", records=(fee_row(gross=500001), NONE), convert=(1, 1))
    push("gross above receive 1", records=(NONE, fee_row(gross=400000000)))
    push("gross equals receive 1", records=(NONE, fee_row(gross=350000000)))
    push("converted to zero", records=(fee_row(gross=2, rebate=1), fee_row(rebate=2)), convert=(1, 7))
    push("convert fails gross", records=(GROSS, NONE), convert_fail=(9000,))
    push("convert fails rebate", records=(NONE, REBATE), convert_fail=(1500,))
    push("self trade", party=(BUYER, BUYER), balances=balances_with({(BUYER, 3): (10 ** 12, 10 ** 9, 5)}), records=(BOTH, BOTH))
    push("self trade underflow", party=(BUYER, BUYER), balances=balances_with({(BUYER, 2): (350000000, 0, 5), (BUYER, 3): (500000, 0, 5)}), convert=(1, 1), unit=(1, 3, 500000), records=(fee_row(gross=500000), NONE), px=70000)
    push("self debit underflow", party=(BUYER, BUYER), balances=balances_with({(BUYER, 2): (350000000, 0, 5), (BUYER, 3): (500000, 0, 5)}), records=(fee_row(gross=200000), fee_row(gross=350000000)), convert=(1, 1))
    for share in (0, 1, 25000, 50000, 99999, 100000, 100001, 101000, 101001, 200000, 1 << 40):
        table = world()["tokens"][:]
        table[2], table[3] = (3, DEPLOY_A, share), (3, DEPLOY_A, share)
        push("share %d" % share, tokens=table, records=(BOTH, BOTH))
        push("share large %d" % share, tokens=table, records=(fee_row(gross=4000000), fee_row(gross=300000000)), convert=(1, 1))
        push("share huge %d" % share, tokens=table, records=(fee_row(gross=400000), fee_row(gross=300000000)), convert=(1, 1), balances=balances_with({(DEPLOY_A, 3): (MAX - 3, 0, 9)}))
        wide = dict(world()["quotes"])
        wide[3] = 1
        push("listed share %d" % share, tokens=table, records=(BOTH, BOTH), quotes=wide)
    table = world()["tokens"][:]
    table[2] = (3, DEPLOY_B, 101000)
    table[3] = (3, DEPLOY_B, 100000)
    push("deployer no row", tokens=table, records=(BOTH, BOTH), sets={BUYER: (2, 3), SELLER: (2, 3)})
    push("flag clear", tokens=[(2, 0, 50000)] * 10, records=(BOTH, BOTH))
    push("flag bit only", tokens=[(1, DEPLOY_A, 50000)] * 10, records=(BOTH, BOTH))
    push("flag high", tokens=[(0xFE, DEPLOY_A, 50000)] * 10, records=(BOTH, BOTH))
    push("token 3 past list", tokens=[(2, 0, 0)] * 3, records=(BOTH, BOTH))
    push("token 2 past list", tokens=[(2, 0, 0)] * 2, records=(BOTH, BOTH))
    push("token edge", tokens=[(2, 0, 0)] * 4, records=(BOTH, BOTH))
    push("token past list when short", tokens=[(2, 0, 0)] * 2, records=(fee_row(builder_tag=1, builder=100), fee_row(builder_tag=1, builder=100)))
    for name, left, right, pool in (("short pool ok", fee_row(rebate=1100), REBATE, {1: 500, 2: 7000000, 3: 100000000}), ("short pool small", REBATE, REBATE, {2: 10, 3: 10}), ("short no pool", REBATE, REBATE, {}), ("short exact", REBATE, REBATE, {2: 1500, 3: 642}), ("even", fee_row(gross=7000, rebate=3000), fee_row(gross=3000, rebate=7000), {2: 5, 3: 5}),
                                    ("builder short", fee_row(builder_tag=1, builder=900), fee_row(gross=100, builder_tag=1, builder=100), {2: 20000, 3: 30000}), ("referrer short", fee_row(referrer_tag=1, referrer=900), fee_row(referrer_tag=1, referrer=33), {2: 20, 3: 40}), ("extra short", fee_row(extra=900), fee_row(extra=33), {2: 20, 3: 40})):
        push("tail " + name, records=(left, right), pool=pool)
    push("pool ceiling", records=(GROSS, GROSS), pool={2: MAX - 3, 3: MAX - 3})
    push("pool ceiling edge", records=(fee_row(gross=7), fee_row(gross=3)), pool={2: MAX - 3, 3: MAX - 1})
    push("pool none", records=(GROSS, GROSS), pool={})
    push("pool wide", records=(GROSS, GROSS), pool={at: at + 1 for at in range(1, 40)})
    push("pool wider", records=(BOTH, REBATE), pool={at: at + 1 for at in range(1, 200)})
    push("deployer ceiling", records=(fee_row(gross=4000000), fee_row(gross=300000000)), convert=(1, 1), balances=balances_with({(DEPLOY_A, 2): (MAX - 3, 0, 9), (DEPLOY_A, 3): (MAX - 3, 0, 9)}))
    push("deployer ceiling edge", records=(fee_row(gross=4000000), fee_row(gross=300000000)), convert=(1, 1), balances=balances_with({(DEPLOY_A, 2): (MAX - 150000000, 0, 9), (DEPLOY_A, 3): (MAX - 2000000, 0, 9)}))
    push("accumulator overflow gross", records=(fee_row(gross=MAX), fee_row()), convert=(1, 1), unit=(1, 3, MAX), balances=balances_with({(SELLER, 3): (MAX, 0, 1), (BUYER, 3): (0, 0, 1)}))
    return rows


def split_cases():
    rows = []

    def push(label, **over):
        rows.append(world(kind="split", label=label, **over))
    amounts = (0, 1, 0x1234567)
    for leg in (0, 1):
        for gross in amounts:
            for rebate in amounts:
                for builder_tag, builder in ((0, 7), (1, 9), (2, 11), (3, 0)):
                    for referrer_tag, referrer in ((0, 13), (1, 17), (0x80, 19)):
                        for extra in (0, 23):
                            record = fee_row(gross, rebate, builder_tag, builder, referrer_tag, referrer, extra)
                            push("grid %d %d %d %d %d %d" % (leg, gross, rebate, builder_tag, referrer_tag, extra), leg=leg, record=record, acc=(100, 200, 300, 400), junk=0xAB00, token=3)
    for leg in (0, 1):
        for slot in range(4):
            for room in (0, 1, 5):
                acc = [10, 20, 30, 40]
                acc[slot] = MAX - room
                push("gross edge %d %d %d" % (leg, slot, room), leg=leg, acc=tuple(acc), record=fee_row(gross=4), convert=(1, 1))
                push("rebate edge %d %d %d" % (leg, slot, room), leg=leg, acc=tuple(acc), record=fee_row(rebate=4), convert=(1, 1))
                push("builder edge %d %d %d" % (leg, slot, room), leg=leg, acc=tuple(acc), record=fee_row(builder_tag=1, builder=4))
                push("referrer edge %d %d %d" % (leg, slot, room), leg=leg, acc=tuple(acc), record=fee_row(referrer_tag=1, referrer=4))
                push("extra edge %d %d %d" % (leg, slot, room), leg=leg, acc=tuple(acc), record=fee_row(extra=4))
                push("mixed edge %d %d %d" % (leg, slot, room), leg=leg, acc=tuple(acc), record=fee_row(builder_tag=1, builder=2, referrer_tag=1, referrer=1, extra=1))
    for leg in (0, 1):
        push("convert fails gross %d" % leg, leg=leg, record=fee_row(gross=5), convert_fail=(5,))
        push("convert fails rebate %d" % leg, leg=leg, record=fee_row(rebate=5), convert_fail=(5,))
        push("convert second %d" % leg, leg=leg, record=fee_row(gross=5, rebate=6), convert_fail=(6,))
        push("convert to zero %d" % leg, leg=leg, record=fee_row(gross=1, rebate=1), convert=(1, 9))
    return rows


def charge_cases():
    rows = []

    def push(label, **over):
        base = dict(balances=balances_with({(SELLER, 2): (10 ** 12, 10 ** 6, 0x34), (SELLER, 1): (10 ** 9, 10 ** 3, 0x39)}), records=(NONE, GROSS), outcome=True)
        base.update(over)
        rows.append(world(kind="charge", label=label, **base))
    for spot in range(len(PAIRS)):
        for outcome in (False, True):
            for taker in (0, 1):
                for flag in (0, 1):
                    push("spot %d/%d/%d/%d" % (spot, outcome, taker, flag), spot=spot, outcome=outcome, taker=taker, flag=flag, records=(NONE, BOTH), tokens=world()["tokens"] + [(2, 0, 0)] * 22)
    fees = (("none", NONE), ("gross", GROSS), ("rebate dropped", REBATE), ("both", BOTH), ("paid", PAID), ("all", fee_row(9000, 1100, 1, 100, 1, 70, 40)), ("tag bits", fee_row(9000, 0, 2, 100, 0, 70, 0)), ("byte", fee_row(9000, 0, 0, 100, 0x80, 70, 0)))
    for name, record in fees:
        push("fee " + name, records=(BOTH, record))
    push("zero count", count=0)
    push("count high", count=0x100)
    push("zero px", px=0)
    push("spot one past", spot=len(PAIRS))
    push("spot far past", spot=1 << 40)
    for name, entry in (("fits", (10 ** 12, 10 ** 6, 1)), ("exact", (9000, 0, 1)), ("exact hold", (10000, 1000, 1)), ("below", (8999, 0, 1)), ("one above", (9001, 0, 1)), ("hold eats", (10000, 1001, 1)), ("hold all", (10000, 10000, 1)),
                        ("hold over", (10000, 20000, 1)), ("hold max", (10 ** 12, MAX, 1)), ("hold near max", (MAX, MAX - 5, 1)), ("hold max edge", (MAX, MAX - 9000, 1)), ("zero", (0, 0, 1)), ("missing", None)):
        push("balance " + name, balances=balances_with({(SELLER, 2): entry}))
        push("balance big " + name, balances=balances_with({(SELLER, 2): entry}), records=(NONE, PAID))
    push("no row", rows=(BUYER, DEPLOY_A), balances={key: value for key, value in balances_with({}).items() if key[0] != SELLER})
    push("deep balances", balances=deep(30))
    push("deeper balances", balances=deep(170))
    push("new token in deep", balances={key: value for key, value in deep(30).items() if key != (SELLER, 2)})
    push("zero fee no entry", balances=balances_with({(SELLER, 2): None}), records=(NONE, NONE))
    for share in (0, 1, 50000, 100000, 100001, 101000, 101001, 1 << 40):
        table = world()["tokens"][:]
        table[2] = (3, DEPLOY_A, share)
        table[3] = (3, DEPLOY_B, share)
        push("share %d" % share, tokens=table, sets={SELLER: (2,)})
        push("share big %d" % share, tokens=table, records=(NONE, fee_row(gross=4000000)))
        wide = dict(world()["quotes"])
        wide[2] = 1
        push("listed share %d" % share, tokens=table, quotes=wide)
    push("flag clear", tokens=[(2, 0, 50000)] * 10)
    push("flag bit", tokens=[(1, DEPLOY_A, 50000)] * 10, records=(NONE, PAID))
    push("base past list", tokens=[(2, 0, 0)] * 3)
    push("quote past list", tokens=[(2, 0, 0)] * 2, spot=2)
    push("token edge", tokens=[(2, 0, 0)] * 4)
    push("short", records=(NONE, fee_row(builder_tag=1, builder=900)), pool={2: 100000})
    push("short pool small", records=(NONE, fee_row(builder_tag=1, builder=900)), pool={2: 5})
    push("short no pool", records=(NONE, fee_row(referrer_tag=1, referrer=900)), pool={})
    push("short extra", records=(NONE, fee_row(extra=900)), pool={2: 899})
    push("even", records=(NONE, fee_row(gross=900, extra=900)), pool={2: 5})
    push("pool ceiling", records=(NONE, GROSS), pool={2: MAX - 3})
    push("deployer ceiling", records=(NONE, fee_row(gross=4000000)), balances=balances_with({(SELLER, 2): (MAX, 0, 1), (DEPLOY_A, 2): (MAX - 3, 0, 1)}))
    push("deployer no row", tokens=[(2, 0, 0), (2, 0, 0), (3, DEPLOY_B, 50000), (3, DEPLOY_B, 50000)] + [(2, 0, 0)] * 6, sets={})
    push("sets deep", sets={user: tuple(range(1, 16)) for user in (BUYER, SELLER, DEPLOY_A)})
    return rows


def all_cases():
    return split_cases() + fill_cases() + charge_cases() + edge_cases()


WIDE_QUOTES = {key: key & 1 for key in range(32, 62)}
WIDE_QUOTES.update({1: 0, 9: 3})
WIDE_ALIGNED = {key: 0 for key in range(32, 62)}
WIDE_ALIGNED.update({2: 1, 7: 0})
EDGE_PAIRS = PAIRS + ((31, 2), (62, 2), (40, 41), (39, 41), (3, 62), (3, 40))
EDGE_TOKENS = [(3, DEPLOY_A, 30000 + at) for at in range(64)]


def high_world(kind, label, **over):
    """Parties whose addresses sort above every other user, so a user descent runs off each node's end."""
    users = (36, 35, 34)
    table = {}
    for (user, token), value in balances_with({}).items():
        table[({BUYER: 36, SELLER: 35, DEPLOY_A: 34}[user], token)] = value
    crowd = {index: (2,) for index in range(3, 34)}
    crowd.update({36: (2, 3), 35: (2, 3), 34: (2,)})
    tokens = [(flag, 34 if deployer == DEPLOY_A else deployer, share) for flag, deployer, share in world()["tokens"]]
    case = dict(kind=kind, label=label, party=users[:2], balances=table, rows=users, sets=crowd, known=tuple(sorted(crowd)) + (DEPLOY_B,), tokens=tokens)
    case.update(over)
    return world(**case)


def edge_cases():
    rows = []

    def fill(label, **over):
        rows.append(world(kind="fill", label=label, **over))

    def charge(label, **over):
        base = dict(balances=balances_with({(SELLER, 2): (10 ** 12, 10 ** 6, 0x34), (SELLER, 1): (10 ** 9, 10 ** 3, 0x39)}), records=(NONE, GROSS), outcome=True)
        base.update(over)
        rows.append(world(kind="charge", label=label, **base))
    for spot in range(len(EDGE_PAIRS)):
        for outcome in (False, True):
            base, quote = EDGE_PAIRS[spot]
            table = balances_with({(SELLER, base): (10 ** 12, 10 ** 9, 0x37), (BUYER, quote): (10 ** 12, 10 ** 10, 0x38), (SELLER, quote): (10 ** 12, 10 ** 6, 0x39)})
            shared = dict(spot=spot, outcome=outcome, pairs=EDGE_PAIRS, tokens=EDGE_TOKENS, quotes=WIDE_QUOTES, aligned=WIDE_ALIGNED, balances=table)
            fill("edge fill %d/%d" % (spot, outcome), unit=(1, base, 500000), records=(BOTH, PAID), **shared)
            charge("edge charge %d/%d" % (spot, outcome), records=(NONE, PAID), **shared)
    fill("empty sets no rebate", sets={})
    fill("empty sets gross", sets={}, records=(GROSS, GROSS))
    for name, cut in (("rebate new", ((BUYER, 2), (SELLER, 3))), ):
        table = {key: value for key, value in deep(30).items() if key not in cut}
        fill("deep %s" % name, balances=table, px=0, unit=(1, 3, 0), records=(REBATE, REBATE))
        table = {key: value for key, value in balances_with({}).items() if key not in cut}
        fill("flat %s" % name, balances=table, px=0, unit=(1, 3, 0), records=(REBATE, REBATE))
    table = {(user, 1 + at * 2): (5, 0, 0) for user in (BUYER, SELLER) for at in range(60)}
    table[(BUYER, 2)] = (10 ** 12, 0, 1)
    table[(SELLER, 3)] = (10 ** 12, 0, 1)
    fill("balance rows either side", balances=table, records=(REBATE, BOTH))
    fill("balance keys above", balances={**balances_with({}), **{(user, 1000 + at): (5, 0, 0) for user in (BUYER, SELLER) for at in range(14)}}, records=(BOTH, BOTH))
    fill("balance keys below", balances={**{(user, at + 10): (5, 0, 0) for user in (BUYER, SELLER) for at in range(14)}, (BUYER, 4000): (10 ** 12, 0, 1), (SELLER, 5000): (10 ** 12, 0, 1)}, pairs=((5000, 4000),), tokens=[(2, 0, 0)] * 8, spot=0, unit=(1, 5000, 500000), records=(BOTH, BOTH), convert_fail=(), stale=(5000, 4000, 1000), pool={4: 1})
    for name, left, right in (("pool wide short", REBATE, REBATE), ("pool wide new", GROSS, GROSS), ("pool wide short new", REBATE, fee_row(rebate=3))):
        fill(name, records=(left, right), pool={at: at + 1 for at in range(1, 200) if "new" not in name or at > 3})
    fill("pool above", records=(GROSS, REBATE), pool={at + 100: at + 1 for at in range(30)})
    fill("pool above short", records=(REBATE, REBATE), pool={at + 100: at + 1 for at in range(30)})
    fill("pool below", records=(GROSS, REBATE), pool={at: at + 1 for at in (0,)})
    for share in (99999, 100000, 101000):
        table = world()["tokens"][:]
        table[2] = (3, DEPLOY_A, share)
        fill("clamp %d" % share, tokens=table, px=1, sz=MAX, unit=(1, 3, 0), records=(NONE, fee_row(gross=MAX)), balances=balances_with({(BUYER, 2): (MAX, 0, 1), (SELLER, 2): (0, 0, 1), (DEPLOY_A, 2): (0, 0, 1)}))
        charge("clamp %d" % share, tokens=table, records=(NONE, fee_row(gross=MAX)), balances=balances_with({(SELLER, 2): (MAX, 0, 1), (DEPLOY_A, 2): (0, 0, 1)}))
    fill("no aligned map", aligned={}, records=(BOTH, BOTH))
    fill("no quote map", quotes={}, records=(BOTH, BOTH))
    fill("listed, no aligned map", aligned={}, quotes={3: 0}, records=(BOTH, BOTH))
    charge("no aligned map", aligned={})
    charge("no quote map", quotes={}, outcome=False)
    fill("pool below short", records=(REBATE, REBATE), pool={0: 5})
    fill("pool below deep", records=(REBATE, REBATE), pool={0: 5, **{at: 5 for at in range(4, 4)}}, unit=(1, 3, 500000))
    charge("pool below short", spot=6, pairs=EDGE_PAIRS[:10] + EDGE_PAIRS[10:], tokens=EDGE_TOKENS, records=(NONE, REBATE), pool={0: 5})
    bigger = {at: at + 1 for at in range(1, 40)}
    charge("pool high quote short", pairs=((3, 62),), spot=0, tokens=EDGE_TOKENS, records=(NONE, fee_row(extra=900)), pool=bigger, balances=balances_with({(SELLER, 62): (10 ** 9, 0, 1)}))
    charge("pool high quote", pairs=((3, 62),), spot=0, tokens=EDGE_TOKENS, records=(NONE, GROSS), pool=bigger, balances=balances_with({(SELLER, 62): (10 ** 9, 0, 1)}))
    charge("pool deep miss", records=(NONE, GROSS), pool={at + 100: 1 for at in range(30)})
    charge("pool deep miss short", records=(NONE, fee_row(extra=900)), pool={at + 100: 1 for at in range(30)})
    charge("pool flat miss above", pairs=((3, 62),), spot=0, tokens=EDGE_TOKENS, records=(NONE, GROSS), pool={5: 1}, balances=balances_with({(SELLER, 62): (10 ** 9, 0, 1)}))
    fill("one token self trade", party=(BUYER, BUYER), pairs=((2, 2),), spot=0, unit=(1, 2, 350000000), records=(fee_row(gross=350000000), fee_row(gross=350000000)), convert=(1, 1), balances=balances_with({(BUYER, 2): (350000000, 0, 7)}))
    fill("one token self trade fits", party=(BUYER, BUYER), pairs=((2, 2),), spot=0, unit=(1, 2, 350000000), records=(fee_row(gross=350), fee_row(gross=350)), convert=(1, 1), balances=balances_with({(BUYER, 2): (350000700, 9, 7)}))
    fill("aligned stale slot", aligned={1: 1}, records=(BOTH, BOTH))
    charge("aligned stale slot", aligned={1: 1})
    fill("aligned three", aligned={0: 1, 1: 1, 8: 1}, records=(BOTH, BOTH), stale=(5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2))
    charge("aligned three", aligned={0: 1, 1: 1, 8: 1}, stale=(5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2))
    fill("no set row plain", sets={DEPLOY_A: (2,)})
    fill("low user plain", sets={SELLER: (2, 3), DEPLOY_A: (2,)})
    fill("users after plain", sets={DEPLOY_A: (2,), 5: (2,), 6: (2,)}, known=(BUYER, SELLER, DEPLOY_A, DEPLOY_B, 5, 6))
    crowd = {index: (2,) for index in range(5, 37)}
    fill("many users plain", sets=crowd, known=tuple(sorted(crowd)) + (BUYER, SELLER, DEPLOY_A, DEPLOY_B))
    decoys = {(user, at): (5, 0, 0) for user in (BUYER, SELLER) for at in range(10, 24)}
    table = {**decoys, (BUYER, 62): (10 ** 12, 0, 1), (SELLER, 63): (10 ** 12, 0, 1), (DEPLOY_A, 63): (1, 0, 0), (BUYER, 63): (2, 0, 1), (SELLER, 62): (3, 0, 1)}
    fill("rightmost keys", balances=table, pairs=((63, 62),), spot=0, tokens=EDGE_TOKENS, unit=(1, 63, 500000), records=(BOTH, BOTH), stale=(63, 62, 1000), pool={4: 1})
    fill("rightmost keys plain", balances=table, pairs=((63, 62),), spot=0, tokens=EDGE_TOKENS, unit=(1, 63, 500000), stale=(63, 62, 1000), pool={4: 1})
    charge("rightmost keys", balances=table, pairs=((63, 62),), spot=0, tokens=EDGE_TOKENS, stale=(63, 62, 1000), pool={4: 1})
    for name, left, right in (("big pool short", REBATE, REBATE), ("big pool mixed", GROSS, REBATE)):
        fill(name, records=(left, right), pool={at: 10 ** 7 + at for at in range(1, 200)})
    charge("big pool short", records=(NONE, fee_row(extra=900)), pool={at: 10 ** 7 + at for at in range(1, 200)})
    fill("big pool right short", records=(REBATE, REBATE), pool={at: 10 ** 7 + at for at in range(1, 200)}, pairs=((180, 170),), spot=0, tokens=EDGE_TOKENS + [(2, 0, 0)] * 140, unit=(1, 180, 500000), balances=balances_with({(SELLER, 180): (10 ** 12, 0, 1), (BUYER, 170): (10 ** 12, 0, 1)}))
    charge("big pool right", records=(NONE, GROSS), pool={at: 10 ** 7 + at for at in range(1, 200)}, pairs=((180, 170),), spot=0, tokens=EDGE_TOKENS + [(2, 0, 0)] * 140, balances=balances_with({(SELLER, 170): (10 ** 12, 0, 1)}))
    charge("big pool right short", records=(NONE, fee_row(extra=900)), pool={at: 10 ** 7 + at for at in range(1, 200)}, pairs=((180, 170),), spot=0, tokens=EDGE_TOKENS + [(2, 0, 0)] * 140, balances=balances_with({(SELLER, 170): (10 ** 12, 0, 1)}))
    table = balances_with({(SELLER, 30): (10 ** 12, 0, 1), (BUYER, 31): (10 ** 12, 0, 1), (SELLER, 31): (10 ** 12, 0, 1)})
    fill("tokens above quote keys", spot=5, tokens=EDGE_TOKENS, unit=(1, 30, 500000), records=(BOTH, BOTH), balances=table)
    charge("tokens above quote keys", spot=5, tokens=EDGE_TOKENS, balances=table)
    charge("rebate one", records=(NONE, fee_row(gross=9000, rebate=1)))
    charge("rebate two", records=(NONE, fee_row(gross=9000, rebate=2)))
    rows.append(high_world("fill", "high users", records=(BOTH, BOTH)))
    rows.append(high_world("fill", "high users empty", records=(REBATE, GROSS)))
    rows.append(high_world("charge", "high users charge", balances={(35, 2): (10 ** 12, 0, 1), (34, 2): (5, 0, 1), (34, 3): (5, 0, 1)}, records=(NONE, PAID), outcome=True))
    rows.append(high_world("fill", "high users new", records=(REBATE, BOTH), sets={index: (2,) for index in range(3, 34)}))
    rows.append(high_world("charge", "high users charge new", balances={(35, 2): (10 ** 12, 0, 1)}, rows=(35,), records=(NONE, PAID), outcome=True, sets={index: (2,) for index in range(3, 34)}))
    return rows


REAL = (FILL_FN, CHARGE_FN, SPLIT_FN, PARTY_ITER, BALANCE_ENTRY, POOL_ENTRY, USER_ENTRY, SET_INSERT, 0x2F4CEF0, 0x2F40170, 0x2F83500, 0x2F42FA0)
FUNCTIONS = (("matched fill", FILL_FN), ("order charge", CHARGE_FN), ("fee split", SPLIT_FN))
HELPERS = (("party copy", PARTY_ITER), ("balance entry", BALANCE_ENTRY), ("pool entry", POOL_ENTRY), ("user entry", USER_ENTRY), ("set insert", SET_INSERT),
           ("balance leaf insert", 0x2F4CEF0), ("set leaf insert", 0x2F40170), ("user leaf insert", 0x2F83500), ("pool leaf insert", 0x2F42FA0))
STUBS = (
    ("0x3742460", "fee body", "fees-trade-fee-94; arguments checked, record bytes come from the vector"),
    ("0x333e310", "token unit conversion", "RE-001-spot-meta-333e310-94; arguments checked, a fixed ratio stands in"),
    ("0x375e300", "base wei for a fill, slot 0x57747a0", "arguments checked; output words come from the vector"),
    ("0x3728670", "outcome token predicate, slot 0x5773198", "fees-aligned-quote-94; every call listed and compared"),
    ("0x35964f0", "user row, inserts", "first argument state +0x298; row created on a miss"),
    ("0x371b3a0", "user row, read only, slot 0x5773170", "first argument state; a shared empty row on a miss"),
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
    machine.step_limit = 12000
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
    slots = {slot for slot, target in relative.items() if target in (FILL_FN, CHARGE_FN)}
    rows = []
    for site, slot in slot_callers(image, slots):
        rows.append(("%#x" % site, "%#x" % image.fde(site)[0], "slot %#x" % slot, "%#x" % relative[slot]))
    for site, target in direct_callers(image, [SPLIT_FN]):
        rows.append(("%#x" % site, "%#x" % image.fde(site)[0], "direct", "%#x" % target))
    return rows


LOCATIONS = (
    (LOC_SPOT, "panic", "spot past the pair list, matched fill"),
    (LOC_SPOT_CHARGE, "panic", "spot past the pair list, order charge"),
    (LOC_TOKEN, "panic", "token past the token rows, net not negative"),
    (LOC_RECEIVE, "panic", "gross above the received amount"),
    (LOC_DEBIT, "panic", "paid amount above total; needs a self trade with one token"),
    (LOC_RECEIVE_ADD, "panic 0xbe", "received amount overflows total"),
    (LOC_REBATE_ADD, "panic 0xbe", "rebate overflows total of the paid token"),
    (LOC_CONVERT, "panic", "token conversion refused"),
    (LOC_GROSS, "panic 0xbe", "gross overflows an accumulator"),
    (LOC_REBATE, "panic 0xbe", "rebate overflows an accumulator"),
    (LOC_BUILDER, "panic 0xbe", "record +8 overflows an accumulator"),
    (LOC_REFERRER, "panic 0xbe", "record +0x30 overflows an accumulator"),
    (LOC_EXTRA, "panic 0xbe", "record +0x60 overflows an accumulator"),
    (LOC_FLOOR, "recorder kind 0", "saturating subtraction at 0"),
    (LOC_CEILING, "recorder kind 0", "saturating addition at the top"),
    (LOC_SHORT_FILL, "recorder kind 2", "paid above collected, matched fill"),
    (LOC_SHORT_CHARGE, "recorder kind 2", "paid above collected, order charge"),
)


def location_rows(image):
    relative = relative_slots(image)
    rows = []
    for slot, kind, meaning in LOCATIONS:
        path, line, column = image.location(slot, relative)
        rows.append(("%#x" % slot, kind, path, line, column, meaning))
    return rows


PINS = (
    ("0x26fe8c4", "498b8f20040000", "spot sweep 0x26fe810 loads exchange +0x420"),
    ("0x26fe8d4", "498d9780000000", "the sweep's spot clearinghouse is exchange +0x80, so exchange +0x420 is clearinghouse +0x3a0"),
    ("0x26fe91b", "0fb791ba000000", "the sweep reads node length +0xba, the shape of the fee pool tree here"),
    ("0x372cb07", "498d9fa0030000", "matched fill: tail works on clearinghouse +0x3a0"),
    ("0x372c332", "498b8708040000", "matched fill: token index at clearinghouse +0x400, height +0x408"),
    ("0x372cc2b", "f68408d200000001", "matched fill: token row +0xd2 bit 0"),
    ("0x372cd4f", "4883b8a800000000", "matched fill: listed token, row +0xa8 not 0 gives 0"),
    ("0x372ce42", "4805d3000000", "matched fill: deployer address at row +0xd3"),
    ("0x372bd63", "498b9f60020000", "matched fill: quote token map at clearinghouse +0x260"),
    ("0x372e300", "48c784 24d801000000000000", "order charge: record +0x58 cleared before the split"),
    ("0x372e385", "b901000000", "order charge: split runs with leg 1"),
    ("0x3c019e2", "753c", "split: record +0x28 byte test"),
    ("0x24fcde7", "7425", "order charge caller: skipped when the outcome test returns false"),
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


FLOATS = ((0x20A9E8, DENOMINATOR, "share denominator"), (0x20A528, CAP, "largest share factor"), (0x20A510, 18446744073709551616.0, "clamp before the cast"), (0x20A218, 18446744073709549568.0, "above this the amount is all ones"))


def float_rows(image):
    rows = []
    for va, value, text in FLOATS:
        data = bytes(image.blob[image.offset(va):image.offset(va) + 8])
        if struct.unpack("<d", data)[0] != value:
            raise EvidenceError("constant %#x" % va)
        rows.append(("%#x" % va, data.hex(), repr(value), text))
    return rows


def path_rows():
    return (
        (1, "caller", "0x26e9acc, 0x430ef6c, 0x431a35c", "matched fill; second argument is one byte from the caller, carried to fee record +0x56"),
        (2, "amounts", "0x372b9d0", "slot 0x57747a0 gives base token, ok bit, base wei; quote wei = px * sz; overflow or ok clear returns with no change; spot past the list panics first"),
        (3, "balance gate", "0x372b9d0", "party 0 total of quote >= quote wei, party 1 total of base >= base wei; hold is not read; a miss returns with no change"),
        (4, "fee gate", "0x372b9d0", "pair base in clearinghouse +0x260 gives class 1; else outcome test true means no fee record; else class 0"),
        (5, "fee", "0x3742460", "per party record, cross byte = party index == fill +0x224 (fees-trade-fee-94, fees-aligned-quote-94)"),
        (6, "split", "0x3c018a0", "accumulators by leg, see split-rules.tsv"),
        (7, "party balances", "0x372b9d0", "gross leaves the received amount, rebate goes to the paid token, then receive, then pay; total and hold both fall"),
        (8, "tail", "0x372b9d0", "for base then quote: paid above collected takes the gap from the pool; else deployer share, then the rest to the pool"),
        (9, "sweep", "0x26fe810", "exchange +0x420 = clearinghouse +0x3a0: the pool is what fees-collection-94 drains"),
        (10, "order charge", "0x372e0a0", "one party, leg 1, record +0x58 cleared; fee taken from quote, at most total - hold; pool takes the uncapped accumulator"),
    )


def split_rows():
    return (
        ("record +0x50 gross", "leg 0", "converted, added to acc[0]", "taken from the received amount"),
        ("record +0x50 gross", "leg 1", "as is, added to acc[1]", "taken from the received amount"),
        ("record +0x58 rebate", "leg 0", "as is, added to acc[3]", "credited to total of the paid token"),
        ("record +0x58 rebate", "leg 1", "converted, added to acc[2]", "credited to total of the paid token"),
        ("record +8, tag +0 bit 0", "leg n", "added to acc[2 + n]", "no balance effect here"),
        ("record +0x30, tag +0x28 byte", "leg n", "added to acc[2 + n]", "no balance effect here"),
        ("record +0x60, skipped when 0", "leg n", "added to acc[2 + n]", "no balance effect here"),
        ("acc[0] - acc[2]", "base token", "net of the base token", "tail"),
        ("acc[1] - acc[3]", "quote token", "net of the quote token", "tail"),
    )


def reference_rows():
    return (
        ("l1/spot_clearinghouse/cl_trait.rs update_supply_delta", "before >= after subtracts, else adds", "collected >= paid adds, else subtracts: the sign is reversed"),
        ("l1/spot_clearinghouse/cl_trait.rs update_supply_delta", "no deployer share", "deployer credit comes before the pool"),
        ("l1/spot_clearinghouse/cl_trait.rs token_supply_deltas", "a supply delta", "fee pool: exchange +0x420 in the sweep 0x26fe810"),
        ("l1/spot_clearinghouse/types.rs adjust_pair_supply_delta", "gross = base wei, offset = quote wei", "inputs are the accumulators, never the fill amounts"),
        ("l1/spot_clearinghouse/types.rs TokenInfo::deployer_share", "needs aligned_quote.active", "no aligned test; row +0xd2 bit 0 and not listed in clearinghouse +0x260"),
        ("l1/spot_clearinghouse/types.rs credit_deployer_share", "returns early at credit 0", "row, balance entry and index row are still created"),
        ("l1/spot_clearinghouse/cl_trait.rs balance_covers", "available >= wei, 0 always passes", "total >= wei, hold not read; a missing entry passes only at 0"),
        ("l1/spot_clearinghouse/cl_trait.rs settle_one_party", "receive_delta = leg0, debit_delta = leg1", "receive = fill amount - gross; pay = fill amount; rebate credited on the paid token"),
        ("l1/spot_clearinghouse/cl_trait.rs settle_one_party", "spot side picks the tokens", "party 0 always receives base, party 1 always receives quote"),
        ("l1/spot_clearinghouse/cl_trait.rs reserve_resting_spot_order", "the nearest shape for one party", "0x372e0a0 raises no hold: it takes a fee capped by total - hold"),
    )


DEAD = "panic or saturation arm the checks before it rule out"
PAD = "padding or unwind pad"
UNREACHED = "arm after a check that rules it out: fee cannot pass total - hold, and no pool root can be null after the first token"
COPY_SIZE = "copy of 0xdd bytes instead of 0xdc: the user address ends at 0xdc and the frame has room"
TAG = "tag 2 is the empty option of 0x3bb6760, which writes 0 or 1 here, so the arm never runs"
PAD_KEY = "4 bytes past the 20-byte address key in the frame"
LEAF = "height word of a leaf or rootless handle, the insert does not read it"
ZERO = "listed token: both arms give amount 0"
HIGH = "the amount is a multiple of 2048 at or above 2^63, so bit 0 stays clear"
POSITIVE = "the product is never negative, so the initial 0 stays unused"
REASONS = {
    0x372BA99: "end word of the party iterator, never read: the loop takes exactly 2 steps",
    0x372BB56: COPY_SIZE, 0x372BB69: COPY_SIZE, 0x372BB84: COPY_SIZE, 0x372BB9A: COPY_SIZE, 0x372BBB8: COPY_SIZE, 0x372BBCB: COPY_SIZE, 0x372BBD9: COPY_SIZE, 0x372BBEF: COPY_SIZE,
    0x372BBFF: TAG, 0x372D418: TAG,
    0x372C4A9: PAD_KEY, 0x372C86B: PAD_KEY, 0x372D0C9: PAD_KEY,
    0x372CA23: LEAF, 0x372CA4C: LEAF, 0x372CA65: LEAF, 0x372CA96: LEAF, 0x372CABF: LEAF, 0x372D2E1: LEAF, 0x372ED7C: LEAF, 0x372ED99: LEAF, 0x372EE14: LEAF,
    0x372CD4F: ZERO, 0x372CD57: ZERO, 0x372CD75: ZERO, 0x372E834: ZERO, 0x372E83C: ZERO, 0x372E85A: ZERO,
    0x372CE03: HIGH, 0x372E8E9: HIGH, 0x372CE26: POSITIVE, 0x372E90C: POSITIVE,
    0x372E60C: "the base token is never short here: acc[0] and acc[2] stay 0, so this arm only runs on the last token",
}
GROUP_REASONS = "not classified"


def analyse(image, full=True, reached_out=None):
    cases = all_cases()
    harness = Harness(image)
    machine = harness.machine
    mismatches, first = 0, ""
    reached = []
    kinds = {}
    digest = hashlib.sha256()
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
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched)})
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
        return UNREACHED
    return REASONS.get(row["va"], GROUP_REASONS)


def write_tsv(path, header, rows):
    lines = ["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def flow_rows(image):
    """One row per named case from the evaluated bytes: what moved."""
    harness = Harness(image)
    rows = []
    for label, kind, over in FLOWS:
        case = world(kind=kind, label=label, **over)
        failed = compare_run(harness, case)
        if failed:
            raise EvidenceError("flow %s: %s" % (label, failed))
        got = harness.state_view()
        before = case["balances"]

        def delta(user, token):
            old = before.get((user, token), (0, 0, 0))
            new = got["balances"].get((user, token), (0, 0, 0))
            return new[0] - old[0]
        pool = {token: got["pool"].get(token, 0) - case["pool"].get(token, 0) for token in (2, 3)}
        rows.append((label, delta(BUYER, 3), delta(BUYER, 2), delta(SELLER, 3), delta(SELLER, 2), delta(DEPLOY_A, 3), delta(DEPLOY_A, 2), pool[3], pool[2]))
    return rows


FLOWS = (
    ("no fee records", "fill", dict(records=(NONE, NONE), outcome=True)),
    ("class 0, gross both parties", "fill", dict(records=(GROSS, GROSS))),
    ("gross 9000 + rebate 1100 both", "fill", dict(records=(BOTH, BOTH))),
    ("builder, referrer, extra on party 0", "fill", dict(records=(PAID, GROSS))),
    ("rebates only, pool pays", "fill", dict(records=(REBATE, REBATE))),
    ("charge, cap by total - hold", "charge", dict(records=(NONE, GROSS), outcome=True, balances={(SELLER, 2): (10000, 5000, 7)})),
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    image = load_image()
    evidence, results = analyse(image)
    if evidence["mismatches"]:
        raise EvidenceError("specification mismatch: %s" % evidence["first_mismatch"])
    evidence["constants"] = [dict(zip(("address", "bytes", "value", "meaning"), row)) for row in float_rows(image)]
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.json").write_text(json.dumps(evidence, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    write_tsv(out / "path-map.tsv", ("order", "stage", "address", "behaviour"), path_rows())
    write_tsv(out / "split-rules.tsv", ("input", "leg", "accumulator", "balance_effect"), split_rows())
    write_tsv(out / "call-sites.tsv", ("site", "function", "form", "target"), caller_rows(image))
    write_tsv(out / "locations.tsv", ("record", "use", "file", "line", "column", "meaning"), location_rows(image))
    write_tsv(out / "pins.tsv", ("address", "bytes", "meaning"), pin_rows(image))
    write_tsv(out / "stubs.tsv", ("address", "role", "note"), STUBS)
    write_tsv(out / "flows.tsv", ("case", "buyer_base", "buyer_quote", "seller_base", "seller_quote", "deployer_base", "deployer_quote", "pool_base", "pool_quote"), flow_rows(image))
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
