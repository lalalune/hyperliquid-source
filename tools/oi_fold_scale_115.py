#!/usr/bin/env python3
"""Rebuild the node #115 open-interest fold, its owner and the two f64 scale clamps, and prove them on the bytes.

The fold at 0x37c0fd0 sums, over a run of step indexes, the product of two per-key values found in two
containers (each either a B-tree map or a sorted ring of 16-byte pairs, with an array fallback for the
first one); the owner at 0x44810d0 runs it from zero and then consumes the first container; the scale
helpers at 0x44811d0 and 0x44812b0 turn a u64 into a clamped i64 through a multiply by an f64 field.
The real bytes of all five functions (including the shared ring search at 0x45547e0) run in a Python
x86-64 evaluator with only the allocator, the B-tree consumer and the panic edges stubbed. A separately
written specification predicts every result, every panic, every consumer call and the iterator write-back.
Conditions and immediates are then mutated on the bytes to show that the comparison can fail. No
disassembler or ELF dump text is parsed and the binary is never executed. Standard library only.
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

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

BTREE_TAG = 0x8000000000000000
STEP_LIMIT = 300000
MUTANT_STEP_LIMIT = 6000

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
HEAP_SIZE = 0x200000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5



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
SHIFTS = {4: "shl", 5: "shr", 7: "sar"}


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
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd"}
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
            self.stub(hook)
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
            self.multiply(row.a, width, self.get(row.b, width), row.target)
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
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.multiply(row.a, width, self.get(row.a, width), self.get(row.b, width))
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

    def multiply(self, destination, width, left, right):
        left = left - (1 << (8 * width)) if left & SIGN[width] else left
        right = right - (1 << (8 * width)) if right & SIGN[width] else right
        product = left * right
        truncated = product & MASK[width]
        self.cf = self.of = product != (truncated - (1 << (8 * width)) if truncated & SIGN[width] else truncated)
        self.sf = bool(truncated & SIGN[width])
        self.zf = truncated == 0
        self.put(destination, width, truncated)

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




# ---- node #115 addresses and layout ----

FOLD = 0x37C0FD0
OWNER = 0x44810D0
SCALE_CLAMPED = 0x44811D0
SCALE_SIGNED = 0x44812B0
RING_SEARCH = 0x45547E0
COLLECT = 0x37BFC90
BTREE_DYING_NEXT = 0x3908620
ENTRIES = (FOLD, OWNER, SCALE_CLAMPED, SCALE_SIGNED, RING_SEARCH, COLLECT)
FOLD_FAMILY = (FOLD, RING_SEARCH)

# GOT slots reached by `call [rip+disp]`; the hook is chosen by the relocated target.
SLOT_MUL_OVERFLOW = 0x64DF870
SLOT_ADD_OVERFLOW = 0x64DF520
SLOT_BOUNDS = 0x64DF620
SLOT_NEG_OVERFLOW = 0x64E00C0
SLOT_DEALLOCATE = 0x64DF4A0
SLOTS = (SLOT_MUL_OVERFLOW, SLOT_ADD_OVERFLOW, SLOT_BOUNDS, SLOT_NEG_OVERFLOW, SLOT_DEALLOCATE)

# read-only f64/u64 constants the scale helpers load
CONST_LOW = 0x459808
CONST_HIGH = 0x459360
CONST_TOP = 0x458E50

KEY_STRIDE = 10000
MULT_FIELD = 0x50
SECOND_FIELD = 0xF0       # second container header inside the market block
ARRAY_PTR_FIELD = 0x150
ARRAY_LEN_FIELD = 0x158
ARRAY_STRIDE = 0x60
ARRAY_VALUE = 0x20
END_FIELD = 0x10
SCALE_FIELD = 0x4E0
LEAF_KEYS = 11
KEYS_AT = 8
VALUES_AT = 0x60
LEN_AT = 0xBA
CHILDREN_AT = 0xC0
LEAF_SIZE = 0xC0
NODE_SIZE = 0x120
PAIR_SIZE = 16

H = HEAP_BASE
MARKET = H + 0x1000
ITER = H + 0x1700
ENV = H + 0x1740
FIRST = H + 0x1780
ARRAY = H + 0x2000
RING_FIRST = H + 0x4000
RING_SECOND = H + 0x4400
NODES = H + 0x8000
USED = 0x12000
MARKET_SIZE = 0x600
OUT_AT = H + 0x1800
SINK = H + 0x1A00
LEN_CELL = H + 0x1A40
BUFFER = H + 0x6000
LEN_SENTINEL = 0x5EED5EED
MARKET_FIELD = 0x18
WRITTEN_LIMIT = 16
SCALE_AT = H + 0x1900
ITER_LOG = 0x48
U64 = MASK[8]


def signed(value):
    value &= U64
    return value - (1 << 64) if value & SIGN[8] else value


def fits(value):
    return -(1 << 63) <= value < (1 << 63)


# ---- specification ----


def lookup(container, key):
    """The map operation both containers implement: exact key match or nothing."""
    return container["items"].get(key)


def fold_spec(case):
    """Result of the fold: ("ok", flag, total, cursor) or ("panic", name, cursor, ...)."""
    cursor, end, total = case["cursor"], case["end"], case["init"]
    while True:
        if cursor >= end:
            return ("ok", 1, total, cursor)
        cursor += 1
        base = KEY_STRIDE * case["mult"]
        if base > U64:
            return ("panic", "mul", cursor)
        key = base + (cursor - 1)
        if key > U64:
            return ("panic", "add", cursor)
        first = lookup(case["first"], key)
        if first is None:
            slot = key % KEY_STRIDE
            if slot >= len(case["array"]):
                return ("panic", "bounds", cursor, slot, len(case["array"]))
            first = case["array"][slot]
        second = lookup(case["second"], key)
        product, overflow = 0, False
        if second is not None:
            product = first * second
            overflow = not fits(product)
        if first < 0 or overflow:
            return ("ok", 0, total, cursor)
        total = total + (product if not overflow else 0)
        if not fits(total):
            return ("ok", 0, signed(total), cursor)


def collect_spec(case):
    """Collector: append the second container's value (0 when absent) for every key in the range to a vector."""
    values, cursor = [], case["cursor"]
    while cursor < case["end"]:
        base = KEY_STRIDE * case["mult"]
        if base > U64:
            return ("panic", "mul", values)
        key = base + cursor
        if key > U64:
            return ("panic", "add", values)
        found = lookup(case["second"], key)
        values.append(0 if found is None else found)
        cursor += 1
    return ("ok", values, case["start"] + len(values))


def owner_spec(case):
    """Owner: fold from zero over [0, end), then consume the first container."""
    inner = dict(case, cursor=0, init=0)
    result = fold_spec(inner)
    first = case["first"]
    if first["kind"] == "tree":
        drop = ("tree", first["root"] != 0, len(first["items"]))
    elif first["cap"] != 0:
        drop = ("free", first["cap"] << 4)
    else:
        drop = ("none",)
    return result, drop


def scale_spec(value, factor, constants, clamped):
    """Both scale helpers; `clamped` selects the 0x44811d0 form (early return, floor at zero)."""
    if clamped and value > 0x028F5C28F5C28F5C:
        return value
    product = float(signed(value)) * factor
    low, high, top = constants
    if to_bits(product) & 0x7FFFFFFFFFFFFFFF > 0x7FEFFFFFFFFFFFFF:
        limited = 0.0
    elif low > product or product > high:
        raised = low if low > product else product
        limited = high if high < raised else raised
    else:
        limited = product
    if limited > top:
        integer = (1 << 63) - 1
    elif not -9223372036854775808.0 <= limited < 9223372036854775808.0:
        integer = -(1 << 63)
    else:
        integer = int(limited)
    if integer == -(1 << 63):
        return ("panic", "negate")
    bound = 0x147AE147AE147AE
    if abs(integer) > bound:
        integer = min(bound, max(-bound, integer))
    if clamped:
        integer = max(integer, 0)
    return integer & U64


# ---- the evaluator harness ----


class Layout:
    """Writes one case into the heap the way the node's collections lay it out."""

    def __init__(self, memory):
        self.memory = memory
        self.next = NODES

    def word(self, at, value, size=8):
        self.memory.write(at, size, value & MASK[8])

    def node(self, size):
        at = self.next
        self.next += size
        return at

    def tree(self, items, height):
        """Build a B-tree of the given height holding `items` (sorted pairs); return the root address."""
        if height == 0:
            at = self.node(LEAF_SIZE)
            for slot, (key, value) in enumerate(items):
                self.word(at + KEYS_AT + slot * 8, key)
                self.word(at + VALUES_AT + slot * 8, value)
            self.word(at + LEN_AT, len(items), 2)
            return at
        children = tree_children(len(items), height)
        spare = len(items) - (children - 1)
        at = self.node(NODE_SIZE)
        groups, separators, taken = [], [], 0
        for child in range(children):
            size = spare // children + (1 if child < spare % children else 0)
            groups.append(items[taken:taken + size])
            taken += size
            if child < children - 1:
                separators.append(items[taken])
                taken += 1
        for slot, (key, value) in enumerate(separators):
            self.word(at + KEYS_AT + slot * 8, key)
            self.word(at + VALUES_AT + slot * 8, value)
        self.word(at + LEN_AT, len(separators), 2)
        for slot, group in enumerate(groups):
            self.word(at + CHILDREN_AT + slot * 8, self.tree(group, height - 1))
        return at

    def container(self, at, spec, buffer):
        if spec["kind"] == "tree":
            self.word(at, BTREE_TAG)
            root = self.tree(sorted(spec["items"].items()), spec["height"]) if spec["root"] else 0
            self.word(at + 8, root)
            self.word(at + 0x10, spec["height"])
            self.word(at + 0x18, len(spec["items"]))
        else:
            self.word(at, spec["cap"])
            self.word(at + 8, buffer)
            self.word(at + 0x10, spec["head"])
            self.word(at + 0x18, len(spec["items"]))
            for index, (key, value) in enumerate(sorted(spec["items"].items())):
                slot = (spec["head"] + index) % spec["cap"]
                self.word(buffer + slot * PAIR_SIZE, key)
                self.word(buffer + slot * PAIR_SIZE + 8, value)


def tree_capacity(height):
    capacity = LEAF_KEYS
    for _ in range(height):
        capacity = 12 * capacity + 11
    return capacity


def tree_minimum(height):
    smallest = 0
    for _ in range(height):
        smallest = 1 + 2 * smallest
    return smallest


def tree_children(count, height):
    """Smallest child count (2..12) whose even split fits a tree of this height; None if no split fits."""
    for children in range(2, 13):
        spare = count - (children - 1)
        if spare >= children * tree_minimum(height - 1) and -(-spare // children) <= tree_capacity(height - 1):
            return children
    return None


def tree_fits(count, height):
    if height == 0:
        return count <= LEAF_KEYS
    return tree_children(count, height) is not None


_RELATIVE = {}


def relative_slots(image):
    if id(image) not in _RELATIVE:
        _RELATIVE[id(image)] = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    return _RELATIVE[id(image)]


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        self.machine.step_limit = STEP_LIMIT if not patches else MUTANT_STEP_LIMIT
        machine = self.machine
        relative = relative_slots(image)
        for slot in SLOTS:
            machine.memory.statics[slot] = relative[slot]
        machine.slots = {
            relative[SLOT_MUL_OVERFLOW]: self.on_mul,
            relative[SLOT_ADD_OVERFLOW]: self.on_add,
            relative[SLOT_BOUNDS]: self.on_bounds,
            relative[SLOT_NEG_OVERFLOW]: self.on_negate,
            relative[SLOT_DEALLOCATE]: self.on_free,
        }
        machine.calls = {BTREE_DYING_NEXT: self.on_next}
        self.layout = Layout(machine.memory)
        self.events = []
        self.pulls = 0

    # -- stubs --

    def on_mul(self, machine):
        raise Panicked(("mul",))

    def on_add(self, machine):
        raise Panicked(("add",))

    def on_bounds(self, machine):
        raise Panicked(("bounds", machine.regs[RDI], machine.regs[RSI]))

    def on_negate(self, machine):
        raise Panicked(("negate",))

    def on_free(self, machine):
        regs = machine.regs
        self.events.append(("free", regs[RDI], regs[RSI], regs[RDX] & MASK[4]))

    def on_next(self, machine):
        regs = machine.regs
        self.events.append(("next", machine.memory.bytes_at(regs[RSI], ITER_LOG)))
        if len(self.events) <= self.pulls:
            machine.memory.write(regs[RDI], 8, 1)
        else:
            machine.memory.write(regs[RDI], 8, 0)

    # -- runs --

    def prepare(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        self.layout.next = NODES
        self.events = []
        layout = self.layout
        layout.word(MARKET + MULT_FIELD, case["mult"])
        layout.word(MARKET + END_FIELD, case["end"])
        layout.word(MARKET + ARRAY_PTR_FIELD, ARRAY)
        layout.word(MARKET + ARRAY_LEN_FIELD, len(case["array"]))
        for index, value in enumerate(case["array"]):
            layout.word(ARRAY + index * ARRAY_STRIDE + ARRAY_VALUE, value)
        layout.container(FIRST, case["first"], RING_FIRST)
        layout.container(MARKET + SECOND_FIELD, case["second"], RING_SECOND)

    def run_fold(self, case):
        self.prepare(case)
        machine, layout = self.machine, self.layout
        layout.word(ITER, MARKET)
        layout.word(ITER + 8, case["cursor"])
        layout.word(ITER + 0x10, case["end"])
        layout.word(ENV, FIRST)
        layout.word(ENV + 8, MARKET)
        machine.real = frozenset(FOLD_FAMILY)
        try:
            machine.run(FOLD, {RDI: ITER, RSI: case["init"] & U64, RDX: ENV})
        except Panicked as stop:
            return ("panic", stop.args[0][0], layout_cursor(machine)) + tuple(stop.args[0][1:])
        flag = machine.regs[RAX]
        return ("ok", flag, signed(machine.regs[RDX]), machine.memory.read(ITER + 8, 8))

    def run_owner(self, case):
        self.prepare(case)
        machine = self.machine
        self.pulls = case["pulls"]
        machine.real = frozenset(FOLD_FAMILY)
        try:
            machine.run(OWNER, {RDI: MARKET, RSI: FIRST})
        except Panicked as stop:
            return ("panic", stop.args[0][0]) + tuple(stop.args[0][1:]), self.events
        return ("ok", machine.regs[RAX], signed(machine.regs[RDX])), self.events

    def run_collect(self, case):
        self.prepare(case)
        machine, layout = self.machine, self.layout
        layout.word(ITER, MARKET)
        layout.word(ITER + 8, case["cursor"])
        layout.word(ITER + 0x10, case["end"])
        layout.word(ITER + MARKET_FIELD, MARKET)
        layout.word(SINK, LEN_CELL)
        layout.word(SINK + 8, case["start"])
        layout.word(SINK + 0x10, BUFFER)
        layout.word(LEN_CELL, LEN_SENTINEL)
        machine.real = frozenset((RING_SEARCH,))
        failure = None
        try:
            machine.run(COLLECT, {RDI: ITER, RSI: SINK})
        except Panicked as stop:
            failure = stop.args[0][0]
        values = []
        for at in range(case["start"], case["start"] + WRITTEN_LIMIT):
            word = machine.memory.read(BUFFER + at * 8, 8)
            if word == POISON:
                break
            values.append(signed(word))
        if failure:
            return ("panic", failure, values) if machine.memory.read(LEN_CELL, 8) == LEN_SENTINEL else ("panic-wrote-length", failure)
        return ("ok", values, machine.memory.read(LEN_CELL, 8))

    def run_ring(self, case):
        self.prepare(case)
        machine = self.machine
        machine.real = frozenset()
        machine.memory.write(OUT_AT, 8, case["key"])
        machine.run(RING_SEARCH, {RDI: FIRST, RSI: OUT_AT})
        return machine.regs[RAX] & MASK[1], machine.regs[RDX]

    def run_scale(self, entry, value, factor_bits):
        machine = self.machine
        machine.memory.reset(USED)
        machine.memory.write(SCALE_AT + SCALE_FIELD, 8, factor_bits)
        machine.real = frozenset()
        try:
            machine.run(entry, {RDI: SCALE_AT, RSI: value})
        except Panicked as stop:
            return ("panic", stop.args[0][0])
        return machine.regs[RAX]


def layout_cursor(machine):
    return machine.memory.read(ITER + 8, 8)


# ---- cases ----

NORMAL_VALUES = (1, 2, 3, 5, 7, 10, 100, 1000, 12345, 0, 0, 4, 6, 9)
EDGE_VALUES = (-1, -5, 1 << 62, (1 << 63) - 1, -(1 << 63), 3037000500, 3037000499, 1 << 32, -(1 << 62), 2147483648)
MULTS = (0, 0, 0, 0, 1, 1, 2, 5, 17, 1844674407370955, 1844674407370956, 1 << 60, 1 << 63)
CURSORS = (0, 0, 0, 1, 7, 9990, 9999, 10000, 12345, 1 << 40, U64 - 3, U64 - 1, 1616, 1615, 5000)
INITS = (0, 0, 0, 0, 1, -1, 5, (1 << 63) - 1, -(1 << 63), (1 << 62), -(1 << 62), 1000)
FRACTIONS = (0.0, 0.3, 0.6, 0.9, 1.0, 1.0, 1.0)
FACTORS = (sys.float_info.max, -sys.float_info.max, 0.0, 1.0, 0.5, 0.001, 2.5, 1e10, 1e17, 1e18, 1e19, -1.0, -1e18, -2.5, float("nan"), float("inf"), float("-inf"),
           5e-324, 1e300, 0.01, 1.5, 100.0, 1e-9, 4.0, 1e15, 0.7, -1e300, 3.0, 1e-300)
SCALE_VALUES = (0, 1, 2, 3, 7, 100, 12345, 10 ** 9, 10 ** 12, 10 ** 15, 10 ** 17, 0x028F5C28F5C28F5B, 0x028F5C28F5C28F5C,
                0x028F5C28F5C28F5D, 1 << 62, (1 << 63) - 1, 1 << 63, U64, U64 - 1, 0x147AE147AE147AE, 0x147AE147AE147AF,
                0x0100000000000000, 9007199254740993, 4611686018427387905, 0x0200000000000000, 123456789012345678)
RING_KEY_POOL = (0, 1, 2, 3, 5, 8, 10, 20, 100, 10000, 10001, 10002, U64, U64 - 1, 1 << 63, 50, 7, 13)


def lcg(variant):
    """A small fixed generator so the sampled cases are the same on every run."""
    state = (variant * 0x9E3779B97F4A7C15 + 0x1234567) & U64
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & U64
        yield state >> 16


def draw(rng, bound):
    return next(rng) % bound


def choose(rng, pool):
    return pool[draw(rng, len(pool))]


def pick_value(rng, edge):
    if draw(rng, 100) < edge:
        return choose(rng, EDGE_VALUES)
    return choose(rng, NORMAL_VALUES)


def make_container(rng, keys, fraction, edge, noise_keys):
    """A container holding most of `keys` plus unrelated keys; the kind and the shape come from the generator."""
    items = {}
    for key in keys:
        if draw(rng, 100) < fraction * 100 and 0 <= key <= U64:
            items[key] = pick_value(rng, edge)
    for _ in range(draw(rng, 4)):
        noise = choose(rng, noise_keys) + draw(rng, 5) - 2
        if 0 <= noise <= U64:
            items.setdefault(noise, pick_value(rng, edge))
    while len(items) > 40:
        items.pop(max(items))
    count = len(items)
    if draw(rng, 2):
        feasible = [height for height in (0, 1, 2) if tree_fits(count, height)]
        height = choose(rng, feasible)
        return dict(kind="tree", items=items, height=height, root=bool(items) or bool(draw(rng, 2)))
    cap = count + draw(rng, 6) if count or draw(rng, 2) else draw(rng, 3)
    return dict(kind="ring", items=items, cap=cap, head=draw(rng, cap) if cap else 0)


def make_fold_case(variant, number, owner=False):
    rng = lcg(variant * 100003 + number)
    mult = choose(rng, MULTS)
    count = draw(rng, 10)
    cursor = 0 if owner else choose(rng, CURSORS)
    end = count if owner else min(U64, cursor + count - (2 if draw(rng, 12) == 0 else 0))
    if end < 0:
        end = 0
    base = KEY_STRIDE * mult
    keys = [base + k for k in range(cursor, min(end, cursor + 12))]
    noise_keys = keys + [base + cursor, 10000, 3]
    edge = choose(rng, (0, 0, 15, 40))
    first = make_container(rng, keys, choose(rng, FRACTIONS), edge, noise_keys)
    second = make_container(rng, keys, choose(rng, FRACTIONS), edge, noise_keys)
    length = draw(rng, 14) if draw(rng, 5) else max(1, count)
    return dict(mult=mult, cursor=cursor, end=end, init=0 if owner else choose(rng, INITS), first=first, second=second,
                array=[pick_value(rng, edge) for _ in range(length)], pulls=draw(rng, 4), start=draw(rng, 4))


def make_ring_case(variant, number):
    rng = lcg(variant * 1009 + number)
    count = draw(rng, 17)
    items = {}
    while len(items) < count:
        items[(choose(rng, RING_KEY_POOL) + draw(rng, 3) if draw(rng, 2) else draw(rng, 60)) & U64] = len(items)
    cap = count + draw(rng, 5) if count else draw(rng, 3)
    first = dict(kind="ring", items=items, cap=cap, head=draw(rng, cap) if cap else 0)
    keys = sorted(items)
    key = choose(rng, keys) if keys and draw(rng, 2) else (choose(rng, RING_KEY_POOL) + draw(rng, 2)) & U64
    return dict(mult=0, cursor=0, end=0, init=0, first=first, second=dict(kind="ring", items={}, cap=0, head=0), array=[],
                pulls=0, key=key)


def make_scale_case(variant, number):
    rng = lcg(variant * 7907 + number)
    value = choose(rng, SCALE_VALUES) if draw(rng, 4) else next(rng) & U64 >> draw(rng, 40)
    return value, to_bits(choose(rng, FACTORS))


# ---- checks ----


def describe_container(container):
    if container["kind"] == "tree":
        return "tree(h=%d,root=%d,n=%d)" % (container["height"], container["root"], len(container["items"]))
    return "ring(cap=%d,head=%d,n=%d)" % (container["cap"], container["head"], len(container["items"]))


def spec_fold_result(case):
    return fold_spec(case)


def spec_owner(case):
    """Result and consumer events the owner must produce."""
    result = fold_spec(dict(case, cursor=0, init=0))
    if result[0] == "panic":
        return ("panic", result[1]) + result[3:], []
    first = case["first"]
    events = []
    if first["kind"] == "tree":
        count = len(first["items"])
        if first["root"]:
            line = ("next", 1, 0, True, first["height"], 1, 0, True, first["height"], count)
        else:
            line = ("next", 0, 0, 0)
        events = [line] * (case["pulls"] + 1)
    elif first["cap"]:
        events = [("free", RING_FIRST, first["cap"] << 4, 0)]
    return ("ok", result[1], result[2]), events


def spec_ring(case):
    keys = sorted(case["first"]["items"])
    index = bisect.bisect_left(keys, case["key"])
    present = index < len(keys) and keys[index] == case["key"]
    return (0 if present else 1, index)


def normal_event(event):
    if event[0] != "next":
        return event
    data = event[1]
    words = [int.from_bytes(data[at:at + 8], "little") for at in range(0, ITER_LOG, 8)]
    if words[0] == 1:
        return ("next", words[0], words[1], words[2] != 0, words[3], words[4], words[5], words[2] == words[6], words[7], words[8])
    return ("next", words[0], words[4], words[8])


def constants_of(image):
    memory = Machine(image).memory
    return tuple(to_float(memory.read(at, 8)) for at in (CONST_LOW, CONST_HIGH, CONST_TOP))


class Runner:
    """Runs the four case kinds against one harness and returns a difference text or None."""

    def __init__(self, image, patches=None, constants=None):
        self.harness = Harness(image, patches)
        self.constants = constants or constants_of(image)

    def fold(self, case):
        want = fold_spec(case)
        got = self.harness.run_fold(case)
        return None if got == want else "fold want %r got %r" % (want, got)

    def owner(self, case):
        want, want_events = spec_owner(case)
        got, events = self.harness.run_owner(case)
        seen = [normal_event(event) for event in events]
        if got != want or seen != want_events:
            return "owner want %r %r got %r %r" % (want, want_events[:2], got, seen[:2])
        return None

    def collect(self, case):
        want = collect_spec(case)
        got = self.harness.run_collect(case)
        return None if got == want else "collect want %r got %r" % (want, got)

    def ring(self, case):
        want = spec_ring(case)
        got = self.harness.run_ring(case)
        return None if got == want else "ring want %r got %r" % (want, got)

    def scale(self, entry, pair):
        value, factor_bits = pair
        want = scale_spec(value, to_float(factor_bits), self.constants, entry == SCALE_CLAMPED)
        got = self.harness.run_scale(entry, value, factor_bits)
        return None if got == want else "scale want %r got %r" % (want, got)


def judge(call, argument):
    """Difference text, or None when the bytes and the specification agree; a stuck evaluator counts as a difference."""
    try:
        return call(argument)
    except (Halt, Panicked, EvidenceError, IndexError, KeyError, ValueError, OverflowError) as problem:
        return "evaluator stopped: %s" % (problem.args[0] if problem.args else type(problem).__name__)


def fold_kind(result):
    if result[0] == "panic":
        return "panic-" + result[1]
    return "exhausted" if result[1] == 1 else "stopped"


# ---- static facts ----


def static_rows(image):
    memory = Machine(image).memory
    rows = [("entry", "start", "end", "bytes", "instructions", "conditional_jumps", "direct_calls", "indirect_calls")]
    for entry in ENTRIES:
        start, end = image.exact_fde(entry)
        body = decode_range(image, start, end)
        rows.append(("fde", "%#x" % start, "%#x" % end, end - start, len(body),
                     sum(1 for row in body if row.op == "jcc"), sum(1 for row in body if row.op == "call"),
                     sum(1 for row in body if row.op == "calli")))
    return rows


def edge_rows(image):
    relative = relative_slots(image)
    rows = [("function", "call_site", "kind", "target")]
    for entry in (FOLD, OWNER, SCALE_CLAMPED, SCALE_SIGNED, COLLECT):
        start, end = image.exact_fde(entry)
        for insn in decode_range(image, start, end):
            if insn.op == "call":
                rows.append(("%#x" % entry, "%#x" % insn.va, "direct", "%#x" % insn.target))
            elif insn.op == "calli" and insn.a[0] == "m" and insn.a[1] is None:
                rows.append(("%#x" % entry, "%#x" % insn.va, "got-slot %#x" % insn.a[4], "%#x" % relative[insn.a[4]]))
    return rows


def constant_rows(image):
    memory = Machine(image).memory
    rows = [("name", "address", "u64", "f64")]
    for name, at in (("low", CONST_LOW), ("high", CONST_HIGH), ("top", CONST_TOP)):
        bits = memory.read(at, 8)
        rows.append((name, "%#x" % at, "%#x" % bits, repr(to_float(bits))))
    for name, bits in (("scale-early-return", 0x028F5C28F5C28F5C), ("scale-result-bound", 0x147AE147AE147AE)):
        rows.append((name, "immediate", "%#x" % bits, "-"))
    return rows


def reference_rows(image):
    """Every rel32 call/jump whose displacement lands exactly on an entry, and every relative relocation naming one.

    This is a byte-pattern scan (opcode E8/E9 plus a displacement), so each row is a candidate site: the
    containing unwind record is shown when there is one.
    """
    address, text = image.text_bytes()
    wanted = {entry: [] for entry in ENTRIES}
    for opcode, kind in ((0xE8, "call"), (0xE9, "jump")):
        at = text.find(bytes((opcode,)))
        while at != -1:
            if at + 5 <= len(text):
                target = address + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
                if target in wanted:
                    wanted[target].append((address + at, kind))
            at = text.find(bytes((opcode,)), at + 1)
    for slot, kind, addend, _ in image.relocations():
        if kind == 8 and addend in wanted:
            wanted[addend].append((slot, "relocation"))
    rows = [("entry", "site", "kind", "inside_function", "function_bytes")]
    for entry in ENTRIES:
        for site, kind in sorted(wanted[entry]):
            try:
                start, end = image.fde(site) if kind != "relocation" else (0, 0)
            except EvidenceError:
                start, end = 0, 0
            rows.append(("%#x" % entry, "%#x" % site, kind, "%#x" % start if start else "-", end - start if start else "-"))
    return rows


# ---- mutants ----


def mutants(image):
    """Every flippable condition and immediate byte in the five bodies, as (entry, address, kind, patch)."""
    found = []
    for entry in ENTRIES:
        start, end = image.exact_fde(entry)
        code = image.blob[image.offset(start):image.offset(start) + (end - start)]
        for insn in decode_range(image, start, end):
            raw = code[insn.va - start:insn.next - start]
            if insn.op == "jcc":
                if insn.size == 2:
                    found.append((entry, insn.va, "jcc", {insn.va: raw[0] ^ 1}))
                else:
                    found.append((entry, insn.va, "jcc", {insn.va + 1: raw[1] ^ 1}))
            elif insn.op in ("cmov", "set"):
                at = raw.index(0x0F) + 1
                found.append((entry, insn.va, insn.op, {insn.va + at: raw[at] ^ 1}))
            if insn.imm_at is not None and insn.imm_size and insn.op in ("cmp", "mov", "imul3", "add", "sub", "and", "shl", "shr"):
                found.append((entry, insn.va, "imm", {insn.va + insn.imm_at: raw[insn.imm_at] ^ 1}))
            for operand in (insn.a, insn.b):
                if not (operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]):
                    continue
                limit = insn.imm_at if insn.imm_at is not None else len(raw)
                disp = operand[4]
                if -128 <= disp < 128:
                    at = raw.rfind(bytes((disp & 0xFF,)), 0, limit)
                else:
                    at = raw.find(struct.pack("<i", disp), 0, limit)
                if at > 0:
                    found.append((entry, insn.va, "disp", {insn.va + at: raw[at] ^ 8}))
    return found


# ---- evidence ----


def counts_table(counter):
    return sorted(counter.items())


def write_rows(path, rows):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write("\t".join(str(cell) for cell in row) + "\n")


def build(out, fold_count, owner_count, ring_count, scale_count, collect_count, sample):
    image = load_image()
    constants = constants_of(image)
    out.mkdir(parents=True, exist_ok=True)
    runner = Runner(image, constants=constants)
    rows_fold = [("id", "mult", "cursor", "end", "init", "first", "second", "array", "outcome", "result")]
    rows_owner = [("id", "mult", "end", "first", "second", "array", "pulls", "outcome", "consumer_events")]
    rows_ring = [("id", "container", "key", "found", "index")]
    rows_collect = [("id", "mult", "cursor", "end", "start", "second", "outcome", "values")]
    rows_scale = [("id", "entry", "value", "factor", "result")]
    failures = []
    outcomes = {}
    pool = {"fold": [], "owner": [], "ring": [], "scale": [], "collect": []}
    total = 0

    def note(kind, label):
        outcomes[(kind, label)] = outcomes.get((kind, label), 0) + 1

    for number in range(fold_count):
        case = make_fold_case(1, number)
        problem = judge(runner.fold, case)
        total += 1
        want = fold_spec(case)
        note("fold", fold_kind(want))
        if problem:
            failures.append(("fold", number, problem))
        if len(pool["fold"]) < 700:
            pool["fold"].append(case)
        if number % sample == 0:
            rows_fold.append((number, case["mult"], case["cursor"], case["end"], case["init"], describe_container(case["first"]),
                              describe_container(case["second"]), len(case["array"]), fold_kind(want), want[1:] if want[0] == "ok" else want[1:]))
    for number in range(owner_count):
        case = make_fold_case(2, number, owner=True)
        problem = judge(runner.owner, case)
        total += 1
        want, events = spec_owner(case)
        label = ("panic-" + want[1]) if want[0] == "panic" else ("exhausted" if want[1] else "stopped")
        note("owner", label + ("+" + events[0][0] if events else ""))
        if problem:
            failures.append(("owner", number, problem))
        if len(pool["owner"]) < 500:
            pool["owner"].append(case)
        if number % sample == 0:
            rows_owner.append((number, case["mult"], case["end"], describe_container(case["first"]), describe_container(case["second"]),
                               len(case["array"]), case["pulls"], label, len(events)))
    for number in range(ring_count):
        case = make_ring_case(3, number)
        problem = judge(runner.ring, case)
        total += 1
        want = spec_ring(case)
        note("ring", "found" if want[0] == 0 else "absent")
        if problem:
            failures.append(("ring", number, problem))
        if len(pool["ring"]) < 500:
            pool["ring"].append(case)
        if number % sample == 0:
            rows_ring.append((number, describe_container(case["first"]), case["key"], 1 - want[0], want[1]))
    for number in range(scale_count):
        for entry in (SCALE_CLAMPED, SCALE_SIGNED):
            pair = make_scale_case(4 + (entry == SCALE_SIGNED), number)
            problem = judge(lambda item: runner.scale(entry, item), pair)
            total += 1
            want = scale_spec(pair[0], to_float(pair[1]), constants, entry == SCALE_CLAMPED)
            note("scale-%#x" % entry, "panic" if isinstance(want, tuple) else ("clamp" if want in (0x147AE147AE147AE, 0, U64 - 0x147AE147AE147AD) else "value"))
            if problem:
                failures.append(("scale", number, problem))
            if len(pool["scale"]) < 800:
                pool["scale"].append((entry, pair))
            if number % sample == 0:
                rows_scale.append((number, "%#x" % entry, "%#x" % pair[0], repr(to_float(pair[1])),
                                   want if isinstance(want, tuple) else "%#x" % want))
    for number in range(collect_count):
        case = make_fold_case(6, number)
        problem = judge(runner.collect, case)
        total += 1
        want = collect_spec(case)
        note("collect", want[0] if want[0] == "ok" else "panic-" + want[1])
        if problem:
            failures.append(("collect", number, problem))
        if len(pool["collect"]) < 600:
            pool["collect"].append(case)
        if number % sample == 0:
            rows_collect.append((number, case["mult"], case["cursor"], case["end"], case["start"], describe_container(case["second"]),
                                 want[0] if want[0] == "ok" else "panic-" + want[1], list(want[1]) if want[0] == "ok" else want[2]))
    if failures:
        raise EvidenceError("specification and bytes disagree: %r" % (failures[:3],))

    controls = [("entry", "address", "kind", "flipped_byte", "result", "killed_by")]
    detected, equivalent_rows, count = 0, [], 0
    for entry, address, kind, patch in mutants(image):
        count += 1
        killer = kill_mutant(image, constants, entry, patch, pool)
        flipped = "%#x" % next(iter(patch))
        if killer is None:
            known = EQUIVALENT.get((entry, address, kind))
            controls.append(("%#x" % entry, "%#x" % address, kind, flipped, "equivalent" if known else "SURVIVED", "-"))
            if known:
                equivalent_rows.append(("%#x" % entry, "%#x" % address, kind, known))
            else:
                equivalent_rows.append(("%#x" % entry, "%#x" % address, kind, "UNEXPLAINED"))
        else:
            detected += 1
            controls.append(("%#x" % entry, "%#x" % address, kind, flipped, "detected", killer))
    unexplained = [row for row in equivalent_rows if row[3] == "UNEXPLAINED"]
    write_rows(out / "functions.tsv", static_rows(image))
    write_rows(out / "edges.tsv", edge_rows(image))
    write_rows(out / "constants.tsv", constant_rows(image))
    write_rows(out / "references.tsv", reference_rows(image))
    write_rows(out / "cases-fold.tsv", rows_fold)
    write_rows(out / "cases-owner.tsv", rows_owner)
    write_rows(out / "cases-ring.tsv", rows_ring)
    write_rows(out / "cases-scale.tsv", rows_scale)
    write_rows(out / "cases-collect.tsv", rows_collect)
    write_rows(out / "outcomes.tsv", [("entry", "outcome", "cases")] + [(a, b, n) for (a, b), n in sorted(outcomes.items())])
    write_rows(out / "controls.tsv", controls)
    write_rows(out / "equivalent-mutants.tsv", [("entry", "address", "kind", "reason")] + [row for row in equivalent_rows if row[3] != "UNEXPLAINED"])
    summary = dict(cases=total, negative_controls=count, negative_detected=detected, equivalent=count - detected - len(unexplained),
                   unexplained=len(unexplained), fold_cases=fold_count, owner_cases=owner_count, ring_cases=ring_count,
                   scale_cases=2 * scale_count, collect_cases=collect_count)
    with open(out / "measure.json", "w", encoding="utf-8", newline="\n") as handle:
        json.dump(summary, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return summary, unexplained


def kill_mutant(image, constants, entry, patch, pool):
    """Name of the first case that exposes the patched bytes, or None when every sampled case still agrees."""
    runner = Runner(image, patch, constants)
    order = {
        RING_SEARCH: ("ring", "fold", "owner"), FOLD: ("fold", "owner"), OWNER: ("owner",),
        SCALE_CLAMPED: ("scale",), SCALE_SIGNED: ("scale",), COLLECT: ("collect", "fold"),
    }[entry]
    for kind in order:
        cases = pool[kind]
        for index, case in enumerate(cases):
            if kind == "scale":
                if case[0] != entry:
                    continue
                problem = judge(lambda item: runner.scale(entry, item), case[1])
            else:
                problem = judge(getattr(runner, kind), case)
            if problem:
                if index > 8:
                    cases.insert(0, cases.pop(index))
                return "%s-%d" % (kind, index)
    return None


SATURATED = ("the mask only drops the lowest magnitude bit before a compare that no finite pattern but the largest reaches; "
             "the same register is the saturated integer, which the later +-0x147ae147ae147ae clamp absorbs")
BELOW_LOW = ("a product at or below -2^63 reaches the integer conversion either clamped to the constant -2^63 or raw; "
             "both convert to 0x8000000000000000, so the result is unchanged")
ABOVE_HIGH = ("a product above 2^63 reaches the conversion either clamped to 2^63 or raw; both pass the top-constant test "
              "and select the saturated integer, so the result is unchanged")
FLOORED = "this form floors negative results at zero right after the lower clamp, so the lower bound cannot show"
UNREACHABLE = ("the replaced zero is stored only when a successful ring search returns an index at or past the length, which a consistent ring cannot produce")
EXTRA_PASS = "the extra pass of the halving loop runs with a zero step and leaves the search position unchanged"
EQUIVALENT = {
    (SCALE_CLAMPED, 0x44811F5, "imm"): SATURATED,
    (SCALE_CLAMPED, 0x4481221, "jcc"): BELOW_LOW,
    (SCALE_CLAMPED, 0x448122B, "jcc"): ABOVE_HIGH,
    (SCALE_CLAMPED, 0x448127D, "imm"): FLOORED,
    (SCALE_SIGNED, 0x44812C2, "imm"): SATURATED,
    (SCALE_SIGNED, 0x44812EE, "jcc"): BELOW_LOW,
    (SCALE_SIGNED, 0x44812F8, "jcc"): ABOVE_HIGH,
    (RING_SEARCH, 0x4554836, "imm"): EXTRA_PASS,
    (RING_SEARCH, 0x45548AA, "imm"): EXTRA_PASS,
    (COLLECT, 0x37BFDE1, "imm"): UNREACHABLE,
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    summary, unexplained = build(args.out, FOLD_CASES, OWNER_CASES, RING_CASES, SCALE_CASES, COLLECT_CASES, SAMPLE)
    print(json.dumps(summary, sort_keys=True))
    for row in unexplained:
        print("unexplained survivor", row)
    return 1 if unexplained else 0


FOLD_CASES = 4500
OWNER_CASES = 3500
RING_CASES = 1500
SCALE_CASES = 1500
COLLECT_CASES = 3000
SAMPLE = 4


if __name__ == "__main__":
    sys.exit(main())
