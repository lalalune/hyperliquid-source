#!/usr/bin/env python3
"""Pin the node #94 withdraw3 amount gates from ELF bytes.

0x2734200 and its copies 0x4d49260 and 0x4d498a0 run the bridge withdrawal: length guards, the
"Withdrawals disabled" window, a bridge flag pair, the nonce times 1000, the per-user nonce row, then
the amount gates (zero, bridge balance, fixed 10^13 cap, a 3*10^12 level with no state effect), the
destination parse, the first dex debit, the bridge record and the row update. The real bytes run under
recording stubs, a separately written rule list predicts every run including all fixture bytes, and
every reached conditional row is mutated. No objdump or readelf output is parsed and the binary is
never executed. Standard library only.

    python3 tools/withdraw_amount_gates.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
import hashlib
import json
import math
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

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
HEAP_SIZE = 0x20000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 20000


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
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
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
        if kind in (2, 3, 4, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 6: "div"}[kind], rm, w=w)
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
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
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
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
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
        self.keep_rdx = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        self.xmm = [POISON | POISON << 64] * 16

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
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            self.put(row.a, width, self.get(row.b, width) * row.target)
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
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
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
            count = (row.target if op == "shld" else self.regs[RCX]) & 63
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
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
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


COPIES = (0x2734200, 0x4D49260, 0x4D498A0)
RECORD = 0x374FCE0
SCALE_WRAPPER = 0x3C097B0
DEX_REF = 0x3332600
DEX_MUT = 0x3332700
TARGETS = COPIES + (RECORD, SCALE_WRAPPER, DEX_REF, DEX_MUT)
NAMES = {COPIES[0]: "core_a", COPIES[1]: "core_b", COPIES[2]: "core_c", RECORD: "bridge_record", SCALE_WRAPPER: "usd_scale", DEX_REF: "dex_ref", DEX_MUT: "dex_mut"}
CALLERS = (0x2732530, 0x4D3D7E0, 0x4D3FC00)

SLOT_PARSE = 0x57731D8
SLOT_SCALE = 0x5774B10
SLOT_DECIMAL = 0x5773848
SLOT_REF = 0x5773320
SLOT_MUT = 0x5773D80
SLOT_DEST = 0x5774B18
SLOT_DEBIT = 0x5774B20
SLOT_RECORD = 0x5774B28
SLOT_MARK = 0x576F488
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_UNWRAP = 0x576E048
SLOT_TEXT_PANIC = 0x576E468
SLOT_ONCE = 0x576E8B8
ONCE_WORD = 0x577AB98
INSERT = 0x3941FE0
STATUS_DROP = 0x3379490
PARSE_HELPER = 0x3799510
MARK_HELPER = 0x14385C0
DEST_HELPER = 0x3813B40
DEBIT_HELPER = 0x370DA60
UNWRAP_TEXT = 0x599A53
DEX_TEXT = 0x58C079
BUG_TEXT = 0x59959B
BUG_TEXT_SIZE = 30
MARK_BASE = 0x7700000000

CALL_TABLE = {COPIES[0]: dict(hash=0x2840FB0, row=0x1F849B0, volume=0x2712A00, drop=0x277EBA0),
              COPIES[1]: dict(hash=0x473BF50, row=0x47D7CA0, volume=0x46F3330, drop=0x4DAF4A0),
              COPIES[2]: dict(hash=0x473BF50, row=0x47D7CA0, volume=0x46F3240, drop=0x4DAF4A0)}
SHIFT = {COPIES[0]: 0, COPIES[1]: 0, COPIES[2]: 0xA80}

TAG_OK = 0x186
TAG_LEN = 0x143
TAG_DISABLED = 0x75
TAG_BRIDGE = 0x27
TAG_LIMIT = 0x28
TAG_ZERO = 0x30
TAG_NONCE_USED = 0x5A
TAG_NONCE = 0xC6
TAG_ADDRESS = 0xB6
TAG_DEX = 0x141
STATUS_TABLE = 0x59A8D0
TEXT_ARMS = (TAG_BRIDGE, TAG_LIMIT, TAG_ZERO, TAG_NONCE_USED, TAG_ADDRESS, TAG_LEN)
PIECE_ARMS = (TAG_DISABLED, TAG_NONCE)
LOOSE_TAIL = (TAG_BRIDGE, TAG_LIMIT, TAG_ZERO)  # text arms with no payload; the shared exit copies stale stack bytes behind the tag

MAX_LEN = 100
CAP = 10 ** 13
MARK_LEVEL = 3 * 10 ** 12
SHIFTED_LEVEL = 0x2BA7DEF2
WINDOW = 5000
NONCE_SCALE = 1000
DECIMAL_MODE = 2
DECIMAL_EXPONENT = 6

F_DEST_PTR = 0x08
F_DEST_LEN = 0x10
F_USD_PTR = 0x20
F_USD_LEN = 0x28
F_NONCE = 0x50
S_BASE_WORD = 0x10
S_HEIGHT = 0x28
S_DEPTH = 0x58
S_NOW = 0x60
S_GATE_TIME = 0x3AA4
S_GATE_HEIGHT = 0x3988
S_FLAG = 0x31A2
S_BRIDGE = 0x3398
BRIDGE_BAL = 0x130
BRIDGE_OAW = 0x140
BRIDGE_MAP = 0x40
S_ROWS = 0x740
S_DEXES = 0x5B8
S_DEBIT_FIRST = 0x3840
S_DEBIT_SECOND = 0x5D0
DEX_STRIDE = 0x2F0
ROW_STRIDE = 0x58
ROW_NONCE = 0x18
ROW_PENDING = 0x3D
BUCKETS = 64
GROUP = 16

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
ACTION = HEAP_BASE + 0x400
USER_AT = HEAP_BASE + 0x500
USD_TEXT = HEAP_BASE + 0x600
DEST_TEXT = HEAP_BASE + 0x700
ROW_AT = HEAP_BASE + 0x800
NONCE_TEXT = HEAP_BASE + 0x900
DEX_AT = HEAP_BASE + 0xA00
CTRL = HEAP_BASE + 0x3000
STATE = HEAP_BASE + 0x8000
STATE_SIZE = 0x5000
COMPARED = 0xE000
USED = 0x10000
FILL = 0xCC
USER = bytes(range(0x31, 0x45))
OTHER = bytes(range(0x51, 0x65))
DESTINATION = bytes(range(0x71, 0x85))
DECIMAL = bytes(range(0xA0, 0xB0))
GOOD_HASH = (0x25 << 57) | 0x1234560B
NONCE_MESSAGE = b"nonce error"
STRESS_NET = 0x1111


class Case:
    FIELDS = dict(dest_len=42, usd_len=5, now=(20000, 100, 5), gate=(20000, 100, 5), height=1000, gate_height=1000, base_word=0, flag=0, oaw=1, nonce=5, items=2, table="miss",
                  stored=0, hash=GOOD_HASH, parse_tag=None, scale_tag=None, x=5000000, bal=1 << 60, dex_len=1, dest_tag=None, debit_tag=None, net=4000000, insert_tag=None,
                  once=0, alloc_fail=False, depth=7)

    def __init__(self, name, kind, **fields):
        self.name = name
        self.kind = kind
        for key, value in self.FIELDS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.FIELDS:
                raise EvidenceError("field " + key)
            setattr(self, key, value)

    def stored_value(self):
        return self.stored if self.items and self.table in ("hit", "hit_first", "hit_next", "hit_second", "hit_wrap", "hit_last_group") else 0


def blank():
    return bytes((index * 7 + 0x40) & 0xFF for index in range(OUT_SIZE))


def failure_body(tag):
    """The 0x60 result record a failing helper leaves: tag then a byte pattern."""
    data = bytearray((index * 11 + 3) & 0xFF for index in range(OUT_SIZE))
    data[0:2] = struct.pack("<H", tag)
    return bytes(data)


def later_or_equal(now, gate):
    def key(value):
        return (struct.unpack("<i", struct.pack("<I", value[0]))[0], value[1], value[2])
    return key(now) >= key(gate)


def spec_run(case, before):
    """Predict one run from the rule list, written apart from the bytes under test."""
    image = bytearray(before)
    shift = SHIFT[case.kind]
    calls = CALL_TABLE[case.kind]
    events = []

    def put(addr, data):
        at = addr - HEAP_BASE
        image[at:at + len(data)] = data

    def finish(tag=None, payload=None):
        depth = min(case.depth + 1, MASK[8])
        put(STATE + S_DEPTH, struct.pack("<Q", max(depth - 1, 0)))
        if tag is not None:
            put(OUT, struct.pack("<H", tag))
        if payload is not None:
            payload()
        if tag in LOOSE_TAIL:
            put(OUT + 2, bytes(OUT_SIZE - 2))
        return "done", tuple(events), bytes(image)

    if case.dest_len > MAX_LEN:
        return finish(TAG_LEN, lambda: put(OUT + 8, struct.pack("<Q", ACTION)))
    if case.usd_len > MAX_LEN:
        return finish(TAG_LEN, lambda: put(OUT + 8, struct.pack("<Q", ACTION + 0x18)))
    if not later_or_equal(case.now, case.gate) or case.height < case.gate_height:
        limit = min(case.base_word + WINDOW, MASK[8])
        return finish(TAG_DISABLED, lambda: put(OUT + 2, bytes([case.height >= limit])))
    if case.flag == 1 and case.oaw == 0:
        return finish(TAG_BRIDGE)
    product = case.nonce * NONCE_SCALE
    if product > MASK[8]:
        events.append(("alloc",))
        if case.alloc_fail:
            events.append(("alloc_fail",))
            return "panic", "alloc", tuple(events)
        put(NONCE_TEXT, NONCE_MESSAGE)

        def text():
            put(OUT + 8, struct.pack("<QQQ", len(NONCE_MESSAGE), NONCE_TEXT, len(NONCE_MESSAGE)))
        return finish(TAG_NONCE, text)
    if case.items and case.table != "skip":
        events.append(("hash",))
    if product <= case.stored_value():
        return finish(TAG_NONCE_USED)
    events.append(("parse",))
    if case.parse_tag is not None:
        put(OUT, failure_body(case.parse_tag))
        return finish()
    events.append(("scale",))
    if case.scale_tag is not None:
        put(OUT, failure_body(case.scale_tag))
        return finish()
    if case.x == 0:
        return finish(TAG_ZERO)
    if case.x > case.bal:
        return finish(TAG_BRIDGE)
    if not case.dex_len:
        return "panic", "dex", tuple(events)
    if case.x > CAP:
        events.append(("mark",))
        return finish(TAG_LIMIT)
    if case.x >= MARK_LEVEL:
        events.append(("mark",))
    events.append(("dest",))
    if case.dest_tag is not None:
        events.append(("drop", case.dest_tag))
        return finish(TAG_ADDRESS)
    events.append(("debit", case.x))
    if case.debit_tag is not None:
        put(OUT, failure_body(case.debit_tag))
        return finish()
    events.append(("insert", product, case.net))
    if case.insert_tag is not None:
        return "panic", "unwrap", tuple(events)
    if case.net > case.bal:
        return "panic", "balance", tuple(events)
    put(STATE + shift + S_BRIDGE + BRIDGE_BAL, struct.pack("<Q", case.bal - case.net))
    if case.once:
        events.append(("once",))
    events.append(("row",))
    put(ROW_AT, struct.pack("<Q", product))
    put(ROW_AT + ROW_PENDING, b"\x00")
    events.append(("volume", (-case.x) & MASK[8]))
    return finish(TAG_OK)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((RECORD, SCALE_WRAPPER, DEX_REF, DEX_MUT))
        statics = machine.memory.statics
        statics[SLOT_SCALE] = SCALE_WRAPPER
        statics[SLOT_REF] = DEX_REF
        statics[SLOT_MUT] = DEX_MUT
        statics[SLOT_RECORD] = RECORD
        statics[ONCE_WORD] = 0
        table = {SLOT_PARSE: self.on_parse, SLOT_DECIMAL: self.on_decimal, SLOT_DEST: self.on_dest, SLOT_DEBIT: self.on_debit, SLOT_MARK: self.on_mark, SLOT_ALLOC: self.on_alloc,
                 SLOT_ALLOC_FAIL: self.on_alloc_fail, SLOT_UNWRAP: self.on_unwrap, SLOT_TEXT_PANIC: self.on_text_panic, SLOT_ONCE: self.on_once}
        for slot, hook in table.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        calls = {STATUS_DROP: self.on_status_drop, INSERT: self.on_insert}
        for names in CALL_TABLE.values():
            for role, target in names.items():
                calls[target] = getattr(self, "on_" + role)
        machine.calls = calls
        self.events = []
        self.case = None
        self.before = None

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def bytes_at(self, addr, size):
        return self.machine.memory.bytes_at(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def on_role(self, role, target):
        self.expect(CALL_TABLE[self.case.kind][role] == target, role + " target of another copy")

    def on_hash(self, machine):
        self.expect(machine.regs[RDI] == STATE + SHIFT[self.case.kind] + S_ROWS + 0x20, "hash seed")
        self.expect(self.bytes_at(machine.regs[RSI], 20) == USER, "hash key")
        self.events.append(("hash",))
        machine.regs[RAX] = self.case.hash

    def on_parse(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == USD_TEXT and regs[RDX] == self.case.usd_len, "usd text")
        self.events.append(("parse",))
        if self.case.parse_tag is not None:
            machine.memory.put_bytes(regs[RDI], failure_body(self.case.parse_tag))
        else:
            data = bytearray(failure_body(TAG_OK))
            data[4:20] = DECIMAL
            machine.memory.put_bytes(regs[RDI], bytes(data))

    def on_decimal(self, machine):
        regs = machine.regs
        self.expect(self.bytes_at(regs[RSI], 16) == DECIMAL, "decimal bytes")
        self.expect(regs[RDX] & MASK[4] == DECIMAL_MODE and regs[RCX] & MASK[4] == DECIMAL_EXPONENT, "mode and exponent")
        self.events.append(("scale",))
        if self.case.scale_tag is not None:
            machine.memory.put_bytes(regs[RDI], failure_body(self.case.scale_tag))
        else:
            data = bytearray(failure_body(TAG_OK))
            data[8:16] = struct.pack("<Q", self.case.x)
            machine.memory.put_bytes(regs[RDI], bytes(data))

    def on_status_drop(self, machine):
        self.expect(self.bytes_at(machine.regs[RDI], 2) == struct.pack("<H", TAG_DEX), "dropped status")

    def on_mark(self, machine):
        self.events.append(("mark",))
        machine.regs[RAX] = POISON

    def on_dest(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == DEST_TEXT and regs[RDX] == self.case.dest_len, "dest text")
        self.events.append(("dest",))
        if self.case.dest_tag is not None:
            machine.memory.put_bytes(regs[RDI], failure_body(self.case.dest_tag))
        else:
            data = bytearray(failure_body(TAG_OK))
            data[2:22] = DESTINATION
            machine.memory.put_bytes(regs[RDI], bytes(data))

    def on_drop(self, machine):
        self.events.append(("drop", struct.unpack("<H", self.bytes_at(machine.regs[RDI], 2))[0]))

    def on_debit(self, machine):
        regs = machine.regs
        case = self.case
        shift = SHIFT[case.kind]
        self.expect(regs[RSI] == DEX_AT, "dex record")
        self.expect(self.bytes_at(regs[RDX], 20) == USER, "debit user")
        self.expect(regs[R8] == STATE + shift + S_DEBIT_FIRST and regs[R9] == STATE + shift + S_DEBIT_SECOND, "debit state words")
        self.events.append(("debit", regs[RCX]))
        if case.debit_tag is not None:
            machine.memory.put_bytes(regs[RDI], failure_body(case.debit_tag))
        else:
            data = bytearray(failure_body(TAG_OK))
            data[8:16] = struct.pack("<Q", case.net)
            machine.memory.put_bytes(regs[RDI], bytes(data))

    def on_insert(self, machine):
        regs = machine.regs
        case = self.case
        self.expect(regs[RSI] == STATE + SHIFT[case.kind] + S_BRIDGE + BRIDGE_MAP, "bridge map")
        key = self.bytes_at(regs[RDX], 28)
        value = self.bytes_at(regs[RCX], 28)
        self.expect(key[8:] == USER, "insert user")
        self.expect(value[8:] == DESTINATION, "insert destination")
        self.events.append(("insert", struct.unpack("<Q", key[:8])[0], struct.unpack("<Q", value[:8])[0]))
        tag = case.insert_tag if case.insert_tag is not None else TAG_OK
        machine.memory.put_bytes(regs[RDI], failure_body(tag))

    def on_once(self, machine):
        self.expect(machine.regs[RDI] == ONCE_WORD and machine.regs[RSI] & MASK[4] == 1, "once arguments")
        self.events.append(("once",))

    def on_row(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + SHIFT[self.case.kind] + S_ROWS, "row map")
        self.expect(self.bytes_at(regs[RSI], 20) == USER, "row key")
        self.events.append(("row",))
        regs[RAX] = ROW_AT

    def on_volume(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE, "volume state")
        self.expect(self.bytes_at(regs[RSI], 20) == USER, "volume user")
        self.expect(regs[RCX] & MASK[4] == 0, "volume second word")
        self.events.append(("volume", regs[RDX]))

    def on_alloc(self, machine):
        self.expect(machine.regs[RDI] & MASK[4] == len(NONCE_MESSAGE), "alloc size")
        self.events.append(("alloc",))
        machine.regs[RAX] = 0 if self.case.alloc_fail else NONCE_TEXT

    def on_alloc_fail(self, machine):
        self.expect(machine.regs[RDI] & MASK[4] == 1 and machine.regs[RSI] & MASK[4] == len(NONCE_MESSAGE), "alloc failure layout")
        self.events.append(("alloc_fail",))
        raise Panicked("alloc")

    def on_unwrap(self, machine):
        regs = machine.regs
        status = struct.unpack("<H", self.bytes_at(regs[RDX], 2))[0]
        self.expect(regs[RSI] & MASK[4] == 0x2B, "unwrap text size")
        self.expect(regs[RDI] == (DEX_TEXT if status == TAG_DEX else UNWRAP_TEXT), "unwrap text")
        raise Panicked("dex" if status == TAG_DEX else "unwrap")

    def on_text_panic(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == BUG_TEXT and regs[RSI] & MASK[4] == BUG_TEXT_SIZE, "balance text")
        raise Panicked("balance")

    def table(self, case, shift):
        memory = self.machine.memory
        base = STATE + shift + S_ROWS
        self.word(base, CTRL)
        self.word(base + 8, BUCKETS - 1)
        self.word(base + 0x18, case.items)
        memory.put_bytes(CTRL - BUCKETS * ROW_STRIDE, bytes([FILL]) * (BUCKETS * ROW_STRIDE))
        memory.put_bytes(CTRL, bytes([0xFF]) * (BUCKETS + GROUP))
        h2 = case.hash >> 57
        start = case.hash & (BUCKETS - 1)

        def entry(slot, key, nonce, control):
            slot &= BUCKETS - 1
            memory.write(CTRL + slot, 1, control)
            if slot < GROUP:
                memory.write(CTRL + BUCKETS + slot, 1, control)
            at = CTRL - (slot + 1) * ROW_STRIDE
            memory.put_bytes(at, key)
            self.word(at + ROW_NONCE, nonce)

        twin = USER[:18] + bytes([USER[18] ^ 0x40, USER[19]])
        late = USER[:15] + bytes([USER[15] ^ 1]) + USER[16:]
        kind = case.table
        if kind == "miss":
            entry(start + 1, OTHER, 1 << 62, h2)
            entry(start + 2, twin, 1 << 62, h2)
            entry(start + 3, late, 1 << 62, h2)
            entry(start + 5, USER, 1 << 62, h2 ^ 1)
        elif kind == "miss_next":
            for step in range(GROUP):
                entry(start + step, OTHER, 1 << 62, (h2 ^ 3) & 0x7F)
            entry(start + GROUP + 1, twin, 1 << 62, h2)
        elif kind == "hit":
            entry(start + 1, twin, 1 << 62, h2)
            entry(start + 4, USER, case.stored, h2)
        elif kind == "hit_second":
            for step in range(GROUP):
                entry(start + step, OTHER, 1 << 62, (h2 ^ 3) & 0x7F)
            entry(start + GROUP + 3, USER, case.stored, h2)
        elif kind == "hit_last_group":
            for step in range(GROUP):
                entry(start + step, OTHER, 1 << 62, (h2 ^ 3) & 0x7F)
            for step in range(GROUP):
                entry(start + GROUP + step, OTHER, 1 << 62, (h2 ^ 5) & 0x7F)
            entry(start + GROUP * 3, USER, case.stored, h2)
        elif kind == "hit_first":
            entry(start, USER, case.stored, h2)
        elif kind == "hit_next":
            entry(start + 1, USER, case.stored, h2)
        elif kind == "hit_wrap":
            entry(start + 2, OTHER, 1 << 62, h2)
            entry(start + 7, USER, case.stored, h2)
        else:
            entry(start + 4, USER, 1 << 62, h2)

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        shift = SHIFT[case.kind]
        memory.put_bytes(HEAP_BASE, bytes([FILL]) * COMPARED)
        memory.put_bytes(OUT, blank())
        memory.put_bytes(USER_AT, USER)
        self.word(ACTION + F_DEST_PTR, DEST_TEXT)
        self.word(ACTION + F_DEST_LEN, case.dest_len)
        self.word(ACTION + F_USD_PTR, USD_TEXT)
        self.word(ACTION + F_USD_LEN, case.usd_len)
        self.word(ACTION + F_NONCE, case.nonce)
        self.word(STATE + S_BASE_WORD, case.base_word)
        self.word(STATE + S_HEIGHT, case.height)
        self.word(STATE + S_DEPTH, case.depth)
        memory.put_bytes(STATE + S_NOW, struct.pack("<III", *case.now))
        memory.put_bytes(STATE + shift + S_GATE_TIME, struct.pack("<III", *case.gate))
        self.word(STATE + shift + S_GATE_HEIGHT, case.gate_height)
        memory.write(STATE + shift + S_FLAG, 1, case.flag)
        memory.write(STATE + shift + S_BRIDGE + BRIDGE_OAW, 1, case.oaw)
        self.word(STATE + shift + S_BRIDGE + BRIDGE_BAL, case.bal)
        self.word(STATE + shift + S_DEXES + 8, DEX_AT)
        self.word(STATE + shift + S_DEXES + 0x10, case.dex_len)
        self.table(case, shift)
        memory.statics[ONCE_WORD] = case.once
        self.events = []
        self.case = case
        self.before = memory.bytes_at(HEAP_BASE, COMPARED)

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        try:
            self.machine.run(case.kind, {RDI: OUT, RSI: USER_AT, RDX: ACTION, RCX: STATE})
        except Panicked as stop:
            return "panic", stop.args[0], tuple(self.events)
        if memory.read(OUT, 2) in LOOSE_TAIL:
            memory.put_bytes(OUT + 2, bytes(OUT_SIZE - 2))
        return "done", tuple(self.events), memory.bytes_at(HEAP_BASE, COMPARED)


def table_with_nonce(table, nonce, stored):
    return dict(table=table, nonce=nonce, stored=stored, x=5000000)


NAMED = (
    ("plain", {}),
    ("dest_len_at_limit", dict(dest_len=100)), ("dest_len_over", dict(dest_len=101)), ("dest_len_huge", dict(dest_len=1 << 40)),
    ("usd_len_at_limit", dict(usd_len=100)), ("usd_len_over", dict(usd_len=101)), ("both_len_over", dict(dest_len=101, usd_len=101)),
    ("len_before_window", dict(usd_len=101, gate_height=1 << 40)),
    ("height_below_gate", dict(height=999)), ("height_at_gate", dict(height=1000, gate_height=1000)), ("height_far_past_window", dict(height=999, base_word=0, gate_height=6000)),
    ("window_byte_set", dict(height=5000, gate_height=6000, base_word=0)), ("window_byte_clear", dict(height=4999, gate_height=6000, base_word=0)),
    ("window_near_top", dict(height=MASK[8] - 1, gate_height=MASK[8], base_word=MASK[8] - 4999)), ("window_top_set", dict(height=MASK[8] - 1, gate_height=MASK[8], base_word=MASK[8] - 5001)),
    ("window_at_turn", dict(height=MASK[8] - 1, gate_height=MASK[8], base_word=MASK[8] - 4998)), ("window_exact_max", dict(height=MASK[8], gate_height=MASK[8], now=(20000, 100, 4), base_word=MASK[8] - 4999)),
    ("window_turn_edge", dict(height=MASK[8] - 2, gate_height=MASK[8], base_word=MASK[8] - 5002)), ("window_big_base", dict(height=9, gate_height=10, base_word=1 << 63)),
    ("time_first_lower", dict(now=(19999, 900, 900))), ("time_first_higher", dict(now=(20001, 0, 0))), ("time_first_negative", dict(now=(0xFFFFFFF0, 200, 200))),
    ("time_gate_negative", dict(gate=(0xFFFFFFF0, 200, 200), now=(5, 0, 0))), ("time_second_lower", dict(now=(20000, 99, 900))), ("time_second_higher", dict(now=(20000, 101, 0))),
    ("time_second_top_bit", dict(now=(20000, 0x80000000, 0), gate=(20000, 1, 0))), ("time_second_gate_top_bit", dict(now=(20000, 1, 0), gate=(20000, 0x80000000, 0))),
    ("time_third_lower", dict(now=(20000, 100, 4))), ("time_third_higher", dict(now=(20000, 100, 6))), ("time_third_top_bit", dict(now=(20000, 100, 0x80000000), gate=(20000, 100, 1))),
    ("time_third_gate_top_bit", dict(now=(20000, 100, 1), gate=(20000, 100, 0x80000000))), ("time_ok_height_low", dict(now=(20001, 0, 0), height=5)),
    ("flag_oaw_clear", dict(flag=1, oaw=0)), ("flag_oaw_set", dict(flag=1, oaw=1)), ("flag_clear_oaw_clear", dict(flag=0, oaw=0)), ("flag_two_oaw_clear", dict(flag=2, oaw=0)),
    ("flag_oaw_two", dict(flag=1, oaw=2)), ("flag_oaw_high_bit", dict(flag=1, oaw=0x80)), ("flag_before_nonce", dict(flag=1, oaw=0, nonce=1 << 63)),
    ("nonce_zero", dict(nonce=0)), ("nonce_one", dict(nonce=1)), ("nonce_top_ok", dict(nonce=MASK[8] // 1000)), ("nonce_first_over", dict(nonce=MASK[8] // 1000 + 1)), ("nonce_max", dict(nonce=MASK[8])),
    ("nonce_over_alloc_fail", dict(nonce=MASK[8], alloc_fail=True)),
    ("no_items", dict(table="skip", items=0, nonce=1)), ("no_items_zero_nonce", dict(table="skip", items=0, nonce=0)),
    ("miss_group", dict(table="miss")), ("miss_next_group", dict(table="miss_next")), ("miss_zero_nonce", dict(table="miss", nonce=0)),
    ("hit_below", table_with_nonce("hit", 5, 4999)), ("hit_equal", table_with_nonce("hit", 5, 5000)), ("hit_above", table_with_nonce("hit", 5, 5001)), ("hit_top_stored", table_with_nonce("hit", 5, MASK[8])),
    ("hit_stored_top_bit", table_with_nonce("hit", 1 << 60, 1 << 63)), ("hit_stored_low_top_bit", table_with_nonce("hit", (1 << 63) // 500, (1 << 63) + 5)),
    ("hit_group_start", table_with_nonce("hit_first", 5, 5000)), ("hit_group_next", table_with_nonce("hit_next", 5, 5000)),
    ("hit_second_equal", table_with_nonce("hit_second", 5, 5000)), ("hit_second_below", table_with_nonce("hit_second", 5, 4000)),
    ("hit_third_group_equal", table_with_nonce("hit_last_group", 5, 5000)), ("hit_third_group_below", table_with_nonce("hit_last_group", 5, 4000)),
    ("hit_at_wrap", dict(table_with_nonce("hit_wrap", 5, 5000), hash=(0x25 << 57) | 60)), ("hit_after_wrap_below", dict(table_with_nonce("hit_wrap", 5, 4000), hash=(0x25 << 57) | 61)),
    ("parse_fails", dict(parse_tag=0xAC)), ("parse_fails_big_tag", dict(parse_tag=0x187)), ("scale_fails", dict(scale_tag=0xA8)), ("scale_fails_high_byte", dict(scale_tag=0x286)), ("scale_fails_next_tag", dict(scale_tag=0x187)),
    ("zero_amount", dict(x=0)), ("zero_amount_with_small_bal", dict(x=0, bal=0)), ("one_unit", dict(x=1, net=1)), ("above_bal", dict(x=500, bal=499)), ("at_bal", dict(x=500, bal=500, net=1)),
    ("bal_edge_top_bit", dict(x=1 << 63, bal=(1 << 63) - 1)), ("bal_edge_top_ok", dict(x=(1 << 63) - 1, bal=1 << 63)), ("bal_zero", dict(x=1, bal=0)),
    ("dex_missing", dict(dex_len=0)), ("dex_missing_above_cap", dict(dex_len=0, x=CAP + 1)), ("dex_missing_after_bal", dict(dex_len=0, x=500, bal=499)),
    ("dex_two", dict(dex_len=2)), ("below_mark", dict(x=MARK_LEVEL - 1)), ("at_mark", dict(x=MARK_LEVEL)), ("mark_next_line", dict(x=MARK_LEVEL + 4096)), ("mark_prev_line", dict(x=MARK_LEVEL - 4096)),
    ("at_cap", dict(x=CAP)), ("cap_plus_one", dict(x=CAP + 1)), ("cap_top_bit", dict(x=1 << 63)), ("cap_top", dict(x=MASK[8], bal=MASK[8])), ("cap_mid", dict(x=2 * CAP)),
    ("cap_before_dest", dict(x=CAP + 1, dest_tag=7)), ("cap_low_word", dict(x=CAP + (1 << 32))), ("mark_and_bad_dest", dict(x=MARK_LEVEL, dest_tag=0x33)),
    ("bad_dest", dict(dest_tag=7)), ("bad_dest_ok_low_byte", dict(dest_tag=0x286)), ("debit_fails", dict(debit_tag=0x5C)), ("debit_fails_33", dict(debit_tag=0x33)), ("debit_fails_big", dict(debit_tag=0x286)),
    ("debit_passes_other_net", dict(net=123)), ("net_zero", dict(net=0)), ("net_equals_bal", dict(x=500, bal=500, net=500)), ("net_above_bal", dict(x=500, bal=500, net=501)),
    ("insert_fails", dict(insert_tag=0x9A)), ("once_path", dict(once=1)), ("depth_zero", dict(depth=0)), ("depth_top", dict(depth=MASK[8])), ("depth_top_minus", dict(depth=MASK[8] - 1)),
    ("depth_top_rejected", dict(depth=MASK[8], nonce=0)), ("depth_top_len", dict(depth=MASK[8], dest_len=101)), ("depth_top_ok", dict(depth=MASK[8], x=1000)),
    ("top_full", dict(x=CAP, bal=CAP, net=CAP - 1000000, nonce=MASK[8] // 1000, table="hit", stored=(MASK[8] // 1000) * 1000 - 1)),
)


def named_cases(kind):
    return [Case(name, kind, **fields) for name, fields in NAMED]


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 11 ^ state


def vector_cases(count):
    source = lcg(0x77A5)
    rows = []
    edges = (0, 1, 2, 999, 1000, 1001, MARK_LEVEL - 1, MARK_LEVEL, CAP, CAP + 1, MASK[8], 1 << 63)
    for index in range(count):
        def pick():
            word = next(source)
            return edges[word >> 8 & 0xF] if word & 1 and word >> 8 & 0xF < len(edges) else next(source) >> (word >> 16 & 63)

        kind = COPIES[index % 3]
        fields = dict(x=pick(), bal=pick(), net=pick(), nonce=pick(), stored=pick(), height=pick(), gate_height=pick() if next(source) & 1 else 0, base_word=pick(), depth=pick())
        word = next(source)
        fields["table"] = ("miss", "miss_next", "hit", "hit_second")[word & 3]
        fields["flag"] = word >> 2 & 3
        fields["oaw"] = word >> 4 & 3
        fields["once"] = word >> 6 & 1
        fields["now"] = (20000 + (word >> 7 & 3), word >> 9 & 3, word >> 11 & 3)
        fields["gate"] = (20000 + (word >> 13 & 3), word >> 15 & 3, word >> 17 & 3)
        fields["dest_len"] = 95 + (word >> 19 & 7)
        fields["usd_len"] = 95 + (word >> 22 & 7)
        if fields["stored"] == 0 and fields["table"] in ("hit", "hit_second"):
            fields["stored"] = 1
        rows.append(Case("v%d" % index, kind, **fields))
    return rows


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case, harness.before)
        if got != want:
            raise EvidenceError("case %s of %#x: %r != %r" % (case.name, case.kind, got[:2], want[:2]))
        outcomes.append(got)
    return outcomes


def direct_to(image, target):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 <= len(text) and start + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            hits.append(start + at)
    return hits


def calls_through(image, slot):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text) and start + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            hits.append(start + at)
    return hits


def slot_rows(image):
    relative = image.relative()
    named = ((SLOT_PARSE, "decimal parse", PARSE_HELPER), (SLOT_SCALE, "usd scale", SCALE_WRAPPER), (SLOT_REF, "dex record", DEX_REF), (SLOT_MUT, "dex record mut", DEX_MUT),
             (SLOT_DEST, "address parse", DEST_HELPER), (SLOT_DEBIT, "first dex debit", DEBIT_HELPER), (SLOT_RECORD, "bridge record", RECORD), (SLOT_MARK, "lazy pair read", MARK_HELPER))
    rows = []
    for slot, role, target in named:
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        rows.append(("%#x" % slot, role, "%#x" % target))
    return rows


def site_rows(image):
    rows = []
    for name, copy, caller in zip(("core_a", "core_b", "core_c"), COPIES, CALLERS):
        sites = direct_to(image, copy)
        owners = sorted({image.fde(site)[0] for site in sites})
        if owners != [caller] or len(sites) != 3:
            raise EvidenceError("callers of %#x" % copy)
        rows.append(("%#x" % copy, name, len(sites), " ".join("%#x" % site for site in sorted(sites)), "%#x" % caller))
    sites = calls_through(image, SLOT_RECORD)
    rows.append(("%#x" % RECORD, "bridge_record", len(sites), " ".join("%#x" % site for site in sorted(sites)), ""))
    return rows


def constant_rows(image):
    """Read the literal limits from each copy's own bytes."""
    rows = []
    for copy, name in zip(COPIES, ("core_a", "core_b", "core_c")):
        start, stop = image.exact_fde(copy)
        data = bytes(image.blob[image.offset(start):image.offset(stop)])
        cap_at = data.index(b"\x48\xb8" + struct.pack("<Q", CAP))
        level_at = data.index(b"\x48\xc1\xe8\x0c\x48\x3d" + struct.pack("<I", SHIFTED_LEVEL))
        window_at = data.index(b"\x48\x3d" + struct.pack("<i", -WINDOW))
        scale_at = data.index(b"\xba" + struct.pack("<I", NONCE_SCALE))
        lengths = [at for at in range(len(data) - 4) if data[at:at + 2] in (b"\x49\x83", b"\x4d\x83") and data[at + 3] == 0x65]
        rows.append((name, "%#x" % (start + cap_at), CAP, "%#x" % (start + level_at), SHIFTED_LEVEL, (SHIFTED_LEVEL + 1) << 12, "%#x" % (start + window_at), WINDOW, "%#x" % (start + scale_at), NONCE_SCALE, len(lengths)))
    if (SHIFTED_LEVEL + 1) << 12 != MARK_LEVEL:
        raise EvidenceError("shifted level")
    return rows


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag in TEXT_ARMS:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 64])
        at = data.find(b"\x48\x8d\x35")
        if at < 0 or data[at + 7] != 0xBA:
            raise EvidenceError("status arm %#x has another shape" % tag)
        text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, at + 8)[0]
        rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")))
    for tag in PIECE_ARMS:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 64])
        at = data.find(b"\x48\x8d\x15")
        if at < 0:
            raise EvidenceError("status arm %#x has another shape" % tag)
        piece = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        offset = image.offset(piece)
        size = image.blob[offset]
        rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[offset + 1:offset + 1 + size]).decode("ascii") + "{}"))
    return rows


FIELD_BYTES = ((0x22157A4, bytes.fromhex("498b9730010000"), "field +0x130 of the serialized struct"),
               (0x22BD46E, bytes.fromhex("488d05"), "key lea of that field helper"),
               (0x22157C0, bytes.fromhex("4d8b8738010000"), "field +0x138"),
               (0x22157C7, bytes.fromhex("488d15"), "key lea of +0x138"),
               (0x22157E4, bytes.fromhex("458b8740010000"), "field +0x140"),
               (0x22157EB, bytes.fromhex("488d15"), "key lea of +0x140"),
               (0x235B43C, bytes.fromhex("418885a2310000"), "vote arm store of state +0x31a2"),
               (0x235B462, bytes.fromhex("418885d8340000"), "vote arm store of state +0x34d8"))
KEY_TEXT = {0x22BD46E: b"bal", 0x22157C7: b"last_pruned_deposit_block_number", 0x22157EB: b"oaw"}


def field_rows(image):
    rows = []
    for va, pattern, role in FIELD_BYTES:
        data = bytes(image.blob[image.offset(va):image.offset(va) + 7])
        if not data.startswith(pattern):
            raise EvidenceError("field row %#x" % va)
        key = ""
        if va in KEY_TEXT:
            at = va + 7 + struct.unpack_from("<i", data, 3)[0]
            text = KEY_TEXT[va]
            if bytes(image.blob[image.offset(at):image.offset(at) + len(text)]) != text:
                raise EvidenceError("key text %#x" % va)
            key = text.decode("ascii")
        rows.append(("%#x" % va, data.hex(), role, key))
    return rows


PIECES = (("nonce", "nonce", ((0, 0), (1, MASK[8] // 1000), (MASK[8] // 1000 + 1, MASK[8]))),
          ("amount", "x", ((0, 0), (1, MARK_LEVEL - 1), (MARK_LEVEL, CAP), (CAP + 1, MASK[8]))))


def piece_rows(harness):
    """Run both ends of each piece on every copy; both ends must walk the same rows."""
    rows = []
    machine = harness.machine
    for label, field, pieces in PIECES:
        for low, high in pieces:
            for copy in COPIES:
                walked = []
                results = []
                for value in (low, high):
                    fields = {field: value}
                    if field == "x":
                        fields["bal"] = MASK[8]
                    case = Case("%s_%#x" % (label, value), copy, **fields)
                    saved = machine.seen
                    machine.seen = set()
                    got = harness.run(case)
                    walked.append(machine.seen)
                    machine.seen = saved | walked[-1]
                    if got != spec_run(case, harness.before):
                        raise EvidenceError("piece end %s %#x" % (label, value))
                    status = struct.unpack_from("<H", got[2], OUT - HEAP_BASE)[0]
                    results.append(status)
                if walked[0] != walked[1] or results[0] != results[1]:
                    raise EvidenceError("piece %s %#x..%#x is not one path" % (label, low, high))
                rows.append((label, "%#x" % copy, low, high, "%#x" % results[0], len(walked[0])))
    return rows


def copy_rows(image):
    """Row by row compare of the three copies: lengths and operations, then displacement shifts."""
    first = decode_range(image, *image.exact_fde(COPIES[0]))
    rows = []
    for copy in COPIES[1:]:
        other = decode_range(image, *image.exact_fde(copy))
        if len(first) != len(other):
            raise EvidenceError("copy row counts differ")
        for left, right in zip(first, other):
            if left.op != right.op or left.size != right.size:
                raise EvidenceError("copy rows differ at %#x" % left.va)
            if left.data != right.data and left.rip_at is None and left.op not in ("call", "jcc", "jmp"):
                delta = right.va - left.va
                rows.append(("%#x" % copy, "%#x" % left.va, "%#x" % right.va, left.data.hex(), right.data.hex()))
    return rows


def edits_for(image, rows, seen):
    edits = []
    for row in rows:
        if row.va not in seen:
            continue
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def first_failure(harness, cases):
    for case in cases:
        try:
            if harness.run(case) != spec_run(case, harness.before):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError):
            return case
    return None


SATURATED_ADD = "bit 0 of the 5000 on the saturating arm: this arm is entered at -5000 or above, and 5001 carries for all of those too, so the result stays u64::MAX"
SHUFFLE = "bit 0 of the pshufd selector: the two low dwords are equal by then, so word 0 or word 1 gives the same broadcast"
INDEX_ZERO = "the stride: every call passes index 0, so the product is 0"
EXPECTED_SURVIVORS = {(0x3332612, "displacement"): "the pointer the first accessor computes is discarded by all callers read here", (0x3332705, "displacement"): "the first accessor has already tested the length, and the word 8 past it is above 0 in every fixture",
                      (0x333260B, "immediate"): INDEX_ZERO, (0x333270B, "immediate"): INDEX_ZERO}
for _base in COPIES:
    EXPECTED_SURVIVORS[(_base + 0xA1, "immediate")] = SATURATED_ADD
    EXPECTED_SURVIVORS[(_base + 0x16A, "immediate")] = SHUFFLE


def run_mutants(image, table, seen, lists):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    for copy in COPIES:
        if first_failure(control, lists[copy]) is not None:
            raise EvidenceError("an unedited image fails under the mutant step limit")
    for target in TARGETS:
        cases = lists[target] if target in lists else lists[COPIES[0]]
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            if first_failure(harness, cases) is not None:
                results.append((va, kind, "killed", "whole run"))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def rows_of(image, target):
    if target in (SCALE_WRAPPER, RECORD):
        return decode_range(image, *image.exact_fde(target))
    return decode_range(image, *image.exact_fde(target))


def analyse(image, mutate=True, vectors=600):
    harness = Harness(image)
    lists = {copy: named_cases(copy) for copy in COPIES}
    outcomes = {copy: check_cases(harness, lists[copy]) for copy in COPIES}
    check_cases(harness, vector_cases(vectors))
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, lists=lists, outcomes=outcomes, vector_count=vectors, unreached=unreached, slots=slot_rows(image), sites=site_rows(image), constants=constant_rows(image),
                  statuses=status_rows(image), fields=field_rows(image), pieces=piece_rows(harness), copies=copy_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, lists)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    if outcome[0] == "panic":
        return "panic", outcome[1], ",".join(str(event[0]) for event in outcome[2]), ""
    data = outcome[2]
    at = OUT - HEAP_BASE
    tag = struct.unpack_from("<H", data, at)[0]
    return "%#x" % tag, data[at:at + 0x10].hex(), ",".join(str(event[0]) for event in outcome[1]), hashlib.sha256(data).hexdigest()[:16]


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("slots.tsv", ("slot", "role", "relative_target"), result["slots"])
    tsv("call-sites.tsv", ("function", "name", "sites", "addresses", "caller_fde"), result["sites"])
    tsv("constants.tsv", ("copy", "cap_at", "cap", "level_at", "shifted_level", "level", "window_at", "window", "scale_at", "scale", "length_guards"), result["constants"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("fields.tsv", ("address", "bytes", "role", "key"), result["fields"])
    tsv("input-pieces.tsv", ("input", "copy", "low", "high", "status", "rows_walked"), result["pieces"])
    tsv("copy-differences.tsv", ("copy", "first_row", "this_row", "first_bytes", "this_bytes"), result["copies"])
    tsv("outcomes.tsv", ("function", "case", "status", "out_head", "events", "state_digest"),
        [("%#x" % copy, case.name) + describe(case, outcome) for copy in COPIES for case, outcome in zip(result["lists"][copy], result["outcomes"][copy])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": sum(len(rows) for rows in result["lists"].values()), "vector_cases": result["vector_count"],
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"), "survived": sum(1 for r in rows if r[2] == "survived")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
