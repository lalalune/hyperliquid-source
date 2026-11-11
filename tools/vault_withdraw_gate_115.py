#!/usr/bin/env python3
"""Reconstruct the node #115 vault withdraw and transfer admission gate 0x44ab4a0 from the ELF bytes and prove it against a written rule list.

The gate takes the vault state, the requested address, a mode word, an amount and the request date-time. It sums the leader's fee and the
fees of an address set (saturating), looks the address up in a map (a VecDeque searched by the real binary search 0x45578e0, or a B-tree walked
by the gate itself), checks the unlock date with a duration helper, converts the available amount to a ratio of the fee base, applies the
fraction, floor, excess, available, self-key, remaining and locked-amount rules and writes either a result record (tag 0x1a2) or an error tag.
The real bytes of the gate and of the deque search run in a small x86-64 evaluator; the fee helper, the chrono helpers, the available and
locked amount hooks, memcmp, the panic and the logging hooks are recording stubs with written contracts. A separately written rule list
predicts every result and every stub call, named wrong readings must be refused, and every reached condition, immediate and field
displacement of the subject code is edited. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/vault_withdraw_gate_115.py --out <dir>
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

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

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
HEAP_SIZE = 0xA0000
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
        if rela["size"] % 24:
            raise EvidenceError("truncated RELA section")
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
SHIFTS = {1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrdi", rm, ("r", reg), width, target=value)
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

    def run(self, entry, args, stack=()):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        for value in reversed(stack):
            self.push(value)
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
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64 if self.regs[RAX] >> 63 else 0)
            right = self.get(row.a, 8)
            right -= (1 << 64 if right >> 63 else 0)
            product = left * right
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not (-(1 << 63) <= product < (1 << 63))
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
        elif op in ("shld", "shrd", "shrdi"):
            bits = 8 * width
            count = (self.regs[RCX] if op == "shrd" else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op == "shld":
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
        elif op == "ror":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) if count else value)
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
            if op in ("addsd", "divsd", "subsd", "mulsd"):
                self.set_low(row.a[1], sse_arith(op[:3], self.low(row.a), self.low(row.b)))
                return
            if op == "minsd":
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
            if row.target not in (0, 3, 5):
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                x, y = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                hit = {0: x == y, 3: x != x or y != y, 5: not x < y}[row.target]
                if hit:
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




def sse_arith(op, a, b):
    """Scalar double add/sub/mul/div on raw bits with the x86 NaN rules: the first NaN operand wins and is quieted, a new NaN is the indefinite value."""
    quiet = 1 << 51
    for bits in (a, b):
        if (bits >> 52) & 0x7FF == 0x7FF and bits & ((1 << 52) - 1):
            return bits | quiet
    x, y = to_float(a), to_float(b)
    if op == "add":
        r = x + y
    elif op == "sub":
        r = x - y
    elif op == "mul":
        r = x * y
    else:
        r = fdiv(x, y)
    return 0xFFF8000000000000 if r != r else to_bits(r)


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


# ---------------------------------------------------------------------------------------------------------------------------
# Subject: the vault withdraw / transfer admission gate in l1/src/vault/mod.rs and the code it runs for real.

GATE = 0x44AB4A0                 # the gate body (FDE 0x44ab4a0..0x44abfaf)
DEQ = 0x45578E0                  # binary search over a VecDeque of 72 byte entries, keyed by a 20 byte address
FEE = 0x44A9430                  # per address fee sum helper (recorded stub here; its own packet is a later step)
MARK_BASE = 0x7700000000

# indirect call slots in .got / .data.rel.ro (the body calls through them); each is a recording stub
SLOT_OVERFLOW = 0x64E4EA8        # logs an arithmetic overflow, then the caller saturates
SLOT_DURATION = 0x64E0F70        # f64 seconds -> (secs, nanos)
SLOT_TIME_ADD = 0x64E0F78        # time of day + delta -> (time of day, whole days as seconds)
SLOT_DATE_ADD = 0x64E0AA0        # date + days -> date or 0
SLOT_AVAIL = 0x64EAAE0           # available amount of an address
SLOT_LATE = 0x64E0B20            # logging hook on the self-key bound failure
SLOT_LOCK = 0x64E5078            # amount already locked for the leader
SLOT_PANIC = 0x64DF830           # panic (never returns)
SLOT_ONCE = 0x64DF9F0            # once-only logging hook
SLOT_MEMCMP = 0x64DFB50          # memcmp
FLAG_WORD = 0x64F01D8            # logging flag word (non zero turns the logging hooks on)
SLOT_NAMES = {
    SLOT_OVERFLOW: "overflow-log", SLOT_DURATION: "duration-from-secs", SLOT_TIME_ADD: "time-add", SLOT_DATE_ADD: "date-add",
    SLOT_AVAIL: "available", SLOT_LATE: "late-log", SLOT_LOCK: "locked", SLOT_PANIC: "panic", SLOT_ONCE: "once-log",
    SLOT_MEMCMP: "memcmp",
}
PANIC_ARGS = {0x646EBD8: "set-exhausted", 0x646AA60: "loop-entry", 0x648C170: "ratio-invalid", 0x648C158: "base-invalid"}

# heap layout
OUT = HEAP_BASE + 0x100          # 0x28 byte result record
SELF = HEAP_BASE + 0x1000        # the vault state (0x100 bytes used)
SEARCH = HEAP_BASE + 0x1100      # 20 byte address searched in the map
DATE_IN = HEAP_BASE + 0x1120     # 12 byte date-time of the request
CTX = HEAP_BASE + 0x1140         # context record: word 0 is passed to the locked amount hook
RING = HEAP_BASE + 0x1400        # VecDeque storage (72 byte entries, up to 40)
ARENA = HEAP_BASE + 0x2400
USED = 0x98000
FILL = 0x31

# fields of the vault state read by the body
F_TAG, F_SET_ROOT, F_SET_HEIGHT, F_SET_LEN = 0x00, 0x08, 0x10, 0x18
F_MAP, F_MAP_ROOT, F_MAP_HEIGHT = 0x50, 0x58, 0x60           # word 0: capacity of a VecDeque, or the tree niche
F_MAP_HEAD, F_MAP_LEN = 0x60, 0x68
F_LOCK_SECS, F_LEADER, F_SELF_KEY, F_FLAG_B6 = 0x78, 0x8C, 0xA0, 0xB6
TREE_NICHE = 1 << 63
ENTRY = 72                       # VecDeque entry: 20 byte key at +0, 48 byte record at +0x18
RECORD_FRAC, RECORD_DATE = 0, 0x24
SUCCESS_TAG = 0x1A2
ERROR_TAGS = (0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x2A, 0x11F)

I64_MAX = (1 << 63) - 1
I64_MIN = -(1 << 63)


def sgn(value, bits=64):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def f64(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & MASK[8]))[0]


def bits64(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def read_const(image, va, size=8):
    at = image.offset(va)
    return bytes(image.blob[at:at + size])


CONSTANTS = (       # (address, role, size)
    (0x450E80, "usd_scale", 8),
    (0x459010, "invalid_ratio_value", 8),
    (0x459BA0, "minimum_base_value", 8),
    (0x459B00, "minimum_ratio", 8),
    (0x459808, "clamp_low", 8),
    (0x459360, "clamp_high", 8),
    (0x458E50, "saturation_threshold", 8),
    (0x4592B0, "one", 8),
    (0x459038, "self_slack_factor", 8),
    (0x4592D8, "kind_floor", 8),
    (0x4679D0, "latest_date", 4),
    (0x4679D4, "latest_seconds", 4),
    (0x4679D8, "latest_fraction", 4),
)


def constant_values(image):
    k = {}
    for va, role, size in CONSTANTS:
        raw = read_const(image, va, size)
        k[role] = struct.unpack("<d", raw)[0] if size == 8 else struct.unpack("<I", raw)[0]
    return k


# --- models of the helpers that are recording stubs (contracts, not claims about their bodies) ---------------------------------------

def model_duration(bits):
    """Duration::from_secs_f64 contract: a finite non-negative f64 below 2**64 becomes (secs, nanos), anything else panics."""
    value = f64(bits)
    if not (0.0 <= value < 18446744073709551616.0):
        raise Panicked("duration")
    secs = int(value)
    nanos = int((value - secs) * 1e9 + 0.5)
    if nanos >= 10 ** 9:
        secs, nanos = secs + 1, nanos - 10 ** 9
    return secs, nanos


def model_time_add(tsecs, tfrac, secs, nanos):
    """NaiveTime + delta contract: returns (time of day, whole-day seconds carried out)."""
    total = tsecs + secs
    frac = tfrac + nanos
    if frac >= 10 ** 9:
        frac -= 10 ** 9
        total += 1
    days = total // 86400
    return total - days * 86400, frac, days * 86400


def model_date_add(date, days):
    """NaiveDate + days contract: the packed date plus the day count while it stays a positive i32, else 0 (None)."""
    value = date + sgn(days, 32)
    return value if 0 < value < (1 << 31) else 0


class Case:
    __slots__ = ("name", "tag", "set_keys", "set_len", "set_height", "set_seed", "set_root_null", "leader", "self_key", "b6", "lock_bits",
                 "store", "entries", "head", "cap", "height", "seed", "root_null", "search", "mode", "amount", "date_in", "mode2",
                 "min_left", "fees", "default_fee", "avail", "default_avail", "locked", "flag", "chunks", "bad_order")

    def __init__(self, **kw):
        for name in self.__slots__:
            setattr(self, name, kw.get(name))


class Arena:
    def __init__(self, memory):
        self.memory, self.at = memory, ARENA

    def alloc(self, size):
        at = self.at
        self.at += (size + 15) & ~15
        if self.at > HEAP_BASE + USED:
            raise EvidenceError("arena exhausted")
        return at




def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 33


def min_items(height):
    return (1 << (height + 1)) - 1


def max_items(height):
    return 11 if height == 0 else 12 * max_items(height - 1) + 11


def feasible_heights(count):
    return [h for h in range(10) if min_items(h) <= count <= max_items(h)]


def split_tree(items, height, stream):
    """Shape of a B-tree of the given height over sorted items: (keys, children), children None in a leaf; nodes hold 1..11 keys."""
    count = len(items)
    if height == 0:
        if not 1 <= count <= 11:
            raise EvidenceError("leaf size")
        return list(items), None
    lo, hi = min_items(height - 1), max_items(height - 1)
    options = [p for p in range(2, 13) if p * lo <= count - (p - 1) <= p * hi]
    parts = options[next(stream) % len(options)]
    rest = count - (parts - 1)
    sizes = [lo] * parts
    spare = rest - lo * parts
    while spare:
        index = next(stream) % parts
        if sizes[index] < hi:
            sizes[index] += 1
            spare -= 1
    keys, children, at = [], [], 0
    for index in range(parts):
        children.append(split_tree(items[at:at + sizes[index]], height - 1, stream))
        at += sizes[index]
        if index < parts - 1:
            keys.append(items[at])
            at += 1
    return keys, children


def tree_inorder(shape):
    keys, children = shape
    if children is None:
        return list(keys)
    out = []
    for index, child in enumerate(children):
        out.extend(tree_inorder(child))
        if index < len(keys):
            out.append(keys[index])
    return out


# --- the harness -----------------------------------------------------------------------------------------------------------------

def memcmp_result(a, b):
    for x, y in zip(a, b):
        if x != y:
            return (x - y) & MASK[4]
    return 0


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset({DEQ})
        machine.calls[FEE] = self.on_fee
        statics = machine.memory.statics
        hooks = {
            SLOT_OVERFLOW: self.on_overflow, SLOT_DURATION: self.on_duration, SLOT_TIME_ADD: self.on_time_add,
            SLOT_DATE_ADD: self.on_date_add, SLOT_AVAIL: self.on_avail, SLOT_LATE: self.on_late, SLOT_LOCK: self.on_lock,
            SLOT_PANIC: self.on_panic, SLOT_ONCE: self.on_once, SLOT_MEMCMP: self.on_memcmp,
        }
        for slot, hook in hooks.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        self.case, self.log = None, []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def key_at(self, address):
        return bytes(self.machine.memory.bytes_at(address, 20))

    def on_fee(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == CTX, "fee context")
        key = self.key_at(regs[RSI])
        self.log.append(("fee", key.hex()))
        regs[RAX] = self.case.fees.get(key, self.case.default_fee) & MASK[8]

    def on_overflow(self, machine):
        self.log.append(("overflow", machine.regs[RDI]))

    def on_duration(self, machine):
        bits = machine.xmm[0] & MASK[8]
        self.log.append(("duration", bits))
        secs, nanos = model_duration(bits)
        machine.regs[RAX], machine.regs[RDX] = secs, nanos
        machine.keep_rdx = True

    def on_time_add(self, machine):
        regs, mem = machine.regs, machine.memory
        out, src = regs[RDI], regs[RSI]
        tsecs, tfrac = mem.read(src, 4), mem.read(src + 4, 4)
        secs, nanos = regs[RDX], regs[RCX] & MASK[4]
        self.log.append(("time-add", tsecs, tfrac, secs, nanos))
        new_secs, new_frac, whole = model_time_add(tsecs, tfrac, secs, nanos)
        mem.write(out, 4, new_secs)
        mem.write(out + 4, 4, new_frac)
        mem.write(out + 8, 8, whole & MASK[8])

    def on_date_add(self, machine):
        regs = machine.regs
        date, days = regs[RDI] & MASK[4], regs[RSI] & MASK[4]
        self.log.append(("date-add", date, days))
        regs[RAX] = model_date_add(date, days)

    def on_avail(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == SELF and regs[RSI] == CTX, "available arguments")
        key = self.key_at(regs[RDX])
        self.log.append(("available", key.hex()))
        regs[RAX] = self.case.avail.get(key, self.case.default_avail) & MASK[8]

    def on_late(self, machine):
        self.log.append(("late",))

    def on_lock(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == machine.memory.read(CTX, 8), "locked amount context word")
        self.log.append(("locked", self.key_at(regs[RSI]).hex()))
        regs[RAX] = self.case.locked & MASK[8]

    def on_panic(self, machine):
        raise Panicked(PANIC_ARGS.get(machine.regs[RDI] - 0, "panic-%#x" % machine.regs[RDI]))

    def on_once(self, machine):
        self.log.append(("once",))

    def on_memcmp(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 20, "memcmp length")
        regs[RAX] = memcmp_result(self.key_at(regs[RDI]), self.key_at(regs[RSI]))

    # --- memory construction ---

    def build_set(self, arena, shape, parent, index):
        mem = self.machine.memory
        keys, children = shape
        node = arena.alloc(0x148)
        mem.put_bytes(node, bytes(0x148 * [0xC7]))
        mem.write(node, 8, parent)
        mem.write(node + 0xE4, 2, index)
        mem.write(node + 0xE6, 2, len(keys))
        for position, key in enumerate(keys):
            mem.put_bytes(node + 8 + 20 * position, key)
        if children is not None:
            for position, child in enumerate(children):
                mem.write(node + 0xE8 + 8 * position, 8, self.build_set(arena, child, node, position))
        return node

    def build_map_node(self, arena, shape, records, parent, index):
        mem = self.machine.memory
        keys, children = shape
        node = arena.alloc(0x360)
        mem.put_bytes(node, bytes(0x360 * [0xC9]))
        mem.write(node + 0x210, 8, parent)
        mem.write(node + 0x2F4, 2, index)
        mem.write(node + 0x2F6, 2, len(keys))
        for position, key in enumerate(keys):
            mem.put_bytes(node + 0x218 + 20 * position, key)
            mem.put_bytes(node + 0x30 * position, records[key])
        if children is not None:
            for position, child in enumerate(children):
                mem.write(node + 0x2F8 + 8 * position, 8, self.build_map_node(arena, child, records, node, position))
        return node

    def fresh(self, case):
        machine = self.machine
        mem = machine.memory
        mem.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        mem.put_bytes(HEAP_BASE, bytes((index * 29 + 5) & 0xFF for index in range(0x1000)))
        mem.put_bytes(SELF, bytes((FILL + 3 * index) & 0xFF for index in range(0x100)))
        mem.put_bytes(OUT, bytes(0x40 * [0xEE]))
        self.case, self.log = case, []
        arena = Arena(mem)
        mem.write(SELF + F_TAG, 8, case.tag)
        if case.set_keys:
            shape = split_tree(case.set_keys, case.set_height, lcg(case.set_seed))
            root = self.build_set(arena, shape, 0, 0)
        else:
            root = 0
        if case.set_root_null:
            root = 0
        mem.write(SELF + F_SET_ROOT, 8, root)
        mem.write(SELF + F_SET_HEIGHT, 8, case.set_height)
        mem.write(SELF + F_SET_LEN, 8, case.set_len)
        mem.write(SELF + F_LOCK_SECS, 8, case.lock_bits)
        mem.put_bytes(SELF + F_LEADER, case.leader)
        mem.put_bytes(SELF + F_SELF_KEY, case.self_key)
        mem.write(SELF + F_FLAG_B6, 1, case.b6)
        mem.put_bytes(SEARCH, case.search)
        for position, word in enumerate(case.date_in):
            mem.write(DATE_IN + 4 * position, 4, word)
        mem.write(CTX, 8, 0x0C0FFEE000000000 + (case.locked & 0xFFFF))
        mem.put_bytes(CTX + 8, bytes(range(0x40, 0x58)))
        mem.statics[FLAG_WORD] = case.flag
        records = {key: record for key, record in case.entries}
        if case.store == "deque":
            cap = case.cap
            slots = [None] * cap
            for index, (key, record) in enumerate(case.entries):
                slots[(case.head + index) % cap] = (key, record)
            for physical in range(cap):
                at = RING + ENTRY * physical
                if slots[physical] is None:
                    mem.put_bytes(at, bytes(ENTRY * [0x9D]))
                else:
                    key, record = slots[physical]
                    mem.put_bytes(at, key + bytes(4))
                    mem.put_bytes(at + 0x18, record)
            for offset, value in ((0, cap), (8, RING), (0x10, case.head), (0x18, len(case.entries))):
                mem.write(SELF + F_MAP + offset, 8, value)
        else:
            keys = [key for key, _ in case.entries]
            if keys:
                shape = split_tree(keys, case.height, lcg(case.seed))
                root = self.build_map_node(arena, shape, records, 0, 0)
            else:
                root = 0
            if case.root_null:
                root = 0
            for offset, value in ((0, TREE_NICHE), (8, root), (0x10, case.height), (0x18, len(case.entries))):
                mem.write(SELF + F_MAP + offset, 8, value)
        return bytes(mem.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        try:
            outcome = self.drive(case)
        except Panicked as panic:
            outcome = ("panic", str(panic))
        after = bytes(machine.memory.heap[:USED])
        lo, hi = OUT - HEAP_BASE, OUT - HEAP_BASE + 0x40
        if after[:lo] != before[:lo] or after[hi:] != before[hi:]:
            raise Halt("the body changed memory outside the result record")
        return before, (outcome, self.log)

    def drive(self, case):
        machine = self.machine
        mem = machine.memory
        regs = {RDI: OUT, RSI: SELF, RDX: SEARCH, RCX: case.mode, R8: case.amount & MASK[8], R9: DATE_IN}
        result = machine.run(GATE, regs, stack=(case.mode2 & MASK[8], case.min_left & MASK[8], CTX))
        self.expect(result == OUT, "result pointer")
        tag = mem.read(OUT, 2)
        raw = mem.bytes_at(OUT, 0x40)
        if tag == SUCCESS_TAG:
            kind, fbits, amount, ratio = (int.from_bytes(raw[o:o + 8], "little") for o in (8, 0x10, 0x18, 0x20))
            if fbits == POISON:
                fbits = None
            return ("ok", kind, fbits, amount, ratio)
        self.expect(raw[2:] == bytes(0x3E * [0xEE]) and tag in ERROR_TAGS, "error record shape")
        return ("err", tag)


# --- the rule list: what the gate decides, written from the control flow and independent of the evaluator ---------------------------

M32 = MASK[4]
M64 = MASK[8]
USD = "usd_scale"


def sat_trunc(value, k, floor_zero):
    """cvttsd2si with the explicit clamp and the saturation compare the body wraps around it."""
    if value != value or abs(value) == math.inf:
        return 0
    low, high = k["clamp_low"], k["clamp_high"]
    value = min(max(value, low), high)
    out = I64_MAX if value > k["saturation_threshold"] else int(value)
    return max(out, 0) if floor_zero else out


def record_fields(record):
    frac = int.from_bytes(record[0:8], "little")
    date = struct.unpack_from("<3I", record, RECORD_DATE)
    return frac, date


def date_gate(case, record_date, k, log, flags):
    """The unlock date check: the request date must be at or after the stored date plus the lock duration."""
    bits = case.lock_bits
    if "lock_ignored" in flags:
        comp = record_date
    else:
        log.append(("duration", bits))
        secs, nanos = model_duration(bits)
        total = min(secs * 10 ** 9 + nanos, I64_MAX)
        quot, rem = divmod(total, 10 ** 9)
        log.append(("time-add", record_date[1], record_date[2], quot, rem))
        new_secs, new_frac, whole = model_time_add(record_date[1], record_date[2], quot, rem)
        comp = (k["latest_date"], k["latest_seconds"], k["latest_fraction"])
        first = (whole + 0xFFDF3B645A1CAC08) & M64
        second = (whole + 0xFFFF574000000000) & M64
        if first > 0xFFBE76C8B4395810 and second >= 0xFFFEAE7FFFFEAE81:
            high = (sgn(whole) * 0x1845C8A0CE512957) >> 64
            days = ((high >> 63 & 1) + ((high & M64) >> 13)) & M32
            log.append(("date-add", record_date[0], days))
            moved = model_date_add(record_date[0], days)
            if moved:
                comp = (moved, new_secs, new_frac)
    mine = (sgn(case.date_in[0], 32), case.date_in[1], case.date_in[2])
    theirs = (sgn(comp[0], 32), comp[1], comp[2])
    if "date_strict" in flags:
        return mine > theirs
    if "date_reversed" in flags:
        return mine <= theirs
    return mine >= theirs


def spec_gate(case, k, flags=frozenset()):
    log = []

    def fee(key):
        log.append(("fee", key.hex()))
        return sgn(case.fees.get(key, case.default_fee))

    total = fee(case.leader) if "base_fee_skipped" not in flags else 0
    if case.tag == 2 and case.set_keys and not case.set_root_null and case.set_len != 0 and "set_ignored" not in flags:
        order = list(case.set_keys)
        if "set_reversed" in flags:
            order = list(reversed(order[:case.set_len])) + order[case.set_len:]
        for index in range(case.set_len):
            if index >= len(order):
                return ("panic", "set-exhausted"), log
            part = fee(order[index])
            grown = total + part
            if not I64_MIN <= grown <= I64_MAX:
                log.append(("overflow", 0))
                if "set_wraps" in flags:
                    grown = sgn(grown)
                else:
                    grown = I64_MAX if grown > 0 else I64_MIN
            total = grown
    if total < 0 or (total == 0 and "zero_base_allowed" not in flags):
        return ("err", 0xA), log
    base = total

    found = None
    if not (case.store == "tree" and case.root_null):
        for key, record in case.entries:
            if key == case.search or ("prefix_key" in flags and key[:16] == case.search[:16]):
                found = record
                break
    if found is None:
        return ("err", 0xB), log
    frac_bits, record_date = record_fields(found)

    if case.tag != 1 or "tag1_checked" in flags:
        try:
            ok = date_gate(case, record_date, k, log, flags)
        except Panicked as panic:
            return ("panic", str(panic)), log
        if not ok:
            return ("err", 0xC), log

    log.append(("available", case.search.hex()))
    avail = case.avail.get(case.search, case.default_avail) & M64
    one = case.mode == 1 or ("mode_any_nonzero" in flags and case.mode != 0)
    amount = (case.amount & M64) if (one and "avail_always" not in flags) else avail
    frac = f64(frac_bits)
    usd = k[USD]
    base_f = float(base)
    lo, hi = float(amount) / usd, float(base) / usd
    ratio = (math.nan if lo == 0 else math.inf) if hi == 0 else lo / hi
    if not math.isfinite(ratio) or hi < k["minimum_base_value"]:
        return ("panic", "ratio-invalid" if one else "base-invalid"), log

    def too_big(code):
        if case.flag:
            log.append(("once",))
        return ("err", code), log

    if not one and case.flag:
        log.append(("once",))
    over = ratio >= frac if "ratio_equal_cap" in flags else ratio > frac
    if (over and "ratio_cap_ignored" not in flags) or (k["minimum_ratio"] > ratio and "ratio_floor_ignored" not in flags):
        return too_big(0xE)
    limit = sat_trunc(frac * base_f, k, True)
    if "limit_rounded_up" in flags and limit < I64_MAX and sat_trunc(frac * base_f, k, True) != frac * base_f:
        limit += 1
    seen = amount + 1 if "amount_plus_one" in flags else amount
    if limit > seen and "excess_ignored" not in flags:
        threshold = 1_000_000 if "excess_one_million" in flags else 5_000_000
        if limit - seen < threshold:
            return ("err", 0x2A), log
    if amount > avail and "avail_ignored" not in flags:
        return ("err", 0xD), log
    if (case.search == case.self_key and "self_path_ignored" not in flags) or "self_path_always" in flags:
        diff = frac - ratio
        slack = (k["one"] - ratio) * k["self_slack_factor"]
        if slack > k["minimum_ratio"] + diff and "self_slack_ignored" not in flags:
            log.append(("late",))
            return ("err", 0xF), log
        bound = 10_000_000 if "self_bound_ten_million" in flags else 100_000_000
        if sat_trunc(diff * base_f, k, False) < bound:
            return ("err", 0x10), log
    product = base_f * ratio
    taken = sat_trunc(product, k, False)
    if (case.mode2 == 1 or ("mode2_any_nonzero" in flags and case.mode2 != 0)) and "remaining_ignored" not in flags:
        left = base - taken
        left = max(min(left, I64_MAX), I64_MIN)
        if (left & M64) < (case.min_left & M64) if "min_left_unsigned" in flags else left < sgn(case.min_left):
            return ("err", 0x11F), log
    if case.tag == 1:
        return ("ok", 0, bits64(product), taken & M64, bits64(ratio)), log
    log.append(("locked", case.leader.hex()))
    locked = sgn(case.locked)
    if (taken < locked) if "locked_lt" in flags else (taken <= locked):
        flagged = case.b6 != 0
        if "kind_inverted" in flags:
            flagged = not flagged
        if flagged:
            return ("ok", 1, bits64(ratio), taken & M64, bits64(ratio)), log
        return ("ok", 0, None, taken & M64, bits64(ratio)), log
    floor = k["kind_floor"] if "kind_floor_zero" not in flags else 0.0
    shown = ratio if ratio > floor else floor
    return ("ok", 1, bits64(shown), taken & M64, bits64(ratio)), log


# --- case generation ---------------------------------------------------------------------------------------------------------------

class Draw:
    def __init__(self, seed):
        self.stream = lcg(seed)

    def below(self, n):
        return next(self.stream) % n

    def chance(self, num, den):
        return self.below(den) < num

    def pick(self, items):
        return items[self.below(len(items))]

    def key(self):
        return bytes(self.below(256) for _ in range(20))

    def uniform(self):
        return (next(self.stream) & 0xFFFFFF) / float(1 << 24)

    def log_range(self, low, high):
        return int(low * math.exp(self.uniform() * math.log(high / low)))


def fresh_case(**kw):
    base = dict(name="case", tag=1, set_keys=[], set_len=0, set_height=0, set_seed=1, set_root_null=False, leader=bytes(range(1, 21)),
                self_key=bytes(range(101, 121)), b6=0, lock_bits=bits64(3600.0), store="deque", entries=[], head=0, cap=4, height=0,
                seed=1, root_null=False, search=bytes(range(1, 21)), mode=0, amount=0, date_in=(800000, 100, 5), mode2=0, min_left=0,
                fees={}, default_fee=0, avail={}, default_avail=0, locked=0, flag=0, chunks=None, bad_order=False)
    base.update(kw)
    return Case(**base)


def make_record(frac_bits, date, filler):
    return struct.pack("<Q", frac_bits) + filler + struct.pack("<3I", *date)


def draw_case(d, index):
    case = fresh_case(name="r%d" % index)
    case.tag = d.pick((0, 1, 1, 2, 2, 2))
    case.leader = d.key()
    case.self_key = d.key() if d.chance(2, 3) else case.leader
    case.b6 = d.pick((0, 1, 1, 7))
    case.flag = d.pick((0, 0, 1, 5))
    case.mode = d.pick((1, 1, 0, 2, 9))
    case.mode2 = d.pick((1, 1, 0, 3))
    # the address set walked when the tag is 2
    count = d.pick((0, 1, 2, 5, 11, 12, 20, 40)) if case.tag == 2 else d.pick((0, 0, 3))
    keys = sorted({d.key() for _ in range(count)})
    case.set_keys = keys
    options = feasible_heights(len(keys)) if keys else [0]
    case.set_height = d.pick(options) if options else 0
    case.set_seed = d.below(1 << 30) + 1
    case.set_len = len(keys)
    pick = d.below(40)
    if pick == 0 and keys:
        case.set_len = len(keys) + d.pick((1, 3))
    elif pick == 1:
        case.set_root_null = True
    elif pick == 2:
        case.set_len = 0
    elif pick == 3 and len(keys) > 2:
        case.set_len = len(keys) - 2
    # fees
    scale = d.pick((10 ** 4, 10 ** 6, 10 ** 8, 10 ** 10, 10 ** 12))
    for key in [case.leader] + keys:
        case.fees[key] = d.log_range(1, scale) if d.chance(19, 20) else -d.log_range(1, scale)
    if d.chance(1, 12):
        case.fees[case.leader] = d.pick((I64_MAX, I64_MAX - 5, 1, 0))
        if keys:
            case.fees[keys[0]] = d.pick((I64_MAX, 7, -3))
    if d.chance(1, 14):
        case.fees[case.leader] = d.pick((I64_MIN, I64_MIN + 3))
        if keys:
            case.fees[keys[-1]] = -d.pick((9, 1 << 40))
    case.default_fee = d.log_range(1, scale)
    total = fee_total(case)
    total = total if total > 0 else d.log_range(10 ** 5, 10 ** 13)
    base_f = float(total)
    # the map entries: sorted, with a record per key
    ecount = d.pick((0, 1, 1, 2, 3, 6, 11, 12, 13, 14, 25, 40))
    pool = {d.key() for _ in range(ecount)}
    search_choice = d.below(10)
    search = case.self_key if search_choice < 3 else case.leader if search_choice < 4 else d.key()
    if d.chance(9, 10):
        pool.add(search)
    case.search = search
    frac = d.pick((0.5, 0.9, 1.0, 0.01, 0.05, 0.3, 2.0, 1e-9)) * (0.5 + d.uniform()) if d.chance(9, 10) else d.pick((0.0, math.nan, math.inf, -0.5))
    frac_bits = bits64(frac)
    date_base = d.pick((730000, 738000, 1, 2147483000, 100, 0x7FFFFFF0))
    record_secs = d.pick((0, 40000, 86399, 86000, 123456))
    entries = []
    for key in sorted(pool):
        fb = frac_bits if key == search else bits64(d.pick((0.5, 0.1, 1.0, 0.02)) * (0.5 + d.uniform()))
        date = (date_base + d.below(3), record_secs, d.pick((0, 999999999, 12345, 500000000)))
        entries.append((key, make_record(fb, date, bytes(d.below(256) for _ in range(28)))))
    case.entries = entries
    case.store = d.pick(("deque", "tree"))
    if case.store == "deque":
        case.cap = max(1, len(entries) + d.pick((0, 0, 1, 3, 7)))
        case.head = d.below(case.cap)
    else:
        opts = feasible_heights(len(entries)) if entries else [0]
        case.height = d.pick(opts)
        case.seed = d.below(1 << 30) + 1
        if d.chance(1, 40):
            case.root_null = True
    # the lock duration and the request date, steered so about half the requests pass
    case.lock_bits = d.pick((bits64(0.0), bits64(3600.5), bits64(259200.0), bits64(3600.5), bits64(0.0), bits64(86400.0 * 30 + 0.25),
                             bits64(-1.0), bits64(math.nan), bits64(math.inf), bits64(1.8446744073709552e19), bits64(9.2e9), bits64(1e-9),
                             bits64(1e7), bits64(4e9), bits64(100.0), bits64(2.5)))
    if f64(case.lock_bits) != f64(case.lock_bits) or not (0 <= f64(case.lock_bits) < 1.8446744073709552e19):
        if not d.chance(1, 4):
            case.lock_bits = bits64(d.pick((0.0, 3600.5, 259200.0, 1e7)))
    case.date_in = (date_base + d.pick((0, 1, 2, 3, 4, 30, 120000, 4, 30, 5000, -5)) if d.chance(19, 20) else d.pick((0xFFFFFFF0, 0x80000000, 5)),
                    d.pick((0, 100, 86399, 40000, 123456)), d.pick((0, 5, 999999999, 12345, 500000000)))
    # amounts around the fraction
    ratio = frac * d.pick((0.5, 0.9, 0.9999, 1.0, 1.0001, 0.2, 0.05, 1e-9, 0.01)) if frac == frac and 0 < frac < 10 else d.uniform()
    ratio = max(ratio, 1e-12)
    wanted = int(ratio * base_f) if ratio * base_f < 1.8e19 else I64_MAX
    case.avail[case.search] = max(0, wanted + d.pick((0, 0, 0, 3, -3, 1000)))
    case.default_avail = d.log_range(1, 10 ** 12)
    if case.mode == 1:
        case.amount = max(0, wanted + d.pick((0, 0, 1, -1, 5, -5, 5_000_000, -5_000_000))) if d.chance(9, 10) else d.log_range(1, 10 ** 13)
        if d.chance(1, 3):
            case.avail[case.search] = case.amount + d.pick((0, 1, -1, 10 ** 6))
    else:
        case.amount = d.log_range(1, 10 ** 9)
    spare = d.pick((0, 100_000_000, 99_999_999, 100_000_001, 250_000_000, -1_000))
    if case.search == case.self_key and d.chance(1, 2):
        # steer the self key bound near 1e8: (frac - ratio) * base ~ spare
        need = (frac - ratio) * base_f if frac == frac else 0
        target = need - spare if abs(need) < 1e18 else 0
        case.avail[case.search] = max(0, int((ratio) * base_f))
    case.locked = d.pick((0, 1, d.log_range(1, 10 ** 13), I64_MAX, -5))
    if d.chance(1, 2):
        case.locked = int(ratio * base_f) + d.pick((0, 1, -1, 1000))
    case.min_left = d.pick((0, -1, 5, 10 ** 6, I64_MIN, I64_MAX, total - int(ratio * base_f), total - int(ratio * base_f) + 1,
                            total - int(ratio * base_f) - 1))
    return case


def fee_total(case):
    total = sgn(case.fees.get(case.leader, case.default_fee))
    if case.tag == 2 and case.set_keys and not case.set_root_null and case.set_len != 0:
        for index in range(min(case.set_len, len(case.set_keys))):
            total += sgn(case.fees.get(case.set_keys[index], case.default_fee))
            total = max(min(total, I64_MAX), I64_MIN)
    return total


def random_cases(count, seed=0x5EED5A17):
    d = Draw(seed)
    for index in range(count):
        yield draw_case(d, index)



# --- named cases: one per terminal outcome and per structural corner ---------------------------------------------------------------

def key_n(n):
    return bytes([(n * 7 + 3 * i + 1) & 0xFF for i in range(20)])


def good_case(**kw):
    """A request that succeeds for a tag-1 vault: fee base 1e9, fraction 0.5, available 2e8 (ratio 0.2)."""
    search = key_n(50)
    entries = [(key_n(10), make_record(bits64(0.5), (730000, 100, 5), bytes(28))), (search, make_record(bits64(0.5), (730000, 100, 5), bytes(28)))]
    entries.sort()
    base = dict(name="good", tag=1, leader=key_n(1), self_key=key_n(2), search=search, entries=entries, fees={key_n(1): 10 ** 9},
                avail={search: 2 * 10 ** 8}, mode=0, mode2=0, store="deque", cap=4, head=2, date_in=(730001, 0, 0), locked=10 ** 9)
    base.update(kw)
    return fresh_case(**base)


def named_cases():
    out = [good_case()]
    add = out.append
    search = key_n(50)
    rec = lambda frac, date=(730000, 100, 5): make_record(bits64(frac), date, bytes(28))
    add(good_case(name="tree-map", store="tree", height=0))
    add(good_case(name="mode1-amount", mode=1, amount=10 ** 8))
    add(good_case(name="mode1-over-available", mode=1, amount=3 * 10 ** 8))
    add(good_case(name="ratio-above-fraction", avail={search: 6 * 10 ** 8}))
    add(good_case(name="ratio-below-floor", avail={search: 1}))
    add(good_case(name="excess-small", avail={search: 499_000_000}))
    add(good_case(name="remaining-too-small", mode2=1, min_left=10 ** 9))
    add(good_case(name="remaining-ok", mode2=1, min_left=0))
    add(good_case(name="base-zero", fees={key_n(1): 0}))
    add(good_case(name="base-negative", fees={key_n(1): -5}))
    add(good_case(name="absent-key", search=key_n(99)))
    add(good_case(name="empty-map", entries=[]))
    add(good_case(name="empty-tree", entries=[], store="tree", height=0))
    add(good_case(name="tree-null-root", store="tree", height=0, root_null=True))
    add(good_case(name="date-tag0-pass", tag=0, date_in=(730001, 0, 0), lock_bits=bits64(3600.0)))
    add(good_case(name="date-tag0-fail", tag=0, date_in=(730000, 100, 5), lock_bits=bits64(3600.0)))
    add(good_case(name="date-tag0-equal", tag=0, date_in=(730000, 3700, 5), lock_bits=bits64(3600.0)))
    add(good_case(name="date-tag0-equal-minus-one", tag=0, date_in=(730000, 3699, 5), lock_bits=bits64(3600.0)))
    add(good_case(name="date-day-carry", tag=2, date_in=(730001, 0, 0), lock_bits=bits64(90000.0)))
    add(good_case(name="date-overflow-latest", tag=0, entries=[(search, rec(0.5, (0x7FFFFFF0, 100, 5)))], lock_bits=bits64(1e9), date_in=(2147473119, 0, 0)))
    add(good_case(name="date-latest-fraction", tag=0, entries=[(search, rec(0.5, (0x7FFFFFF0, 100, 5)))], lock_bits=bits64(1e9), date_in=(2147473118, 86399, 999999999)))
    add(good_case(name="duration-negative", tag=0, lock_bits=bits64(-2.0)))
    add(good_case(name="duration-nan", tag=0, lock_bits=bits64(math.nan)))
    add(good_case(name="duration-huge", tag=0, lock_bits=bits64(2.0 ** 64)))
    add(good_case(name="duration-saturating", tag=0, lock_bits=bits64(9.3e9)))
    add(good_case(name="self-key-ok", search=key_n(2), entries=[(key_n(2), rec(0.9))], avail={key_n(2): 2 * 10 ** 8}))
    add(good_case(name="self-key-slack", search=key_n(2), entries=[(key_n(2), rec(0.2399))], avail={key_n(2): 2 * 10 ** 8}))
    add(good_case(name="self-key-small", search=key_n(2), entries=[(key_n(2), rec(0.25))], avail={key_n(2): 2 * 10 ** 8}))
    add(good_case(name="self-key-bound-edge", search=key_n(2), entries=[(key_n(2), rec(0.3))], avail={key_n(2): 2 * 10 ** 8}))
    add(good_case(name="self-key-mode1", search=key_n(2), mode=1, amount=2 * 10 ** 8, entries=[(key_n(2), rec(0.9))], avail={key_n(2): 3 * 10 ** 8}))
    add(good_case(name="tag0-kind-flag", tag=0, b6=1, locked=10 ** 9))
    add(good_case(name="tag0-over-locked", tag=0, b6=0, locked=5, date_in=(730001, 0, 0)))
    add(good_case(name="tag0-under-locked", tag=0, b6=0, locked=10 ** 9, date_in=(730001, 0, 0)))
    add(good_case(name="tag0-over-locked-small-ratio", tag=0, locked=5, avail={search: 1_000_000}, date_in=(730001, 0, 0)))
    add(good_case(name="log-flag", flag=1, avail={search: 6 * 10 ** 8}))
    twin = search[:16] + bytes([search[16] ^ 1, 0, 0, 0])
    hi = max(search, twin)
    add(good_case(name="key-prefix-collision", search=hi, avail={hi: 2 * 10 ** 8}, entries=sorted([(twin, rec(0.1)), (search, rec(0.5))]), cap=3, head=1))
    add(good_case(name="key-prefix-collision-tree", search=hi, avail={hi: 2 * 10 ** 8}, store="tree", entries=sorted([(twin, rec(0.1)), (search, rec(0.5))])))
    # the address set: sizes around the leaf capacity, and the failure shapes
    for count in (1, 2, 11, 12, 13, 23, 60, 150):
        keys = sorted(key_n(100 + i) for i in range(count))
        height = feasible_heights(len(keys))[-1]
        add(good_case(name="set-%d" % count, tag=2, set_keys=keys, set_len=count, set_height=height, set_seed=7 + count,
                      fees=dict([(key_n(1), 10 ** 9)] + [(k, 3) for k in keys]), date_in=(730001, 0, 0)))
    keys = sorted(key_n(100 + i) for i in range(5))
    add(good_case(name="set-len-too-big", tag=2, set_keys=keys, set_len=9, set_height=0, fees={key_n(1): 10 ** 9}))
    add(good_case(name="set-len-zero", tag=2, set_keys=keys, set_len=0, set_height=0, fees={key_n(1): 10 ** 9}))
    add(good_case(name="set-null-root", tag=2, set_keys=keys, set_len=5, set_height=0, set_root_null=True, fees={key_n(1): 10 ** 9}))
    add(good_case(name="set-short-len", tag=2, set_keys=keys, set_len=2, set_height=0, fees={key_n(1): 10 ** 9, keys[0]: 1, keys[1]: 2, keys[2]: 4}))
    add(good_case(name="set-overflow-up", tag=2, set_keys=keys, set_len=5, set_height=0, fees={key_n(1): I64_MAX - 3, keys[0]: 10, keys[1]: 20}))
    add(good_case(name="set-overflow-down", tag=2, set_keys=keys, set_len=5, set_height=0, fees={key_n(1): I64_MIN + 3, keys[0]: -10, keys[1]: -20}))
    add(good_case(name="set-recovers", tag=2, set_keys=keys, set_len=5, set_height=0, fees={key_n(1): I64_MAX - 3, keys[0]: 10, keys[1]: -I64_MAX}))
    # deep trees reach the unrolled descent loops (height 8 is the smallest that needs them, 9 leaves a remainder)
    for height in (8, 9):
        keys = sorted(key_n(1000 + i) + bytes(0) for i in range(min_items(height)))
        keys = sorted({bytes([(i >> 8) & 0xFF, i & 0xFF]) + key_n(7)[:18] for i in range(min_items(height))})
        add(good_case(name="set-deep-%d" % height, tag=2, set_keys=keys, set_len=len(keys), set_height=height, set_seed=3,
                      fees=dict([(key_n(1), 10 ** 9)] + [(k, 1) for k in keys]), date_in=(730001, 0, 0)))
    # map shapes: deque wrap positions and trees of height 0..2
    for cap_extra, head in ((0, 0), (0, 3), (2, 5), (1, 1)):
        entries = sorted([(key_n(200 + i), rec(0.5)) for i in range(5)] + [(search, rec(0.5))])
        add(good_case(name="deque-%d-%d" % (cap_extra, head), entries=entries, cap=len(entries) + cap_extra, head=head % (len(entries) + cap_extra)))
    for count in (1, 11, 12, 30, 140):
        entries = sorted([(key_n(300 + i), rec(0.5)) for i in range(count - 1)] + [(search, rec(0.5))])
        height = feasible_heights(count)[-1]
        add(good_case(name="map-tree-%d" % count, store="tree", entries=entries, height=height, seed=11 + count))
    return out


def draw_stream(count):
    for case in named_cases():
        yield case
    for case in random_cases(count):
        yield case


# --- wrong readings (each one must be refused by the bytes) ---------------------------------------------------------------------------

VARIANTS = (
    "lock_ignored", "date_strict", "date_reversed", "base_fee_skipped", "set_ignored", "set_wraps", "zero_base_allowed", "prefix_key",
    "tag1_checked", "avail_always", "ratio_cap_ignored", "ratio_floor_ignored", "excess_ignored", "excess_one_million", "avail_ignored",
    "self_path_ignored", "self_path_always", "self_slack_ignored", "self_bound_ten_million", "remaining_ignored", "kind_inverted",
    "kind_floor_zero", "mode_any_nonzero", "mode2_any_nonzero", "locked_lt", "min_left_unsigned", "set_reversed", "ratio_equal_cap",
    "amount_plus_one", "limit_rounded_up",
)




# --- streaming comparison --------------------------------------------------------------------------------------------------------

def digest(outcome, log):
    return hashlib.sha256(repr((outcome, log)).encode()).hexdigest()[:16]


def hexbits(value):
    return "0x%016x" % value


def run_case(harness, case):
    harness.machine.seen = set()
    try:
        _, (got, log) = harness.run(case)
    except (Halt, EvidenceError, IndexError, KeyError, ValueError, OverflowError, struct.error) as problem:
        got, log = ("halt", type(problem).__name__), []
    return got, log


def outcome_name(outcome):
    if outcome[0] == "ok":
        return "ok-kind%d" % outcome[1]
    return "%s-%s" % (outcome[0], ("%#x" % outcome[1]) if outcome[0] == "err" else outcome[1])


def check_stream(harness, cases, k, variants=(), keep=0, hits=None):
    """One real run per case, compared with the rule list and with every named deviation; only the sample rows are kept."""
    stats = {"cases": 0, "mismatches": 0, "first_mismatch": None, "kinds": collections.Counter(), "stores": collections.Counter(),
             "stub_calls": collections.Counter()}
    caught = {name: [0, None] for name in variants}
    rows = []
    for index, case in enumerate(cases):
        got, log = run_case(harness, case)
        expected, expected_log = spec_gate(case, k)
        stats["cases"] += 1
        stats["kinds"][(case.store, case.tag, outcome_name(expected))] += 1
        for entry in expected_log:
            stats["stub_calls"][entry[0]] += 1
        if (got, log) != (expected, expected_log):
            stats["mismatches"] += 1
            if stats["first_mismatch"] is None:
                stats["first_mismatch"] = (index, case.name, got, expected)
        for name in variants:
            if spec_gate(case, k, frozenset((name,))) != (got, log):
                caught[name][0] += 1
                if caught[name][1] is None:
                    caught[name][1] = index
        if hits is not None:
            hits.update(harness.machine.seen)
        if keep and index % keep == 0:
            rows.append((index, case.name, case.store, case.tag, case.mode, len(case.set_keys), len(case.entries), outcome_name(expected),
                         len(log), digest(got, log)))
    return stats, caught, rows


# --- byte level controls ---------------------------------------------------------------------------------------------------------

def mutants_of(image, reached):
    """One edit for every reached conditional jump, immediate and structure field displacement of the subject bodies."""
    out = []
    for entry in (GATE, DEQ):
        start, end = image.exact_fde(entry)
        for row in decode_range(image, start, end):
            if row.va not in reached:
                continue
            data = row.data
            if row.op == "jcc":
                at = 0 if 0x70 <= data[0] <= 0x7F else 1
                out.append((row.va, "condition", row.va + at, data[at], data[at] ^ 1))
                continue
            if row.imm_at is not None and row.imm_size in (1, 4) and row.op not in ("call", "jmp"):
                out.append((row.va, "immediate", row.va + row.imm_at, data[row.imm_at], data[row.imm_at] ^ 1))
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and operand[1] is not None and 0x20 <= abs(operand[4]) < 0x400:
                    disp = operand[4]
                    packed = struct.pack("<i", disp) if abs(disp) >= 128 else struct.pack("<b", disp)
                    spot = bytes(data).find(packed)
                    if spot >= 0 and bytes(data).count(packed) == 1:
                        out.append((row.va, "displacement", row.va + spot, data[spot], data[spot] ^ 8))
    return out


def run_mutants(image, mutants, cases, k):
    rows = []
    expected = [(case, spec_gate(case, k)) for case in cases]
    for va, kind, at, old, new in mutants:
        harness = Harness(image, {at: new})
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        killed, first = False, ""
        for index, (case, want) in enumerate(expected):
            if run_case(harness, case) != want:
                killed, first = True, "%d" % index
                break
        rows.append((va, kind, at, old, new, killed, first))
    return rows


def structural_controls(image, harness, k, cases):
    """Each entry: (name, detected, how)."""
    out = []

    def raises(name, thunk, *errors):
        try:
            thunk()
        except errors or (EvidenceError,) as problem:
            out.append((name, True, type(problem).__name__))
            return
        out.append((name, False, "no error"))

    raises("wrong image digest", lambda: load_image(BINARY, "0" * 64), EvidenceError)
    raises("mid-function address is not an FDE start", lambda: image.exact_fde(GATE + 1), EvidenceError)
    raises("address in a NOBITS section has no file bytes", lambda: image.offset(image.named[".bss"]["address"] + 8), EvidenceError)
    raises("decoder refuses a window that ends inside the body", lambda: decode_range(image, GATE, image.exact_fde(GATE)[1] - 1), EvidenceError)
    raises("truncated section table", lambda: Image(bytes(image.blob[:48])), Exception)

    wide = next(case for case in cases if case.name == "good")
    stripped = Harness(image)
    del stripped.machine.calls[FEE]
    raises("fee helper call without a model", lambda: stripped.run(wide), Halt)
    plain = Harness(image)
    plain.machine.real = frozenset()
    raises("deque search not run as real code", lambda: plain.run(wide), Halt)
    trapped = Harness(image, {GATE: 0xCC})
    raises("entry byte replaced by int3", lambda: trapped.run(wide), Halt)
    for slot in (SLOT_AVAIL, SLOT_MEMCMP, SLOT_OVERFLOW):
        loose = Harness(image)
        del loose.machine.slots[MARK_BASE + slot]
        probe = next(case for case in cases if case.name == {SLOT_AVAIL: "good", SLOT_MEMCMP: "tree-map", SLOT_OVERFLOW: "set-overflow-up"}[slot])
        raises("hook %#x (%s) removed" % (slot, SLOT_NAMES[slot]), lambda: loose.run(probe), Halt)

    def tampered(name, role, value):
        changed = dict(k, **{role: value})
        probes = cases[:600]
        hit = any(run_case(harness, case) != spec_gate(case, changed) for case in probes)
        out.append((name, hit, "mismatch"))

    tampered("tampered minimum base constant", "minimum_base_value", 1.0)
    tampered("tampered minimum ratio constant", "minimum_ratio", 1e-3)
    tampered("tampered self slack factor constant", "self_slack_factor", 0.5)
    tampered("tampered kind floor constant", "kind_floor", 0.5)
    tampered("tampered latest date constant", "latest_date", 2147473119)

    base = next(case for case in cases if case.name == "good")
    out.append(("record fraction byte flipped", run_case(harness, good_case(entries=[(key, record[:7] + bytes([record[7] ^ 1]) + record[8:]) for key, record in base.entries]))
                != spec_gate(base, k), "mismatch"))
    out.append(("search key one byte off", run_case(harness, good_case(search=base.search[:19] + bytes([base.search[19] ^ 1]))) != spec_gate(base, k), "mismatch"))
    return out


# --- evidence tables ---------------------------------------------------------------------------------------------------------------

def constant_rows(image, k):
    refs = collections.defaultdict(list)
    for row in decode_range(image, *image.exact_fde(GATE)):
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] is None and operand[4] in [va for va, _, _ in CONSTANTS]:
                refs[operand[4]].append(row.va)
    rows = []
    for va, role, size in CONSTANTS:
        raw = read_const(image, va, size).hex()
        value = repr(k[role])
        rows.append((hexbits(va), role, size, raw, value, " ".join("%#x" % r for r in refs[va])))
    return rows


def layout_rows(image):
    """Fields of the vault state: every displacement used with the state register (r13) by the body."""
    ops = collections.defaultdict(set)
    for row in decode_range(image, *image.exact_fde(GATE)):
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] == R13 and operand[2] is None:
                ops[operand[4]].add("%s/%d" % (row.op, row.width))
    return [("%#x" % disp, ";".join(sorted(ops[disp]))) for disp in sorted(ops)]


def slot_rows(image):
    rows = []
    for slot, kind, addend, _ in image.relocations():
        if kind == 8 and addend in (GATE, DEQ, FEE):
            section = next((s["name"] for s in image.sections if s["address"] <= slot < s["address"] + s["size"] and s["type"] != 8), "?")
            rows.append((hexbits(slot), "%#x" % addend, section))
    return sorted(rows)


def stub_rows(image):
    """Every call the gate makes: direct targets and indirect slots, with the contract this packet gives the stub."""
    rows = []
    for row in decode_range(image, *image.exact_fde(GATE)):
        if row.op == "call":
            rows.append(("%#x" % row.va, "direct", "%#x" % row.target, "real" if row.target == DEQ else "stub"))
        elif row.op == "calli":
            operand = row.a
            if operand[0] == "m" and operand[1] is None:
                rows.append(("%#x" % row.va, "slot", "%#x" % operand[4], SLOT_NAMES.get(operand[4], "?")))
            else:
                rows.append(("%#x" % row.va, "register", "r13", "memcmp"))
    return rows


def direct_callers(image, targets):
    rows = []
    start_text, text = image.text_bytes()
    for target in targets:
        for at in range(len(text) - 5):
            if text[at] in (0xE8, 0xE9) and start_text + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
                owner = bisect.bisect_right(image.starts, start_text + at) - 1
                rows.append(("%#x" % (start_text + at), "call" if text[at] == 0xE8 else "jmp", "%#x" % target, "%#x" % image.starts[owner]))
    return sorted(rows)


def function_rows(image, hits):
    rows = []
    for entry in (GATE, DEQ):
        start, end = image.exact_fde(entry)
        for row in decode_range(image, start, end):
            rows.append(("%#x" % entry, "%#x" % row.va, row.size, row.op, hits.get(row.va, 0)))
    return rows


def analyse(count=12000, mutate=True, mutant_cases=400):
    image = load_image()
    k = constant_values(image)
    harness = Harness(image)
    named = named_cases()
    cases = list(draw_stream(count))
    reached = collections.Counter()
    stats, caught, sample = check_stream(harness, cases, k, VARIANTS, keep=5, hits=reached)
    result = {"image": image, "k": k, "stats": stats, "caught": caught, "sample": sample, "reached": reached, "cases": len(cases)}
    result["structural"] = structural_controls(image, harness, k, cases)
    result["mutants"] = []
    if mutate:
        picked = cases[:len(named)] + cases[len(named)::max(1, count // mutant_cases)]
        result["mutants"] = run_mutants(image, mutants_of(image, reached), picked, k)
    return result


def render(result):
    image, k, stats = result["image"], result["k"], result["stats"]
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(x) for x in row) for row in rows]) + "\n"

    tsv("constants.tsv", ("address", "role", "bytes", "raw", "value", "referenced_by"), constant_rows(image, k))
    tsv("state-fields.tsv", ("displacement", "accesses"), layout_rows(image))
    tsv("pointer-slots.tsv", ("slot", "addend", "section"), slot_rows(image))
    tsv("call-sites.tsv", ("site", "kind", "target", "role"), stub_rows(image))
    tsv("direct-callers.tsv", ("site", "kind", "target", "owner"), direct_callers(image, (GATE, DEQ)))
    tsv("function-rows.tsv", ("function", "address", "size", "op", "cases_reaching"), function_rows(image, result["reached"]))
    tsv("outcomes.tsv", ("store", "tag", "outcome", "cases"), [(s, t, o, n) for (s, t, o), n in sorted(stats["kinds"].items())])
    tsv("stub-calls.tsv", ("stub", "calls_in_rule_list"), sorted(stats["stub_calls"].items()))
    tsv("cases-sample.tsv", ("index", "name", "store", "tag", "mode", "set_keys", "map_entries", "outcome", "stub_calls", "digest"), result["sample"])
    tsv("variants.tsv", ("deviation", "cases_refused", "first_refusing_case"),
        [(name, n, "" if first is None else first) for name, (n, first) in sorted(result["caught"].items())])
    tsv("structural-controls.tsv", ("control", "detected", "how"), [(n, int(d), h) for n, d, h in result["structural"]])
    tsv("mutants.tsv", ("address", "kind", "edited_byte_at", "old", "new", "killed", "first_case"),
        [("%#x" % va, kind, "%#x" % at, old, new, int(killed), first) for va, kind, at, old, new, killed, first in result["mutants"]])
    equivalent = equivalent_rows(result["mutants"])
    tsv("equivalent-mutants.tsv", ("mutation", "address", "reason"), equivalent)
    unreached = [(hexbits_va, op) for _, hexbits_va, _, op, n in function_rows(image, result["reached"]) if n == 0]
    tsv("unreached.tsv", ("address", "op"), unreached)
    controls = len(result["caught"]) + len(result["structural"]) + len(result["mutants"])
    killed = sum(1 for row in result["mutants"] if row[5])
    detected = sum(1 for n, first in result["caught"].values() if n) + sum(1 for _, d, _ in result["structural"] if d) + killed
    evidence = {
        "binary_sha256": SHA256, "function": "%#x" % GATE, "helpers": {"deque_search": "%#x" % DEQ, "fee_helper": "%#x" % FEE},
        "cases": stats["cases"], "mismatches": stats["mismatches"], "first_mismatch": stats["first_mismatch"],
        "instructions_reached": len(result["reached"]), "mutants": len(result["mutants"]), "mutants_killed": killed,
        "mutants_equivalent": len(equivalent),
    }
    files["evidence.json"] = json.dumps(evidence, indent=1, sort_keys=True, default=str) + "\n"
    files["measure.json"] = json.dumps({"cases": stats["cases"], "negative_controls": controls, "negative_detected": detected,
                                        "equivalent": len(equivalent), "mismatches": stats["mismatches"], "mutants": len(result["mutants"]),
                                        "mutants_killed": killed}, indent=1, sort_keys=True) + "\n"
    return files


def equivalent_rows(mutants):
    return [("%s edit %#x -> %#x" % (kind, old, new), "%#x" % va, EQUIVALENT_REASONS.get(va, "")) for va, kind, at, old, new, killed, _ in mutants
            if not killed]


EQUIVALENT_REASONS = {}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--cases", type=int, default=12000)
    parser.add_argument("--no-mutants", action="store_true")
    args = parser.parse_args(argv)
    result = analyse(args.cases, not args.no_mutants)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = render(result)
    for name, text in files.items():
        (out / name).write_text(text)
    print(files["measure.json"], end="")
    return 0 if result["stats"]["mismatches"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
