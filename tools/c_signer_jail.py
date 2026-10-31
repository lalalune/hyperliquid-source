#!/usr/bin/env python3
"""Pin node #94 cSigner: jailSelf, unjailSelf, voteJail, the stake quorum and the stake-weighted median jail time.

0x3993800 is the action body, 0x398faa0 jails one signer, 0x3992850 is the active signer gate, 0x39416f0 and 0x3597650
test 2/3 of stake over the votes, 0x3bb1c70 and 0x3386c30 build and sort the (time, stake) rows, 0x33a4f60 and 0x33bc340
write the time maps. The real bytes run under recording stubs over real B-tree nodes, a separately written rule list
predicts every run, and every reached conditional row, immediate and field offset is mutated. No objdump or readelf
output is parsed and the binary is never executed. Standard library only.

    python3 tools/c_signer_jail.py --out <dir>
"""

import argparse
import bisect
import datetime
import hashlib
import json
import multiprocessing
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
HEAP_SIZE = 0x80000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
MUTANT_STEP_LIMIT = 60000
WORKERS = 4


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
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
            return finish("movlps", rm, ("x", reg), 8)
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

    def reset(self, used=None):
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
            return (self.statics[addr] & ((1 << 8 * count) - 1)).to_bytes(count, "little")
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
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            value = self.get(row.a, 8)
            product = left * (value - (1 << 64) if value & SIGN[8] else value)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
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
        elif op == "movlps":
            self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
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
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
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


def wrap32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


BODY = 0x3993800
GATE = 0x3992850
JAIL = 0x398FAA0
VOTED = 0x39416F0
QUORUM = 0x3597650
COLLECT = 0x3BB1C70
SORT = 0x3386C30
UPSERT = 0x33A4F60
ENTRY = 0x33BC340
TARGETS = (BODY, GATE, JAIL, VOTED, QUORUM, COLLECT, SORT, UPSERT, ENTRY)
NAMES = {BODY: "c_signer_body", GATE: "active_signer_gate", JAIL: "jail_signer", VOTED: "votes_reach_quorum", QUORUM: "stake_quorum_two_thirds",
         COLLECT: "collect_vote_stakes", SORT: "insertion_sort_vote_rows", UPSERT: "vote_map_upsert", ENTRY: "time_map_entry"}
ENTRIES = (BODY, GATE, JAIL, QUORUM)

SLOT_BODY = 0x57738F8
SLOT_GATE = 0x57738F0
SLOT_COMPARE = 0x576E488
SLOT_VALIDATORS = 0x5775128
SLOT_STATIC = 0x57732E8
SLOT_DRIFT = 0x5776250
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_ONCE = 0x576E8B8
SLOT_UNWRAP = 0x576E470
SLOT_ADD = 0x576E118
SLOT_EXPECT = 0x576E468
SLOT_TIME_ADD = 0x576E8A8
SLOT_DATE_ADD = 0x576E8B0
SLOT_DATE_FROM = 0x576E890
SLOT_QUORUM = 0x5775DB0
ONCE_BODY = 0x577AB98
ONCE_LIST = 0x5786250
LIST_CELL = 0x5786238
CUR = 0x37D9DF0
CUR_ROUND = 0x37D5E10
PROTECTED = 0x3BB4F30
DROP_SET = 0x33F3A90
DROP_STAKES = 0x33F0DA0
DROP_SECOND_ITER = 0x33F2530
DROP_SECOND = 0x33F7BC0
DROP_ROWS = 0x33FC310
TRACKER_INSERT = 0x33C2190
ROW_INSERT = 0x33C2490
CLONE_VOTES = 0x33EB3E0
NEXT_VOTE = 0x33B0F60
VOTER_SET = 0x3BB59C0
SECOND_CHECK = 0x330EAA0
FIRST_KEYS = 0x3BDA450
JVT_REMOVE = 0x33AA7C0
ROW_TAKE = 0x33AAB70
JAILED_REMOVE = 0x33AD2F0
JAILED_INSERT = 0x33A64C0
LEAF_INSERT = 0x2F5F150
GROW = 0x32D6A00
DROP_STATUS = 0x3999770
STATIC_TABLE = 0x58A6B4
STATUS_TABLE = 0x59A8D0
MARK_BASE = 0x7700000000

TAG_OK = 0x186
TAG_UNKNOWN = 0x91
TAG_INACTIVE = 0x95
TAG_ONCE_EVERY = 0x9B
TAG_JAILED_UNTIL = 0x9C
UNJAIL_GAP = 300
EPOCH_DAYS = 719163
TOP = MASK[8]

S_ROUND = 0x30
S_ROUND_ARG = 0x58
S_JVT = 0x88
S_JAILED = 0xD8
S_ALLOWED = 0x120
S_PROFILES = 0x150
S_UNTIL = 0x1B0
S_LAST = 0x1C8
S_ALLOW_ALL = 0x290
S_SIZE = 0x2A0

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
ACTION = HEAP_BASE + 0x300
SIGNER_AT = HEAP_BASE + 0x340
NOW_AT = HEAP_BASE + 0x360
TIME_AT = HEAP_BASE + 0x380
LIST = HEAP_BASE + 0x3A0
LIST_MAIN = HEAP_BASE + 0x3C0
HOLD_STAKES = HEAP_BASE + 0x3E0
HOLD_SET = HEAP_BASE + 0x400
STATE = HEAP_BASE + 0x500
NODES = HEAP_BASE + 0x1000
ARENA = HEAP_BASE + 0x70000
USED = 0x78000
FILL = 0xCC
BASE_DATE = (2026 << 13) | (304 << 4) | 5
CUR_MARK = 0x7100000000
ROUND_MARK = 0x7200000000
LIST_ROOT = 0x7300000000
MAIN_ROOT = 0x7310000000


class Layout:
    def __init__(self, key_size, val_size, val_at, key_at, len_at, edge_at, parent_at, slot_at):
        self.key_size, self.val_size, self.val_at, self.key_at = key_size, val_size, val_at, key_at
        self.len_at, self.edge_at, self.parent_at, self.slot_at = len_at, edge_at, parent_at, slot_at
        self.size = edge_at + 12 * 8


ADDRESS_SET = Layout(20, 0, 0xE8, 8, 0xE6, 0xE8, 0, 0xE4)
TIME_MAP = Layout(20, 12, 0xE4, 8, 0x16A, 0x170, 0, 0x168)
STAKE_MAP = Layout(20, 8, 8, 0x60, 0x13E, 0x140, 0, 0x13C)
TRACKER_MAP = Layout(20, 0x20, 0, 0x168, 0x246, 0x248, 0x160, 0x244)
ROW_MAP = Layout(0, 0x30, 0, 0, 0x21A, 0x220, 0x210, 0x218)
PROFILE_MAP = Layout(20, 0x58, 0, 0x3D0, 0x4AE, 0x4B0, 0x3C8, 0x4AC)


def address_of(index):
    return bytes([0x20 + index]) + bytes((0xA0 + index + at * 5) & 0xFF for at in range(19))


def pack_time(value):
    return struct.pack("<iII", *value)


def date_of(year, ordinal, flags=5):
    return (year << 13) | (ordinal << 4) | flags


def day_number(date):
    return datetime.date(date >> 13, 1, 1).toordinal() + ((date >> 4) & 0x1FF) - 1


def date_at(number):
    day = datetime.date.fromordinal(number)
    return date_of(day.year, day.timetuple().tm_yday)


EPOCH_DATE = date_of(1970, 1)
T0 = (BASE_DATE, 3600, 9)


def later(value, seconds):
    return (value[0], value[1] + seconds, value[2])


class Case:
    FIELDS = dict(mode=3, junk=0, tag=2, signer=1, target=5, until=later(T0, 7200), now=T0, jailed=(), j_shape="leaf", protected=(), main=(), list_null=False, main_null=False,
                  jail_until=(), u_shape="leaf", last=(), l_shape="leaf", cur=True, validators=((1, 100), (2, 100), (3, 100)), v_shape="leaf", v_null=False,
                  jvt=(), t_shape="leaf", fake_len=None, remove_miss=False, take_miss=False, once=0, once_list=0, allow=0, allowed=(), a_shape="leaf", a_len=None, profiles=(), p_shape="leaf", round_row=True,
                  voters=(), no_row_empty_root=False, tall_row=False, carry=0, date_fail=False, s_shape="leaf")

    def __init__(self, name, kind, **fields):
        self.name = name
        self.kind = kind
        for key, value in self.FIELDS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.FIELDS:
                raise EvidenceError("field " + key)
            setattr(self, key, value)


def blank():
    return bytes((index * 7 + 0x40) & 0xFF for index in range(OUT_SIZE))


def carry_rejected(carry):
    """Whole seconds beyond the i32 day count: the host compares carry + 0xffff574000000000 with 0xfffeae7ffffeae81."""
    return ((carry + 0xFFFF574000000000) & TOP) < 0xFFFEAE7FFFFEAE81


class Spec:
    """The rule list, kept apart from the evaluator: plain dictionaries plus the expected event list."""

    def __init__(self, case, where):
        self.case = case
        self.where = where
        self.events = []
        self.until = {address_of(index): value for index, value in case.jail_until}
        self.last = {address_of(index): value for index, value in case.last}
        self.jvt = {}
        for index, word, rows in case.jvt:
            self.jvt[address_of(index)] = [word, None if rows is None else {address_of(voter): value for voter, value in rows}]
        self.stakes = dict(case.validators) if not case.v_null else {}
        self.head = None

    def done(self, tag, time=None):
        self.head = (tag, time)
        return self

    def once(self, cell, value):
        if value:
            self.events.append(("once", cell))

    def static(self):
        self.events.append(("static", self.case.mode))
        if self.case.mode == 0:
            raise Panic("invalid_chain")

    def protected_rows(self, main):
        case = self.case
        null = case.main_null if main else case.list_null
        count = 0 if null else self.where["main_len" if main else "list_len"]
        self.events.append(("protected", int(main and not null), count))
        return set() if null else set(case.main if main else case.protected)

    def stake(self, index):
        return self.stakes[index]

    def add_stakes(self, values):
        total = 0
        for value in values:
            total += value
            if total > TOP:
                raise Panic("add_overflow")
        return total

    def quorum(self, chosen):
        stakes = self.stakes
        total = self.add_stakes(stakes[index] for index in sorted(stakes))
        signed = self.add_stakes(stakes[index] for index in sorted(chosen) if index in stakes)
        if total >> 63 or 3 * signed > TOP:
            return False
        return 3 * signed > 2 * total

    def voted(self, votes):
        self.events.append(("voter_set", len(votes)))
        result = self.quorum({address_index(key) for key in votes})
        self.events.append(("drop_set",))
        self.events.append(("drop_second_iter",))
        return result

    def jail(self, target, time):
        case = self.case
        main = case.mode == 3
        if main:
            self.once(ONCE_LIST, case.once_list)
        else:
            self.static()
        protected = self.protected_rows(main)
        if target in protected:
            for index in sorted(case.jailed):
                if index in protected:
                    self.events.append(("drop_set",))
                    return
        self.once(ONCE_BODY, case.once)
        self.events.append(("jailed_insert", target))
        key = address_of(target)
        if key not in self.until:
            self.events.append(("date_from",))
            if not case.jail_until:
                self.events.append(("alloc", 0x170))
            self.until[key] = (EPOCH_DATE, 0, 0)
        if time is not None and time > self.until[key]:
            self.until[key] = time
        self.events.append(("drop_set",))

    def unjail(self):
        case = self.case
        signer = case.signer
        if signer not in case.jailed:
            return self.done(TAG_OK)
        self.static()
        protected = self.protected_rows(False)
        self.events.append(("drop_set",))
        if signer in protected:
            self.events.append(("jailed_remove", signer))
            return self.done(TAG_OK)
        key = address_of(signer)
        if key in self.until and self.until[key] > case.now:
            return self.done(TAG_JAILED_UNTIL, self.until[key])
        if key not in self.last:
            self.events.append(("date_from",))
            if not case.last:
                self.events.append(("alloc", 0x170))
            self.last[key] = (EPOCH_DATE, 0, 0)
        kept = self.last[key]
        total = kept[1] + UNJAIL_GAP
        days, seconds = divmod(total, 86400)
        carry = days * 86400 + case.carry
        if carry_rejected(carry) or case.date_fail:
            raise Panic("date_overflow")
        whole = abs(carry) // 86400
        allowed = (date_at(day_number(kept[0]) + (whole if carry >= 0 else -whole)), seconds, kept[2])
        if allowed > case.now:
            return self.done(TAG_ONCE_EVERY)
        self.last[key] = case.now
        self.events.append(("jailed_remove", signer))
        return self.done(TAG_OK)

    def vote(self):
        case = self.case
        target, voter = case.target, case.signer
        if not case.cur:
            return self.done(TAG_OK)
        self.events.append(("validators", case.mode))
        self.static()
        protected = self.protected_rows(False)
        if target in protected:
            self.events.append(("drop_set",))
            self.events.append(("drop_stakes",))
            return self.done(TAG_OK)
        key = address_of(target)
        fired = None
        if voter in self.stakes:
            if key not in self.jvt:
                self.events.append(("tracker_insert", target))
                self.jvt[key] = [0x100, None]
            entry = self.jvt[key]
            if entry[1] is None:
                self.events.append(("row_insert",))
                entry[1] = {}
            votes = entry[1]
            voter_key = address_of(voter)
            if entry[0] & 0xFF:
                self.upsert(votes, voter_key)
            else:
                before = self.voted(votes)
                self.upsert(votes, voter_key)
                if not before and self.voted(votes):
                    entry[0] = 1
                    self.events.append(("clone", len(votes)))
                    fired = dict(votes)
        size = len(self.jvt) if case.fake_len is None else case.fake_len + (0 if len(self.jvt) == len(case.jvt) else 1)
        if size >= 0x65:
            size = size if self.jvt else 0
            self.events.append(("first_keys", size, 100))
            if size:
                self.events.append(("free", 8 * min(size, 100)))
        if fired is None:
            self.events.append(("drop_set",))
            self.events.append(("drop_stakes",))
            return self.done(TAG_OK)
        self.events.append(("drop_second",))
        self.events.append(("jvt_remove", target))
        if case.remove_miss:
            self.events.append(("drop_set",))
            self.events.append(("drop_stakes",))
            return self.done(TAG_OK)
        del self.jvt[key]
        self.events.append(("row_take",))
        if case.take_miss:
            self.events.append(("drop_rows",))
            self.events.append(("drop_set",))
            self.events.append(("drop_stakes",))
            return self.done(TAG_OK)
        self.events.append(("drop_second",))
        self.events.append(("drop_rows",))
        rows = []
        for voter_key in sorted(fired):
            if not fired[voter_key][0]:
                break
            if address_index(voter_key) in self.stakes:
                rows.append((fired[voter_key], self.stakes[address_index(voter_key)]))
        capacity = 0
        if rows:
            capacity = 4
            self.events.append(("alloc", 0x60))
            while capacity < len(rows):
                self.events.append(("grow", capacity))
                capacity *= 2
        if len(rows) >= 0x15:
            self.events.append(("drift_sort", len(rows)))
        rows.sort()
        total = self.add_stakes(row[1] for row in rows)
        chosen = None
        running = 0
        for value, stake in rows:
            running = min(TOP, running + stake)
            if running >> 63 or 2 * running >= total:
                chosen = value
                break
        if capacity:
            self.events.append(("rows", tuple(rows)))
            self.events.append(("free", capacity * 0x18))
        if chosen is not None:
            self.jail(target, chosen)
        self.events.append(("drop_set",))
        self.events.append(("drop_stakes",))
        return self.done(TAG_OK)

    def upsert(self, votes, voter_key):
        if not votes:
            self.events.append(("alloc", 0x170))
        votes[voter_key] = self.case.until

    def gate(self):
        case = self.case
        if case.allow:
            self.events.append(("round",))
            self.events.append(("validators", case.mode))
            hit = not case.v_null and case.signer in self.stakes
            self.events.append(("drop_stakes",))
            return int(hit)
        size = case.a_len if case.a_len is not None else len(case.allowed)
        if not case.allowed or not size:
            return 0
        wanted = address_of(case.signer)
        profiles = dict(case.profiles)
        for index in sorted(case.allowed)[:size]:
            self.events.append(("drop_status", TAG_UNKNOWN))
            if index in profiles and address_of(profiles[index]) == wanted:
                return 1
        return 0


class Panic(Exception):
    pass


def address_index(key):
    return key[0] - 0x20


def spec_run(case, where):
    spec = Spec(case, where)
    try:
        if case.kind == BODY:
            spec.once(ONCE_BODY, case.once)
            if case.tag == 0:
                spec.unjail()
            elif case.tag == 1:
                spec.jail(case.signer, None)
                spec.done(TAG_OK)
            else:
                spec.vote()
            return "done", spec.head, tuple(spec.events), snapshot_of(spec)
        if case.kind == JAIL:
            spec.jail(case.target, None if case.until is None else case.until)
            return "value", None, tuple(spec.events), snapshot_of(spec)
        if case.kind == GATE:
            return "value", spec.gate(), tuple(spec.events), snapshot_of(spec)
        return "value", int(spec.quorum(set(case.voters))), tuple(spec.events), snapshot_of(spec)
    except Panic as stop:
        return "panic", stop.args[0], tuple(spec.events)


def snapshot_of(spec):
    jvt = []
    for key in sorted(spec.jvt):
        word, rows = spec.jvt[key]
        jvt.append((key, word, None if rows is None else tuple(sorted(rows.items()))))
    return tuple(sorted(spec.until.items())), tuple(sorted(spec.last.items())), tuple(jvt), spec.where["frozen"]


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((JAIL, VOTED, QUORUM, COLLECT, SORT, UPSERT, ENTRY, SECOND_CHECK))
        statics = machine.memory.statics
        statics[ONCE_BODY] = 0
        statics[ONCE_LIST] = 0
        hooks = {SLOT_COMPARE: self.on_compare, SLOT_VALIDATORS: self.on_validators, SLOT_STATIC: self.on_static, SLOT_DRIFT: self.on_drift, SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_ALLOC_FAIL: self.on_stop,
                 SLOT_ONCE: self.on_once, SLOT_UNWRAP: self.on_stop, SLOT_ADD: self.on_add, SLOT_EXPECT: self.on_expect, SLOT_TIME_ADD: self.on_time_add, SLOT_DATE_ADD: self.on_date_add, SLOT_DATE_FROM: self.on_date_from}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        statics[SLOT_QUORUM] = QUORUM
        machine.calls = {CUR: self.on_cur, CUR_ROUND: self.on_round, PROTECTED: self.on_protected, DROP_SET: self.on_drop_set, DROP_STAKES: self.on_drop_stakes, DROP_SECOND_ITER: self.on_drop_second_iter, DROP_SECOND: self.on_drop_second, DROP_ROWS: self.on_drop_rows,
                         TRACKER_INSERT: self.on_tracker, ROW_INSERT: self.on_row, CLONE_VOTES: self.on_clone, NEXT_VOTE: self.on_next, VOTER_SET: self.on_voter_set, FIRST_KEYS: self.on_first_keys, JVT_REMOVE: self.on_jvt_remove, ROW_TAKE: self.on_row_take,
                         JAILED_REMOVE: self.on_jailed_remove, JAILED_INSERT: self.on_jailed_insert, LEAF_INSERT: self.on_leaf, GROW: self.on_grow, DROP_STATUS: self.on_drop_status}
        self.events = []
        self.case = None
        self.where = None
        self.next_node = NODES
        self.arena = ARENA
        self.removed = set()

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def bytes_at(self, addr, size):
        return self.machine.memory.bytes_at(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def on_compare(self, machine):
        regs = machine.regs
        size = regs[RDX]
        self.expect(size == 20, "compare length")
        left, right = self.bytes_at(regs[RDI], size), self.bytes_at(regs[RSI], size)
        result = 0 if left == right else 0x1234 if left > right else -0x1234
        regs[RAX] = (0x5A5A5A5A << 32) | result & MASK[4]

    def on_cur(self, machine):
        self.expect(machine.regs[RDI] == STATE, "current state pointer")
        machine.regs[RAX] = CUR_MARK if self.case.cur else 0

    def on_round(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + S_ROUND and regs[RSI] == self.read(STATE + S_ROUND_ARG), "round arguments")
        self.events.append(("round",))
        regs[RAX] = 1 if self.case.round_row else 0
        regs[RDX] = ROUND_MARK
        machine.keep_rdx = True

    def on_validators(self, machine):
        regs = machine.regs
        case = self.case
        wanted = (ROUND_MARK if case.round_row else STATE) if case.kind == GATE else CUR_MARK
        self.expect(regs[RSI] == wanted and regs[RCX] == STATE, "validators arguments")
        self.expect(regs[RDX] & 0xFF == case.mode, "validators chain")
        self.events.append(("validators", regs[RDX] & 0xFF))
        out = regs[RDI]
        self.word(out, self.where["v_root"])
        self.word(out + 8, self.where["v_height"])
        self.word(out + 0x10, len(case.validators))

    def on_static(self, machine):
        mode = machine.regs[RDI] & 0xFF
        self.events.append(("static", mode))
        if mode == 0:
            raise Panicked("invalid_chain")
        self.expect(mode == self.case.mode, "static chain")
        machine.regs[RAX] = LIST

    def on_protected(self, machine):
        regs = machine.regs
        out, it = regs[RDI], regs[RSI]
        root = self.read(it + 0x10)
        main = root == MAIN_ROOT
        case = self.case
        size = self.read(it + 0x40)
        self.expect(self.read(it + 0x48) == STATE, "protected state")
        if root == 0:
            self.expect(self.read(it) == 0, "empty list flag")
            size = 0
        else:
            self.expect(self.read(it) == 1 and self.read(it + 0x20) == 1 and self.read(it + 0x30) == root and self.read(it + 8) == 0 and self.read(it + 0x28) == 0, "list iterator")
            self.expect(self.read(it + 0x18) == self.read(it + 0x38), "list height")
            self.expect(self.read(it + 0x18) == self.read((LIST_MAIN if main else LIST) + 8), "list height value")
        self.events.append(("protected", int(main), size))
        keys = () if root == 0 else case.main if main else case.protected
        self.write_set(out, keys, "leaf" if len(keys) < 3 else "split")

    def write_set(self, holder, indexes, shape):
        if not indexes:
            self.word(holder, 0)
            self.word(holder + 8, 0xB0B0)
            self.word(holder + 0x10, 0)
            return
        root, height, _ = self.tree(ADDRESS_SET, [(address_of(index), b"") for index in indexes], shape, address_of(indexes[0]))
        self.word(holder, root)
        self.word(holder + 8, height)
        self.word(holder + 0x10, len(indexes))

    def on_drop_set(self, machine):
        self.events.append(("drop_set",))

    def on_drop_stakes(self, machine):
        self.events.append(("drop_stakes",))

    def on_drop_second_iter(self, machine):
        self.events.append(("drop_second_iter",))

    def on_drop_second(self, machine):
        self.events.append(("drop_second",))

    def on_drop_rows(self, machine):
        self.events.append(("drop_rows",))

    def on_drop_status(self, machine):
        self.events.append(("drop_status", self.read(machine.regs[RDI], 2)))

    def allocate(self, size):
        at = self.arena
        self.arena += (size + 15) & ~15
        self.expect(self.arena < HEAP_BASE + USED, "arena")
        self.machine.memory.put_bytes(at, bytes([FILL]) * size)
        return at

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        self.events.append(("alloc", size))
        machine.regs[RAX] = self.allocate(size)

    def on_free(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] & MASK[4] == 0 and regs[RSI], "free size")
        if regs[RSI] % 0x18 == 0 and regs[RDI] >= ARENA:
            rows = []
            for at in range(regs[RSI] // 0x18):
                row = self.bytes_at(regs[RDI] + 0x18 * at, 0x18)
                if row[:4] == bytes([FILL]) * 4:
                    break
                rows.append((struct.unpack_from("<iII", row), struct.unpack_from("<Q", row, 0x10)[0]))
            self.events.append(("rows", tuple(rows)))
        self.events.append(("free", regs[RSI]))

    def on_stop(self, machine):
        raise Panicked("unwrap")

    def on_once(self, machine):
        self.events.append(("once", machine.regs[RDI]))

    def on_add(self, machine):
        raise Panicked("add_overflow")

    def on_expect(self, machine):
        self.expect(machine.regs[RSI] == 0x26, "panic text size")
        self.expect(self.bytes_at(machine.regs[RDI], 0x26) == b"`NaiveDateTime + TimeDelta` overflowed", "panic text")
        raise Panicked("date_overflow")

    def on_time_add(self, machine):
        regs = machine.regs
        seconds, frac = self.read(regs[RSI], 4), self.read(regs[RSI] + 4, 4)
        self.expect(regs[RCX] & MASK[4] == 0, "time delta nanos")
        total = seconds + wrap32(regs[RDX])
        days, kept = divmod(total, 86400)
        out = regs[RDI]
        self.word(out, kept, 4)
        self.word(out + 4, frac, 4)
        self.word(out + 8, (days * 86400 + self.case.carry) & MASK[8])

    def on_date_add(self, machine):
        regs = machine.regs
        if self.case.date_fail:
            regs[RAX] = 0
            return
        regs[RAX] = date_at(day_number(wrap32(regs[RDI])) + wrap32(regs[RSI]))

    def on_date_from(self, machine):
        self.expect(machine.regs[RDI] & MASK[4] == EPOCH_DAYS, "unix epoch day")
        self.events.append(("date_from",))
        machine.regs[RAX] = EPOCH_DATE

    def on_drift(self, machine):
        regs = machine.regs
        base, count = regs[RDI], regs[RSI]
        self.events.append(("drift_sort", count))
        rows = [self.bytes_at(base + 0x18 * at, 0x18) for at in range(count)]

        def order(row):
            date, seconds, frac = struct.unpack_from("<iII", row)
            return date, seconds, frac, struct.unpack_from("<Q", row, 0x10)[0]
        rows.sort(key=order)
        for at, row in enumerate(rows):
            self.machine.memory.put_bytes(base + 0x18 * at, row)

    def on_grow(self, machine):
        regs = machine.regs
        vec, length = regs[RDI], regs[RSI]
        self.expect(regs[RDX] == 1 and regs[RCX] == 8 and regs[R8] == 0x18, "grow arguments")
        capacity = self.read(vec)
        self.expect(length == capacity, "grow length")
        self.events.append(("grow", capacity))
        fresh = self.allocate(capacity * 2 * 0x18)
        self.machine.memory.put_bytes(fresh, self.bytes_at(self.read(vec + 8), length * 0x18))
        self.word(vec, capacity * 2)
        self.word(vec + 8, fresh)

    def rows(self, layout, root, height):
        """In-order rows of one real tree: (key, value) byte pairs."""
        found = []
        if not root:
            return found
        count = self.read(root + layout.len_at, 2)
        self.expect(count <= 11, "node length")
        for at in range(count):
            if height:
                found.extend(self.rows(layout, self.read(root + layout.edge_at + 8 * at), height - 1))
            found.append((self.bytes_at(root + layout.key_at + layout.key_size * at, layout.key_size) if layout.key_size else b"", root + layout.val_at + layout.val_size * at))
        if height:
            found.extend(self.rows(layout, self.read(root + layout.edge_at + 8 * count), height - 1))
        return found

    def on_next(self, machine):
        regs = machine.regs
        out, it = regs[RDI], regs[RSI]
        left = self.read(it + 0x40)
        if not left:
            self.word(out, 0)
            return
        root, height = self.read(it + 0x10), self.read(it + 0x18)
        self.expect(self.read(it) == 1 and self.read(it + 0x20) == 1 and self.read(it + 0x30) == root and self.read(it + 0x38) == height, "vote iterator")
        rows = self.rows(TIME_MAP, root, height)
        self.expect(left <= len(rows), "vote iterator length")
        spot = rows[len(rows) - left]
        self.word(it + 0x40, left - 1)
        node, index = self.locate_row(root, height, spot[0])
        self.word(out, node)
        self.word(out + 8, 0)
        self.word(out + 0x10, index)

    def locate_row(self, root, height, key):
        count = self.read(root + TIME_MAP.len_at, 2)
        for at in range(count):
            found = self.bytes_at(root + TIME_MAP.key_at + 20 * at, 20)
            if found == key:
                return root, at
            if found > key and height:
                return self.locate_row(self.read(root + TIME_MAP.edge_at + 8 * at), height - 1, key)
        return self.locate_row(self.read(root + TIME_MAP.edge_at + 8 * count), height - 1, key)

    def on_voter_set(self, machine):
        regs = machine.regs
        out, it = regs[RDI], regs[RSI]
        root, height, size = self.read(it + 0x10), self.read(it + 0x18), self.read(it + 0x40)
        self.expect(self.read(it) == int(root != 0) and self.read(it + 0x20) == int(root != 0) and self.read(it + 0x30) == root and self.read(it + 0x38) == height and self.read(it + 8) == 0 and self.read(it + 0x28) == 0, "voter iterator")
        rows = self.rows(TIME_MAP, root, height)
        self.expect(len(rows) == size, "voter iterator length")
        self.events.append(("voter_set", size))
        items = [(key, b"") for key, _ in rows]
        if not items:
            self.word(out, 0)
            self.word(out + 8, 0xB0B0)
            self.word(out + 0x10, 0)
            return
        base, tall, _ = self.tree(ADDRESS_SET, items, "leaf" if len(items) < 3 else "split", items[0][0])
        self.word(out, base)
        self.word(out + 8, tall)
        self.word(out + 0x10, len(items))

    def on_clone(self, machine):
        regs = machine.regs
        root, height, out = regs[RSI], regs[RDX], regs[RDI]
        rows = self.rows(TIME_MAP, root, height)
        self.events.append(("clone", len(rows)))
        self.word(out, root)
        self.word(out + 8, height)
        self.word(out + 0x10, len(rows))

    def on_first_keys(self, machine):
        regs = machine.regs
        out, it = regs[RDI], regs[RSI]
        size, take = self.read(it + 0x40), self.read(it + 0x48)
        self.expect(self.read(it + 0x10) == self.read(STATE + S_JVT) and self.read(it + 0x18) == self.read(STATE + S_JVT + 8), "first keys root")
        self.events.append(("first_keys", size, take))
        self.word(out, min(size, take))
        self.word(out + 8, self.allocate(8 * min(size, take)))
        self.word(out + 0x10, min(size, take))

    def on_jvt_remove(self, machine):
        regs = machine.regs
        out, holder, key_at = regs[RDI], regs[RSI], regs[RDX]
        self.expect(holder == STATE + S_JVT, "jvt remove holder")
        key = self.bytes_at(key_at, 20)
        self.events.append(("jvt_remove", address_index(key)))
        if self.case.remove_miss:
            self.word(out + 0x19, 2, 1)
            return
        for found, spot in self.rows(TRACKER_MAP, self.read(holder), self.read(holder + 8)):
            if found == key:
                self.machine.memory.put_bytes(out, self.bytes_at(spot, 0x20))
                self.removed.add(key)
                self.word(holder + 0x10, self.read(holder + 0x10) - 1)
                return
        raise Halt("jvt remove missed")

    def on_row_take(self, machine):
        regs = machine.regs
        out, holder = regs[RDI], regs[RSI]
        self.expect(regs[RDX] == 1, "row take count")
        self.events.append(("row_take",))
        if self.case.take_miss:
            self.word(out, 0, 4)
            return
        rows = self.rows(ROW_MAP, self.read(holder), self.read(holder + 8))
        self.word(out, 1, 4)
        self.machine.memory.put_bytes(out + 8, self.bytes_at(rows[0][1], 0x30))

    def on_jailed_remove(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + S_JAILED, "jailed holder")
        self.events.append(("jailed_remove", address_index(self.bytes_at(regs[RSI], 20))))

    def on_jailed_insert(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + S_JAILED, "jailed holder")
        self.events.append(("jailed_insert", address_index(self.bytes_at(regs[RSI], 20))))

    def on_leaf(self, machine):
        regs = machine.regs
        out, handle, key_at, value_at = regs[RDI], regs[RSI], regs[RDX], regs[RCX]
        node, height, index = self.read(handle), self.read(handle + 8), self.read(handle + 0x10)
        self.expect(height == 0, "leaf handle")
        self.insert_row(TIME_MAP, node, index, self.bytes_at(key_at, 20), self.bytes_at(value_at, 12))
        self.word(out, node)
        self.word(out + 8, 0)
        self.word(out + 0x10, index)

    def insert_row(self, layout, node, index, key, value):
        count = self.read(node + layout.len_at, 2)
        self.expect(count < 11 and index <= count, "leaf room")
        memory = self.machine.memory
        for at in range(count, index, -1):
            memory.put_bytes(node + layout.key_at + layout.key_size * at, self.bytes_at(node + layout.key_at + layout.key_size * (at - 1), layout.key_size))
            memory.put_bytes(node + layout.val_at + layout.val_size * at, self.bytes_at(node + layout.val_at + layout.val_size * (at - 1), layout.val_size))
        memory.put_bytes(node + layout.key_at + layout.key_size * index, key)
        memory.put_bytes(node + layout.val_at + layout.val_size * index, value)
        self.word(node + layout.len_at, count + 1, 2)

    def on_tracker(self, machine):
        regs = machine.regs
        out, entry, value_at = regs[RDI], regs[RSI], regs[RDX]
        holder, node, height, index = self.read(entry), self.read(entry + 8), self.read(entry + 0x10), self.read(entry + 0x18)
        self.expect(holder == STATE + S_JVT, "tracker holder")
        key = self.bytes_at(entry + 0x20, 20)
        self.events.append(("tracker_insert", address_index(key)))
        value = self.bytes_at(value_at, 0x20)
        if node == 0:
            node = self.empty_node(TRACKER_MAP)
            index = 0
            self.word(holder, node)
            self.word(holder + 8, 0)
        self.insert_row(TRACKER_MAP, node, index, key, value)
        self.word(holder + 0x10, self.read(holder + 0x10) + 1)
        self.word(out, node)
        self.word(out + 8, height)
        self.word(out + 0x10, index)

    def on_row(self, machine):
        regs = machine.regs
        out, entry, value_at = regs[RDI], regs[RSI], regs[RDX]
        holder, node = self.read(entry), self.read(entry + 8)
        self.events.append(("row_insert",))
        value = self.bytes_at(value_at, 0x30)
        if node == 0:
            node = self.empty_node(ROW_MAP)
            self.word(holder, node)
            self.word(holder + 8, 0)
        self.insert_row(ROW_MAP, node, 0, b"", value)
        self.word(holder + 0x10, self.read(holder + 0x10) + 1)
        self.word(out, node)
        self.word(out + 8, 0)
        self.word(out + 0x10, 0)

    def empty_node(self, layout):
        base, _ = self.node(layout, (), (), bytes(layout.key_size))
        return base

    def node(self, layout, items, children, stale_key, parent=0, slot=0):
        base = self.next_node
        self.next_node += layout.size + 0x10
        self.expect(self.next_node < ARENA, "node area")
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * (layout.size + 0x10))
        spots = {}
        for at in range(11):
            key, value = items[at] if at < len(items) else (stale_key, b"\xFF" * layout.val_size)
            if layout.key_size:
                memory.put_bytes(base + layout.key_at + layout.key_size * at, key)
            if layout.val_size:
                memory.put_bytes(base + layout.val_at + layout.val_size * at, value)
            if at < len(items):
                spots[key] = base + layout.val_at + layout.val_size * at
        self.word(base + layout.len_at, len(items), 2)
        self.word(base + layout.parent_at, parent)
        self.word(base + layout.slot_at, slot, 2)
        for at, child in enumerate(children):
            self.word(base + layout.edge_at + 8 * at, child)
        return base, spots

    def link(self, layout, parent, children):
        for slot, child in enumerate(children):
            self.word(child + layout.parent_at, parent)
            self.word(child + layout.slot_at, slot, 2)

    def tree(self, layout, items, shape, stale_key):
        items = sorted(items)
        if shape == "leaf":
            base, spots = self.node(layout, items, (), stale_key)
            return base, 0, spots
        if shape == "tall":
            return self.tall(layout, items, stale_key)
        half = len(items) // 2
        left, one = self.node(layout, items[:half], (), stale_key)
        right, two = self.node(layout, items[half + 1:], (), stale_key)
        base, spots = self.node(layout, items[half:half + 1], (left, right), stale_key)
        self.link(layout, base, (left, right))
        spots.update(one)
        spots.update(two)
        return base, 1, spots

    def tall(self, layout, items, stale):
        """Height 2: four leaves, two inner nodes and a root, for at least 7 rows."""
        size = len(items)
        cuts = [size * part // 4 for part in (1, 2, 3)]
        spans = ((0, cuts[0]), (cuts[0] + 1, cuts[1]), (cuts[1] + 1, cuts[2]), (cuts[2] + 1, size))
        spots = {}
        leaves = []
        for low, high in spans:
            base, found = self.node(layout, items[low:high], (), stale)
            leaves.append(base)
            spots.update(found)
        low, one = self.node(layout, items[cuts[0]:cuts[0] + 1], leaves[:2], stale)
        high, two = self.node(layout, items[cuts[2]:cuts[2] + 1], leaves[2:], stale)
        root, three = self.node(layout, items[cuts[1]:cuts[1] + 1], (low, high), stale)
        self.link(layout, low, leaves[:2])
        self.link(layout, high, leaves[2:])
        self.link(layout, root, (low, high))
        spots.update(one)
        spots.update(two)
        spots.update(three)
        return root, 2, spots

    def holder(self, at, layout, pairs, shape):
        items = [(address_of(index), pack_time(value)) for index, value in pairs]
        if not items:
            self.word(at, 0)
            self.word(at + 8, 0xB1B1)
            self.word(at + 0x10, 0)
            return
        root, height, _ = self.tree(layout, items, shape, address_of(pairs[0][0]))
        self.word(at, root)
        self.word(at + 8, height)
        self.word(at + 0x10, len(items))

    def tracker_value(self, word, rows):
        data = bytearray(0x20)
        struct.pack_into("<H", data, 0x18, word)
        data[0x1A:0x20] = bytes(range(0x61, 0x67))
        data[8:0x10] = b"\xB2" * 8
        if rows is None:
            if self.case.no_row_empty_root:
                empty, _ = self.node(ROW_MAP, (), (), b"")
                struct.pack_into("<QQQ", data, 0, empty, 0, 0)
            return bytes(data)
        votes = bytearray(0x30)
        votes[8:0x10] = b"\xB3" * 8
        if rows:
            root, height, _ = self.tree(TIME_MAP, [(address_of(index), pack_time(value)) for index, value in rows], "leaf" if len(rows) <= 9 else "split", address_of(rows[0][0]))
            struct.pack_into("<QQQ", votes, 0, root, height, len(rows))
        leaf, _ = self.node(ROW_MAP, ((b"", bytes(votes)),), (), b"")
        if self.case.tall_row:
            top, _ = self.node(ROW_MAP, (), (leaf,), b"")
            self.link(ROW_MAP, top, (leaf,))
            struct.pack_into("<QQQ", data, 0, top, 1, 1)
        else:
            struct.pack_into("<QQQ", data, 0, leaf, 0, 1)
        return bytes(data)

    def staking(self, case, where):
        memory = self.machine.memory
        memory.put_bytes(STATE, bytes((index * 5 + 0x11) & 0xFF for index in range(S_SIZE)))
        self.word(STATE + S_ALLOW_ALL, case.allow, 1)
        self.holder(STATE + S_UNTIL, TIME_MAP, case.jail_until, case.u_shape)
        self.holder(STATE + S_LAST, TIME_MAP, case.last, case.l_shape)
        self.write_set(STATE + S_JAILED, case.jailed, case.j_shape)
        if case.allowed:
            self.write_set(STATE + S_ALLOWED, case.allowed, case.a_shape)
            if case.a_len is not None:
                self.word(STATE + S_ALLOWED + 0x10, case.a_len)
        else:
            self.word(STATE + S_ALLOWED, 0)
            self.word(STATE + S_ALLOWED + 0x10, 0 if case.a_len is None else case.a_len)
        if case.profiles:
            items = []
            for index, signer in case.profiles:
                value = bytearray(bytes((0x31 + index + at) & 0xFF for at in range(0x58)))
                value[0x40:0x54] = address_of(signer)
                items.append((address_of(index), bytes(value)))
            root, height, _ = self.tree(PROFILE_MAP, items, case.p_shape, items[0][0])
            self.word(STATE + S_PROFILES, root)
            self.word(STATE + S_PROFILES + 8, height)
        else:
            self.word(STATE + S_PROFILES, 0)
        if case.jvt:
            items = [(address_of(index), self.tracker_value(word, rows)) for index, word, rows in case.jvt]
            root, height, _ = self.tree(TRACKER_MAP, items, case.t_shape, items[0][0])
            self.word(STATE + S_JVT, root)
            self.word(STATE + S_JVT + 8, height)
            self.word(STATE + S_JVT + 0x10, len(items) if case.fake_len is None else case.fake_len)
        else:
            self.word(STATE + S_JVT, 0)
            self.word(STATE + S_JVT + 8, 0xB4B4)
            self.word(STATE + S_JVT + 0x10, 0 if case.fake_len is None else case.fake_len)
        if case.validators and not case.v_null:
            root, height, _ = self.tree(STAKE_MAP, [(address_of(index), struct.pack("<Q", stake)) for index, stake in case.validators], case.v_shape, address_of(case.validators[0][0]))
        else:
            root, height = 0, 0xB5B5
        where["v_root"], where["v_height"] = root, height

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(HEAP_BASE, bytes([FILL]) * 0x1000)
        memory.put_bytes(OUT, blank())
        statics = memory.statics
        statics[ONCE_BODY] = case.once
        statics[ONCE_LIST] = case.once_list
        where = {}
        self.next_node = NODES
        self.arena = ARENA
        self.events = []
        self.case = case
        self.where = where
        self.removed = set()
        self.staking(case, where)
        self.word(ACTION, case.tag, 1)
        memory.put_bytes(ACTION + 1, address_of(case.target))
        for at in range(0x15, 0x18):
            self.word(ACTION + at, 0xE0 + at, 1)
        if case.until is None:
            memory.put_bytes(ACTION + 0x18, bytes(12))
        else:
            memory.put_bytes(ACTION + 0x18, pack_time(case.until))
        memory.put_bytes(TIME_AT, memory.bytes_at(ACTION + 0x18, 12))
        memory.put_bytes(SIGNER_AT, address_of(case.signer))
        memory.put_bytes(NOW_AT, pack_time(case.now))
        where["list_len"] = 0 if case.list_null else 7
        where["main_len"] = 0 if case.main_null else 9
        self.word(LIST, 0 if case.list_null else LIST_ROOT)
        self.word(LIST + 8, 3)
        self.word(LIST + 0x10, 7)
        statics[LIST_CELL] = 0 if case.main_null else MAIN_ROOT
        statics[LIST_CELL + 8] = 2 | 9 << 64
        self.word(LIST_MAIN + 8, 2)
        if case.kind == QUORUM:
            self.word(HOLD_STAKES, where["v_root"])
            self.word(HOLD_STAKES + 8, where["v_height"])
            self.word(HOLD_STAKES + 0x10, len(case.validators))
            self.write_set(HOLD_SET, case.voters, case.s_shape)
        where["frozen"] = hashlib.sha256(self.frozen()).hexdigest()

    def frozen(self):
        """Everything the path must leave alone: the action, its inputs and the state words outside the maps it edits."""
        data = bytearray(self.bytes_at(STATE, S_SIZE))
        for field in (S_JVT, S_UNTIL, S_LAST):
            data[field:field + 0x18] = bytes(0x18)
        return bytes(data) + self.bytes_at(ACTION, 0x24) + self.bytes_at(SIGNER_AT, 20) + self.bytes_at(NOW_AT, 12)

    def state(self):
        until = tuple((key, struct.unpack("<iII", self.bytes_at(spot, 12))) for key, spot in self.rows(TIME_MAP, self.read(STATE + S_UNTIL), self.read(STATE + S_UNTIL + 8)))
        last = tuple((key, struct.unpack("<iII", self.bytes_at(spot, 12))) for key, spot in self.rows(TIME_MAP, self.read(STATE + S_LAST), self.read(STATE + S_LAST + 8)))
        self.expect(self.read(STATE + S_UNTIL + 0x10) == len(until) and self.read(STATE + S_LAST + 0x10) == len(last), "time map length")
        jvt = []
        for key, spot in self.rows(TRACKER_MAP, self.read(STATE + S_JVT), self.read(STATE + S_JVT + 8)):
            if key in self.removed:
                continue
            root, height, size = self.read(spot), self.read(spot + 8), self.read(spot + 0x10)
            word = self.read(spot + 0x18, 2)
            rows = self.rows(ROW_MAP, root, height) if size else []
            if not rows:
                jvt.append((key, word, None))
                continue
            self.expect(len(rows) == 1, "one vote row")
            at = rows[0][1]
            votes = tuple((voter, struct.unpack("<iII", self.bytes_at(place, 12))) for voter, place in self.rows(TIME_MAP, self.read(at), self.read(at + 8)))
            self.expect(self.read(at + 0x10) == len(votes), "vote length")
            jvt.append((key, word, votes))
        return until, last, tuple(jvt), hashlib.sha256(self.frozen()).hexdigest()

    def run(self, case):
        self.fresh(case)
        junk = case.junk << 8
        try:
            if case.kind == BODY:
                self.machine.run(BODY, {RDI: OUT, RSI: STATE, RDX: case.mode | junk, RCX: NOW_AT, R8: SIGNER_AT, R9: ACTION})
                raw = self.bytes_at(OUT, OUT_SIZE)
                tag = struct.unpack_from("<H", raw)[0]
                time = None
                expected = bytearray(blank())
                expected[0:2] = raw[0:2]
                if tag == TAG_JAILED_UNTIL:
                    time = struct.unpack_from("<iII", raw, 4)
                    expected[4:16] = raw[4:16]
                if raw != bytes(expected):
                    raise Halt("result bytes outside the status")
                return "done", (tag, time), tuple(self.events), self.state()
            if case.kind == JAIL:
                self.machine.run(JAIL, {RDI: STATE, RSI: case.mode | junk, RDX: ACTION + 1, RCX: TIME_AT})
                return "value", None, tuple(self.events), self.state()
            if case.kind == GATE:
                got = self.machine.run(GATE, {RDI: STATE, RSI: case.mode | junk, RDX: SIGNER_AT})
                return "value", got & 0xFF, tuple(self.events), self.state()
            got = self.machine.run(QUORUM, {RDI: HOLD_STAKES, RSI: HOLD_SET})
            return "value", got & 0xFF, tuple(self.events), self.state()
        except Panicked as stop:
            return "panic", stop.args[0], tuple(self.events)



LATE = later(T0, 7200)
THREE = ((1, 100), (2, 100), (3, 100))
MANY = tuple(range(1, 16))
TIMES = tuple(later(T0, 60 * at) for at in range(40))


def unjail_cases():
    rows = [("unjail_not_jailed", dict()), ("unjail_other_jailed", dict(jailed=(2,))), ("unjail_plain", dict(jailed=(1,))), ("unjail_list_null", dict(jailed=(1,), list_null=True)),
            ("unjail_protected_skips_time", dict(jailed=(1,), protected=(1,), jail_until=((1, later(T0, 900)),), last=((1, T0),))), ("unjail_protected_other", dict(jailed=(1,), protected=(2,))),
            ("unjail_until_later_day", dict(jailed=(1,), jail_until=((1, (BASE_DATE + 16, 1, 1)),))), ("unjail_until_earlier_day", dict(jailed=(1,), jail_until=((1, (BASE_DATE - 16, 80000, 800)),))),
            ("unjail_until_later_second", dict(jailed=(1,), jail_until=((1, later(T0, 1)),))), ("unjail_until_earlier_second", dict(jailed=(1,), jail_until=((1, (BASE_DATE, 3599, 900)),))),
            ("unjail_until_later_frac", dict(jailed=(1,), jail_until=((1, (BASE_DATE, 3600, 10)),))), ("unjail_until_earlier_frac", dict(jailed=(1,), jail_until=((1, (BASE_DATE, 3600, 8)),))), ("unjail_until_equal", dict(jailed=(1,), jail_until=((1, T0),))),
            ("unjail_until_negative_date", dict(jailed=(1,), jail_until=((1, (-(5 << 13), 0, 0)),))), ("unjail_until_other_row", dict(jailed=(1,), jail_until=((2, later(T0, 900)),))),
            ("unjail_last_299", dict(jailed=(1,), last=((1, later(T0, -299)),))), ("unjail_last_300", dict(jailed=(1,), last=((1, later(T0, -300)),))), ("unjail_last_301", dict(jailed=(1,), last=((1, later(T0, -301)),))),
            ("unjail_last_frac_above", dict(jailed=(1,), last=((1, (BASE_DATE, 3300, 10)),))), ("unjail_last_frac_below", dict(jailed=(1,), last=((1, (BASE_DATE, 3300, 8)),))),
            ("unjail_last_next_day_blocks", dict(jailed=(1,), now=(BASE_DATE + 16, 100, 0), last=((1, (BASE_DATE, 86300, 0)),))), ("unjail_last_next_day_passes", dict(jailed=(1,), now=(BASE_DATE + 16, 200, 0), last=((1, (BASE_DATE, 86300, 0)),))),
            ("unjail_last_far_past", dict(jailed=(1,), last=((1, (BASE_DATE - 16 * 40, 5, 5)),))), ("unjail_last_other_rows", dict(jailed=(4,), signer=4, last=((1, T0), (2, T0), (6, T0)))),
            ("unjail_last_row_first", dict(jailed=(1,), last=((2, T0), (3, T0)))), ("unjail_last_row_end", dict(jailed=(7,), signer=7, last=((2, T0), (3, T0)))),
            ("unjail_until_and_last", dict(jailed=(1,), jail_until=((1, T0),), last=((1, T0),))), ("unjail_carry_negative", dict(jailed=(1,), carry=-86400 * 3, last=((1, T0),))), ("unjail_carry_round", dict(jailed=(1,), carry=-1, last=((1, (BASE_DATE, 3400, 0)),))),
            ("unjail_date_add_fails", dict(jailed=(1,), date_fail=True)), ("unjail_carry_top", dict(jailed=(1,), carry=0xA8C000000000)), ("unjail_carry_bottom", dict(jailed=(1,), carry=-0xA8C000000000 - 86400)),
            ("unjail_new_row_then_gap", dict(jailed=(1,), now=(EPOCH_DATE, 100, 0))), ("unjail_invalid_chain", dict(jailed=(1,), mode=0)), ("unjail_once", dict(once=1)), ("unjail_chain_1", dict(jailed=(1,), mode=1)), ("unjail_chain_2", dict(jailed=(1,), mode=2)), ("unjail_junk", dict(jailed=(1,), junk=0xABCDEF))]
    for shape, indexes in (("split", MANY[:7]), ("tall", MANY)):
        for signer in (indexes[0], indexes[3], indexes[-1], 40):
            rows.append(("unjail_jailed_%s_%d" % (shape, signer), dict(signer=signer, jailed=indexes, j_shape=shape)))
            rows.append(("unjail_until_%s_%d" % (shape, signer), dict(signer=signer, jailed=(signer,), u_shape=shape, jail_until=tuple((at, later(T0, 900)) for at in indexes))))
            rows.append(("unjail_last_%s_%d" % (shape, signer), dict(signer=signer, jailed=(signer,), l_shape=shape, last=tuple((at, T0) for at in indexes))))
    return [Case(name, BODY, tag=0, **fields) for name, fields in rows]


def jail_self_cases():
    rows = [("self_plain", dict()), ("self_chain_1", dict(mode=1)), ("self_chain_2", dict(mode=2)), ("self_invalid_chain", dict(mode=0)), ("self_once", dict(once=1)), ("self_list_once", dict(once_list=1)), ("self_junk", dict(junk=0xABCDEF)),
            ("self_row_present", dict(jail_until=((1, LATE),))), ("self_row_other", dict(jail_until=((2, LATE),))), ("self_main_protected", dict(main=(1,))), ("self_main_protected_peer", dict(main=(1, 2), jailed=(2,))), ("self_main_protected_free", dict(main=(1, 2), jailed=(3,)))]
    return [Case(name, BODY, tag=1, **fields) for name, fields in rows]


def jail_direct_cases():
    rows = [("jail_plain", dict()), ("jail_none_time", dict(until=None)), ("jail_none_row", dict(until=None, jail_until=((5, LATE),))), ("jail_later", dict(jail_until=((5, later(T0, 7199)),))), ("jail_equal", dict(jail_until=((5, LATE),))), ("jail_earlier", dict(jail_until=((5, later(T0, 7201)),))),
            ("jail_later_day", dict(until=(BASE_DATE + 16, 0, 0), jail_until=((5, LATE),))), ("jail_earlier_day", dict(until=(BASE_DATE - 16, 80000, 0), jail_until=((5, LATE),))), ("jail_later_frac", dict(jail_until=((5, (LATE[0], LATE[1], 8)),))), ("jail_earlier_frac", dict(jail_until=((5, (LATE[0], LATE[1], 10)),))),
            ("jail_negative_date", dict(until=(-(3 << 13), 0, 0), jail_until=((5, LATE),))), ("jail_row_first", dict(jail_until=((6, LATE), (7, LATE)))), ("jail_row_end", dict(jail_until=((2, LATE), (3, LATE)))), ("jail_row_mid", dict(jail_until=((2, LATE), (7, LATE)))),
            ("jail_chain_1", dict(mode=1)), ("jail_chain_2", dict(mode=2)), ("jail_invalid_chain", dict(mode=0)), ("jail_junk", dict(junk=0xAB)), ("jail_once", dict(once=1)), ("jail_list_once", dict(once_list=1)), ("jail_list_null", dict(mode=1, list_null=True)), ("jail_main_null", dict(main_null=True)),
            ("jail_protected_alone", dict(main=(5,))), ("jail_protected_peer", dict(main=(5, 6), jailed=(6,))), ("jail_protected_peer_late", dict(main=(5, 6), jailed=(2, 3, 6))), ("jail_protected_no_peer", dict(main=(5, 6), jailed=(2,))), ("jail_protected_other_list", dict(protected=(5, 6), jailed=(6,))),
            ("jail_chain_1_list", dict(mode=1, protected=(5, 6), jailed=(6,))), ("jail_chain_1_other_list", dict(mode=1, main=(5, 6), jailed=(6,))), ("jail_not_protected", dict(main=(6,), jailed=(6,)))]
    for shape, indexes in (("split", MANY[:7]), ("tall", MANY)):
        rows.append(("jail_main_%s_hit" % shape, dict(target=indexes[-1], main=indexes, jailed=indexes[:3], j_shape="leaf")))
        rows.append(("jail_jailed_%s_peer" % shape, dict(target=30, main=(30, indexes[-1]), jailed=indexes, j_shape=shape)))
        rows.append(("jail_jailed_%s_peer_first" % shape, dict(target=30, main=(30, indexes[0]), jailed=indexes, j_shape=shape)))
        rows.append(("jail_jailed_%s_none" % shape, dict(target=30, main=(30,), jailed=indexes, j_shape=shape)))
        rows.append(("jail_until_%s" % shape, dict(target=indexes[3], u_shape=shape, jail_until=tuple((at, T0) for at in indexes))))
        rows.append(("jail_until_%s_new" % shape, dict(target=40, u_shape=shape, jail_until=tuple((at, T0) for at in indexes))))
    return [Case(name, JAIL, **fields) for name, fields in rows]


def vote(*rows, target=5, word=0x100):
    return ((target, word, tuple(rows)),)


def vote_cases():
    a, b, c, d = later(T0, 100), later(T0, 200), later(T0, 300), later(T0, 400)
    rows = [("vote_first", dict()), ("vote_no_cur", dict(cur=False)), ("vote_voter_absent", dict(signer=9)), ("vote_validators_null", dict(v_null=True)), ("vote_protected_target", dict(protected=(5,))), ("vote_protected_other", dict(protected=(4,))), ("vote_list_null", dict(list_null=True)), ("vote_invalid_chain", dict(mode=0)),
            ("vote_chain_1", dict(mode=1)), ("vote_chain_2", dict(mode=2)), ("vote_junk", dict(junk=0xABCDEF)), ("vote_once", dict(once=1)),
            ("vote_second", dict(signer=2, jvt=vote((1, a)))), ("vote_replace", dict(jvt=vote((1, a), (2, b)))), ("vote_replace_no_fire", dict(jvt=vote((1, a)))), ("vote_first_row_end", dict(signer=4, validators=THREE + ((4, 100),), jvt=vote((1, a), (2, b)))),
            ("vote_fire_three", dict(signer=3, jvt=vote((1, a), (2, b)))), ("vote_fire_order", dict(signer=1, jvt=vote((2, a), (3, b)))), ("vote_exact_two_thirds", dict(signer=2, validators=((1, 100), (2, 100), (3, 100)), jvt=vote((1, a)))), ("vote_above_two_thirds", dict(signer=2, validators=((1, 101), (2, 100), (3, 100)), jvt=vote((1, a)))),
            ("vote_already_quorum", dict(signer=3, validators=((1, 200), (2, 200), (3, 100)), jvt=vote((1, a), (2, b)))), ("vote_fired_flag", dict(signer=3, jvt=vote((1, a), (2, b), word=0x101))), ("vote_fired_flag_low", dict(signer=3, jvt=vote((1, a), (2, b), word=1))), ("vote_word_high_only", dict(signer=3, jvt=vote((1, a), (2, b), word=0x200))),
            ("vote_empty_tracker", dict(jvt=((5, 0x100, None),))), ("vote_empty_root", dict(jvt=((5, 0x100, None),), no_row_empty_root=True)), ("vote_tall_row", dict(signer=2, jvt=vote((1, a)), tall_row=True)), ("vote_tall_row_fire", dict(signer=3, jvt=vote((1, a), (2, b)), tall_row=True)),
            ("vote_other_tracker", dict(jvt=vote((1, a), target=6))), ("vote_tracker_before", dict(jvt=vote((1, a), target=2))), ("vote_trackers_both", dict(jvt=vote((1, a), target=2) + vote((1, a), target=7))),
            ("vote_size_100", dict(fake_len=100, jvt=vote((1, a)))), ("vote_size_101", dict(fake_len=101, jvt=vote((1, a)))), ("vote_size_500", dict(fake_len=500, jvt=vote((1, a)))), ("vote_size_new", dict(fake_len=100, jvt=vote((1, a), target=7))), ("vote_size_no_root", dict(signer=9, fake_len=101)), ("vote_size_fire", dict(signer=3, fake_len=101, jvt=vote((1, a), (2, b)))),
            ("vote_remove_miss", dict(signer=3, remove_miss=True, jvt=vote((1, a), (2, b)))), ("vote_take_miss", dict(signer=3, take_miss=True, jvt=vote((1, a), (2, b)))),
            ("vote_median_lowest", dict(signer=3, until=d, validators=((1, 600), (2, 100), (3, 100)), jvt=vote((1, a), (2, b)))), ("vote_median_middle", dict(signer=3, until=b, validators=((1, 100), (2, 100), (3, 100)), jvt=vote((1, a), (2, c)))), ("vote_median_high", dict(signer=3, until=c, validators=((1, 100), (2, 150), (3, 700)), jvt=vote((1, a), (2, b)))),
            ("vote_median_half", dict(signer=4, until=d, validators=((1, 100), (2, 100), (3, 100), (4, 100)), jvt=vote((1, a), (2, b), (3, c)))), ("vote_median_half_above", dict(signer=4, until=d, validators=((1, 100), (2, 101), (3, 100), (4, 101)), jvt=vote((1, a), (2, b), (3, c)))), ("vote_median_tie_stake", dict(signer=3, until=a, validators=((1, 300), (2, 100), (3, 200)), jvt=vote((1, a), (2, a)))),
            ("vote_median_reverse", dict(signer=1, until=d, jvt=vote((2, c), (3, b)))), ("vote_stale_voter", dict(signer=3, validators=THREE + ((4, 1),), jvt=vote((1, a), (2, b), (9, TIMES[1])))), ("vote_stale_voters_low", dict(signer=3, validators=((2, 100), (3, 300)), jvt=vote((1, a), (2, b)))), ("vote_zero_stake_row", dict(signer=3, validators=((1, 0), (2, 100), (3, 100), (4, 50)), jvt=vote((1, a), (2, b)))),
            ("vote_saturates", dict(signer=3, until=c, validators=((1, 1 << 63), (2, 1 << 61), (3, 1 << 62)), jvt=vote((1, a), (2, b), word=0x100))), ("vote_rows_total_overflow", dict(signer=3, validators=((1, 1 << 63), (2, 1 << 63), (3, 8)), jvt=vote((1, a), (2, b)))),
            ("vote_top_bit_total", dict(signer=3, validators=((1, 1 << 62), (2, 1 << 62), (3, 1 << 62)), jvt=vote((1, a), (2, b)))), ("vote_zero_date_row", dict(signer=3, jvt=vote((1, (0, 7, 7)), (2, b)))), ("vote_zero_date_late", dict(signer=3, jvt=vote((1, a), (2, (0, 7, 7))))), ("vote_zero_until", dict(signer=3, until=(0, 0, 0), jvt=vote((1, a), (2, b)))),
            ("vote_jail_protected_main", dict(signer=3, main=(5, 6), jailed=(6,), jvt=vote((1, a), (2, b)))), ("vote_jail_new_row", dict(signer=3, jail_until=((7, T0),), jvt=vote((1, a), (2, b)))), ("vote_jail_row_later", dict(signer=3, jail_until=((5, T0),), jvt=vote((1, a), (2, b)))), ("vote_jail_row_kept", dict(signer=3, jail_until=((5, later(T0, 99999)),), jvt=vote((1, a), (2, b)))), ("vote_jail_chain_1", dict(signer=3, mode=1, jvt=vote((1, a), (2, b)))),
            ("vote_validators_split", dict(signer=4, validators=tuple((at, 100) for at in MANY[:7]), v_shape="split")), ("vote_validators_tall", dict(signer=12, validators=tuple((at, 100) for at in MANY), v_shape="tall")), ("vote_validators_tall_miss", dict(signer=20, validators=tuple((at, 100) for at in MANY), v_shape="tall")), ("vote_target_late", dict(target=30, signer=4, validators=tuple((at, 100) for at in MANY[:7]), v_shape="split"))]
    for shape, indexes in (("split", MANY[:7]), ("tall", MANY)):
        tracker = tuple((at, 0x100, ((1, a),)) for at in indexes)
        rows.append(("vote_tracker_%s_hit" % shape, dict(target=indexes[3], signer=2, jvt=tracker, t_shape=shape, validators=THREE)))
        rows.append(("vote_tracker_%s_end" % shape, dict(target=indexes[-1], signer=2, jvt=tracker, t_shape=shape)))
        rows.append(("vote_protected_%s" % shape, dict(target=indexes[-1], protected=indexes)))
    for count in (5, 6, 9, 10, 11):
        people = tuple((at, 100) for at in range(1, count + 1))
        votes = tuple((at, TIMES[count - at]) for at in range(1, count))
        rows.append(("vote_rows_%d" % count, dict(signer=count, until=TIMES[0], validators=people, v_shape="split", jvt=vote(*votes))))
    return [Case(name, BODY, tag=2, **fields) for name, fields in rows]


def sort_cases():
    """Six voters whose rows differ in one field each, so that the sort compare of that field decides the order."""
    people = ((1, 100), (2, 100), (3, 100), (4, 100), (5, 100), (6, 100), (7, 70), (8, 70), (9, 70))
    forms = (("date", lambda at: (BASE_DATE + 16 * (6 - at), 5, 5)), ("seconds", lambda at: (BASE_DATE, 500 + 6 - at, 5)), ("frac", lambda at: (BASE_DATE, 500, 6 - at)), ("mixed", lambda at: (BASE_DATE + 16 * (at % 2), 500 + (at % 3), at % 2)))
    rows = []
    for name, form in forms:
        votes = tuple((at, form(at)) for at in range(1, 6))
        rows.append(("vote_sort_" + name, dict(signer=6, target=20, until=form(6), validators=people, v_shape="split", jvt=vote(*votes, target=20))))
    stakes = ((1, 106), (2, 105), (3, 104), (4, 103), (5, 102), (6, 101), (7, 70), (8, 70), (9, 70))
    rows.append(("vote_sort_stake", dict(signer=6, target=20, until=T0, validators=stakes, v_shape="split", jvt=vote(*((at, T0) for at in range(1, 6)), target=20))))
    return [Case(name, BODY, tag=2, **fields) for name, fields in rows]


def big_vote_cases():
    """k votes of weight 100 against k // 2 silent validators: only the k-th vote passes 2/3, so all k rows reach the sort."""
    rows = []
    for count, weight in ((5, 99), (8, 99), (12, 99), (20, 99), (21, 102), (22, 99)):
        people = tuple((at, 100) for at in range(1, count + 1)) + tuple((at, weight) for at in range(count + 1, count + count // 2 + 1))
        votes = tuple((at, TIMES[count - at]) for at in range(1, count))
        rows.append(("vote_big_%d" % count, dict(signer=count, until=TIMES[0], validators=people, v_shape="tall", jvt=vote(*votes))))
    return [Case(name, BODY, tag=2, **fields) for name, fields in rows]


def gate_cases():
    profiles = ((1, 7), (2, 8), (3, 1))
    rows = [("gate_stake_hit", dict(allow=1)), ("gate_stake_miss", dict(allow=1, signer=9)), ("gate_stake_empty", dict(allow=1, v_null=True)), ("gate_stake_no_row", dict(allow=1, round_row=False)), ("gate_stake_split", dict(allow=1, signer=6, validators=tuple((at, 1) for at in MANY[:7]), v_shape="split")), ("gate_stake_tall", dict(allow=1, signer=14, validators=tuple((at, 1) for at in MANY), v_shape="tall")), ("gate_stake_tall_miss", dict(allow=1, signer=30, validators=tuple((at, 1) for at in MANY), v_shape="tall")), ("gate_flag_two", dict(allow=2)), ("gate_junk", dict(allow=1, junk=0xAB, mode=2)),
            ("gate_set_empty", dict()), ("gate_set_size_zero", dict(allowed=(1,), a_len=0, profiles=profiles)), ("gate_set_no_root", dict(a_len=3)), ("gate_set_first", dict(allowed=(3,), profiles=profiles)), ("gate_set_last", dict(allowed=(1, 2, 3), profiles=profiles)), ("gate_set_miss", dict(signer=9, allowed=(1, 2, 3), profiles=profiles)), ("gate_set_key_is_signer", dict(signer=2, allowed=(1, 2), profiles=profiles)), ("gate_set_no_profile", dict(allowed=(5, 6), profiles=profiles)), ("gate_set_partly_profile", dict(allowed=(3, 5), profiles=profiles)), ("gate_set_profile_empty", dict(allowed=(1, 2))), ("gate_set_profile_empty_split", dict(allowed=MANY[:7], a_shape="split")), ("gate_set_profile_empty_tall", dict(allowed=MANY, a_shape="tall")),
            ("gate_set_split", dict(signer=8, allowed=MANY[:7], a_shape="split", profiles=tuple((at, at + 1) for at in MANY[:7]), p_shape="split")), ("gate_set_tall", dict(signer=20, allowed=MANY, a_shape="tall", profiles=tuple((at, at + 5) for at in MANY), p_shape="tall")), ("gate_set_tall_miss", dict(signer=30, allowed=MANY, a_shape="tall", profiles=tuple((at, at + 5) for at in MANY), p_shape="tall")), ("gate_profiles_split_miss", dict(signer=30, allowed=(20, 21), profiles=tuple((at, at + 1) for at in MANY[:7]), p_shape="split"))]
    return [Case(name, GATE, **fields) for name, fields in rows]


def quorum_cases():
    top = 1 << 63
    rows = [("quorum_none", dict(voters=())), ("quorum_one", dict(voters=(1,))), ("quorum_two_exact", dict(voters=(1, 2))), ("quorum_all", dict(voters=(1, 2, 3))), ("quorum_above", dict(validators=((1, 200), (2, 201), (3, 200)), voters=(1, 2))), ("quorum_below", dict(validators=((1, 200), (2, 199), (3, 201)), voters=(1, 2))), ("quorum_stranger", dict(voters=(1, 2, 9))), ("quorum_only_strangers", dict(voters=(8, 9))), ("quorum_no_stakes", dict(v_null=True, voters=(1, 2))), ("quorum_no_stakes_split", dict(v_null=True, voters=MANY[:7], s_shape="split")), ("quorum_no_stakes_tall", dict(v_null=True, voters=MANY, s_shape="tall")), ("quorum_empty_both", dict(v_null=True, voters=())), ("quorum_zero_total", dict(validators=((1, 0), (2, 0)), voters=(1, 2))),
            ("quorum_top_bit_total", dict(validators=((1, top), (2, 8)), voters=(1, 2))), ("quorum_triple_overflow", dict(validators=((1, top - 8), (2, 1 << 62)), voters=(1,))), ("quorum_triple_top", dict(validators=((1, (top // 3) * 2), (2, 1)), voters=(1,))), ("quorum_double_edge", dict(validators=((1, top - 1),), voters=(1,))), ("quorum_total_overflow", dict(validators=((1, top), (2, top)), voters=(1,))), ("quorum_total_max", dict(validators=((1, top), (2, top - 1)), voters=(1, 2)))]
    for shape, indexes in (("split", MANY[:7]), ("tall", MANY)):
        stakes = tuple((at, 100) for at in indexes)
        size = len(indexes) * 2 // 3
        rows.append(("quorum_%s_exact" % shape, dict(validators=stakes, v_shape=shape, s_shape=shape if size >= 7 else "leaf", voters=indexes[:size])))
        rows.append(("quorum_%s_above" % shape, dict(validators=stakes, v_shape=shape, s_shape=shape if size + 1 >= 7 else "leaf", voters=indexes[:size + 1])))
        rows.append(("quorum_%s_all" % shape, dict(validators=stakes, v_shape=shape, s_shape=shape, voters=indexes)))
        rows.append(("quorum_%s_miss" % shape, dict(validators=stakes, v_shape=shape, s_shape="split", voters=tuple(range(21, 28)))))
    return [Case(name, QUORUM, **fields) for name, fields in rows]


GROUPS = ((BODY, unjail_cases() + jail_self_cases() + vote_cases() + sort_cases() + big_vote_cases()), (JAIL, jail_direct_cases()), (GATE, gate_cases()), (QUORUM, quorum_cases()))


def named_cases():
    return [case for _, group in GROUPS for case in group]


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 33


def vector_cases(count):
    source = lcg(0x1234ABCD)

    def pick(limit):
        return next(source) % limit

    def indexes(limit, top=7):
        return tuple(sorted({1 + pick(top) for _ in range(pick(limit))}))

    def moment():
        return later(T0, pick(1200) - 600) if pick(4) else (BASE_DATE + 16 * (pick(3) - 1), pick(86400), pick(3))

    rows = []
    for at in range(count):
        kind = at % 8
        fields = dict(mode=1 + pick(3), once=int(pick(9) == 0), once_list=int(pick(9) == 0))
        stakes = tuple((index, 1 + pick(400)) for index in sorted({1 + pick(7) for _ in range(1 + pick(6))}))
        name = "v%d" % at
        if kind in (0, 1, 2, 3):
            voters = indexes(5)
            votes = tuple((index, moment()) for index in voters)
            word = 0x100 if pick(5) else 0x101
            fields.update(tag=2, signer=1 + pick(7), target=1 + pick(8), until=moment(), validators=stakes, jvt=((1 + pick(8), word, votes),) if votes else (), protected=indexes(2), main=indexes(3), jailed=indexes(3), jail_until=tuple((index, moment()) for index in indexes(3)))
            if votes and pick(2):
                fields["jvt"] = ((fields["target"], word, votes),)
            rows.append(Case(name, BODY, **fields))
        elif kind == 4:
            fields.update(tag=0, signer=1 + pick(7), now=T0, protected=indexes(2), jailed=indexes(5), jail_until=tuple((index, moment()) for index in indexes(4)), last=tuple((index, moment()) for index in indexes(4)))
            rows.append(Case(name, BODY, **fields))
        elif kind == 5:
            fields.update(target=1 + pick(7), until=moment() if pick(4) else None, main=indexes(4), protected=indexes(4), jailed=indexes(5), jail_until=tuple((index, moment()) for index in indexes(4)))
            rows.append(Case(name, JAIL, **fields))
        elif kind == 6:
            fields.update(validators=stakes, voters=indexes(6))
            rows.append(Case(name, QUORUM, **fields))
        else:
            fields.update(allow=pick(2), signer=1 + pick(7), validators=stakes, allowed=indexes(5), profiles=tuple((index, 1 + pick(7)) for index in indexes(6)))
            rows.append(Case(name, GATE, **fields))
    return rows


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case, harness.where)
        if got != want:
            raise EvidenceError("case %s %#x: %r != %r" % (case.name, case.kind, got, want))
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


def slot_sites(image, slot):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text) and start + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            hits.append(start + at)
    return hits


def caller_rows(image):
    relative = image.relative()
    rows = []
    for slot, target, role, count in ((SLOT_BODY, BODY, "c_signer_body", 3), (SLOT_GATE, GATE, "active_signer_gate", 4), (SLOT_QUORUM, QUORUM, "stake_quorum_two_thirds", None), (SLOT_VALIDATORS, 0x3C10FA0, "stakes_at_round", 10), (SLOT_STATIC, 0x33DE620, "per_chain_list", None)):
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not hold %#x" % (slot, target))
        sites = sorted(slot_sites(image, slot))
        if count is not None and len(sites) != count:
            raise EvidenceError("slot %#x has %d sites" % (slot, len(sites)))
        rows.append(("slot %#x" % slot, role, "%#x" % target, len(sites), " ".join("%#x" % site for site in sites[:12])))
    for target, role, count in ((JAIL, "jail_signer", 4), (VOTED, "votes_reach_quorum", 2), (COLLECT, "collect_vote_stakes", 1), (ENTRY, "time_map_entry", 2)):
        sites = sorted(direct_to(image, target))
        if len(sites) != count:
            raise EvidenceError("%#x has %d direct calls" % (target, len(sites)))
        rows.append(("direct", role, "%#x" % target, len(sites), " ".join("%#x" % site for site in sites)))
    return rows


FIELDS = (
    ("allowed_validators", 0x5A6CC4, 18, S_ALLOWED, 0x39909B6, "498d9620010000"), ("allow_all_validators", 0x5A6CD6, 20, S_ALLOW_ALL, 0x39909D2, "410fb68e90020000"), ("broadcasters", 0x5A6CEA, 12, 0x138, 0x3990A68, "498d9638010000"),
    ("validator_to_profile", 0x5A6CF6, 20, S_PROFILES, 0x3990AA9, "498db650010000"), ("jail_until", 0x5A6D48, 10, S_UNTIL, 0x3990B5A, "4d8d86b0010000"), ("signer_to_last_manual_unjail_time", 0x5A6D52, 33, S_LAST, 0x3990B82, "4d8d86c8010000"),
)
CONSTANTS = (
    ("unjail_gap_seconds", 0x3994A0B, "ba2c010000", "edx = 300 seconds handed to the time add"),
    ("seconds_per_day_magic", 0x3994A54, "48b9572951cea0c84518", "signed divide of the second carry by 86400"),
    ("carry_range_offset", 0x3994A1D, "48b900000000" + "4057ffff", "carry + 0xffff574000000000"),
    ("carry_range_bound", 0x3994A2A, "48ba81aefeff7faefeff", "below 0xfffeae7ffffeae81 panics: days outside i32"),
    ("jvt_scan_above", 0x3994135, "4883f865", "cmp len, 101"),
    ("jvt_scan_take", 0x399418F, "48c744247864000000", "take(100) of the jvt keys; the vector is freed unread"),
    ("median_double", 0x39944A5, "4c8d1c3f", "r11 = 2 * running stake"),
    ("status_once_every", 0x3994AAA, "6641c704249b00", "status 0x9b"),
    ("status_jailed_until", 0x39948AE, "6641c704249c00", "status 0x9c"),
    ("status_ok", 0x3994797, "6641c704248601", "status 0x186"),
    ("main_chain_compare", 0x398FABE, "4080fe03", "jail helper takes a separate static on chain 3"),
    ("unix_epoch_days", 0x33BC37A, "bf3bf90a00", "edi = 719163: default row value is 1970-01-01"),
)


def field_rows(image):
    rows = []
    for name, key, size, offset, proof, form in FIELDS:
        text = bytes(image.blob[image.offset(key):image.offset(key) + size]).decode("ascii")
        if text != name:
            raise EvidenceError("key text %s" % text)
        want = bytes.fromhex(form)
        if bytes(image.blob[image.offset(proof):image.offset(proof) + len(want)]) != want:
            raise EvidenceError("field proof %#x" % proof)
        rows.append((name, "%#x" % key, "%#x" % offset, "%#x" % proof, form))
    return rows


TEXTS = ((0x1ED55D, b"Can only manually unjail once every "), (0x2023BB, b"Jailed until "), (0x21A01F, b"`NaiveDateTime + TimeDelta` overflowed"), (0x58C1CA, b"invalid chain"), (0x5A6CC4, b"allowed_validators"))


def constant_rows(image):
    rows = []
    for name, va, form, note in CONSTANTS:
        want = bytes.fromhex(form)
        if bytes(image.blob[image.offset(va):image.offset(va) + len(want)]) != want:
            raise EvidenceError("constant row %s %s" % (name, bytes(image.blob[image.offset(va):image.offset(va) + len(want)]).hex()))
        rows.append((name, "%#x" % va, form, note))
    gap = struct.unpack_from("<d", image.blob, image.offset(0x20A3E8))[0]
    if gap != float(UNJAIL_GAP):
        raise EvidenceError("display gap")
    rows.append(("display_gap_f64", "0x20a3e8", "%r" % gap, "f64 the 0x9b text prints; same number as the edx immediate"))
    for va, wanted in TEXTS:
        if bytes(image.blob[image.offset(va):image.offset(va) + len(wanted)]) != wanted:
            raise EvidenceError("text %#x" % va)
        rows.append(("text", "%#x" % va, wanted.hex(), wanted.decode("ascii")))
    for wanted in (b"unjailSelf", b"voteJail", b"struct variant CSignerAction::VoteJail with 2 elements", b"variant index 0 <= i < 3"):
        at = image.blob.find(wanted)
        if at < 0:
            raise EvidenceError("missing text")
        rows.append(("wire_text", "%#x" % at, "", wanted.decode("ascii")))
    return rows


def static_rows(image):
    """Jump table of the per-chain list getter: chain 0 panics, chains 1..3 return one lazily built cell each."""
    rows = []
    base = image.offset(STATIC_TABLE)
    for mode in range(4):
        arm = STATIC_TABLE + struct.unpack_from("<i", image.blob, base + 4 * mode)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 17])
        if data[:3] == b"\x48\x8d\x3d":
            text = arm + 7 + struct.unpack_from("<i", data, 3)[0]
            rows.append((mode, "%#x" % arm, "panic", "%#x" % text))
            continue
        if data[:2] != b"\x8b\x05" or data[10:13] != b"\x48\x8d\x05":
            raise EvidenceError("static arm %#x" % arm)
        rows.append((mode, "%#x" % arm, "cell", "%#x" % (arm + 17 + struct.unpack_from("<i", data, 13)[0])))
    if [row[2] for row in rows] != ["panic", "cell", "cell", "cell"]:
        raise EvidenceError("static table shape")
    return rows


def status_rows(image):
    rows = []
    base = image.offset(STATUS_TABLE)
    for tag, template in ((TAG_UNKNOWN, None), (TAG_INACTIVE, None), (TAG_ONCE_EVERY, 0x1ED55D), (TAG_JAILED_UNTIL, 0x2023BB)):
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * tag)[0]
        data = bytes(image.blob[image.offset(arm):image.offset(arm) + 64])
        if template is not None:
            rows.append(("%#x" % tag, "%#x" % arm, "(formatted arm, template at %#x)" % template))
            continue
        at = data.find(b"\x48\x8d\x35")
        text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, at + 8)[0]
        rows.append(("%#x" % tag, "%#x" % arm, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")))
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
            if harness.run(case) != spec_run(case, harness.where):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, TypeError, struct.error):
            return case
    return None


EIGHT = "bound of the unrolled eight step tree descent: it picks between two walks of one path and no tree here is that tall"
FIRST_LEAF = "first leaf length: only tested against a slot of 0, and a leaf reached with rows left has a nonzero word at both offsets"
ONE_PASS = "state word of the loop at 0x3993a77 or of its earlier clone flag: the body runs once, so the edit changes no path"
ONCE_ARG = "constant argument of the lazy cell call, which the stub does not read"
ZERO_WORD = "zero stored into a frame or iterator word that the stub on this path does not read"
NO_TIME = "low byte of the empty time word of jailSelf: a date of 1 is below every stored row, so the row keeps its value"
SECOND_MAP = "copy or read of the second inner map words, which are zero in every fixture"
OPEN = "open: no named case tells this edit apart and it was not analysed further"
EXPECTED_SURVIVORS = {}
for reason, kind, group in (
    (EIGHT, "immediate", (0x3992A15, 0x3992AF8, 0x3992DA5, 0x3992E89, 0x398FCC5, 0x398FDA8, 0x3597715, 0x35977F8, 0x35978F5, 0x35979D8, 0x3597C05, 0x3597CE8)),
    (FIRST_LEAF, "displacement", (0x3992A73, 0x3992E03, 0x398FD22, 0x3597772, 0x3597952, 0x3597C62)),
    (ONE_PASS, "immediate", (0x3993A77, 0x3993A79, 0x3993A88, 0x3993A9A, 0x3993AA8, 0x399403F, 0x399411A)),
    (ONE_PASS, "condition", (0x3993A9D,)),
    (ONCE_ARG, "immediate", (0x3994582, 0x398FB2C, 0x39900ED)),
    (ZERO_WORD, "immediate", (0x3993D8A, 0x3993DE1, 0x3993DFD, 0x3993E22, 0x3993F55, 0x3993F5E, 0x399415F, 0x3994177, 0x3994237, 0x399424A, 0x399439F, 0x39943C3, 0x3941799, 0x39417B1, 0x39417D8, 0x39417E1)),
    (NO_TIME, "immediate", (0x399383D,)),
    (SECOND_MAP, "displacement", (0x3993F08, 0x3993F74, 0x3993F85, 0x3993FE4, 0x3993FE8, 0x3994030, 0x3994038, 0x3941777, 0x394177B)),
    (SECOND_MAP, "condition", (0x3941787, 0x394178B)),
):
    for address in group:
        EXPECTED_SURVIVORS[(address, kind)] = reason


def cases_for(target, cases):
    wanted = {BODY: (BODY,), GATE: (GATE,), JAIL: (JAIL, BODY), VOTED: (BODY, QUORUM), QUORUM: (QUORUM, BODY), COLLECT: (BODY,), SORT: (BODY,), UPSERT: (BODY,), ENTRY: (JAIL, BODY)}[target]
    return [case for kind in wanted for case in cases if case.kind == kind]


POOL = {}


def run_one(task):
    target, patch = task
    harness = Harness(POOL["image"], patch)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    return first_failure(harness, POOL["chosen"][target]) is not None


def run_mutants(image, table, seen, cases):
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    POOL.update(image=image, chosen={target: cases_for(target, cases) for target in TARGETS})
    rows = [(target,) + edit for target in TARGETS for edit in edits_for(image, table[target], seen)]
    tasks = [(row[0], row[3]) for row in rows]
    try:
        with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
            killed = pool.map(run_one, tasks, 8)
    except OSError:
        killed = [run_one(task) for task in tasks]
    return [(va, kind, "killed", "whole run") if dead else (va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), OPEN)) for (_, va, kind, _), dead in zip(rows, killed)]


def analyse(image, mutate=True, vectors=480):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    check_cases(harness, vector_cases(vectors))
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, callers=caller_rows(image), constants=constant_rows(image), fields=field_rows(image), statuses=status_rows(image), statics=static_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases)
    return result


def describe(case, outcome):
    if outcome[0] == "panic":
        return outcome[0], outcome[1], ",".join(str(event[0]) for event in outcome[2]), ""
    digest = hashlib.sha256(repr(outcome[3]).encode()).hexdigest()[:16]
    head = outcome[1]
    if case.kind == BODY:
        return "%#x" % head[0], "" if head[1] is None else "%d/%d/%d" % head[1], ",".join(str(event[0]) for event in outcome[2]), digest
    return str(head), "", ",".join(str(event[0]) for event in outcome[2]), digest


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("callers.tsv", ("reach", "role", "target", "sites", "addresses"), result["callers"])
    tsv("constants.tsv", ("name", "address", "bytes", "note"), result["constants"])
    tsv("field-names.tsv", ("key", "key_address", "offset", "proof_address", "proof_bytes"), result["fields"])
    tsv("status-text.tsv", ("status", "arm", "text"), result["statuses"])
    tsv("chain-lists.tsv", ("chain", "arm", "kind", "address"), result["statics"])
    tsv("outcomes.tsv", ("entry", "case", "result", "detail", "events", "state_digest"),
        [("%#x" % case.kind, case.name) + describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"],
        "named_by_entry": {NAMES[kind]: len(group) for kind, group in GROUPS},
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
