#!/usr/bin/env python3
"""Pin the node #94 outcome market top of book from ELF bytes: own book, sibling complement, merge, mid, gate.

An outcome token's spot has a question record with two sides. `0x37270e0` reads the top of the book of each
side through `0x3c01010`. One leg may be turned into the frame of the other as `value - ask`, `value - bid`,
where `value` is the sibling record found by `0x37272c0`. The two legs then merge: highest nonzero bid, lowest
nonzero ask. `0x3730b40` uses this as the mid of an outcome spot, and `0x372a0f0` runs it after an insert so that
a failed turn replaces the insert result. The real bytes run in a Python evaluator, including the real SipHash
and hash table probes. A separately written specification predicts every result, and every condition, immediate
and field offset of the seven functions is flipped to show the run can tell. No objdump or readelf output is
parsed, and the binary is never executed. Standard library only.
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

MERGED = 0x37270E0
LEG = 0x3C01010
SIBLING = 0x37272C0
CLASSIFY = 0x3728670
TOPS = 0x3C18B70
MID = 0x3730B40
GATE = 0x372A0F0
HASH = 0x399C4A0
HASH_WRITE = 0x3A00700

SLOT_MERGED = 0x5775E00
SLOT_CLASSIFY = 0x5773198
SLOT_MID = 0x5774E10
SLOT_GATE = 0x57747C0
SLOT_RECORDER = 0x5773190
SLOT_BOUNDS = 0x576DFC8
SLOT_PANIC = 0x576E470
LOC_LIST = 0x56F1FD8
LOC_BOOK = 0x56DFDA8
LOC_TOKEN = 0x56F21F0
LOC_LEVEL = 0x56E9FE8
LOC_SUM = 0x56F2008
LOCATION_NAMES = {LOC_LIST: "spot past the list", LOC_BOOK: "book past the slab", LOC_TOKEN: "token past the row list", LOC_LEVEL: "tree walk ran out of levels", LOC_SUM: "saturating fill sum"}

OK_WORD = 0x186
ABORT_WORD = 0x187
NONE_BYTE = 0x27
ERR_RECORD_SIDES = 1
ERR_NO_ID = 3
ERR_NO_RECORD = 4
ERR_UNFILLED = 5
ERR_UNDERFLOW = 8
ERR_ZERO = 9

BOOK_STRIDE = 0xD8
TOKEN_STRIDE = 0xE8
LIST_STRIDE = 0x20
FILL_STRIDE = 0x228
ENTRY_A = 0x20
ENTRY_B = 0x10
ENTRY_C = 0x90
BIDS = 0x80
ASKS = 0x98
NODE_LEAF = 0x1C8
NODE_INNER = 0x228
NODE_PARENT = 0x160
NODE_KEYS = 0x168
NODE_INDEX = 0x1C0
NODE_LENGTH = 0x1C2
NODE_EDGES = 0x1C8
TEMPT_KEY = -0x7654321
LEAF_EDGE = 0x7300000000

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
HEAP_SIZE = 0x100000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 2000000
MUTANT_STEP_LIMIT = 60000

OUT = HEAP_BASE + 0x800
CTX = HEAP_BASE + 0x900
ARG = HEAP_BASE + 0x980
HOLDER = HEAP_BASE + 0x1000
OWNER = HOLDER + 0x10
TABLE = HOLDER + 0x400
SLAB = HOLDER + 0x800
ORDER = HOLDER + 0x880
RESULT = HOLDER + 0x900
BUMP = HOLDER + 0x1000

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


# ---- specification: written from the reading, no call into the evaluator ----

def siphash13(k0, k1, word):
    """SipHash-1-3 of one little-endian u64, as the std hasher finishes it."""
    v0, v1, v2, v3 = k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D, k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573

    def rol(value, count):
        return (value << count | value >> (64 - count)) & MASK[8]

    def sip_round():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & MASK[8]
        v1 = rol(v1, 13) ^ v0
        v0 = rol(v0, 32)
        v2 = (v2 + v3) & MASK[8]
        v3 = rol(v3, 16) ^ v2
        v0 = (v0 + v3) & MASK[8]
        v3 = rol(v3, 21) ^ v0
        v2 = (v2 + v1) & MASK[8]
        v1 = rol(v1, 17) ^ v2
        v2 = rol(v2, 32)

    v3 ^= word
    sip_round()
    v0 ^= word
    last = 8 << 56
    v3 ^= last
    sip_round()
    v0 ^= last
    v2 ^= 0xFF
    sip_round()
    sip_round()
    sip_round()
    return v0 ^ v1 ^ v2 ^ v3


class Tree:
    """One chain of B-tree nodes, leaf first. Each level is (length, keys, index in its parent)."""

    def __init__(self, keys=(), height=0, null=False, count=None, levels=None):
        self.levels = levels if levels is not None else [(len(keys), list(keys), 0)] + [(1, [-(0x4000 + level)], 0) for level in range(1, height + 1)]
        self.null = null
        self.count = sum(row[0] for row in self.levels) if count is None else count


def first_key(tree):
    """Absolute first key of a side, 0 when the side is empty; a walk past the root is a panic."""
    if tree.null or tree.count == 0:
        return 0
    level = 0
    if tree.levels[0][0] > 0:
        return abs_key(tree.levels[0][1][0])
    while True:
        index = tree.levels[level][2]
        level += 1
        if level == len(tree.levels):
            raise Stop(("panic", LOC_LEVEL))
        length, keys, _ = tree.levels[level]
        if index < length:
            return abs_key(keys[index])


def abs_key(key):
    return abs(key) & MASK[8]


class Stop(Exception):
    pass


def book_of(world, index):
    return world.books.get(index, (Tree(), Tree()))


def top_pair(world, index):
    bids, asks = book_of(world, index)
    return first_key(bids), first_key(asks)


def find_b(world, key):
    if world.empty_b:
        return None
    return world.map_b.get(key)


def find_c(world, record_id):
    if world.empty_c:
        return None
    return world.map_c.get(record_id)


def list_key(world, index):
    if index >= world.list_len:
        raise Stop(("bounds", index, world.list_len, LOC_LIST))
    return world.spots[index]


def spec_classify(world, key):
    if not world.empty_a and key in world.map_a:
        return 1
    record_id = find_b(world, key)
    if record_id is None:
        return 0
    return 2 if find_c(world, record_id) is not None else 1


def spec_sibling(world, book):
    """Record of the side whose token differs from the spot's list word, or an error byte."""
    key = list_key(world, book)
    record_id = find_b(world, key)
    if record_id is None:
        return ("err", ERR_NO_ID)
    entry = find_c(world, record_id)
    if entry is None:
        return ("err", ERR_NO_RECORD)
    for side in (0, 1):
        if entry[side][0] != key:
            return ("record", record_id, side)
    return ("err", ERR_RECORD_SIDES)


def token_row(world, token):
    if token >= world.row_count:
        raise Stop(("panic", LOC_TOKEN))
    return world.rows.get(token, ())


def turn(world, book, price):
    """value - price through the sibling record: (result, byte kept for the error)."""
    found = spec_sibling(world, book)
    if found[0] == "err":
        return 0, found[1]
    token, value = world.map_c[found[1]][found[2]]
    if len(token_row(world, token)) != 1:
        return 0, 0
    if value < price:
        return 0, ERR_UNDERFLOW
    if value == price:
        return 0, ERR_ZERO
    return value - price, None


def spec_leg(world, record, side, has, wanted):
    token = record[0]
    row = token_row(world, token)
    if len(row) != 1:
        return ("err", 0)
    book = row[0]
    if book >= world.book_count:
        raise Stop(("bounds", book, world.book_count, LOC_BOOK))
    bid, ask = top_pair(world, book)
    flip = (wanted != book) if has else side == 1
    if not flip:
        return ("ok", bid, ask)
    new_ask, first_byte = (0, 1) if bid == 0 else turn(world, book, bid)
    first_bad = bid != 0 and new_ask == 0
    if ask == 0:
        if first_bad:
            return ("err", first_byte)
        return ("ok", 0, new_ask)
    new_bid, second_byte = turn(world, book, ask)
    if first_bad:
        return ("err", first_byte)
    if new_bid == 0:
        return ("err", second_byte)
    return ("ok", new_bid, new_ask)


def spec_merged(world, record_id, has, wanted):
    entry = find_c(world, record_id)
    if entry is None:
        return ("err", ERR_NO_RECORD)
    first = spec_leg(world, entry[0], 0, has, wanted)
    second = spec_leg(world, entry[1], 1, has, wanted)
    if first[0] == "err":
        return first
    if second[0] == "err":
        return second
    bids = [value for value in (first[1], second[1]) if value]
    asks = [value for value in (first[2], second[2]) if value]
    return ("ok", max(bids) if bids else 0, min(asks) if asks else 0)


def floor_mean(bid, ask):
    return 0 if bid == 0 or ask == 0 else (bid + ask) // 2


def spec_mid(world, index):
    key = list_key(world, index)
    kind = spec_classify(world, key)
    if kind in (0, 1):
        if index >= world.book_count:
            raise Stop(("bounds", index, world.book_count, LOC_BOOK))
        bid, ask = top_pair(world, index)
        return floor_mean(bid, ask) if kind == 0 else 0
    answer = spec_merged(world, find_b(world, key), True, index)
    return 0 if answer[0] == "err" else floor_mean(answer[1], answer[2])


def spec_gate(world, case):
    """Byte result and recorder hits of the post-insert gate; 0x27 means carry on."""
    events = []
    key = list_key(world, case.spot)
    record_id = find_b(world, key)
    if record_id is None:
        return ERR_NO_ID, events
    if case.word != OK_WORD:
        answer = spec_merged(world, record_id, False, 0)
    else:
        total = 0
        for _, amount in case.fills:
            if total + amount > MASK[8]:
                events.append(("recorder", 0, LOC_SUM))
            total = min(total + amount, MASK[8])
        if case.tag != 1:
            return ERR_UNFILLED, events
        answer = spec_merged(world, record_id, bool(case.fills), case.fills[0][0] if case.fills else 0)
    return (NONE_BYTE if answer[0] == "ok" else answer[1]), events


def spec_run(case):
    world = case.world
    try:
        if case.kind == "merged":
            return {"stop": None, "answer": spec_merged(world, case.record_id, case.has & 0xFF != 0, case.wanted), "events": []}
        if case.kind == "leg":
            entry = world.map_c[case.record_id]
            return {"stop": None, "answer": spec_leg(world, entry[case.index], case.side, case.has & 0xFF != 0, case.wanted), "events": []}
        if case.kind == "sibling":
            found = spec_sibling(world, case.book)
            return {"stop": None, "answer": found, "events": []}
        if case.kind == "classify":
            return {"stop": None, "answer": spec_classify(world, case.key), "events": []}
        if case.kind == "tops":
            return {"stop": None, "answer": top_pair(world, case.book), "events": []}
        if case.kind == "mid":
            return {"stop": None, "answer": spec_mid(world, case.spot), "events": []}
        answer, events = spec_gate(world, case)
        return {"stop": None, "answer": answer, "events": events}
    except Stop as caught:
        return {"stop": caught.args[0], "events": []}


# ---- harness: real bytes, only panics and the recorder stubbed ----

RAMPS = {}


def ramp(size, start):
    """Non-periodic filler, so that a wrong field offset reads a wrong value."""
    key = (size, start)
    if key not in RAMPS:
        RAMPS[key] = bytes((start + index * 37 + (index >> 4)) & 0xFF | 1 for index in range(size))
    return RAMPS[key]


class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        machine.memory.statics.update(self.relative)
        relative = self.relative
        machine.slots = {relative[SLOT_PANIC]: self.on_panic, relative[SLOT_BOUNDS]: self.on_bounds, relative[SLOT_RECORDER]: self.on_recorder}
        self.real = RealExcept()
        self.real.stubs = frozenset(machine.slots)
        machine.real = self.real
        self.top = HEAP_SIZE
        self.bump = BUMP
        self.events = []
        self.records = {}

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("harness heap too small")
        return at

    def put(self, addr, width, value):
        self.machine.memory.write(addr, width, value)

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_recorder(self, m):
        self.events.append(("recorder", m.regs[RDI], m.regs[RSI]))

    # world bytes

    def write_tree(self, at, tree):
        memory = self.machine.memory
        child = 0
        nodes = []
        for level, (length, keys, index) in enumerate(tree.levels):
            size = NODE_INNER if level else NODE_LEAF
            node = self.alloc(size)
            memory.put_bytes(node, ramp(size, level + 9))
            for slot in range(11):
                self.put(node + NODE_KEYS + slot * 8, 8, TEMPT_KEY)
            for slot, key in enumerate(keys):
                self.put(node + NODE_KEYS + slot * 8, 8, key)
            self.put(node + NODE_LENGTH, 2, length)
            self.put(node + NODE_INDEX, 2, index)
            self.put(node + NODE_PARENT, 8, 0)
            if level:
                for slot in range(12):
                    self.put(node + NODE_EDGES + slot * 8, 8, LEAF_EDGE)
                self.put(node + NODE_EDGES, 8, child)
                self.put(child + NODE_PARENT, 8, node)
            child = node
            nodes.append(node)
        self.put(at, 8, 0 if tree.null else child)
        self.put(at + 8, 8, len(tree.levels) - 1)
        self.put(at + 0x10, 8, tree.count)

    def write_table(self, at, entries, stride, write_entry, world, mark, empty):
        """A hash table of `buckets`: control bytes after the entries, entries growing down from them."""
        memory = self.machine.memory
        buckets = world.buckets
        mask = buckets - 1
        block = self.alloc(buckets * stride + buckets + 16)
        memory.put_bytes(block, ramp(buckets * stride, mark))
        ctrl = block + buckets * stride
        control = bytearray(b"\xff" * buckets)
        k0, k1 = struct.unpack("<QQ", ramp(16, mark + 3))

        def slot_for(home):
            jump, position = 0, home
            while True:
                for step in range(16):
                    index = (position + step) & mask
                    if control[index] == 0xFF:
                        return index
                jump += 16
                position = (position + jump) & mask

        for key in sorted(entries):
            value = siphash13(k0, k1, key)
            home, tag = value & mask, value >> 57
            room = buckets - buckets // 4 - len(entries)
            for step in range(world.decoys):
                index = (home + step) & mask
                if control[index] == 0xFF and buckets - control.count(0xFF) < room:
                    control[index] = tag
                    self.put(ctrl - (index + 1) * stride, 8, key ^ (0x1000 + step))
            for step in range(world.tombs):
                index = (home + world.decoys + step) & mask
                if control[index] == 0xFF and buckets - control.count(0xFF) < room:
                    control[index] = 0x80
            index = slot_for(home)
            control[index] = tag
            place = ctrl - (index + 1) * stride
            self.put(place, 8, key)
            write_entry(place, key)
        memory.put_bytes(ctrl, bytes(control) + bytes(control[:16]))
        self.put(at, 8, ctrl)
        self.put(at + 8, 8, mask)
        self.put(at + 0x18, 8, 0 if empty else len(entries))
        self.put(at + 0x20, 8, k0)
        self.put(at + 0x28, 8, k1)
        return ctrl

    def write_world(self, case):
        world = case.world
        memory = self.machine.memory
        meta = TABLE if case.split else OWNER
        self.write_table(OWNER + 0x40, world.map_a, ENTRY_A, lambda place, key: None, world, 61, world.empty_a)
        self.write_table(OWNER + 0x70, world.map_b, ENTRY_B, lambda place, key: self.put(place + 8, 8, world.map_b[key]), world, 71, world.empty_b)
        self.records = {}

        def write_record(place, key):
            for side, (token, value) in enumerate(world.map_c[key]):
                record = place + 8 + side * 0x28
                self.records[record] = (key, side)
                self.put(record + 0x18, 8, value)
                self.put(record + 0x20, 8, token)

        self.write_table(OWNER + 0xD0, world.map_c, ENTRY_C, write_record, world, 81, world.empty_c)
        spots = self.alloc(LIST_STRIDE * max(len(world.spots), 1))
        memory.put_bytes(spots, ramp(LIST_STRIDE * max(len(world.spots), 1), 63))
        for index, token in enumerate(world.spots):
            self.put(spots + index * LIST_STRIDE, 8, token)
        self.put(meta + 0x168, 8, spots)
        self.put(meta + 0x170, 8, world.list_len)
        rows = self.alloc(TOKEN_STRIDE * max(world.row_count, 1))
        memory.put_bytes(rows, ramp(TOKEN_STRIDE * max(world.row_count, 1), 57))
        for token in range(min(world.row_count, 16)):
            row = world.rows.get(token, ())
            array = self.alloc(max(len(row), 1) * 8)
            for slot, book in enumerate(row):
                self.put(array + slot * 8, 8, book)
            self.put(rows + token * TOKEN_STRIDE + 0x58, 8, array)
            self.put(rows + token * TOKEN_STRIDE + 0x60, 8, len(row))
        self.put(meta + 0x180, 8, rows)
        self.put(meta + 0x188, 8, world.row_count)
        books = self.alloc(BOOK_STRIDE * max(world.book_count, 1))
        memory.put_bytes(books, ramp(BOOK_STRIDE * max(world.book_count, 1), 69))
        for index in range(min(world.book_count, 16)):
            bids, asks = book_of(world, index)
            self.write_tree(books + index * BOOK_STRIDE + BIDS, bids)
            self.write_tree(books + index * BOOK_STRIDE + ASKS, asks)
        self.books = books
        self.put(SLAB + 8, 8, books)
        self.put(SLAB + 0x10, 8, world.book_count)
        return meta

    # the runs

    def answer_pair(self):
        memory = self.machine.memory
        tag = memory.read(OUT, 1)
        if tag == 1:
            if memory.bytes_at(OUT + 2, 0x1E) != ramp(0x20, 13)[2:]:
                raise Halt("error result wrote past the byte")
            return ("err", memory.read(OUT + 1, 1))
        if tag != 0:
            raise Halt("result tag")
        if memory.bytes_at(OUT + 1, 7) != ramp(0x20, 13)[1:8] or memory.bytes_at(OUT + 0x18, 8) != ramp(0x20, 13)[0x18:]:
            raise Halt("ok result wrote past its words")
        return ("ok", memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8))

    def run_case(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(self.top)
        self.top = BUMP - HEAP_BASE
        self.bump = BUMP
        self.events = []
        self.case = case
        memory.put_bytes(OUT, ramp(0x20, 13))
        memory.put_bytes(CTX, ramp(0x80, 17))
        memory.put_bytes(HOLDER, ramp(0x1000, 31))
        meta = self.write_world(case)
        kind = case.kind
        stack_word = STACK_TOP - 0x100
        if kind == "merged":
            self.put(stack_word, 8, meta)
            result = machine.run(MERGED, {RDI: OUT, RSI: OWNER, RDX: case.record_id, RCX: case.has | 0xABCD0000, R8: case.wanted, R9: SLAB})
            if result != OUT:
                raise Halt("result pointer")
            answer = self.answer_pair()
        elif kind == "leg":
            record = next(at for at, name in self.records.items() if name == (case.record_id, case.index))
            self.put(CTX, 8, meta)
            self.put(CTX + 8, 8, SLAB)
            self.put(CTX + 0x10, 8, ARG)
            self.put(CTX + 0x18, 8, OWNER)
            memory.put_bytes(ARG, struct.pack("<QQ", case.has, case.wanted))
            machine.run(LEG, {RDI: OUT, RSI: CTX, RDX: case.side | 0xABCD00, RCX: record})
            answer = self.answer_pair()
        elif kind == "sibling":
            spots = memory.read(meta + 0x168, 8)
            machine.run(SIBLING, {RDI: OUT, RSI: OWNER, RDX: case.book, RCX: spots, R8: case.world.list_len})
            tag = memory.read(OUT, 1)
            if tag == 1:
                answer = ("err", memory.read(OUT + 1, 1))
            elif tag == 0:
                answer = ("record",) + self.records[memory.read(OUT + 8, 8)]
            else:
                raise Halt("sibling tag")
        elif kind == "classify":
            answer = machine.run(CLASSIFY, {RDI: OWNER, RSI: case.key}) & 0xFF
        elif kind == "tops":
            result = machine.run(TOPS, {RDI: OUT, RSI: self.books + case.book * BOOK_STRIDE + BIDS})
            if result != OUT:
                raise Halt("result pointer")
            answer = (memory.read(OUT, 8), memory.read(OUT + 8, 8))
        elif kind == "mid":
            answer = machine.run(MID, {RDI: HOLDER, RSI: case.spot, RDX: SLAB})
        else:
            self.put(ORDER, 4, case.tag)
            self.put(ORDER + 0x28, 8, case.spot)
            self.put(RESULT, 2, case.word)
            fills = self.alloc(FILL_STRIDE * max(len(case.fills), 1))
            memory.put_bytes(fills, ramp(FILL_STRIDE * max(len(case.fills), 1), 91))
            for index, (book, amount) in enumerate(case.fills):
                self.put(fills + index * FILL_STRIDE + 0x1F8, 8, book)
                self.put(fills + index * FILL_STRIDE + 0x200, 8, amount)
            self.put(RESULT + 0x10, 8, fills)
            self.put(RESULT + 0x18, 8, len(case.fills))
            answer = machine.run(GATE, {RDI: OWNER, RSI: ORDER, RDX: RESULT, RCX: SLAB, R8: meta}) & 0xFF
        return {"stop": None, "answer": answer, "events": self.events}

    def run(self, case):
        try:
            return self.run_case(case)
        except Panicked as caught:
            return {"stop": caught.args[0], "events": self.events}
        finally:
            self.top = max(self.top, self.bump - HEAP_BASE)


CRASHES = (Halt, EvidenceError, RecursionError, IndexError, KeyError, ZeroDivisionError, StopIteration, OverflowError, ValueError, TypeError, AttributeError, struct.error)
COMPARED = ("stop", "answer", "events")


def compare_run(harness, case):
    try:
        actual = harness.run(case)
    except CRASHES as caught:
        return "%s: crash %s" % (case.label, caught)
    expected = spec_run(case)
    for key in COMPARED:
        if key in expected and actual.get(key) != expected.get(key):
            return "%s: %s differs: %s / %s" % (case.label, key, str(actual.get(key))[:300], str(expected.get(key))[:300])
    return None


# ---- cases ----

VALUE = 100000000
OTHER_VALUE = 100000003
TOKEN_YES = 4
TOKEN_NO = 5
RECORD_ID = 10


class World:
    """A question with two sides: token 4 on book 2, token 5 on book 3; book 0 plain, book 1 in the first map."""

    def __init__(self, **changes):
        self.map_a = {2}
        self.map_b = {TOKEN_YES: RECORD_ID, TOKEN_NO: RECORD_ID, 6: 99}
        self.map_c = {RECORD_ID: ((TOKEN_YES, VALUE), (TOKEN_NO, OTHER_VALUE))}
        self.spots = [1, 2, TOKEN_YES, TOKEN_NO, 6, 9, 7]
        self.rows = {1: [0], 2: [1], TOKEN_YES: [2], TOKEN_NO: [3], 6: [4], 7: [6], 9: [5]}
        self.row_count = 10
        self.book_count = 7
        self.books = {0: (Tree([-50000000, -40000000]), Tree([52000000])),
                      1: (Tree([-44000000]), Tree([46000000])),
                      2: (Tree([-60000000, -59000000]), Tree([65000000, 66000000])),
                      3: (Tree([-30000000, -29000000]), Tree([34000000])),
                      4: (Tree([-20000000]), Tree([22000000])),
                      5: (Tree([-10000000]), Tree([12000000])),
                      6: (Tree([-11000000]), Tree([13000000]))}
        self.buckets = 16
        self.decoys = 0
        self.tombs = 0
        self.empty_a = self.empty_b = self.empty_c = False
        self.list_len = None
        for key, value in changes.items():
            setattr(self, key, value)
        if self.list_len is None:
            self.list_len = len(self.spots)


class Case:
    def __init__(self, label, kind, world=None, **fields):
        self.label = label
        self.kind = kind
        self.world = world or World()
        self.split = False
        self.record_id = RECORD_ID
        self.has = 0
        self.wanted = 0xFEDCBA
        self.index = 0
        self.side = 0
        self.book = 2
        self.key = 0
        self.spot = 2
        self.tag = 1
        self.word = 0xB7
        self.fills = ()
        for key, value in fields.items():
            setattr(self, key, value)


def books(**sides):
    """World with books replaced: b2=(bid, ask) and so on, 0 for an empty side."""
    world = World()
    for name, (bid, ask) in sides.items():
        world.books[int(name[1:])] = (Tree([-bid]) if bid else Tree(), Tree([ask]) if ask else Tree())
    return world


def table_worlds():
    """The same logical maps with collisions, tombstones, wrapped and long probes."""
    return (("plain", {}), ("decoys", dict(decoys=3)), ("tombs", dict(tombs=2)), ("both", dict(decoys=2, tombs=1)), ("long", dict(buckets=32, decoys=20)), ("longer", dict(buckets=64, decoys=40)), ("wide", dict(buckets=128, decoys=50, tombs=50)))


def merged_cases():
    rows = []
    low, high = 3000000, 90000000
    for has, wanted, name, tiers in ((0, 0, "side", (0, low, high)), (1, 2, "book2", (0, high)), (1, 3, "book3", (0, high)), (1, 77, "neither", (0, high)), (0x100, 3, "low byte zero", (0, high))):
        for b2 in tiers:
            for a2 in (value + 5 if value else 0 for value in tiers):
                for b3 in (value + 1 if value else 0 for value in tiers):
                    for a3 in (value + 7 if value else 0 for value in tiers):
                        rows.append(Case("merge %s %d %d %d %d" % (name, b2, a2, b3, a3), "merged", books(b2=(b2, a2), b3=(b3, a3)), has=has, wanted=wanted))
    edges = (0, 5, VALUE - 1, VALUE, VALUE + 1, OTHER_VALUE - 1, OTHER_VALUE, OTHER_VALUE + 1)
    for bid in edges:
        for ask in edges:
            rows.append(Case("turn side1 %d %d" % (bid, ask), "merged", books(b3=(bid, ask))))
            rows.append(Case("turn book2 %d %d" % (bid, ask), "merged", books(b2=(bid, ask)), has=1, wanted=3))
    return rows


def tree_cases():
    rows = []
    for height in range(0, 18):
        keys = [-(70000 + height), -(70001 + height)]
        asks = [71000 + height, 71005 + height]
        world = World()
        world.books[2] = (Tree(keys, height=height), Tree(asks, height=(height + 3) % 18))
        rows.append(Case("tree height %d" % height, "tops", world))
        rows.append(Case("leg tree height %d" % height, "leg", world))
    empties = (("leaf empty", [(0, [], 0), (1, [-777], 0)], -777),
               ("second key of parent", [(0, [], 1), (2, [-775, -776], 0)], -776),
               ("climb two", [(0, [], 0), (0, [], 0), (1, [-778], 0)], -778),
               ("index past parent", [(0, [], 1), (1, [-773], 0), (1, [-774], 0)], -774),
               ("index past parent second", [(0, [], 1), (1, [-773], 1), (2, [-772, -771], 0)], -771))
    for name, levels, _ in empties:
        world = World()
        world.books[2] = (Tree(levels=levels), Tree([2]))
        rows.append(Case("bids %s" % name, "tops", world))
        world = World()
        world.books[2] = (Tree([-2]), Tree(levels=levels))
        rows.append(Case("asks %s" % name, "tops", world))
        for leg, field in (("bids", 0), ("asks", 1)):
            world = World()
            pair = [Tree([-61000000]), Tree([62000000])]
            pair[field] = Tree(levels=levels)
            world.books[2] = tuple(pair)
            rows.append(Case("leg %s %s" % (leg, name), "merged", world))
    for field, leg in ((0, "bids"), (1, "asks")):
        for name, tree in (("no root", Tree([-9, -8], null=True)), ("zero count", Tree([-9, -8], count=0)), ("walk past root", Tree(levels=[(0, [], 0)], count=5)), ("two levels past root", Tree(levels=[(0, [], 3), (2, [-1, -2], 0)], count=5)), ("one key", Tree([-(1 << 63)]) if field == 0 else Tree([1 << 62]))):
            pair = [Tree([-5000]), Tree([6000])]
            pair[field] = tree
            world = World()
            world.books[2] = tuple(pair)
            rows.append(Case("%s %s" % (leg, name), "tops", world))
            rows.append(Case("leg %s %s" % (leg, name), "merged", world))
    return rows


def leg_cases():
    rows = []
    for index, side, has, wanted, name in ((0, 0, 0, 0, "own"), (1, 1, 0, 0, "other"), (1, 2, 0, 0, "side 2"), (1, 0x81, 0, 0, "side high bit"), (0, 1, 0, 0, "first as other"), (0, 0, 1, 2, "wanted own"), (0, 1, 1, 2, "wanted own, side 1"),
                                            (1, 0, 1, 2, "wanted other"), (1, 1, 1, 3, "wanted own second"), (0, 0, 0x7700, 3, "low byte zero"), (0, 1, 0x7701, 3, "low byte one")):
        rows.append(Case("leg %s" % name, "leg", index=index, side=side, has=has, wanted=wanted))
    return rows


def error_cases():
    rows = []
    # own row
    for count, row in (("none", []), ("two", [2, 3])):
        world = World()
        world.rows[TOKEN_YES] = list(row)
        rows.append(Case("own row %s" % count, "merged", world))
        world = World()
        world.rows[TOKEN_NO] = list(row)
        rows.append(Case("second row %s" % count, "merged", world))
        rows.append(Case("first row bad, second turn bad", "merged", books_error(world, row)))
    world = World(row_count=TOKEN_YES)
    rows.append(Case("token past list", "merged", world))
    world = World(row_count=TOKEN_NO)
    rows.append(Case("token past list second", "merged", world))
    world = World(row_count=TOKEN_YES + 1)
    rows.append(Case("exact row bound", "merged", world, has=1, wanted=3))
    world = World(row_count=TOKEN_NO + 1)
    rows.append(Case("one past second row", "merged", world))
    rows.append(Case("book past slab", "merged", World(book_count=2)))
    rows.append(Case("book past slab second", "merged", World(book_count=3)))
    rows.append(Case("exact book bound", "merged", World(book_count=4)))
    # sibling failures, for a turn of book 3 and a turn of book 2
    def linked(**changes):
        return World(**changes)
    for name, world, has, wanted in (("list short", linked(list_len=3), 0, 0), ("list exact", linked(list_len=4), 0, 0), ("list short book 2", linked(list_len=2), 1, 3),
                                     ("no id", World(map_b={TOKEN_YES: RECORD_ID}), 0, 0), ("no id empty map", World(empty_b=True), 0, 0),
                                     ("same token", World(map_c={RECORD_ID: ((TOKEN_NO, VALUE), (TOKEN_NO, OTHER_VALUE))}), 0, 0), ("first differs", World(map_c={RECORD_ID: ((1, VALUE), (TOKEN_NO, OTHER_VALUE))}), 1, 2),
                                     ("second differs", World(map_c={RECORD_ID: ((TOKEN_NO, VALUE), (1, OTHER_VALUE))}), 0, 0),
                                     ("no record", World(map_b={TOKEN_YES: RECORD_ID, TOKEN_NO: 12}, map_c={RECORD_ID: ((TOKEN_YES, VALUE), (TOKEN_NO, OTHER_VALUE)), 13: ((1, 1), (2, 2))}), 0, 0)):
        rows.append(Case("sibling %s" % name, "merged", world, has=has, wanted=wanted))
        for bid, ask, side in ((0, 34000000, "ask only"), (30000000, 0, "bid only"), (0, 0, "empty")):
            changed = World(**{key: getattr(world, key) for key in ("map_b", "map_c", "list_len", "empty_b")})
            changed.books[3] = (Tree([-bid]) if bid else Tree(), Tree([ask]) if ask else Tree())
            changed.books[2] = (Tree([-bid]) if bid else Tree(), Tree([ask]) if ask else Tree())
            rows.append(Case("sibling %s %s" % (name, side), "merged", changed, has=has, wanted=wanted))
    # sibling row: the leg turned is book 3, the sibling token is 4
    for name, row, bid, ask in (("none", [], 30000000, 34000000), ("two", [2, 3], 30000000, 34000000), ("none ask only", [], 0, 34000000), ("two bid only", [2, 3], 30000000, 0)):
        world = books(b3=(bid, ask))
        world.rows[TOKEN_NO] = [3]
        world.map_c = {RECORD_ID: ((TOKEN_YES, VALUE), (TOKEN_NO, OTHER_VALUE)), 0: ((8, 1), (9, 2))}
        rows.append(Case("sibling row %s" % name, "merged", sibling_row_world(world, row), has=1, wanted=2))
    # no matching record for the merge
    rows.append(Case("merge no record", "merged", World(), record_id=11))
    rows.append(Case("merge empty map", "merged", World(empty_c=True)))
    rows.append(Case("merge split table", "merged", split=True))
    rows.append(Case("merge split table flipped", "merged", split=True, has=1, wanted=3))
    rows.append(Case("merge split sibling short", "merged", World(list_len=3), split=True))
    rows.append(Case("merge split row bound", "merged", World(row_count=TOKEN_NO), split=True))
    rows.append(Case("merge split book bound", "merged", World(book_count=3), split=True))
    rows.append(Case("merge empty map, nothing to turn", "merged", empty_turn(empty_c=True)))
    world = World(map_c={RECORD_ID: ((12, VALUE), (TOKEN_NO, OTHER_VALUE))})
    world.books[3] = (Tree(), Tree([34000000]))
    rows.append(Case("second turn token past rows", "leg", world, index=1, side=1))
    world = World(map_c={RECORD_ID: ((12, VALUE), (TOKEN_NO, OTHER_VALUE))})
    rows.append(Case("first turn token past rows", "leg", world, index=1, side=1))
    rows.append(Case("merge values high", "merged", value_world(MASK[8], MASK[8] - 2)))
    rows.append(Case("merge turn from top value", "merged", value_world(1 << 63, 1 << 63)))
    return rows


def empty_turn(**changes):
    """Book 3 is empty, so the turned leg never reaches the sibling lookup."""
    world = World(**changes)
    world.books[3] = (Tree(), Tree())
    return world


def books_error(world, row):
    changed = World()
    changed.rows[TOKEN_YES] = list(row)
    changed.books[3] = (Tree([-200000000]), Tree([34000000]))
    return changed


def sibling_row_world(world, row):
    """Book 2 stays the wanted book; the sibling of book 3 is token 4, whose row is changed after the leg of book 2 ran."""
    world.map_c = {RECORD_ID: ((TOKEN_NO, VALUE), (8, OTHER_VALUE))}
    world.rows[8] = list(row)
    world.spots = [1, 2, 8, TOKEN_NO, 6, 9, 7]
    world.map_b = {TOKEN_NO: RECORD_ID}
    return world


def value_world(first, second):
    world = World()
    world.map_c = {RECORD_ID: ((TOKEN_YES, first), (TOKEN_NO, second))}
    return world


def sibling_cases():
    rows = []
    for label, changes in table_worlds():
        for book in (2, 3):
            rows.append(Case("sibling %s book %d" % (label, book), "sibling", World(**changes), book=book))
        rows.append(Case("sibling %s no record" % label, "sibling", World(**changes), book=4))
        rows.append(Case("sibling %s no id" % label, "sibling", World(**changes), book=5))
    rows.append(Case("sibling list end", "sibling", World(list_len=3), book=3))
    rows.append(Case("sibling list exact", "sibling", World(list_len=4), book=3))
    rows.append(Case("sibling empty id map", "sibling", World(empty_b=True), book=3))
    rows.append(Case("sibling empty record map", "sibling", World(empty_c=True), book=3))
    rows.append(Case("sibling same token", "sibling", World(map_c={RECORD_ID: ((TOKEN_NO, VALUE), (TOKEN_NO, OTHER_VALUE))}), book=3))
    return rows


def classify_cases():
    rows = []
    for label, changes in table_worlds():
        for key in (2, TOKEN_YES, TOKEN_NO, 6, 9, 1):
            rows.append(Case("classify %s %d" % (label, key), "classify", World(**changes), key=key))
    rows.append(Case("classify first map empty", "classify", World(empty_a=True), key=2))
    rows.append(Case("classify first map empty, in second", "classify", World(empty_a=True, map_b={2: RECORD_ID}), key=2))
    rows.append(Case("classify second map empty", "classify", World(empty_b=True), key=TOKEN_YES))
    rows.append(Case("classify third map empty", "classify", World(empty_c=True), key=TOKEN_YES))
    rows.append(Case("classify in first and second", "classify", World(map_a={TOKEN_YES}), key=TOKEN_YES))
    return rows


def mid_cases():
    rows = []
    for spot in range(0, 7):
        rows.append(Case("mid spot %d" % spot, "mid", spot=spot))
    for label, changes in table_worlds():
        rows.append(Case("mid %s" % label, "mid", World(**changes), spot=2))
        rows.append(Case("mid %s second" % label, "mid", World(**changes), spot=3))
    rows.append(Case("mid list end", "mid", spot=7))
    rows.append(Case("mid exact list end", "mid", World(list_len=2), spot=2))
    rows.append(Case("mid book end", "mid", World(book_count=1), spot=1))
    rows.append(Case("mid first map book end", "mid", World(book_count=0), spot=0))
    rows.append(Case("mid exact book end", "mid", World(book_count=2), spot=1))
    rows.append(Case("mid plain book exact", "mid", World(book_count=1), spot=0))
    for bid, ask in ((0, 52), (50, 0), (0, 0), (7, 8), (7, 7), (9, 2)):
        rows.append(Case("mid plain %d %d" % (bid, ask), "mid", books(b0=(bid, ask)), spot=0))
    rows.append(Case("mid plain high", "mid", high_book(), spot=0))
    for name, b2, b3 in (("own only", (60000000, 65000000), (0, 0)), ("other only", (0, 0), (30000000, 34000000)), ("no bid", (0, 65000000), (0, 34000000)), ("no ask", (60000000, 0), (30000000, 0)), ("crossed", (60000000, 65000000), (30000000, 34000000)), ("empty", (0, 0), (0, 0)), ("odd", (61000001, 65000000), (0, 0)), ("zero turn", (61000000, 65000000), (0, VALUE + 3))):
        rows.append(Case("mid outcome %s" % name, "mid", books(b2=b2, b3=b3), spot=2))
        rows.append(Case("mid outcome second %s" % name, "mid", books(b2=b2, b3=b3), spot=3))
    rows.append(Case("mid outcome failed", "mid", books(b3=(VALUE + 5, 34000000)), spot=2))
    rows.append(Case("mid outcome high", "mid", value_world(MASK[8], MASK[8] - 2), spot=2))
    rows.append(Case("mid outcome no id map", "mid", World(empty_b=True), spot=2))
    return rows


def high_book():
    world = World()
    world.books[0] = (Tree([-(1 << 63)]), Tree([(1 << 63) - 1]))
    return world


def gate_cases():
    rows = []
    for word in (0xB7, 0x86, 0x286, 0x185, 0x187):
        rows.append(Case("gate word %#x" % word, "gate", word=word))
        rows.append(Case("gate word %#x, turn fails" % word, "gate", books(b3=(VALUE + 5, 0)), word=word))
        rows.append(Case("gate word %#x, tag 0" % word, "gate", word=word, tag=0))
    for tag in (1, 0, 2, 0x101):
        rows.append(Case("gate ok tag %#x" % tag, "gate", word=OK_WORD, tag=tag))
        rows.append(Case("gate ok tag %#x, fill" % tag, "gate", word=OK_WORD, tag=tag, fills=((3, 7),)))
    for book, name in ((2, "book 2"), (3, "book 3"), (77, "neither")):
        for prices, label in ((dict(b2=(60000000, 65000000), b3=(30000000, 34000000)), "fine"), (dict(b2=(VALUE + 1, 0), b3=(30000000, 34000000)), "book 2 over"), (dict(b2=(60000000, 65000000), b3=(0, OTHER_VALUE)), "book 3 at value")):
            rows.append(Case("gate fill %s %s" % (name, label), "gate", books(**prices), word=OK_WORD, fills=((book, 5),)))
            rows.append(Case("gate fills %s %s" % (name, label), "gate", books(**prices), word=OK_WORD, fills=((book, 5), (book ^ 1, 6), (book ^ 3, 8))))
    rows.append(Case("gate no fills, turn over", "gate", books(b3=(0, VALUE + 9)), word=OK_WORD))
    rows.append(Case("gate spot past list", "gate", spot=7))
    rows.append(Case("gate spot exact", "gate", World(list_len=3), spot=3))
    rows.append(Case("gate spot end", "gate", World(list_len=2), spot=2))
    rows.append(Case("gate plain spot", "gate", spot=0))
    rows.append(Case("gate plain spot ok", "gate", spot=0, word=OK_WORD))
    rows.append(Case("gate no record", "gate", spot=4))
    rows.append(Case("gate no record ok", "gate", spot=4, word=OK_WORD))
    rows.append(Case("gate no record ok, tag 0", "gate", spot=4, word=OK_WORD, tag=0))
    rows.append(Case("gate empty id map", "gate", World(empty_b=True)))
    rows.append(Case("gate empty id map, nothing to turn", "gate", empty_turn(empty_b=True)))
    rows.append(Case("gate no fills, first leg past value", "gate", books(b2=(OTHER_VALUE + 1, 0)), word=OK_WORD))
    rows.append(Case("gate split", "gate", split=True))
    rows.append(Case("gate split ok", "gate", split=True, word=OK_WORD, fills=((3, 1),)))
    rows.append(Case("gate split short", "gate", World(list_len=2), split=True))
    rows.append(Case("gate panic row", "gate", World(row_count=TOKEN_YES)))
    high = MASK[8]
    for name, fills in (("carry once", ((3, high), (3, 1), (2, 0))), ("carry twice", ((3, high), (3, 5), (2, 7), (2, 0))), ("no carry", ((3, high - 1), (3, 1))), ("zero", ((3, 0), (3, 0))), ("carry then one", ((3, high), (3, 5), (3, 1)))):
        rows.append(Case("gate sum %s" % name, "gate", word=OK_WORD, fills=fills))
        rows.append(Case("gate sum %s, tag 0" % name, "gate", word=OK_WORD, fills=fills, tag=0))
    for label, changes in table_worlds():
        rows.append(Case("gate %s" % label, "gate", World(**changes)))
    return rows


def all_cases():
    return classify_cases() + sibling_cases() + leg_cases() + tree_cases() + error_cases() + mid_cases() + gate_cases() + merged_cases()


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


def read_mid_sites(image, sites):
    """The two doubles each mid host loads right after the call: FF 15, then F2 0F 10 05 rip loads in 0x60 bytes."""
    rows = []
    for site in sites:
        window = bytes(image.blob[image.offset(site):image.offset(site) + 0x68])
        values = []
        at = window.find(b"\xf2\x0f\x10\x05")
        while 0 <= at < 0x60:
            target = site + at + 8 + struct.unpack_from("<i", window, at + 4)[0]
            values.append({"at": "%#x" % target, "value": struct.unpack_from("<d", image.blob, image.offset(target))[0]})
            at = window.find(b"\xf2\x0f\x10\x05", at + 1)
        rows.append({"site": "%#x" % site, "host": "%#x" % image.fde(site)[0], "doubles_after_call": values})
    return rows


def read_gate_sites(image, sites):
    """What each gate host does with the byte: `cmp al, imm8` then a near jne to a store of word 0x187."""
    rows = []
    for site in sites:
        after = bytes(image.blob[image.offset(site) + 6:image.offset(site) + 16])
        skip = 2 if after[:2] == b"\x89\xc3" else 0
        if after[skip:skip + 4] != b"\x3c\x27\x0f\x85":
            raise EvidenceError("gate site bytes at %#x" % site)
        arm = site + 6 + skip + 8 + struct.unpack_from("<i", after, skip + 4)[0]
        window = bytes(image.blob[image.offset(arm):image.offset(arm) + 0x40])
        at = window.find(b"\x87\x01")
        store = at >= 3 and 0x66 in window[max(at - 5, 0):at]
        rows.append({"site": "%#x" % site, "host": "%#x" % image.fde(site)[0], "compare": "cmp al, 0x27", "arm": "%#x" % arm, "byte_kept_in_ebx": bool(skip), "word_0x187_bytes_at": "%#x" % (arm + at) if store else None})
    return rows


def read_hash_check(harness):
    """The real 0x399c4a0 against the SipHash-1-3 written in the specification."""
    machine = harness.machine
    rows = []
    for k0, k1, word in ((0, 0, 0), (1, 2, 3), (0x0123456789ABCDEF, 0xFEDCBA9876543210, 4), (MASK[8], MASK[8], MASK[8])):
        machine.memory.reset(BUMP - HEAP_BASE)
        machine.memory.put_bytes(ARG, struct.pack("<QQQ", k0, k1, word))
        real = machine.run(HASH, {RDI: ARG, RSI: ARG + 0x10})
        written = siphash13(k0, k1, word)
        if real != written:
            raise EvidenceError("hash differs for %#x" % word)
        rows.append({"k0": "%#x" % k0, "k1": "%#x" % k1, "key": "%#x" % word, "hash": "%#x" % real})
    return rows


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


GROUPS = ((MERGED, "merged top"), (LEG, "one leg"), (SIBLING, "sibling record"), (CLASSIFY, "spot class"), (TOPS, "plain top pair"), (MID, "mid"), (GATE, "post-insert gate"))


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
    {"reference": "l1/books.rs:613", "claim": "mid_px is (bid & ask) + ((bid ^ ask) >> 1) when both sides exist", "observed": "the same two-word formula at 0x3730c03 and at 0x3730d38, with 0 standing for an absent side", "verdict": "match for class 0 spots; the reference has no outcome arm"},
    {"reference": "l1/spot_clearinghouse/impl_outcome.rs:135", "claim": "SpotOutcomeMarket carries token_a and token_b, and no book read turns one into the other", "observed": "0x3c01010 reads the sibling record value and returns value - ask, value - bid", "verdict": "body absent from the reference"},
    {"reference": "l1/book/book/mod.rs:171", "claim": "InsertOutcome and RemoveOutcome are the book results; neither is the word 0x187", "observed": "hosts of 0x372a0f0 replace the insert result with word 0x187 and the gate byte", "verdict": "absent"},
)
FIELDS = {
    "holder": {"+0x10": "owner block O, the first argument of 0x3728670", "+0x178/+0x180": "spot list seen from the holder: O+0x168/+0x170"},
    "owner": {"+0x40/+0x48/+0x58/+0x60": "first map: control, mask, items, hash keys; stride 0x20; key is the spot word",
              "+0x70/+0x78/+0x88/+0x90": "second map, stride 0x10: spot word to id at entry +8",
              "+0xd0/+0xd8/+0xe8/+0xf0": "third map, stride 0x90: id to entry",
              "+0x168/+0x170": "spot list, stride 0x20, word +0", "+0x180/+0x188": "token rows, stride 0xe8"},
    "entry_0x90": {"+0x00": "id", "+0x08": "first record, 0x28 bytes", "+0x30": "second record, 0x28 bytes"},
    "record_0x28": {"+0x18": "value", "+0x20": "token"},
    "token_row": {"+0x58/+0x60": "book list: pointer, length; a leg reads only when the length is 1"},
    "book": {"stride": "0xd8", "+0x80": "bid side: root, height, length", "+0x98": "ask side: root, height, length"},
    "side_node": {"+0x160": "parent", "+0x168": "signed keys", "+0x1c0": "index in parent", "+0x1c2": "length", "+0x1c8": "edges", "leaf_size": "0x1c8", "inner_size": "0x228"},
    "slab_view": {"+0x08/+0x10": "book pointer, length"},
    "gate_order": {"+0x00": "dword tested against 1", "+0x28": "spot index"},
    "gate_result": {"+0x00": "word; 0x186 takes the fill arm", "+0x10/+0x18": "fills: pointer, count"},
    "fill_0x228": {"+0x1f8": "book of the fill", "+0x200": "amount, summed and dropped"},
}
SHUFFLE = "pshufd 0x44 with one bit changed: the four dwords of the byte pattern are all equal, so the result is the same"
EIGHT = "cmp with 8 changed to 9: a count of exactly 8 has low bits 0 and takes the other path, so no count separates the two"
CLASS_TWO = "class 2 already found this word in the second map, so its item count is not 0 here"
REASONS = {0x3727152: SHUFFLE, 0x372731C: SHUFFLE, 0x37273E3: SHUFFLE, 0x37286B7: SHUFFLE, 0x3728764: SHUFFLE, 0x372882B: SHUFFLE, 0x3730C6E: SHUFFLE, 0x372A170: SHUFFLE,
           0x3C010D5: EIGHT, 0x3C011D5: EIGHT, 0x3C18BC5: EIGHT, 0x3C18CA5: EIGHT, 0x3730C2D: CLASS_TWO}
REASON_RANGES = ()


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "no case in the list separates this mutant; no claim rests on this row")


def outcome_name(case, spec):
    if spec["stop"]:
        return "%s: stop %s" % (case.kind, spec["stop"][0])
    answer = spec["answer"]
    if isinstance(answer, tuple) and answer and isinstance(answer[0], str):
        return "%s: %s" % (case.kind, answer[0]) if answer[0] != "err" else "%s: err %d" % (case.kind, answer[1])
    if case.kind == "gate" or case.kind == "classify":
        return "%s: byte %#x" % (case.kind, answer)
    return "%s: value" % case.kind


def turn_rows(harness):
    """Real runs of the second leg turned: bid and ask of its book against the sibling value."""
    rows = []
    edges = (0, 1, VALUE - 1, VALUE, VALUE + 1, OTHER_VALUE)
    for bid in edges:
        for ask in edges:
            run = harness.run(Case("turn", "leg", books(b3=(bid, ask)), index=1, side=1))
            answer = run["answer"]
            rows.append((bid, ask, VALUE, answer[0], answer[1], answer[2] if answer[0] == "ok" else ""))
    return rows


def worked_run(harness):
    """Book 2 is 0.60/0.65 and book 3 is 0.30/0.34 of a value of 1e8."""
    world = books(b2=(60000000, 65000000), b3=(30000000, 34000000))
    frames = {}
    for name, case in (("first side frame", Case("worked", "merged", world, has=1, wanted=2)), ("second side frame", Case("worked", "merged", world, has=1, wanted=3)), ("side flag", Case("worked", "merged", world))):
        frames[name] = list(harness.run(case)["answer"])
    frames["mid of spot 2"] = harness.run(Case("worked", "mid", world, spot=2))["answer"]
    frames["mid of spot 3"] = harness.run(Case("worked", "mid", world, spot=3))["answer"]
    return {"values": [VALUE, OTHER_VALUE], "book_2": [60000000, 65000000], "book_3": [30000000, 34000000], "results": frames}


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harness = Harness(image)
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    machine = harness.machine
    for case in cases:
        machine.seen = set()
        trouble = compare_run(harness, case)
        if trouble:
            mismatches.append(trouble)
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        name = outcome_name(case, spec_run(case))
        outcomes[name] = outcomes.get(name, 0) + 1
    steps = machine.steps
    worked = worked_run(harness)
    turns = turn_rows(harness)
    hash_check = read_hash_check(harness)
    functions = []
    for start, role in GROUPS + ((HASH, "SipHash of one u64"), (HASH_WRITE, "hasher write")):
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = harness.relative
    slots = {SLOT_MERGED: MERGED, SLOT_CLASSIFY: CLASSIFY, SLOT_MID: MID, SLOT_GATE: GATE}
    for slot, value in slots.items():
        if relative.get(slot) != value:
            raise EvidenceError("slot %#x" % slot)
    site_rows = []
    for slot, value in sorted(slots.items()):
        for va in slot_sites(image, slot):
            site_rows.append((value, va, "slot %#x" % slot, image.fde(va)[0], image.fde(va)[1]))
    direct = direct_sites(image, (LEG, SIBLING, TOPS))
    for target in sorted(direct):
        for va, opcode in sorted(direct[target]):
            site_rows.append((target, va, "rel32 %#x" % opcode, image.fde(va)[0], image.fde(va)[1]))
    locations = []
    for slot, name in sorted(LOCATION_NAMES.items()):
        path, line, column = image.location(slot, relative)
        locations.append({"slot": "%#x" % slot, "name": name, "path": path, "line": line, "column": column})
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    mid_sites = read_mid_sites(image, slot_sites(image, SLOT_MID))
    gate_sites = read_gate_sites(image, slot_sites(image, SLOT_GATE))
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "slots": {"%#x" % slot: "%#x" % value for slot, value in sorted(slots.items())},
        "mid_sites": mid_sites,
        "gate_sites": gate_sites,
        "hash_check": hash_check,
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
        "_sites": site_rows, "_results": results_rows, "_turns": turns,
    }


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    turns = evidence.pop("_turns")
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    lines = ["target\tsite\tcall\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%s\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    lines = ["bid\task\tsibling_value\tresult\tfirst\tsecond"]
    lines += ["%d\t%d\t%d\t%s\t%s\t%s" % row_ for row_ in turns]
    files["turn.tsv"] = "\n".join(lines) + "\n"
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
