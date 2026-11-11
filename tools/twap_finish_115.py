#!/usr/bin/env python3
"""Rebuild the node #115 TWAP finish step (take the order out of the tracker, build the status event, push it) and prove it.

Four finish callees (perp 0x5a17dd0 / 0x5a18190, spot 0x5a18550 / 0x5a18840) are what the advance step hands a completed
order to. Each calls a take function (0x5a10250 perp, 0x5a10560 spot) that removes the order from the user's order ring
(and removes the user record itself once its ring is empty), then builds a status record from the taken order and pushes a
0x2b8 / 0x2c8 byte event with tag 4 onto the output vector. The real bytes of the four finish callees and the two take
functions run in a Python x86-64 evaluator with only the deeper edges stubbed (precheck, ring searches, order and user
removal, the four status builders, free, memcpy and the vector grow). A separately written specification predicts every stub
call, the pushed event bytes and the tracker afterwards. Conditions are then flipped on the bytes to show that the comparison
can fail. No disassembler or ELF dump text is parsed and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import fractions
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

PERP, SPOT = "perp", "spot"
# slice body, advance callee, family
COPIES = (
    dict(slice=0x5A305E0, advance=0x5A145D0, family=PERP, markets=0x7C8, count=0x7D0),
    dict(slice=0x5A33760, advance=0x5A13910, family=PERP, markets=0x1338, count=0x1340),
    dict(slice=0x5A31640, advance=0x5A13F70, family=SPOT),
    dict(slice=0x5A32BE0, advance=0x5A14C30, family=SPOT),
)
PERP_TICK = 0x5A01110
SPOT_TICK = 0x5A01310
SPOT_MID = 0x3C11290
LOOKUP_USER = 0x57F4AC0
LOOKUP_ORDER = 0x57F36B0
BOOK_TOP = 0x46DF820
DROP_ERROR = 0x44E0810
ROUND = 0x63EFE40
FLOOR = 0x63EFFE0
FMA = 0x63F0210
RECORDER = 0x4524E40
CALL_ONCE = 0x5C87D50
PANIC_UNWRAP = 0x1680C30
PANIC_INDEX = 0x1680CBF
ONCE_STATE = 0x64F01D8
ONCE_VALUE = 0x64F01C0
ONCE_VTABLE = 0x63FE250
ONCE_LOCATION = 0x63FE278
LOCATION_MARKET = 0x648B990
LOCATION_BOOKS = 0x647DC08
LOCATION_SZ = 0x64B7FC8
UNWRAP_SIZE = 0x2B
ERROR_WORD = 0x156
DIVISOR = 10000
MARKET_STRIDE = 0x510
BOOK_STRIDE = 0x120
BOOK_TOP_FIELD = 0xA8
MARKETS_FIELD = 0x7C8
COUNT_FIELD = 0x7D0
SPOT_MID_FIELD = 0x80
SPOT_TICK_FIELD = 0x90
BUCKET_SECONDS = 60.0
THRESHOLDS = {PERP: dict(whole=30000000, floor=12000000), SPOT: dict(whole=3000000000, floor=1200000000)}
JITTER_MODULUS = 40
CATCH_UP = 3
SIG_FIGS = 5
SLICE_SIZE = 0x70
USER_STRIDE = 0x38
ORDER_STRIDE = 0x70
BTREE_TAG = 0x8000000000000000

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
STEP_LIMIT = 300000
MUTANT_STEP_LIMIT = 8000
FAKE_MEMCMP = 0x7E000000



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
        if two == 0x13 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
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


# ---- node #115 finish step: coordinates ----

H = HEAP_BASE
OUTER, TRACKER, REASON, USER_AT, VEC_AT = H + 0x400, H + 0xC00, H + 0x500, H + 0x540, H + 0x600
MARKETS, USERS, ORDERS, VECTOR, FREED = H + 0x10000, H + 0x20000, H + 0x24000, H + 0x30000, H + 0x3F000
USED = 0x38000
SYNTHETIC = 0x7D000000
TREE_BASE = H + 0x50000
NODE_SIZE = 0x2A8
USER_STRIDE = 0x38
MARKET_STRIDE = 0x510
BODY = 0x68
PAYLOAD = 0x58
ERROR_CODE = 0xD4
TEMP_WORD = 0x156
DIVISOR = 10000
TAG_PERP = ("perp", "spot")
TREE = BTREE_TAG
NO_USER = 0x8000000000000001
EVENT_SIZE = {PERP: 0x2B8, SPOT: 0x2C8}
EVENT_PREFIX = 0xC0
BOOK_AT = 0x90

# finish callee, take function, family, markets/count offsets (perp), builder when the tag selects, builder otherwise,
# vector grow slot, precheck, user search, order removal, user removal
FINISH = (
    dict(finish=0x5A17DD0, take=0x5A10250, family=PERP, markets=0x7C8, count=0x7D0, yes="5182b60", no="5181da0"),
    dict(finish=0x5A18190, take=0x5A10250, family=PERP, markets=0x1338, count=0x1340, yes="5182b60", no="5181da0"),
    dict(finish=0x5A18550, take=0x5A10560, family=SPOT, markets=None, count=None, yes="5182640", no="51821b0"),
    dict(finish=0x5A18840, take=0x5A10560, family=SPOT, markets=None, count=None, yes="5182640", no="51821b0"),
)
TAKE = {
    PERP: dict(take=0x5A10250, precheck=0x5A11B80, remove_order=0x4DDFA30, remove_user=0x4DDDF70),
    SPOT: dict(take=0x5A10560, precheck=0x5A11970, remove_order=0x4DDE450, remove_user=0x4DDFDC0),
}
BUILDERS = {"5182b60": 0x5182B60, "5181da0": 0x5181DA0, "5182640": 0x5182640, "51821b0": 0x51821B0}
USER_SEARCH = 0x57F4AC0
DROP_ERROR, DROP_TEMP, DROP_TREE = 0x5A4A6F0, 0x44E0810, 0x5248950
SLOT_FREE, SLOT_COPY, SLOT_EXPECT, SLOT_COMPARE = 0x64DF4A0, 0x64DF508, 0x64DF6A0, 0x64DFB50
SLOT_GROW = {PERP: 0x64E5A28, SPOT: 0x64E4F88}
LANDING = (0x5A3E1D0, 0x5A40AE0)

BYTE_PINS = (
    (0x5A17F3A, bytes.fromhex("48b84b598638d6c56d34"), "quotient by 10000, magic multiplier"),
    (0x5A17F59, bytes.fromhex("4869ea10050000"), "perp market stride 0x510"),
    (0x5A180C7, bytes.fromhex("4869fbb8020000"), "perp event size 0x2b8"),
    (0x5A187D1, bytes.fromhex("4969fec8020000"), "spot event size 0x2c8"),
    (0x5A1053B, bytes.fromhex("486bf070"), "freed order ring element size 0x70"),
    (0x5A103E6, bytes.fromhex("486bca38"), "user record stride 0x38"),
    (0x5A17F68, bytes.fromhex("66c78424100200005601"), "temporary word 0x156"),
    (0x5A1830B, bytes.fromhex("493b942440130000"), "copy 2 market count offset 0x1340"),
    (0x5A18320, bytes.fromhex("4903ac2438130000"), "copy 2 market buffer offset 0x1338"),
)


def lcg(variant):
    state = (variant * 0x9E3779B97F4A7C15 + 0x1234567) & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 16


def user_id(number):
    return bytes((number * 37 + index * 11 + 5) & 0xFF for index in range(20))


def phys(ring):
    capacity, head, length, index = ring
    at = index + head
    return at - capacity if at >= capacity else at


def signed64(value):
    return value - (1 << 64) if value & SIGN[8] else value


def pattern(salt, count):
    return bytes((salt * 31 + at * 13 + 7) & 0xFF for at in range(count))


def builder_output(name, record, argument):
    """The stub's deterministic 0x78 byte status record: the same function drives the stub and the specification."""
    material = hashlib.sha256(b"%s|%d|" % (name.encode(), argument) + record).digest()
    material += hashlib.sha256(material + b"2").digest() + hashlib.sha256(material + b"3").digest() + hashlib.sha256(material + b"4").digest()
    return material[:0x78]


class FinCase:
    def __init__(self, label, **options):
        self.label = label
        self.family = PERP
        self.user = 3
        self.oid = 77
        self.users = (5, 2, 3, 1)
        self.user_state = "found"       # found | absent | past | tree
        self.orders = (4, 1, 3)
        self.removal = "found"          # found | none
        self.side = 0
        self.after_len = 2
        self.user_free = 0              # word written by the user removal: 0, NO_USER, TREE, or a capacity
        self.pre = "ok"                 # ok | alt
        self.pre_tag = 0
        self.asset = 2 * DIVISOR + 5
        self.decoy = 5 * DIVISOR + 1
        self.count = 4
        self.reason_cap = TREE | 2
        self.vec = (4, 1)
        self.now = (0x12345678, 3600, 123456789)
        self.tree = (0, 5, 0)           # height, keys per leaf, separators in the root (height 1)
        self.user_in_tree = True
        self.tree_pos = 0
        for key, value in options.items():
            setattr(self, key, value)

    def body(self):
        out = bytearray(pattern(self.oid, BODY))
        struct.pack_into("<Q", out, 0, self.asset)
        struct.pack_into("<Q", out, 0x10, self.decoy)
        out[0x22] = self.side
        return bytes(out)

    def tree_nodes(self):
        """The user tree as a list of nodes: sorted 20-byte keys and child node numbers (node 0 is the root)."""
        height, per_leaf, separators = self.tree
        total = per_leaf if height == 0 else (separators + 1) * per_leaf + separators
        keys = [user_id((self.user + 7 * step + 3) % 256) for step in range(1, total + 1)]
        if self.user_in_tree and total:
            keys[self.tree_pos % total] = user_id(self.user)
        keys.sort()
        if height == 0:
            return [dict(keys=keys, children=[])]
        root = [keys[(per_leaf + 1) * index + per_leaf] for index in range(separators)]
        nodes = [dict(keys=root, children=list(range(1, separators + 2)))]
        for index in range(separators + 1):
            nodes.append(dict(keys=keys[(per_leaf + 1) * index:(per_leaf + 1) * index + per_leaf], children=[]))
        return nodes

    def alt_payload(self):
        out = bytearray(pattern(self.oid + 9, PAYLOAD))
        struct.pack_into("<Q", out, 0, self.decoy)
        struct.pack_into("<Q", out, 0x10, self.asset)
        out[8] = self.pre_tag
        return bytes(out)


def moment_bytes(moment):
    return struct.pack("<III", *(value & MASK[4] for value in moment))


def spec_finish(case, variant=""):
    """Prediction of the finish step: stub calls in order, the pushed event, the vector and the order ring length."""
    user = user_id(case.user)
    events = []
    result = dict(events=events, ring_len=case.orders[2])
    capacity, head, length, position = case.users
    reason_free = lambda: signed64(case.reason_cap) > 0 or (variant == "free_reason_nonneg" and case.reason_cap == 0)
    if variant == "free_reason_always":
        reason_free = lambda: case.reason_cap != 0
    failed = False
    tag = 1
    record = None
    if variant == "precheck_after_find":
        events.append(("find user", 0x18, user))
    events.append(("precheck", 0, user))
    if case.pre != "ok":
        tag = 0
        record = case.alt_payload() + bytes([STACK_MARK]) * (BODY - PAYLOAD)
    else:
        found_at = None
        if case.user_state == "tree":
            nodes = case.tree_nodes()
            node, levels = 0, case.tree[0]
            while True:
                keys = nodes[node]["keys"]
                index = len(keys)
                for position, key in enumerate(keys):
                    events.append(("compare", key))
                    if user > key and variant != "compare_reversed":
                        continue
                    if user < key and variant == "compare_reversed":
                        continue
                    index = position
                    if user == key:
                        found_at = ("tree", node, position)
                    break
                if found_at is not None or levels == 0:
                    break
                levels -= 1
                node = nodes[node]["children"][index]
            failed = found_at is None
        else:
            if variant != "precheck_after_find":
                events.append(("find user", 0x18, user))
            failed = case.user_state == "absent" or (case.user_state == "past" and variant != "past_accepted")
            if not failed:
                found_at = phys(case.users) if variant != "no_wrap" else case.users[3] + case.users[1]
        if failed:
            pass
        else:
            events.append(("remove order", found_at, case.oid))
            if case.removal == "none":
                failed = True
            else:
                result["ring_len"] = case.after_len
                empty = case.after_len == 0
                if variant == "remove_user_always":
                    empty = True
                if variant == "no_remove_user":
                    empty = False
                if empty:
                    events.append(("remove user", 0x18, user))
                    word = case.user_free
                    if word == TREE:
                        events.append(("drop tree", FREED))
                    elif word == 0 or (word == NO_USER and variant != "none_freed"):
                        pass
                    else:
                        stride = 0x68 if variant == "free_stride_68" else 0x70
                        events.append(("free", FREED, (word * stride) & MASK[8], 0))
                record = case.body()
    if failed:
        events.append(("drop error", ERROR_CODE if variant != "error_code" else ERROR_CODE + 1))
        if reason_free():
            events.append(("free", 0x50000, case.reason_cap, 0))
        return result
    family = case.family
    select = tag & 1
    if family == PERP:
        word = struct.unpack_from("<Q", record, 0 if select else 0x10)[0]
        if variant == "asset_word_swapped":
            word = struct.unpack_from("<Q", record, 0x10 if select else 0)[0]
        index = word // (1000 if variant == "market_div_1000" else DIVISOR)
        outside = index > case.count if variant == "bounds_inclusive" else index >= case.count
        if outside:
            result["stop"] = "expect"
            return result
        argument = index
    else:
        select = 1 if tag == 1 else 0
        argument = BOOK_AT if variant != "spot_book_offset" else BOOK_AT + 8
    if family == PERP and variant != "no_drop_temp":
        events.append(("drop temp", TEMP_WORD))
    row = FINISH[0] if family == PERP else FINISH[2]
    names = (row["yes"], row["no"])
    if variant == "builder_swapped":
        names = names[::-1]
    name = names[0] if select else names[1]
    events.append(("build", name, record, argument))
    out = builder_output(name, record, argument)
    events.append(("copy", 0x90))
    reason = struct.pack("<QQQ", case.reason_cap, 0x50000, 0x20)
    cap, filled = case.vec
    if filled == cap:
        if variant != "grow_missing":
            events.append(("grow", cap))
        cap = max(2 * cap, 4)
    events.append(("copy", EVENT_SIZE[family]))
    tail = (moment_bytes(case.now), user)
    if variant == "oid_user_swapped":
        event = struct.pack("<Q", 4) + out + reason + user + struct.pack("<Q", case.oid) + tail[0]
        event = event[:EVENT_PREFIX]
    else:
        event = struct.pack("<Q", 5 if variant == "event_tag" else 4) + out + reason + struct.pack("<Q", case.oid) + tail[0] + tail[1]
    result["vec"] = (cap, filled + 1)
    result["event"] = event
    return result


class FinishHarness:
    def __init__(self, image, patches=None):
        self.image = image
        self.machine = Machine(image, patches)
        self.machine.step_limit = STEP_LIMIT if not patches else MUTANT_STEP_LIMIT
        machine = self.machine
        relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        slots = {SLOT_FREE: self.on_free, SLOT_COPY: self.on_copy, SLOT_EXPECT: self.on_expect, SLOT_COMPARE: self.on_compare,
                 SLOT_GROW[PERP]: self.on_grow, SLOT_GROW[SPOT]: self.on_grow}
        # imported functions (free, memcpy, ...) have no RELATIVE addend: they get a synthetic target per slot
        target = {slot: relative.get(slot, SYNTHETIC + slot) for slot in slots}
        for slot in slots:
            machine.memory.statics[slot] = target[slot]
        machine.slots = {target[slot]: hook for slot, hook in slots.items()}
        machine.real = frozenset(row["take"] for row in FINISH)
        calls = {USER_SEARCH: self.on_find_user, DROP_ERROR: self.on_drop_error, DROP_TEMP: self.on_drop_temp, DROP_TREE: self.on_drop_tree}
        for family, row in TAKE.items():
            calls[row["precheck"]] = self.on_precheck
            calls[row["remove_order"]] = self.on_remove_order
            calls[row["remove_user"]] = self.on_remove_user
        for name, va in BUILDERS.items():
            calls[va] = (lambda machine, name=name: self.on_build(machine, name))
        machine.calls = calls
        self.events = []

    def word(self, at, value):
        self.machine.memory.write(at, 8, value & MASK[8])

    def run_finish(self, index, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        self.events = []
        self.case = case
        row = FINISH[index]
        capacity, head, length, position = case.users
        words = (TREE if case.user_state == "tree" else capacity, USERS, head, length)
        if case.user_state == "tree":
            words = (TREE, TREE_BASE, case.tree[0], 0)
            self.write_tree(case)
        for slot, value in enumerate(words):
            self.word(TRACKER + 0x18 + slot * 8, value)
        for slot in range(capacity):
            memory.put_bytes(USERS + slot * USER_STRIDE, pattern(slot + 40, USER_STRIDE))
        entry = USERS + phys(case.users) * USER_STRIDE if capacity else USERS
        ocap, ohead, olen = case.orders
        for slot, value in enumerate((ocap, ORDERS, ohead, olen)):
            self.word(entry + 0x18 + slot * 8, value)
        self.order_ring = entry + 0x18
        self.touched = None
        memory.put_bytes(USER_AT, user_id(case.user))
        memory.put_bytes(OUTER + 0x60, moment_bytes(case.now))
        if row["family"] == PERP:
            self.word(OUTER + row["markets"], MARKETS)
            self.word(OUTER + row["count"], case.count)
        memory.put_bytes(REASON, struct.pack("<QQQ", case.reason_cap, 0x50000, 0x20))
        cap, filled = case.vec
        memory.put_bytes(VEC_AT, struct.pack("<QQQ", cap, VECTOR, filled))
        out = {}
        try:
            machine.run(row["finish"], {RDI: TRACKER, RSI: USER_AT, RDX: case.oid, RCX: REASON, R8: OUTER, R9: VEC_AT})
        except Panicked as stop:
            out["stop"] = stop.args[0]
        out["events"] = self.events
        cap, _, length_after = struct.unpack("<QQQ", memory.bytes_at(VEC_AT, 24))
        if "stop" not in out:
            if length_after != filled:
                out["vec"] = (cap, length_after)
                size = EVENT_SIZE[row["family"]]
                out["event"] = memory.bytes_at(VECTOR + filled * size, EVENT_PREFIX)
            ring_len = memory.read((self.touched or self.order_ring) + 0x18, 8)
            out["ring_len"] = ring_len
        return out

    def write_tree(self, case):
        memory = self.machine.memory
        ocap, ohead, olen = case.orders
        for number, node in enumerate(case.tree_nodes()):
            base = TREE_BASE + number * NODE_SIZE
            memory.put_bytes(base, bytes([STACK_MARK]) * NODE_SIZE)
            for index in range(len(node["keys"])):
                memory.put_bytes(base + 0x168 + 0x14 * index, node["keys"][index])
                memory.put_bytes(base + 0x20 * index, struct.pack("<QQQQ", ocap, ORDERS, ohead, olen))
            memory.write(base + 0x246, 2, len(node["keys"]))
            for index, child in enumerate(node["children"]):
                self.word(base + 0x248 + 8 * index, TREE_BASE + child * NODE_SIZE)

    # -- stubs, a stub never looks at the case beyond what the function it stands for would have been given --

    def on_precheck(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("precheck", regs[RSI] - TRACKER, memory.bytes_at(regs[RDX], 20)))
        if self.case.pre == "ok":
            memory.write(regs[RDI] + 8, 1, 2)
        else:
            memory.put_bytes(regs[RDI], self.case.alt_payload())

    def on_find_user(self, machine):
        regs = machine.regs
        self.events.append(("find user", regs[RDI] - TRACKER, machine.memory.bytes_at(regs[RSI], 20)))
        machine.keep_rdx = True
        machine.regs[RAX] = 1 if self.case.user_state == "absent" else 0
        machine.regs[RDX] = self.case.users[3] if self.case.user_state != "past" else self.case.users[2] + 2

    def on_remove_order(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.touched = regs[RSI]
        if TREE_BASE <= regs[RSI] < TREE_BASE + 8 * NODE_SIZE:
            node, rest = divmod(regs[RSI] - TREE_BASE, NODE_SIZE)
            where = ("tree", node, rest // 0x20) if rest % 0x20 == 0 else -1
        else:
            slot, rest = divmod(regs[RSI] - 0x18 - USERS, USER_STRIDE)
            where = slot if rest == 0 else -1
        self.events.append(("remove order", where, memory.read(regs[RDX], 8)))
        body = bytearray(self.case.body())
        body[0x22] = 2 if self.case.removal == "none" else self.case.side
        memory.put_bytes(regs[RDI], bytes(body))
        if self.case.removal != "none":
            memory.write(regs[RSI] + 0x18, 8, self.case.after_len)

    def on_remove_user(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.events.append(("remove user", regs[RSI] - TRACKER, memory.bytes_at(regs[RDX], 20)))
        memory.write(regs[RDI], 8, self.case.user_free)
        memory.write(regs[RDI] + 8, 8, FREED)

    def on_drop_tree(self, machine):
        self.events.append(("drop tree", machine.memory.read(machine.regs[RDI], 8)))

    def on_drop_error(self, machine):
        self.events.append(("drop error", machine.memory.read(machine.regs[RDI], 2)))

    def on_drop_temp(self, machine):
        self.events.append(("drop temp", machine.memory.read(machine.regs[RDI], 2)))

    def on_build(self, machine, name):
        regs = machine.regs
        memory = machine.memory
        record = memory.bytes_at(regs[RSI], BODY)
        if regs[RDX] == OUTER + BOOK_AT:
            argument = BOOK_AT
        else:
            index, rest = divmod(regs[RDX] - MARKETS, MARKET_STRIDE)
            argument = index if rest == 0 else -1
        self.events.append(("build", name, record, argument))
        memory.put_bytes(regs[RDI], builder_output(name, record, argument))

    def on_free(self, machine):
        regs = machine.regs
        self.events.append(("free", regs[RDI], regs[RSI], regs[RDX]))

    def on_copy(self, machine):
        regs = machine.regs
        self.events.append(("copy", regs[RDX]))
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])

    def on_grow(self, machine):
        memory = machine.memory
        regs = machine.regs
        cap = memory.read(regs[RDI], 8)
        self.events.append(("grow", cap))
        memory.write(regs[RDI], 8, max(2 * cap, 4))

    def on_expect(self, machine):
        raise Panicked("expect")

    def on_compare(self, machine):
        regs = machine.regs
        memory = machine.memory
        left, right = memory.bytes_at(regs[RDI], 20), memory.bytes_at(regs[RSI], 20)
        self.events.append(("compare", right))
        machine.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]


# ---- cases ----

NOWS = ((0x12345678, 3600, 123456789), (0, 0, 0), (0xFFFFFFFF, 86399, 999999999), (1 << 31, 1, 2))
RINGS = ((5, 2, 3, 1), (5, 4, 3, 2), (5, 3, 3, 0), (4, 3, 4, 3), (8, 7, 5, 4), (1, 0, 1, 0), (6, 5, 2, 1), (3, 2, 2, 0), (7, 0, 6, 5))
ORDER_RINGS = ((4, 1, 3), (5, 4, 5), (1, 0, 1), (9, 8, 2), (6, 0, 6))
FREE_WORDS = (0, NO_USER, TREE, 1, 7, 0x4000000000000000)
REASONS = (TREE | 2, TREE, 0, 1, 24, 0x7FFFFFFFFFFFFFFF, MASK[8], 0x40)
ASSETS = (0, 9999, 10000, 10001, 3 * DIVISOR + 77, 19999, 7 * DIVISOR, 0xFFFFFFFFFFFFFFFF, (1 << 40) + 3, 4 * DIVISOR + 9999)


def named_cases():
    rows = []

    def add(label, **options):
        rows.append(FinCase(label, **options))

    add("order taken, user keeps orders")
    add("order taken, ring emptied: user removed, freed", after_len=0, user_free=3)
    add("ring emptied, user removal word zero", after_len=0, user_free=0)
    add("ring emptied, user removal word no-user", after_len=0, user_free=NO_USER)
    add("ring emptied, user removal word tree", after_len=0, user_free=TREE)
    add("ring emptied, capacity above 2^62", after_len=0, user_free=0x4000000000000000)
    add("order not found", removal="none")
    add("order not found, reason with capacity", removal="none", reason_cap=24)
    add("order not found, reason capacity zero", removal="none", reason_cap=0)
    add("user absent", user_state="absent")
    add("user position past the length", user_state="past")
    add("tree, one leaf, user present", user_state="tree", tree=(0, 5, 0), user=3)
    add("tree, one leaf, user absent", user_state="tree", tree=(0, 5, 0), user_in_tree=False, user=4)
    add("tree, user first key", user_state="tree", tree=(0, 7, 0), tree_pos=0, user=5)
    add("tree, user last key", user_state="tree", tree=(0, 7, 0), tree_pos=6, user=6)
    add("tree, root and leaves, user in a leaf", user_state="tree", tree=(1, 4, 3), tree_pos=5, user=9)
    add("tree, root and leaves, user in the root", user_state="tree", tree=(1, 4, 3), tree_pos=4, user=10)
    add("tree, root and leaves, user absent", user_state="tree", tree=(1, 4, 3), user_in_tree=False, user=11)
    add("tree, root and leaves, last leaf", user_state="tree", tree=(1, 3, 4), tree_pos=18, user=12)
    add("tree, emptied ring removes the user", user_state="tree", tree=(1, 4, 2), tree_pos=2, after_len=0, user_free=5, user=13)
    add("tree, empty root", user_state="tree", tree=(0, 0, 0), user_in_tree=False, user=14)
    add("precheck rejects, alt record", pre="alt")
    add("precheck rejects, alt tag 1", pre="alt", pre_tag=1)
    add("precheck rejects, alt tag 3", pre="alt", pre_tag=3)
    add("asset index equals the count", asset=4 * DIVISOR, count=4)
    add("asset index one below the count", asset=3 * DIVISOR + 9999, count=4)
    add("asset index above the count", asset=9 * DIVISOR, count=4)
    add("asset index zero, count zero", asset=0, count=0)
    add("asset maximum", asset=MASK[8])
    add("vector full: grow", vec=(4, 4))
    add("vector empty with capacity", vec=(4, 0))
    add("vector capacity 1 full", vec=(1, 1))
    add("reason capacity 24: freed on error only", reason_cap=24)
    add("reason capacity zero", reason_cap=0)
    add("reason capacity top bit set", reason_cap=TREE)
    add("reason capacity maximum positive", reason_cap=0x7FFFFFFFFFFFFFFF, removal="none")
    add("side byte 1", side=1)
    add("wrapped user ring", users=(5, 4, 3, 2))
    add("user at the last logical slot", users=(5, 3, 4, 3))
    add("single slot rings", users=(1, 0, 1, 0), orders=(1, 0, 1), after_len=0, user_free=1)
    add("large user ring", users=(0x50, 3, 0x41, 7))
    add("large oid", oid=MASK[8])
    return rows


def random_case(source, number):
    pick = lambda pool: pool[next(source) % len(pool)]
    state = ("found", "found", "found", "found", "found", "absent", "past")[next(source) % 7]
    tree = next(source) % 5 == 0
    options = dict(user=1 + next(source) % (250 if tree else 9), oid=next(source) % 200, users=pick(RINGS), user_state=state, orders=pick(ORDER_RINGS),
                   removal=("found", "found", "found", "none")[next(source) % 4], side=next(source) % 2,
                   after_len=(0, 0, 1, 2, 5)[next(source) % 5], user_free=pick(FREE_WORDS),
                   pre="alt" if next(source) % 6 == 0 else "ok", pre_tag=pick((0, 1, 3, 0xFF)),
                   asset=pick(ASSETS) if next(source) % 3 else next(source) % (8 * DIVISOR), decoy=pick(ASSETS) if next(source) % 2 else 3 * DIVISOR + 3,
                   count=next(source) % 9, reason_cap=pick(REASONS), vec=pick(((4, 0), (4, 3), (4, 4), (1, 1), (8, 2), (2, 2))),
                   now=pick(NOWS))
    if tree:
        options.update(user_state="tree", tree=pick(((0, 1, 0), (0, 5, 0), (0, 11, 0), (1, 3, 2), (1, 4, 3), (1, 5, 1), (1, 2, 4))),
                       user_in_tree=next(source) % 4 != 0, tree_pos=next(source) % 40, pre="ok" if next(source) % 5 else "alt")
    return FinCase("random %d" % number, **options)


def cases_for(index, count):
    family = FINISH[index]["family"]
    for case in named_cases():
        case.family = family
        yield case
    source = lcg(41 + index)
    for number in range(count):
        case = random_case(source, number)
        case.family = family
        yield case


# ---- comparison ----

def matches(actual, expected):
    if ("stop" in actual) != ("stop" in expected):
        return False
    if actual["events"] != expected["events"]:
        return False
    if "stop" in expected:
        return True
    return all(actual.get(key) == expected.get(key) for key in ("vec", "event", "ring_len"))


def check(harness, index, case, variant=""):
    expected = spec_finish(case, variant)
    try:
        actual = harness.run_finish(index, case)
    except (Halt, Panicked, EvidenceError, ZeroDivisionError, struct.error, ValueError, KeyError):
        return False, expected, None
    return matches(actual, expected), expected, actual


def outcome_of(expected):
    if "stop" in expected:
        return "stop: " + expected["stop"]
    names = [event[0] for event in expected["events"]]
    if "event" in expected:
        return "pushed after removing user" if "remove user" in names else "pushed"
    return "error, reason freed" if "free" in names and names[-1] == "free" else "error"


def analyse(image, per_copy, rows_every):
    harness = FinishHarness(image)
    counts, outcomes, mismatches, rows = {}, {}, [], []
    for index in range(len(FINISH)):
        for number, case in enumerate(cases_for(index, per_copy)):
            ok, expected, actual = check(harness, index, case)
            counts[index] = counts.get(index, 0) + 1
            if not ok:
                mismatches.append((index, number, case.label))
                continue
            kind = outcome_of(expected)
            outcomes[(index, kind)] = outcomes.get((index, kind), 0) + 1
            if number % rows_every == 0:
                rows.append((index, number, kind, case.label, len(expected["events"]),
                             hashlib.sha256(expected["event"]).hexdigest()[:16] if "event" in expected else "-"))
    return harness, counts, outcomes, mismatches, rows


VARIANTS = ("asset_word_swapped", "market_div_1000", "bounds_inclusive", "free_reason_always", "free_reason_nonneg", "remove_user_always",
            "no_remove_user", "none_freed", "event_tag", "oid_user_swapped", "no_drop_temp", "builder_swapped", "error_code",
            "free_stride_68", "grow_missing", "precheck_after_find", "past_accepted", "no_wrap", "spot_book_offset", "compare_reversed")
VARIANT_NOTE = {
    "asset_word_swapped": "the asset id is read from the other record word",
    "market_div_1000": "market index is the asset id divided by 1000",
    "bounds_inclusive": "an asset index equal to the market count is accepted",
    "free_reason_always": "the reason string is freed whenever its capacity word is nonzero",
    "free_reason_nonneg": "the reason string is freed when its capacity word is zero or positive",
    "remove_user_always": "the user record is removed even when its order ring still holds orders",
    "no_remove_user": "the user record is never removed",
    "none_freed": "the no-user marker word frees a buffer",
    "event_tag": "the pushed event has tag 5",
    "oid_user_swapped": "the user key comes before the order id in the event",
    "no_drop_temp": "no drop of the temporary word before the builder",
    "builder_swapped": "the two status builders are selected the other way round",
    "error_code": "the not-found error code is 0xd5",
    "free_stride_68": "the freed order ring is sized with a 0x68 byte element",
    "grow_missing": "a full vector is not grown",
    "precheck_after_find": "the precheck runs after the user search",
    "past_accepted": "a user position at or past the ring length is accepted",
    "no_wrap": "the physical user slot does not wrap at the capacity",
    "spot_book_offset": "spot builder gets the book at outer + 0x98",
    "compare_reversed": "the tree search steps right on a smaller key instead of a larger one",
}


def jcc_patch(image, row):
    at = image.offset(row.va)
    first = image.blob[at]
    if 0x70 <= first <= 0x7F:
        return row.va, first ^ 1
    if first == 0x0F and 0x80 <= image.blob[at + 1] <= 0x8F:
        return row.va + 1, image.blob[at + 1] ^ 1
    return None


def detects(image, index, patches, probe):
    harness = FinishHarness(image, patches)
    for case in probe:
        try:
            ok, _, _ = check(harness, index, case)
        except Exception:  # a crashed mutant is a detected mutant
            return True
        if not ok:
            return True
    return False


def function_rows(image, va):
    start, end = image.exact_fde(va)
    return start, end, decode_range(image, start, end)


def run_mutants(image, seen, probe, probe2, limit):
    rows = []
    for index in (0, 2):
        row = FINISH[index]
        sites = []
        for name, va in (("finish", row["finish"]), ("take", row["take"])):
            for insn in function_rows(image, va)[2]:
                if insn.op == "jcc" and insn.va in seen:
                    patch = jcc_patch(image, insn)
                    if patch:
                        sites.append((name, insn.va, patch))
        step = max(1, len(sites) // limit)
        for name, va, (at, byte) in sites[::step]:
            patches = {at: byte}
            caught = detects(image, index, patches, probe[index])
            stage = 1
            if not caught:
                caught = detects(image, index, patches, probe2[index])
                stage = 2
            rows.append((index, name, va, at, byte, "detected" if caught else "survived", stage))
    return rows


def pin_controls(image):
    rows = []
    for va, expected, what in BYTE_PINS:
        at = image.offset(va)
        genuine = bytes(image.blob[at:at + len(expected)]) == expected
        broken = bytearray(expected)
        broken[-1] ^= 1
        refused = bytes(image.blob[at:at + len(expected)]) != bytes(broken)
        rows.append((hex(va), what, genuine, refused))
    return rows


def corrupt_controls(image):
    results = []
    for label, action in (("wrong digest", lambda: load_image(BINARY, "0" * 64)),
                          ("outside every FDE", lambda: image.fde(0x10)),
                          ("not an FDE start", lambda: image.exact_fde(FINISH[0]["finish"] + 1)),
                          ("take address inside another body", lambda: image.exact_fde(FINISH[2]["take"] + 4))):
        try:
            action()
            results.append((label, False))
        except EvidenceError:
            results.append((label, True))
    return results


def shape(row, start):
    target = row.target
    if row.op in ("jcc", "jmp") and target is not None:
        target = target - start
    return (row.op, row.a, row.b, row.width, row.cc, target if row.op != "call" else None)


def copy_differences(image):
    out = []
    for first, second, key in ((0, 1, "finish"), (2, 3, "finish"), (0, 2, "finish"), (0, 2, "take")):
        sa, ea, ra = function_rows(image, FINISH[first][key])
        sb, eb, rb = function_rows(image, FINISH[second][key])
        if len(ra) != len(rb):
            out.append((key, first, second, -1, "-", "-", "instruction count", len(ra), len(rb)))
            continue
        for index, (x, y) in enumerate(zip(ra, rb)):
            if shape(x, sa) != shape(y, sb):
                out.append((key, first, second, index, hex(x.va), hex(y.va), x.op, x.b if x.op in ("cmp", "add") else "-", y.b if y.op in ("cmp", "add") else "-"))
            elif x.op == "call" and x.target != y.target:
                out.append((key, first, second, index, hex(x.va), hex(y.va), "call target", hex(x.target), hex(y.target)))
    return out


def table(rows):
    return "".join("\t".join(str(cell) for cell in row) + "\n" for row in rows)


STUB_ROLES = (
    (TAKE[PERP]["precheck"], "direct", "perp precheck: byte at result + 8 equal to 2 lets the take go on"),
    (TAKE[SPOT]["precheck"], "direct", "spot precheck: byte at result + 8 equal to 2 lets the take go on"),
    (USER_SEARCH, "direct", "user ring search: rax 1 when absent, rdx the logical position"),
    (TAKE[PERP]["remove_order"], "direct", "perp order removal from the user's order ring: byte 0x22 of the body equal to 2 means none"),
    (TAKE[SPOT]["remove_order"], "direct", "spot order removal from the user's order ring"),
    (TAKE[PERP]["remove_user"], "direct", "perp removal of the user record; first result word is the freed ring capacity or a marker"),
    (TAKE[SPOT]["remove_user"], "direct", "spot removal of the user record"),
    (DROP_TREE, "direct", "drop of a removed tree-form order container"),
    (DROP_ERROR, "direct", "drop of the error value"),
    (DROP_TEMP, "direct", "drop of the temporary word 0x156"),
) + tuple((va, "direct", "status builder " + name) for name, va in sorted(BUILDERS.items())) + (
    (SLOT_FREE, "slot", "free(pointer, size, align 0)"),
    (SLOT_COPY, "slot", "memcpy"),
    (SLOT_EXPECT, "slot", "expect failure on the market index"),
    (SLOT_COMPARE, "slot", "20-byte key compare in the tree arm of the user search"),
    (SLOT_GROW[PERP], "slot", "grow of the output vector, 0x2b8 byte elements"),
    (SLOT_GROW[SPOT], "slot", "grow of the output vector, 0x2c8 byte elements"),
) + tuple((va, "landing pad", "unwind cleanup, reached only after a panic") for va in LANDING)


def build(image, per_copy, rows_every, mutant_limit):
    harness, counts, outcomes, mismatches, rows = analyse(image, per_copy, rows_every)
    seen = harness.machine.seen
    coverage = []
    for index, row in enumerate(FINISH):
        for name in ("finish", "take"):
            start, end, decoded = function_rows(image, row[name])
            coverage.append((index, name, hex(start), hex(end), end - start, len(decoded), sum(1 for item in decoded if item.va in seen)))
    probe = {index: list(cases_for(index, 200)) for index in range(4)}
    probe2 = {index: list(cases_for(index, 1200)) for index in range(4)}
    mutants = run_mutants(image, seen, probe, probe2, mutant_limit)
    variants = []
    for variant in VARIANTS:
        first, wrong, tried = None, 0, 0
        for index in range(4):
            for number, case in enumerate(cases_for(index, 600)):
                ok, _, _ = check(harness, index, case, variant)
                tried += 1
                if not ok:
                    wrong += 1
                    if first is None:
                        first = case.label
        variants.append((variant, VARIANT_NOTE[variant], first or "-", wrong, tried))
    return harness, counts, outcomes, mismatches, rows, coverage, mutants, variants


def render(image, per_copy, rows_every, mutant_limit):
    harness, counts, outcomes, mismatches, rows, coverage, mutants, variants = build(image, per_copy, rows_every, mutant_limit)
    if mismatches:
        raise EvidenceError("%d mismatches, first %r" % (len(mismatches), mismatches[0]))
    controls = corrupt_controls(image)
    pins = pin_controls(image)
    detected_mutants = sum(1 for row in mutants if row[5] == "detected")
    survivors = len(mutants) - detected_mutants
    detected_variants = sum(1 for row in variants if row[3] > 0)
    pin_ok = sum(1 for row in pins if row[2] and row[3])
    negative = detected_mutants + len(variants) + len(controls) + len(pins)
    detected = detected_mutants + detected_variants + sum(1 for _, ok in controls if ok) + pin_ok
    total = sum(counts.values())
    files = {}
    files["cases.tsv"] = "copy\tcase\toutcome\tlabel\tstub events\tevent sha256 prefix\n" + table(
        (hex(FINISH[c]["finish"]), n, k, label, e, h) for c, n, k, label, e, h in rows)
    files["outcomes.tsv"] = "copy\toutcome\tcases\n" + table((hex(FINISH[c]["finish"]), k, outcomes[(c, k)]) for c, k in sorted(outcomes))
    files["copies.tsv"] = "copy\tfunction\tstart\tend\tbytes\tinstructions\tstepped\n" + table(
        (hex(FINISH[c[0]]["finish"]), c[1]) + c[2:] for c in coverage)
    files["callees.tsv"] = "copy\tfamily\ttake\tprecheck\tremove order\tremove user\tbuilder when tag selects\tbuilder otherwise\n" + table(
        (hex(r["finish"]), r["family"], hex(r["take"]), hex(TAKE[r["family"]]["precheck"]), hex(TAKE[r["family"]]["remove_order"]),
         hex(TAKE[r["family"]]["remove_user"]), "0x" + r["yes"], "0x" + r["no"]) for r in FINISH)
    files["stubs.tsv"] = "address\tkind\trole\n" + table((hex(va), kind, what) for va, kind, what in STUB_ROLES)
    files["constants.tsv"] = "constant\taddress\tbytes\n" + table((what, hex(va), expected.hex()) for va, expected, what in BYTE_PINS)
    files["copy_differences.tsv"] = "function\tfirst\tsecond\tindex\tva first\tva second\twhat\tfirst\tsecond\n" + table(copy_differences(image))
    files["mutants.tsv"] = "copy\tfunction\tjcc va\tpatched byte va\tnew byte\tresult\tstage\n" + table(
        (hex(FINISH[c]["finish"]), n, hex(v), hex(a), hex(b), r, s) for c, n, v, a, b, r, s in mutants)
    files["variants.tsv"] = "variant\tmeaning\tfirst case where the bytes disagree\tdisagreeing cases\tcases tried\n" + table(variants)
    files["controls.tsv"] = "control\tdetected\n" + table(controls) + table(
        ("pin %s %s" % (va, what), genuine and refused) for va, what, genuine, refused in pins)
    summary = dict(binary_sha256=SHA256, cases=total, mismatches=len(mismatches), per_copy=per_copy,
                   coverage=[dict(copy=c[0], function=c[1], bytes=c[4], instructions=c[5], stepped=c[6]) for c in coverage],
                   mutants=len(mutants), mutants_detected=detected_mutants, survivors=survivors,
                   variants=len(variants), variants_detected=detected_variants, controls=len(controls), pins=len(pins))
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    measure = dict(cases=total, negative_controls=negative, negative_detected=detected, mutants_tried=len(mutants), mutants_survived=survivors)
    files["measure.json"] = json.dumps(measure, indent=1, sort_keys=True) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (folder / name).write_text(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--cases", type=int, default=3000, help="random cases per finish copy")
    parser.add_argument("--sample", type=int, default=3, help="keep every Nth case in cases.tsv")
    parser.add_argument("--mutants", type=int, default=60, help="jcc flips per representative copy")
    args = parser.parse_args(argv)
    image = load_image()
    write_outputs(args.out, render(image, args.cases, args.sample, args.mutants))
    return 0


if __name__ == "__main__":
    sys.exit(main())
